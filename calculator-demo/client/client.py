r"""Client that verifies the calculator server's attestation, then talks to it encrypted.

Usage:
  python client\client.py 6 * 7
  python client\client.py 10 / 4 --tamper     # flip one ciphertext byte to see it rejected
  python client\client.py 1 + 1 --url http://localhost:8000
"""

import argparse
import hashlib
import json
import os
import sys

import requests

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "server"))
import tee_crypto as tc  # noqa: E402


def log(step: str, msg: str = "") -> None:
    print(f"[CLIENT] {step:<22} {msg}", flush=True)


def replay_rtmrs(event_log: list) -> list[str]:
    """RTMR[i] = sha384(RTMR[i] || digest) for each event, starting from zeros."""
    rtmr = [b"\x00" * 48 for _ in range(4)]
    for ev in event_log:
        rtmr[ev["imr"]] = hashlib.sha384(rtmr[ev["imr"]] + bytes.fromhex(ev["digest"])).digest()
    return [r.hex() for r in rtmr]


def verify_attestation(url: str) -> bytes:
    att = requests.get(f"{url}/attestation", timeout=10).json()
    server_pub = bytes.fromhex(att["server_pub"])
    quote = bytes.fromhex(att["quote"])
    q = tc.parse_tdx_quote(quote)
    log("A fetch attestation", f"server pub {tc.short(server_pub)}, quote {len(quote)} bytes")
    log("", f"TDX quote v{q['version']}, tee_type={q['tee_type']} (0x81 = Intel TDX)")

    # Check 1: the quote commits to exactly this public key.
    expected = tc.report_data_for(server_pub).hex()
    if q["report_data"] != expected:
        sys.exit("[CLIENT] ABORT: quote.report_data != sha256(server_pub). Possible MITM.")
    log("B key binding", "OK  quote.report_data == sha256(server_pub)||0*32")

    # Check 2: the event log replays to the RTMRs in the quote.
    if att.get("event_log"):
        replayed = replay_rtmrs(json.loads(att["event_log"]))
        ok = [replayed[i] == q[f"rtmr{i}"] for i in range(4)]
        log("C event log replay", " ".join(f"RTMR{i}:{'OK' if o else 'MISMATCH'}" for i, o in enumerate(ok)))

    # Check 3: measurements. In production you pin these to known-good values
    # (MRTD = firmware/OS image, RTMR3 = your docker-compose hash, etc.).
    log("D measurements", f"MRTD  {tc.short(q['mr_td'])}")
    log("", f"RTMR3 {tc.short(q['rtmr3'])}")

    # Check 4 (production only): verify the quote signature chain up to Intel's
    # root CA, e.g. with dcap-qvl or Phala's verification API. The simulator's
    # quote is NOT signed by a real CPU, so we skip it here and say so loudly.
    log("E Intel signature", "SKIPPED: simulator quote is not hardware-signed")
    return server_pub


def call(url: str, server_pub_raw: bytes, payload: dict, tamper: bool) -> dict:
    print()
    eph = tc.new_ephemeral()
    eph_pub_raw = tc.pub_bytes(eph.public_key())
    log("1 ephemeral key", f"fresh P-256 key for this request, pub {tc.short(eph_pub_raw)}")
    shared = tc.ecdh_shared_secret(eph, tc.load_pub(server_pub_raw))
    log("2 ECDH", f"shared secret = {tc.short(shared)}")
    key = tc.session_key(shared, eph_pub_raw, server_pub_raw)
    log("3 HKDF-SHA256", f"session AES-256 key = {tc.short(key)}")

    plain = json.dumps(payload).encode()
    nonce, ct = tc.seal(key, plain, aad=eph_pub_raw)
    log("4 AES-GCM encrypt", f"{plain.decode()}  ->  {tc.short(ct, 24)}")
    if tamper:
        ct = bytes([ct[0] ^ 0x01]) + ct[1:]
        log("   TAMPER", "flipped one bit of the ciphertext before sending")

    r = requests.post(f"{url}/calc", timeout=10, json={
        "client_pub": eph_pub_raw.hex(), "nonce": nonce.hex(), "ciphertext": ct.hex()})
    if r.status_code != 200:
        log("5 server said", f"HTTP {r.status_code} {r.text}")
        return {}
    env = r.json()
    log("5 response on wire", f"ciphertext {tc.short(bytes.fromhex(env['ciphertext']), 24)}")
    out = tc.open_(key, bytes.fromhex(env["nonce"]), bytes.fromhex(env["ciphertext"]), aad=eph_pub_raw)
    log("6 AES-GCM decrypt", out.decode())
    return json.loads(out)


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("a", type=float)
    p.add_argument("op", choices=["+", "-", "*", "/", "x"])
    p.add_argument("b", type=float)
    p.add_argument("--url", default="http://localhost:8000")
    p.add_argument("--tamper", action="store_true")
    args = p.parse_args()

    pub = verify_attestation(args.url)
    res = call(args.url, pub, {"op": "*" if args.op == "x" else args.op, "a": args.a, "b": args.b}, args.tamper)
    if "result" in res:
        print(f"\n  {res['expr']} = {res['result']:g}")

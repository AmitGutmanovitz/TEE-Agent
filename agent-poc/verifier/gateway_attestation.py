r"""Verify Phala's Private AI gateway attestation, independently and without an API key.

Run:  .\.venv\Scripts\python agent-poc\verifier\gateway_attestation.py

Each check prints PASS / FAIL and the one thing it proves.
Docs: https://docs.phala.com/phala-cloud/confidential-ai/verify/verify-attestation
"""

import asyncio
import hashlib
import json
import os
import socket
import ssl
import sys
import time

import dcap_qvl
import requests
import rfc8785
from cryptography import x509
from cryptography.hazmat.primitives import serialization

GATEWAY = os.environ.get("PHALA_AI_BASE", "https://inference.phala.com")
HOST = GATEWAY.removeprefix("https://").split("/")[0]

# TDX quote v4: 48-byte header, then the TD report body. Offsets inside the body.
_BODY = 48
_FIELDS = {"mr_td": (136, 48), "rtmr0": (328, 48), "rtmr1": (376, 48),
           "rtmr2": (424, 48), "rtmr3": (472, 48), "report_data": (520, 64)}


def quote_field(quote: bytes, name: str) -> bytes:
    off, size = _FIELDS[name]
    return quote[_BODY + off:_BODY + off + size]


class Report:
    """Prints results and also keeps them (plus raw evidence in `artifacts`) for the Inspector."""

    def __init__(self):
        self.failed = 0
        self.items = []      # (layer, status, name, detail, proves)
        self.artifacts = {}  # raw evidence collected along the way
        self.layer = ""

    def section(self, title: str) -> None:
        self.layer = title
        print(f"\n== {title} ==")

    def check(self, ok: bool, name: str, proves: str, detail: str = "") -> bool:
        tag = "PASS" if ok else "FAIL"
        self.failed += not ok
        self.items.append((self.layer, tag, name, detail, proves))
        print(f"  [{tag}] {name}")
        if detail:
            print(f"         {detail}")
        print(f"         proves: {proves}")
        return ok

    def info(self, name: str, detail: str) -> None:
        self.items.append((self.layer, "INFO", name, detail, ""))
        print(f"  [INFO] {name}\n         {detail}")


def replay_rtmr(event_log: list, imr: int) -> bytes:
    rtmr = b"\x00" * 48
    for ev in event_log:
        if ev["imr"] == imr:
            rtmr = hashlib.sha384(rtmr + bytes.fromhex(ev["digest"])).digest()
    return rtmr


def dstack_event_digest(ev: dict) -> str:
    """dstack runtime events: sha384(event_type_le32 || ':' || name || ':' || payload)."""
    data = ev["event_type"].to_bytes(4, "little") + b":" + ev["event"].encode() + b":" + bytes.fromhex(ev["event_payload"])
    return hashlib.sha384(data).hexdigest()


def tls_info(host: str, port: int = 443) -> dict:
    """Open a TLS connection (normal hostname + CA validation) and describe what was negotiated."""
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=15) as s, ctx.wrap_socket(s, server_hostname=host) as tls:
        der = tls.getpeercert(binary_form=True)
        cipher, version = tls.cipher(), tls.version()
    cert = x509.load_der_x509_certificate(der)
    spki = cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return {"host": host, "tls_version": version, "cipher_suite": cipher[0], "cipher_bits": cipher[2],
            "subject": cert.subject.rfc4514_string(), "issuer": cert.issuer.rfc4514_string(),
            "not_before": cert.not_valid_before_utc.isoformat(), "not_after": cert.not_valid_after_utc.isoformat(),
            "public_key_type": type(cert.public_key()).__name__.replace("_", ""),
            "cert_sha256": hashlib.sha256(der).hexdigest(), "spki_sha256": hashlib.sha256(spki).hexdigest()}


def server_spki_sha256(host: str) -> str:
    return tls_info(host)["spki_sha256"]


def verify_gateway(r: Report) -> dict:
    """Run all gateway checks. Returns the verified keyset (for receipt checks later)."""
    nonce = os.urandom(32).hex()
    r.section(f"Layer B: Phala Private AI gateway ({GATEWAY})")
    print(f"  our fresh nonce: {nonce}")
    att = requests.get(f"{GATEWAY}/v1/aci/attestation", params={"nonce": nonce}, timeout=30).json()
    r.artifacts["gateway_attestation"] = att
    r.artifacts["gateway_nonce"] = nonce
    a, ev = att["attestation"], att["attestation"]["evidence"]
    quote = bytes.fromhex(ev["quote"])

    # 1. Intel DCAP: the quote is signed by a genuine, up-to-date TDX CPU.
    try:
        vr = asyncio.run(dcap_qvl.get_collateral_and_verify(quote))
        status = vr.status
        r.check(status == "UpToDate", "1. Intel DCAP quote signature + TCB status",
                "a genuine Intel TDX CPU produced this quote (signature chain to Intel's root CA)",
                f"TCB status: {status}" + (f", advisories: {vr.advisory_ids}" if vr.advisory_ids else ""))
    except Exception as e:  # noqa: BLE001
        r.check(False, "1. Intel DCAP quote signature + TCB status", "genuine TDX hardware", f"error: {e}")

    # 2. Keyset digest: JCS (RFC 8785) of the keyset, sha256.
    digest = "sha256:" + hashlib.sha256(rfc8785.dumps(a["workload_keyset"])).hexdigest()
    r.check(digest == att["workload_keyset_digest"], "2. Keyset digest (RFC 8785 JCS + SHA-256)",
            "the keyset we read is exactly the one the enclave committed to", digest)

    # 3. Nonce + keyset bound into the quote's report_data.
    stmt = json.dumps({"keyset_digest": digest, "nonce": nonce, "purpose": "aci.report_data.v1"},
                      separators=(",", ":")).encode()
    want = hashlib.sha256(stmt).digest()
    rd = quote_field(quote, "report_data")
    r.check(rd[:32] == want and rd[32:] == b"\x00" * 32 and a["report_data"] == want.hex(),
            "3. report_data = sha256({keyset_digest, nonce, purpose})",
            "the quote is fresh (made for our nonce, not replayed) and vouches for these signing/TLS keys",
            f"report_data[0:32] = {rd[:32].hex()}")

    # 4. Event log replays to RTMR3, and the measured compose-hash is sha256(app_compose).
    log = json.loads(ev["event_log"])
    rtmr3_ok = replay_rtmr(log, 3) == quote_field(quote, "rtmr3")
    digests_ok = all(dstack_event_digest(e) == e["digest"] for e in log if e["imr"] == 3)
    compose_ev = next(e for e in log if e["event"] == "compose-hash")
    compose_hash = hashlib.sha256(ev["app_compose"].encode()).hexdigest()
    r.check(rtmr3_ok and digests_ok and compose_ev["event_payload"] == compose_hash,
            "4. Event log -> RTMR3, compose-hash = sha256(app_compose)",
            "exactly this docker-compose (gateway code + config) was booted in the enclave",
            f"compose-hash {compose_hash}")
    prov = a.get("source_provenance") or {}
    r.info("   source (informational, not a trust root)",
           f"{prov.get('repo_url')} @ {prov.get('repo_commit')}")
    vm = json.loads(ev["vm_config"])
    r.info("   VM", f"{vm.get('image')} os_image_hash={vm.get('os_image_hash')} gpus={vm.get('num_gpus')}")

    # 5. Keyset not expired.
    na = a["workload_keyset"]["not_after"]
    r.check(time.time() < na < time.time() + 400 * 86400, "5. Keyset expiry",
            "the keys are within their declared validity window",
            f"not_after = {time.strftime('%Y-%m-%d', time.gmtime(na))}")

    # 6. TLS pin: the certificate we actually connect to is the enclave's.
    pins = {k["spki_sha256"] for k in a["workload_keyset"]["tls_public_keys"] if k["domain"] == HOST}
    ti = tls_info(HOST)
    r.artifacts["gateway_tls"] = ti
    live = ti["spki_sha256"]
    r.check(live in pins, f"6. TLS key pin for {HOST}",
            "our HTTPS connection terminates inside the attested enclave, not at a proxy",
            f"live SPKI sha256 {live}")
    return a["workload_keyset"] | {"_digest": digest}


if __name__ == "__main__":
    rep = Report()
    verify_gateway(rep)
    print(f"\n{'ALL CHECKS PASSED' if not rep.failed else f'{rep.failed} CHECK(S) FAILED'}")
    sys.exit(1 if rep.failed else 0)

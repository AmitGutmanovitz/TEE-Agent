"""Calculator server meant to run inside a Phala dstack CVM (here: the simulator).

Endpoints
  GET  /attestation -> {"server_pub", "quote", "event_log", "key_cert_chain"}
  POST /calc        -> body {"client_pub", "nonce", "ciphertext"} (all hex)
                       plaintext inside is {"op": "+|-|*|/", "a": num, "b": num}
"""

import hashlib
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import requests
from cryptography.hazmat.primitives.serialization import load_pem_private_key

import tee_crypto as tc

TAPPD = os.environ.get("DSTACK_SIMULATOR_ENDPOINT", "http://tappd-sim:8090")
KEY_PATH = "/calc-server/ecdh-key"   # KMS derivation path: same app + same path = same key


def log(step: str, msg: str = "") -> None:
    print(f"[SERVER] {step:<22} {msg}", flush=True)


def tappd(method: str, body: dict) -> dict:
    r = requests.post(f"{TAPPD}/prpc/Tappd.{method}?json", json=body, timeout=30)
    r.raise_for_status()
    return r.json()


# ---------------------------------------------------------------- boot ------
log("BOOT", f"talking to TEE guest agent at {TAPPD}")

# 1. Ask the TEE's KMS for our long-term private key. On real hardware the KMS
#    only releases it to a CVM whose measurements match this app, so the key is
#    bound to the code. It is deterministic for (app id, path).
dk = tappd("DeriveKey", {"path": KEY_PATH, "subject": "calc-server"})
SERVER_PRIV = load_pem_private_key(dk["key"].encode(), password=None)
SERVER_PUB_RAW = tc.pub_bytes(SERVER_PRIV.public_key())
log("1 KMS DeriveKey", f"path={KEY_PATH} -> P-256 key, pub={tc.short(SERVER_PUB_RAW)}")
log("", f"cert chain from KMS: {len(dk['certificate_chain'])} certs (leaf signed by KMS CA)")

# 2. Ask the TEE for a quote that commits to our public key.
REPORT_DATA = tc.report_data_for(SERVER_PUB_RAW)
q = tappd("TdxQuote", {"report_data": REPORT_DATA.hex(), "hash_algorithm": "raw"})
QUOTE = bytes.fromhex(q["quote"].removeprefix("0x"))
parsed = tc.parse_tdx_quote(QUOTE)
log("2 TdxQuote", f"{len(QUOTE)}-byte TDX quote v{parsed['version']}, tee_type={parsed['tee_type']}")
log("", f"report_data = sha256(pub)||0*32 = {tc.short(parsed['report_data'])}")
log("", f"MRTD  = {tc.short(parsed['mr_td'])}")
log("", f"RTMR3 = {tc.short(parsed['rtmr3'])}  (app/compose measurement)")
if parsed["report_data"] != REPORT_DATA.hex():
    sys.exit("quote does not contain our report_data; simulator API changed?")

ATTESTATION = json.dumps({
    "server_pub": SERVER_PUB_RAW.hex(),
    "quote": QUOTE.hex(),
    "event_log": q.get("event_log"),
    "key_cert_chain": dk["certificate_chain"],
}).encode()


# ------------------------------------------------------------- handlers -----
def calculate(req: dict) -> dict:
    a, b, op = float(req["a"]), float(req["b"]), req["op"]
    ops = {"+": a + b, "-": a - b, "*": a * b, "/": a / b if b else None}
    if op not in ops:
        return {"error": f"unknown op {op!r}"}
    if ops[op] is None:
        return {"error": "division by zero"}
    return {"result": ops[op], "expr": f"{a:g} {op} {b:g}"}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # silence default access log
        pass

    def _send(self, code: int, body: bytes) -> None:
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/attestation":
            log("GET /attestation", "sending pubkey + quote to client")
            self._send(200, ATTESTATION)
        else:
            self._send(404, b'{"error":"not found"}')

    def do_POST(self):
        if self.path != "/calc":
            return self._send(404, b'{"error":"not found"}')
        env = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        client_pub_raw = bytes.fromhex(env["client_pub"])
        nonce, ct = bytes.fromhex(env["nonce"]), bytes.fromhex(env["ciphertext"])
        print("", flush=True)
        log("POST /calc", f"ciphertext on the wire: {tc.short(ct, 24)}")
        log("", f"client ephemeral pub: {tc.short(client_pub_raw)}")

        shared = tc.ecdh_shared_secret(SERVER_PRIV, tc.load_pub(client_pub_raw))
        log("3 ECDH", f"shared secret = {tc.short(shared)}")
        key = tc.session_key(shared, client_pub_raw, SERVER_PUB_RAW)
        log("4 HKDF-SHA256", f"session AES-256 key = {tc.short(key)}")
        try:
            plain = tc.open_(key, nonce, ct, aad=client_pub_raw)
        except Exception:
            log("5 AES-GCM decrypt", "FAILED: auth tag mismatch (tampered or wrong key)")
            return self._send(400, b'{"error":"decryption failed"}')
        log("5 AES-GCM decrypt", f"plaintext = {plain.decode()}")

        result = json.dumps(calculate(json.loads(plain))).encode()
        log("6 compute", result.decode())
        r_nonce, r_ct = tc.seal(key, result, aad=client_pub_raw)
        log("7 AES-GCM encrypt", f"response ciphertext = {tc.short(r_ct, 24)}")
        self._send(200, json.dumps({"nonce": r_nonce.hex(), "ciphertext": r_ct.hex()}).encode())


if __name__ == "__main__":
    log("READY", "listening on :8000")
    ThreadingHTTPServer(("0.0.0.0", 8000), Handler).serve_forever()

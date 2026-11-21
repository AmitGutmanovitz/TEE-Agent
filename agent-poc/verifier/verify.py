r"""Independent verifier for one agent answer. Trusts nothing the agent says.

  .\.venv\Scripts\python agent-poc\verifier\verify.py <proof_id> [--agent URL] [--expect-compose FILE]

Reads PHALA_API_KEY (receipts) and CHAT_TOKEN/ADMIN_TOKEN (agent auth) from agent-poc/.env or the environment.

Layer A: our agent (its TDX quote binds the key that signed the answer)
Layer B: Phala's AI gateway (real Intel TDX quote, keyset, compose hash, TLS pin)
Layer C: this specific inference (Ed25519 receipt over the exact request/response bytes,
         plus the upstream GPU TEE session evidence)
"""

import argparse
import base64
import hashlib
import json
import os
import sys

import requests
import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

sys.path.insert(0, os.path.dirname(__file__))
from gateway_attestation import GATEWAY, Report, quote_field, replay_rtmr, verify_gateway  # noqa: E402


def load_env() -> None:
    p = os.path.join(os.path.dirname(__file__), "..", ".env")
    if os.path.exists(p):
        for line in open(p, encoding="utf-8"):
            if "=" in line and not line.lstrip().startswith("#"):
                k, v = line.strip().split("=", 1)
                os.environ.setdefault(k, v)


def h(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def strip_alg(x: str | None) -> str:
    return (x or "").split(":", 1)[-1]


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


# ---------------------------------------------------------------- Layer A ---
def verify_agent(r: Report, agent: str, proof: dict, expected_compose: str | None = None) -> None:
    r.section(f"Layer A: our agent ({agent})")
    nonce = os.urandom(32).hex()
    att = requests.get(f"{agent}/attestation", params={"nonce": nonce}, timeout=30).json()
    r.artifacts["agent_attestation"] = att
    r.artifacts["agent_nonce"] = nonce
    quote = bytes.fromhex(att["quote"])
    pub = bytes.fromhex(att["agent_pubkey"])
    rd = quote_field(quote, "report_data")
    r.check(rd == hashlib.sha256(pub).digest() + hashlib.sha256(bytes.fromhex(nonce)).digest(),
            "A1. Agent quote report_data = sha256(agent_pubkey) || sha256(our nonce)",
            "the answer-signing key lives inside this (fresh) TEE quote")
    if att.get("event_log"):
        log = json.loads(att["event_log"])
        r.check(all(replay_rtmr(log, i) == quote_field(quote, f"rtmr{i}") for i in range(4)),
                "A2. Agent event log replays to RTMR0-3", "the boot measurements in the quote are consistent")
    r.info("   agent measurements", f"MRTD {quote_field(quote, 'mr_td').hex()[:32]}...  "
           f"RTMR3 {quote_field(quote, 'rtmr3').hex()[:32]}...")
    if att["tee_mode"] == "tappd-simulator":
        r.info("A3. Intel signature on agent quote",
               "SKIPPED: local simulator quote is not hardware-signed (becomes real on a Phala CVM)")
    else:
        import asyncio

        import dcap_qvl
        try:
            status = asyncio.run(dcap_qvl.get_collateral_and_verify(quote)).status
        except Exception as e:  # noqa: BLE001
            status = f"error {e}"
        r.check(status == "UpToDate", "A3. Agent quote: Intel DCAP signature + TCB",
                "the agent runs in a genuine, patched Intel TDX CVM", f"TCB status: {status}")
        log = json.loads(att.get("event_log") or "[]")
        ch = next((e["event_payload"] for e in log if e.get("event") == "compose-hash"), None)
        app_compose = att.get("app_compose") or ""
        r.check(bool(ch) and ch == h(app_compose.encode()), "A6. Agent compose-hash (RTMR3) = sha256(app_compose)",
                "exactly this app_compose (docker-compose + settings) was booted in the agent CVM",
                f"compose-hash {ch}")
        if expected_compose:
            booted = json.loads(app_compose).get("docker_compose_file", "") if app_compose else ""
            r.check(booted.strip() == open(expected_compose, encoding="utf-8").read().strip(),
                    "A7. Booted docker-compose = our reviewed compose file",
                    "the agent CVM runs the code we expect: our image, pinned by digest",
                    f"compared with {expected_compose}")
        else:
            r.info("A7. Booted docker-compose", "not compared (pass --expect-compose <file> to pin it)")
    st = proof["statement"]
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(bytes.fromhex(proof["agent_signature"]), canonical(st))
        ok = proof["agent_pubkey"] == pub.hex()
    except Exception:  # noqa: BLE001
        ok = False
    r.check(ok, "A4. Agent signature over the answer statement",
            "this TEE agent vouches: model, system prompt hash, request/response hashes, receipt id")
    req, resp = base64.b64decode(proof["request_b64"]), base64.b64decode(proof["response_b64"])
    plain = base64.b64decode(proof.get("request_plain_b64") or proof["request_b64"])
    sys_prompt = json.loads(plain)["messages"][0]["content"]
    r.check(h(req) == st["request_sha256"] and h(resp) == st["response_sha256"]
            and h(plain) == st.get("plaintext_request_sha256", h(plain))
            and h(sys_prompt.encode()) == st["system_prompt_sha256"],
            "A5. Request/response bytes match the signed hashes",
            "the system prompt and messages shown below are what the agent actually sent",
            f"system prompt: {sys_prompt!r}")


# ---------------------------------------------------------------- Layer C ---
def verify_receipt(r: Report, keyset: dict, proof: dict, api_key: str) -> None:
    st = proof["statement"]
    r.section(f"Layer C: this inference (receipt {st['receipt_id']})")
    auth = {"Authorization": f"Bearer {api_key}"}
    rc = requests.get(f"{GATEWAY}/v1/aci/receipts/{st['receipt_id']}", headers=auth, timeout=30).json()
    receipt = rc.get("receipt", rc)
    r.artifacts["receipt"] = receipt

    r.check(receipt.get("workload_keyset_digest") == keyset["_digest"],
            "C1. Receipt cites the attested keyset", "the receipt was issued under the keys we verified in Layer B")
    keys = {k["key_id"]: k for k in keyset["receipt_signing_keys"]}
    sig = receipt.get("signature")
    sig_hex = sig.get("value") if isinstance(sig, dict) else sig
    key_id = receipt.get("key_id") or (sig.get("key_id") if isinstance(sig, dict) else None)
    unsigned = {k: v for k, v in receipt.items() if k != "signature"}
    try:
        raw_sig = bytes.fromhex(sig_hex) if all(c in "0123456789abcdef" for c in sig_hex.lower()) else base64.b64decode(sig_hex)
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(keys[key_id]["public_key"])).verify(raw_sig, rfc8785.dumps(unsigned))
        ok = True
    except Exception as e:  # noqa: BLE001
        ok, err = False, e
    r.check(ok, "C2. Ed25519 receipt signature (attested key, JCS body)",
            "the enclave itself signed this receipt; it cannot be forged outside the TEE",
            "" if ok else f"error: {err!r}")

    req, resp = base64.b64decode(proof["request_b64"]), base64.b64decode(proof["response_b64"])
    plain = base64.b64decode(proof.get("request_plain_b64") or proof["request_b64"])
    events = {e["type"]: e for e in receipt.get("event_log", [])}
    got_req = strip_alg(events.get("request.received", {}).get("body_hash"))
    got_resp = strip_alg(events.get("response.returned", {}).get("body_hash"))
    if st.get("e2ee"):
        # With E2EE the receipt hashes the body the gateway restored after decrypting it inside its enclave:
        # our plaintext request, re-serialized as compact JSON (same key order, UTF-8).
        restored = json.dumps(json.loads(plain), separators=(",", ":"), ensure_ascii=False).encode()
        r.artifacts["restored_request"] = restored.decode()
        r.check(got_req == h(restored), "C3. Receipt request hash = our plaintext request, as decrypted in the gateway",
                "the enclave decrypted our ciphertext back to exactly this system prompt + conversation",
                f"sha256 {got_req[:16]}... of the compact plaintext JSON")
    else:
        r.check(got_req == h(req), "C3. Receipt request body hash = our exact request bytes",
                "the enclave received exactly this system prompt + conversation")
    r.check(got_resp == h(resp), "C4. Receipt response body hash = our exact response bytes",
            "the answer we got is exactly what the enclave returned, unmodified")

    ups = [e for e in receipt.get("event_log", []) if e.get("type") == "upstream.verified"]
    up = ups[0] if ups else {}
    r.check(up.get("result") == "verified" and up.get("required") is True and bool(up.get("session_id")),
            "C5. upstream.verified event", "the gateway checked the model server's TEE attestation before routing",
            json.dumps(up)[:300])
    fwd = events.get("request.forwarded", {}).get("body_hash")
    r.info("   gateway -> model server", f"route {events.get('route.selected', {}).get('target_route_id')}; "
           f"forwarded body hash {strip_alg(fwd)[:16]}... (the gateway re-encodes the request before forwarding)")
    if up.get("session_id"):
        sess = requests.get(f"{GATEWAY}/v1/aci/sessions/{up['session_id']}", headers=auth, timeout=30).json()
        r.artifacts["session"] = sess
        verify_model_server(r, sess, up["session_id"], receipt.get("served_at"))


# ---------------------------------------------------------------- Layer D ---
def verify_model_server(r: Report, sess: dict, session_id: str, served_at: int | None) -> None:
    """Re-verify, ourselves, the evidence the gateway collected from the GPU machine that ran the model."""
    import asyncio

    import dcap_qvl

    r.section(f"Layer D: the model server that ran the LLM ({sess.get('endpoint')})")
    r.check(hashlib.sha256(rfc8785.dumps(sess)).hexdigest() == session_id,
            "D1. Session id = sha256(JCS(session))", "the session record is exactly the one the signed receipt points to")
    raw = base64.b64decode(sess["evidence"]["data"].split(",", 1)[1])
    r.check("sha256:" + h(raw) == sess["evidence"]["digest"], "D2. Evidence digest",
            "the raw evidence bundle is the one named in the session")
    a = json.loads(raw)["all_attestations"][0]
    r.artifacts["model_server_evidence"] = a
    quote = bytes.fromhex(a["intel_quote"])

    try:
        status = asyncio.run(dcap_qvl.get_collateral_and_verify(quote)).status
    except Exception as e:  # noqa: BLE001
        status = f"error {e}"
    r.check(status == "UpToDate", "D3. Model server TDX quote: Intel DCAP signature + TCB",
            "the model server is a genuine, patched Intel TDX confidential VM", f"TCB status: {status}")

    rd = quote_field(quote, "report_data")
    addr = bytes.fromhex(a["signing_address"].removeprefix("0x"))
    tls_fp = bytes.fromhex(a["tls_cert_fingerprint"])
    nonce = bytes.fromhex(a["request_nonce"])
    r.check(rd == hashlib.sha256(addr + tls_fp).digest() + nonce,
            "D4. report_data = sha256(signing_address || tls_fingerprint) || nonce",
            "the model server's TLS key and signing key were generated inside that TDX VM, for this fresh nonce")
    cb = [c["spki_sha256"] for c in sess.get("channel_binding", [])]
    r.check(a["tls_cert_fingerprint"] in cb, "D5. Gateway's channel is pinned to that TLS key",
            "the gateway's connection to the model terminates inside the attested model server",
            f"{sess.get('endpoint')} spki {a['tls_cert_fingerprint'][:16]}...")

    tcb = a["info"]["tcb_info"]
    log = tcb["event_log"]
    compose = tcb["app_compose"]
    ch = next((e["event_payload"] for e in log if e.get("event") == "compose-hash"), None)
    r.check(replay_rtmr(log, 3) == quote_field(quote, "rtmr3") and ch == h(compose.encode()),
            "D6. Model server event log -> RTMR3, compose-hash = sha256(app_compose)",
            "exactly this docker-compose (the inference server software) was booted on the GPU machine",
            f"compose-hash {ch}")
    images = sorted({ln.split("image:", 1)[1].strip().split()[-1]
                     for ln in json.loads(compose)["docker_compose_file"].splitlines()
                     if "image:" in ln and "@sha256:" in ln})
    r.info("   model server images (from the measured compose)", "\n         ".join(images) or "-")

    nv = json.loads(a["nvidia_payload"])
    try:
        resp = requests.post("https://nras.attestation.nvidia.com/v3/attest/gpu", json=nv, timeout=60).json()
        overall = _jwt_claims(resp[0][1])
        gpus = [_jwt_claims(j) for j in resp[1].values()]
        r.artifacts["nras"] = {"overall": overall, "gpus": gpus}
        ok = (overall.get("x-nvidia-overall-att-result") is True and nv["nonce"] == a["request_nonce"]
              and all(g.get("x-nvidia-gpu-attestation-report-nonce-match") and g.get("dbgstat") == "disabled"
                      and g.get("measres") == "success" for g in gpus))
        detail = "; ".join(f"{g.get('hwmodel')} driver {g.get('x-nvidia-gpu-driver-version')} "
                           f"secboot={g.get('secboot')} debug={g.get('dbgstat')}" for g in gpus)
    except Exception as e:  # noqa: BLE001
        ok, detail = False, f"error {e}"
    r.check(ok, "D7. NVIDIA NRAS: GPU attestation (same nonce as the TDX quote)",
            "an NVIDIA confidential-computing GPU in CC mode, measurements match NVIDIA's golden values", detail)

    ok_time = served_at is not None and sess["established_at"] <= served_at <= sess["expires_at"]
    r.check(ok_time, "D8. Our request was served inside the session's validity window",
            "this verified model server session was the one in force when our answer was produced")
    c = sess.get("claims", {})
    r.info("   NOT proven (Phala's own claims)",
           f"model_weights_provenance={c.get('model_weights_provenance', {}).get('status')}, "
           f"serving_software_known_good={c.get('serving_software_known_good', {}).get('status')}; "
           f"gpu: {c.get('gpu_attested', {}).get('reason')}")


# ---------------------------------------------------------------- Layer E ---
def verify_e2ee(r: Report, proof: dict, debug: dict, keyset: dict) -> None:
    """Re-do the end-to-end encryption ourselves from the one-time keys the agent disclosed (admin debug data)."""
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "agent"))
    import e2ee  # noqa: E402  (same module the agent uses; its math is standard X25519/HKDF/AES-GCM)
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    st, tr = proof["statement"], debug.get("e2ee")
    r.section("Layer E: end-to-end encryption between the agent and the gateway enclave")
    if not tr:
        r.info("E0. E2EE", "off for this answer (plain TLS only)")
        return
    attested = {k["public_key"] for k in keyset.get("e2ee_public_keys", [])}
    r.check(st["e2ee"]["gateway_public_key"] in attested, "E1. Gateway E2EE key is in the attested keyset",
            "the prompt was encrypted to a key that only exists inside the attested gateway enclave",
            f"{tr['gateway_key']['key_id']} {st['e2ee']['gateway_public_key'][:24]}...")
    wire = json.loads(base64.b64decode(proof["request_b64"]))
    plain = json.loads(base64.b64decode(proof["request_plain_b64"]))
    ok = True
    for i, f in enumerate(tr["request_fields"]):
        aad = e2ee.aad("aci.e2ee.request.v2", plain["model"], f["field"], tr["nonce"], tr["ts"])
        blob, _ = e2ee.encrypt_field(st["e2ee"]["gateway_public_key"], plain["messages"][i]["content"], aad,
                                     eph=X25519PrivateKey.from_private_bytes(bytes.fromhex(f["ephemeral_private"])),
                                     aes_nonce=bytes.fromhex(f["aes_nonce"]))
        ok &= blob == wire["messages"][i]["content"] and plain["messages"][i]["content"] not in json.dumps(wire)
    r.check(ok, "E2. Re-encrypting each plaintext field reproduces the exact ciphertext on the wire",
            "the bytes sent were the encryption of exactly this system prompt + messages, and no plaintext leaked",
            f"{len(tr['request_fields'])} field(s), X25519 -> HKDF-SHA256 -> AES-256-GCM")
    client = X25519PrivateKey.from_private_bytes(bytes.fromhex(tr["client_private_one_time"]))
    wire_resp = json.loads(base64.b64decode(proof["response_b64"]))
    ok = bool(tr.get("response_fields"))
    for f in tr.get("response_fields", []):
        i = int(f["field"].split(".")[1])
        name = f["field"].split(".")[-1]
        aad = e2ee.aad("aci.e2ee.response.v2", plain["model"], f["field"], tr["nonce"], tr["ts"], wire_resp.get("id") or "")
        pt, _ = e2ee.decrypt_field(client, wire_resp["choices"][i]["message"][name], aad)
        ok &= pt == f["plaintext"] == debug["response_decrypted_json"]["choices"][i]["message"][name]
    r.check(ok, "E3. Decrypting the wire response with our one-time key gives the answer",
            "the answer came back encrypted to us; only the holder of the one-time key could read it",
            f"{len(tr.get('response_fields', []))} field(s)")


def _jwt_claims(jwt: str) -> dict:
    p = jwt.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))


def run_all(proof_id: str, agent: str, expect_compose: str | None = None) -> tuple[Report, dict, dict | None]:
    """Fetch the proof (+ admin debug data if ADMIN_TOKEN is available) and run every layer."""
    load_env()
    agent = agent.rstrip("/")
    api_key = os.environ.get("PHALA_API_KEY")
    if not api_key:
        sys.exit("Set PHALA_API_KEY (agent-poc/.env) - receipts are only readable with the same key")
    token = os.environ.get("CHAT_TOKEN") or os.environ.get("ADMIN_TOKEN")
    hdr = {"Authorization": f"Bearer {token}"} if token else {}
    pr = requests.get(f"{agent}/proof/{proof_id}", headers=hdr, timeout=30)
    if pr.status_code != 200:
        sys.exit(f"could not fetch proof: HTTP {pr.status_code} {pr.text[:200]}")
    proof = pr.json()
    debug = None
    if os.environ.get("ADMIN_TOKEN"):
        d = requests.get(f"{agent}/debug/{proof_id}", timeout=30,
                         headers={"Authorization": f"Bearer {os.environ['ADMIN_TOKEN']}"})
        debug = d.json() if d.status_code == 200 else None
    rep = Report()
    verify_agent(rep, agent, proof, expect_compose)
    keyset = verify_gateway(rep)
    verify_receipt(rep, keyset, proof, api_key)
    if debug is not None:
        verify_e2ee(rep, proof, debug, keyset)
    elif proof["statement"].get("e2ee"):
        rep.section("Layer E: end-to-end encryption")
        rep.info("E. E2EE checks", "skipped: needs ADMIN_TOKEN to read the one-time keys")
    return rep, proof, debug


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("proof_id")
    ap.add_argument("--agent", default=os.environ.get("AGENT_URL", "http://localhost:8000"))
    ap.add_argument("--expect-compose", help="compose file the agent CVM must have booted (real CVM only)")
    args = ap.parse_args()
    rep, _, _ = run_all(args.proof_id, args.agent, args.expect_compose)
    print(f"\n{'ALL CHECKS PASSED' if not rep.failed else f'{rep.failed} CHECK(S) FAILED'}")
    sys.exit(1 if rep.failed else 0)

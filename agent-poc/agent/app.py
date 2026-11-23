"""Verifiable chat agent. Runs inside a Phala CVM (or the local dstack simulator).

  GET  /                      web UI
  GET  /system-prompt         current system prompt + its sha256             (chat token)
  PUT  /system-prompt         {"prompt": "..."} change it at runtime         (admin token)
  POST /chat                  {"message": "...", "session": "optional id"}   (chat token)
  POST /reset                 {"session": "..."} clear a conversation        (chat token)
  GET  /proof/{id}            full evidence for one answer                   (chat token)
  GET  /attestation?nonce=hex agent's own TDX quote binding its signing key  (public)
  GET  /info                  backend, model, TEE mode, signing key          (public)
  GET  /metrics               token/latency totals                           (admin token)

Tokens are sent as "Authorization: Bearer <token>". If ADMIN_TOKEN / CHAT_TOKEN are unset the
endpoints are open, which is only allowed with the local simulator; on a real CVM both are required.

The LLM runs at Phala's Private AI gateway (inference.phala.com) on TEE hardware.
Every answer is signed by this agent with a key that only exists inside its TEE.
"""

import base64
import hashlib
import hmac
import json
import os
import sqlite3
import threading
import time
import uuid
from collections import OrderedDict

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel

import e2ee
import rfc8785
from tee import TEE

# LLM backend switch:
#   phala  -> Phala Private AI gateway, model runs in a TEE, answers are verifiable (receipts)
#   gemini -> Google Gemini API (OpenAI-compatible endpoint), NOT TEE-verified
#   openai -> plain OpenAI API, NOT TEE-verified
# All three speak the OpenAI chat-completions format; only base URL, path, key and model differ.
BACKEND = os.environ.get("LLM_BACKEND", "phala").lower()
BACKENDS = {
    "phala": {"base": os.environ.get("PHALA_AI_BASE", "https://inference.phala.com"),
              "path": "/v1/chat/completions",
              "key": os.environ.get("PHALA_API_KEY", ""),
              "model": os.environ.get("PHALA_MODEL", "qwen/qwen-2.5-7b-instruct"),
              # Chat models hosted by Phala itself (providers == ["phala"]), so verify.py can re-check the
              # model server's own TDX + GPU evidence (layer D). Cheapest first (Phala price list, 2026-11-20).
              "models": ["qwen/qwen-2.5-7b-instruct", "phala/gemma-4-26b-a4b-uncensored",
                         "phala/qwen3.8-27b-uncensored", "phala/deepseek-v4.1-flash-1017-uncensored"],
              "tee_verified": True},
    "gemini": {"base": "https://generativelanguage.googleapis.com",
               "path": "/v1beta/openai/chat/completions",
               "key": os.environ.get("GEMINI_API_KEY", ""),
               "model": os.environ.get("GEMINI_MODEL", "gemini-2.5-flash-lite"),
               "models": ["gemini-2.5-flash-lite", "gemini-2.5-flash"],
               "tee_verified": False},
    "openai": {"base": os.environ.get("OPENAI_BASE", "https://api.openai.com"),
               "path": "/v1/chat/completions",
               "key": os.environ.get("OPEN_AI_API_KEY", ""),
               "model": os.environ.get("OPENAI_MODEL", "gpt-4.1-mini"),
               "models": ["gpt-4.1-mini", "gpt-4o-mini", "gpt-5-mini", "gpt-5-nano"],
               "tee_verified": False},
}
for _b in BACKENDS.values():
    _b["key"] = _b["key"].strip()
    if _b["model"] not in _b["models"]:
        _b["models"].insert(0, _b["model"])
if BACKEND not in BACKENDS:
    raise SystemExit(f"LLM_BACKEND must be one of {list(BACKENDS)}")
# Defaults (from LLM_BACKEND); each /chat request may pick another backend + model from the lists above.
CFG = BACKENDS[BACKEND]
BASE, API_KEY, MODEL = CFG["base"].rstrip("/"), CFG["key"], CFG["model"]
DEFAULT_PROMPT = os.environ.get(
    "SYSTEM_PROMPT", "You are a concise, helpful assistant. Answer in at most three sentences.")
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")
CHAT_TOKEN = os.environ.get("CHAT_TOKEN", "")
PROOF_DB = os.environ.get("PROOF_DB", "/data/proofs.db")
MAX_SESSIONS = int(os.environ.get("MAX_SESSIONS", "1000"))
LLM_RETRIES = 3
# End-to-end encryption to the attested Phala gateway (ACI E2EE v2). Only for the phala backend.
E2EE_ON = os.environ.get("E2EE", "1") == "1"
E2EE = BACKEND == "phala" and E2EE_ON


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def log(msg: str) -> None:
    print(f"[AGENT] {msg}", flush=True)


# ---- identity: a signing key derived inside the TEE --------------------------------
tee = TEE()
if tee.mode != "tappd-simulator" and not (ADMIN_TOKEN and CHAT_TOKEN):
    raise SystemExit("ADMIN_TOKEN and CHAT_TOKEN must be set when running on a real CVM")
SIGNER = Ed25519PrivateKey.from_private_bytes(tee.derive_seed("/agent/answer-signing/v1"))
SIGNER_PUB = SIGNER.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
log(f"TEE mode: {tee.mode}")
log(f"answer-signing key (Ed25519, derived from TEE KMS): {SIGNER_PUB.hex()}")
log(f"LLM backend: {BACKEND}  model: {MODEL}  via {BASE}  "
    f"({'TEE-verified inference' if CFG['tee_verified'] else 'NOT TEE-verified'}), key set: {bool(API_KEY)}")
log(f"auth: admin token {'set' if ADMIN_TOKEN else 'OFF'}, chat token {'set' if CHAT_TOKEN else 'OFF'}")

# ---- storage: proofs survive restarts; conversations are capped in memory ----------
os.makedirs(os.path.dirname(PROOF_DB) or ".", exist_ok=True)
db = sqlite3.connect(PROOF_DB, check_same_thread=False)
db.execute("CREATE TABLE IF NOT EXISTS proofs (id TEXT PRIMARY KEY, created INTEGER, body TEXT)")
# Inspector data per answer: raw traffic, stage log, one-time E2EE keys. Admin token only.
db.execute("CREATE TABLE IF NOT EXISTS debug (id TEXT PRIMARY KEY, created INTEGER, body TEXT)")
db_lock = threading.Lock()
log(f"E2EE to gateway: {'ON (' + e2ee.ALGO + ')' if E2EE else 'off'}")
sessions: "OrderedDict[str, list]" = OrderedDict()
usage_totals = {"requests": 0, "prompt_tokens": 0, "completion_tokens": 0, "latency_ms_sum": 0, "errors": 0}
state = {"system_prompt": DEFAULT_PROMPT, "prompt_history": []}
http = httpx.Client(timeout=120)


def set_prompt(p: str) -> None:
    state["system_prompt"] = p
    state["prompt_history"].append({"sha256": sha256(p.encode()), "at": int(time.time())})
    log(f"system prompt set, sha256={sha256(p.encode())[:16]}...")


set_prompt(DEFAULT_PROMPT)
app = FastAPI(title="Verifiable agent on Phala")


# ---- auth -------------------------------------------------------------------------------
def _check(expected: str, authorization: str | None) -> None:
    if not expected:
        return  # auth off (local simulator only)
    got = (authorization or "").removeprefix("Bearer ").strip()
    if not hmac.compare_digest(got.encode(), expected.encode()):
        raise HTTPException(401, "missing or wrong token")


def chat_auth(authorization: str | None = Header(default=None)):
    # the admin token also works for chat endpoints
    if ADMIN_TOKEN and authorization and hmac.compare_digest(
            authorization.removeprefix("Bearer ").strip().encode(), ADMIN_TOKEN.encode()):
        return
    _check(CHAT_TOKEN, authorization)


def admin_auth(authorization: str | None = Header(default=None)):
    _check(ADMIN_TOKEN, authorization)


class PromptIn(BaseModel):
    prompt: str


class ChatIn(BaseModel):
    message: str = ""
    session: str | None = None
    backend: str | None = None   # optional per-request choice, see GET /models
    model: str | None = None


@app.get("/")
def ui():
    return FileResponse(os.path.join(os.path.dirname(__file__), "static", "index.html"))


@app.get("/system-prompt", dependencies=[Depends(chat_auth)])
def get_prompt():
    p = state["system_prompt"]
    return {"prompt": p, "sha256": sha256(p.encode()), "history": state["prompt_history"]}


@app.put("/system-prompt", dependencies=[Depends(admin_auth)])
def put_prompt(body: PromptIn):
    set_prompt(body.prompt)
    return get_prompt()


@app.post("/reset", dependencies=[Depends(chat_auth)])
def reset(body: ChatIn):
    sessions.pop(body.session or "default", None)
    return {"ok": True}


_gw = {"keyset": None, "fetched": 0.0}


def gateway_e2ee_key() -> dict:
    """Fetch the gateway's attested keyset (cached 10 min) and pick its X25519 E2EE key.
    The agent checks the keyset digest and that the quote's report_data binds it to OUR fresh nonce.
    (The full Intel DCAP check of that quote is done independently by verify.py.)"""
    if _gw["keyset"] and time.time() - _gw["fetched"] < 600:
        return _gw["keyset"]
    nonce = os.urandom(32).hex()
    att = http.get(f"{BACKENDS['phala']['base'].rstrip('/')}/v1/aci/attestation", params={"nonce": nonce}).json()
    ks = att["attestation"]["workload_keyset"]
    digest = "sha256:" + sha256(rfc8785.dumps(ks))
    stmt = json.dumps({"keyset_digest": digest, "nonce": nonce, "purpose": "aci.report_data.v1"},
                      separators=(",", ":")).encode()
    if digest != att["workload_keyset_digest"] or att["attestation"]["report_data"] != sha256(stmt):
        raise HTTPException(502, "gateway attestation does not bind its keyset; refusing to encrypt to it")
    key = next(k for k in ks["e2ee_public_keys"] if k["algo"] == e2ee.ALGO)
    _gw.update(keyset={"key": key, "keyset_digest": digest, "attestation_nonce": nonce}, fetched=time.time())
    log(f"gateway E2EE key {key['key_id']} {key['public_key'][:16]}... (keyset {digest[:23]}...)")
    return _gw["keyset"]


def build_request(messages: list, MODEL: str, use_e2ee: bool) -> tuple[bytes, dict, dict]:
    """Returns (wire body bytes, extra headers, e2ee trace). Fresh keys/nonce each call (no replay on retry)."""
    if not use_e2ee:
        return json.dumps({"model": MODEL, "messages": messages}).encode(), {}, {}
    gw = gateway_e2ee_key()
    peer = gw["key"]["public_key"]
    client_priv, client_priv_hex, client_pub_hex = e2ee.new_client_key()
    nonce, ts = os.urandom(32).hex(), int(time.time())
    wire_msgs, fields = [], []
    for i, m in enumerate(messages):
        field = f"messages.{i}.content"
        blob, tr = e2ee.encrypt_field(peer, m["content"],
                                      e2ee.aad("aci.e2ee.request.v2", MODEL, field, nonce, ts))
        wire_msgs.append({**m, "content": blob})
        fields.append({"field": field, "role": m["role"], **tr})
    headers = {"X-E2EE-Version": "2", "X-Client-Pub-Key": client_pub_hex, "X-Model-Pub-Key": peer,
               "X-E2EE-Nonce": nonce, "X-E2EE-Timestamp": str(ts)}
    trace = {"algo": e2ee.ALGO, "gateway_key": gw["key"], "gateway_keyset_digest": gw["keyset_digest"],
             "client_private_one_time": client_priv_hex, "client_public": client_pub_hex,
             "nonce": nonce, "ts": ts, "request_fields": fields, "_client_priv": client_priv}
    return json.dumps({"model": MODEL, "messages": wire_msgs}).encode(), headers, trace


def call_llm(messages: list, stages: list, t0: float, cfg: dict, model: str,
             use_e2ee: bool) -> tuple[httpx.Response, bytes, dict, dict]:
    """POST to the LLM, retrying on 429 / 5xx with exponential backoff."""
    for attempt in range(LLM_RETRIES + 1):
        req_bytes, extra, trace = build_request(messages, model, use_e2ee)
        stages.append((ms(t0), "request built" + (" + E2EE-encrypted" if trace else ""), f"{len(req_bytes)} bytes"))
        headers = {"Authorization": f"Bearer {cfg['key']}", "Content-Type": "application/json", **extra}
        r = http.post(f"{cfg['base'].rstrip('/')}{cfg['path']}", content=req_bytes, headers=headers)
        stages.append((ms(t0), f"LLM responded HTTP {r.status_code}", f"{len(r.content)} bytes"))
        if r.status_code != 429 and r.status_code < 500 or attempt == LLM_RETRIES:
            return r, req_bytes, extra, trace
        wait = float(r.headers.get("retry-after", 0) or 0) or 2 ** attempt
        log(f"LLM {r.status_code}, retry {attempt + 1}/{LLM_RETRIES} in {wait:.0f}s")
        time.sleep(min(wait, 30))
    return r, req_bytes, extra, trace


def ms(t0: float) -> int:
    return int((time.perf_counter() - t0) * 1000)


@app.post("/chat", dependencies=[Depends(chat_auth)])
def chat(body: ChatIn):
    BACKEND = (body.backend or globals()["BACKEND"]).lower()
    if BACKEND not in BACKENDS:
        raise HTTPException(400, f"unknown backend '{BACKEND}'")
    CFG = BACKENDS[BACKEND]
    MODEL = body.model or CFG["model"]
    if MODEL not in CFG["models"]:
        raise HTTPException(400, f"model '{MODEL}' is not offered for backend '{BACKEND}' (see GET /models)")
    if not CFG["key"]:
        raise HTTPException(400, f"API key for backend '{BACKEND}' is not set on this server")
    BASE = CFG["base"].rstrip("/")
    use_e2ee = BACKEND == "phala" and E2EE_ON
    t0 = time.perf_counter()
    stages = [(0, "request received by agent", f"session={body.session or 'default'}")]
    sid = body.session or "default"
    history = sessions.setdefault(sid, [])
    sessions.move_to_end(sid)
    while len(sessions) > MAX_SESSIONS:
        sessions.popitem(last=False)
    system_prompt = state["system_prompt"]
    messages = [{"role": "system", "content": system_prompt}] + history + [{"role": "user", "content": body.message}]
    plain_req = json.dumps({"model": MODEL, "messages": messages}).encode()

    # Send exact bytes we control, so we can hash precisely what went on the wire.
    t_llm = time.perf_counter()
    r, req_bytes, req_headers, trace = call_llm(messages, stages, t0, CFG, MODEL, use_e2ee)
    latency_ms = int((time.perf_counter() - t_llm) * 1000)
    resp_bytes = r.content
    if r.status_code != 200:
        usage_totals["errors"] += 1
        raise HTTPException(502, f"LLM error ({BACKEND}) {r.status_code}: {r.text[:500]}")
    data = r.json()
    if trace:  # decrypt response fields encrypted to our one-time client key
        resp_fields = []
        for i, ch in enumerate(data.get("choices", [])):
            for f in e2ee.RESPONSE_FIELDS:
                v = (ch.get("message") or {}).get(f)
                if isinstance(v, str) and v:
                    field = f"choices.{i}.message.{f}"
                    pt, tr = e2ee.decrypt_field(trace["_client_priv"], v, e2ee.aad(
                        "aci.e2ee.response.v2", MODEL, field, trace["nonce"], trace["ts"], data.get("id") or ""))
                    ch["message"][f] = pt
                    resp_fields.append({"field": field, **tr})
        trace["response_fields"] = resp_fields
        stages.append((ms(t0), "response decrypted", f"{len(resp_fields)} field(s)"))
    answer = data["choices"][0]["message"]["content"]
    usage = data.get("usage") or {}
    usage_totals["requests"] += 1
    usage_totals["prompt_tokens"] += usage.get("prompt_tokens", 0)
    usage_totals["completion_tokens"] += usage.get("completion_tokens", 0)
    usage_totals["latency_ms_sum"] += latency_ms
    history += [{"role": "user", "content": body.message}, {"role": "assistant", "content": answer}]

    # Signed statement: "this TEE agent sent exactly this request and got exactly this response".
    pid = uuid.uuid4().hex
    statement = {
        "proof_id": pid,
        "backend": BACKEND,
        "tee_verified_inference": CFG["tee_verified"],
        "model": MODEL,
        "usage": {"prompt_tokens": usage.get("prompt_tokens"), "completion_tokens": usage.get("completion_tokens")},
        "latency_ms": latency_ms,
        "gateway": BASE,
        "system_prompt_sha256": sha256(system_prompt.encode()),
        "plaintext_request_sha256": sha256(plain_req),
        "request_sha256": sha256(req_bytes),
        "response_sha256": sha256(resp_bytes),
        "e2ee": ({"algo": trace["algo"], "gateway_public_key": trace["gateway_key"]["public_key"],
                  "client_public_key": trace["client_public"], "nonce": trace["nonce"]} if trace else None),
        "receipt_id": r.headers.get("x-receipt-id"),
        "keyset_digest": r.headers.get("x-aci-keyset-digest"),
        "time": int(time.time()),
    }
    sig = SIGNER.sign(canonical(statement)).hex()
    stages.append((ms(t0), "statement signed by agent key (Ed25519)", f"receipt {statement['receipt_id']}"))
    record = {
        "statement": statement,
        "agent_signature": sig,
        "agent_pubkey": SIGNER_PUB.hex(),
        "request_plain_b64": base64.b64encode(plain_req).decode(),
        "request_b64": base64.b64encode(req_bytes).decode(),
        "response_b64": base64.b64encode(resp_bytes).decode(),
    }
    trace.pop("_client_priv", None)
    debug = {
        "stages_ms": stages,
        "request_headers": {k: v for k, v in req_headers.items()} | {"Authorization": "Bearer <redacted>",
                                                                      "Content-Type": "application/json"},
        "request_plain_json": json.loads(plain_req),
        "request_wire_json": json.loads(req_bytes),
        "response_status": r.status_code,
        "response_headers": dict(r.headers),
        "response_wire_json": json.loads(resp_bytes),
        "response_decrypted_json": data,
        "e2ee": trace or None,
        "llm_url": f"{BASE}{CFG['path']}",
        "agent_log": [f"+{t} ms  {s}  {d}" for t, s, d in stages],
    }
    with db_lock:
        db.execute("INSERT INTO proofs VALUES (?, ?, ?)", (pid, statement["time"], json.dumps(record)))
        db.execute("INSERT INTO debug VALUES (?, ?, ?)", (pid, statement["time"], json.dumps(debug)))
        db.commit()
    log(f"answered ({len(answer)} chars) receipt={statement['receipt_id']} proof={pid} in {ms(t0)} ms")
    return {"answer": answer, "proof_id": pid, "statement": statement, "agent_signature": sig}


@app.get("/info")
def info():
    return {"backend": BACKEND, "model": MODEL, "tee_verified_inference": CFG["tee_verified"],
            "tee_mode": tee.mode, "agent_pubkey": SIGNER_PUB.hex(), "e2ee": E2EE,
            "auth": {"admin": bool(ADMIN_TOKEN), "chat": bool(CHAT_TOKEN)}}


@app.get("/models")
def models():
    """Backends that have a key on this server, with their selectable models (public: no secrets)."""
    return {"default": {"backend": BACKEND, "model": MODEL},
            "backends": [{"backend": b, "tee_verified": c["tee_verified"], "default_model": c["model"],
                          "models": c["models"]} for b, c in BACKENDS.items() if c["key"]]}


@app.get("/metrics", dependencies=[Depends(admin_auth)])
def metrics():
    """Token and latency totals since start: input for the cost tests."""
    n = usage_totals["requests"] or 1
    return usage_totals | {"avg_latency_ms": usage_totals["latency_ms_sum"] // n, "backend": BACKEND, "model": MODEL}


@app.get("/debug/{pid}", dependencies=[Depends(admin_auth)])
def debug_record(pid: str):
    """Inspector data: raw traffic, stage timings, one-time E2EE keys. Admin only."""
    with db_lock:
        row = db.execute("SELECT body FROM debug WHERE id = ?", (pid,)).fetchone()
    if not row:
        raise HTTPException(404, "unknown proof id")
    return json.loads(row[0])


@app.get("/proof/{pid}", dependencies=[Depends(chat_auth)])
def proof(pid: str):
    with db_lock:
        row = db.execute("SELECT body FROM proofs WHERE id = ?", (pid,)).fetchone()
    if not row:
        raise HTTPException(404, "unknown proof id")
    return json.loads(row[0])


@app.get("/attestation")
def attestation(nonce: str):
    """report_data = sha256(agent_pubkey) || sha256(nonce): binds our key AND your freshness nonce.
    On a real CVM this also returns app_compose, so a verifier can check which compose file was booted."""
    n = bytes.fromhex(nonce)
    rd = hashlib.sha256(SIGNER_PUB).digest() + hashlib.sha256(n).digest()
    q = tee.quote(rd)
    return {"tee_mode": tee.mode, "agent_pubkey": SIGNER_PUB.hex(), "nonce": nonce, **q, **tee.app_info()}

r"""Inspector: follow one answer through every hop and render all raw evidence as a local HTML page.

  .\.venv\Scripts\python agent-poc\verifier\inspect_answer.py <proof_id> [--agent URL] [--expect-compose FILE] [--no-open]
  .\.venv\Scripts\python agent-poc\verifier\inspect_answer.py --ask "your question" [--agent URL]

Runs the full verifier (layers A-E) on your machine, outside the agent, then writes
agent-poc/inspector/<proof_id>.html. Needs PHALA_API_KEY and ADMIN_TOKEN (for raw traffic and one-time keys).
"""

import argparse
import base64
import hashlib
import html
import json
import os
import sys
import time
import webbrowser
from urllib.parse import urlparse

import requests

sys.path.insert(0, os.path.dirname(__file__))
from gateway_attestation import tls_info  # noqa: E402
from verify import load_env, run_all  # noqa: E402

OUT = os.path.join(os.path.dirname(__file__), "..", "inspector")

# TDX quote v4: 48-byte header + TD report body (offsets inside the body)
BODY = 48
FIELDS = [("tee_tcb_svn", 0, 16), ("mr_seam", 16, 48), ("mr_td", 136, 48), ("mr_config_id", 184, 48),
          ("rtmr0", 328, 48), ("rtmr1", 376, 48), ("rtmr2", 424, 48), ("rtmr3", 472, 48), ("report_data", 520, 64)]
FIELD_HELP = {
    "mr_td": "hash of the initial VM image (firmware) - same for every CVM on this OS version",
    "mr_config_id": "dstack puts the app's compose hash here on some setups",
    "rtmr0": "firmware configuration", "rtmr1": "OS kernel", "rtmr2": "kernel command line / initrd",
    "rtmr3": "runtime events: app-id, compose-hash, instance-id, key provider ... (replayed below)",
    "report_data": "64 bytes chosen by the software in the TEE - this is how a key or nonce is bound to the quote",
    "tee_tcb_svn": "TDX module security version", "mr_seam": "hash of the Intel TDX module",
}

E = html.escape


def parse_quote(qhex: str) -> dict:
    q = bytes.fromhex(qhex.removeprefix("0x"))
    out = {"version": int.from_bytes(q[0:2], "little"), "tee_type": hex(int.from_bytes(q[4:8], "little")),
           "size_bytes": len(q)}
    for name, off, size in FIELDS:
        out[name] = q[BODY + off:BODY + off + size].hex()
    return out


def replay_steps(event_log: list, imr: int = 3) -> list:
    rtmr, steps = b"\x00" * 48, []
    for ev in event_log:
        if ev["imr"] == imr:
            rtmr = hashlib.sha384(rtmr + bytes.fromhex(ev["digest"])).digest()
            steps.append((ev.get("event") or f"type {ev['event_type']}", ev["digest"], rtmr.hex(), ev.get("event_payload", "")))
    return steps


def payload_text(name: str, p: str) -> str:
    try:
        b = bytes.fromhex(p)
        t = b.decode()
        if t.isprintable() and len(t) < 120:
            return t
    except Exception:  # noqa: BLE001
        pass
    return p


# ---------------------------------------------------------------- html bits -----
def code(obj, cls="") -> str:
    s = obj if isinstance(obj, str) else json.dumps(obj, indent=2, ensure_ascii=False)
    return f'<pre class="code {cls}">{E(s)}</pre>'


def kv(rows: list, cls="kv") -> str:
    tr = "".join(f"<tr><th>{E(str(k))}</th><td>{v if isinstance(v, Raw) else E(str(v))}</td></tr>" for k, v in rows)
    return f'<table class="{cls}">{tr}</table>'


class Raw(str):
    pass


def hexv(s: str) -> Raw:
    return Raw(f'<span class="hex">{E(s)}</span>')


def details(title: str, body: str, open_=False) -> str:
    return f"<details{' open' if open_ else ''}><summary>{E(title)}</summary>{body}</details>"


def badge(status: str) -> str:
    return f'<span class="b b-{status.lower()}">{status}</span>'


def section(id_: str, title: str, lead: str, body: str) -> str:
    return f'<section id="{id_}"><h2>{E(title)}</h2><p class="lead">{lead}</p>{body}</section>'


# ---------------------------------------------------------------- sections -----
def sec_journey(proof, debug, art) -> str:
    st = proof["statement"]
    rows = []
    for t, s, d in (debug or {}).get("stages_ms", []):
        rows.append(f"<tr><td class='t'>+{t} ms</td><td>Agent CVM</td><td>{E(s)}</td><td class='hex'>{E(d)}</td></tr>")
    for ev in art.get("receipt", {}).get("event_log", []):
        detail = ev.get("body_hash") or ev.get("target_route_id") or (
            f"{ev.get('result')} (session {ev.get('session_id', '')[:16]}...)" if ev.get("session_id") else "")
        rows.append(f"<tr><td class='t'>gateway</td><td>Gateway enclave</td><td>{E(ev['type'])}</td>"
                    f"<td class='hex'>{E(str(detail))}</td></tr>")
    hops = ("<div class='hops'><div>You<br><small>this machine</small></div><span>&rarr;</span>"
            "<div>Agent CVM<br><small>Intel TDX</small></div><span>&rarr;</span>"
            "<div>Phala gateway<br><small>Intel TDX</small></div><span>&rarr;</span>"
            "<div>Model server<br><small>TDX + NVIDIA H100</small></div></div>")
    lead = (f"One question, followed hop by hop. The agent spent {st['latency_ms']} ms waiting for the LLM. "
            "Agent rows come from the agent's own log; gateway rows come from the receipt the gateway enclave signed.")
    return section("journey", "1. Journey of this answer", lead,
                   hops + f"<table class='grid'><tr><th>When</th><th>Where</th><th>Step</th><th>Detail</th></tr>{''.join(rows)}</table>")


def sec_traffic(proof, debug, art) -> str:
    if not debug:
        return section("traffic", "2. Raw LLM traffic", "Needs ADMIN_TOKEN.", "")
    b = details("Request the agent built (plaintext, before encryption)", code(debug["request_plain_json"]), True)
    b += details("HTTP request headers sent to the gateway", code(debug["request_headers"]), True)
    b += details("Request body actually on the wire (encrypted fields)", code(debug["request_wire_json"]))
    if art.get("restored_request"):
        b += details("What the gateway enclave got after decrypting (its receipt hashes exactly these bytes)",
                     code(json.loads(art["restored_request"])))
    b += details("HTTP response headers", code(debug["response_headers"]), True)
    b += details("Response body on the wire (encrypted fields)", code(debug["response_wire_json"]))
    b += details("Response after the agent decrypted it", code(debug["response_decrypted_json"]), True)
    b += details("Agent log for this request", code("\n".join(debug.get("agent_log", []))), True)
    return section("traffic", "2. Raw LLM traffic",
                   f"Exactly what went between the agent and <code>{E(debug['llm_url'])}</code>. "
                   "The API key is redacted; everything else is byte-for-byte.", b)


def sec_e2ee(proof, debug, art) -> str:
    tr = (debug or {}).get("e2ee")
    if not tr:
        return section("e2ee", "3. Encryption keys", "E2EE was off for this answer (or ADMIN_TOKEN missing).", "")
    gk = tr["gateway_key"]
    head = kv([
        ("Suite", tr["algo"]),
        ("Gateway E2EE public key", hexv(gk["public_key"])),
        ("  key id", gk["key_id"]),
        ("  where it comes from", "the gateway's attested keyset (bound to its Intel-signed quote, see section 5)"),
        ("Agent one-time client private key", hexv(tr["client_private_one_time"])),
        ("Agent one-time client public key", hexv(tr["client_public"])),
        ("Request nonce (X-E2EE-Nonce)", hexv(tr["nonce"])),
        ("Timestamp (X-E2EE-Timestamp)", f"{tr['ts']}  ({time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(tr['ts']))})"),
    ])
    formula = code("For every field:\n"
                   "  shared  = X25519(ephemeral_private, other_side_public)\n"
                   "  key     = HKDF-SHA256(salt=none, ikm=shared, info=\"aci.e2ee.v2.x25519\", 32 bytes)\n"
                   "  aad     = JCS({purpose, algo, model, field, nonce, ts[, id]})   <- binds the ciphertext to this request\n"
                   "  blob    = ephemeral_public(32) || aes_nonce(12) || AES-256-GCM(key, aes_nonce, plaintext, aad) || tag(16)", "small")
    rows = ""
    for f in tr["request_fields"]:
        rows += details(f"Request field {f['field']}  ({f['role']})", kv([
            ("Plaintext", f["plaintext"]),
            ("Ephemeral private key (one-time)", hexv(f["ephemeral_private"])),
            ("Ephemeral public key", hexv(f["ephemeral_public"])),
            ("X25519 shared secret", hexv(f["shared_secret"])),
            ("AES-256 key (HKDF output)", hexv(f["aes_key"])),
            ("AES-GCM nonce", hexv(f["aes_nonce"])),
            ("Associated data (AAD)", Raw(f"<code>{E(f['aad'])}</code>")),
            ("Ciphertext blob on the wire", hexv(f["ciphertext_blob"])),
        ]), f["role"] == "user")
    for f in tr.get("response_fields", []):
        rows += details(f"Response field {f['field']}  (decrypted by the agent)", kv([
            ("Gateway's ephemeral public key (from the blob)", hexv(f["server_ephemeral_public"])),
            ("X25519 shared secret (agent one-time key x that)", hexv(f["shared_secret"])),
            ("AES-256 key (HKDF output)", hexv(f["aes_key"])),
            ("AES-GCM nonce", hexv(f["aes_nonce"])),
            ("Associated data (AAD)", Raw(f"<code>{E(f['aad'])}</code>")),
            ("Ciphertext blob on the wire", hexv(f["ciphertext_blob"])),
            ("Decrypted plaintext", f["plaintext"]),
        ]), True)
    lead = ("The agent encrypts every message to the gateway enclave's attested key, so the prompt is unreadable anywhere "
            "between the agent CVM and the gateway enclave (even to a TLS-terminating proxy). The answer comes back "
            "encrypted to a one-time key the agent made for this request. All keys shown are <b>one-time</b> keys; "
            "the long-term private keys never leave their TEEs and are never shown. Section 8 re-does this math independently (checks E2, E3).")
    return section("e2ee", "3. Encryption and decryption keys", lead, head + formula + rows)


def sec_tls(agent_url, art) -> str:
    rows = []
    gw = art.get("gateway_tls")
    pins = [k for k in art.get("gateway_attestation", {}).get("attestation", {}).get("workload_keyset", {}).get("tls_public_keys", [])]
    if gw:
        pin_ok = any(p["spki_sha256"] == gw["spki_sha256"] and p["domain"] == gw["host"] for p in pins)
        rows.append(details(f"Your machine -> {gw['host']} (Phala gateway)", kv(list(gw.items()) + [
            ("attested pin", "MATCH: this TLS key is listed in the gateway's attested keyset" if pin_ok else "NO MATCH")]), True))
    host = urlparse(agent_url).hostname
    if urlparse(agent_url).scheme == "https":
        try:
            rows.append(details(f"Your machine -> {host} (agent, via Phala's dstack gateway)", kv(list(tls_info(host).items())), True))
        except Exception as e:  # noqa: BLE001
            rows.append(f"<p>could not read TLS for {E(host)}: {E(str(e))}</p>")
    else:
        rows.append(f"<p>The agent was reached over plain HTTP ({E(agent_url)}): either local testing, or the internal "
                    "network inside the same confidential VM (the verifier service runs next to the agent).</p>")
    sess = art.get("session", {})
    if sess.get("channel_binding"):
        rows.append(details("Gateway -> model server (as recorded in the attested session)", code(sess["channel_binding"])))
    lead = ("TLS protects each network hop. What makes it trustworthy here is the <b>pin</b>: the TLS key the server presents "
            "must be one that its TEE quote vouches for, so the TLS session ends inside the enclave.")
    return section("tls", "4. TLS on each hop", lead, "".join(rows))


def quote_block(title: str, qhex: str, event_log_json, binding: str) -> str:
    q = parse_quote(qhex)
    rows = [("quote version / TEE type / size", f"v{q['version']} / {q['tee_type']} (0x81 = Intel TDX) / {q['size_bytes']} bytes")]
    for name, _, _ in FIELDS:
        rows.append((f"{name}", Raw(f"{hexv(q[name])}<div class='help'>{E(FIELD_HELP.get(name, ''))}</div>")))
    rows.append(("report_data binding", binding))
    body = kv(rows)
    if event_log_json:
        log = json.loads(event_log_json) if isinstance(event_log_json, str) else event_log_json
        named = [e for e in log if e.get("event")]
        ev_rows = "".join(f"<tr><td>{e['imr']}</td><td>{E(e['event'])}</td><td class='hex'>{E(payload_text(e['event'], e.get('event_payload', '')))}</td></tr>" for e in named)
        body += details(f"Event log: {len(log)} events ({len(named)} named runtime events)",
                        f"<table class='grid'><tr><th>RTMR</th><th>event</th><th>payload</th></tr>{ev_rows}</table>")
        steps = replay_steps(log, 3)
        st_rows = "".join(f"<tr><td>{i + 1}</td><td>{E(n)}</td><td class='hex'>{E(d[:24])}...</td><td class='hex'>{E(v)}</td></tr>"
                          for i, (n, d, v, _) in enumerate(steps))
        match = steps and steps[-1][2] == q["rtmr3"]
        body += details(f"RTMR3 replay: RTMR3 = SHA-384(RTMR3 || event digest), {len(steps)} steps -> "
                        f"{'MATCHES the quote' if match else 'does NOT match'}",
                        f"<table class='grid'><tr><th>#</th><th>event</th><th>digest</th><th>RTMR3 after</th></tr>{st_rows}</table>")
    body += details("Raw quote (hex)", f"<pre class='code hex'>{E(qhex)}</pre>")
    return details(title, body, True)


def sec_attestation(art) -> str:
    out = ""
    a = art.get("agent_attestation")
    if a:
        out += quote_block(f"Agent CVM quote ({a['tee_mode']})", a["quote"], a.get("event_log"),
                           f"sha256(agent signing key {a['agent_pubkey'][:16]}...) || sha256(our nonce {art['agent_nonce'][:16]}...)")
        if a.get("app_compose"):
            out += details("Agent app_compose (its sha256 is the compose-hash event in RTMR3)", code(json.loads(a["app_compose"])))
    g = art.get("gateway_attestation")
    if g:
        ev = g["attestation"]["evidence"]
        out += quote_block("Phala gateway quote", ev["quote"], ev.get("event_log"),
                           f"sha256({{keyset_digest, nonce={art['gateway_nonce'][:16]}..., purpose}}) || 32 zero bytes")
        out += details("Gateway attested keyset (signing, E2EE and TLS keys)", code(g["attestation"]["workload_keyset"]))
    m = art.get("model_server_evidence")
    if m:
        out += quote_block("Model server quote (GPU machine running the LLM)", m["intel_quote"], m.get("event_log"),
                           f"sha256(signing address {m['signing_address'][:12]}... || TLS fingerprint) || nonce {m['request_nonce'][:16]}...")
    lead = ("A quote is a report signed by the Intel CPU: it lists what was booted (measurements) plus 64 bytes of "
            "<code>report_data</code> chosen by the software inside. Every quote here was fetched with a fresh random nonce "
            "from this machine, so none can be a replay.")
    return section("attestation", "5. TEE quotes, decoded", lead, out)


def sec_receipt(art) -> str:
    rc = art.get("receipt")
    if not rc:
        return ""
    return section("receipt", "6. Gateway receipt",
                   "Signed by the gateway enclave (Ed25519, key from the attested keyset) over JCS(receipt without signature).",
                   kv([("receipt id", rc.get("receipt_id")), ("key id", rc.get("key_id")),
                       ("signature", hexv(rc.get("signature", ""))), ("served at", rc.get("served_at"))]) + code(rc))


def sec_model(art) -> str:
    sess, nv = art.get("session"), art.get("nras")
    if not sess:
        return ""
    b = details("Session claims (the gateway's verifier output)", code(sess.get("claims")), True)
    if nv:
        b += details("NVIDIA NRAS result, decoded (overall + per GPU)", code(nv), True)
    m = art.get("model_server_evidence", {})
    if m:
        compose = json.loads(m["info"]["tcb_info"]["app_compose"])
        b += details("Model server docker-compose (measured into its RTMR3)", code(compose.get("docker_compose_file", "")))
    return section("model", "7. Model server and GPU", f"Endpoint <code>{E(sess.get('endpoint', ''))}</code>.", b)


def sec_checks(rep) -> str:
    rows, layer = "", None
    for lay, status, name, detail, proves in rep.items:
        if lay != layer:
            rows += f"<tr class='layer'><td colspan='3'>{E(lay)}</td></tr>"
            layer = lay
        rows += (f"<tr><td>{badge(status)}</td><td><b>{E(name)}</b>"
                 f"{'<div class=help>' + E(detail) + '</div>' if detail else ''}</td><td>{E(proves)}</td></tr>")
    return section("checks", "8. Every check", "Run by the verifier, a separate program that trusts nothing the agent says "
                   "(on your machine via inspect_answer.py, or the verifier service next to the agent in the demo).",
                   f"<table class='grid checks'><tr><th></th><th>Check</th><th>What it proves</th></tr>{rows}</table>")


CSS = """
:root{--bg:#f7f7f5;--panel:#fff;--ink:#1d1d1b;--muted:#6b6b66;--line:#e2e1dc;--accent:#2f6fde;--ok:#1a7f37;--bad:#c62828;--code:#f2f1ed}
@media (prefers-color-scheme: dark){:root{--bg:#191918;--panel:#232321;--ink:#ecebe6;--muted:#a3a29c;--line:#3a3936;--accent:#7aa7ff;--ok:#57c26b;--bad:#ff6b6b;--code:#1c1c1b}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 system-ui,sans-serif}
main{max-width:1100px;margin:0 auto;padding:24px 16px 80px}h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:0 0 4px}
nav{position:sticky;top:0;background:var(--bg);padding:8px 0;border-bottom:1px solid var(--line);margin-bottom:16px;display:flex;gap:12px;flex-wrap:wrap;z-index:2}
nav a{color:var(--accent);text-decoration:none;font-size:13px}
section{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px;margin:16px 0}
.lead{color:var(--muted);margin:0 0 12px}.summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px;margin:12px 0}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px}.card .n{font-size:22px;font-weight:600}
details{border:1px solid var(--line);border-radius:8px;margin:8px 0;padding:0 10px}summary{cursor:pointer;padding:8px 0;font-weight:600}
pre.code{background:var(--code);border-radius:6px;padding:10px;overflow:auto;max-height:520px;font:12px/1.45 ui-monospace,Consolas,monospace;white-space:pre-wrap;word-break:break-all}
pre.small{font-size:12px}.hex,code{font-family:ui-monospace,Consolas,monospace;font-size:12px;word-break:break-all}
table{border-collapse:collapse;width:100%;margin:6px 0}th,td{text-align:left;vertical-align:top;padding:6px 8px;border-bottom:1px solid var(--line)}
table.kv th{width:28%;color:var(--muted);font-weight:500}.help{color:var(--muted);font-size:12px;margin-top:2px}
.grid th{color:var(--muted);font-weight:500}.t{white-space:nowrap;color:var(--muted)}tr.layer td{font-weight:600;padding-top:14px}
.b{display:inline-block;padding:1px 8px;border-radius:99px;font-size:11px;font-weight:700;color:#fff}.b-pass{background:var(--ok)}.b-fail{background:var(--bad)}.b-info{background:var(--muted)}
.hops{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin:8px 0 12px}.hops div{border:1px solid var(--line);border-radius:8px;padding:8px 12px;text-align:center}
.hops small{color:var(--muted)}.answer{font-size:15px;border-left:3px solid var(--accent);padding:6px 12px;margin:8px 0}
"""


def render(rep, proof, debug, agent_url) -> str:
    st, art = proof["statement"], rep.artifacts
    plain = json.loads(base64.b64decode(proof.get("request_plain_b64") or proof["request_b64"]))
    question = plain["messages"][-1]["content"]
    answer = (debug or {}).get("response_decrypted_json", {}).get("choices", [{}])[0].get("message", {}).get("content", "")
    n_pass = sum(1 for i in rep.items if i[1] == "PASS")
    n_fail = sum(1 for i in rep.items if i[1] == "FAIL")
    cards = (f"<div class='summary'><div class='card'><div class='n'>{n_pass} passed / {n_fail} failed</div>checks run by the verifier</div>"
             f"<div class='card'><div class='n'>{E(st['model'])}</div>{'TEE-verified inference' if st['tee_verified_inference'] else 'NOT TEE-verified'}</div>"
             f"<div class='card'><div class='n'>{'E2EE on' if st.get('e2ee') else 'TLS only'}</div>{E((st.get('e2ee') or {}).get('algo', 'agent -> gateway'))}</div>"
             f"<div class='card'><div class='n'>{st['usage']['prompt_tokens']} + {st['usage']['completion_tokens']}</div>tokens in + out</div></div>")
    nav = "".join(f"<a href='#{i}'>{t}</a>" for i, t in [("journey", "Journey"), ("traffic", "Raw traffic"), ("e2ee", "Keys"),
                                                          ("tls", "TLS"), ("attestation", "Quotes"), ("receipt", "Receipt"),
                                                          ("model", "Model + GPU"), ("checks", "Checks")])
    head = (f"<h1>Inspector: answer {E(st['proof_id'])}</h1><p class='lead'>Agent {E(agent_url)} &middot; "
            f"{time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(st['time']))} &middot; system prompt sha256 "
            f"<code>{E(st['system_prompt_sha256'][:16])}...</code></p>"
            f"<p><b>System prompt:</b> {E(plain['messages'][0]['content'])}</p><p><b>Question:</b> {E(question)}</p>"
            f"<div class='answer'>{E(answer)}</div>{cards}")
    body = (sec_journey(proof, debug, art) + sec_traffic(proof, debug, art) + sec_e2ee(proof, debug, art) +
            sec_tls(agent_url, art) + sec_attestation(art) + sec_receipt(art) + sec_model(art) + sec_checks(rep))
    return (f"<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
            f"<title>Answer Inspector</title><style>{CSS}</style></head><body><main><nav>{nav}</nav>{head}{body}</main></body></html>")


def main():
    load_env()
    ap = argparse.ArgumentParser()
    ap.add_argument("proof_id", nargs="?")
    ap.add_argument("--ask", help="ask this question first (uses ADMIN_TOKEN), then inspect the answer")
    ap.add_argument("--agent", default=os.environ.get("AGENT_URL", "http://localhost:8000"))
    ap.add_argument("--expect-compose")
    ap.add_argument("--no-open", action="store_true")
    a = ap.parse_args()
    agent = a.agent.rstrip("/")
    pid = a.proof_id
    if a.ask:
        r = requests.post(f"{agent}/chat", json={"message": a.ask, "session": os.urandom(8).hex()}, timeout=180,
                          headers={"Authorization": f"Bearer {os.environ.get('ADMIN_TOKEN', '')}"})
        r.raise_for_status()
        pid = r.json()["proof_id"]
        print("answer:", r.json()["answer"])
    if not pid:
        sys.exit("give a proof_id or --ask")
    rep, proof, debug = run_all(pid, agent, a.expect_compose)
    os.makedirs(OUT, exist_ok=True)
    path = os.path.abspath(os.path.join(OUT, f"{pid}.html"))
    with open(path, "w", encoding="utf-8") as f:
        f.write(render(rep, proof, debug, agent))
    print(f"\nInspector page: {path}")
    if not a.no_open:
        webbrowser.open("file:///" + path.replace("\\", "/"))


if __name__ == "__main__":
    main()

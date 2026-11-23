# Verifiable AI agent on Phala TEE (POC)

A small chat agent with a system prompt you can change at runtime. Its LLM inference runs inside
Phala's TEEs (Intel TDX + NVIDIA H100). A standalone verifier proves, for any single answer,
**which prompt went in, which answer came out, and that both passed only through attested hardware.**

The goal is verifiability of execution, not confidentiality.

```
 Client / verify.py ──▶ Agent (our CVM) ──▶ Phala AI gateway (TDX) ──▶ Model server (TDX + H100)
        ▲                    │                       │                          │
        └──── evidence: agent quote · gateway quote · signed receipt · model-server session ◀┘
```

Locally, "our CVM" is two Docker containers: the agent, and Phala's dstack TEE simulator. On a
Phala CVM, the same compose file runs on real TDX hardware (see "Moving to a real Phala CVM").

---

## 1. Prerequisites

- Docker Desktop
- Python 3.11+ (for the verifier and the tests, which run on your machine, outside the agent)
- A Phala account with a **Private AI API key** and a small balance (cloud.phala.com → Private AI → API Keys).
  Gifted credits don't pay for Private AI. All the tests in this README together cost about $0.02.

## 2. Setup (once)

From the project root (the folder that contains `agent-poc`):

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -r agent-poc\verifier\requirements.txt
copy agent-poc\.env.example agent-poc\.env
notepad agent-poc\.env        # paste your key after PHALA_API_KEY=
```

`.env` holds secrets. Never commit or share it.

## 3. Run the agent

```powershell
cd agent-poc
docker compose up -d --build
docker compose logs agent      # shows TEE mode, signing key, backend and model
```

Open **http://localhost:8000**:
- **System prompt:** edit it and click *Save prompt*. Its sha256 appears next to the button.
- **Chat:** every answer shows the backend, the model, whether the inference was TEE-verified, the
  `proof_id`, the receipt id, the tokens used and the latency.

### API

Locally, `ADMIN_TOKEN` and `CHAT_TOKEN` are unset, so the endpoints are open. On a CVM they're required (see section 6).

| Method | Path | What it does |
| --- | --- | --- |
| GET | `/system-prompt` | Current prompt, its sha256, and the change history |
| PUT | `/system-prompt` | `{"prompt": "..."}` changes it immediately |
| POST | `/chat` | `{"message": "...", "session": "optional"}` returns the answer + a signed statement |
| POST | `/reset` | `{"session": "..."}` clears a conversation |
| GET | `/proof/{proof_id}` | Full evidence for one answer (exact request/response bytes) |
| GET | `/attestation?nonce=<64 hex>` | The agent's TDX quote, binding its signing key and your nonce |
| GET | `/info`, `/metrics` | Backend/model info; token and latency totals |
| GET | `/debug/{proof_id}` | Admin only: raw LLM traffic, stage log and one-time E2EE keys (used by the Inspector) |

PowerShell example:
```powershell
Invoke-RestMethod -Method Put http://localhost:8000/system-prompt -ContentType 'application/json' -Body '{"prompt":"You are a pirate. One sentence."}'
Invoke-RestMethod -Method Post http://localhost:8000/chat -ContentType 'application/json' -Body '{"message":"What is 2+2?"}'
```

### LLM backend

Set `LLM_BACKEND` before `docker compose up -d`. The default is `phala`.

| Value | Provider and default model | TEE-verified inference |
| --- | --- | --- |
| `phala` | Phala Private AI, `qwen/qwen-2.5-7b-instruct`, the cheapest chat model ($0.10 / $0.20 per 1M tokens) | **Yes** |
| `gemini` | Google Gemini, `gemini-2.5-flash-lite` | No |
| `openai` | OpenAI, `gpt-4.1-mini` | No |

You can override the model with `PHALA_MODEL`, `GEMINI_MODEL` or `OPENAI_MODEL` in `.env`. Answers from
`gemini` and `openai` are labelled *NOT TEE-verified* everywhere.

## 4. Verify an answer

Copy a `proof_id` from the chat, then run this from the project root:

```powershell
.\.venv\Scripts\python agent-poc\verifier\verify.py <proof_id>
```

The verifier runs outside the agent and trusts nothing the agent says. It checks four layers and
prints PASS/FAIL for each check, plus what that check proves:

| # | Check | What it proves |
| --- | --- | --- |
| **A** | **Our agent** | |
| A1 | Agent quote `report_data` = sha256(agent key) ‖ sha256(our nonce) | The key that signs answers lives in this TEE, and the quote is fresh |
| A2 | Event log replays to RTMR0-3 | The boot measurements are consistent |
| A3 | Intel signature on the agent quote | *Skipped locally:* the simulator's quote isn't hardware-signed. Real on a CVM |
| A4 | Ed25519 signature over the answer statement | The agent vouches for the model, prompt hash, request/response hashes and receipt id |
| A5 | Request/response bytes match the signed hashes | Shows the exact system prompt and messages that were sent |
| **B** | **Phala AI gateway** (`inference.phala.com`) | |
| 1 | Intel DCAP signature + TCB status (`dcap-qvl`) | A genuine, patched Intel TDX CPU produced the quote |
| 2 | Keyset digest (RFC 8785 JCS + SHA-256) | The keys we read are the ones the enclave committed to |
| 3 | `report_data` = sha256({keyset_digest, nonce, purpose}) | The quote is fresh (made for our nonce) and vouches for the signing and TLS keys |
| 4 | Event log → RTMR3; compose-hash = sha256(app_compose) | Exactly this gateway code and config was booted |
| 5 | Keyset expiry | The keys are within their validity window |
| 6 | TLS key pin | Our HTTPS connection terminates inside that enclave |
| **C** | **This answer** (receipt) | |
| C1 | Receipt cites the attested keyset | It was issued under the keys verified in layer B |
| C2 | Ed25519 receipt signature | The enclave signed it; it can't be forged outside the TEE |
| C3 | Receipt request hash = our exact request bytes | The enclave received exactly this system prompt + messages |
| C4 | Receipt response hash = our exact response bytes | The answer is exactly what the enclave returned |
| C5 | `upstream.verified` event | The gateway verified the model server before routing to it |
| **D** | **The model server that ran the LLM** | |
| D1, D2 | Session id = sha256(JCS(session)); evidence digest | The evidence is the one the signed receipt points to |
| D3 | Model server TDX quote: Intel DCAP + TCB | The model runs in a genuine, patched TDX VM |
| D4 | `report_data` = sha256(signing address ‖ TLS fingerprint) ‖ nonce | Its keys were generated inside that VM, for a fresh nonce |
| D5 | Gateway channel pinned to that TLS key | The gateway really talked to that VM |
| D6 | Event log → RTMR3; compose-hash = sha256(app_compose) | The exact inference software (container images by digest) that was booted |
| D7 | **NVIDIA NRAS** GPU attestation, same nonce | A real NVIDIA H100 in confidential-computing mode, debug off, measurements OK |
| D8 | Our request was served inside the session's validity window | That verified session was the one in force |

**Not proven**, as Phala's own claims also state:
- **Which model weights were loaded.** `model_weights_provenance: unknown`
- **That the GPU is cryptographically bound to that CPU TEE.** Both pieces of evidence share a nonce, nothing more.

To check only the gateway, which needs no key:
```powershell
.\.venv\Scripts\python agent-poc\verifier\gateway_attestation.py
```

### Inspector: see everything for one answer

```powershell
.\.venv\Scripts\python agent-poc\verifier\inspect_answer.py --ask "What is a TEE?" --agent <url> --expect-compose agent-poc\deploy\docker-compose.cvm.yml
.\.venv\Scripts\python agent-poc\verifier\inspect_answer.py <proof_id> --agent <url>
```

This runs the full verifier, then writes and opens `agent-poc/inspector/<proof_id>.html`. It needs
`PHALA_API_KEY` and `ADMIN_TOKEN` in `.env`. The page has these sections:

1. **Journey:** each step with timings, from the agent's own log and the gateway's signed receipt.
2. **Raw LLM traffic:** the plaintext request, the HTTP headers, the encrypted request on the wire, the encrypted
   response, the decrypted response, and the exact bytes the gateway enclave hashed after decrypting.
3. **Encryption and decryption keys:** the gateway's attested E2EE key, the agent's one-time client key pair,
   and, for every field, the ephemeral keys, X25519 shared secret, HKDF-derived AES key, nonce, AAD and ciphertext.
4. **TLS on each hop:** version, cipher, certificate and SPKI pin, compared with the attested keyset.
5. **TEE quotes, decoded:** the agent, gateway and model-server quotes, split into fields, with their event logs
   and a step-by-step RTMR3 replay.
6. **Gateway receipt**, 7. **Model server and NVIDIA GPU claims**, 8. **every check, with what it proves.**

**End-to-end encryption (on by default with the `phala` backend; set `E2EE=0` to turn it off).** The agent
encrypts every message to the gateway enclave's attested X25519 key (Phala ACI E2EE v2: X25519 → HKDF-SHA256 →
AES-256-GCM, with a JCS associated-data block binding the model, field, nonce and timestamp). The answer comes back
encrypted to a one-time key. Layer E of the verifier re-encrypts the plaintext with the disclosed one-time keys and
gets the exact wire bytes (E2), and decrypts the response itself (E3). Only one-time keys are ever disclosed, and
only to the admin token through `GET /debug/{proof_id}`.

### Demo page (for sharing)

The CVM also runs a demo service on port 8080. It's a web page where a visitor types a question, optionally
changes the system prompt, clicks **Run test**, and sees the answer, a pass/fail verdict and the full Inspector
report. Earlier runs are listed. It uses the same verifier code as `verify.py`, running in its own container next
to the agent, so it's part of the attested compose too. For fully independent verification, run `verify.py` on your
own machine.

```powershell
.\agent-poc\deploy\deploy.ps1 link     # prints the shareable link: <demo_url>#code=<DEMO_TOKEN>
```

The access code is `DEMO_TOKEN` in `.env`, generated on the first `apply`. It's separate from the chat and admin
tokens. It rides in the `#fragment`, which browsers never send to the server. To revoke a link, change
`DEMO_TOKEN` and run `apply`. The CVM must be running while the page is in use. Locally, the page is at
http://localhost:8080.

## 5. Cost tests

The scripts are in `agent-poc/tests`; results go to `tests/results/`. Run them from the project root
with the agent up on the `phala` backend:

```powershell
.\.venv\Scripts\python agent-poc\tests\test2_questions.py          # tokens and cost per single question
cd agent-poc; docker compose -f docker-compose.yml -f tests/compose.small.yml up -d; cd ..
.\.venv\Scripts\python agent-poc\tests\test1_load.py --label small  # throughput at tdx.small size
.\.venv\Scripts\python agent-poc\tests\test3_verify_overhead.py    # verification time per answer
```

Results from 2026-11-20, with the cheapest model:
- **$0.000046 per question**, which is about $46 per million questions.
- **One tdx.small handles about 16 requests/s** at under 20% CPU. The limit was Phala's API rate limit
  (about 300 requests/min on our account), not the CVM.
- **CVMs are the cost:** about $44 per tdx.small per month, always on with 20 GB disk.

## 6. Deploy to Phala Cloud (Terraform)

Everything is in `agent-poc/deploy`:
- **`docker-compose.cvm.yml`** is the CVM compose file. It has no simulator, mounts `/var/run/dstack.sock`,
  passes secrets as `${VAR}`, and pins the image by digest. Its hash is measured into each CVM's RTMR3.
- **`terraform/`** holds a `phala_app` resource using the official provider `phala-network/phala`,
  pinned to `0.3.0-beta.5` (Phala's API rejects 0.2.x). It sets size, encrypted env vars and public
  TCB info. Optional `phala_app_instance` resources add more CVMs of the same app.
- **`deploy.ps1`** builds and pushes the image, pins the digest, and runs Terraform. Terraform runs in the
  `hashicorp/terraform` container, so you don't need it installed.

Add these to `agent-poc/.env` first: `PHALA_CLOUD_API_KEY` (Phala Cloud → Settings → API Keys, `phak_...`) and
`PHALA_API_KEY`. `ADMIN_TOKEN` and `CHAT_TOKEN` are generated on the first run if they're missing.
Optionally add `OPEN_AI_API_KEY`. It's passed to the CVM as an encrypted secret and used when `LLM_BACKEND=openai`
is set in `docker-compose.cvm.yml`.

```powershell
docker login
.\agent-poc\deploy\deploy.ps1 build -Image docker.io/<user>/verifiable-agent
.\agent-poc\deploy\deploy.ps1 plan
.\agent-poc\deploy\deploy.ps1 apply      # prints app_id and the public endpoint
.\agent-poc\deploy\deploy.ps1 stop       # power off: compute billing stops, disk (~$0.07/day for 20 GB) kept
.\agent-poc\deploy\deploy.ps1 start      # power on again: same app id, same URL, same signing key
.\agent-poc\deploy\deploy.ps1 destroy    # deletes the CVM(s) and stops all billing
```

To scale, set `extra_instances` in `terraform/variables.tf`. Each one is another CVM of the same app,
billed separately. This path hasn't been tested yet.

The tokens for the web UI and the API are in `agent-poc/.env` as `CHAT_TOKEN` and `ADMIN_TOKEN`.

**Tested on 2026-11-20** on one tdx.small: all 26 verifier checks passed, including A3 (agent quote
Intel-signed, TCB up to date), A6 and A7 (the CVM booted exactly `docker-compose.cvm.yml`). The compose
hash printed by `terraform output compose_hash` matched the one measured in the agent's RTMR3.

Verify an answer from the deployed agent, pinning the compose file it must have booted:
```powershell
.\.venv\Scripts\python agent-poc\verifier\verify.py <proof_id> --agent <endpoint> --expect-compose agent-poc\deploy\docker-compose.cvm.yml
```
On a real CVM, A3 (Intel signature on the agent's quote), A6 (compose-hash = sha256(app_compose)) and
A7 (booted compose = our file) become real checks.

**Access control.** On a real CVM the agent refuses to start without `ADMIN_TOKEN` and `CHAT_TOKEN`.
Send them as `Authorization: Bearer <token>`, or type one into the web UI.

| Endpoint | Who can call it |
| --- | --- |
| `/info`, `/attestation` | Anyone |
| `/chat`, `/reset`, `GET /system-prompt`, `/proof/*` | Chat token |
| `PUT /system-prompt`, `/metrics`, `/debug/*` | Admin token |

**Terraform state contains the secrets in plaintext**, a limitation of the provider. Keep it local and
git-ignored (`.gitignore` covers it), or use an encrypted remote backend.

## 7. Known limitations

- **Conversations are kept in memory**, up to 1,000 sessions. Proofs are stored in SQLite (`/data/proofs.db`, on a volume).
- **NRAS token signature not checked:** the verifier trusts NVIDIA's response over TLS and doesn't
  check the JWT signature against NVIDIA's JWKS.
- **The gateway re-encodes requests before forwarding them to the model server.** The receipt covers both
  hashes, but only the bytes we sent and received can be checked by us.

## Files

```
agent-poc/
  docker-compose.yml        agent + dstack simulator; LLM_BACKEND switch
  .env.example              key names (copy to .env)
  agent/app.py              the agent: chat, system prompt, signing, proofs
  agent/tee.py              TEE client: simulator, dstack.sock or tappd.sock
  agent/static/index.html   web UI
  verifier/verify.py        full verifier (layers A-D)
  verifier/gateway_attestation.py   gateway checks only (no key needed)
  tests/                    cost tests, size caps, auth test
  deploy/docker-compose.cvm.yml     compose for the CVM (image pinned by digest)
  deploy/terraform/         phala_app resource (Terraform)
  deploy/deploy.ps1         build, push, plan, apply, destroy
```

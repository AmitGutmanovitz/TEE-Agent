# TEE-Agent: a verifiable AI agent on Phala TEE

A proof of concept for an AI agent whose LLM execution can be **verified**: for any single answer, anyone
can check which code produced it, which system prompt and question went in, and that the model really ran
inside attested hardware (Intel TDX + NVIDIA H100). The goal is verifiability of LLM execution more than
confidentiality.

```
 You / verifier ──▶ Agent CVM ──▶ Phala AI gateway ──▶ Model server
                    (Intel TDX)   (Intel TDX)          (Intel TDX + NVIDIA H100)
        ▲                │               │                     │
        └── evidence: agent quote · gateway quote + signed receipt · model-server quote · NVIDIA GPU report
```

## What it does

- **Chat agent with a changeable system prompt.** A small FastAPI service with a web UI and an API. Admin and chat
  access tokens control who can do what.
- **Runs in a TEE.** It runs as a Docker Compose app in a Phala Cloud CVM (Intel TDX). Its signing key is derived
  inside the TEE and bound into an Intel-signed quote. Every answer is signed with that key.
- **Verifiable inference.** LLM calls go to Phala's Private AI gateway, and the model (default
  `qwen/qwen-2.5-7b-instruct`, the cheapest chat model) runs on a TDX + H100 server. The gateway signs a receipt
  over the exact request and response bytes.
- **End-to-end encryption** from the agent into the gateway enclave (Phala ACI E2EE v2: X25519, HKDF-SHA256,
  AES-256-GCM).
- **Independent verifier** (`verify.py`). Checks 5 layers (about 30 checks) on your own machine:
  - **A. Agent:** Intel-signed quote, booted compose file, answer signature.
  - **B. Gateway:** Intel DCAP, nonce binding, compose hash, TLS pin.
  - **C. Receipt:** Ed25519 signature over the exact request and response.
  - **D. Model server:** TDX quote, plus the NVIDIA H100 attestation via NRAS.
  - **E. Encryption:** re-encrypts and decrypts to confirm the wire bytes.
- **Inspector:** an HTML report for one answer. It shows the raw traffic, the one-time encryption keys, decoded
  TEE quotes, RTMR replay, the receipt, the GPU report, and every check.
- **Demo page** for non-technical viewers: type a question, click **Run test**, and watch the verification result.
- **Infrastructure as code:** Terraform (official `phala-network/phala` provider) plus `deploy.ps1` to
  build, deploy, start, stop and destroy.

What is **not** proven: that an answer is correct, and which exact model weights were loaded.

## Repository layout

| Path | What it is |
| --- | --- |
| [`agent-poc/`](agent-poc/) | **The project**: agent, verifier, Inspector, demo page, cost tests, deployment. Full guide in [`agent-poc/README.md`](agent-poc/README.md). |
| `agent-poc/agent/` | The agent (FastAPI): chat, system prompt, TEE client, E2EE, signed proofs |
| `agent-poc/verifier/` | `verify.py` (all checks), `inspect_answer.py` (HTML report), `gateway_attestation.py` |
| `agent-poc/demo/` | Demo page + verifier service that runs next to the agent |
| `agent-poc/deploy/` | CVM compose file (images pinned by digest), Terraform, `deploy.ps1` |
| `agent-poc/tests/` | Cost/load tests, auth tests, end-to-end tests |
| [`calculator-demo/`](calculator-demo/) | First stepping stone: an encrypted, attested calculator on the local Phala simulator |

## Quick start (local, with the Phala TEE simulator)

Requirements: Docker Desktop, Python 3.11+, and a Phala Private AI API key.

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -r agent-poc\verifier\requirements.txt
copy agent-poc\.env.example agent-poc\.env      # then put your PHALA_API_KEY in it
cd agent-poc
docker compose up -d --build                     # agent on :8000, demo page on :8080
```

Open http://localhost:8000, chat, and copy a `proof_id`. Then, from the repo root:

```powershell
.\.venv\Scripts\python agent-poc\verifier\verify.py <proof_id>
.\.venv\Scripts\python agent-poc\verifier\inspect_answer.py <proof_id>
```

Locally the agent's own quote comes from the simulator, so check A3 is skipped. Everything about the LLM
(layers B to E) is verified against Phala's real hardware.

## Deploy to Phala Cloud

Add `PHALA_CLOUD_API_KEY` to `agent-poc/.env`, then run `docker login`, and then:

```powershell
.\agent-poc\deploy\deploy.ps1 build -Image docker.io/<user>/verifiable-agent
.\agent-poc\deploy\deploy.ps1 apply     # creates the CVM, prints the URLs
.\agent-poc\deploy\deploy.ps1 link      # shareable demo-page link
.\agent-poc\deploy\deploy.ps1 stop      # or: start / destroy
```

Terraform runs inside the `hashicorp/terraform` container. Terraform state contains the secrets in plaintext, so
it is git-ignored.

## Results (measured 2026-11-20/21)

- **Verification:** all checks pass on a real CVM, including the agent's Intel-signed quote and NVIDIA H100 attestation.
- **LLM cost:** about **$0.000046 per question** (~$46 per million) with `qwen-2.5-7b-instruct`.
- **Capacity:** one tdx.small CVM (1 vCPU) handles about 16 requests/s at under 20% CPU. Phala's API rate limit was
  the ceiling, not the CVM.
- **CVM cost:** about **$44 per CVM per month** when always on, which dominates the total cost.
- **Verification time:** about 8 s from a laptop, or about 3.5 s from the in-CVM verifier service.

See [`agent-poc/README.md`](agent-poc/README.md) for the full verification table, the API, the cost tests and
the known limitations.

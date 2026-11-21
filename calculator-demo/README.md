# Phala TEE stepping stone: attested, encrypted calculator

A local stand-in for a Phala dstack CVM. It needs no Phala Cloud account and no TEE hardware.

```
 your PC (client)                         Docker = pretend CVM
 ┌──────────────────┐   HTTP :8000   ┌───────────────────┐  HTTP  ┌──────────────────────┐
 │ client/client.py │ ─────────────▶ │ calc-server       │ ─────▶ │ tappd-sim            │
 │ verifies quote,  │  only cipher-  │ server/server.py  │        │ Phala TEE simulator  │
 │ encrypts request │  text on wire  │ decrypts, computes│        │ (fake TDX + KMS)     │
 └──────────────────┘                └───────────────────┘        └──────────────────────┘
```

## Run it

From this `calculator-demo` folder (the venv lives in the repo root):

```powershell
docker compose up -d --build              # start simulator + server
docker logs -f calc-server                # watch the server side (2nd terminal)
..\.venv\Scripts\python client\client.py 6 x 7
..\.venv\Scripts\python client\client.py 10 / 4 --tamper
docker compose down                       # stop
```

To set up the client venv the first time, run `python -m venv .venv` and then `.\.venv\Scripts\python -m pip install cryptography requests`.

## What happens, step by step

**Server boot (inside the CVM):**
1. **KMS DeriveKey.** The server asks the TEE guest agent (`Tappd.DeriveKey`, path `/calc-server/ecdh-key`) for a P-256 private key. On real Phala the KMS only releases this key to a CVM whose measurements match the app. The key never leaves the enclave, and the same app + path always gets the same key.
2. **TdxQuote.** The server asks for a TDX quote with `report_data = sha256(server_pubkey) || 32 zero bytes`. The quote also contains the measurements: MRTD (firmware/OS image) and RTMR0-3 (boot chain; RTMR3 holds the app / docker-compose hash). On real hardware the CPU signs the quote.

**Client, once per connection: verify before trusting.**
- A. It fetches `/attestation`, which returns the pubkey, the quote, the event log and the KMS cert chain.
- B. **Key binding.** It checks that the quote's report_data equals sha256(pubkey). This proves that the key belongs to the code inside the TEE, so a man in the middle can't swap it.
- C. **Event log replay.** It recomputes `RTMR = sha384(RTMR || digest)` over the log and compares the result to the quote.
- D. **Measurements.** It prints MRTD and RTMR3. In production you pin these to known-good values, which is the verifiability part: it proves *which code* is running.
- E. **Intel signature.** This check is skipped here because simulator quotes aren't hardware-signed. In production you verify the chain to Intel's root CA, for example with `dcap-qvl` or Phala's verification API.

**Each request (ECIES-style):**
1. The client makes a fresh ephemeral P-256 key.
2. **ECDH** between the ephemeral private key and the server's attested public key gives a shared secret. The server computes the same secret from its private key and the client's ephemeral public key.
3. **HKDF-SHA256** turns that secret into a one-time AES-256 key.
4. **AES-256-GCM** encrypts the JSON `{"op","a","b"}`, using a random 12-byte nonce and the client's public key as associated data.
5. The server decrypts, computes, and encrypts the answer with the same key and a new nonce.
6. The client decrypts the answer. With `--tamper`, one flipped bit makes the GCM tag check fail, and the server rejects the request.

The two log streams print the same shared secret and AES key on both sides, which shows the key agreement working. **This is for teaching only. Never log keys in a real app.**

## What changes on real Phala hardware
- Remove the `tappd-sim` service and mount `/var/run/tappd.sock` (or `dstack.sock`) instead. The API calls stay the same.
- The quote becomes CPU-signed, so check E becomes real and must pass.
- Pin MRTD and RTMR3 (compose hash) in the client.
- Phala also offers RA-TLS / a TLS gateway, where the attested key sits in the TLS certificate instead of this hand-rolled scheme. Here the scheme is done by hand so you can see every step.

## Files
- `docker-compose.yml`: the simulator plus the server
- `server/server.py`: HTTP server, TEE calls, decrypt, compute, encrypt
- `server/tee_crypto.py`: shared crypto and TDX quote parsing (the client uses it too)
- `client/client.py`: attestation checks and an encrypted call

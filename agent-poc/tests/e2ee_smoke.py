r"""Ask one question and show the E2EE trace summary (tokens from agent-poc/.env, never printed).

  .\.venv\Scripts\python agent-poc\tests\e2ee_smoke.py [agent_url]
"""

import json
import os
import sys

import requests

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "verifier"))
from verify import load_env  # noqa: E402

load_env()
url = (sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000").rstrip("/")
A = {"Authorization": f"Bearer {os.environ.get('ADMIN_TOKEN', '')}"}
print("info:", requests.get(f"{url}/info").json())
r = requests.post(f"{url}/chat", json={"message": "In one sentence: what is a TEE?"}, headers=A, timeout=180)
print(r.status_code, r.text[:300] if r.status_code != 200 else "")
if r.status_code != 200:
    sys.exit(1)
j = r.json()
print("answer:", j["answer"])
print("proof_id:", j["proof_id"])
d = requests.get(f"{url}/debug/{j['proof_id']}", headers=A).json()
print("\n".join(d["agent_log"]))
e = d["e2ee"]
if e:
    f0 = e["request_fields"][-1]
    print("wire content of user message:", d["request_wire_json"]["messages"][-1]["content"][:80], "...")
    print("user field trace keys:", list(f0.keys()))
    print("response fields:", [(x["field"], x["plaintext"][:60]) for x in e["response_fields"]])
    print("response headers:", {k: v for k, v in d["response_headers"].items() if k.lower().startswith("x-")})

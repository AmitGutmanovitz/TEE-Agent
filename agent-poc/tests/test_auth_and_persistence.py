r"""Checks access control on an agent started with ADMIN_TOKEN / CHAT_TOKEN.

  .\.venv\Scripts\python agent-poc\tests\test_auth_and_persistence.py http://localhost:8001 <admin> <chat>
"""

import sys

import requests

url, admin, chat = sys.argv[1], sys.argv[2], sys.argv[3]
A = {"Authorization": f"Bearer {admin}"}
C = {"Authorization": f"Bearer {chat}"}
checks = [
    ("info is public", requests.get(f"{url}/info").status_code == 200),
    ("attestation is public", requests.get(f"{url}/attestation", params={"nonce": "00" * 32}).status_code == 200),
    ("chat without token -> 401", requests.post(f"{url}/chat", json={"message": "hi"}).status_code == 401),
    ("wrong token -> 401", requests.post(f"{url}/chat", json={"message": "hi"},
                                         headers={"Authorization": "Bearer nope"}).status_code == 401),
    ("read prompt without token -> 401", requests.get(f"{url}/system-prompt").status_code == 401),
    ("change prompt with CHAT token -> 401",
     requests.put(f"{url}/system-prompt", json={"prompt": "x"}, headers=C).status_code == 401),
    ("change prompt with ADMIN token -> 200",
     requests.put(f"{url}/system-prompt", json={"prompt": "Answer in one short sentence."}, headers=A).status_code == 200),
    ("metrics with CHAT token -> 401", requests.get(f"{url}/metrics", headers=C).status_code == 401),
]
r = requests.post(f"{url}/chat", json={"message": "What is 5+5?"}, headers=C)
checks.append(("chat with CHAT token -> 200", r.status_code == 200))
pid = r.json().get("proof_id") if r.status_code == 200 else None
checks.append(("proof without token -> 401", requests.get(f"{url}/proof/{pid}").status_code == 401))
checks.append(("proof with CHAT token -> 200", requests.get(f"{url}/proof/{pid}", headers=C).status_code == 200))
for name, ok in checks:
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
print("proof_id:", pid)
sys.exit(0 if all(ok for _, ok in checks) else 1)

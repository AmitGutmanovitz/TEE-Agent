r"""End-to-end test against a deployed agent. Tokens are read from agent-poc/.env and never printed.

  .\.venv\Scripts\python agent-poc\tests\remote_e2e.py <endpoint>
"""

import os
import subprocess
import sys

import requests

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, "..", "verifier"))
from verify import load_env  # noqa: E402

load_env()
url = sys.argv[1].rstrip("/")
A = {"Authorization": f"Bearer {os.environ['ADMIN_TOKEN']}"}
C = {"Authorization": f"Bearer {os.environ['CHAT_TOKEN']}"}

print("info:", requests.get(f"{url}/info", timeout=30).json())
checks = [
    ("chat without token -> 401", requests.post(f"{url}/chat", json={"message": "hi"}, timeout=30).status_code == 401),
    ("change prompt with chat token -> 401",
     requests.put(f"{url}/system-prompt", json={"prompt": "x"}, headers=C, timeout=30).status_code == 401),
]
r = requests.put(f"{url}/system-prompt", headers=A, timeout=30,
                 json={"prompt": "You are a pirate running inside an Intel TDX enclave. Answer in one sentence."})
checks.append(("change prompt with admin token -> 200", r.status_code == 200))
r = requests.post(f"{url}/chat", json={"message": "Where are you running, and what is 6 times 7?"}, headers=C, timeout=180)
checks.append(("chat with chat token -> 200", r.status_code == 200))
for name, ok in checks:
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
if r.status_code != 200:
    sys.exit(f"chat failed: {r.status_code} {r.text[:300]}")
j = r.json()
print("answer:", j["answer"])
print("proof_id:", j["proof_id"])
compose = os.path.join(HERE, "..", "deploy", "docker-compose.cvm.yml")
res = subprocess.run([sys.executable, os.path.join(HERE, "..", "verifier", "verify.py"), j["proof_id"],
                      "--agent", url, "--expect-compose", compose])
sys.exit(res.returncode or (0 if all(ok for _, ok in checks) else 1))

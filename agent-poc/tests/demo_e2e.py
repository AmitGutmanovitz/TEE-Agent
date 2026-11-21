r"""Run one test through the demo service, like a visitor would (DEMO_TOKEN from agent-poc/.env, never printed).

  .\.venv\Scripts\python agent-poc\tests\demo_e2e.py <demo_url>
"""

import os
import sys
import time

import requests

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "verifier"))
from verify import load_env  # noqa: E402

load_env()
url = sys.argv[1].rstrip("/")
code = os.environ.get("DEMO_TOKEN") or os.environ["CHAT_TOKEN"]
H = {"Authorization": f"Bearer {code}"}
for i in range(20):
    try:
        if requests.get(f"{url}/", timeout=15).status_code == 200:
            break
    except requests.RequestException:
        pass
    time.sleep(10)
print("page:", requests.get(f"{url}/", timeout=15).status_code)
print("wrong code ->", requests.get(f"{url}/prompt", headers={"Authorization": "Bearer nope"}, timeout=15).status_code)
r = requests.post(f"{url}/run", json={"question": "What is 17 times 23?"}, headers=H, timeout=300)
print("run:", r.status_code)
j = r.json()
print({k: j.get(k) for k in ["answer", "passed", "failed", "failed_checks", "answer_seconds", "total_seconds"]})
rep = requests.get(f"{url}/report/{j['proof_id']}", timeout=30)
print("report:", rep.status_code, len(rep.text), "bytes")

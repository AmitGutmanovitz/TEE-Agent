r"""End-to-end smoke test: change the system prompt, chat, check that the prompt took effect.

  .\.venv\Scripts\python agent-poc\verifier\smoke_test.py
"""

import json
import sys

import requests

A = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000"
print("info:", requests.get(f"{A}/info").json())

for prompt in ["You are a pirate. Always answer in pirate speak, one sentence.",
               "You are a formal British butler. Answer in one sentence."]:
    p = requests.put(f"{A}/system-prompt", json={"prompt": prompt}).json()
    requests.post(f"{A}/reset", json={"message": ""})
    r = requests.post(f"{A}/chat", json={"message": "What is 2+2?"})
    r.raise_for_status()
    j = r.json()
    print(f"\nprompt sha256 {p['sha256'][:16]}... : {prompt}")
    print(f"answer: {j['answer']}")
    print("statement:", json.dumps(j["statement"]))
    assert j["statement"]["system_prompt_sha256"] == p["sha256"]

print("\nmetrics:", requests.get(f"{A}/metrics").json())

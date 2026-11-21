r"""Test 2: token profile of single, independent questions (each in a fresh session).

  .\.venv\Scripts\python agent-poc\tests\test2_questions.py
"""

import json
import os
import sys
import uuid

import requests

sys.path.insert(0, os.path.dirname(__file__))
from common import AGENT, QUESTIONS, SYSTEM_PROMPT, cost  # noqa: E402

requests.put(f"{AGENT}/system-prompt", json={"prompt": SYSTEM_PROMPT}).raise_for_status()
rows = []
for q in QUESTIONS:
    r = requests.post(f"{AGENT}/chat", json={"message": q, "session": uuid.uuid4().hex}, timeout=120)
    r.raise_for_status()
    j = r.json()
    u = j["statement"]["usage"]
    rows.append({"question": q, "prompt_tokens": u["prompt_tokens"], "completion_tokens": u["completion_tokens"],
                 "latency_ms": j["statement"]["latency_ms"], "cost_usd": cost(u["prompt_tokens"], u["completion_tokens"]),
                 "proof_id": j["proof_id"], "answer": j["answer"]})
    print(f"{u['prompt_tokens']:>5} in {u['completion_tokens']:>4} out {j['statement']['latency_ms']:>6} ms  {q}")

n = len(rows)
avg = {k: sum(r[k] for r in rows) / n for k in ["prompt_tokens", "completion_tokens", "latency_ms", "cost_usd"]}
print(f"\naverage per question: {avg['prompt_tokens']:.0f} input + {avg['completion_tokens']:.0f} output tokens, "
      f"{avg['latency_ms']:.0f} ms, ${avg['cost_usd']:.7f}  (= ${avg['cost_usd'] * 1e6:.0f} per 1M questions)")
out = os.path.join(os.path.dirname(__file__), "results")
os.makedirs(out, exist_ok=True)
json.dump({"rows": rows, "average": avg}, open(os.path.join(out, "test2_questions.json"), "w"), indent=2)

r"""Test 3: how long verification takes, per layer, for a few real answers.

  .\.venv\Scripts\python agent-poc\tests\test3_verify_overhead.py
Asks 3 fresh questions (proofs live in agent memory), then times verification of each answer.
Verification itself uses only free API calls (no LLM tokens).
"""

import contextlib
import io
import json
import os
import sys
import time

import requests

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, "..", "verifier"))
import verify as v  # noqa: E402
from gateway_attestation import Report, verify_gateway  # noqa: E402

sys.path.insert(0, HERE)
from common import QUESTIONS, SYSTEM_PROMPT  # noqa: E402

v.load_env()
key = os.environ["PHALA_API_KEY"]
agent = "http://localhost:8000"
requests.put(f"{agent}/system-prompt", json={"prompt": SYSTEM_PROMPT}).raise_for_status()
proofs = [requests.post(f"{agent}/chat", json={"message": q, "session": f"t3-{i}"}, timeout=120).json()["proof_id"]
          for i, q in enumerate(QUESTIONS[:3])]


def timed(fn, *a):
    rep = Report()
    t0 = time.perf_counter()
    with contextlib.redirect_stdout(io.StringIO()):
        res = fn(rep, *a)
    return time.perf_counter() - t0, rep.failed, res


rows = []
for pid in proofs:
    proof = requests.get(f"{agent}/proof/{pid}", timeout=30).json()
    ta, fa, _ = timed(v.verify_agent, agent, proof)
    tb, fb, keyset = timed(verify_gateway)
    # Layer C includes fetching the receipt and the session, and Layer D (model server + NVIDIA NRAS).
    tcd, fcd, _ = timed(v.verify_receipt, keyset, proof, key)
    rows.append({"proof_id": pid, "agent_s": ta, "gateway_s": tb, "receipt_and_model_server_s": tcd,
                 "total_s": ta + tb + tcd, "failed_checks": fa + fb + fcd})
    print(f"{pid}: agent {ta:.2f}s  gateway {tb:.2f}s  receipt+model-server {tcd:.2f}s  "
          f"total {ta + tb + tcd:.2f}s  failed checks: {fa + fb + fcd}")

avg = {k: sum(r[k] for r in rows) / len(rows) for k in ["agent_s", "gateway_s", "receipt_and_model_server_s", "total_s"]}
print(f"\naverage: agent {avg['agent_s']:.2f}s, gateway {avg['gateway_s']:.2f}s, "
      f"receipt+model server {avg['receipt_and_model_server_s']:.2f}s, total {avg['total_s']:.2f}s")
json.dump({"rows": rows, "average": avg}, open(os.path.join(HERE, "results", "test3_verify_overhead.json"), "w"), indent=2)

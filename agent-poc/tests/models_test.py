r"""Ask the same question with every selectable model and verify each answer (tokens from .env, never printed).

  .\.venv\Scripts\python agent-poc\tests\models_test.py [agent_url] [--quick]
--quick: only the first model of each backend.
"""

import os
import sys

import requests

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, "..", "verifier"))
import contextlib  # noqa: E402
import io  # noqa: E402

from verify import load_env, run_all  # noqa: E402

load_env()
args = [a for a in sys.argv[1:] if not a.startswith("--")]
url = (args[0] if args else "http://localhost:8000").rstrip("/")
A = {"Authorization": f"Bearer {os.environ.get('ADMIN_TOKEN', '')}"}
m = requests.get(f"{url}/models", timeout=30).json()
print("default:", m["default"])
for b in m["backends"]:
    for model in (b["models"][:1] if "--quick" in sys.argv else b["models"]):
        r = requests.post(f"{url}/chat", headers=A, timeout=180,
                          json={"message": "Reply with exactly: OK", "session": os.urandom(6).hex(),
                                "backend": b["backend"], "model": model})
        if r.status_code != 200:
            print(f"  {b['backend']:<7} {model:<36} HTTP {r.status_code}: {r.text[:160]}")
            continue
        j = r.json()
        with contextlib.redirect_stdout(io.StringIO()):
            rep, _, _ = run_all(j["proof_id"], url, None)
        n_pass = sum(1 for i in rep.items if i[1] == "PASS")
        print(f"  {b['backend']:<7} {model:<36} answer={j['answer'][:30]!r:<34} checks: {n_pass} pass / {rep.failed} fail"
              f"  e2ee={'on' if j['statement'].get('e2ee') else 'off'}")

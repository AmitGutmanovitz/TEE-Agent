r"""Debug helper: print a receipt and the upstream session as JSON.

  .\.venv\Scripts\python agent-poc\verifier\dump_receipt.py <receipt_id> [out_dir]
"""

import json
import os
import sys

import requests

sys.path.insert(0, os.path.dirname(__file__))
from verify import GATEWAY, load_env  # noqa: E402

load_env()
auth = {"Authorization": f"Bearer {os.environ['PHALA_API_KEY']}"}
rid = sys.argv[1]
out = sys.argv[2] if len(sys.argv) > 2 else "."
rc = requests.get(f"{GATEWAY}/v1/aci/receipts/{rid}", headers=auth, timeout=30).json()
open(os.path.join(out, "receipt.json"), "w").write(json.dumps(rc, indent=2))
receipt = rc.get("receipt", rc)
sid = next((e["session_id"] for e in receipt.get("event_log", []) if e.get("session_id")), None)
if sid:
    s = requests.get(f"{GATEWAY}/v1/aci/sessions/{sid}", headers=auth, timeout=30).json()
    open(os.path.join(out, "session.json"), "w").write(json.dumps(s, indent=2))
print("saved receipt.json", "and session.json" if sid else "")

"""Minimal client for the dstack guest agent: the TEE API inside a Phala CVM.

The same code runs in three places:
  * Local simulator : DSTACK_SIMULATOR_ENDPOINT=http://dstack-sim:8090  (Tappd HTTP API)
  * Phala CVM (new) : /var/run/dstack.sock  (dstack API: /GetKey, /GetQuote)
  * Phala CVM (old) : /var/run/tappd.sock   (Tappd API)
Only two calls are used: derive a stable app key, and get a TDX quote over 64 bytes.
"""

import hashlib
import json
import os

import httpx


class TEE:
    def __init__(self):
        sim = os.environ.get("DSTACK_SIMULATOR_ENDPOINT")
        if sim:
            self.mode, self.http = "tappd-simulator", httpx.Client(base_url=sim, timeout=30)
        elif os.path.exists("/var/run/dstack.sock"):
            self.mode = "dstack"
            self.http = httpx.Client(base_url="http://localhost", timeout=30,
                                     transport=httpx.HTTPTransport(uds="/var/run/dstack.sock"))
        elif os.path.exists("/var/run/tappd.sock"):
            self.mode = "tappd"
            self.http = httpx.Client(base_url="http://localhost", timeout=30,
                                     transport=httpx.HTTPTransport(uds="/var/run/tappd.sock"))
        else:
            raise RuntimeError("No TEE endpoint: set DSTACK_SIMULATOR_ENDPOINT or mount the dstack socket")

    def _post(self, path: str, body: dict) -> dict:
        r = self.http.post(path, json=body)
        r.raise_for_status()
        return r.json()

    def derive_seed(self, path: str) -> bytes:
        """32 bytes that only this app (same compose hash / app id) can obtain from the KMS."""
        if self.mode == "dstack":
            key = self._post("/GetKey", {"path": path, "purpose": "signing", "algorithm": "secp256k1"})["key"]
            return hashlib.sha256(bytes.fromhex(key)).digest()
        key_pem = self._post("/prpc/Tappd.DeriveKey?json", {"path": path, "subject": "agent"})["key"]
        return hashlib.sha256(key_pem.encode()).digest()

    def quote(self, report_data: bytes) -> dict:
        """TDX quote whose report_data field is exactly the given 64 bytes."""
        assert len(report_data) == 64
        if self.mode == "dstack":
            q = self._post("/GetQuote", {"report_data": report_data.hex()})
        else:
            q = self._post("/prpc/Tappd.TdxQuote?json",
                           {"report_data": report_data.hex(), "hash_algorithm": "raw"})
        return {"quote": q["quote"].removeprefix("0x"), "event_log": q.get("event_log")}

    def app_info(self) -> dict:
        """On a real CVM: app id and the app_compose that was measured into RTMR3 (empty on the simulator)."""
        if self.mode == "tappd-simulator":
            return {}
        try:
            i = self._post("/Info" if self.mode == "dstack" else "/prpc/Tappd.Info?json", {})
            tcb = i.get("tcb_info")
            tcb = json.loads(tcb) if isinstance(tcb, str) else (tcb or {})
            return {"app_id": i.get("app_id"), "instance_id": i.get("instance_id"),
                    "app_compose": tcb.get("app_compose"), "compose_hash": tcb.get("compose_hash")}
        except Exception as e:  # noqa: BLE001
            return {"app_info_error": repr(e)[:200]}

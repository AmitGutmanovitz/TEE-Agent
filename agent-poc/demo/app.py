"""Demo service: a web page where a visitor runs a new test and watches the verification result.

Runs next to the agent (same CVM, separate container). For each run it:
  1. optionally sets the agent's system prompt,
  2. asks the agent the visitor's question,
  3. runs the full verifier (layers A-E, same code as verifier/verify.py) against that answer,
  4. renders the Inspector report (same code as verifier/inspect_answer.py).

  GET  /                 demo page (access code required for actions)
  GET  /prompt           current system prompt              (access code)
  POST /run              {"question", "system_prompt"?}     (access code)
  GET  /runs             earlier runs                       (access code)
  GET  /report/{id}      Inspector report (the 128-bit random id is the capability)
"""

import hmac
import os
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "verifier"))

import requests  # noqa: E402
from fastapi import FastAPI, Header, HTTPException  # noqa: E402
from fastapi.responses import FileResponse, HTMLResponse  # noqa: E402
from pydantic import BaseModel  # noqa: E402

import inspect_answer as ia  # noqa: E402
from verify import run_all  # noqa: E402

AGENT = os.environ.get("AGENT_URL", "http://agent:8000").rstrip("/")
PUBLIC_AGENT_URL = os.environ.get("PUBLIC_AGENT_URL", AGENT)
ADMIN = os.environ.get("ADMIN_TOKEN", "")
DEMO_CODE = os.environ.get("DEMO_TOKEN") or os.environ.get("CHAT_TOKEN", "")
A = {"Authorization": f"Bearer {ADMIN}"}

app = FastAPI(title="Verifiable agent demo")
reports: dict[str, str] = {}
runs: list[dict] = []
run_lock = threading.Lock()  # one test at a time keeps the demo simple and the rate limit safe


def check_code(authorization: str | None) -> None:
    if not DEMO_CODE:
        return
    got = (authorization or "").removeprefix("Bearer ").strip()
    if not hmac.compare_digest(got.encode(), DEMO_CODE.encode()):
        raise HTTPException(401, "wrong or missing access code")


class RunIn(BaseModel):
    question: str
    system_prompt: str | None = None


@app.get("/")
def page():
    return FileResponse(os.path.join(HERE, "static", "index.html"))


@app.get("/prompt")
def prompt(authorization: str | None = Header(default=None)):
    check_code(authorization)
    return requests.get(f"{AGENT}/system-prompt", headers=A, timeout=30).json()


@app.get("/runs")
def list_runs(authorization: str | None = Header(default=None)):
    check_code(authorization)
    return list(reversed(runs))


@app.get("/report/{pid}", response_class=HTMLResponse)
def report(pid: str):
    if pid not in reports:
        raise HTTPException(404, "unknown report")
    return reports[pid]


@app.post("/run")
def run(body: RunIn, authorization: str | None = Header(default=None)):
    check_code(authorization)
    if not body.question.strip():
        raise HTTPException(400, "empty question")
    if not run_lock.acquire(timeout=120):
        raise HTTPException(429, "another test is running, try again in a moment")
    try:
        t0 = time.time()
        if body.system_prompt is not None and body.system_prompt.strip():
            r = requests.put(f"{AGENT}/system-prompt", json={"prompt": body.system_prompt.strip()}, headers=A, timeout=30)
            r.raise_for_status()
        r = requests.post(f"{AGENT}/chat", json={"message": body.question.strip(), "session": os.urandom(8).hex()},
                          headers=A, timeout=180)
        if r.status_code != 200:
            raise HTTPException(502, f"agent error {r.status_code}: {r.text[:300]}")
        chat = r.json()
        t_answer = time.time() - t0
        try:
            rep, proof, debug = run_all(chat["proof_id"], AGENT, None)
        except SystemExit as e:
            raise HTTPException(502, f"verification could not run: {e}") from e
        reports[chat["proof_id"]] = ia.render(rep, proof, debug, PUBLIC_AGENT_URL)
        summary = {
            "proof_id": chat["proof_id"], "question": body.question.strip(), "answer": chat["answer"],
            "system_prompt_sha256": chat["statement"]["system_prompt_sha256"],
            "passed": sum(1 for i in rep.items if i[1] == "PASS"), "failed": sum(1 for i in rep.items if i[1] == "FAIL"),
            "failed_checks": [i[2] for i in rep.items if i[1] == "FAIL"],
            "answer_seconds": round(t_answer, 1), "total_seconds": round(time.time() - t0, 1),
            "at": int(time.time()),
        }
        runs.append(summary)
        return summary
    finally:
        run_lock.release()

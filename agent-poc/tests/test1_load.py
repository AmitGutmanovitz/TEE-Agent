r"""Test 1: how much load one agent instance handles, with real LLM calls (Phala API).

  .\.venv\Scripts\python agent-poc\tests\test1_load.py --label small
Start the agent with the matching size cap first (tests/compose.small.yml or compose.medium.yml).

Each request is an independent question in a fresh session. For each concurrency level we measure
throughput, end-to-end latency, how much of it is the agent itself (vs the LLM), CPU and memory.
"""

import argparse
import asyncio
import json
import os
import subprocess
import sys
import threading
import time
import uuid

import httpx

sys.path.insert(0, os.path.dirname(__file__))
from common import AGENT, CONTAINER, QUESTIONS, SYSTEM_PROMPT, cost, pct  # noqa: E402


def mem_mib(s: str) -> float:
    s = s.strip()
    for unit, f in (("GiB", 1024), ("MiB", 1), ("KiB", 1 / 1024), ("B", 1 / 1024 / 1024)):
        if s.endswith(unit):
            return float(s[: -len(unit)]) * f
    return 0.0


def sampler(stop: threading.Event, out: list) -> None:
    while not stop.is_set():
        r = subprocess.run(["docker", "stats", "--no-stream", "--format", "{{json .}}", CONTAINER],
                           capture_output=True, text=True)
        try:
            d = json.loads(r.stdout)
            out.append((float(d["CPUPerc"].rstrip("%")), mem_mib(d["MemUsage"].split("/")[0])))
        except Exception:  # noqa: BLE001
            pass


async def worker(client, queue, results):
    while True:
        try:
            i = queue.get_nowait()
        except asyncio.QueueEmpty:
            return
        t0 = time.perf_counter()
        try:
            r = await client.post(f"{AGENT}/chat", json={"message": QUESTIONS[i % len(QUESTIONS)],
                                                         "session": uuid.uuid4().hex}, timeout=180)
            lat = time.perf_counter() - t0
            if r.status_code == 200:
                st = r.json()["statement"]
                results.append({"ok": True, "lat": lat, "llm": st["latency_ms"] / 1000,
                                "pt": st["usage"]["prompt_tokens"], "ct": st["usage"]["completion_tokens"]})
            else:
                results.append({"ok": False, "lat": lat, "err": f"{r.status_code} {r.text[:160]}"})
        except Exception as e:  # noqa: BLE001
            results.append({"ok": False, "lat": time.perf_counter() - t0, "err": repr(e)[:160]})


async def run_level(conc: int, n: int):
    q = asyncio.Queue()
    for i in range(n):
        q.put_nowait(i)
    results = []
    async with httpx.AsyncClient(limits=httpx.Limits(max_connections=conc + 5)) as c:
        t0 = time.perf_counter()
        await asyncio.gather(*[worker(c, q, results) for _ in range(conc)])
        return results, time.perf_counter() - t0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--label", required=True)
    ap.add_argument("--levels", default="1,5,10,25,50")
    args = ap.parse_args()
    httpx.put(f"{AGENT}/system-prompt", json={"prompt": SYSTEM_PROMPT}).raise_for_status()
    info = httpx.get(f"{AGENT}/info").json()
    print(f"== Test 1 [{args.label}]  backend={info['backend']} model={info['model']}")
    print(f"{'conc':>4} {'reqs':>5} {'ok':>4} {'req/s':>6} {'p50 s':>6} {'p95 s':>6} {'agent ms':>9} "
          f"{'cpu% avg':>8} {'cpu% max':>8} {'mem MiB':>8}  errors")
    summary = []
    for conc in [int(x) for x in args.levels.split(",")]:
        n = max(20, 4 * conc)
        stats, stop = [], threading.Event()
        th = threading.Thread(target=sampler, args=(stop, stats), daemon=True)
        th.start()
        results, wall = asyncio.run(run_level(conc, n))
        stop.set()
        th.join()
        ok = [r for r in results if r["ok"]]
        lats = [r["lat"] for r in ok]
        overhead = [(r["lat"] - r["llm"]) * 1000 for r in ok]
        errs = sorted({r["err"] for r in results if not r["ok"]})
        row = {
            "concurrency": conc, "requests": n, "ok": len(ok), "throughput_rps": len(ok) / wall,
            "p50_s": pct(lats, 50), "p95_s": pct(lats, 95), "agent_overhead_ms_p50": pct(overhead, 50),
            "cpu_avg": sum(s[0] for s in stats) / len(stats) if stats else None,
            "cpu_max": max((s[0] for s in stats), default=None),
            "mem_max_mib": max((s[1] for s in stats), default=None),
            "cost_usd": sum(cost(r["pt"], r["ct"]) for r in ok), "errors": errs[:3],
        }
        summary.append(row)
        f = lambda v, d=2: "-" if v is None else f"{v:.{d}f}"  # noqa: E731
        print(f"{conc:>4} {n:>5} {len(ok):>4} {f(row['throughput_rps']):>6} {f(row['p50_s']):>6} {f(row['p95_s']):>6} "
              f"{f(row['agent_overhead_ms_p50'], 0):>9} {f(row['cpu_avg'], 1):>8} {f(row['cpu_max'], 1):>8} "
              f"{f(row['mem_max_mib'], 0):>8}  {'; '.join(errs)[:120]}")
    total = sum(r["cost_usd"] for r in summary)
    print(f"LLM cost of this run: ${total:.4f}")
    out = os.path.join(os.path.dirname(__file__), "results")
    os.makedirs(out, exist_ok=True)
    json.dump({"label": args.label, "info": info, "levels": summary},
              open(os.path.join(out, f"test1_load_{args.label}.json"), "w"), indent=2)


if __name__ == "__main__":
    main()

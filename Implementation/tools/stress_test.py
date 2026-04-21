"""
Stress test for the IDS backend.

Fires concurrent mixed workloads against /predict, /quarantine, /blocked-ips,
/sandbox/state, /events, /reports, /reports/{id} and records:
  - per-endpoint success rate
  - p50/p95/p99 latency
  - time-to-first-timeout (when the server stops responding within 5s)
  - backend process CPU/memory samples (if psutil available)

Usage:
    python -m Implementation.tools.stress_test --duration 180 --concurrency 20
"""

from __future__ import annotations

import argparse
import os
import random
import statistics
import sys
import threading
import time
from collections import Counter, defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import requests
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[1] / ".env")

BASE = os.getenv("IDS_BASE_URL", "http://127.0.0.1:6050")
READ_KEY = os.getenv("IDS_API_KEY") or "ids-secret-key"
ADMIN_KEY = os.getenv("IDS_ADMIN_API_KEY") or READ_KEY

HDR_READ = {"X-API-Key": READ_KEY}
HDR_ADMIN = {"X-API-Key": ADMIN_KEY, "Content-Type": "application/json"}


class Bucket:
    __slots__ = ("latencies", "codes", "timeouts", "errors")

    def __init__(self) -> None:
        self.latencies: list[float] = []
        self.codes: "Counter[int | str]" = Counter()
        self.timeouts = 0
        self.errors: "Counter[str]" = Counter()


stats: dict[str, Bucket] = defaultdict(Bucket)
stats_lock = threading.Lock()
stop = threading.Event()
first_timeout_at: dict[str, float] = {}
start_ts = 0.0


def record(name: str, elapsed: float, code: int | str) -> None:
    with stats_lock:
        b = stats[name]
        b.latencies.append(elapsed)
        b.codes[code] += 1
        if code == "TIMEOUT":
            b.timeouts += 1
            if name not in first_timeout_at:
                first_timeout_at[name] = time.time() - start_ts


def hit(name: str, fn, timeout: float = 5.0) -> None:
    t = time.time()
    try:
        r = fn()
        record(name, time.time() - t, r.status_code)
    except requests.exceptions.Timeout:
        record(name, timeout, "TIMEOUT")
    except Exception as e:
        record(name, time.time() - t, f"ERR:{type(e).__name__}")


_session_tls = threading.local()


def _session() -> requests.Session:
    """Per-thread Session that reuses HTTP connections (avoids TIME_WAIT exhaustion)."""
    s = getattr(_session_tls, "session", None)
    if s is None:
        s = requests.Session()
        adapter = requests.adapters.HTTPAdapter(pool_connections=1, pool_maxsize=2)
        s.mount("http://", adapter)
        s.mount("https://", adapter)
        _session_tls.session = s
    return s


def call_health():
    return _session().get(f"{BASE}/health", timeout=5)


def call_events():
    return _session().get(f"{BASE}/events", headers=HDR_READ, timeout=5)


def call_stats():
    return _session().get(f"{BASE}/events/stats", headers=HDR_READ, timeout=5)


def call_sandbox():
    return _session().get(f"{BASE}/sandbox/state", headers=HDR_READ, timeout=5)


def call_quarantine():
    return _session().get(f"{BASE}/quarantine", headers=HDR_READ, timeout=5)


def call_blocked():
    return _session().get(f"{BASE}/blocked-ips", headers=HDR_READ, timeout=5)


def call_reports_list():
    return _session().get(f"{BASE}/reports", headers=HDR_READ, timeout=15)


def call_reports_item():
    lst = _session().get(f"{BASE}/reports", headers=HDR_READ, timeout=15).json()
    if not lst:
        return call_health()
    rid = random.choice(lst)["id"]
    return _session().get(f"{BASE}/reports/{rid}", headers=HDR_READ, timeout=5)


def call_predict():
    flow = {
        "PROTOCOL": 6,
        "IN_BYTES": random.randint(100, 100000),
        "IN_PKTS": random.randint(1, 1000),
        "FLOW_DURATION_MILLISECONDS": random.randint(1, 30000),
        "TCP_FLAGS": 2,
        "MIN_TTL": 64,
        "MAX_TTL": 64,
        "Source IP": f"203.0.113.{random.randint(1, 254)}",
        "Destination IP": "192.168.1.100",
    }
    return _session().post(f"{BASE}/predict/", headers=HDR_ADMIN, json=flow, timeout=10)


ENDPOINTS = [
    ("GET /health", call_health, 1),
    ("GET /events", call_events, 2),
    ("GET /events/stats", call_stats, 2),
    ("GET /sandbox/state", call_sandbox, 2),
    ("GET /quarantine", call_quarantine, 1),
    ("GET /blocked-ips", call_blocked, 1),
    ("GET /reports (list)", call_reports_list, 1),
    ("GET /reports/{id}", call_reports_item, 2),
    ("POST /predict", call_predict, 4),
]


def pick_endpoint():
    total = sum(w for _, _, w in ENDPOINTS)
    r = random.uniform(0, total)
    acc = 0.0
    for name, fn, w in ENDPOINTS:
        acc += w
        if r <= acc:
            return name, fn
    return ENDPOINTS[0][0], ENDPOINTS[0][1]


def worker():
    while not stop.is_set():
        name, fn = pick_endpoint()
        hit(name, fn)


def sampler(backend_pid: int | None, samples: list):
    try:
        import psutil
        proc = psutil.Process(backend_pid) if backend_pid else None
    except Exception:
        proc = None
    while not stop.is_set():
        ts = time.time() - start_ts
        if proc:
            try:
                samples.append({
                    "t": round(ts, 1),
                    "cpu": proc.cpu_percent(interval=None),
                    "mem_mb": round(proc.memory_info().rss / 1024 / 1024, 1),
                    "threads": proc.num_threads(),
                })
            except Exception:
                pass
        stop.wait(5)


def pct(xs, p):
    if not xs:
        return 0.0
    return statistics.quantiles(sorted(xs), n=100)[p - 1] if len(xs) >= 2 else xs[0]


def main():
    global start_ts
    ap = argparse.ArgumentParser()
    ap.add_argument("--duration", type=int, default=180, help="seconds")
    ap.add_argument("--concurrency", type=int, default=20)
    ap.add_argument("--pid", type=int, default=None)
    ap.add_argument("--skip-rate-limited", action="store_true",
                    help="Skip /predict which is intentionally rate-limited to 60/min")
    args = ap.parse_args()

    if args.skip_rate_limited:
        global ENDPOINTS
        ENDPOINTS = [e for e in ENDPOINTS if e[0] != "POST /predict"]

    print(f"Stress test: duration={args.duration}s concurrency={args.concurrency}")
    print(f"Target: {BASE}")
    print(f"PID sampled: {args.pid or 'none'}")

    samples: list = []
    start_ts = time.time()

    threads = []
    for _ in range(args.concurrency):
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        threads.append(t)
    sampler_t = threading.Thread(target=sampler, args=(args.pid, samples), daemon=True)
    sampler_t.start()

    next_report = time.time() + 30
    while time.time() - start_ts < args.duration:
        time.sleep(1)
        if time.time() >= next_report:
            next_report = time.time() + 30
            with stats_lock:
                total_reqs = sum(len(b.latencies) for b in stats.values())
                total_to = sum(b.timeouts for b in stats.values())
            elapsed = time.time() - start_ts
            print(f"  [{elapsed:5.0f}s] reqs={total_reqs} timeouts={total_to} "
                  f"mem={samples[-1]['mem_mb'] if samples else 'n/a'}MB "
                  f"threads={samples[-1]['threads'] if samples else 'n/a'}")

    stop.set()
    time.sleep(1)

    print()
    print("=" * 110)
    print(f"{'Endpoint':<22} {'N':>6} {'2xx':>6} {'429':>5} {'4xx':>5} {'5xx':>5} {'T/O':>4} {'Err':>6} "
          f"{'p50':>7} {'p95':>7} {'p99':>7}")
    print("=" * 110)
    grand_total = grand_ok = grand_to = grand_err = 0
    err_kinds: "Counter[str]" = Counter()
    with stats_lock:
        for name in sorted(stats.keys()):
            b = stats[name]
            ms = [x * 1000 for x in b.latencies]
            n = len(ms)
            ok = sum(v for c, v in b.codes.items() if isinstance(c, int) and 200 <= c < 400)
            c429 = b.codes.get(429, 0)
            c4xx = sum(v for c, v in b.codes.items() if isinstance(c, int) and 400 <= c < 500 and c != 429)
            c5xx = sum(v for c, v in b.codes.items() if isinstance(c, int) and 500 <= c < 600)
            err = sum(v for c, v in b.codes.items() if isinstance(c, str) and c.startswith("ERR"))
            for c, v in b.codes.items():
                if isinstance(c, str) and c.startswith("ERR"):
                    err_kinds[c] += v
            grand_total += n
            grand_ok += ok
            grand_to += b.timeouts
            grand_err += err
            print(f"{name:<22} {n:>6} {ok:>6} {c429:>5} {c4xx:>5} {c5xx:>5} {b.timeouts:>4} {err:>6} "
                  f"{pct(ms, 50):>7.1f} {pct(ms, 95):>7.1f} {pct(ms, 99):>7.1f}")
    print("=" * 110)
    print(f"{'TOTAL':<22} {grand_total:>6} {grand_ok:>6} (2xx={grand_ok/max(grand_total,1)*100:.1f}%)  "
          f"timeouts={grand_to}  errors={grand_err}")
    if err_kinds:
        print(f"  error kinds: {dict(err_kinds)}")

    if samples:
        print()
        print("Resource samples (every 5s):")
        print(f"  t(s) {'cpu%':>6} {'mem_mb':>8} {'threads':>8}")
        for s in samples[::max(1, len(samples) // 10)]:
            print(f"  {s['t']:5.0f} {s['cpu']:>6.1f} {s['mem_mb']:>8.1f} {s['threads']:>8}")

    # Quick health judgement
    if grand_to > 0:
        print()
        print(f"[WARN] {grand_to} request(s) timed out — backend saturation detected")
        first_to = min(first_timeout_at.values()) if first_timeout_at else None
        if first_to is not None:
            print(f"       First timeout at t={first_to:.0f}s")


if __name__ == "__main__":
    sys.exit(main() or 0)

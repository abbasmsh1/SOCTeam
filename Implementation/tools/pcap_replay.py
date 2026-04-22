"""
Replay a PCAP through the IDS as a regression harness.

Runs CICFlowMeter over the PCAP (using the same patched FlowExtractor as the
live path), POSTs each extracted flow to /predict, and optionally asserts
that sandbox state converges to an expected IP-block set.

Usage:
    python -m Implementation.tools.pcap_replay --pcap test.pcap --expect-blocked 10.0.0.5
    python -m Implementation.tools.pcap_replay --pcap test.pcap --base http://127.0.0.1:6050

Exit codes:
    0  replay succeeded (and all assertions passed if provided)
    1  replay failed to process the PCAP
    2  assertion failure (expected IPs not blocked)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import List, Set

import requests


def _load_env():
    from dotenv import load_dotenv
    env_path = Path(__file__).resolve().parents[1] / ".env"
    if env_path.exists():
        load_dotenv(env_path)


def replay(pcap_path: str, base_url: str, admin_key: str,
           expect_blocked: List[str]) -> int:
    _load_env()
    if not os.path.exists(pcap_path):
        print(f"[replay] PCAP not found: {pcap_path}", file=sys.stderr)
        return 1

    # Import here so the script can still be invoked with --help without torch
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from Implementation.src.IDS.FlowExtractor import FlowExtractor

    fe = FlowExtractor()
    print(f"[replay] extracting flows from {pcap_path}")
    try:
        df = fe.extract_from_pcap(pcap_path)
    except Exception as exc:
        print(f"[replay] flow extraction failed: {exc}", file=sys.stderr)
        return 1
    print(f"[replay] extracted {len(df)} flows")
    if df.empty:
        return 1

    sent = ok = fail = 0
    t0 = time.time()
    headers = {"X-API-Key": admin_key, "Content-Type": "application/json"}
    with requests.Session() as s:
        s.headers.update(headers)
        for _, row in df.iterrows():
            payload = {k: (None if (v is None) else (float(v) if hasattr(v, "item") else v))
                       for k, v in row.dropna().to_dict().items()}
            try:
                r = s.post(f"{base_url}/predict/", json=payload, timeout=30)
                sent += 1
                if r.ok:
                    ok += 1
                else:
                    fail += 1
            except Exception:
                fail += 1
    elapsed = time.time() - t0
    print(f"[replay] {ok}/{sent} flows accepted ({fail} fails) in {elapsed:.1f}s")

    if expect_blocked:
        # Give the SOC workflow + sandbox writes time to land
        print("[replay] waiting 15s for SOC workflow to settle...")
        time.sleep(15)
        bl = requests.get(f"{base_url}/blocked-ips", headers=headers, timeout=30).json()
        blocked: Set[str] = set((bl.get("blocked_ips") or {}).keys())
        missing = [ip for ip in expect_blocked if ip not in blocked]
        if missing:
            print(f"[replay] FAIL: expected blocked IPs missing: {missing}", file=sys.stderr)
            return 2
        print(f"[replay] OK: all expected blocked IPs present ({len(expect_blocked)})")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--base", default="http://127.0.0.1:6050")
    ap.add_argument("--admin-key", default=os.getenv("IDS_ADMIN_API_KEY"))
    ap.add_argument("--expect-blocked", default="", help="comma-separated IPs expected to end up on the block list")
    args = ap.parse_args()
    if not args.admin_key:
        # Late-load after dotenv
        _load_env()
        args.admin_key = os.getenv("IDS_ADMIN_API_KEY")
        if not args.admin_key:
            print("[replay] IDS_ADMIN_API_KEY required (set env or pass --admin-key)", file=sys.stderr)
            return 1
    expected = [ip.strip() for ip in args.expect_blocked.split(",") if ip.strip()]
    return replay(args.pcap, args.base.rstrip("/"), args.admin_key, expected)


if __name__ == "__main__":
    sys.exit(main())

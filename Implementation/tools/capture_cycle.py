"""
Standalone packet-capture helper. Invoked as a subprocess by FlowExtractor
to isolate scapy from the backend's Python process — avoids `L2pcapListenSocket`
errors that appeared only under uvicorn threading/asyncio state.

Usage:
    python -m Implementation.tools.capture_cycle --iface <NPF_NAME> --duration 10 --out <pcap_path>

Writes a PCAP file on success, prints a one-line JSON status on stdout, exits 0.
"""

from __future__ import annotations

import argparse
import json
import os
import sys


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", required=True)
    ap.add_argument("--duration", type=int, default=10)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    try:
        import scapy.all as scapy  # lazy: avoid importing if we're just CLI-inspecting
    except ImportError as exc:
        print(json.dumps({"ok": False, "error": f"scapy missing: {exc}"}))
        return 2

    try:
        packets = scapy.sniff(iface=args.iface, timeout=args.duration)
    except Exception as exc:
        print(json.dumps({"ok": False, "error": f"sniff failed: {type(exc).__name__}: {exc}"}))
        return 3

    n = len(packets or [])
    if n == 0:
        # Still write a valid empty pcap so the caller knows it's the no-traffic case
        try:
            scapy.wrpcap(args.out, [])
        except Exception:
            pass
        print(json.dumps({"ok": True, "packets": 0, "out": args.out}))
        return 0

    try:
        scapy.wrpcap(args.out, packets)
    except Exception as exc:
        print(json.dumps({"ok": False, "error": f"wrpcap failed: {exc}"}))
        return 4

    print(json.dumps({"ok": True, "packets": n, "out": args.out, "size": os.path.getsize(args.out)}))
    return 0


if __name__ == "__main__":
    sys.exit(main())

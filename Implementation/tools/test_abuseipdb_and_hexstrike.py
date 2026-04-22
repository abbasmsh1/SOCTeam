"""
Smoke-tests two external integrations:

  1. AbuseIPDBReputationSource — queries real /api/v2/check for several IPs
     and prints the returned abuse_score, total_reports, country, ISP, and
     Tor/VPN/proxy flags. Requires ABUSEIPDB_API_KEY in env (already set
     in Implementation/.env).

  2. HexstrikeClient — runs health_check + nmap_scan against the
     explicitly-authorised target scanme.nmap.org. Requires the HexStrike
     server to be listening on http://127.0.0.1:8888.

Safe by design: scanme.nmap.org is operated by the Nmap project as a test
scan target ("free to scan this machine"). We do not scan anything else.
"""

from __future__ import annotations

import json
import os
import socket
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv  # noqa: E402

load_dotenv(ROOT / "Implementation" / ".env")

# ── Colours for terminal output ──────────────────────────────────────────
C_HEAD = "\033[1;36m"   # cyan bold
C_OK   = "\033[32m"
C_WARN = "\033[33m"
C_BAD  = "\033[31m"
C_DIM  = "\033[2m"
C_END  = "\033[0m"


def header(title: str) -> None:
    print(f"\n{C_HEAD}{'=' * 70}\n  {title}\n{'=' * 70}{C_END}")


# ── 1. AbuseIPDB ─────────────────────────────────────────────────────────
def test_abuseipdb() -> bool:
    header("1. AbuseIPDB reputation source")

    from Implementation.src.Agents.ReputationSource import (
        AbuseIPDBReputationSource, build_reputation_source,
    )

    key = os.getenv("ABUSEIPDB_API_KEY", "").strip()
    if not key:
        print(f"{C_BAD}FAIL{C_END}  ABUSEIPDB_API_KEY is not set")
        return False
    print(f"  API key: {key[:8]}…{key[-4:]} ({len(key)} chars)")
    print(f"  REPUTATION_SOURCE={os.getenv('REPUTATION_SOURCE', 'simulated')}")

    factory = build_reputation_source()
    print(f"  factory resolved: {type(factory).__name__}")

    if not isinstance(factory, AbuseIPDBReputationSource):
        print(f"{C_WARN}WARN{C_END}  factory did not return the AbuseIPDB adapter; "
              f"direct-instantiating for the test.")
        factory = AbuseIPDBReputationSource(api_key=key)

    class _Rep:
        """Matches the attribute surface the adapter sets on the object."""
        abuse_score = 0.0
        total_reports = 0
        country = ""
        isp = ""
        is_tor = False
        is_vpn = False
        is_proxy = False

    # Mixed test set: well-known-good DNS + commonly-reported scanner IPs.
    # We don't care what score they return — only that we get a real
    # response, not the simulated fallback.
    targets = [
        ("8.8.8.8",          "Google DNS — expect low/zero abuse score"),
        ("1.1.1.1",          "Cloudflare DNS — expect low/zero abuse score"),
        ("118.25.6.39",      "Historically reported scanner IP — may show reports"),
        ("185.220.101.1",    "Tor exit node (per Tor consensus) — is_tor may be true"),
    ]

    all_ok = True
    print(f"\n  {'IP':<18} {'score':>5} {'reports':>8} {'country':>8} "
          f"{'tor':>4} {'vpn':>4} {'proxy':>5}  isp")
    print(f"  {'-' * 18:<18} {'-' * 5:>5} {'-' * 8:>8} {'-' * 8:>8} "
          f"{'-' * 4:>4} {'-' * 4:>4} {'-' * 5:>5}  {'-' * 28}")

    for ip, note in targets:
        rep = _Rep()
        t0 = time.time()
        try:
            factory.fetch(ip, rep)
        except Exception as exc:
            print(f"  {ip:<18}  {C_BAD}EXCEPTION{C_END}: {exc}")
            all_ok = False
            continue
        dt = (time.time() - t0) * 1000
        isp = (rep.isp or "")[:28]
        print(
            f"  {ip:<18} {rep.abuse_score:>5.0f} {rep.total_reports:>8} "
            f"{(rep.country or '?'):>8} "
            f"{('yes' if rep.is_tor else 'no'):>4} "
            f"{('yes' if rep.is_vpn else 'no'):>4} "
            f"{('yes' if rep.is_proxy else 'no'):>5}  {isp} "
            f"{C_DIM}[{dt:.0f} ms]{C_END}"
        )
        print(f"    {C_DIM}— {note}{C_END}")

    print(f"\n{C_OK}PASS{C_END}  AbuseIPDB reachable, parser returned real data"
          if all_ok else f"\n{C_BAD}FAIL{C_END}  some queries failed")
    return all_ok


# ── 2. HexStrike port scan ───────────────────────────────────────────────
def is_port_open(host: str, port: int, timeout: float = 1.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def test_hexstrike() -> bool:
    header("2. HexStrike port scanning")

    from Implementation.src.Agents.HexstrikeClient import HexstrikeClient

    if not is_port_open("127.0.0.1", 8888):
        print(f"{C_WARN}WARN{C_END}  HexStrike server is not listening on :8888.")
        print(f"  Start it with:")
        print(f"    cd hexstrike-fresh && hexstrike_env\\Scripts\\python.exe hexstrike_server.py")
        print(f"  or re-run start_all.ps1 without -SkipHexstrike.")
        return False

    client = HexstrikeClient(base_url="http://127.0.0.1:8888", timeout=300)
    print(f"  Client: base_url={client.base_url}  timeout={client.timeout}s")

    # 2a. Skip /health on purpose — HexStrike's health endpoint walks
    # `which <tool>` for ~60+ tools and times out on a cold cache. Instead
    # we verify the server is reachable via a cheap /api/cache/stats call.
    print("\n  [2a] lightweight liveness via /api/cache/stats")
    import requests
    try:
        r = requests.get("http://127.0.0.1:8888/api/cache/stats", timeout=5)
        if r.status_code == 200:
            print(f"       status: {C_OK}alive{C_END}  ({r.text[:80]}...)")
        else:
            print(f"       status: {C_BAD}HTTP {r.status_code}{C_END}")
            return False
    except Exception as exc:
        print(f"       {C_BAD}unreachable: {exc}{C_END}")
        return False

    # 2b. Nmap scan on scanme.nmap.org
    TARGET = "scanme.nmap.org"
    PORTS  = "22,80,443,9929,31337"     # the ports scanme.nmap.org deliberately exposes
    # Use -sT (TCP connect): works without admin on Windows; -sCV / -sS need raw sockets.
    print(f"\n  [2b] nmap_scan(target={TARGET!r}, scan_type='-sT -sV', ports={PORTS!r})")
    print(f"       {C_DIM}scanme.nmap.org is authorised for test scans by the nmap project.{C_END}")
    t0 = time.time()
    result = client.nmap_scan(TARGET, scan_type="-sT -sV", ports=PORTS)
    dt = time.time() - t0
    print(f"       elapsed: {dt:.1f}s")

    if "error" in result:
        print(f"       {C_BAD}error: {result.get('error')} — {result.get('message', '')}{C_END}")
        return False

    # HexStrike wraps tool failures inside success=False + stderr. Surface that.
    if result.get("success") is False or (result.get("return_code") or 0) != 0:
        stderr = (result.get("stderr") or "")[:400]
        he = result.get("human_escalation", {}) or {}
        err_msg = he.get("error_message", "")[:400]
        print(f"       {C_WARN}tool failed (return_code={result.get('return_code')}):{C_END}")
        if err_msg:
            print(f"       stderr/err_msg: {err_msg}")
        if stderr and stderr != err_msg:
            print(f"       stderr: {stderr}")
        if "not recognized" in (err_msg + stderr) or "No such file" in (err_msg + stderr):
            print(f"\n       {C_WARN}>>> nmap binary is not installed on this host.{C_END}")
            print(f"       {C_DIM}    Install with: winget install -e --id Insecure.Nmap{C_END}")
            print(f"       {C_DIM}    or download:   https://nmap.org/download.html{C_END}")
        return False

    # Pretty-print a trimmed version
    print(f"       {C_DIM}top-level keys: {list(result.keys())}{C_END}")
    stdout = result.get("stdout") or result.get("output") or ""
    if stdout:
        lines = [ln for ln in stdout.splitlines() if ln.strip()]
        snippet = "\n       ".join(lines[:12])
        print(f"\n       first lines of nmap output:\n       {snippet}")
        if len(lines) > 12:
            print(f"       {C_DIM}... ({len(lines) - 12} more lines){C_END}")
    else:
        # Some HexStrike builds return structured results
        print(f"       {C_DIM}result preview:\n       "
              f"{json.dumps(result, indent=2)[:600]}{C_END}")

    # 2c. RustScan for speed comparison (best-effort — tool may not be installed)
    print(f"\n  [2c] rustscan_scan(target={TARGET!r}, ports='1-1000')  {C_DIM}(optional){C_END}")
    t0 = time.time()
    rs = client.rustscan_scan(TARGET, ports="1-1000")
    dt = time.time() - t0
    if "error" in rs:
        print(f"       {C_DIM}rustscan unavailable: {rs.get('error')} "
              f"({dt:.1f}s elapsed) — this is fine if the tool isn't installed.{C_END}")
    else:
        print(f"       elapsed: {dt:.1f}s")
        rstdout = rs.get("stdout") or rs.get("output") or ""
        for ln in (rstdout.splitlines() or [])[:6]:
            print(f"       {ln}")

    # 2d. Stats
    print("\n  [2d] client.get_stats()")
    for k, v in client.get_stats().items():
        print(f"       {k:<16} {v}")

    print(f"\n{C_OK}PASS{C_END}  HexStrike reachable, nmap scan returned data")
    return True


# ── main ─────────────────────────────────────────────────────────────────
def main() -> int:
    results = {}
    try:
        results["abuseipdb"] = test_abuseipdb()
    except Exception as exc:
        print(f"{C_BAD}AbuseIPDB test crashed: {exc}{C_END}")
        results["abuseipdb"] = False

    try:
        results["hexstrike"] = test_hexstrike()
    except Exception as exc:
        print(f"{C_BAD}HexStrike test crashed: {exc}{C_END}")
        results["hexstrike"] = False

    header("Summary")
    for name, ok in results.items():
        col = C_OK if ok else C_BAD
        print(f"  {name:<12} {col}{'PASS' if ok else 'FAIL'}{C_END}")
    return 0 if all(results.values()) else 1


if __name__ == "__main__":
    sys.exit(main())

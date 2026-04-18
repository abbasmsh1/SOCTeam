#!/usr/bin/env python3
"""
e2e_soc_smoke_test.py
======================
End-to-end smoke test for the Autonomous SOC pipeline.

Tests (in order):
  1. Baseline: GET /sandbox/state → empty
  2. POST /soc/auto-rules for each of the 8 heuristic attack types
  3. GET /sandbox/state → rules present after malicious detections
  4. POST /sandbox/clear → sandbox reset
  5. GET /sandbox/state → clean again

Usage:
    python e2e_soc_smoke_test.py [--base-url http://localhost:6050] [--api-key ids-secret-key]

Requires: requests  (pip install requests)
"""

import argparse
import json
import sys
import io
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List

import requests

# ── Colour helpers ─────────────────────────────────────────────────────────────

GREEN  = "[OK]  "
RED    = "[FAIL]"
YELLOW = "[WARN]"
CYAN   = "[INFO]"
RESET  = ""
BOLD   = ""

def ok(msg: str)   -> None: print(f"  {GREEN} {msg}")
def fail(msg: str) -> None: print(f"  {RED} {msg}")
def info(msg: str) -> None: print(f"  {CYAN} {msg}")
def warn(msg: str) -> None: print(f"  {YELLOW} {msg}")

# ── Attack scenarios ───────────────────────────────────────────────────────────

ATTACK_SCENARIOS: List[Dict[str, Any]] = [
    {
        "label": "SMB / Lateral Movement",
        "payload": {
            "detection": {
                "SourceIP":      "10.0.0.31",
                "DestinationIP": "10.0.0.50",
                "Protocol":      "TCP",
                "Attack":        "Infilteration",
                "severity":      "HIGH",
            }
        },
    },
    {
        "label": "SQL Injection",
        "payload": {
            "detection": {
                "SourceIP":      "203.0.113.5",
                "DestinationIP": "10.0.0.1",
                "Protocol":      "TCP",
                "Attack":        "SQL Injection",
                "severity":      "CRITICAL",
            }
        },
    },
    {
        "label": "DDoS / DoS",
        "payload": {
            "detection": {
                "SourceIP":      "0.0.0.0",
                "DestinationIP": "10.0.0.1",
                "Protocol":      "UDP",
                "Attack":        "DDoS",
                "severity":      "CRITICAL",
            }
        },
    },
    {
        "label": "Brute-Force / SSH",
        "payload": {
            "detection": {
                "SourceIP":      "198.51.100.7",
                "DestinationIP": "10.0.0.1",
                "Protocol":      "TCP",
                "Attack":        "Brute Force",
                "severity":      "HIGH",
            }
        },
    },
    {
        "label": "Botnet C2",
        "payload": {
            "detection": {
                "SourceIP":      "10.0.0.20",
                "DestinationIP": "185.220.101.5",
                "Protocol":      "TCP",
                "Attack":        "Bot",
                "severity":      "CRITICAL",
            }
        },
    },
    {
        "label": "Data Exfiltration",
        "payload": {
            "detection": {
                "SourceIP":      "10.0.0.14",
                "DestinationIP": "203.0.113.99",
                "Protocol":      "TCP",
                "Attack":        "Exfilteration",
                "severity":      "CRITICAL",
            }
        },
    },
    {
        "label": "Port Scan",
        "payload": {
            "detection": {
                "SourceIP":      "192.168.99.3",
                "DestinationIP": "10.0.0.1",
                "Protocol":      "TCP",
                "Attack":        "PortScan",
                "severity":      "MEDIUM",
            }
        },
    },
    {
        "label": "Generic Threat (free-text)",
        "payload": {
            "description": "Suspicious outbound ICMP flood detected from host 10.0.0.55"
        },
    },
]

# ── Test runner ────────────────────────────────────────────────────────────────

@dataclass
class TestResult:
    label: str
    passed: bool
    detail: str = ""

@dataclass
class SuiteResult:
    results: List[TestResult] = field(default_factory=list)

    def add(self, r: TestResult) -> None:
        self.results.append(r)
        if r.passed:
            ok(r.label)
        else:
            fail(f"{r.label}: {r.detail}")

    @property
    def n_pass(self) -> int: return sum(1 for r in self.results if r.passed)
    @property
    def n_fail(self) -> int: return sum(1 for r in self.results if not r.passed)


def run_suite(base_url: str, api_key: str) -> SuiteResult:
    suite = SuiteResult()
    session = requests.Session()
    session.headers.update({"X-API-Key": api_key, "Content-Type": "application/json"})
    timeout = 30

    # ── 1. Health check ──────────────────────────────────────────────────────
    print(f"\n{BOLD}[1/5] Health Check{RESET}")
    try:
        r = session.get(f"{base_url}/events/stats", timeout=timeout)
        r.raise_for_status()
        suite.add(TestResult("Backend reachable (GET /events/stats)", True))
    except Exception as exc:
        suite.add(TestResult("Backend reachable", False, str(exc)))
        fail("Cannot reach backend — aborting remaining tests.")
        return suite

    # ── 2. Baseline sandbox state ────────────────────────────────────────────
    print(f"\n{BOLD}[2/5] Baseline Sandbox State (GET /sandbox/state){RESET}")
    try:
        r = session.get(f"{base_url}/sandbox/state", timeout=timeout)
        r.raise_for_status()
        state = r.json()
        suite.add(TestResult("GET /sandbox/state returns 200", True))
        info(f"blocked_ips={state.get('blocked_ips', [])!r}  "
             f"firewall_rules={len(state.get('firewall_rules', []))}  "
             f"total_actions={state.get('total_actions', 0)}")
    except Exception as exc:
        suite.add(TestResult("GET /sandbox/state", False, str(exc)))

    # ── 3. Auto-rule generation for all 8 scenarios ──────────────────────────
    print(f"\n{BOLD}[3/5] POST /soc/auto-rules — 8 Attack Scenarios{RESET}")
    generated_rules: List[str] = []
    for scenario in ATTACK_SCENARIOS:
        label = scenario["label"]
        try:
            r = session.post(
                f"{base_url}/soc/auto-rules",
                json=scenario["payload"],
                timeout=timeout,
            )
            r.raise_for_status()
            data = r.json()
            rules = data.get("rules", [])
            generated_rules.extend(rules)
            suite.add(TestResult(
                f"Auto-rules: {label}",
                True,
                f"{len(rules)} rule(s)",
            ))
            info(f"  Rules generated: {len(rules)}  "
                 f"agent={data.get('agent_response_used', '?')}  "
                 f"heuristic={data.get('heuristic_used', '?')}")
            if rules:
                info(f"  Sample rule: {rules[0][:80]}")
            # Brief pause between requests
            time.sleep(0.3)
        except Exception as exc:
            suite.add(TestResult(f"Auto-rules: {label}", False, str(exc)))

    # ── 4. Sandbox populated ─────────────────────────────────────────────────
    print(f"\n{BOLD}[4/5] Verify Sandbox Populated (GET /sandbox/state){RESET}")
    try:
        r = session.get(f"{base_url}/sandbox/state", timeout=timeout)
        r.raise_for_status()
        state = r.json()
        total = state.get("total_actions", 0)
        suite.add(TestResult(
            "Sandbox has recorded actions after detections",
            total > 0,
            f"total_actions={total}",
        ))
        info(f"blocked_ips={state.get('blocked_ips', [])!r}")
        info(f"firewall_rules count={len(state.get('firewall_rules', []))}")
        info(f"rate_limited_hosts={state.get('rate_limited_hosts', [])!r}")
    except Exception as exc:
        suite.add(TestResult("Verify sandbox populated", False, str(exc)))

    # ── 5. Clear sandbox ─────────────────────────────────────────────────────
    print(f"\n{BOLD}[5/5] Clear Sandbox (POST /sandbox/clear){RESET}")
    try:
        r = session.post(f"{base_url}/sandbox/clear", timeout=timeout)
        r.raise_for_status()
        suite.add(TestResult("POST /sandbox/clear returns 200", True))

        # Confirm cleared
        r2 = session.get(f"{base_url}/sandbox/state", timeout=timeout)
        r2.raise_for_status()
        state2 = r2.json()
        cleared = (
            len(state2.get("blocked_ips", [])) == 0
            and len(state2.get("firewall_rules", [])) == 0
            and state2.get("total_actions", -1) == 0
        )
        suite.add(TestResult(
            "Sandbox is empty after clear",
            cleared,
            f"blocked_ips={state2.get('blocked_ips')!r}",
        ))
    except Exception as exc:
        suite.add(TestResult("Clear sandbox", False, str(exc)))

    return suite


# ── Entry point ────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Autonomous SOC E2E smoke test")
    parser.add_argument("--base-url", default="http://localhost:6050", help="IDS backend base URL")
    parser.add_argument("--api-key",  default="ids-secret-key",        help="X-API-Key header value")
    args = parser.parse_args()

    print(f"\n=== Autonomous SOC Smoke Test ===")
    print(f"  Target: {args.base_url}")

    suite = run_suite(args.base_url, args.api_key)

    print(f"\n{BOLD}{'═' * 44}{RESET}")
    total = suite.n_pass + suite.n_fail
    colour = GREEN if suite.n_fail == 0 else RED
    print(f"  {colour}{BOLD}Results: {suite.n_pass}/{total} passed{RESET}")
    if suite.n_fail:
        print(f"\n  {RED}Failed tests:{RESET}")
        for r in suite.results:
            if not r.passed:
                print(f"    • {r.label}: {r.detail}")
    print()
    sys.exit(0 if suite.n_fail == 0 else 1)


if __name__ == "__main__":
    main()

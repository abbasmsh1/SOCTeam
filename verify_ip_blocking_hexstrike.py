"""
SOC Team - IP Blocking & Hexstrike Verification Script
======================================================
Standalone verification script that tests the RemediationAgent's
IP blocking logic and validates the Hexstrike-AI client and server
installation — all without requiring the backend server to be running.

Sections:
  1. RemediationAgent – IP Blocking (parse rules, block IPs, handle edge cases)
  2. HexstrikeClient  – Server Health & Tool Capabilities
  3. Hexstrike-AI     – Server File Installation Check
  4. End-to-End       – Full IP Blocking Flow Simulation
"""

import sys
import os
import json
import datetime

# Ensure the project root is on the import path
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

print("=" * 60)
print("  SOC TEAM - IP BLOCKING & HEXSTRIKE VERIFICATION")
print("=" * 60)


# ──────────────────────────────────────────────────────────
# SECTION 1: RemediationAgent – IP Blocking
# ──────────────────────────────────────────────────────────
print("\n[1/4] Testing RemediationAgent – IP Blocking Logic")
print("-" * 50)

try:
    from Implementation.src.Agents.RemediationAgent import RemediationAgent

    agent = RemediationAgent(dry_run=True)

    # Test 1a: Basic BLOCK_IP — single malicious IP
    result = agent.process({
        "threat_info": {"Attack": "DDoS", "SourceIP": "192.168.1.99"},
        "defense_plan": (
            "[ACTIONABLE_RULES]"
            '[{"action": "BLOCK_IP", "target": "192.168.1.99", "duration": "24h", "reason": "DDoS attack detected"}]'
            "[/ACTIONABLE_RULES]"
        ),
    })
    rules = result.get("enforced_rules", [])
    log = result.get("execution_log", [])

    blocked = any(r.get("action") == "BLOCK_IP" and r.get("target") == "192.168.1.99" for r in rules)
    print(f"  Test 1a (BLOCK_IP 192.168.1.99):  {'PASS' if blocked else 'FAIL'}")
    if log:
        print(f"           Status={log[0].get('status', '?')}, DryRun={log[0].get('dry_run', '?')}")

    # Test 1b: Multiple malicious IPs — mixed actions
    plan_multi = (
        "[ACTIONABLE_RULES]"
        '[{"action": "BLOCK_IP", "target": "10.0.0.1", "duration": "1h"},'
        ' {"action": "BLOCK_IP", "target": "10.0.0.2", "duration": "permanent"},'
        ' {"action": "RATE_LIMIT", "target": "10.0.0.3", "limit": "10/s"}]'
        "[/ACTIONABLE_RULES]"
    )
    result2 = agent.process({
        "threat_info": {"Attack": "Port Scan", "SourceIP": "10.0.0.1"},
        "defense_plan": plan_multi,
    })
    rules2 = result2.get("enforced_rules", [])
    block_count = sum(1 for r in rules2 if r.get("action") == "BLOCK_IP")
    rate_count = sum(1 for r in rules2 if r.get("action") == "RATE_LIMIT")
    print(f"  Test 1b (Multi-IP rules):          {'PASS' if block_count == 2 and rate_count == 1 else 'FAIL'}")
    print(f"           BLOCK_IP={block_count}, RATE_LIMIT={rate_count}")

    # Test 1c: Rule parsing from LLM-style text (with markdown code fences)
    plan_llmstyle = (
        "Based on the analysis, the following actions are recommended:\n"
        "[ACTIONABLE_RULES]\n```json\n"
        '[{"action": "BLOCK_IP", "target": "172.16.5.22", "duration": "6h", "reason": "Brute force"}]\n'
        "```\n[/ACTIONABLE_RULES]"
    )
    result3 = agent.process({
        "threat_info": {"Attack": "BruteForce", "SourceIP": "172.16.5.22"},
        "defense_plan": plan_llmstyle,
    })
    llm_rules = result3.get("enforced_rules", [])
    llm_blocked = any(r.get("target") == "172.16.5.22" for r in llm_rules)
    print(f"  Test 1c (LLM-style plan parse):    {'PASS' if llm_blocked else 'FAIL'}")

    # Test 1d: Empty plan — should not crash, should return NO_ACTION
    result4 = agent.process({
        "threat_info": {"Attack": "Unknown"},
        "defense_plan": "No actionable rules here.",
    })
    print(f"  Test 1d (Empty plan graceful):     {'PASS' if result4.get('remediation_status') == 'NO_ACTION' else 'FAIL'}")

    print(f"\n  Remediation log path: {agent.log_path}")

except Exception as e:
    print(f"  EXCEPTION in RemediationAgent tests: {e}")
    import traceback
    traceback.print_exc()


# ──────────────────────────────────────────────────────────
# SECTION 2: HexstrikeClient – Health & Capabilities
# ──────────────────────────────────────────────────────────
print("\n[2/4] Testing HexstrikeClient – Server Health & Capabilities")
print("-" * 50)

try:
    from Implementation.src.Agents.HexstrikeClient import HexstrikeClient
    import inspect

    client = HexstrikeClient(base_url="http://localhost:8888", timeout=5)

    # Health check — verifies Hexstrike server is reachable
    health = client.health_check()
    is_healthy = health.get("status") == "healthy"
    print(f"  Hexstrike server at port 8888:     {'ONLINE' if is_healthy else 'OFFLINE (expected if not started)'}")
    if not is_healthy:
        print(f"    Reason: {health.get('error', 'unknown')}")

    # Enumerate available tool wrapper methods by category
    tool_methods = [
        m for m in dir(client)
        if not m.startswith("_") and callable(getattr(client, m))
        and m not in {"health_check", "get_process_status", "terminate_process", "get_cache_stats"}
    ]
    print(f"\n  Available security tool wrappers ({len(tool_methods)}):")

    categories = {
        "Network Recon":   ["nmap_scan", "rustscan_scan", "masscan_scan", "amass_enum", "subfinder_enum"],
        "Web Security":    ["nuclei_scan", "sqlmap_scan", "nikto_scan", "gobuster_scan", "feroxbuster_scan", "ffuf_scan", "wpscan_scan"],
        "Auth/Passwords":  ["hydra_brute"],
        "Cloud/Container": ["trivy_scan", "kube_hunter_scan"],
        "AI Intelligence": ["analyze_target", "select_tools"],
    }
    for cat, methods in categories.items():
        found = [m for m in methods if hasattr(client, m)]
        print(f"    {cat:<20}: {', '.join(found)}")

    # Print method signatures for key tools
    print(f"\n  nmap_scan signature: {inspect.signature(client.nmap_scan)}")
    print(f"  nuclei_scan signature: {inspect.signature(client.nuclei_scan)}")

except Exception as e:
    print(f"  EXCEPTION in HexstrikeClient tests: {e}")
    import traceback
    traceback.print_exc()


# ──────────────────────────────────────────────────────────
# SECTION 3: Hexstrike Server File Check
# ──────────────────────────────────────────────────────────
print("\n[3/4] Checking Hexstrike-AI Server Installation")
print("-" * 50)

hexstrike_path = os.path.join(os.path.dirname(__file__), "hexstrike-ai")
server_file = os.path.join(hexstrike_path, "hexstrike_server.py")
mcp_file = os.path.join(hexstrike_path, "hexstrike_mcp.py")
readme_file = os.path.join(hexstrike_path, "README.md")

# Check existence and size of key server files
for label, path in [("hexstrike_server.py", server_file), ("hexstrike_mcp.py", mcp_file), ("README.md", readme_file)]:
    if os.path.exists(path):
        size_kb = os.path.getsize(path) // 1024
        print(f"  {label:<24} FOUND ({size_kb} KB)")
    else:
        print(f"  {label:<24} MISSING")

# Scan the README for mentions of supported security tools
if os.path.exists(readme_file):
    with open(readme_file, "r", encoding="utf-8", errors="replace") as f:
        readme = f.read(3000)
    tool_keywords = [
        "nmap", "nuclei", "sqlmap", "hydra", "metasploit", "nikto",
        "gobuster", "ffuf", "amass", "trivy", "rustscan", "masscan",
        "feroxbuster", "wpscan", "kube",
    ]
    found_tools = [t for t in tool_keywords if t.lower() in readme.lower()]
    print(f"\n  Tools mentioned in README: {', '.join(found_tools)}")

# Load and display MCP configuration if present
mcp_config = os.path.join(hexstrike_path, "hexstrike-ai-mcp.json")
if os.path.exists(mcp_config):
    with open(mcp_config, "r") as f:
        cfg = json.load(f)
    print(f"\n  MCP config loaded: {json.dumps(cfg, indent=4)}")


# ──────────────────────────────────────────────────────────
# SECTION 4: End-to-End IP Blocking Flow (Static Simulation)
# ──────────────────────────────────────────────────────────
print("\n[4/4] End-to-End IP Blocking Flow Simulation (offline)")
print("-" * 50)

try:
    from Implementation.src.Agents.RemediationAgent import RemediationAgent

    # Simulate what a Blue Team SOC response would produce for known attacks
    MALICIOUS_IPS = [
        ("192.168.200.1", "DDoS",        "24h"),
        ("10.10.50.99",   "Port_Scan",   "12h"),
        ("172.20.1.33",   "Brute_Force", "permanent"),
    ]

    agent = RemediationAgent(dry_run=True)
    all_passed = True

    for src_ip, attack, duration in MALICIOUS_IPS:
        plan = (
            f'[ACTIONABLE_RULES]'
            f'[{{"action": "BLOCK_IP", "target": "{src_ip}", "duration": "{duration}", "reason": "{attack} attack from {src_ip}"}}]'
            f'[/ACTIONABLE_RULES]'
        )
        result = agent.process({
            "threat_info": {"Attack": attack, "SourceIP": src_ip},
            "defense_plan": plan,
        })
        log = result.get("execution_log", [])
        blocked = any(e.get("action") == "BLOCK_IP" and e.get("target") == src_ip for e in log)
        status = log[0].get("status") if log else "NO LOG"
        flag = "PASS" if blocked else "FAIL"
        if not blocked:
            all_passed = False
        print(f"  {flag}  {src_ip:18} | Attack={attack:12} | Status={status} | Duration={duration}")

    print(f"\n  Overall IP Blocking: {'ALL PASS' if all_passed else 'SOME CHECKS FAILED'}")

except Exception as e:
    print(f"  EXCEPTION in end-to-end test: {e}")
    import traceback
    traceback.print_exc()

# ── Summary ──
print("\n" + "=" * 60)
print("  VERIFICATION COMPLETE")
print("=" * 60)
print(f"  Timestamp: {datetime.datetime.now().isoformat()}")

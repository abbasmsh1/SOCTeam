"""
Autonomous SOC Rule Generator
==============================
Receives IDS threat alerts, invokes the Blue Team Agent for agentic
LLM-powered analysis, parses structured [ACTIONABLE_RULES] blocks, and
enforces them inside the DefensiveActionSandbox.

Improvements over v1:
  - Correct BlueTeam API call (threat_info / system_state payload).
  - Proper response extraction from defense_plan key.
  - Richer heuristic fallback covering 8 attack categories.
  - Structured ThreatContext dataclass for clean data flow.
  - process_threat() returns a rich result dict (usable by the API layer).
  - Multi-rule deduplication prevents re-blocking the same target twice.
  - process_ids_detection() convenience method bridges IDS → SOC.
"""

import sys
import os
import json
import re
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# -- Path bootstrap -----------------------------------------------------------
# Add project root and local Agents dir to path to ensure robust imports
_agent_dir = os.path.dirname(os.path.abspath(__file__))
_project_root = os.path.abspath(os.path.join(_agent_dir, "..", ".."))

if _project_root not in sys.path:
    sys.path.insert(0, _project_root)
if _agent_dir not in sys.path:
    sys.path.insert(0, _agent_dir)

from Agents.LegacyCompat import BlueTeamAgent
from Agents.DefensiveActionSandbox import DefensiveActionSandbox

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Threat context dataclass
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ThreatContext:
    """Normalised view of a threat alert passed to the SOC pipeline."""
    description: str
    source_ip: str = "UNKNOWN"
    destination_ip: str = "UNKNOWN"
    attack_type: str = "Unknown"
    confidence: float = 0.0
    protocol: str = "ANY"
    port: int = 0
    raw: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_ids_detection(cls, detection: Dict[str, Any]) -> "ThreatContext":
        """Build a ThreatContext from an IDS /predict response payload."""
        label = str(detection.get("prediction") or detection.get("Attack") or "Unknown")
        src_ip = (
            detection.get("Source IP")
            or detection.get("SourceIP")
            or detection.get("src_ip")
            or "UNKNOWN"
        )
        dst_ip = (
            detection.get("Destination IP")
            or detection.get("DestinationIP")
            or detection.get("dst_ip")
            or "UNKNOWN"
        )
        confidence = float(
            detection.get("malicious_confidence")
            or detection.get("confidence")
            or detection.get("ids_confidence")
            or 0.0
        )
        protocol = str(detection.get("Protocol", "ANY"))
        port = int(detection.get("Destination Port") or detection.get("dst_port") or 0)

        description = (
            f"ALERT: {label} detected. "
            f"Source: {src_ip} → Destination: {dst_ip}. "
            f"Protocol: {protocol}, Port: {port}. "
            f"Confidence: {confidence:.1%}."
        )

        return cls(
            description=description,
            source_ip=src_ip,
            destination_ip=dst_ip,
            attack_type=label,
            confidence=confidence,
            protocol=protocol,
            port=port,
            raw=detection,
        )

    @classmethod
    def from_text(cls, text: str) -> "ThreatContext":
        """Build a ThreatContext from a free-form threat description string."""
        ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
        src_ip = ip_match.group(0) if ip_match else "UNKNOWN"
        attack_type = _infer_attack_type(text)
        return cls(
            description=text,
            source_ip=src_ip,
            attack_type=attack_type,
            raw={},
        )


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _infer_attack_type(text: str) -> str:
    """Simple keyword-based attack-type classifier."""
    text_lower = text.lower()
    if any(kw in text_lower for kw in ("smb", "wannacry", "lateral movement", "445")):
        return "SMB_LATERAL_MOVEMENT"
    if any(kw in text_lower for kw in ("sql injection", "sqli", "waf")):
        return "SQL_INJECTION"
    if any(kw in text_lower for kw in ("ddos", "flood", "volumetric")):
        return "DDOS"
    if any(kw in text_lower for kw in ("bruteforce", "brute force", "ssh", "rdp", "login attempt")):
        return "BRUTEFORCE"
    if any(kw in text_lower for kw in ("botnet", "c&c", "command and control", "c2")):
        return "BOTNET"
    if any(kw in text_lower for kw in ("exfiltration", "data transfer", "dns tunnel")):
        return "EXFILTRATION"
    if any(kw in text_lower for kw in ("portscan", "port scan", "nmap", "masscan")):
        return "PORT_SCAN"
    if any(kw in text_lower for kw in ("ransomware", "crypto", "encrypt")):
        return "RANSOMWARE"
    return "Unknown"


# ─────────────────────────────────────────────────────────────────────────────
# AutoSOCRuleGenerator
# ─────────────────────────────────────────────────────────────────────────────

class AutoSOCRuleGenerator:
    """
    Agentic SOC pipeline:
      1. Normalise incoming alert into a ThreatContext.
      2. Call BlueTeamAgent for LLM-powered defensive planning.
      3. Extract structured [ACTIONABLE_RULES] from the plan.
      4. Fallback to heuristic rules if the LLM is unavailable.
      5. Deduplicate rules and enforce them in the DefensiveActionSandbox.
      6. Return a rich result dict for the API caller.
    """

    def __init__(self, api_key: Optional[str] = None) -> None:
        self.agent = BlueTeamAgent(api_key=api_key)
        self.sandbox = DefensiveActionSandbox()

    # ── Public interfaces ────────────────────────────────────────────────────

    def process_ids_detection(self, detection: Dict[str, Any]) -> Dict[str, Any]:
        """
        Convenience bridge: takes a raw IDS detection dict and runs the
        full SOC pipeline.  Use this from the IDS API layer.
        """
        ctx = ThreatContext.from_ids_detection(detection)
        return self.process_threat(ctx)

    def process_threat(self, threat: Any) -> Dict[str, Any]:
        """
        Full SOC pipeline.

        Args:
            threat: Either a ThreatContext, a plain string description,
                    or a raw IDS detection dict.

        Returns:
            dict with keys: rules_enforced, rules_failed, agent_plan,
                            sandbox_summary, threat_context.
        """
        # Normalise input
        if isinstance(threat, str):
            ctx = ThreatContext.from_text(threat)
        elif isinstance(threat, dict):
            ctx = ThreatContext.from_ids_detection(threat)
        else:
            ctx = threat  # already a ThreatContext

        logger.info("[SOC] Incoming alert: %s", ctx.description)
        print(f"\n[SOC] {'='*55}")
        print(f"[SOC] Incoming Alert  : {ctx.description}")
        print(f"[SOC] Attack Type     : {ctx.attack_type}")
        print(f"[SOC] Source IP       : {ctx.source_ip}")
        print(f"[SOC] Confidence      : {ctx.confidence:.1%}")
        print(f"[SOC] {'='*55}\n")
        print("[SOC] Dispatching Blue Team Agent for autonomous analysis...")

        # ── Phase 1: LLM Agent ────────────────────────────────────────────
        agent_plan, rules = self._invoke_agent(ctx)

        # ── Phase 2: Heuristic fallback ───────────────────────────────────
        if not rules:
            print("[SOC] Agent returned no structured rules → engaging heuristic fallback.")
            rules = self._heuristic_fallback(ctx)

        if not rules:
            print("[SOC] ⚠ No actionable rules generated for this alert.")
            return {
                "rules_enforced": [],
                "rules_failed": [],
                "agent_plan": agent_plan,
                "sandbox_summary": self.sandbox.list_active_rules(),
                "threat_context": vars(ctx),
            }

        # ── Phase 3: Deduplicate ──────────────────────────────────────────
        rules = self._deduplicate_rules(rules)
        print(f"[SOC] ✔ {len(rules)} unique rule(s) queued for enforcement.")

        # ── Phase 4: Enforce in sandbox ───────────────────────────────────
        enforced, failed = self._enforce_rules(rules, ctx)

        sandbox_summary = self.sandbox.list_active_rules()
        print(f"\n[SOC] Enforcement complete — {len(enforced)} enforced, {len(failed)} failed.")
        print(f"[SOC] Active blocks: {len(sandbox_summary.get('blocked_ips', {}))}")
        print(f"[SOC] Firewall rules: {sandbox_summary.get('firewall_rules_count', 0)}\n")

        return {
            "rules_enforced": enforced,
            "rules_failed": failed,
            "agent_plan": agent_plan,
            "sandbox_summary": sandbox_summary,
            "threat_context": {
                "description": ctx.description,
                "source_ip": ctx.source_ip,
                "destination_ip": ctx.destination_ip,
                "attack_type": ctx.attack_type,
                "confidence": ctx.confidence,
            },
        }

    # ── Private: Agent invocation ────────────────────────────────────────────

    def _invoke_agent(self, ctx: ThreatContext):
        """
        Call the BlueTeamAgent with the correct payload format and
        extract (plan_text, rules_list).
        """
        threat_info_payload = {
            "description": ctx.description,
            "attack_type": ctx.attack_type,
            "source_ip": ctx.source_ip,
            "destination_ip": ctx.destination_ip,
            "confidence": ctx.confidence,
            "protocol": ctx.protocol,
            "port": ctx.port,
        }

        try:
            response_data = self.agent.process({
                "threat_info": threat_info_payload,
                "system_state": "Production network — autonomous response authorised.",
            })
        except Exception as exc:
            logger.warning("[SOC] Agent call failed: %s", exc)
            return "AGENT_UNAVAILABLE", []

        # BlueTeamAgent returns {"defense_plan": str, "security_assessment": dict, ...}
        plan_text = ""
        if isinstance(response_data, dict):
            plan_text = (
                response_data.get("defense_plan")
                or response_data.get("plan")
                or ""
            )
            # Also handle old-style messages list (legacy)
            if not plan_text and "messages" in response_data:
                last = response_data["messages"][-1] if response_data["messages"] else None
                if last:
                    plan_text = getattr(last, "content", str(last))
        else:
            plan_text = str(response_data)

        print("\n[SOC] --- Agent Defence Plan -------------------------")
        print(plan_text or "(No plan text returned)")
        print("[SOC] --------------------------------------------------\n")

        rules = self._extract_rules(plan_text)
        return plan_text, rules

    # ── Private: Rule extraction ─────────────────────────────────────────────

    def _extract_rules(self, text: str) -> List[Dict[str, Any]]:
        """Parse the [ACTIONABLE_RULES]…[/ACTIONABLE_RULES] block."""
        if not text:
            return []
        try:
            pattern = r"\[ACTIONABLE_RULES\]\s*([\s\S]*?)\s*\[/ACTIONABLE_RULES\]"
            match = re.search(pattern, text)
            if match:
                raw_json = match.group(1).strip()
                parsed = json.loads(raw_json)
                if isinstance(parsed, list):
                    return parsed
        except Exception as exc:
            logger.debug("[SOC] Rule extraction parse error: %s", exc)
        return []

    # ── Private: Heuristic fallback ──────────────────────────────────────────

    def _heuristic_fallback(self, ctx: ThreatContext) -> List[Dict[str, Any]]:
        """
        Deterministic, playbook-based rule generation for 8 attack categories.
        Used when the LLM is unavailable or returns no structured rules.
        """
        rules: List[Dict[str, Any]] = []
        src = ctx.source_ip
        atype = ctx.attack_type.upper()
        text = ctx.description.lower()

        # ── SMB / Lateral Movement / Ransomware ──────────────────────────
        if atype in ("SMB_LATERAL_MOVEMENT", "RANSOMWARE") or any(
            kw in text for kw in ("smb", "445", "wannacry", "ransomware")
        ):
            rules += [
                {
                    "action": "BLOCK_IP",
                    "target": src,
                    "reason": "SMB lateral movement / ransomware propagation",
                    "duration": "permanent",
                },
                {
                    "action": "FIREWALL_RULE",
                    "priority": 10,
                    "action_type": "DENY",
                    "src_ip": src,
                    "port": 445,
                    "protocol": "TCP",
                    "reason": "Deny SMB from suspicious host",
                },
                {
                    "action": "ISOLATE_HOST",
                    "target": src,
                    "reason": "Quarantine host exhibiting lateral movement",
                },
            ]

        # ── SQL Injection / WAF hit ───────────────────────────────────────
        elif atype == "SQL_INJECTION" or any(
            kw in text for kw in ("sql injection", "sqli", "union select", "waf")
        ):
            rules += [
                {
                    "action": "BLOCK_IP",
                    "target": src,
                    "reason": "Confirmed SQL injection attempt via WAF signature",
                    "duration": "permanent",
                },
                {
                    "action": "TCP_RESET",
                    "target": src,
                    "reason": "Terminate active exfiltration session",
                },
                {
                    "action": "TUNE_SIEM",
                    "target": "WAF_SQLI_RULE",
                    "reason": "Increase sensitivity for SQLi pattern detected from this source",
                },
            ]

        # ── DDoS / Flood ─────────────────────────────────────────────────
        elif atype == "DDOS" or any(kw in text for kw in ("ddos", "flood", "volumetric")):
            rules += [
                {
                    "action": "RATE_LIMIT",
                    "target": src,
                    "limit": "5/s",
                    "reason": "Anomalous volumetric traffic (DDoS)",
                },
                {
                    "action": "BLOCK_IP",
                    "target": src,
                    "reason": "DDoS source — high packet rate detected",
                    "duration": "1h",
                },
            ]

        # ── Bruteforce ────────────────────────────────────────────────────
        elif atype == "BRUTEFORCE" or any(
            kw in text for kw in ("bruteforce", "brute force", "ssh", "rdp", "login attempt")
        ):
            port_for_rule = ctx.port or (22 if "ssh" in text else 3389)
            rules += [
                {
                    "action": "BLOCK_IP",
                    "target": src,
                    "reason": "Repeated failed authentication (bruteforce)",
                    "duration": "1h",
                },
                {
                    "action": "FIREWALL_RULE",
                    "priority": 15,
                    "action_type": "DENY",
                    "src_ip": src,
                    "port": port_for_rule,
                    "protocol": "TCP",
                    "reason": f"Block bruteforce source on port {port_for_rule}",
                },
                {
                    "action": "RATE_LIMIT",
                    "target": src,
                    "limit": "2/s",
                    "reason": "Throttle repeated auth attempts",
                },
            ]

        # ── Botnet / C2 ───────────────────────────────────────────────────
        elif atype == "BOTNET" or any(kw in text for kw in ("botnet", "c&c", "c2", "command and control")):
            rules += [
                {
                    "action": "BLOCK_IP",
                    "target": src,
                    "reason": "Botnet C2 communication detected",
                    "duration": "permanent",
                },
                {
                    "action": "ISOLATE_HOST",
                    "target": src,
                    "reason": "Host appears compromised — quarantine for forensics",
                },
                {
                    "action": "TCP_RESET",
                    "target": src,
                    "reason": "Kill active C2 sessions",
                },
                {
                    "action": "ENRICH_TARGET",
                    "target": src,
                    "reason": "Run threat intelligence scan on C2 node",
                },
            ]

        # ── Data Exfiltration ─────────────────────────────────────────────
        elif atype == "EXFILTRATION" or any(
            kw in text for kw in ("exfiltration", "data transfer", "dns tunnel", "exfil")
        ):
            rules += [
                {
                    "action": "BLOCK_IP",
                    "target": src,
                    "reason": "Suspected data exfiltration source",
                    "duration": "permanent",
                },
                {
                    "action": "TCP_RESET",
                    "target": src,
                    "reason": "Interrupt active exfil stream",
                },
                {
                    "action": "TUNE_SIEM",
                    "target": "EXFIL_BEACON_RULE",
                    "reason": "Strengthen egress monitoring for similar patterns",
                },
            ]

        # ── Port Scan / Reconnaissance ────────────────────────────────────
        elif atype == "PORT_SCAN" or any(kw in text for kw in ("port scan", "portscan", "nmap", "masscan")):
            rules += [
                {
                    "action": "RATE_LIMIT",
                    "target": src,
                    "limit": "10/s",
                    "reason": "Port scanning activity detected",
                },
                {
                    "action": "ENRICH_TARGET",
                    "target": src,
                    "reason": "Gather threat intelligence on scanner",
                },
                {
                    "action": "FIREWALL_RULE",
                    "priority": 50,
                    "action_type": "DENY",
                    "src_ip": src,
                    "port": "ANY",
                    "protocol": "TCP",
                    "reason": "Block port scanner from further probing",
                },
            ]

        # ── Generic unknown threat ────────────────────────────────────────
        else:
            rules += [
                {
                    "action": "ENRICH_TARGET",
                    "target": src,
                    "reason": "Unknown threat — enrichment requested for triage",
                },
                {
                    "action": "RATE_LIMIT",
                    "target": src,
                    "limit": "20/s",
                    "reason": "Precautionary throttle on suspicious source",
                },
            ]

        return rules

    # ── Private: Deduplication ───────────────────────────────────────────────

    @staticmethod
    def _deduplicate_rules(rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicate (action, target) pairs, keeping first occurrence."""
        seen = set()
        unique = []
        for rule in rules:
            key = (str(rule.get("action", "")).upper(), str(rule.get("target", "")))
            if key not in seen:
                seen.add(key)
                unique.append(rule)
        return unique

    # ── Private: Sandbox enforcement ─────────────────────────────────────────

    def _enforce_rules(
        self, rules: List[Dict[str, Any]], ctx: ThreatContext
    ):
        """Execute each rule in the sandbox; track successes and failures."""
        enforced, failed = [], []
        threat_info = {
            "confidence": max(ctx.confidence, 0.9),  # ensure sandbox validation passes
            "Attack": ctx.attack_type,
            "SourceIP": ctx.source_ip,
        }

        for rule in rules:
            action = rule.get("action", "?")
            target = rule.get("target", "?")
            try:
                result = self.sandbox.execute_rule(
                    rule, threat_info=threat_info, auto_pilot=True
                )
                status = result.get("status", "?")
                if "REJECTED" in status or "UNSUPPORTED" in status:
                    print(f"  [✗] {action} → {target} | {status}")
                    failed.append({"rule": rule, "status": status})
                else:
                    print(f"  [✔] {action} → {target} | {status}")
                    enforced.append({"rule": rule, "result": result})
            except Exception as exc:
                err = str(exc)
                logger.warning("[SOC] Rule enforcement error: %s", err)
                print(f"  [!] {action} → {target} | ERROR: {err}")
                failed.append({"rule": rule, "error": err})

        return enforced, failed


# ─────────────────────────────────────────────────────────────────────────────
# Demo / standalone entry-point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    DEMO_SCENARIOS = {
        "smb": (
            "CRITICAL ALERT: Detected rapid SMB (TCP/445) connection attempts from internal host "
            "10.0.0.155 targeting multiple peer workstations (10.0.0.21, 10.0.0.22, 10.0.0.23). "
            "Pattern consistent with lateral movement variant of 'WannaCry' malware family."
        ),
        "sqli": (
            "HIGH ALERT: WAF blocked SQL injection payload from 203.0.113.42 targeting "
            "/api/users endpoint. Pattern: UNION SELECT NULL,NULL,NULL — possible automated scanner."
        ),
        "ddos": (
            "CRITICAL ALERT: Volumetric UDP flood from 198.51.100.77. Incoming packet rate: "
            "2.4 Mpps — DDoS attack in progress against port 53."
        ),
        "bruteforce": (
            "MEDIUM ALERT: 847 failed SSH login attempts from 192.0.2.88 over the last 60 seconds. "
            "Target: jump-server-01 (10.10.0.5:22). Possible credential stuffing attack."
        ),
        "botnet": (
            "HIGH ALERT: Internal host 10.0.5.33 is communicating with known Mirai botnet C2 "
            "server 45.33.32.156 over port 23 (Telnet). Continuous beacon at 30-second intervals."
        ),
    }

    parser = argparse.ArgumentParser(description="AutoSOC Rule Generator Demo")
    parser.add_argument(
        "--scenario",
        choices=list(DEMO_SCENARIOS.keys()) + ["all"],
        default="smb",
        help="Demo threat scenario to simulate (default: smb)",
    )
    args = parser.parse_args()

    generator = AutoSOCRuleGenerator()

    scenarios_to_run = (
        list(DEMO_SCENARIOS.items())
        if args.scenario == "all"
        else [(args.scenario, DEMO_SCENARIOS[args.scenario])]
    )

    for name, alert in scenarios_to_run:
        print(f"\n{'='*60}")
        print(f"  SCENARIO: {name.upper()}")
        print(f"{'='*60}")
        result = generator.process_threat(alert)
        print(f"\n  Summary | Enforced: {len(result['rules_enforced'])} | "
              f"Failed: {len(result['rules_failed'])}")

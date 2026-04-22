"""
Sandbox-backed remediation agent.
"""

from __future__ import annotations

import datetime
import json
import logging
import os
import re
from typing import Any, Dict, List
try:
    from .BaseAgent import BaseAgent
    from .DefensiveActionSandbox import DefensiveActionSandbox
    from .runtime_compat import MessagesState, StateGraph
except (ImportError, ValueError):
    from BaseAgent import BaseAgent
    from DefensiveActionSandbox import DefensiveActionSandbox
    from runtime_compat import MessagesState, StateGraph

logger = logging.getLogger(__name__)


class RemediationAgent:
    """Apply defensive rules safely through the sandbox executor."""

    def __init__(self, dry_run: bool = False, hexstrike: Any = None):
        self.dry_run = dry_run
        self.hexstrike = hexstrike
        self.sandbox = DefensiveActionSandbox()
        try:
            from .IPBlockingManager import IPBlockingManager
        except (ImportError, ValueError):
            from IPBlockingManager import IPBlockingManager  # type: ignore
        try:
            self.ip_manager = IPBlockingManager()
        except Exception as exc:
            logger.warning("RemediationAgent: IPBlockingManager init failed: %s", exc)
            self.ip_manager = None

        current_file = os.path.abspath(__file__)
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(current_file))))
        self.reports_dir = os.path.join(base_dir, "Reports")
        self.log_path = os.path.join(self.reports_dir, "remediation_log.json")
        self.active_rules_path = os.path.join(self.reports_dir, "active_remediations.json")

        os.makedirs(self.reports_dir, exist_ok=True)

    def process(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        threat_info = input_data.get("threat_info", {})
        plan = input_data.get("defense_plan", "")
        auto_pilot = bool(input_data.get("auto_pilot", False))
        force_enforce = bool(input_data.get("force_enforce", False))

        rules = self._parse_rules(plan)
        rules = self._augment_firewall_rules(rules, threat_info)
        effective_auto_pilot = auto_pilot or force_enforce
        execution_results = [self.apply_remediation_rule(rule, threat_info, effective_auto_pilot) for rule in rules]
        self._save_active_rules()

        return {
            "remediation_status": "COMPLETED" if execution_results else "NO_ACTION",
            "execution_log": execution_results,
            "enforced_rules": rules,
            "effective_auto_pilot": effective_auto_pilot,
            "active_protections": self.sandbox.list_active_rules(),
            "timestamp": datetime.datetime.utcnow().isoformat(),
        }

    def apply_remediation_rule(
        self,
        rule: Dict[str, Any],
        threat_info: Dict[str, Any],
        auto_pilot: bool,
    ) -> Dict[str, Any]:
        action = rule.get("action", "UNKNOWN").upper()
        target = rule.get(
            "target",
            threat_info.get("SourceIP")
            or threat_info.get("Source IP")
            or threat_info.get("IPV4_SRC_ADDR")
            or threat_info.get("src_ip")
            or "UNKNOWN",
        )
        duration = rule.get("duration", "permanent")
        reason = rule.get("reason", "Detected threat pattern")

        log_entry: Dict[str, Any] = {
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "action": action,
            "target": target,
            "duration": duration,
            "reason": reason,
            "dry_run": self.dry_run,
            "auto_pilot": auto_pilot,
            "status": "PENDING",
        }

        should_enforce = auto_pilot and not self.dry_run
        sandbox_result = self.sandbox.execute_rule(
            rule={**rule, "action": action, "target": target, "duration": duration, "reason": reason},
            threat_info=threat_info,
            auto_pilot=should_enforce,
        )
        log_entry["status"] = sandbox_result.get("status", "UNKNOWN")
        log_entry["effect"] = sandbox_result.get("effect")
        log_entry["sandboxed"] = True
        log_entry["state_snapshot"] = sandbox_result.get("state_snapshot", {})

        # Persist BLOCK_IP actions in IPBlockingManager so is_ip_blocked() sees them
        if (
            should_enforce
            and action in ("BLOCK_IP", "BLOCK_IP_AGGRESSIVE")
            and self.ip_manager is not None
            and "REJECTED" not in str(log_entry["status"]).upper()
            and target and target != "UNKNOWN"
        ):
            try:
                self.ip_manager.add_blocked_ip(
                    ip=target,
                    reason=reason,
                    duration=duration,
                    threat_severity=str(threat_info.get("Attack", "high")).lower(),
                )
            except Exception as exc:
                logger.warning("RemediationAgent: add_blocked_ip failed for %s: %s", target, exc)

        if action == "ENRICH_TARGET" and self.hexstrike:
            attack_class = str(threat_info.get("Attack") or threat_info.get("predicted_label") or "UNKNOWN")
            log_entry["status"] = self._execute_enrichment(target, attack_class=attack_class)

        self._save_log(log_entry)
        return log_entry

    def _execute_enrichment(self, target: str, attack_class: str = "UNKNOWN") -> str:
        """
        Run HexStrike enrichment. Uses a per-attack-class bandit to pick which
        tool(s) to run — productive tools win more pulls over time.
        """
        if not self.hexstrike:
            return "HEXSTRIKE_UNAVAILABLE"
        try:
            from .HexstrikeBandit import get_bandit
            bandit = get_bandit()
        except Exception:
            bandit = None

        any_substantive = False
        tools_run = []
        for _ in range(2):  # Two pulls per enrichment pass
            tool = (
                bandit.select(attack_class) if bandit
                else "analyze_target"
            )
            if tool in tools_run:  # Avoid re-pulling the same arm inside one pass
                continue
            tools_run.append(tool)
            try:
                if tool == "analyze_target":
                    result = self.hexstrike.analyze_target(target, "comprehensive")
                elif tool == "nmap_scan":
                    result = self.hexstrike.nmap_scan(target)
                elif tool == "nuclei_scan":
                    web = target if target.startswith("http") else f"http://{target}"
                    result = self.hexstrike.nuclei_scan(web, severity="critical,high")
                elif tool == "check_ip_reputation":
                    result = self.hexstrike.check_ip_reputation(target)
                else:
                    continue
                if bandit:
                    r = bandit.reward(attack_class, tool, result)
                    logger.debug("Bandit %s/%s -> reward=%.2f", attack_class, tool, r)
                if isinstance(result, dict) and ("analysis" in result or "target_profile" in result
                                                 or "score" in result or "results" in result):
                    any_substantive = True
            except Exception as exc:
                logger.warning("Bandit tool %s failed for %s: %s", tool, target, exc)
                if bandit:
                    bandit.reward(attack_class, tool, {"error": str(exc)})
        return "ENRICHMENT_COMPLETED" if any_substantive else "ENRICHMENT_EMPTY"

    def _augment_firewall_rules(self, rules: List[Dict[str, Any]], threat_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Inject a FIREWALL_RULE for attack families that require explicit network policy entries."""
        attack_text = str(
            threat_info.get("Attack")
            or threat_info.get("predicted_label")
            or threat_info.get("attack_type")
            or ""
        ).lower()
        matched = any(tag in attack_text for tag in ("ddos", "xss", "brute", "bruteforce", "brute-force"))
        if not matched:
            return rules

        has_firewall_rule = any(str(rule.get("action", "")).upper() == "FIREWALL_RULE" for rule in rules)
        if has_firewall_rule:
            return rules

        source_ip = (
            threat_info.get("SourceIP")
            or threat_info.get("Source IP")
            or threat_info.get("IPV4_SRC_ADDR")
            or threat_info.get("ipv4_src_addr")
            or threat_info.get("src_ip")
            or threat_info.get("source_ip")
            or threat_info.get("Src IP")
            or "UNKNOWN"
        )
        firewall_rule = {
            "action": "FIREWALL_RULE",
            "target": source_ip,
            "action_type": "DENY",
            "src_ip": source_ip,
            "dst_ip": "ANY",
            "port": "ANY",
            "protocol": "ANY",
            "priority": 10,
            "reason": f"Auto firewall policy for attack pattern: {attack_text or 'unknown'}",
        }
        return [*rules, firewall_rule]

    def _save_log(self, entry: Dict[str, Any]) -> None:
        try:
            current_logs: List[Dict[str, Any]] = []
            if os.path.exists(self.log_path):
                with open(self.log_path, "r", encoding="utf-8") as fh:
                    try:
                        current_logs = json.load(fh)
                    except json.JSONDecodeError:
                        current_logs = []
            current_logs.append(entry)
            with open(self.log_path, "w", encoding="utf-8") as fh:
                json.dump(current_logs, fh, indent=2)
        except OSError as exc:
            logger.error("Failed to save remediation log: %s", exc)

    def _save_active_rules(self) -> None:
        try:
            with open(self.active_rules_path, "w", encoding="utf-8") as fh:
                json.dump(self.sandbox.list_active_rules(), fh, indent=2)
        except OSError as exc:
            logger.error("Failed to save active remediation snapshot: %s", exc)

    def _parse_rules(self, text: str) -> List[Dict[str, Any]]:
        try:
            pattern = r"\[ACTIONABLE_RULES\](.*?)\[/ACTIONABLE_RULES\]"
            match = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
            if not match:
                return []

            content = match.group(1).strip()
            content = re.sub(r"```(?:json)?", "", content)
            content = content.replace("```", "").replace("**", "").strip()

            json_match = re.search(r"(\[.*\]|\{.*\})", content, re.DOTALL)
            if not json_match:
                return []

            rules = json.loads(json_match.group(1).strip())
            return rules if isinstance(rules, list) else [rules]
        except (json.JSONDecodeError, ValueError) as exc:
            logger.warning("Rule parsing exception: %s", exc)
            return []


if __name__ == "__main__":
    agent = RemediationAgent()
    print(
        agent.process(
            {
                "threat_info": {"Attack": "DDoS", "SourceIP": "192.168.1.100", "confidence": 0.95},
                "defense_plan": (
                    '[ACTIONABLE_RULES][{"action": "BLOCK_IP", '
                    '"target": "192.168.1.100", "duration": "1h"}]'
                    '[/ACTIONABLE_RULES]'
                ),
            }
        )
    )

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

from .DefensiveActionSandbox import DefensiveActionSandbox

logger = logging.getLogger(__name__)


class RemediationAgent:
    """Apply defensive rules safely through the sandbox executor."""

    def __init__(self, dry_run: bool = True, hexstrike: Any = None):
        self.dry_run = dry_run
        self.hexstrike = hexstrike
        self.sandbox = DefensiveActionSandbox()

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

        rules = self._parse_rules(plan)
        execution_results = [self.apply_remediation_rule(rule, threat_info, auto_pilot) for rule in rules]
        self._save_active_rules()

        return {
            "remediation_status": "COMPLETED" if execution_results else "NO_ACTION",
            "execution_log": execution_results,
            "enforced_rules": rules,
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
        target = rule.get("target", threat_info.get("SourceIP", threat_info.get("Source IP", "UNKNOWN")))
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

        sandbox_result = self.sandbox.execute_rule(
            rule={**rule, "action": action, "target": target, "duration": duration, "reason": reason},
            threat_info=threat_info,
            auto_pilot=(auto_pilot and not self.dry_run),
        )
        log_entry["status"] = sandbox_result.get("status", "UNKNOWN")
        log_entry["effect"] = sandbox_result.get("effect")
        log_entry["sandboxed"] = True
        log_entry["state_snapshot"] = sandbox_result.get("state_snapshot", {})

        if action == "ENRICH_TARGET" and self.hexstrike:
            log_entry["status"] = self._execute_enrichment(target)

        self._save_log(log_entry)
        return log_entry

    def _execute_enrichment(self, target: str) -> str:
        if self.hexstrike:
            try:
                logger.info("Queueing enrichment scan for %s", target)
                return "ENRICHMENT_QUEUED"
            except Exception as exc:
                logger.warning("Enrichment failed for %s: %s", target, exc)
                return "ENRICHMENT_FAILED"
        return "HEXSTRIKE_UNAVAILABLE"

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

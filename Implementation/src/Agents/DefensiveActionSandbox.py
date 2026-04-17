"""
Sandboxed defensive action executor.

This module gives agents a safe environment to "execute" defensive rules
without touching the host firewall, IAM system, or SIEM. It persists the
simulated state so the rest of the SOC stack can inspect active controls.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import json
import os
from typing import Any, Dict, List, Optional


class DefensiveActionSandbox:
    """Stateful sandbox for defensive actions against suspicious entities."""

    SUPPORTED_ACTIONS = {
        "BLOCK_IP",
        "BLOCK_IP_AGGRESSIVE",
        "RATE_LIMIT",
        "ISOLATE_HOST",
        "TCP_RESET",
        "ENRICH_TARGET",
        "RESET_PASSWORD",
        "TUNE_SIEM",
        "NETWORK_ISOLATION",
        "THREAT_ESCALATION",
        "SUBNET_BLOCK",
    }

    def __init__(self, state_path: Optional[str] = None) -> None:
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
        reports_dir = os.path.join(base_dir, "Reports")
        os.makedirs(reports_dir, exist_ok=True)
        self.state_path = state_path or os.path.join(reports_dir, "sandbox_state.json")

    def load_state(self) -> Dict[str, Any]:
        if not os.path.exists(self.state_path):
            return self._empty_state()
        try:
            with open(self.state_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
                return {**self._empty_state(), **data}
        except (OSError, json.JSONDecodeError):
            return self._empty_state()

    def save_state(self, state: Dict[str, Any]) -> None:
        with open(self.state_path, "w", encoding="utf-8") as fh:
            json.dump(state, fh, indent=2)

    def execute_rule(
        self,
        rule: Dict[str, Any],
        threat_info: Optional[Dict[str, Any]] = None,
        auto_pilot: bool = False,
    ) -> Dict[str, Any]:
        threat_info = threat_info or {}
        action = str(rule.get("action", "")).upper().strip()
        target = rule.get("target") or threat_info.get("SourceIP") or threat_info.get("Source IP") or "UNKNOWN"
        reason = rule.get("reason", "Automated SOC response")
        state = self.load_state()

        result: Dict[str, Any] = {
            "timestamp": dt.datetime.utcnow().isoformat(),
            "action": action,
            "target": target,
            "reason": reason,
            "auto_pilot": auto_pilot,
            "sandboxed": True,
            "status": "REJECTED",
        }

        if action not in self.SUPPORTED_ACTIONS:
            result["status"] = f"UNSUPPORTED_ACTION:{action}"
            return result

        validation_error = self._validate_rule(rule, threat_info)
        if validation_error:
            result["status"] = f"REJECTED:{validation_error}"
            return result

        if not auto_pilot:
            result["status"] = "STAGED"
            result["state_snapshot"] = state
            self._append_history(state, result)
            self.save_state(state)
            return result

        handler = getattr(self, f"_handle_{action.lower()}")
        update = handler(rule, threat_info, state)
        result.update(update)
        self._append_history(state, result)
        self.save_state(state)
        result["state_snapshot"] = self._summarize_state(state)
        return result

    def inspect_target(self, target: str) -> Dict[str, Any]:
        state = self.load_state()
        return {
            "target": target,
            "blocked": target in state["blocked_ips"],
            "rate_limited": target in state["rate_limits"],
            "isolated": target in state["isolated_hosts"],
            "recent_actions": [entry for entry in state["history"] if entry.get("target") == target][-10:],
        }

    def list_active_rules(self) -> Dict[str, Any]:
        return self._summarize_state(self.load_state())

    def _validate_rule(self, rule: Dict[str, Any], threat_info: Dict[str, Any]) -> Optional[str]:
        action = str(rule.get("action", "")).upper()
        target = str(rule.get("target", "")).strip()
        malicious_confidence = float(
            threat_info.get("confidence")
            or threat_info.get("ids_confidence")
            or threat_info.get("malicious_confidence")
            or 0.0
        )
        attack_name = str(threat_info.get("Attack", "")).upper()

        if action in {"BLOCK_IP", "RATE_LIMIT", "TCP_RESET", "ENRICH_TARGET"}:
            if not self._looks_like_ip_or_host(target):
                return "INVALID_TARGET"

        if action == "ISOLATE_HOST":
            if not self._is_internal_ip(target):
                return "ISOLATE_HOST_REQUIRES_INTERNAL_IP"

        if action == "BLOCK_IP" and malicious_confidence < 0.5 and attack_name not in {"DDOS", "BOTNET", "BRUTEFORCE"}:
            return "LOW_CONFIDENCE_BLOCK"

        return None

    def _handle_block_ip(self, rule: Dict[str, Any], threat_info: Dict[str, Any], state: Dict[str, Any]) -> Dict[str, Any]:
        target = rule["target"]
        state["blocked_ips"][target] = {
            "duration": rule.get("duration", "permanent"),
            "reason": rule.get("reason", "Threat detected"),
            "added_at": dt.datetime.utcnow().isoformat(),
        }
        return {"status": "ENFORCED", "effect": "IP_BLOCKED"}

    def _handle_rate_limit(self, rule: Dict[str, Any], threat_info: Dict[str, Any], state: Dict[str, Any]) -> Dict[str, Any]:
        target = rule["target"]
        state["rate_limits"][target] = {
            "limit": rule.get("limit", "100/s"),
            "reason": rule.get("reason", "Traffic throttled"),
            "added_at": dt.datetime.utcnow().isoformat(),
        }
        return {"status": "ENFORCED", "effect": "RATE_LIMITED"}

    def _handle_isolate_host(self, rule: Dict[str, Any], threat_info: Dict[str, Any], state: Dict[str, Any]) -> Dict[str, Any]:
        target = rule["target"]
        state["isolated_hosts"][target] = {
            "reason": rule.get("reason", "Host quarantine"),
            "added_at": dt.datetime.utcnow().isoformat(),
        }
        return {"status": "ENFORCED", "effect": "HOST_ISOLATED"}

    def _handle_tcp_reset(self, rule: Dict[str, Any], threat_info: Dict[str, Any], state: Dict[str, Any]) -> Dict[str, Any]:
        state["tcp_resets"].append({
            "target": rule["target"],
            "reason": rule.get("reason", "Terminate active sessions"),
            "timestamp": dt.datetime.utcnow().isoformat(),
        })
        return {"status": "ENFORCED", "effect": "TCP_RESET_SENT"}

    def _handle_enrich_target(self, rule: Dict[str, Any], threat_info: Dict[str, Any], state: Dict[str, Any]) -> Dict[str, Any]:
        state["enrichment_queue"].append({
            "target": rule["target"],
            "reason": rule.get("reason", "Gather more intelligence"),
            "timestamp": dt.datetime.utcnow().isoformat(),
        })
        return {"status": "QUEUED", "effect": "ENRICHMENT_REQUESTED"}

    def _handle_reset_password(self, rule: Dict[str, Any], threat_info: Dict[str, Any], state: Dict[str, Any]) -> Dict[str, Any]:
        state["password_resets"].append({
            "target": rule["target"],
            "reason": rule.get("reason", "Credential containment"),
            "timestamp": dt.datetime.utcnow().isoformat(),
        })
        return {"status": "ENFORCED", "effect": "PASSWORD_RESET_STAGED"}

    def _handle_tune_siem(self, rule: Dict[str, Any], threat_info: Dict[str, Any], state: Dict[str, Any]) -> Dict[str, Any]:
        state["siem_tuning"].append({
            "target": rule["target"],
            "reason": rule.get("reason", "Detection tuning"),
            "timestamp": dt.datetime.utcnow().isoformat(),
        })
        return {"status": "QUEUED", "effect": "SIEM_TUNING_STAGED"}

    def _handle_block_ip_aggressive(self, rule: Dict[str, Any], threat_info: Dict[str, Any], state: Dict[str, Any]) -> Dict[str, Any]:
        """Block an IP with higher certainty, used by Tier 2 for confirmed threats."""
        target = rule["target"]
        state["blocked_ips"][target] = {
            "duration": rule.get("duration", "permanent"),
            "reason": rule.get("reason", "Confirmed threat detected"),
            "severity": rule.get("severity", "high"),
            "added_at": dt.datetime.utcnow().isoformat(),
            "aggressive": True,
        }
        return {"status": "ENFORCED", "effect": "IP_BLOCKED_AGGRESSIVE"}

    def _handle_network_isolation(self, rule: Dict[str, Any], threat_info: Dict[str, Any], state: Dict[str, Any]) -> Dict[str, Any]:
        """Isolate a network segment affected by an attack (Tier 3)."""
        target = rule["target"]
        if "isolation_network" not in state:
            state["isolation_network"] = {}
        state["isolation_network"][target] = {
            "reason": rule.get("reason", "Network isolation for containment"),
            "duration": rule.get("duration", "1h"),
            "added_at": dt.datetime.utcnow().isoformat(),
        }
        return {"status": "ENFORCED", "effect": "NETWORK_ISOLATED"}

    def _handle_threat_escalation(self, rule: Dict[str, Any], threat_info: Dict[str, Any], state: Dict[str, Any]) -> Dict[str, Any]:
        """Escalate threat level and trigger incident response (Tier 3)."""
        if "threat_escalations" not in state:
            state["threat_escalations"] = []
        state["threat_escalations"].append({
            "target": rule["target"],
            "incident_id": rule.get("incident_id", "UNKNOWN"),
            "severity": rule.get("severity", "high"),
            "reason": rule.get("reason", "Escalated threat detected"),
            "timestamp": dt.datetime.utcnow().isoformat(),
        })
        return {"status": "ESCALATED", "effect": "THREAT_ESCALATION_TRIGGERED"}

    def _handle_subnet_block(self, rule: Dict[str, Any], threat_info: Dict[str, Any], state: Dict[str, Any]) -> Dict[str, Any]:
        """Block an entire subnet/CIDR range (Tier 3 for widespread attacks)."""
        target = rule["target"]
        if "blocked_subnets" not in state:
            state["blocked_subnets"] = {}
        state["blocked_subnets"][target] = {
            "reason": rule.get("reason", "Subnet blocked due to widespread attack"),
            "duration": rule.get("duration", "24h"),
            "threat_type": rule.get("threat_type", "Unknown"),
            "added_at": dt.datetime.utcnow().isoformat(),
        }
        return {"status": "ENFORCED", "effect": "SUBNET_BLOCKED"}

    def _append_history(self, state: Dict[str, Any], result: Dict[str, Any]) -> None:
        state["history"].append({k: v for k, v in result.items() if k != "state_snapshot"})
        state["history"] = state["history"][-100:]

    def _summarize_state(self, state: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "blocked_ips": state.get("blocked_ips", {}),
            "blocked_subnets": state.get("blocked_subnets", {}),
            "isolation_network": state.get("isolation_network", {}),
            "rate_limits": state.get("rate_limits", {}),
            "isolated_hosts": state.get("isolated_hosts", {}),
            "pending_enrichment": len(state.get("enrichment_queue", [])),
            "pending_siem_tuning": len(state.get("siem_tuning", [])),
            "threat_escalations": len(state.get("threat_escalations", [])),
            "history_count": len(state.get("history", [])),
        }

    @staticmethod
    def _empty_state() -> Dict[str, Any]:
        return {
            "blocked_ips": {},
            "blocked_subnets": {},
            "isolation_network": {},
            "rate_limits": {},
            "isolated_hosts": {},
            "tcp_resets": [],
            "enrichment_queue": [],
            "password_resets": [],
            "siem_tuning": [],
            "threat_escalations": [],
            "history": [],
        }

    @staticmethod
    def _looks_like_ip_or_host(target: str) -> bool:
        if not target:
            return False
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            return "." in target or ":" in target

    @staticmethod
    def _is_internal_ip(target: str) -> bool:
        try:
            return ipaddress.ip_address(target).is_private
        except ValueError:
            return False

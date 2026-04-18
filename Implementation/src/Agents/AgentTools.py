"""
Per-agent tool registry.

The tools exposed here are intentionally defensive and inspection-focused.
They help agents reason about malicious IPs and draft actions while routing
all enforcement through the sandbox executor.

Tier 2 & 3 Enhanced Tools:
- IP reputation checking and blocking decisions
- Aggressive blocking for confirmed threats
- Network isolation and containment
- Threat escalation and incident response
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional

try:
    from .DefensiveActionSandbox import DefensiveActionSandbox
    from .IPBlockingManager import IPBlockingManager
    from .runtime_compat import StructuredTool
except (ImportError, ValueError):
    from DefensiveActionSandbox import DefensiveActionSandbox
    from IPBlockingManager import IPBlockingManager
    from runtime_compat import StructuredTool


def _tool(name: str, description: str, func: Callable[..., Any]) -> StructuredTool:
    return StructuredTool.from_function(
        func=func,
        name=name,
        description=description,
        handle_tool_error=True,
    )


def get_agent_tools(
    *,
    agent_name: str,
    sandbox: DefensiveActionSandbox,
    flow_history: Optional[Any] = None,
    ip_blocking_mgr: Optional[IPBlockingManager] = None,
) -> List[StructuredTool]:
    if ip_blocking_mgr is None:
        ip_blocking_mgr = IPBlockingManager()
    
    normalized = agent_name.lower()
    tools: List[StructuredTool] = [
        _tool(
            "inspect_protection_state",
            "Inspect the sandbox protection state for a target IP or host.",
            lambda target: sandbox.inspect_target(target),
        ),
        _tool(
            "list_active_protections",
            "List all protections staged or enforced in the defensive sandbox.",
            lambda: sandbox.list_active_rules(),
        ),
    ]

    if flow_history is not None:
        tools.append(
            _tool(
                "lookup_ip_history",
                "Look up recent flow history and threat ratio for an IP address.",
                lambda ip_address, window_minutes=5: flow_history.get_ip_stats(ip_address, window_minutes),
            )
        )

    if "tier1" in normalized:
        tools.append(
            _tool(
                "draft_block_rule",
                "Draft a sandbox-safe IP block rule for a malicious source IP.",
                lambda target, reason="Malicious activity detected", duration="1h": {
                    "action": "BLOCK_IP",
                    "target": target,
                    "reason": reason,
                    "duration": duration,
                },
            )
        )
    elif "tier2" in normalized or "blue" in normalized:
        # Tier 2: Investigation + IP blocking decision tools
        def check_ip_reputation_tier2(ip: str, threat_info: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
            """Check IP reputation and recommend blocking action."""
            threat_info = threat_info or {}
            should_block, reasoning = ip_blocking_mgr.should_block_ip(ip, threat_info)
            reputation = ip_blocking_mgr.get_or_fetch_reputation(ip)
            return {
                "ip": ip,
                "should_block": should_block,
                "blocking_reasoning": reasoning,
                "reputation": reputation.to_dict(),
                "is_whitelisted": ip_blocking_mgr.is_ip_whitelisted(ip),
                "already_blocked": ip_blocking_mgr.is_ip_blocked(ip),
            }
        
        tools.extend([
            _tool(
                "check_ip_reputation",
                "Tier 2: Check IP reputation, threat intelligence, and get blocking recommendation.",
                check_ip_reputation_tier2,
            ),
            _tool(
                "draft_rate_limit_rule",
                "Draft a sandbox-safe rate limit rule for suspicious traffic.",
                lambda target, limit="100/s", reason="Suspicious traffic burst": {
                    "action": "RATE_LIMIT",
                    "target": target,
                    "limit": limit,
                    "reason": reason,
                },
            ),
            _tool(
                "draft_aggressive_block_rule",
                "Tier 2: Draft an aggressive IP block rule for confirmed threats after investigation.",
                lambda target, reason="Confirmed threat after investigation", severity="high", duration="permanent": {
                    "action": "BLOCK_IP_AGGRESSIVE",
                    "target": target,
                    "reason": reason,
                    "severity": severity,
                    "duration": duration,
                },
            ),
            _tool(
                "queue_target_enrichment",
                "Stage an enrichment request for deeper inspection of a target.",
                lambda target, reason="Requires intelligence gathering": sandbox.execute_rule(
                    {"action": "ENRICH_TARGET", "target": target, "reason": reason},
                    auto_pilot=True,
                ),
            ),
            _tool(
                "get_blocked_ips_list",
                "Retrieve current list of blocked IPs and their details.",
                lambda: ip_blocking_mgr.get_block_list(),
            ),
            _tool(
                "whitelist_ip",
                "Add an IP to whitelist (exempt from blocking).",
                lambda ip, reason="": ip_blocking_mgr.add_to_whitelist(ip, reason),
            ),
        ])
    elif "tier3" in normalized:
        # Tier 3: Incident response + advanced containment tools
        def block_ip_tier3(ip: str, reason: str, severity: str = "critical", duration: str = "permanent") -> Dict[str, Any]:
            """Tier 3: Actively block a malicious IP with automatic enforcement."""
            return sandbox.execute_rule(
                {
                    "action": "BLOCK_IP_AGGRESSIVE",
                    "target": ip,
                    "reason": reason,
                    "severity": severity,
                    "duration": duration,
                },
                auto_pilot=True,
            )
        
        def isolate_network_tier3(network: str, reason: str = "Compartmentalization for active attack") -> Dict[str, Any]:
            """Tier 3: Isolate a network segment to contain attack spread."""
            return sandbox.execute_rule(
                {
                    "action": "NETWORK_ISOLATION",
                    "target": network,
                    "reason": reason,
                    "duration": "2h",
                },
                auto_pilot=True,
            )
        
        def escalate_threat_tier3(incident_id: str, target: str, severity: str = "critical") -> Dict[str, Any]:
            """Tier 3: Escalate a threat to maximum response level."""
            return sandbox.execute_rule(
                {
                    "action": "THREAT_ESCALATION",
                    "incident_id": incident_id,
                    "target": target,
                    "severity": severity,
                    "reason": "Tier 3 escalation - comprehensive incident response activated",
                },
                auto_pilot=True,
            )
        
        def block_subnet_tier3(subnet: str, threat_type: str = "DDoS", duration: str = "24h") -> Dict[str, Any]:
            """Tier 3: Block entire subnet/CIDR range for widespread attacks."""
            return sandbox.execute_rule(
                {
                    "action": "SUBNET_BLOCK",
                    "target": subnet,
                    "threat_type": threat_type,
                    "reason": f"Subnet blocked - widespread {threat_type} attack detected",
                    "duration": duration,
                },
                auto_pilot=True,
            )
        
        tools.extend([
            _tool(
                "block_malicious_ip",
                "Tier 3: Actively block a malicious IP with enforcement action.",
                block_ip_tier3,
            ),
            _tool(
                "isolate_network_segment",
                "Tier 3: Isolate a network segment to prevent attack lateral movement.",
                isolate_network_tier3,
            ),
            _tool(
                "escalate_incident",
                "Tier 3: Escalate an incident to maximum response severity.",
                escalate_threat_tier3,
            ),
            _tool(
                "block_subnet_cidr",
                "Tier 3: Block an entire subnet/CIDR range for widespread attacks.",
                block_subnet_tier3,
            ),
            _tool(
                "draft_isolation_rule",
                "Draft an isolation rule for a compromised internal host.",
                lambda target, reason="Compromised internal host": {
                    "action": "ISOLATE_HOST",
                    "target": target,
                    "reason": reason,
                },
            ),
            _tool(
                "draft_reset_password_rule",
                "Draft a password reset rule for a suspected compromised account.",
                lambda target, reason="Compromised credentials": {
                    "action": "RESET_PASSWORD",
                    "target": target,
                    "reason": reason,
                },
            ),
            _tool(
                "get_blocked_ips_list",
                "Retrieve current list of blocked IPs and their details.",
                lambda: ip_blocking_mgr.get_block_list(),
            ),
        ])
    elif "red" in normalized:
        tools.append(
            _tool(
                "draft_enrichment_request",
                "Request target enrichment so blue team can validate suspicious infrastructure safely.",
                lambda target, reason="Investigate suspected attacker infrastructure": {
                    "action": "ENRICH_TARGET",
                    "target": target,
                    "reason": reason,
                },
            )
        )
    elif "purple" in normalized:
        tools.append(
            _tool(
                "summarize_defensive_posture",
                "Summarize current sandbox protections for purple-team exercise analysis.",
                lambda: sandbox.list_active_rules(),
            )
        )

    return tools

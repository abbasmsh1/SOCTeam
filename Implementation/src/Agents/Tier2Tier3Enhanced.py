"""
Tier2 and Tier3 IP Blocking Agent Enhancement
==============================================

Integrates IP blocking and incident response capabilities into Tier2 and Tier3 agents.
This module enhances the BaseAgent to include IP reputation checking and blocking decision tools.
"""

from typing import Any, Dict, Optional
from .BaseAgent import BaseAgent
from .IPBlockingManager import IPBlockingManager
from .DefensiveActionSandbox import DefensiveActionSandbox


class Tier2AgentEnhanced(BaseAgent):
    """Enhanced Tier 2 Analyst with IP blocking investigation tools."""
    
    def __init__(self, api_key: Optional[str] = None, hexstrike_url: Optional[str] = None):
        super().__init__(
            agent_name="Tier2Analyst_Enhanced",
            api_key=api_key,
            hexstrike_url=hexstrike_url,
            enable_hexstrike=True,
        )
        self.ip_blocking_mgr = IPBlockingManager()
        self.sandbox = DefensiveActionSandbox()
    
    def investigate_ip(self, ip: str, threat_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Investigate an IP address for potential blocking.
        
        Returns blocking recommendation based on:
        - IP reputation (abuse score, VPN/Proxy status)
        - Attack type severity
        - Confidence score
        - Historical threat data
        """
        should_block, reasoning = self.ip_blocking_mgr.should_block_ip(ip, threat_info)
        reputation = self.ip_blocking_mgr.get_or_fetch_reputation(ip)
        
        return {
            "ip": ip,
            "recommendation": "BLOCK" if should_block else "MONITOR",
            "reasoning": reasoning,
            "reputation": reputation.to_dict(),
            "is_whitelisted": self.ip_blocking_mgr.is_ip_whitelisted(ip),
            "already_blocked": self.ip_blocking_mgr.is_ip_blocked(ip),
        }
    
    def apply_aggressive_block(self, ip: str, reason: str, severity: str = "high") -> Dict[str, Any]:
        """Apply aggressive blocking for confirmed threats."""
        rule = {
            "action": "BLOCK_IP_AGGRESSIVE",
            "target": ip,
            "reason": reason,
            "severity": severity,
            "duration": "permanent",
        }
        result = self.sandbox.execute_rule(rule, auto_pilot=True)
        return result


class Tier3AgentEnhanced(BaseAgent):
    """Enhanced Tier 3 Responder with incident response and containment tools."""
    
    def __init__(self, api_key: Optional[str] = None, hexstrike_url: Optional[str] = None):
        super().__init__(
            agent_name="Tier3Analyst_Enhanced",
            api_key=api_key,
            hexstrike_url=hexstrike_url,
            enable_hexstrike=True,
        )
        self.ip_blocking_mgr = IPBlockingManager()
        self.sandbox = DefensiveActionSandbox()
    
    def block_malicious_ip(self, ip: str, reason: str, severity: str = "critical") -> Dict[str, Any]:
        """Actively block a malicious IP with enforcement."""
        rule = {
            "action": "BLOCK_IP_AGGRESSIVE",
            "target": ip,
            "reason": reason,
            "severity": severity,
            "duration": "permanent",
        }
        result = self.sandbox.execute_rule(rule, auto_pilot=True)
        ip_blocking_record = self.ip_blocking_mgr.add_blocked_ip(
            ip, 
            reason=reason,
            severity=severity
        )
        return {
            "sandbox_result": result,
            "blocking_record": ip_blocking_record,
        }
    
    def isolate_network(self, network: str, reason: str = "Attack containment") -> Dict[str, Any]:
        """Isolate a network segment to prevent attack spread."""
        rule = {
            "action": "NETWORK_ISOLATION",
            "target": network,
            "reason": reason,
            "duration": "2h",
        }
        return self.sandbox.execute_rule(rule, auto_pilot=True)
    
    def escalate_incident(self, incident_id: str, target: str, severity: str = "critical") -> Dict[str, Any]:
        """Escalate incident to maximum response level."""
        rule = {
            "action": "THREAT_ESCALATION",
            "incident_id": incident_id,
            "target": target,
            "severity": severity,
            "reason": "Tier 3 escalation - comprehensive incident response activated",
        }
        return self.sandbox.execute_rule(rule, auto_pilot=True)
    
    def block_subnet(self, subnet: str, threat_type: str = "DDoS", duration: str = "24h") -> Dict[str, Any]:
        """Block entire subnet/CIDR range for widespread attacks."""
        rule = {
            "action": "SUBNET_BLOCK",
            "target": subnet,
            "threat_type": threat_type,
            "reason": f"Subnet blocked - widespread {threat_type} attack detected",
            "duration": duration,
        }
        return self.sandbox.execute_rule(rule, auto_pilot=True)
    
    def get_active_protections(self) -> Dict[str, Any]:
        """Get summary of all active protections and blocks."""
        return self.sandbox.list_active_rules()
    
    def get_block_list(self) -> Dict[str, Any]:
        """Get current IP block list."""
        return self.ip_blocking_mgr.get_block_list()

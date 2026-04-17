import sys
import os
import json
import re

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

from Agents.LegacyCompat import BlueTeamAgent
from Agents.DefensiveActionSandbox import DefensiveActionSandbox

class AutoSOCRuleGenerator:
    def __init__(self, api_key: str = None):
        self.agent = BlueTeamAgent(api_key=api_key)
        self.sandbox = DefensiveActionSandbox()
        
    def process_threat(self, threat_description: str):
        """
        Agentic workflow:
        1. Receive threat alert
        2. Agent analyzes and generates rules
        3. Parse and enforce rules in sandbox
        """
        print(f"\n[SOC] Incoming Alert: {threat_description}")
        print("[SOC] Notifying Blue Team Agent for autonomous response...")
        
        # Call agent via process() API
        response_data = self.agent.process({"prompt": threat_description})
        
        # Extract content from response (SecurityTeamAgent returns AIMessage in messages list)
        response = ""
        if "messages" in response_data and response_data["messages"]:
            msg = response_data["messages"][-1]
            response = msg.content if hasattr(msg, "content") else str(msg)
        else:
            response = str(response_data)
        
        print("\n--- AGENT ANALYSIS ---")
        print(response)
        print("----------------------\n")
        
        # Extract rules
        rules = self._extract_rules(response)
        
        # DEMO FALLBACK: If no rules were generated (e.g. LLM unavailable), 
        # use local pattern matching for the demo
        if not rules:
            print("[SOC] Agent returned empty rules. Using Demo Intelligence Fallback...")
            rules = self._demo_logic_fallback(threat_description)
        
        if not rules:
            print("[SOC] No actionable rules generated.")
            return
            
        print(f"[SOC] Agent generated {len(rules)} autonomous rules. Enforcing in sandbox...")
        
        for rule in rules:
            try:
                # Ensure it's a valid action for the sandbox
                # Add high confidence for demo reliability
                self.sandbox.execute_rule(rule, threat_info={"confidence": 1.0}, auto_pilot=True)
                print(f" [+] Rule Enforced: {rule.get('action')} - {rule.get('reason', 'No reason provided')}")
            except Exception as e:
                print(f" [!] Failed to enforce rule: {e}")
                
    def _demo_logic_fallback(self, threat: str) -> list:
        """Heuristic-based rule generation for the demo."""
        rules = []
        threat_lower = threat.lower()
        
        # Extract IP if possible
        ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", threat)
        target_ip = ip_match.group(0) if ip_match else "UNKNOWN"
        
        if "smb" in threat_lower or "445" in threat:
            rules.append({
                "action": "BLOCK_IP",
                "target": target_ip,
                "reason": "Probable SMB Lateral Movement (WannaCry variant)",
                "duration": "permanent"
            })
            rules.append({
                "action": "FIREWALL_RULE",
                "priority": 10,
                "action_type": "DENY",
                "src_ip": target_ip,
                "port": 445,
                "protocol": "TCP",
                "reason": "Deny SMB from suspicious host"
            })
            
        elif "sql injection" in threat_lower or "waf" in threat_lower:
            rules.append({
                "action": "BLOCK_IP",
                "target": target_ip,
                "reason": "Confirmed SQL Injection attempt via WAF signature",
                "duration": "permanent"
            })
            rules.append({
                "action": "TCP_RESET",
                "target": target_ip,
                "reason": "Terminate active exfiltration session"
            })
            
        elif "ddos" in threat_lower or "flood" in threat_lower:
            rules.append({
                "action": "RATE_LIMIT",
                "target": target_ip,
                "limit": "10/s",
                "reason": "Anomalous traffic volume (DDoS protection)"
            })
            
        return rules

    def _extract_rules(self, text: str) -> list:
        """Parses [ACTIONABLE_RULES] block from agent output."""
        try:
            # Look for the block
            pattern = r"\[ACTIONABLE_RULES\]\s*([\s\S]*?)\s*\[/ACTIONABLE_RULES\]"
            match = re.search(pattern, text)
            
            if match:
                json_str = match.group(1).strip()
                # Clean up any potential markdown junk or extra braces if necessary
                return json.loads(json_str)
        except Exception as e:
            print(f" [!] Error parsing agent rules: {e}")
        return []

if __name__ == "__main__":
    # Demo scenario
    generator = AutoSOCRuleGenerator()
    
    # Example SMB Lateral Movement detection
    simulation_alert = (
        "CRITICAL ALERT: Detected rapid SMB (TCP/445) connection attempts from internal host 10.0.0.155 "
        "targeting multiple peer workstations (10.0.0.21, 10.0.0.22, 10.0.0.23). Pattern consistent with "
        "lateral movement variant of 'WannaCry' malware family."
    )
    
    generator.process_threat(simulation_alert)

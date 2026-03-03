"""
Tier Analyst Agent
Unified agent supporting Tier 1 (triage), Tier 2 (investigation), and Tier 3 (incident response) roles.
"""

from Implementation.src.Agents.BaseAgent import BaseAgent, AgentConfig, AgentState
from Implementation.utils.Geolocator import GeoLocator
# from Implementation.src.IDS.IDS import IDSPredictor # Moved to __init__ to avoid circular import
from langgraph.graph import StateGraph, START, END
from typing import Dict, Any, Literal, Optional
import json
import logging
import datetime
import re
import requests
import os

logger = logging.getLogger(__name__)

TierLevel = Literal[1, 2, 3]


class TierAnalystAgent(BaseAgent):
    """
    Unified Tier Analyst Agent with tier-based behavior.
    
    Tiers:
    - 1: Alert triage, enrichment, false positive detection
    - 2: Deep investigation, correlation analysis
    - 3: Incident response, forensics, remediation
    """
    
    def __init__(
        self,
        tier: TierLevel = 1,
        api_key: Optional[str] = None
    ):
        """
        Initialize Tier Analyst Agent.
        
        Args:
            tier: Tier level (1, 2, or 3)
            api_key: Mistral API key
        """
        self.tier = tier
        
        # Temperature settings per tier
        temperature_map = {
            1: 0.3,  # Balanced for triage
            2: 0.3,  # Balanced for investigation
            3: 0.3   # Precise for response planning
        }
        
        super().__init__(
            agent_name=f"Tier{tier}Analyst",
            temperature=temperature_map[tier],
            api_key=api_key
        )
        
        # Tier 1 specific initialization
        if tier == 1:
            self.geo_locator = GeoLocator()
            self.internal_networks = ["192.168.", "10.", "172.16."]
            
            # Initialize IDS predictor
            try:
                from Implementation.src.IDS.IDS import IDSPredictor
                base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
                project_root = os.path.dirname(base_dir)
                model_path = os.path.join(project_root, "Models", "best_ids_model.pth")
                self.ids_predictor = IDSPredictor(model_path=model_path)
            except Exception as e:
                logger.warning(f"Could not load IDS model: {e}")
                self.ids_predictor = None
    
    def _create_graph(self) -> StateGraph:
        """Create workflow graph based on tier."""
        workflow = StateGraph(AgentState)
        node_name = f"tier{self.tier}_analyst"
        workflow.add_node(node_name, self._process_node)
        
        # Use set_entry_point/set_finish_point for LangGraph 0.0.x compatibility
        try:
            workflow.set_entry_point(node_name)
        except:
            workflow.add_edge("__start__", node_name)
            
        try:
            workflow.set_finish_point(node_name)
        except:
            workflow.add_edge(node_name, "__end__")
        return workflow
    
    def _process_node(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Process node that delegates to tier-specific logic."""
        system_message = self._get_system_message()
        return self._call_model(state, system_message)
    
    def _get_system_message(self) -> str:
        """Get system message based on tier."""
        if self.tier == 1:
            return """You are a Tier 1 SOC Analyst. Triage alerts with high precision.
You must provide a descriptive analysis and end your response with a JSON block containing:
{
  "severity": "Low/Medium/High/Critical",
  "false_positive": true/false,
  "recommended_actions": ["Action 1", ...],
  "escalate": true/false,
  "confidence": 0.0-1.0,
  "rationale": "..."
}
FORCE 'escalate': true for any DDoS or Botnet attack."""
        
        elif self.tier == 2:
            return """You are a **Tier 2 SOC Analyst** conducting a deep investigation.
Provide a detailed forensic report and end your response with a JSON block containing:
{
  "validated_severity": "Low/Medium/High/Critical",
  "incident_classification": "Confirmed Incident/False Positive/Suspicious Activity",
  "recommended_actions": ["Action 1", ...],
  "escalate": true/false,
  "confidence": 0.0-1.0,
  "investigation_summary": "..."
}
FORCE 'escalate': true for confirmed DDoS or Botnet threats."""
        
        else:  # tier 3
            return """You are a **Tier 3 Incident Responder**.
Provide a remediation strategy and end your response with a JSON block containing:
{
  "credible_threat": true/false,
  "response_plan": "...",
  "summary": "..."
}"""

    def process(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process input based on tier level."""
        if self.tier == 1:
            return self._process_tier1(input_data)
        elif self.tier == 2:
            return self._process_tier2(input_data)
        else:
            return self._process_tier3(input_data)

    def _process_tier1(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Tier 1 processing: Alert triage and enrichment."""
        alert_data = input_data.get("alert_data", {})
        enriched_alert = self.enrich_log(alert_data)
        
        # Get IDS prediction
        ids_prediction = None
        if self.ids_predictor:
            try:
                ids_prediction = self.ids_predictor.predict(alert_data)
                enriched_alert["ids_prediction"] = ids_prediction.get("predicted_label", "Unknown")
                enriched_alert["ids_confidence"] = ids_prediction.get("confidence", 0.0)
            except:
                pass

        # Call LLM
        prompt = f"Enriched Alert:\n{json.dumps(enriched_alert, indent=2)}"
        llm_response = self._stream_with_config(prompt) or "LLM Error"
        
        # Parse result using JSON block preference
        metadata = self._extract_json_block(llm_response) or {}
        
        # Heuristic overrides (safety net)
        final_severity = metadata.get("severity", "Medium")
        should_escalate = metadata.get("escalate", False)
        is_false_positive = metadata.get("false_positive", False)
        
        attack_type = str(alert_data.get("Attack", "")).upper()
        if any(p in attack_type for p in ["DDOS", "BOTNET"]):
            final_severity = "High"
            should_escalate = True
            is_false_positive = False

        return {
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "raw_alert": alert_data,
            "enriched_alert": enriched_alert,
            "triage_response": llm_response,
            "severity": final_severity,
            "false_positive": is_false_positive,
            "escalate": should_escalate,
            "ids_prediction": ids_prediction
        }

    def _process_tier2(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Tier 2 processing."""
        tier1_output = input_data.get("tier1_output", {})
        prompt = f"### Alert Details\n{str(tier1_output.get('enriched_alert', {}))}\n\n### Tier 1 Triage\n{tier1_output.get('triage_response', '')}"
        
        llm_response = self._stream_with_config(prompt) or "LLM Error"
        metadata = self._extract_json_block(llm_response) or {}
        
        val_severity = metadata.get("validated_severity", "High")
        should_escalate = metadata.get("escalate", False)
        
        # Heuristic override for Tier 2
        attack_type = str(tier1_output.get("raw_alert", {}).get("Attack", "")).upper()
        if any(p in attack_type for p in ["DDOS", "BOTNET"]):
            val_severity = "High"
            should_escalate = True

        return {
            "tier": "Tier 2",
            "validated_severity": val_severity,
            "incident_classification": metadata.get("incident_classification", "Suspicious"),
            "recommended_actions": metadata.get("recommended_actions", "N/A"),
            "escalate": "Yes" if should_escalate else "No",
            "confidence": float(metadata.get("confidence", 0.0)),
            "full_report": llm_response
        }

    def _process_tier3(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Tier 3 processing."""
        llm_response = self._stream_with_config(str(input_data)) or "LLM Error"
        metadata = self._extract_json_block(llm_response) or {}
        
        return {
            "tier": "Tier 3",
            "response_plan": llm_response,
            "status": "Plan Generated",
            "credible_threat": metadata.get("credible_threat", False)
        }

    def enrich_log(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich alert with geolocation and IP reputation data."""
        enriched_alert = alert.copy()
        src_ip = alert.get("SourceIP")
        dst_ip = alert.get("DestinationIP")

        if src_ip:
            enriched_alert["source_geolocation"] = self.geo_locator.locate_ip(src_ip)
            enriched_alert["src_ip_reputation"] = self.abuseipdb_check(src_ip)

        if dst_ip:
            enriched_alert["destination_geolocation"] = self.geo_locator.locate_ip(dst_ip)
            enriched_alert["dst_ip_reputation"] = self.abuseipdb_check(dst_ip)

        return enriched_alert
    
    def abuseipdb_check(self, ip: str) -> Dict[str, Any]:
        """Query AbuseIPDB for IP reputation."""
        try:
            base_url = self.config.get('abuseipdb_base_url')
            api_key = self.config.get('abuseipdb_api_key')
            
            if not base_url or not api_key:
                return {"error": "AbuseIPDB configuration not found"}
            
            url = f"{base_url}?ipAddress={ip}&maxAgeInDays=90"
            headers = {"Accept": "application/json", "Key": api_key}

            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json().get("data", {})
                reputation = {
                    "ip": ip,
                    "abuseConfidenceScore": data.get("abuseConfidenceScore", 0),
                    "totalReports": data.get("totalReports", 0),
                    "isWhitelisted": data.get("isWhitelisted", False),
                    "countryCode": data.get("countryCode", "Unknown"),
                    "usageType": data.get("usageType", "Unknown"),
                    "domain": data.get("domain", "N/A"),
                    "lastReportedAt": data.get("lastReportedAt", "Unknown")
                }

                if reputation["abuseConfidenceScore"] >= 75:
                    reputation["status"] = "malicious"
                elif reputation["abuseConfidenceScore"] >= 40:
                    reputation["status"] = "suspicious"
                else:
                    reputation["status"] = "clean"

                return reputation
            else:
                logger.error(f"AbuseIPDB API error: {response.status_code}")
                return {"error": f"AbuseIPDB API error {response.status_code}"}

        except Exception as e:
            logger.error(f"Error querying AbuseIPDB: {e}")
            return {"error": str(e)}
    
    def assess_severity(self, alert: Dict[str, Any]) -> str:
        """Assess alert severity based on heuristics."""
        score = 0
        ip_rep = alert.get("ip_reputation", {})
        
        if ip_rep.get("status") == "malicious":
            score += 5
        elif ip_rep.get("status") == "suspicious":
            score += 3

        # IDS prediction scoring
        ids_prediction = alert.get("ids_prediction", "")
        ids_confidence = alert.get("ids_confidence", 0.0)
        
        if ids_prediction and ids_prediction.upper() != "BENIGN":
            if ids_confidence > 0.8:
                score += 5
            elif ids_confidence > 0.6:
                score += 3
            elif ids_confidence > 0.4:
                score += 1
            
            if ids_prediction.upper() in ["DOS", "DDOS", "BRUTEFORCE", "BOTNET", "INFILTRATION", "WEBATTACK", "CRYPTOMINING"]:
                score += 5
            elif ids_prediction.upper() in ["PORTSCAN", "SCAN"]:
                score += 3

        label = alert.get("Attack", "").upper()
        if label in ["DOS", "DDOS", "BRUTEFORCE", "BOTNET", "INFILTRATION", "WEBATTACK", "CRYPTOMINING"]:
            score += 5
        elif label in ["PORTSCAN", "SCAN"]:
            score += 3

        severity = alert.get("Severity", "").upper()
        if severity in ["CRITICAL"]:
            return "Critical"
        elif severity in ["HIGH"]:
            return "High"
        elif severity in ["MEDIUM"]:
            return "Medium"
        elif severity in ["LOW"]:
            return "Low"

        if score <= 2:
            return "Low"
        elif score <= 5:
            return "Medium"
        elif score <= 8:
            return "High"
        else:
            return "Critical"
    
    def check_false_positive(self, alert: Dict[str, Any]) -> bool:
        """Check if alert is likely a false positive."""
        label = alert.get("Attack", "").upper()
        ip_status = alert.get("ip_reputation", {}).get("status", "clean")
        ids_prediction = alert.get("ids_prediction", "")
        ids_confidence = alert.get("ids_confidence", 0.0)
        
        # IDS predicts BENIGN with high confidence
        if ids_prediction and ids_prediction.upper() == "BENIGN" and ids_confidence > 0.7:
            return True

        # Heuristic rules
        if label == "BENIGN":
            return True
        if ip_status == "clean" and label in ["PORTSCAN", "SCAN"]:
            return True
        if any(alert.get("SourceIP", "").startswith(net) for net in self.internal_networks):
            if label in ["PORTSCAN", "SCAN"] and ip_status == "clean":
                return True
            if ids_prediction and ids_prediction.upper() == "BENIGN":
                return True

        return False

    def extract_section(self, text: str, section_name: str) -> str:
        """Fallback for regex extraction."""
        match = re.search(rf"\*\*{section_name}:\*\*\s*(.+)", text, re.IGNORECASE)
        return match.group(1).strip() if match else "N/A"

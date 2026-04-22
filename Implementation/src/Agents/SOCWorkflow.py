"""
SOC Workflow using LangGraph to connect Tier1Analyst and Tier2Analyst.
This workflow orchestrates the escalation process from Tier 1 to Tier 2 analysis.
"""

from .runtime_compat import MemorySaver, StateGraph
from typing import Dict, Any, Literal, List, Optional
import copy
import datetime
import uuid
import json
import os
import re
import threading
from concurrent.futures import ThreadPoolExecutor
try:
    from typing import TypedDict
except ImportError:
    from typing_extensions import TypedDict
from .LegacyCompat import Tier1Analyst, Tier2Analyst, Tier3Analyst
from .WarRoomWorkflow import WarRoomWorkflow

from .VectorMemoryManager import VectorMemoryManager
from .MetadataManager import MetadataManager
from .ReportGeneratorAgent import ReportGeneratorAgent
from .RemoteAgentClient import RemoteAgentClient
from .RemediationAgent import RemediationAgent
from ..Database.FlowHistoryManager import FlowHistoryManager
from ...utils.Logger import setup_logger

logger = setup_logger(__name__)

# Auto-pilot / enforcement threshold (0–1). Defaults to >90%; can override via env.
_REMEDIATION_AUTO_MIN = float(
    os.getenv("IDS_REMEDIATION_AUTO_MIN_CONFIDENCE", os.getenv("IDS_AUTO_WORKFLOW_CONFIDENCE", "0.9"))
)
# When true (default), Tier 2+ runs on a worker thread so the caller returns after Tier 1 (direct mode / microservices).
_TIER2_BACKGROUND = os.getenv("SOC_WORKFLOW_TIER2_BACKGROUND", "true").strip().lower() in (
    "1",
    "true",
    "yes",
)

class SOCWorkflowState(TypedDict, total=False):
    """State schema for the SOC workflow."""
    alert_data: Dict[str, Any]
    current_status: str
    context_logs: str
    current_incidents: str
    tier1_result: Dict[str, Any]
    tier2_result: Dict[str, Any]
    tier3_result: Dict[str, Any] # Added Tier 3
    war_room_result: Dict[str, Any] # Added War Room
    escalate: bool
    escalate_to_tier3: bool # Added escalation flag
    trigger_war_room: bool # Added War Room trigger
    remediation_result: Dict[str, Any] # Added Remediation
    hexstrike_enrichment: Dict[str, Any] # Added background enrichment state
    forensic_future: Any # Handle for background thread
    final_result: Dict[str, Any]


class SOCWorkflow:
    """
    SOC Workflow that orchestrates Tier 1, Tier 2, and Tier 3 analysis using LangGraph.
    """

    def __init__(self, api_key: str = None, agent_urls: Dict[str, str] = None, hexstrike_url: str = None):
        """
        Initialize the SOC workflow with Tier 1, Tier 2, and Tier 3 analysts.

        Args:
            api_key: Optional API key for LLM services
            agent_urls: Optional dictionary mapping agent roles to their microservice URLs.
                        Example: {"tier1": "http://localhost:6051", "tier2": "http://localhost:6052"}
            hexstrike_url: Optional Hexstrike-AI MCP server URL. Falls back to config.json.
        """
        agent_urls = agent_urls or {}

        # Load hexstrike_url from config if not provided
        if not hexstrike_url:
            try:
                config_path = os.path.join(
                    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                    "config.json",
                )
                with open(config_path, "r") as fh:
                    config = json.load(fh)
                    hexstrike_url = config.get("hexstrike_url", "http://localhost:8888")
            except Exception:
                hexstrike_url = "http://localhost:8888"

        self.hexstrike_url = hexstrike_url

        self.tier1_analyst = (
            RemoteAgentClient(agent_urls["tier1"], local_factory=lambda: Tier1Analyst(api_key=api_key, hexstrike_url=hexstrike_url))
            if "tier1" in agent_urls
            else Tier1Analyst(api_key=api_key, hexstrike_url=hexstrike_url)
        )
        self.tier2_analyst = (
            RemoteAgentClient(agent_urls["tier2"], local_factory=lambda: Tier2Analyst(api_key=api_key, hexstrike_url=hexstrike_url))
            if "tier2" in agent_urls
            else Tier2Analyst(api_key=api_key, hexstrike_url=hexstrike_url)
        )
        self.tier3_analyst = (
            RemoteAgentClient(agent_urls["tier3"], local_factory=lambda: Tier3Analyst(api_key=api_key, hexstrike_url=hexstrike_url))
            if "tier3" in agent_urls
            else Tier3Analyst(api_key=api_key, hexstrike_url=hexstrike_url)
        )
        self.war_room = (
            RemoteAgentClient(agent_urls["warroom"], local_factory=lambda: WarRoomWorkflow(api_key=api_key, hexstrike_url=hexstrike_url))
            if "warroom" in agent_urls
            else WarRoomWorkflow(api_key=api_key, hexstrike_url=hexstrike_url)
        )
        self.memory = MemorySaver() if api_key else None
        self.kb_memory = VectorMemoryManager() # Initialize persistent Vector DB memory
        self.metadata_mgr = MetadataManager() # Initialize SQL Metadata Repository
        self.reporter = RemoteAgentClient(agent_urls["reporter"]) if "reporter" in agent_urls else ReportGeneratorAgent()

        # Initialize RemediationAgent with Hexstrike client
        try:
            from .HexstrikeClient import HexstrikeClient
            self.remediation_executor = RemoteAgentClient(agent_urls["remediation"]) if "remediation" in agent_urls else RemediationAgent(hexstrike=HexstrikeClient(base_url=hexstrike_url))
        except Exception:
            self.remediation_executor = RemoteAgentClient(agent_urls["remediation"]) if "remediation" in agent_urls else RemediationAgent()

        self.flow_history = FlowHistoryManager()
        self.executor = ThreadPoolExecutor(max_workers=5)
        
        
        # Use LangGraph only if we have an API key AND we are NOT running in microservices mode
        if api_key and not agent_urls:
            self.graph = self._create_graph()
            self.app = self.graph.compile()
        else:
            self.app = None

    def _normalize_recommended_actions(self, actions: Any) -> list[str]:
        """Normalize recommendation payload into a list of action strings."""
        if isinstance(actions, list):
            return [str(a).strip() for a in actions if str(a).strip()]
        if isinstance(actions, str):
            text = actions.strip()
            if not text or text.upper() == "N/A":
                return []
            if "\n" in text:
                parts = [p.strip("-* ").strip() for p in text.splitlines()]
            else:
                parts = [p.strip() for p in text.split(",")]
            return [p for p in parts if p]
        return []

    def _collect_all_recommendations(
        self,
        tier1_result: Dict[str, Any],
        tier2_result: Dict[str, Any],
        tier3_result: Dict[str, Any],
    ) -> List[str]:
        """
        Merge analyst recommendations from all tiers (deduplicated, order preserved)
        so the security team / sandbox receives one unified action list.
        """
        merged: List[str] = []
        merged.extend(self._normalize_recommended_actions(tier1_result.get("recommended_actions")))
        merged.extend(self._normalize_recommended_actions(tier2_result.get("recommended_actions")))
        merged.extend(self._normalize_recommended_actions(tier3_result.get("recommended_actions")))
        seen: set[str] = set()
        out: List[str] = []
        for item in merged:
            key = item.casefold()
            if key and key not in seen:
                seen.add(key)
                out.append(item)
        return out

    @staticmethod
    def _reports_project_root() -> str:
        """Project root (parent of ``Implementation``)."""
        return os.path.dirname(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        )

    def _extract_actionable_rules_from_text(self, text: str) -> List[Dict[str, Any]]:
        """Parse [ACTIONABLE_RULES] ... [/ACTIONABLE_RULES] blocks (same contract as RemediationAgent)."""
        if not text:
            return []
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
        try:
            rules = json.loads(json_match.group(1).strip())
            return rules if isinstance(rules, list) else [rules]
        except (json.JSONDecodeError, ValueError):
            return []

    @staticmethod
    def _strip_actionable_rules_blocks(text: str) -> str:
        """Remove all ACTIONABLE_RULES blocks, keeping narrative text for the defense plan."""
        if not text:
            return ""
        cleaned = re.sub(
            r"\[ACTIONABLE_RULES\].*?\[/ACTIONABLE_RULES\]",
            "",
            text,
            flags=re.DOTALL | re.IGNORECASE,
        )
        return cleaned.strip()

    @staticmethod
    def _dedupe_rule_dicts(rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen = set()
        out: List[Dict[str, Any]] = []
        for r in rules:
            key = (
                str(r.get("action", "")),
                str(r.get("target", "")),
                str(r.get("reason", ""))[:120],
            )
            if key in seen:
                continue
            seen.add(key)
            out.append(r)
        return out

    def _recommendations_to_rule_dicts(
        self,
        action_texts: List[str],
        alert_data: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Map natural-language recommendations to sandbox rule dicts."""
        s_src = FlowHistoryManager.resolve_src_ip(alert_data)
        s_dst = FlowHistoryManager.resolve_dst_ip(alert_data)
        source_ip = s_src if s_src != "Unknown" else "UNKNOWN"
        target_ip = s_dst if s_dst != "Unknown" else source_ip
        threat_label = str(alert_data.get("Attack", alert_data.get("predicted_label", "Unknown")))
        if not action_texts:
            return []

        rules: List[Dict[str, Any]] = []
        for rec in action_texts:
            rec_lower = rec.lower()
            if "block" in rec_lower and "ip" in rec_lower:
                rules.append({
                    "action": "BLOCK_IP",
                    "target": source_ip,
                    "duration": "1h",
                    "reason": f"Tier recommendation: {rec}",
                })
            elif "rate" in rec_lower and "limit" in rec_lower:
                rules.append({
                    "action": "RATE_LIMIT",
                    "target": source_ip,
                    "limit": "50/s",
                    "reason": f"Tier recommendation: {rec}",
                })
            elif "isolate" in rec_lower:
                rules.append({
                    "action": "ISOLATE_HOST",
                    "target": source_ip,
                    "reason": f"Tier recommendation: {rec}",
                })
            elif "reset" in rec_lower and "password" in rec_lower:
                rules.append({
                    "action": "RESET_PASSWORD",
                    "target": source_ip,
                    "reason": f"Tier recommendation: {rec}",
                })
            elif "scan" in rec_lower or "enrich" in rec_lower or "investigate" in rec_lower:
                rules.append({
                    "action": "ENRICH_TARGET",
                    "target": target_ip,
                    "reason": f"Tier recommendation: {rec}",
                })
            elif "siem" in rec_lower or "rule" in rec_lower or "detection" in rec_lower:
                rules.append({
                    "action": "TUNE_SIEM",
                    "target": "IDS_RULESET",
                    "reason": f"Tier recommendation: {rec}",
                })

        if not rules:
            rules.append({
                "action": "ENRICH_TARGET",
                "target": target_ip,
                "reason": f"Generic recommendation for {threat_label}",
            })
        return rules

    def _serialize_actionable_rules_block(self, rules: List[Dict[str, Any]]) -> str:
        return "[ACTIONABLE_RULES]\n" + json.dumps(rules, indent=2) + "\n[/ACTIONABLE_RULES]"

    def _build_actionable_rules_from_recommendations(
        self,
        recommendations: Any,
        alert_data: Dict[str, Any],
    ) -> str:
        """
        Convert high-level recommendations into executable ACTIONABLE_RULES JSON.
        This ensures report recommendations can be enforced automatically.
        """
        action_texts = self._normalize_recommended_actions(recommendations)
        if not action_texts:
            return ""
        rules = self._recommendations_to_rule_dicts(action_texts, alert_data)
        return self._serialize_actionable_rules_block(rules)

    def _merge_defense_plan_with_recommendations(
        self,
        defense_plan: str,
        recommendations: Any,
        alert_data: Dict[str, Any],
    ) -> str:
        """
        Merge tier recommendations into the defense plan as a single ACTIONABLE_RULES block.

        Preserves narrative from Blue Team / Tier 3, parses any existing rules, unions
        with rules derived from **all** supplied recommendations, deduplicates, and
        re-serializes so the sandbox executes one combined policy set.
        """
        plan_text = str(defense_plan or "")
        narrative = self._strip_actionable_rules_blocks(plan_text)
        existing = self._extract_actionable_rules_from_text(plan_text)
        action_texts = self._normalize_recommended_actions(recommendations)
        generated = self._recommendations_to_rule_dicts(action_texts, alert_data) if action_texts else []
        merged = self._dedupe_rule_dicts(existing + generated)
        if not merged:
            return plan_text
        block = self._serialize_actionable_rules_block(merged)
        if not narrative:
            return block
        return f"{narrative}\n\n{block}".strip()

    def _persist_security_team_handoff(
        self,
        *,
        alert_data: Dict[str, Any],
        all_recommendations: List[str],
        defense_plan_for_sandbox: str,
        remediation_result: Dict[str, Any],
    ) -> Optional[str]:
        """
        Write a machine-readable handoff file for operators / Blue Team so every
        tier recommendation is traceable alongside sandbox execution results.
        """
        reports_dir = os.path.join(self._reports_project_root(), "Reports")
        try:
            os.makedirs(reports_dir, exist_ok=True)
        except OSError as exc:
            logger.warning("Could not create Reports dir for security handoff: %s", exc)
            return None

        payload = {
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "purpose": "Security team — consolidated recommendations → sandbox",
            "alert": {
                "Attack": alert_data.get("Attack"),
                "SourceIP": alert_data.get("SourceIP") or alert_data.get("Source IP") or alert_data.get("IPV4_SRC_ADDR"),
                "DestinationIP": alert_data.get("DestinationIP") or alert_data.get("Destination IP") or alert_data.get("IPV4_DST_ADDR"),
            },
            "recommended_actions_all_tiers": all_recommendations,
            "parsed_actionable_rules": self._extract_actionable_rules_from_text(defense_plan_for_sandbox),
            "remediation": {
                "status": remediation_result.get("remediation_status"),
                "execution_log": remediation_result.get("execution_log", []),
                "enforced_rules": remediation_result.get("enforced_rules", []),
            },
        }
        path = os.path.join(reports_dir, "security_team_sandbox_handoff.json")
        try:
            backlog: List[Dict[str, Any]] = []
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as fh:
                    try:
                        raw = json.load(fh)
                        if isinstance(raw, list):
                            backlog = raw
                        elif isinstance(raw, dict):
                            backlog = [raw]
                    except json.JSONDecodeError:
                        backlog = []
            backlog.append(payload)
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(backlog, fh, indent=2)
            logger.info("Security team handoff written: %s", path)
            return path
        except OSError as exc:
            logger.warning("Failed to write security team handoff: %s", exc)
            return None
    
    def _create_graph(self) -> StateGraph:
        """Create the LangGraph workflow."""
        workflow = StateGraph(SOCWorkflowState)
        
        # Add nodes
        workflow.add_node("tier1_analysis", self._tier1_node)
        workflow.add_node("tier2_analysis", self._tier2_node)
        workflow.add_node("tier3_analysis", self._tier3_node) # Added Tier 3 node
        workflow.add_node("war_room", self._war_room_node) # Added War Room node
        workflow.add_node("remediation_execution", self._remediation_node) # Added Remediation node
        workflow.add_node("finalize", self._finalize_node)
        
        # Define entry point
        try:
            workflow.set_entry_point("tier1_analysis")
        except:
            workflow.add_edge("__start__", "tier1_analysis")
        
        # Conditional edge: escalate to Tier 2 if needed
        workflow.add_conditional_edges(
            "tier1_analysis",
            self._should_escalate,
            {
                "escalate": "tier2_analysis",
                "no_escalation": "finalize"
            }
        )
        
        # Conditional edge: escalate to Tier 3 if needed
        workflow.add_conditional_edges(
            "tier2_analysis",
            self._should_escalate_to_tier3,
            {
                "escalate_tier3": "tier3_analysis",
                "finalize": "finalize"
            }
        )
        
        workflow.add_edge("tier3_analysis", "finalize") # Default, will be overridden by conditional if needed
        
        # Conditional edge: trigger War Room if needed
        workflow.add_conditional_edges(
            "tier3_analysis",
            self._should_trigger_war_room,
            {
                "trigger_war_room": "war_room",
                "remediation": "remediation_execution",
                "finalize": "finalize"
            }
        )
        
        workflow.add_edge("war_room", "remediation_execution")
        workflow.add_edge("remediation_execution", "finalize")
        
        # Set finish point
        try:
            workflow.set_finish_point("finalize")
        except:
            workflow.add_edge("finalize", "__end__")
        
        return workflow
    
    def _tier1_node(self, state: SOCWorkflowState) -> SOCWorkflowState:
        """Tier 1 analysis node."""
        input_data = {
            "alert_data": state.get("alert_data", {}),
            "context_logs": state.get("context_logs", ""),
            "current_status": state.get("current_status", "Unknown"),
            "forensic_status": "PENDING" if state.get("forensic_future") else "IDLE"
        }
        
        tier1_result = self.tier1_analyst.process(input_data)
        escalate = tier1_result.get("escalate", False)
        
        logger.info(f"Tier 1 [Triage]: Severity={tier1_result.get('severity')}, Escalate={escalate}")
        
        return {
            **state,
            "tier1_result": tier1_result,
            "escalate": escalate
        }
    
    def _tier2_node(self, state: SOCWorkflowState) -> SOCWorkflowState:
        """Tier 2 analysis node."""
        tier1_result = state.get("tier1_result", {})
        alert_data = state.get("alert_data", {})
        force_forensics = bool(alert_data.get("force_forensics", False))

        # Tier2+ requires forensic enrichment; block until available.
        enrichment = state.get("hexstrike_enrichment", {})
        future = state.get("forensic_future")
        if not enrichment:
            if not future:
                future = self._execute_forensic_background(alert_data, force_forensics=True)
            if future:
                try:
                    logger.info("Awaiting HexStrike enrichment before Tier 2 analysis...")
                    enrichment = future.result(timeout=90)
                except Exception as e:
                    logger.error("Forensic enrichment failed/timed out before Tier 2: %s", e)
                    enrichment = {"error": str(e)}
            elif force_forensics:
                src_ip = FlowHistoryManager.resolve_src_ip(alert_data)
                enrichment = self._fetch_forensics(src_ip)
        
        # Retrieve similar past incidents from memory
        alert_summary = f"{tier1_result.get('severity', '')} {str(state.get('alert_data', ''))}"
        similar_incidents = self.kb_memory.search_similar(alert_summary)
        
        input_data = {
            "tier1_output": tier1_result,
            "context_logs": state.get("context_logs", "No additional logs available."),
            "current_incidents": state.get("current_incidents", "No active incidents logged."),
            "similar_incidents": similar_incidents,
            "hexstrike_enrichment": enrichment
        }
        
        tier2_result = self.tier2_analyst.process(input_data)
        
        # Determine if we should escalate to Tier 3
        # Robust check: look for "Yes" flag or "Confirmed" in classification
        escalate_to_tier3 = False
        t2_escalate = str(tier2_result.get("escalate", "No")).lower().strip()
        classification = str(tier2_result.get("incident_classification", "")).lower()
        
        if t2_escalate == "yes" or "confirmed" in classification:
            escalate_to_tier3 = True
            
        logger.info(f"Tier 2 [Investigation]: Severity={tier2_result.get('validated_severity')}, Escalate={escalate_to_tier3}")
        
        return {
            **state,
            "tier2_result": tier2_result,
            "hexstrike_enrichment": enrichment,
            "escalate_to_tier3": escalate_to_tier3
        }

    def _tier3_node(self, state: SOCWorkflowState) -> SOCWorkflowState:
        """Tier 3 analysis node."""
        tier1_result = state.get("tier1_result", {})
        tier2_result = state.get("tier2_result", {})
        
        input_data = {
            "tier1_output": tier1_result,
            "tier2_output": tier2_result,
            "alert_data": state.get("alert_data", {}),
            "hexstrike_enrichment": state.get("hexstrike_enrichment", {}),
            "context_logs": state.get("context_logs", ""),
        }
        
        tier3_result = self.tier3_analyst.process(input_data)
        
        # Check for credible threat to trigger War Room
        trigger_war_room = tier3_result.get("credible_threat", False)
        
        return {
            **state,
            "tier3_result": tier3_result,
            "trigger_war_room": trigger_war_room
        }

    def _war_room_node(self, state: SOCWorkflowState) -> SOCWorkflowState:
        """War Room node."""
        tier1_result = state.get("tier1_result", {})
        tier2_result = state.get("tier2_result", {})
        tier3_result = state.get("tier3_result", {})
        
        # Combine info for the incident
        incident_data = {
            "tier1": tier1_result,
            "tier2": tier2_result,
            "tier3": tier3_result
        }
        
        war_room_result = self.war_room.run_simulation(incident_data)
        
        return {
            **state,
            "war_room_result": war_room_result
        }

    def _remediation_node(self, state: SOCWorkflowState) -> SOCWorkflowState:
        """Remediation execution node."""
        war_room_result = state.get("war_room_result", {})
        tier3_result = state.get("tier3_result", {})
        tier1_result = state.get("tier1_result", {})
        tier2_result = state.get("tier2_result", {})
        alert_data = state.get("alert_data", {})
        
        # Get generated code from Blue Team if available
        blue_plan = war_room_result.get("blue_team_plan", {})
        generated_code = blue_plan.get("generated_defensive_code", {}).get("final_code", "")
        defense_plan = blue_plan.get("defense_plan", tier3_result.get("response_plan", ""))
        all_recommendations = self._collect_all_recommendations(
            tier1_result, tier2_result, tier3_result
        )
        defense_plan = self._merge_defense_plan_with_recommendations(
            defense_plan=defense_plan,
            recommendations=all_recommendations,
            alert_data=alert_data,
        )
        
        # Determine auto-pilot based on confidence (IDS + tier analysts)
        t1_conf = float(tier1_result.get("ids_prediction", {}).get("confidence", 0.0) or 0.0)
        t2_conf = float(tier2_result.get("confidence", 0.0) or 0.0)
        alert_conf = float(alert_data.get("confidence") or alert_data.get("malicious_confidence") or 0.0)
        max_confidence = max(t1_conf, t2_conf, alert_conf)
        
        input_data = {
            "threat_info": alert_data,
            "generated_code": generated_code,
            "defense_plan": defense_plan,
            "auto_pilot": max_confidence > _REMEDIATION_AUTO_MIN,
            "force_enforce": max_confidence > _REMEDIATION_AUTO_MIN,
        }
        
        remediation_result = self.remediation_executor.process(input_data)

        self._persist_security_team_handoff(
            alert_data=alert_data,
            all_recommendations=all_recommendations,
            defense_plan_for_sandbox=defense_plan,
            remediation_result=remediation_result,
        )
        
        return {
            **state,
            "remediation_result": remediation_result
        }
    
    def _infer_final_severity(
        self,
        alert_data: Dict[str, Any],
        tier1_result: Dict[str, Any],
        tier2_result: Dict[str, Any],
        escalated: bool,
    ) -> str:
        """
        Produce a non-unknown final severity when tiers omit it, remote calls fail ({}),
        or JSON contained null severities. Uses IDS confidence + predicted label as fallback.
        """
        t2 = tier2_result or {}
        t1 = tier1_result or {}
        if escalated and t2:
            vs = t2.get("validated_severity")
            if self._is_meaningful_severity(vs):
                return str(vs).strip()
        s1 = t1.get("severity")
        if self._is_meaningful_severity(s1):
            return str(s1).strip()

        conf = alert_data.get("confidence")
        if conf is None:
            conf = alert_data.get("malicious_confidence")
        try:
            c = float(conf)
        except (TypeError, ValueError):
            c = 0.0
        label = str(alert_data.get("predicted_label") or alert_data.get("Attack") or "").upper()
        if any(x in label for x in ("DDOS", "BOTNET", "INFIL", "EXPLOIT", "RANSOM", "WORM")):
            tier = "High"
        elif any(x in label for x in ("BRUTE", "DOS", "SQL", "XSS", "INJECTION")):
            tier = "High"
        elif any(x in label for x in ("SCAN", "FUZZ", "PORT")):
            tier = "Medium"
        else:
            tier = "Medium"
        if c >= 0.85:
            return "High"
        if c >= 0.65:
            return "High" if tier == "High" else "Medium"
        if c >= 0.45:
            return tier if tier == "High" else "Medium"
        return "Low"

    @staticmethod
    def _is_meaningful_severity(value: Any) -> bool:
        if value is None:
            return False
        s = str(value).strip()
        if not s:
            return False
        return s.lower() not in ("unknown", "n/a", "none", "null")

    def _finalize_node(self, state: SOCWorkflowState) -> SOCWorkflowState:
        """Finalize and combine results."""
        tier1_result = state.get("tier1_result", {})
        tier2_result = state.get("tier2_result", {})
        tier3_result = state.get("tier3_result", {})
        war_room_result = state.get("war_room_result", {})
        remediation_result = state.get("remediation_result", {})
        escalated = state.get("escalate", False)
        escalated_tier3 = state.get("escalate_to_tier3", False)
        triggered_war_room = state.get("trigger_war_room", False)
        
        final_result = {
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "workflow_version": "2.0", # Updated version
            "tier1_analysis": tier1_result,
            "escalated_to_tier2": escalated,
            "escalated_to_tier3": escalated_tier3,
            "war_room_triggered": triggered_war_room,
            "hexstrike_enrichment": state.get("hexstrike_enrichment", {}),
            "alert_data": state.get("alert_data", {}),
            "context_logs": state.get("context_logs", ""),
        }
        
        combined_recs = self._collect_all_recommendations(
            tier1_result,
            tier2_result if escalated else {},
            tier3_result if escalated_tier3 else {},
        )
        alert_data = state.get("alert_data") or {}
        if escalated and tier2_result:
            final_result["tier2_analysis"] = tier2_result
            final_result["final_severity"] = self._infer_final_severity(
                alert_data, tier1_result, tier2_result, True
            )
            final_result["incident_classification"] = tier2_result.get("incident_classification", "N/A")
            final_result["recommended_actions"] = (
                combined_recs
                if combined_recs
                else tier2_result.get("recommended_actions", "N/A")
            )
            
            if escalated_tier3 and tier3_result:
                final_result["tier3_analysis"] = tier3_result
                final_result["response_plan"] = tier3_result.get("response_plan", "N/A")
                
                # Always surface war_room_analysis when the War Room was
                # triggered — even if the simulation returned an empty/partial
                # result — so the report generator can render a useful fallback
                # instead of "Simulation data unavailable".
                if triggered_war_room:
                    final_result["war_room_analysis"] = war_room_result or {
                        "red_team_plan": {"attack_plan": "War Room was triggered but the simulation returned no data."},
                        "blue_team_plan": {"defense_plan": "War Room was triggered but the simulation returned no data."},
                        "purple_team_report": {"analysis_report": "War Room was triggered but the simulation returned no data."},
                    }
                    final_result["purple_team_report"] = (
                        (war_room_result or {}).get("purple_team_report", {}).get("analysis_report", "N/A")
                    )
            
            # Add remediation to results if it ran
            if remediation_result:
                final_result["remediation"] = remediation_result
        else:
            final_result["final_severity"] = self._infer_final_severity(
                alert_data, tier1_result, tier2_result, False
            )
            final_result["incident_classification"] = "Tier 1 Analysis Only"
            final_result["recommended_actions"] = (
                combined_recs if combined_recs else tier1_result.get("triage_response", "N/A")
            )

        # If recommendations exist but remediation did not run earlier, execute them now.
        if not final_result.get("remediation"):
            fallback_recs = self._normalize_recommended_actions(final_result.get("recommended_actions"))
            recommendation_plan = self._build_actionable_rules_from_recommendations(
                recommendations=fallback_recs,
                alert_data=state.get("alert_data", {}),
            )
            if recommendation_plan:
                try:
                    fallback_remediation = self.remediation_executor.process({
                        "threat_info": state.get("alert_data", {}),
                        "generated_code": "",
                        "defense_plan": recommendation_plan,
                        "auto_pilot": False,
                    })
                    final_result["remediation"] = fallback_remediation
                    state["remediation_result"] = fallback_remediation
                    self._persist_security_team_handoff(
                        alert_data=state.get("alert_data", {}),
                        all_recommendations=fallback_recs,
                        defense_plan_for_sandbox=recommendation_plan,
                        remediation_result=fallback_remediation,
                    )
                    logger.info("Executed remediation from report recommendations")
                except Exception as e:
                    logger.error(f"Recommendation-based remediation failed: {e}")
        
        # Save meaningful incidents to memory
        if escalated and tier2_result and final_result.get("incident_classification") == "Confirmed Incident":
             self.kb_memory.add_incident(final_result)

        # RL feedback — label the experience row keyed by this alert so the
        # fine-tuner can learn from agent verdicts.
        try:
            alert_data = state.get("alert_data") or {}
            rl_alert_id = alert_data.get("rl_alert_id")
            predicted_label = alert_data.get("predicted_label") or alert_data.get("Attack") or ""
            if rl_alert_id:
                from Implementation.src.IDS.rl import FeedbackHook
                FeedbackHook.instance().on_workflow_finalize(
                    alert_id=rl_alert_id,
                    predicted_label=predicted_label,
                    tier1=tier1_result,
                    tier2=tier2_result,
                )
        except Exception as exc:
            logger.debug("RL finalize hook skipped: %s", exc)

        # Incident graph — record IP ↔ attack ↔ rule relationships.
        try:
            alert_data = state.get("alert_data") or {}
            from Implementation.src.IDS.incident_graph import get_incident_graph
            src_ip = FlowHistoryManager.resolve_src_ip(alert_data)
            dst_ip = FlowHistoryManager.resolve_dst_ip(alert_data)
            incident_id = alert_data.get("rl_alert_id") or final_result.get("timestamp") or "INC-anon"
            rule_ids = [
                (e.get("rule") or {}).get("id") or (e.get("rule") or {}).get("action")
                for e in (remediation_result or {}).get("execution_log", [])
                if isinstance(e, dict)
            ]
            get_incident_graph().record_incident(
                incident_id=incident_id,
                src_ip=src_ip if src_ip != "Unknown" else None,
                dst_ip=dst_ip if dst_ip != "Unknown" else None,
                attack_type=alert_data.get("predicted_label") or alert_data.get("Attack"),
                severity=final_result.get("final_severity"),
                rule_ids=[r for r in rule_ids if r],
            )
        except Exception as exc:
            logger.debug("Incident graph ingest skipped: %s", exc)

        # Generate Report
        print("DEBUG: Finalizing node - Generating report...")
        report_path = self.reporter.generate_report(final_result)
        final_result["report_path"] = report_path
        
        # Structured Persistence: Save to Metadata Repository (SQL)
        self.metadata_mgr.save_incident(final_result)
        
        print(f"DEBUG: Report generated: {report_path}")
        logger.info(f"Workflow completed. Incident recorded in Metadata DB. Report: {report_path}")

        return {
            **state,
            "final_result": final_result
        }
    
    def _should_escalate(self, state: SOCWorkflowState) -> Literal["escalate", "no_escalation"]:
        """Determine if escalation to Tier 2 is needed."""
        escalate = state.get("escalate", False)
        return "escalate" if escalate else "no_escalation"

    def _should_escalate_to_tier3(self, state: SOCWorkflowState) -> Literal["escalate_tier3", "finalize"]:
        """Determine if escalation to Tier 3 is needed."""
        escalate = state.get("escalate_to_tier3", False)
        return "escalate_tier3" if escalate else "finalize"

    def _should_trigger_war_room(self, state: SOCWorkflowState) -> Literal["trigger_war_room", "remediation", "finalize"]:
        """Determine if War Room should be triggered."""
        if state.get("trigger_war_room"):
            return "trigger_war_room"
        
        # If Tier 3 ran, we definitely want remediation or war room
        # Check if Tier 3 confirmed a credible threat or generated a plan
        if state.get("tier3_result"):
            return "remediation"
            
        return "finalize"

    def _shallow_state_for_background(self, state: SOCWorkflowState) -> SOCWorkflowState:
        """Detach top-level mutable dicts so the worker thread does not race the caller."""
        out: Dict[str, Any] = dict(state)
        if isinstance(state.get("alert_data"), dict):
            out["alert_data"] = copy.copy(state["alert_data"])
        if isinstance(state.get("tier1_result"), dict):
            out["tier1_result"] = copy.copy(state["tier1_result"])
        return out  # type: ignore[return-value]

    def _immediate_result_tier1_escalation(self, state: SOCWorkflowState) -> Dict[str, Any]:
        """API payload returned immediately while Tier 2+ runs on a background executor thread."""
        tier1 = state.get("tier1_result") or {}
        alert = state.get("alert_data") or {}
        return {
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "workflow_version": "2.0",
            "tier1_analysis": tier1,
            "escalated_to_tier2": True,
            "escalated_to_tier3": False,
            "war_room_triggered": False,
            "tier2_processing": "background",
            "incident_classification": "Tier 2 pending (background worker)",
            "final_severity": self._infer_final_severity(alert, tier1, {}, False),
            "recommended_actions": tier1.get("recommended_actions", []),
            "context_logs": state.get("context_logs", ""),
            "alert_data": alert,
            "hexstrike_enrichment": state.get("hexstrike_enrichment", {}),
            "message": (
                "Escalated to Tier 2. Investigation (Tier 2 → Tier 3 → remediation → report) "
                "runs on a background thread; /predict/ and other hot paths are not blocked by it. "
                "A full incident report will appear under Reports/ when the pipeline completes."
            ),
        }

    def _background_tier2_pipeline(self, state: SOCWorkflowState) -> None:
        """
        Run Tier 2 through finalize on a worker thread (used after Tier 1 escalation).
        Mirrors the previous inline direct-execution path.
        """
        try:
            future = state.get("forensic_future")
            if future:
                try:
                    logger.info("Background SOC: awaiting deep forensics before Tier 2...")
                    state["hexstrike_enrichment"] = future.result(timeout=120)
                except Exception as e:
                    logger.error("Background SOC: forensic thread failed/timed out: %s", e)
                    state["hexstrike_enrichment"] = {"error": str(e)}

            logger.info("Background SOC: Tier 2 starting...")
            state = self._tier2_node(state)

            if self._should_escalate_to_tier3(state) == "escalate_tier3":
                state = self._tier3_node(state)
                if self._should_trigger_war_room(state) == "trigger_war_room":
                    state = self._war_room_node(state)
                if state.get("tier3_result") or state.get("war_room_result"):
                    logger.info("Background SOC: remediation...")
                    state = self._remediation_node(state)

            logger.info("Background SOC: finalizing (report + metadata)...")
            state = self._finalize_node(state)
            report_path = state.get("final_result", {}).get("report_path", "")
            logger.info("Background SOC pipeline complete. Report: %s", report_path)
        except Exception as exc:
            logger.exception("Background SOC Tier 2+ pipeline failed")
            # Flip the RL row so it doesn't linger as 'pending' when the
            # background pipeline crashes before reaching _finalize_node.
            self._rl_mark_workflow_failed(state.get("alert_data") or {}, str(exc)[:200])

    def _rl_mark_workflow_failed(self, alert_data: Dict[str, Any], reason: str) -> None:
        """
        Flip the RL row to WORKFLOW_FAILED so it doesn't linger as 'pending'.
        Safe to call from any exception handler — never throws.
        """
        try:
            rl_alert_id = (alert_data or {}).get("rl_alert_id")
            if not rl_alert_id:
                return
            predicted_label = (
                (alert_data or {}).get("predicted_label")
                or (alert_data or {}).get("Attack")
                or ""
            )
            from Implementation.src.IDS.rl import FeedbackHook
            FeedbackHook.instance().on_workflow_finalize(
                alert_id=rl_alert_id,
                predicted_label=predicted_label,
                workflow_failed=True,
                failure_reason=reason,
            )
        except Exception as exc:
            logger.debug("RL failure hook swallowed: %s", exc)

    def process(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process an alert through the SOC workflow.
        """
        print(f"\nSOCWorkflow: Processing alert for {input_data.get('alert_data', {}).get('Attack', 'Unknown')}")
        logger.info(f"Processing alert: {input_data.get('alert_data', {}).get('Attack', 'Unknown')}")
        
        # Enrich with flow_history.db: stats + recent rows (same IP resolution as persistence layer)
        alert = input_data.get("alert_data") or {}
        src_ip = FlowHistoryManager.resolve_src_ip(alert)
        dst_ip = FlowHistoryManager.resolve_dst_ip(alert)
        historical_summary = self.flow_history.format_history_for_llm(
            src_ip,
            dst_ip=dst_ip if dst_ip != "Unknown" else None,
            windows=(5, 60),
        )

        # Initialize state
        initial_state: SOCWorkflowState = {
            "alert_data": input_data.get("alert_data", {}),
            "current_status": input_data.get("current_status", "Unknown"),
            "context_logs": input_data.get("context_logs", "") + "\n\n" + historical_summary,
            "current_incidents": input_data.get("current_incidents", "No active incidents logged."),
            "tier1_result": {},
            "tier2_result": {},
            "tier3_result": {},
            "war_room_result": {},
            "escalate": False,
            "escalate_to_tier3": False,
            "trigger_war_room": False,
            "final_result": {},
            "hexstrike_enrichment": {},
            "forensic_future": None,
            "forensic_status": "IDLE"
        }

        # Threaded Forensics: Spawn background thread for high-severity/external IPs
        future = self._execute_forensic_background(input_data.get("alert_data", {}))
        initial_state["forensic_future"] = future
        
        # Calculate status
        if future:
            initial_state["forensic_status"] = "INVESTIGATING"
        else:
            initial_state["forensic_status"] = "IDLE"
        
        if self.app:
            try:
                # Use LangGraph to process the workflow
                thread_id = str(uuid.uuid4())
                config = {"configurable": {"thread_id": thread_id}}

                # Await forensic enrichment so Tier 2+ see hexstrike_enrichment in state
                if future:
                    try:
                        logger.info("Awaiting HexStrike enrichment before LangGraph invoke...")
                        initial_state["hexstrike_enrichment"] = future.result(timeout=60)
                    except Exception as exc:
                        logger.error("Forensic thread failed/timed out: %s", exc)
                        initial_state["hexstrike_enrichment"] = {"error": str(exc)}

                print(f"DEBUG: Invoking LangGraph app (thread: {thread_id})...")
                result = self.app.invoke(initial_state, config)
                print(f"DEBUG: App invoke complete. Keys in result: {result.keys()}")
                
                final_result = result.get("final_result", {})
                
                # Surface forensic status
                if "forensic_status" not in final_result:
                    future = result.get("forensic_future")
                    if future and future.done():
                        final_result["forensic_status"] = "COMPLETED"
                    elif future:
                        final_result["forensic_status"] = "INVESTIGATING"
                    else:
                        final_result["forensic_status"] = "IDLE"
                
                return final_result
            except Exception as e:
                logger.exception("LangGraph workflow failed")
                self._rl_mark_workflow_failed(input_data.get("alert_data") or {}, str(e)[:200])
                return {
                    "error": f"Workflow execution failed: {e}",
                    "timestamp": datetime.datetime.utcnow().isoformat()
                }
        else:
            # Direct execution (remote tier URLs / no LangGraph app). Tier 1 stays on this thread.
            logger.info(
                "SOCWorkflow direct mode: Tier 1 inline; Tier 2+ background=%s",
                _TIER2_BACKGROUND,
            )
            state = initial_state

            try:
                print("DEBUG: Executing Tier 1 Node...")
                state = self._tier1_node(state)
                print(f"DEBUG: Tier 1 Complete. Severity: {state.get('tier1_result', {}).get('severity')}")

                if self._should_escalate(state) != "escalate":
                    print("DEBUG: Finalizing Workflow (Tier 1 only)...")
                    state = self._finalize_node(state)
                    final_result = state.get("final_result", {})
                    if "forensic_status" not in final_result:
                        final_result["forensic_status"] = state.get("forensic_status", "IDLE")
                    return final_result

                if _TIER2_BACKGROUND:
                    worker_state = self._shallow_state_for_background(state)
                    self.executor.submit(self._background_tier2_pipeline, worker_state)
                    logger.info("Tier 2+ scheduled on background thread (executor)")
                    return self._immediate_result_tier1_escalation(state)

                future = state.get("forensic_future")
                if future:
                    try:
                        logger.info("Waiting for deep forensics to complete before Tier 2 analysis...")
                        state["hexstrike_enrichment"] = future.result(timeout=60)
                    except Exception as e:
                        logger.error("Forensic thread failed/timed out: %s", e)
                        state["hexstrike_enrichment"] = {"error": str(e)}

                print("DEBUG: Escalating to Tier 2 (blocking)...")
                state = self._tier2_node(state)
                print("DEBUG: Tier 2 Complete.")

                if self._should_escalate_to_tier3(state) == "escalate_tier3":
                    state = self._tier3_node(state)
                    if self._should_trigger_war_room(state) == "trigger_war_room":
                        state = self._war_room_node(state)
                    if state.get("tier3_result") or state.get("war_room_result"):
                        print("DEBUG: Executing Remediation Node...")
                        state = self._remediation_node(state)

                print("DEBUG: Finalizing Workflow...")
                state = self._finalize_node(state)
            except Exception as exc:
                logger.exception("Direct-mode workflow failed")
                self._rl_mark_workflow_failed(state.get("alert_data") or {}, str(exc)[:200])
                return {
                    "error": f"Workflow execution failed: {exc}",
                    "timestamp": datetime.datetime.utcnow().isoformat(),
                }
            print("DEBUG: Finalize Complete.")

            final_result = state.get("final_result", {})
            if "forensic_status" not in final_result:
                final_result["forensic_status"] = state.get("forensic_status", "IDLE")

            return final_result

    def run_full_triage(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main entry point for SOC triage.
        Orchestrates the entire process from ingestion to remediation.
        """
        # Check if we should launch background forensics
        self._execute_forensic_background(alert_data)
        
        return self.process({"alert_data": alert_data})

    def _execute_forensic_background(self, alert_data: Dict[str, Any], force_forensics: bool = False) -> Optional[Any]:
        """
        Spawn the background forensic thread when the alert meets the severity
        gate. Two knobs relax the default, both via env var:
          - FORCE_FORENSICS=true             — always run forensics
          - IDS_FORENSIC_MIN_SEVERITY=medium — lower floor (default: medium)
        """
        if os.getenv("FORCE_FORENSICS", "").lower() in ("1", "true", "yes"):
            force_forensics = True
        src_ip = FlowHistoryManager.resolve_src_ip(alert_data)
        if not (force_forensics or self._is_scannable_ip(src_ip)):
            return None

        severity = str(alert_data.get("Priority", alert_data.get("severity", "low"))).lower()
        min_sev = os.getenv("IDS_FORENSIC_MIN_SEVERITY", "medium").lower()
        allowed = {"low", "medium", "high", "critical"}
        rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        min_rank = rank.get(min_sev, 1)
        sev_ok = severity in allowed and rank.get(severity, 0) >= min_rank
        if force_forensics or sev_ok or "ddos" in str(alert_data).lower():
            logger.info("Spawning background forensic thread for %s (severity=%s, min=%s)",
                        src_ip, severity, min_sev)
            return self.executor.submit(self._fetch_forensics, src_ip)
        return None

    def _is_scannable_ip(self, ip: str) -> bool:
        """
        Can we target this IP for a forensic scan? Historically we excluded all
        RFC1918 ranges, which silently disabled forensics for every CSV-fed
        test case and most lab setups. Now we only block IPs that are literally
        pointless to scan: loopback, link-local, unspecified. Private RFC1918
        is allowed (operators usually *do* want to scan their own internal
        suspicious hosts).

        Set IDS_FORENSIC_EXCLUDE_PRIVATE=true to restore the stricter behaviour.
        """
        if not ip or ip == "Unknown":
            return False
        try:
            import ipaddress
            addr = ipaddress.ip_address(ip)
            # Always-skip cases
            if addr.is_loopback or addr.is_link_local or addr.is_unspecified or addr.is_multicast:
                return False
            if os.getenv("IDS_FORENSIC_EXCLUDE_PRIVATE", "").lower() in ("1", "true", "yes"):
                return not addr.is_private
            return True
        except ValueError:
            # Not a valid IP literal (hostname, garbage) — let HexStrike decide
            return True

    # Back-compat shim — older callers still use _is_external_ip.
    def _is_external_ip(self, ip: str) -> bool:
        return self._is_scannable_ip(ip)

    def _fetch_forensics(self, ip: str) -> Dict[str, Any]:
        """Deep enrichment from HexStrike.

        Collects three complementary signals in parallel:
          - analyze_target : AI decision-engine profile (risk_level, attack_surface_score)
          - nmap_scan      : actual port-scan + service-version output
          - check_ip_reputation : AbuseIPDB-backed reputation (country, abuse_score, tor/vpn)

        Runs in a worker thread spawned from _execute_forensic_background.
        """
        try:
            logger.info("Deep forensics started for %s", ip)
            from .HexstrikeClient import HexstrikeClient
            client = HexstrikeClient(base_url=self.hexstrike_url)

            # 1. AI profile — cheap, pure reasoning, always runs
            try:
                analysis = client.analyze_target(ip, analysis_type="comprehensive") or {}
            except Exception as exc:
                analysis = {"error": f"analyze_target failed: {exc}"}

            # 2. Real nmap scan — quick TCP-connect on a sensible port set.
            #    -sT works without admin/root on Windows; -Pn skips ping (many
            #    test hosts don't respond to ping). Output stapled onto the
            #    analysis dict so ReportGeneratorAgent surfaces it under
            #    "Port scan / scan summary".
            try:
                nmap_ports = os.getenv("IDS_FORENSIC_NMAP_PORTS", "21,22,23,25,53,80,110,139,143,443,445,3389,8080,8443")
                nmap_flags = os.getenv("IDS_FORENSIC_NMAP_FLAGS", "-sT -sV")
                scan = client.nmap_scan(ip, scan_type=nmap_flags, ports=nmap_ports) or {}
                scan_stdout = scan.get("stdout") or scan.get("output") or ""
                open_lines = [ln for ln in scan_stdout.splitlines() if "/tcp" in ln and "open" in ln]
                analysis["nmap"] = {
                    "command_flags": nmap_flags,
                    "ports_probed": nmap_ports,
                    "return_code": scan.get("return_code"),
                    "success": scan.get("success"),
                    "stdout_tail": scan_stdout[-3000:],   # cap to keep reports bounded
                    "open_ports_summary": open_lines[:20],
                    "stderr_tail": (scan.get("stderr") or "")[-400:],
                }
                # Denormalise so the report's existing lookup keys resolve
                if open_lines:
                    analysis["port_scan_results"] = open_lines
                    analysis["open_services"] = open_lines
            except Exception as exc:
                logger.warning("nmap_scan failed for %s: %s", ip, exc)
                analysis["nmap"] = {"error": str(exc)}

            # 3. Reputation
            try:
                reputation = client.check_ip_reputation(ip) or {}
            except Exception as exc:
                reputation = {"error": f"reputation failed: {exc}"}

            # 4. Convenience: the decision engine already names preferred tools;
            #    copy that into recommended_tools_outputs so the report surfaces
            #    it even when we haven't executed those tools ourselves.
            target_profile = analysis.get("target_profile") or {}
            if isinstance(target_profile, dict):
                rec = target_profile.get("recommended_tools") or target_profile.get("tools")
                if rec and not analysis.get("recommended_tools_outputs"):
                    analysis["recommended_tools_outputs"] = rec

            return {
                "source": "HexStrike-AI (Deep Forensics)",
                "analysis": analysis,
                "reputation": reputation,
                "completed_at": datetime.datetime.utcnow().isoformat(),
            }
        except Exception as e:
            logger.error("HexStrike deep forensics failed: %s", e)
            return {"error": str(e)}


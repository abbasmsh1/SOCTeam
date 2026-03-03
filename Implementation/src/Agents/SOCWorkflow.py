"""
SOC Workflow using LangGraph to connect Tier1Analyst and Tier2Analyst.
This workflow orchestrates the escalation process from Tier 1 to Tier 2 analysis.
"""

from langgraph.graph import StateGraph, MessagesState, START, END
from langgraph.checkpoint.memory import MemorySaver
from typing import Dict, Any, Literal
import datetime
import uuid
try:
    from typing import TypedDict
except ImportError:
    from typing_extensions import TypedDict
from Implementation.src.Agents.LegacyCompat import Tier1Analyst, Tier2Analyst, Tier3Analyst
from Implementation.src.Agents.WarRoomWorkflow import WarRoomWorkflow

from Implementation.src.Agents.VectorMemoryManager import VectorMemoryManager
from Implementation.src.Agents.ReportGeneratorAgent import ReportGeneratorAgent
from Implementation.src.Agents.RemoteAgentClient import RemoteAgentClient
from Implementation.src.Agents.RemediationAgent import RemediationAgent
from Implementation.utils.Logger import setup_logger

logger = setup_logger(__name__)

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
    final_result: Dict[str, Any]


class SOCWorkflow:
    """
    SOC Workflow that orchestrates Tier 1, Tier 2, and Tier 3 analysis using LangGraph.
    """
    
    def __init__(self, api_key: str = None, agent_urls: Dict[str, str] = None):
        """
        Initialize the SOC workflow with Tier 1, Tier 2, and Tier 3 analysts.
        
        Args:
            api_key: Optional API key for LLM services
            agent_urls: Optional dictionary mapping agent roles to their microservice URLs.
                        Example: {"tier1": "http://localhost:6051", "tier2": "http://localhost:6052"}
        """
        agent_urls = agent_urls or {}
        
        self.tier1_analyst = RemoteAgentClient(agent_urls["tier1"]) if "tier1" in agent_urls else Tier1Analyst(api_key=api_key)
        self.tier2_analyst = RemoteAgentClient(agent_urls["tier2"]) if "tier2" in agent_urls else Tier2Analyst(api_key=api_key)
        self.tier3_analyst = RemoteAgentClient(agent_urls["tier3"]) if "tier3" in agent_urls else Tier3Analyst(api_key=api_key)
        self.war_room = RemoteAgentClient(agent_urls["warroom"]) if "warroom" in agent_urls else WarRoomWorkflow(api_key=api_key)
        self.memory = MemorySaver() if api_key else None
        self.kb_memory = VectorMemoryManager() # Initialize persistent Vector DB memory
        self.reporter = RemoteAgentClient(agent_urls["reporter"]) if "reporter" in agent_urls else ReportGeneratorAgent()
        self.remediation_executor = RemoteAgentClient(agent_urls["remediation"]) if "remediation" in agent_urls else RemediationAgent()
        
        
        # Use LangGraph only if we have an API key AND we are NOT running in microservices mode
        if api_key and not agent_urls:
            self.graph = self._create_graph()
            self.app = self.graph.compile()
        else:
            self.app = None
    
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
            "current_status": state.get("current_status", "Unknown")
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
        
        # Retrieve similar past incidents from memory
        alert_summary = f"{tier1_result.get('severity', '')} {str(state.get('alert_data', ''))}"
        similar_incidents = self.kb_memory.search_similar(alert_summary)
        
        input_data = {
            "tier1_output": tier1_result,
            "context_logs": state.get("context_logs", "No additional logs available."),
            "current_incidents": state.get("current_incidents", "No active incidents logged."),
            "similar_incidents": similar_incidents # Pass similar incidents to Tier 2
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
            "escalate_to_tier3": escalate_to_tier3
        }

    def _tier3_node(self, state: SOCWorkflowState) -> SOCWorkflowState:
        """Tier 3 analysis node."""
        tier1_result = state.get("tier1_result", {})
        tier2_result = state.get("tier2_result", {})
        
        input_data = {
            "tier1_output": tier1_result,
            "tier2_output": tier2_result
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
        alert_data = state.get("alert_data", {})
        
        # Get generated code from Blue Team if available
        blue_plan = war_room_result.get("blue_team_plan", {})
        generated_code = blue_plan.get("generated_defensive_code", {}).get("final_code", "")
        defense_plan = blue_plan.get("defense_plan", tier3_result.get("response_plan", ""))
        
        # Determine auto-pilot based on confidence
        # We look for IDS or Analyst confidence > 0.90
        t1_conf = float(tier1_result.get("ids_prediction", {}).get("confidence", 0.0) or 0.0)
        t2_conf = float(tier2_result.get("confidence", 0.0) or 0.0)
        max_confidence = max(t1_conf, t2_conf)
        
        input_data = {
            "threat_info": alert_data,
            "generated_code": generated_code,
            "defense_plan": defense_plan,
            "auto_pilot": max_confidence >= 0.90
        }
        
        remediation_result = self.remediation_executor.process(input_data)
        
        return {
            **state,
            "remediation_result": remediation_result
        }
    
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
            "war_room_triggered": triggered_war_room
        }
        
        if escalated and tier2_result:
            final_result["tier2_analysis"] = tier2_result
            final_result["final_severity"] = tier2_result.get("validated_severity", tier1_result.get("severity", "Unknown"))
            final_result["incident_classification"] = tier2_result.get("incident_classification", "N/A")
            final_result["recommended_actions"] = tier2_result.get("recommended_actions", "N/A")
            
            if escalated_tier3 and tier3_result:
                final_result["tier3_analysis"] = tier3_result
                final_result["response_plan"] = tier3_result.get("response_plan", "N/A")
                
                if triggered_war_room and war_room_result:
                    final_result["war_room_analysis"] = war_room_result
                    final_result["purple_team_report"] = war_room_result.get("purple_team_report", {}).get("analysis_report", "N/A")
            
            # Add remediation to results if it ran
            if remediation_result:
                final_result["remediation"] = remediation_result
        else:
            final_result["final_severity"] = tier1_result.get("severity", "Unknown")
            final_result["incident_classification"] = "Tier 1 Analysis Only"
            final_result["recommended_actions"] = tier1_result.get("triage_response", "N/A")
        
        # Save meaningful incidents to memory
        if escalated and tier2_result and final_result.get("incident_classification") == "Confirmed Incident":
             self.kb_memory.add_incident(final_result)

        # Generate Report
        print("DEBUG: Finalizing node - Generating report...")
        report_path = self.reporter.generate_report(final_result)
        final_result["report_path"] = report_path
        print(f"DEBUG: Report generated: {report_path}")
        logger.info(f"Workflow completed. Report generated at: {report_path}")

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
    
    def process(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process an alert through the SOC workflow.
        """
        print(f"\nSOCWorkflow: Processing alert for {input_data.get('alert_data', {}).get('Attack', 'Unknown')}")
        logger.info(f"Processing alert: {input_data.get('alert_data', {}).get('Attack', 'Unknown')}")
        # Initialize state
        initial_state: SOCWorkflowState = {
            "alert_data": input_data.get("alert_data", {}),
            "current_status": input_data.get("current_status", "Unknown"),
            "context_logs": input_data.get("context_logs", "No additional logs available."),
            "current_incidents": input_data.get("current_incidents", "No active incidents logged."),
            "tier1_result": {},
            "tier2_result": {},
            "tier3_result": {},
            "war_room_result": {},
            "escalate": False,
            "escalate_to_tier3": False,
            "trigger_war_room": False,
            "remediation_result": {},
            "final_result": {}
        }
        
        if self.app:
            try:
                # Use LangGraph to process the workflow
                thread_id = str(uuid.uuid4())
                config = {"configurable": {"thread_id": thread_id}}
                
                print(f"DEBUG: Invoking LangGraph app (thread: {thread_id})...")
                result = self.app.invoke(initial_state, config)
                print(f"DEBUG: App invoke complete. Keys in result: {result.keys()}")
                
                final_result = result.get("final_result", {})
                print(f"DEBUG: Final result report_path: {final_result.get('report_path')}")
                return final_result
            except Exception as e:
                return {
                    "error": f"Workflow execution failed: {e}",
                    "timestamp": datetime.datetime.utcnow().isoformat()
                }
        else:
            # Fallback: process without LangGraph (direct calls)
            logger.warning("Running in direct execution mode (no API key)...")
            state = initial_state
            
            # Tier 1
            print("DEBUG: Executing Tier 1 Node...")
            state = self._tier1_node(state)
            print(f"DEBUG: Tier 1 Complete. Severity: {state.get('tier1_result', {}).get('severity')}")
            
            # Check escalation
            if self._should_escalate(state) == "escalate":
                # Tier 2
                print("DEBUG: Escalating to Tier 2...")
                state = self._tier2_node(state)
                print("DEBUG: Tier 2 Complete.")
                
                # Check escalation to Tier 3
                if self._should_escalate_to_tier3(state) == "escalate_tier3":
                    # Tier 3
                    state = self._tier3_node(state)
                    
                    # Check War Room
                    if self._should_trigger_war_room(state) == "trigger_war_room":
                        state = self._war_room_node(state)
                    
                    # Manual path: Remediation
                    # If we have Tier 3 or War Room, we should remediate
                    if state.get("tier3_result") or state.get("war_room_result"):
                        print("DEBUG: Executing Remediation Node...")
                        state = self._remediation_node(state)
            
            # Finalize
            print("DEBUG: Finalizing Workflow...")
            state = self._finalize_node(state)
            print("DEBUG: Finalize Complete.")
            return state.get("final_result", {})


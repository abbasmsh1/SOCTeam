"""
War Room Workflow
=================
LangGraph state-machine that orchestrates a Red vs Blue exercise,
mediated by Purple Team analysis.

Flow:  Red Team  →  Blue Team  →  Purple Team (analysis)
"""

from Implementation.src.Agents.runtime_compat import StateGraph
from typing import Dict, Any, TypedDict, Optional
import logging

from Implementation.src.Agents.LegacyCompat import BlueTeamAgent, PurpleTeamAgent, RedTeamAgent
from Implementation.src.Agents.HexstrikeClient import HexstrikeClient

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# State schema
# ---------------------------------------------------------------------------

class WarRoomState(TypedDict):
    """Shared state structure flowing through the War Room graph."""
    incident_data: Dict[str, Any]
    red_output: Dict[str, Any]
    blue_output: Dict[str, Any]
    purple_report: Dict[str, Any]


# ---------------------------------------------------------------------------
# Workflow
# ---------------------------------------------------------------------------

class WarRoomWorkflow:
    """
    Coordinates a Red Team (Attack) vs Blue Team (Defense) exercise,
    with Purple Team as the final mediator/analyst.

    The execution order is sequential:
        1. Red Team simulates attack escalation.
        2. Blue Team proposes a defensive response.
        3. Purple Team synthesises both outputs into a lessons-learned report.
    """

    def __init__(self, api_key: str = None, hexstrike_url: Optional[str] = None):
        """
        Initialise agents and compile the LangGraph workflow.

        Args:
            api_key: Mistral API key for LLM inference
            hexstrike_url: Optional Hexstrike-AI MCP server URL
        """
        # Load hexstrike_url from config if not provided
        if not hexstrike_url:
            try:
                import os
                import json
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

        # Initialize Hexstrike client for real-time scanning
        try:
            self.hexstrike = HexstrikeClient(base_url=hexstrike_url)
            health = self.hexstrike.health_check()
            if health.get("status") == "healthy":
                logger.info(f"WarRoomWorkflow: Hexstrike-AI connected at {hexstrike_url}")
            else:
                logger.warning(f"WarRoomWorkflow: Hexstrike-AI unhealthy - {health.get('error')}")
                self.hexstrike = None
        except Exception as exc:
            logger.warning(f"WarRoomWorkflow: Hexstrike-AI unavailable - {exc}")
            self.hexstrike = None

        self.blue_agent = BlueTeamAgent(api_key=api_key, hexstrike_url=hexstrike_url)
        self.red_agent = RedTeamAgent(api_key=api_key, hexstrike_url=hexstrike_url)
        self.purple_agent = PurpleTeamAgent(api_key=api_key)

        self.graph = self._create_graph()
        self.app = self.graph.compile()

    # ── Graph construction ──────────────────────────────────────────────

    def _create_graph(self) -> StateGraph:
        """Build the Red → Blue → Purple state graph."""
        workflow = StateGraph(WarRoomState)

        workflow.add_node("red_team", self._red_node)
        workflow.add_node("blue_team", self._blue_node)
        workflow.add_node("purple_team", self._purple_node)

        # Entry point – compatible with both old and new LangGraph API
        try:
            workflow.set_entry_point("red_team")
        except AttributeError:
            workflow.add_edge("__start__", "red_team")

        # Sequential edges
        workflow.add_edge("red_team", "blue_team")
        workflow.add_edge("blue_team", "purple_team")

        # Finish point
        try:
            workflow.set_finish_point("purple_team")
        except AttributeError:
            workflow.add_edge("purple_team", "__end__")

        return workflow

    # ── Graph nodes ─────────────────────────────────────────────────────

    def _red_node(self, state: WarRoomState) -> WarRoomState:
        """
        Red Team node – simulates an attack based on the incident.

        If Hexstrike is available, performs real reconnaissance scans first.
        """
        incident = state["incident_data"]
        target = incident.get("target", incident.get("target_info", {}).get("target", ""))

        # Enhance Red Team with Hexstrike reconnaissance
        hexstrike_recon = {}
        if self.hexstrike and target:
            try:
                logger.info(f"War Room Red Team: Running Hexstrike recon on {target}")

                # Phase 1: AI-driven target analysis
                hexstrike_recon["ai_analysis"] = self.hexstrike.analyze_target(target, "comprehensive")

                # Phase 2: Port scanning
                hexstrike_recon["port_scan"] = self.hexstrike.rustscan_scan(target)

                # Phase 3: Subdomain enumeration (if domain)
                if "." in target and not target.replace(".", "").isdigit():
                    hexstrike_recon["subdomains"] = self.hexstrike.subfinder_enum(target)

                # Phase 4: Vulnerability scanning
                web_target = target if target.startswith("http") else f"http://{target}"
                hexstrike_recon["vuln_scan"] = self.hexstrike.nuclei_scan(
                    web_target,
                    severity="critical,high"
                )

                logger.info(f"War Room Red Team: Recon complete - found {len(hexstrike_recon)} data points")

            except Exception as exc:
                logger.warning(f"War Room Red Team Hexstrike recon failed: {exc}")
                hexstrike_recon["error"] = str(exc)

        # Build enhanced input for Red Team
        red_input = {"target_info": incident}
        if hexstrike_recon:
            red_input["hexstrike_reconnaissance"] = hexstrike_recon
            red_input["target_info"]["scan_results"] = hexstrike_recon

        red_result = self.red_agent.process(red_input)

        # Attach recon data to result for Blue Team to use
        if hexstrike_recon:
            red_result["hexstrike_reconnaissance"] = hexstrike_recon

        return {**state, "red_output": red_result}

    def _blue_node(self, state: WarRoomState) -> WarRoomState:
        """
        Blue Team node – defends against the incident and Red Team output.

        If Hexstrike is available, performs defensive security assessment.
        """
        incident = state["incident_data"]
        red_output = state.get("red_output", {})

        # Build Blue Team input
        blue_input = {
            "threat_info": incident,
            "system_state": (
                f"Under attack. Red Team Simulation: "
                f"{red_output.get('attack_plan', 'None')}"
            ),
        }

        # If Hexstrike is available, add security assessment
        if self.hexstrike and incident.get("target"):
            try:
                target = incident.get("target")
                logger.info(f"War Room Blue Team: Running defensive assessment on {target}")

                # Defensive vulnerability scan
                web_target = target if target.startswith("http") else f"http://{target}"
                blue_input["security_assessment"] = self.hexstrike.nuclei_scan(
                    web_target,
                    severity="critical,high,medium"
                )

                # Container security if applicable
                if incident.get("is_containerized"):
                    blue_input["container_assessment"] = self.hexstrike.trivy_scan(target, "image")

                logger.info(f"War Room Blue Team: Assessment complete")

            except Exception as exc:
                logger.warning(f"War Room Blue Team Hexstrike assessment failed: {exc}")
                blue_input["assessment_error"] = str(exc)

        blue_result = self.blue_agent.process(blue_input)
        return {**state, "blue_output": blue_result}

    def _purple_node(self, state: WarRoomState) -> WarRoomState:
        """Purple Team node – analyses Red/Blue outputs for lessons learned."""
        red_output = state.get("red_output", {})
        blue_output = state.get("blue_output", {})

        purple_result = self.purple_agent.analyze_exercise(red_output, blue_output)
        return {**state, "purple_report": purple_result}

    # ── Public API ──────────────────────────────────────────────────────

    def run_simulation(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute the full War Room simulation.

        Args:
            incident_data: Contextual data about the security incident.

        Returns:
            Combined outputs from Red, Blue, and Purple teams.
        """
        initial_state: WarRoomState = {
            "incident_data": incident_data,
            "red_output": {},
            "blue_output": {},
            "purple_report": {},
        }

        result = self.app.invoke(initial_state)

        return {
            "red_team_plan": result["red_output"],
            "blue_team_plan": result["blue_output"],
            "purple_team_report": result["purple_report"],
        }

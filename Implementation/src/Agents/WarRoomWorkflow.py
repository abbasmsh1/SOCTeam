from langgraph.graph import StateGraph, START, END
from typing import Dict, Any, TypedDict
from Implementation.src.Agents.LegacyCompat import BlueTeamAgent, RedTeamAgent
from Implementation.src.Agents.PurpleTeamAgent import PurpleTeamAgent
import os

class WarRoomState(TypedDict):
    incident_data: Dict[str, Any]
    red_output: Dict[str, Any]
    blue_output: Dict[str, Any]
    purple_report: Dict[str, Any]

class WarRoomWorkflow:
    """
    Workflow to coordinate Red Team (Attack) vs Blue Team (Defense) exercises,
    mediated by Purple Team.
    """

    def __init__(self, api_key: str = None):
        self.blue_agent = BlueTeamAgent(api_key=api_key)
        self.red_agent = RedTeamAgent(api_key=api_key)
        self.purple_agent = PurpleTeamAgent(api_key=api_key)
        self.graph = self._create_graph()
        self.app = self.graph.compile()

    def _create_graph(self) -> StateGraph:
        workflow = StateGraph(WarRoomState)

        # Parallel execution for Red and Blue is possible, but sequential is easier to manage for now
        # Let's have Red attack first, then Blue defend (reactive), or vice versa.
        # Scenario: Incident detected -> Red simulates escalation -> Blue proposes defense -> Purple analyzes.
        
        workflow.add_node("red_team", self._red_node)
        workflow.add_node("blue_team", self._blue_node)
        workflow.add_node("purple_team", self._purple_node)

        # Define entry point
        try:
            workflow.set_entry_point("red_team")
        except:
            workflow.add_edge("__start__", "red_team")
            
        workflow.add_edge("red_team", "blue_team")
        workflow.add_edge("blue_team", "purple_team")
        
        # Define finish point
        try:
            workflow.set_finish_point("purple_team")
        except:
            workflow.add_edge("purple_team", "__end__")

        return workflow

    def _red_node(self, state: WarRoomState) -> WarRoomState:
        incident = state["incident_data"]
        # Red team simulates an attack based on the incident details
        red_result = self.red_agent.process({"target_info": incident})
        return {**state, "red_output": red_result}

    def _blue_node(self, state: WarRoomState) -> WarRoomState:
        incident = state["incident_data"]
        red_output = state.get("red_output", {})
        
        # Blue team defends against the incident AND the simulated Red Team escalation
        blue_input = {
            "threat_info": incident,
            "system_state": f"Under attack. Red Team Simulation: {red_output.get('attack_plan', 'None')}"
        }
        blue_result = self.blue_agent.process(blue_input)
        return {**state, "blue_output": blue_result}

    def _purple_node(self, state: WarRoomState) -> WarRoomState:
        red_output = state.get("red_output", {})
        blue_output = state.get("blue_output", {})
        
        purple_result = self.purple_agent.analyze_exercise(red_output, blue_output)
        return {**state, "purple_report": purple_result}

    def run_simulation(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run the War Room simulation.
        """
        initial_state: WarRoomState = {
            "incident_data": incident_data,
            "red_output": {},
            "blue_output": {},
            "purple_report": {}
        }

        result = self.app.invoke(initial_state)
        
        return {
            "red_team_plan": result["red_output"],
            "blue_team_plan": result["blue_output"],
            "purple_team_report": result["purple_report"]
        }

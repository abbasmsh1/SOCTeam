from langchain_mistralai import ChatMistralAI
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import StateGraph, MessagesState, START, END
from typing import Dict, Any
import os
import json
import uuid
import datetime

# Load configuration
try:
    config_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), 'config.json')
    with open(config_path, 'r') as f:
        config = json.load(f)
except Exception as e:
    print(f"Warning: Config load failed: {e}")
    config = {}

class PurpleTeamAgent:
    """
    Purple Team Agent (Coordinator/Optimizer).
    Coordinates Red/Blue exercises and analyzes results to improve security posture.
    """

    def __init__(self, api_key: str = None):
        from dotenv import load_dotenv
        load_dotenv()
        
        api_key = api_key or os.getenv('MISTRAL_API_KEY')
        self.llm = ChatMistralAI(
            model=config.get('Model', 'mistral-large-latest'),
            api_key=api_key,
            temperature=0.2,
            timeout=60,
        ) if api_key else None

        self.memory = MemorySaver() if api_key else None

        if api_key:
            self.graph = self._create_graph()
            self.app = self.graph.compile(checkpointer=self.memory)
        else:
            self.app = None

    def _create_graph(self) -> StateGraph:
        workflow = StateGraph(MessagesState)
        workflow.add_node("coordinator", self._call_model)
        try:
            workflow.set_entry_point("coordinator")
        except:
            workflow.add_edge("__start__", "coordinator")
        try:
            workflow.set_finish_point("coordinator")
        except:
            workflow.add_edge("coordinator", "__end__")
        return workflow

    def _call_model(self, state: MessagesState):
        if not self.llm:
            return {"messages": []}

        last_message = state["messages"][-1].content
        system_msg = """You are the Purple Team Lead (Coordinator).
        Your goal is to maximize the effectiveness of the security posture by coordinating Red (Attack) and Blue (Defense) teams.
        
        Capabilities:
        1. Analyze the outcome of Red vs Blue exercises.
        2. Identify gaps where Blue failed to stop Red.
        3. Identify gaps where Red failed to find vulnerabilities.
        4. Generate "Lessons Learned" and actionable recommendations.
        """

        messages = [
            {"role": "system", "content": system_msg},
            {"role": "user", "content": last_message}
        ]
        response = self.llm.invoke(messages)
        from langchain_core.messages import AIMessage
        return {"messages": [AIMessage(content=getattr(response, 'content', str(response)))]}

    def analyze_exercise(self, red_output: Dict[str, Any], blue_output: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze the results of a Red/Blue exercise.
        """
        prompt = f"""Analyze this War Game Exercise:
        
        Red Team (Attacker) Plan & Output:
        {json.dumps(red_output, indent=2)}
        
        Blue Team (Defender) Plan & Output:
        {json.dumps(blue_output, indent=2)}
        
        Provide a comprehensive report:
        1. Who won? (Did the attack succeed?)
        2. What were the key vulnerabilities?
        3. How effective were the defenses?
        4. Recommendations for improvement."""

        report = "LLM disabled."
        
        if self.app:
            try:
                thread_id = str(uuid.uuid4())
                config = {"configurable": {"thread_id": thread_id}}
                result = None
                for event in self.app.stream({"messages": [{"role": "user", "content": prompt}]},
                                             config, stream_mode="values"):
                    result = event.get("messages", [])
                report = result[-1].content if result else ""
            
            except Exception as e:
                report = f"Error in Purple Team processing: {e}"

        return {
            "analysis_report": report,
            "timestamp": datetime.datetime.utcnow().isoformat()
        }

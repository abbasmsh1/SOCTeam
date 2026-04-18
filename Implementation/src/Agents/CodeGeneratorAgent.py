try:
    from langchain_mistralai import ChatMistralAI
    from langgraph.checkpoint.memory import MemorySaver
    from langgraph.graph import StateGraph, MessagesState, START, END
    from langgraph.prebuilt import ToolNode, tools_condition
except ImportError:
    from .runtime_compat import ChatMistralAI, MemorySaver, StateGraph, MessagesState, START, END, ToolNode, tools_condition

try:
    from .HexstrikeClient import HexstrikeClient
    from .HexstrikeTools import get_hexstrike_tools
except (ImportError, ValueError):
    from HexstrikeClient import HexstrikeClient
    from HexstrikeTools import get_hexstrike_tools
from typing import Dict, Any
import os
import json
import uuid

# Load configuration
try:
    config_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), 'config.json')
    with open(config_path, 'r') as f:
        config = json.load(f)
except Exception as e:
    print(f"Warning: Config load failed: {e}")
    config = {}

class CodeGeneratorAgent:
    """
    Agent specialized in generating secure code based on requirements.
    """

    def __init__(self, api_key: str = None):
        from dotenv import load_dotenv
        load_dotenv()
        
        api_key = api_key or os.getenv('MISTRAL_API_KEY')
        
        try:
            import agentlightning as agl
            agl.setup_logging(apply_to=[__name__])
            self.tracer = agl.AgentOpsTracer()
        except ImportError:
            self.tracer = None

        try:
            self.hexstrike = HexstrikeClient(base_url=config.get('hexstrike_url', 'http://localhost:8888'))
            self.tools = get_hexstrike_tools(self.hexstrike)
        except Exception:
            self.hexstrike = None
            self.tools = []

        self.llm = ChatMistralAI(
            model=config.get('Model', 'mistral-large-latest'),
            api_key=api_key,
            temperature=0.2, # Lower temperature for code generation
            timeout=60,
        ) if api_key else None

        self.memory = MemorySaver() if api_key else None

        if api_key and self.tools:
            self.llm = getattr(self.llm, 'bind_tools', lambda x: self.llm)(self.tools)

        if api_key:
            self.graph = self._create_graph()
            self.app = self.graph.compile(checkpointer=self.memory)
        else:
            self.app = None

    def _create_graph(self) -> StateGraph:
        workflow = StateGraph(MessagesState)
        workflow.add_node("generator", self._call_model)
        try:
            workflow.set_entry_point("generator")
        except:
            workflow.add_edge("__start__", "generator")
        try:
            workflow.add_node("tools", ToolNode(self.tools))
        workflow.add_conditional_edges("generator", tools_condition)
        workflow.add_edge("tools", "generator")
        except:
            workflow.add_node("tools", ToolNode(self.tools))
        workflow.add_conditional_edges("generator", tools_condition)
        workflow.add_edge("tools", "generator")
        return workflow

    def _call_model(self, state: MessagesState):
        if not self.llm:
            return {"messages": []}

        last_message = state["messages"][-1].content
        system_msg = """You are a Senior Secure Code Developer. 
        Your goal is to generate Python or Shell code that meets the user's requirements while strictly adhering to secure coding practices.
        
        Guidelines:
        1. Input Validation: Always validate inputs.
        2. Error Handling: Implement robust error handling.
        3. Least Privilege: Code should assume minimal privileges.
        4. No Hardcoding: Do not hardcode credentials or sensitive data.
        5. Clarity: Write clean, commented code.
        
        Output Format:
        Return ONLY the code block wrapped in markdown backticks (e.g., ```python ... ```). 
        Do not add conversational filler before or after the code.
        """

        messages = [
            {"role": "system", "content": system_msg},
            {"role": "user", "content": last_message}
        ]
        response = self.llm.invoke(messages)
        from langchain_core.messages import AIMessage
        return {"messages": [AIMessage(content=getattr(response, 'content', str(response)))]}

    def generate_code(self, requirements: str, context: str = "") -> Dict[str, Any]:
        """
        Generate code based on requirements.
        """
        prompt = f"""Requirements: {requirements}
        Context: {context}
        
        Generate the secure code implementation."""

        generated_code = "LLM disabled or API key missing."
        if self.app:
            try:
                thread_id = str(uuid.uuid4())
                config = {"configurable": {"thread_id": thread_id}}
                result = None
                for event in self.app.stream({"messages": [{"role": "user", "content": prompt}]},
                                             config, stream_mode="values"):
                    result = event.get("messages", [])
                generated_code = result[-1].content if result else ""
            except Exception as e:
                generated_code = f"Error generating code: {e}"

        return {
            "generated_code": generated_code,
            "requirements": requirements
        }

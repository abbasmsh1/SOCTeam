from langchain_mistralai import ChatMistralAI
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import StateGraph, MessagesState, START, END
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

class CodeReviewAgent:
    """
    Agent specialized in auditing code for security flaws and logic errors.
    """

    def __init__(self, api_key: str = None):
        from dotenv import load_dotenv
        load_dotenv()
        
        api_key = api_key or os.getenv('MISTRAL_API_KEY')
        self.llm = ChatMistralAI(
            model=config.get('Model', 'mistral-large-latest'),
            api_key=api_key,
            temperature=0.1, # Low temperature for analytical tasks
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
        workflow.add_node("reviewer", self._call_model)
        try:
            workflow.set_entry_point("reviewer")
        except:
            workflow.add_edge("__start__", "reviewer")
        try:
            workflow.set_finish_point("reviewer")
        except:
            workflow.add_edge("reviewer", "__end__")
        return workflow

    def _call_model(self, state: MessagesState):
        if not self.llm:
            return {"messages": []}

        last_message = state["messages"][-1].content
        system_msg = """You are a Senior Security Auditor. 
        Your goal is to review the provided code for security vulnerabilities, logic errors, and adherence to best practices.
        
        Review Criteria:
        1. Security: Check for injection flaws, hardcoded secrets, insecure configurations, etc.
        2. Logic: Ensure the code does what it claims to do.
        3. Efficiency: Check for obvious performance bottlenecks.
        
        Output Format:
        Return a JSON object with the following structure:
        {
            "status": "APPROVED" | "REJECTED",
            "comments": "Detailed feedback explaining the decision.",
            "security_risks": ["List", "of", "risks"],
            "suggestions": "Specific code improvements."
        }
        """

        messages = [
            {"role": "system", "content": system_msg},
            {"role": "user", "content": last_message}
        ]
        response = self.llm.invoke(messages)
        from langchain_core.messages import AIMessage
        return {"messages": [AIMessage(content=getattr(response, 'content', str(response)))]}

    def review_code(self, code: str, requirements: str = "") -> Dict[str, Any]:
        """
        Review code against requirements.
        """
        prompt = f"""Requirements: {requirements}
        
        Code to Review:
        {code}
        
        Perform the security review."""

        review_result = {"status": "ERROR", "comments": "LLM disabled or API key missing."}
        if self.app:
            try:
                thread_id = str(uuid.uuid4())
                config = {"configurable": {"thread_id": thread_id}}
                result = None
                for event in self.app.stream({"messages": [{"role": "user", "content": prompt}]},
                                             config, stream_mode="values"):
                    result = event.get("messages", [])
                
                raw_response = result[-1].content if result else "{}"
                
                # Attempt to parse JSON from response
                try:
                    # Clean up markdown code blocks if present
                    cleaned_response = raw_response.strip()
                    if cleaned_response.startswith("```json"):
                        cleaned_response = cleaned_response[7:]
                    if cleaned_response.endswith("```"):
                        cleaned_response = cleaned_response[:-3]
                    
                    review_result = json.loads(cleaned_response)
                except json.JSONDecodeError:
                    review_result = {
                        "status": "REJECTED", 
                        "comments": f"Failed to parse reviewer response. Raw output: {raw_response}",
                        "security_risks": ["Parse Error"]
                    }

            except Exception as e:
                review_result = {"status": "ERROR", "comments": f"Error during review: {e}"}

        return review_result

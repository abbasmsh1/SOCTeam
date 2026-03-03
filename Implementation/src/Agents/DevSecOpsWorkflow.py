"""
Optimized DevSecOps Workflow
Inlines code generation and review logic to reduce overhead.
"""

from langgraph.graph import StateGraph, START, END
from langchain_mistralai import ChatMistralAI
from typing import Dict, Any, TypedDict
import os
import json
import uuid
import logging
from dotenv import load_dotenv

logger = logging.getLogger(__name__)

# Load environment
load_dotenv()

# Load configuration
try:
    config_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), 'config.json')
    with open(config_path, 'r') as f:
        config = json.load(f)
except Exception as e:
    logger.warning(f"Config load failed: {e}")
    config = {}


class DevSecOpsState(TypedDict):
    """DevSecOps workflow state."""
    requirements: str
    context: str
    generated_code: str
    review_feedback: Dict[str, Any]
    iteration_count: int
    max_iterations: int
    final_status: str


class DevSecOpsWorkflow:
    """
    Streamlined DevSecOps workflow with inline code generation and review.
    Reduces overhead by eliminating separate agent classes.
    """

    def __init__(self, api_key: str = None):
        """Initialize DevSecOps workflow."""
        self.api_key = api_key or os.getenv('MISTRAL_API_KEY')
        
        # Initialize LLMs
        if self.api_key:
            self.llm_generator = ChatMistralAI(
                model=config.get('Model', 'mistral-large-latest'),
                api_key=self.api_key,
                temperature=0.2,  # Low for code generation
                timeout=60,
            )
            self.llm_reviewer = ChatMistralAI(
                model=config.get('Model', 'mistral-large-latest'),
                api_key=self.api_key,
                temperature=0.1,  # Very low for analysis
                timeout=60,
            )
        else:
            self.llm_generator = None
            self.llm_reviewer = None
        
        self.graph = self._create_graph()
        self.app = self.graph.compile()

    def _create_graph(self) -> StateGraph:
        """Create workflow graph."""
        workflow = StateGraph(DevSecOpsState)

        workflow.add_node("generate", self._generate_node)
        workflow.add_node("review", self._review_node)

        workflow.add_edge(START, "generate")
        workflow.add_edge("generate", "review")
        
        workflow.add_conditional_edges(
            "review",
            self._check_approval,
            {
                "approved": END,
                "rejected": "generate",
                "max_retries": END
            }
        )

        return workflow

    def _generate_code(self, requirements: str, context: str = "") -> str:
        """Generate code based on requirements."""
        if not self.llm_generator:
            return "LLM disabled or API key missing."
        
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
        
        user_msg = f"""Requirements: {requirements}
        Context: {context}
        
        Generate the secure code implementation."""
        
        try:
            messages = [
                {"role": "system", "content": system_msg},
                {"role": "user", "content": user_msg}
            ]
            response = self.llm_generator.invoke(messages)
            return getattr(response, 'content', str(response))
        except Exception as e:
            logger.error(f"Code generation error: {e}")
            return f"Error generating code: {e}"

    def _review_code(self, code: str, requirements: str = "") -> Dict[str, Any]:
        """Review code for security and quality."""
        if not self.llm_reviewer:
            return {"status": "ERROR", "comments": "LLM disabled or API key missing."}
        
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
        
        user_msg = f"""Requirements: {requirements}
        
        Code to Review:
        {code}
        
        Perform the security review."""
        
        try:
            messages = [
                {"role": "system", "content": system_msg},
                {"role": "user", "content": user_msg}
            ]
            response = self.llm_reviewer.invoke(messages)
            raw_response = getattr(response, 'content', str(response))
            
            # Parse JSON response
            try:
                cleaned_response = raw_response.strip()
                if cleaned_response.startswith("```json"):
                    cleaned_response = cleaned_response[7:]
                if cleaned_response.endswith("```"):
                    cleaned_response = cleaned_response[:-3]
                
                return json.loads(cleaned_response.strip())
            except json.JSONDecodeError:
                return {
                    "status": "REJECTED",
                    "comments": f"Failed to parse reviewer response. Raw output: {raw_response}",
                    "security_risks": ["Parse Error"]
                }
        except Exception as e:
            logger.error(f"Code review error: {e}")
            return {"status": "ERROR", "comments": f"Error during review: {e}"}

    def _generate_node(self, state: DevSecOpsState) -> DevSecOpsState:
        """Generate code node."""
        requirements = state["requirements"]
        context = state.get("context", "")
        feedback = state.get("review_feedback", {})
        iteration = state.get("iteration_count", 0)

        # Append feedback to context for iteration
        if feedback and feedback.get("status") == "REJECTED":
            context += f"\n\nPrevious Attempt Feedback:\n{feedback.get('comments')}\nSecurity Risks: {feedback.get('security_risks')}"

        generated_code = self._generate_code(requirements, context)
        
        return {
            **state,
            "generated_code": generated_code,
            "iteration_count": iteration + 1
        }

    def _review_node(self, state: DevSecOpsState) -> DevSecOpsState:
        """Review code node."""
        code = state["generated_code"]
        requirements = state["requirements"]
        
        review_result = self._review_code(code, requirements)
        
        return {
            **state,
            "review_feedback": review_result,
            "final_status": review_result.get("status", "UNKNOWN")
        }

    def _check_approval(self, state: DevSecOpsState) -> str:
        """Check if code is approved or needs iteration."""
        status = state.get("final_status")
        iteration = state.get("iteration_count", 0)
        max_iterations = state.get("max_iterations", 3)

        if status == "APPROVED":
            return "approved"
        elif iteration >= max_iterations:
            return "max_retries"
        else:
            return "rejected"

    def run(self, requirements: str, context: str = "", max_iterations: int = 3) -> Dict[str, Any]:
        """
        Run the DevSecOps workflow.
        
        Args:
            requirements: Code requirements
            context: Additional context
            max_iterations: Maximum iteration count
            
        Returns:
            Workflow result with final code and review
        """
        initial_state: DevSecOpsState = {
            "requirements": requirements,
            "context": context,
            "generated_code": "",
            "review_feedback": {},
            "iteration_count": 0,
            "max_iterations": max_iterations,
            "final_status": "PENDING"
        }

        try:
            result = self.app.invoke(initial_state)
            
            return {
                "final_code": result["generated_code"],
                "status": result["final_status"],
                "iterations": result["iteration_count"],
                "review_feedback": result["review_feedback"]
            }
        except Exception as e:
            logger.error(f"DevSecOps workflow error: {e}")
            return {
                "final_code": "",
                "status": "ERROR",
                "iterations": 0,
                "review_feedback": {"comments": f"Workflow error: {e}"}
            }

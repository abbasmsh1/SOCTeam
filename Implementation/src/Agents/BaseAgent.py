"""
Base Agent Class
Provides shared functionality for all SOC Team agents, reducing code duplication.
"""

from langchain_mistralai import ChatMistralAI
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import StateGraph, START, END
from typing import Dict, Any, Optional, TypedDict, Annotated, Sequence
import os
import json
import uuid
import logging
import operator
from dotenv import load_dotenv

logger = logging.getLogger(__name__)


class AgentConfig:
    """Centralized configuration management for agents."""
    
    _config_cache: Optional[Dict[str, Any]] = None
    
    @classmethod
    def load_config(cls) -> Dict[str, Any]:
        """Load configuration from config.json with caching."""
        if cls._config_cache is not None:
            return cls._config_cache
        
        try:
            config_path = os.path.join(
                os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                'config.json'
            )
            with open(config_path, 'r') as f:
                cls._config_cache = json.load(f)
                logger.debug(f"Configuration loaded from {config_path}")
                return cls._config_cache
        except Exception as e:
            logger.warning(f"Config load failed: {e}. Using defaults.")
            cls._config_cache = {}
            return cls._config_cache
    
    @classmethod
    def get(cls, key: str, default: Any = None) -> Any:
        """Get configuration value with default."""
        config = cls.load_config()
        return config.get(key, default)
    
    @classmethod
    def clear_cache(cls):
        """Clear configuration cache (useful for testing)."""
        cls._config_cache = None


class AgentState(TypedDict):
    """Explicit state definition for LangGraph 0.0.x compatibility."""
    messages: Annotated[Sequence[Any], operator.add]


class BaseAgent:
    """
    Base class for all SOC Team agents.
    Provides common initialization, LLM setup, and graph management.
    """
    
    def __init__(
        self,
        agent_name: str,
        temperature: float = 0.3,
        api_key: Optional[str] = None,
        hexstrike_url: Optional[str] = None,
        enable_hexstrike: bool = False
    ):
        """
        Initialize base agent.
        
        Args:
            agent_name: Name of the agent (for logging)
            temperature: LLM temperature setting
            api_key: Mistral API key (falls back to env var)
            hexstrike_url: Hexstrike-AI MCP server URL
            enable_hexstrike: Whether to initialize Hexstrike client
        """
        # Load environment variables
        load_dotenv()
        
        self.agent_name = agent_name
        self.config = AgentConfig.load_config()
        
        # Initialize API key
        self.api_key = api_key or os.getenv('MISTRAL_API_KEY')
        
        # Initialize LLM
        self.llm = self._initialize_llm(temperature) if self.api_key else None
        
        # Initialize memory
        self.memory = MemorySaver() if self.api_key else None
        
        # Initialize Hexstrike client if requested
        self.hexstrike = None
        if enable_hexstrike:
            self._initialize_hexstrike(hexstrike_url)
        
        # Initialize graph and app (subclasses should implement _create_graph)
        if self.api_key:
            try:
                self.graph = self._create_graph()
                self.app = self.graph.compile(checkpointer=self.memory)
                logger.info(f"{self.agent_name} initialized successfully")
            except Exception as e:
                logger.error(f"Failed to initialize {self.agent_name}: {e}")
                self.graph = None
                self.app = None
        else:
            logger.warning(f"{self.agent_name} initialized without API key")
            self.graph = None
            self.app = None
    
    def _initialize_llm(self, temperature: float) -> ChatMistralAI:
        """Initialize the LLM with configuration."""
        return ChatMistralAI(
            model=self.config.get('Model', 'mistral-large-latest'),
            api_key=self.api_key,
            temperature=temperature,
            timeout=60,
        )
    
    def _initialize_hexstrike(self, hexstrike_url: Optional[str] = None):
        """Initialize Hexstrike-AI MCP client."""
        try:
            from Implementation.src.Agents.HexstrikeClient import HexstrikeClient
            
            url = hexstrike_url or self.config.get('hexstrike_url', 'http://localhost:8888')
            self.hexstrike = HexstrikeClient(base_url=url)
            
            # Health check
            health = self.hexstrike.health_check()
            if health.get('status') == 'healthy':
                logger.info(f"{self.agent_name}: Hexstrike-AI MCP server connected")
            else:
                logger.warning(f"{self.agent_name}: Hexstrike-AI server unhealthy - {health.get('error')}")
                self.hexstrike = None
        except Exception as e:
            logger.warning(f"{self.agent_name}: Failed to connect to Hexstrike-AI - {e}")
            self.hexstrike = None
    
    def _create_graph(self) -> StateGraph:
        """
        Create the agent's workflow graph.
        Must be implemented by subclasses.
        """
        raise NotImplementedError("Subclasses must implement _create_graph()")
    
    def _call_model(self, state: Dict[str, Any], system_message: str) -> Dict[str, Any]:
        """
        Standard LLM invocation pattern.
        
        Args:
            state: Current message state
            system_message: System prompt for the agent
            
        Returns:
            Updated state with AI response
        """
        if not self.llm:
            logger.warning(f"{self.agent_name}: LLM not available")
            return {"messages": []}
        
        try:
            try:
                msg = state["messages"][-1]
                if hasattr(msg, "content"):
                    last_message = msg.content
                elif isinstance(msg, dict):
                    last_message = msg.get("content", str(msg))
                else:
                    last_message = str(msg)
            except (KeyError, IndexError):
                last_message = "No input provided."
            
            messages = [
                {"role": "system", "content": system_message},
                {"role": "user", "content": last_message}
            ]
            
            response = self.llm.invoke(messages)
            
            from langchain_core.messages import AIMessage
            # Handle response robustly
            if hasattr(response, 'content'):
                content = response.content
            elif isinstance(response, dict):
                content = response.get('content', str(response))
            else:
                content = str(response)
                
            return {"messages": [AIMessage(content=content)]}
        
        except Exception as e:
            logger.error(f"{self.agent_name}: Error calling model - {e}")
            from langchain_core.messages import AIMessage
            return {"messages": [AIMessage(content=f"Error: {e}")]}
    
    def _stream_with_config(self, prompt: str, timeout_override: Optional[int] = None) -> Optional[str]:
        """
        Standard streaming pattern for agent processing.
        
        Args:
            prompt: User prompt
            timeout_override: Optional timeout override
            
        Returns:
            Final AI response content or None
        """
        if not self.app:
            logger.error(f"{self.agent_name}: App not initialized")
            return None
        
        try:
            thread_id = str(uuid.uuid4())
            config = {"configurable": {"thread_id": thread_id}}
            
            # Try using graph processing
            if self.app:
                try:
                    result = self.app.invoke(
                        {"messages": [{"role": "user", "content": prompt}]},
                        config
                    )
                    messages = result.get("messages", [])
                    if messages:
                        msg = messages[-1]
                        if hasattr(msg, "content"):
                            return msg.content
                        elif isinstance(msg, dict):
                            return msg.get("content", str(msg))
                        return str(msg)
                except (KeyError, Exception) as graph_err:
                    logger.warning(f"{self.agent_name}: Graph execution failed ({graph_err}). Falling back to direct LLM call.")
            
            # Fallback: Direct LLM call if graph fails or is not initialized
            if self.llm:
                messages = [
                    {"role": "system", "content": "You are a helpful SOC Analyst agent."},
                    {"role": "user", "content": prompt}
                ]
                response = self.llm.invoke(messages)
                if hasattr(response, 'content'):
                    return response.content
                elif isinstance(response, dict):
                    return response.get('content', str(response))
                return str(response)
                
            return None
        
        except Exception as e:
            logger.error(f"{self.agent_name}: Error during processing - {e}")
            return None
    
    def is_ready(self) -> bool:
        """Check if agent is ready to process requests."""
        return self.llm is not None and self.app is not None
    
    def _extract_json_block(self, text: str) -> Optional[Dict[str, Any]]:
        """
        Robustly extract a JSON object from text, handling markdown fences and chatter.
        """
        import re
        import json
        
        # 1. Look for ```json ... ``` or ``` ... ```
        json_pattern = r"```(?:json)?\s*(\{.*?\})\s*```"
        match = re.search(json_pattern, text, re.DOTALL)
        
        if not match:
            # 2. Look for FIRST { and LAST }
            start = text.find('{')
            end = text.rfind('}')
            if start != -1 and end != -1:
                json_str = text[start:end+1]
            else:
                return None
        else:
            json_str = match.group(1)
            
        try:
            return json.loads(json_str)
        except json.JSONDecodeError:
            # Last ditch effort: try to clean single/double quotes or common LLM artifacts
            try:
                # Basic cleaning for mismatched quotes if any
                cleaned = json_str.replace("'", '"')
                return json.loads(cleaned)
            except:
                return None

    def get_status(self) -> Dict[str, Any]:
        """Get agent status information."""
        return {
            "agent_name": self.agent_name,
            "llm_available": self.llm is not None,
            "app_available": self.app is not None,
            "hexstrike_available": self.hexstrike is not None,
            "ready": self.is_ready()
        }

"""
Base agent utilities shared across the SOC system.
"""

from __future__ import annotations

import json
import logging
import operator
import os
import re
import uuid
from typing import Annotated, Any, Dict, Optional, Sequence, TypedDict

from dotenv import load_dotenv

try:
    from .AgentTools import get_agent_tools
    from .DefensiveActionSandbox import DefensiveActionSandbox
    from .runtime_compat import AIMessage, ChatOpenAI, MemorySaver, StateGraph
except (ImportError, ValueError):
    from AgentTools import get_agent_tools
    from DefensiveActionSandbox import DefensiveActionSandbox
    from runtime_compat import AIMessage, ChatOpenAI, MemorySaver, StateGraph

# Local database manager
try:
    from ..Database.FlowHistoryManager import FlowHistoryManager
except (ImportError, ValueError):
    try:
        from Database.FlowHistoryManager import FlowHistoryManager
    except ImportError:
        try:
            from FlowHistoryManager import FlowHistoryManager
        except ImportError:
            # Create a mock if it absolutely cannot be found
            class FlowHistoryManager:
                def __init__(self, *args, **kwargs): pass
                def log_flow(self, *args, **kwargs): pass
                def get_history(self, *args, **kwargs): return []

logger = logging.getLogger(__name__)


class AgentConfig:
    """Cached configuration loader for agent settings."""

    _config_cache: Optional[Dict[str, Any]] = None

    @classmethod
    def load_config(cls) -> Dict[str, Any]:
        if cls._config_cache is not None:
            return cls._config_cache

        try:
            config_path = os.path.join(
                os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                "config.json",
            )
            with open(config_path, "r", encoding="utf-8") as fh:
                cls._config_cache = json.load(fh)
        except (FileNotFoundError, json.JSONDecodeError) as exc:
            logger.warning("Config load failed: %s. Using defaults.", exc)
            cls._config_cache = {}
        return cls._config_cache

    @classmethod
    def get(cls, key: str, default: Any = None) -> Any:
        return cls.load_config().get(key, default)

    @classmethod
    def clear_cache(cls) -> None:
        cls._config_cache = None


class AgentState(TypedDict):
    """Shared LangGraph-compatible state structure."""

    messages: Annotated[Sequence[Any], operator.add]


class BaseAgent:
    """Common runtime for all SOC agents."""

    def __init__(
        self,
        agent_name: str,
        temperature: float = 0.3,
        api_key: Optional[str] = None,
        hexstrike_url: Optional[str] = None,
        enable_hexstrike: bool = False,
    ) -> None:
        load_dotenv()

        self.agent_name = agent_name
        self.config = AgentConfig.load_config()
        self.api_key = api_key or os.getenv("RAGARENN_API_KEY")
        self.hexstrike = None
        self.tools = []
        self.tool_map: Dict[str, Any] = {}
        self.sandbox = DefensiveActionSandbox()
        self.flow_history = FlowHistoryManager()
        
        # Initialize IP Blocking Manager for Tier 2 and 3 agents
        try:
            try:
                from .IPBlockingManager import IPBlockingManager
            except (ImportError, ValueError):
                from IPBlockingManager import IPBlockingManager
            self.ip_blocking_mgr = IPBlockingManager()
        except Exception as exc:
            logger.warning("%s: Failed to initialize IPBlockingManager: %s", agent_name, exc)
            self.ip_blocking_mgr = None
        
        self.tracer = None

        try:
            import agentlightning as agl

            agl.setup_logging(apply_to=[__name__])
            self.tracer = agl.AgentOpsTracer()
        except ImportError:
            logger.debug("%s: agentlightning not available (optional tracer)", self.agent_name)

        self.llm = self._initialize_llm(temperature) if self.api_key else None
        self.memory = MemorySaver() if self.api_key else None

        try:
            try:
                from .HexstrikeClient import HexstrikeClient
                from .HexstrikeTools import get_hexstrike_tools
            except (ImportError, ValueError):
                from HexstrikeClient import HexstrikeClient
                from HexstrikeTools import get_hexstrike_tools

            url = hexstrike_url or self.config.get("hexstrike_url", "http://localhost:8888")
            self.hexstrike = HexstrikeClient(base_url=url)
            self.tools.extend(get_hexstrike_tools(self.hexstrike))
        except Exception as exc:
            logger.warning("Failed to load hexstrike tools: %s", exc)

        if enable_hexstrike:
            self._initialize_hexstrike(hexstrike_url)

        self.tools.extend(
            get_agent_tools(
                agent_name=self.agent_name,
                sandbox=self.sandbox,
                flow_history=self.flow_history,
                ip_blocking_mgr=self.ip_blocking_mgr,
            )
        )
        self.tool_map = {tool.name: tool for tool in self.tools}

        if self.tools and self.llm and hasattr(self.llm, "bind_tools"):
            try:
                self.llm = self.llm.bind_tools(self.tools)
            except Exception as exc:
                logger.warning("%s: Failed to bind tools: %s", self.agent_name, exc)

        if self.api_key:
            try:
                self.graph = self._create_graph()
                self.app = self.graph.compile(checkpointer=self.memory)
            except Exception as exc:
                logger.error("Failed to initialise %s: %s", self.agent_name, exc)
                self.graph = None
                self.app = None
        else:
            self.graph = None
            self.app = None

    def _initialize_llm(self, temperature: float) -> Any:
        callbacks = []
        if getattr(self, "tracer", None) and hasattr(self.tracer, "get_langchain_handler"):
            handler = self.tracer.get_langchain_handler()
            if handler:
                callbacks.append(handler)

        try:
            from .LLMClient import build_llm
        except (ImportError, ValueError):
            from LLMClient import build_llm  # type: ignore

        return build_llm(
            temperature=temperature,
            api_key=self.api_key,
            callbacks=callbacks,
        )

    def _initialize_hexstrike(self, hexstrike_url: Optional[str] = None) -> None:
        try:
            from .HexstrikeClient import HexstrikeClient

            url = hexstrike_url or self.config.get("hexstrike_url", "http://localhost:8888")
            self.hexstrike = HexstrikeClient(base_url=url)
            # Try health check but don't fail if Hexstrike is not available
            try:
                health = self.hexstrike.health_check()
                if health.get("status") != "healthy":
                    logger.debug("%s: Hexstrike health check failed (non-critical)", self.agent_name)
            except Exception as hc_exc:
                logger.debug("%s: Hexstrike health check unavailable (continuing without it): %s", self.agent_name, hc_exc)
        except Exception as exc:
            logger.debug("%s: Hexstrike tools will not be available: %s", self.agent_name, exc)
            self.hexstrike = None

    def _create_graph(self) -> StateGraph:
        raise NotImplementedError("Subclasses must implement _create_graph()")

    def _call_model(self, state: Dict[str, Any], system_message: str) -> Dict[str, Any]:
        if not self.llm:
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

            response = self.llm.invoke(
                [
                    {"role": "system", "content": system_message},
                    {"role": "user", "content": last_message},
                ]
            )
            content = response.content if hasattr(response, "content") else str(response)
            return {"messages": [AIMessage(content=content)]}
        except Exception as exc:
            logger.error("%s: Error calling model: %s", self.agent_name, exc)
            return {"messages": [AIMessage(content=f"Error: {exc}")]}

    def _stream_with_config(self, prompt: str, timeout_override: Optional[int] = None) -> Optional[str]:
        try:
            if self.app:
                thread_id = str(uuid.uuid4())
                config = {"configurable": {"thread_id": thread_id}}
                result = self.app.invoke({"messages": [{"role": "user", "content": prompt}]}, config)
                messages = result.get("messages", [])
                if messages:
                    msg = messages[-1]
                    return msg.content if hasattr(msg, "content") else str(msg)

            if self.llm:
                response = self.llm.invoke(
                    [
                        {"role": "system", "content": "You are a helpful SOC Analyst agent."},
                        {"role": "user", "content": prompt},
                    ]
                )
                return response.content if hasattr(response, "content") else str(response)
            return None
        except Exception as exc:
            logger.error("%s: Error during processing: %s", self.agent_name, exc)
            return None

    def _extract_json_block(self, text: str) -> Optional[Dict[str, Any]]:
        json_pattern = r"```(?:json)?\s*(\{.*?\})\s*```"
        match = re.search(json_pattern, text, re.DOTALL)
        if match:
            json_str = match.group(1)
        else:
            start = text.find("{")
            end = text.rfind("}")
            if start == -1 or end == -1:
                return None
            json_str = text[start : end + 1]

        try:
            return json.loads(json_str)
        except json.JSONDecodeError:
            try:
                return json.loads(json_str.replace("'", '"'))
            except (json.JSONDecodeError, ValueError):
                return None

    def is_ready(self) -> bool:
        return self.llm is not None and self.app is not None

    def get_status(self) -> Dict[str, Any]:
        return {
            "agent_name": self.agent_name,
            "llm_available": self.llm is not None,
            "app_available": self.app is not None,
            "hexstrike_available": self.hexstrike is not None,
            "tool_count": len(self.tools),
            "ready": self.is_ready(),
        }

    def list_tools(self) -> Dict[str, Any]:
        return {
            "agent_name": self.agent_name,
            "tools": [
                {"name": tool.name, "description": tool.description}
                for tool in self.tools
            ],
        }

    def execute_tool(self, tool_name: str, **kwargs: Any) -> Any:
        tool = self.tool_map.get(tool_name)
        if tool is None:
            raise KeyError(f"Unknown tool: {tool_name}")
        return tool.invoke(kwargs)

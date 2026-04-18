"""
Compatibility helpers for optional agent dependencies.

The project can run in a reduced "local test" mode without LangGraph,
LangChain, or the Mistral SDK installed. These shims provide the tiny
surface area the rest of the agent code needs for imports and unit tests.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List, Optional


try:
    from langchain_openai import ChatOpenAI  # type: ignore
except ImportError:  # pragma: no cover
    class ChatOpenAI:  # type: ignore
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.args = args
            self.kwargs = kwargs

        def bind_tools(self, tools: Iterable[Any]) -> "ChatOpenAI":
            self.tools = list(tools)
            return self

        def invoke(self, messages: List[Dict[str, str]]) -> Any:
            last_message = messages[-1]["content"] if messages else ""
            return AIMessage(content=last_message)

try:
    from langchain_mistralai import ChatMistralAI  # type: ignore
except ImportError:  # pragma: no cover
    class ChatMistralAI(ChatOpenAI):  # type: ignore
        pass


try:
    from langchain_core.messages import AIMessage  # type: ignore
except ImportError:  # pragma: no cover
    @dataclass
    class AIMessage:  # type: ignore
        content: str


try:
    from langgraph.checkpoint.memory import MemorySaver  # type: ignore
    from langgraph.graph import END, START, MessagesState, StateGraph  # type: ignore
    from langgraph.prebuilt import ToolNode, tools_condition  # type: ignore
except ImportError:  # pragma: no cover
    START = "__start__"
    END = "__end__"
    MessagesState = dict  # type: ignore

    class MemorySaver:  # type: ignore
        pass

    class _CompiledGraph:
        def __init__(self, nodes: Dict[str, Callable[..., Dict[str, Any]]], entry_point: Optional[str]) -> None:
            self.nodes = nodes
            self.entry_point = entry_point

        def invoke(self, state: Dict[str, Any], config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
            if not self.entry_point:
                return state
            handler = self.nodes[self.entry_point]
            result = handler(state)
            if isinstance(result, dict):
                merged = dict(state)
                merged.update(result)
                return merged
            return state

    class StateGraph:  # type: ignore
        def __init__(self, state_type: Any = None) -> None:
            self.state_type = state_type
            self.nodes: Dict[str, Callable[..., Dict[str, Any]]] = {}
            self.entry_point: Optional[str] = None

        def add_node(self, name: str, handler: Callable[..., Dict[str, Any]]) -> None:
            self.nodes[name] = handler

        def set_entry_point(self, name: str) -> None:
            self.entry_point = name

        def set_finish_point(self, name: str) -> None:
            if self.entry_point is None:
                self.entry_point = name

        def add_edge(self, start: str, end: str) -> None:
            if start == START and self.entry_point is None:
                self.entry_point = end

        def add_conditional_edges(self, *args: Any, **kwargs: Any) -> None:
            return None

        def compile(self, checkpointer: Any = None) -> _CompiledGraph:
            return _CompiledGraph(self.nodes, self.entry_point)

    class ToolNode:  # type: ignore
        def __init__(self, tools: Iterable[Any]) -> None:
            self.tools = list(tools)

    def tools_condition(*args: Any, **kwargs: Any) -> str:  # type: ignore
        return "continue"


try:
    from langchain_core.tools import StructuredTool, ToolException  # type: ignore
except ImportError:  # pragma: no cover
    class ToolException(Exception):
        pass

    @dataclass
    class StructuredTool:  # type: ignore
        name: str
        description: str
        func: Callable[..., Any]
        handle_tool_error: bool = True

        def invoke(self, input_data: Optional[Dict[str, Any]] = None) -> Any:
            if input_data is None:
                return self.func()
            if isinstance(input_data, dict):
                return self.func(**input_data)
            return self.func(input_data)

        @classmethod
        def from_function(
            cls,
            func: Callable[..., Any],
            name: str,
            description: str,
            handle_tool_error: bool = True,
        ) -> "StructuredTool":
            return cls(
                name=name,
                description=description,
                func=func,
                handle_tool_error=handle_tool_error,
            )

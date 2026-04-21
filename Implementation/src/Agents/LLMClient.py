"""
LLM provider factory.

Picks a langchain chat model implementation based on the LLM_PROVIDER env var:

  LLM_PROVIDER=ragarenn   # Eskemm Ragarenn OpenAI-compatible gateway
  LLM_PROVIDER=ollama     # Local Ollama server (host gpu / offline demos)
  LLM_PROVIDER=mistral    # Mistral API
  LLM_PROVIDER=openai     # Standard OpenAI
  LLM_PROVIDER=anthropic  # Anthropic Claude

The factory falls back gracefully when a provider's SDK is missing: it logs
a warning and uses whatever is available. This lets the SOC pipeline keep
running in degraded heuristic-only mode rather than crashing on import.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Callable, Iterable, List, Optional

logger = logging.getLogger(__name__)


def _fallback_chat():
    """Dummy chat model — keeps downstream code happy when no SDK is available."""
    from .runtime_compat import AIMessage  # local import to avoid circular

    class _Dummy:
        def __init__(self) -> None:
            self.tools: List[Any] = []

        def bind_tools(self, tools: Iterable[Any]) -> "_Dummy":
            self.tools = list(tools)
            return self

        def invoke(self, messages: List[Any]) -> Any:
            last = messages[-1] if messages else {"content": ""}
            text = last.get("content", "") if isinstance(last, dict) else getattr(last, "content", "")
            return AIMessage(content=f"[LLM unavailable] {text[:200]}")

    return _Dummy()


def _build_ragarenn(temperature: float, api_key: Optional[str], callbacks: List[Any]):
    """Eskemm Ragarenn OpenAI-compatible gateway."""
    from langchain_openai import ChatOpenAI

    return ChatOpenAI(
        model=os.getenv("LLM_MODEL", "mistral-small"),
        api_key=api_key or os.getenv("RAGARENN_API_KEY"),
        base_url=os.getenv(
            "RAGARENN_API_BASE",
            "https://ragarenn.eskemm-numerique.fr/sso/ch@t/api",
        ),
        temperature=temperature,
        timeout=60,
        callbacks=callbacks,
    )


def _build_mistral(temperature: float, api_key: Optional[str], callbacks: List[Any]):
    from langchain_openai import ChatOpenAI

    return ChatOpenAI(
        model=os.getenv("LLM_MODEL", "mistral-small"),
        api_key=api_key or os.getenv("MISTRAL_API_KEY"),
        base_url=os.getenv("MISTRAL_API_BASE", "https://api.mistral.ai/v1"),
        temperature=temperature,
        timeout=60,
        callbacks=callbacks,
    )


def _build_openai(temperature: float, api_key: Optional[str], callbacks: List[Any]):
    from langchain_openai import ChatOpenAI

    return ChatOpenAI(
        model=os.getenv("LLM_MODEL", "gpt-4o-mini"),
        api_key=api_key,
        base_url=os.getenv("OPENAI_API_BASE", "https://api.openai.com/v1"),
        temperature=temperature,
        timeout=60,
        callbacks=callbacks,
    )


def _build_ollama(temperature: float, _api_key: Optional[str], callbacks: List[Any]):
    # Use the modern langchain-ollama package. The legacy path via
    # langchain_community.chat_models.ChatOllama is deprecated in LangChain 0.3.1
    # and slated for removal in 1.0.0; we refuse to silently fall back to it.
    try:
        from langchain_ollama import ChatOllama  # type: ignore
    except ImportError as exc:
        raise ImportError(
            "langchain-ollama is required for LLM_PROVIDER=ollama. "
            "Install it with: pip install -U langchain-ollama"
        ) from exc

    return ChatOllama(
        model=os.getenv("LLM_MODEL", "llama3.2"),
        base_url=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"),
        temperature=temperature,
        callbacks=callbacks,
    )


def _build_anthropic(temperature: float, api_key: Optional[str], callbacks: List[Any]):
    from langchain_anthropic import ChatAnthropic  # type: ignore

    return ChatAnthropic(
        model=os.getenv("LLM_MODEL", "claude-sonnet-4-6"),
        api_key=api_key,
        temperature=temperature,
        timeout=60,
        callbacks=callbacks,
    )


_BUILDERS: dict[str, Callable[..., Any]] = {
    "ragarenn": _build_ragarenn,
    "ollama": _build_ollama,
    "mistral": _build_mistral,
    "openai": _build_openai,
    "anthropic": _build_anthropic,
}


def build_llm(
    temperature: float = 0.3,
    api_key: Optional[str] = None,
    callbacks: Optional[List[Any]] = None,
    provider: Optional[str] = None,
) -> Any:
    """Return a langchain-compatible chat model for the active provider."""
    callbacks = callbacks or []
    provider = (provider or os.getenv("LLM_PROVIDER") or "ragarenn").strip().lower()
    builder = _BUILDERS.get(provider)
    if builder is None:
        logger.warning("[LLMClient] Unknown provider %r; using ragarenn", provider)
        builder = _build_ragarenn

    try:
        return builder(temperature, api_key, callbacks)
    except ImportError as exc:
        logger.warning("[LLMClient] provider=%s SDK missing (%s); using fallback", provider, exc)
        return _fallback_chat()
    except Exception as exc:
        logger.error("[LLMClient] provider=%s init failed: %s", provider, exc)
        return _fallback_chat()

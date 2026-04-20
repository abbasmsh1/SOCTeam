"""
Minimal, reusable pipeline primitive for SOC workflows.

Most SOC code paths in this project follow the same four-phase loop:

  1. normalize   — turn heterogeneous inputs into a ThreatContext-like object
  2. analyze     — ask an LLM / rules engine for proposed actions
  3. enforce     — push actions into the sandbox / firewall / IP store
  4. report      — return a result dict the API can serialise

Each phase is a plain callable taking (ctx, state) and returning an updated
state dict. That keeps the primitive usable for LangGraph-less call paths
(like AutoSOCRuleGenerator) without forcing every workflow onto LangGraph.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


class Phase(str, Enum):
    NORMALIZE = "normalize"
    ANALYZE = "analyze"
    ENFORCE = "enforce"
    REPORT = "report"


PhaseHandler = Callable[[Any, Dict[str, Any]], Dict[str, Any]]


@dataclass
class PipelineResult:
    phase: Phase
    state: Dict[str, Any]
    error: Optional[str] = None


@dataclass
class SOCPipeline:
    """Run a fixed-order sequence of phase handlers over a context."""

    name: str = "soc"
    handlers: Dict[Phase, PhaseHandler] = field(default_factory=dict)

    def set_handler(self, phase: Phase, handler: PhaseHandler) -> "SOCPipeline":
        self.handlers[phase] = handler
        return self

    def run(self, ctx: Any, initial_state: Optional[Dict[str, Any]] = None) -> PipelineResult:
        state: Dict[str, Any] = dict(initial_state or {})
        for phase in (Phase.NORMALIZE, Phase.ANALYZE, Phase.ENFORCE, Phase.REPORT):
            handler = self.handlers.get(phase)
            if handler is None:
                continue
            try:
                update = handler(ctx, state) or {}
                state.update(update)
            except Exception as exc:
                logger.exception("[pipeline=%s] phase=%s failed", self.name, phase.value)
                return PipelineResult(phase=phase, state=state, error=str(exc))
        return PipelineResult(phase=Phase.REPORT, state=state)

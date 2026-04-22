"""
SOC pipeline migration — thin wrappers that let the monolithic SOCWorkflow
borrow the phase-based pipeline primitive for focused sub-flows.

Why not port the whole LangGraph workflow onto SOCPipeline?
  SOCWorkflow needs conditional edges (escalate/not-escalate/war-room) that
  LangGraph models first-class. SOCPipeline is linear.

Where SOCPipeline helps inside SOCWorkflow:
  1. _remediation_node — its logic is normalize→extract_rules→enforce→report.
  2. _fetch_forensics — normalize target → run enrichments → report.
  3. The WarRoomWorkflow red→blue→purple sequence.

This file provides Pipeline factories that SOCWorkflow / WarRoomWorkflow can
call without rewriting themselves. Linear sub-flows become composable,
testable, and log cleanly with the pipeline primitive.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Dict, Optional

from .SOCPipeline import Phase, PipelineResult, SOCPipeline

logger = logging.getLogger(__name__)


def build_remediation_pipeline(
    remediation_executor: Any,
    on_sandbox_result: Optional[Callable[[Dict[str, Any]], None]] = None,
) -> SOCPipeline:
    """
    Linear remediation sub-flow:
      NORMALIZE: extract threat_info + defense_plan from context
      ANALYZE:   ask RemediationAgent.process to parse rules
      ENFORCE:   that same call executes via the sandbox
      REPORT:    call back with the execution log
    """

    def normalize(ctx: Dict[str, Any], state: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "threat_info": ctx.get("threat_info", {}),
            "defense_plan": ctx.get("defense_plan", ""),
            "auto_pilot": bool(ctx.get("auto_pilot", False)),
        }

    def analyze_and_enforce(ctx: Dict[str, Any], state: Dict[str, Any]) -> Dict[str, Any]:
        result = remediation_executor.process({
            "threat_info": state["threat_info"],
            "generated_code": "",
            "defense_plan": state["defense_plan"],
            "auto_pilot": state["auto_pilot"],
        })
        return {"remediation_result": result}

    def report(ctx: Dict[str, Any], state: Dict[str, Any]) -> Dict[str, Any]:
        result = state.get("remediation_result", {}) or {}
        if on_sandbox_result:
            try:
                on_sandbox_result(result)
            except Exception as exc:
                logger.debug("on_sandbox_result hook failed: %s", exc)
        return {"execution_log": result.get("execution_log", [])}

    return (
        SOCPipeline(name="remediation")
        .set_handler(Phase.NORMALIZE, normalize)
        .set_handler(Phase.ANALYZE, analyze_and_enforce)
        .set_handler(Phase.REPORT, report)
    )


def build_forensic_pipeline(hexstrike_client: Any) -> SOCPipeline:
    """
    Linear forensic enrichment sub-flow:
      NORMALIZE: resolve IP target
      ANALYZE:   analyze_target + check_ip_reputation
      REPORT:    combined dict for downstream tier consumption
    """

    def normalize(ctx: Dict[str, Any], state: Dict[str, Any]) -> Dict[str, Any]:
        ip = ctx.get("ip") or ctx.get("target") or ""
        return {"ip": ip}

    def analyze(ctx: Dict[str, Any], state: Dict[str, Any]) -> Dict[str, Any]:
        ip = state.get("ip")
        if not ip:
            return {"analysis": {}, "reputation": {}}
        out: Dict[str, Any] = {"source": "HexStrike-AI (Deep Forensics)"}
        try:
            out["analysis"] = hexstrike_client.analyze_target(ip, "comprehensive")
        except Exception as exc:
            out["analysis"] = {"error": str(exc)}
        try:
            out["reputation"] = hexstrike_client.check_ip_reputation(ip)
        except Exception as exc:
            out["reputation"] = {"error": str(exc)}
        return {"forensic": out}

    def report(ctx: Dict[str, Any], state: Dict[str, Any]) -> Dict[str, Any]:
        import datetime as _dt
        f = state.get("forensic", {}) or {}
        f["completed_at"] = _dt.datetime.utcnow().isoformat()
        return f

    return (
        SOCPipeline(name="forensic-enrichment")
        .set_handler(Phase.NORMALIZE, normalize)
        .set_handler(Phase.ANALYZE, analyze)
        .set_handler(Phase.REPORT, report)
    )


def run_pipeline_safely(pipeline: SOCPipeline, ctx: Any) -> Dict[str, Any]:
    """Run a SOCPipeline and coerce to a flat dict for LangGraph state merging."""
    result: PipelineResult = pipeline.run(ctx)
    out = dict(result.state or {})
    if result.error:
        out["_pipeline_error"] = result.error
    return out

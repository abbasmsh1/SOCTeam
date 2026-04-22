"""
LLM-as-judge: score SOC report quality against a rubric using a third-party LLM.

Picks N recent reports from Reports/, asks the LLM to rate each on:
  - Evidence (0-10): Are the Tier 2 / HexStrike / reputation findings coherent?
  - Reasoning (0-10): Does the attack-plan / defense-plan follow from evidence?
  - Severity fit (0-10): Is the final severity justified?
  - Actionability (0-10): Could an analyst follow the recommendations?
Plus a free-text critique.

Outputs JSONL to Reports/llm_judge_scores.jsonl — one line per report.
Cheap — can run overnight on 100 reports.

Usage:
    python -m Implementation.tools.llm_judge --limit 20 --provider ollama
    python -m Implementation.tools.llm_judge --provider ragarenn --model mistral-small
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import logging
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

REPORTS_DIR = Path("E:/IMT/2nd Sem/Project/Reports")
OUT_PATH = REPORTS_DIR / "llm_judge_scores.jsonl"

RUBRIC = (
    "You are a senior SOC analyst reviewing an AI-generated incident report.\n"
    "Rate each category strictly on a 0–10 scale (0 = absent, 10 = excellent).\n"
    "Return JSON only, matching exactly this schema:\n"
    '{"evidence": int, "reasoning": int, "severity_fit": int, "actionability": int, "critique": "one paragraph"}\n\n'
    "Report:\n-----\n{report}\n-----\nReturn ONLY the JSON object, no prose."
)


def _load_llm(provider: Optional[str], model: Optional[str]):
    """Lazy — avoid importing torch/langchain unless needed."""
    import os as _os
    if provider: _os.environ["LLM_PROVIDER"] = provider
    if model: _os.environ["LLM_MODEL"] = model
    from Implementation.src.Agents.LLMClient import build_llm
    return build_llm(
        temperature=0.0,
        api_key=_os.environ.get("RAGARENN_API_KEY"),
    )


def _load_reports(limit: int) -> List[Path]:
    files = sorted(
        [p for p in REPORTS_DIR.glob("SOC_Report_*.md") if p.is_file()],
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    return files[:limit]


def _extract_json(text: str) -> Optional[Dict[str, Any]]:
    match = re.search(r"\{[\s\S]*\}", text or "")
    if not match:
        return None
    try:
        return json.loads(match.group(0))
    except Exception:
        return None


def judge_one(llm, report_text: str) -> Dict[str, Any]:
    prompt = RUBRIC.format(report=report_text[:12000])
    try:
        resp = llm.invoke([{"role": "user", "content": prompt}])
        content = resp.content if hasattr(resp, "content") else str(resp)
    except Exception as exc:
        return {"error": f"{type(exc).__name__}: {exc}"}
    parsed = _extract_json(content) or {"error": "unparseable", "raw": content[:400]}
    return parsed


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=10)
    ap.add_argument("--provider", default=os.getenv("LLM_PROVIDER"))
    ap.add_argument("--model", default=os.getenv("LLM_MODEL"))
    ap.add_argument("--out", type=Path, default=OUT_PATH)
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    reports = _load_reports(args.limit)
    if not reports:
        print("No reports found", file=sys.stderr)
        return 1
    llm = _load_llm(args.provider, args.model)

    scores: List[Dict[str, Any]] = []
    with open(args.out, "a", encoding="utf-8") as out:
        for i, path in enumerate(reports, 1):
            text = path.read_text(encoding="utf-8", errors="ignore")
            logger.info("[%d/%d] judging %s", i, len(reports), path.name)
            score = judge_one(llm, text)
            record = {
                "ts": _dt.datetime.utcnow().isoformat(),
                "report": path.name,
                **score,
            }
            out.write(json.dumps(record) + "\n")
            scores.append(record)

    if not scores:
        return 1
    numeric = [s for s in scores if isinstance(s.get("evidence"), int)]
    if numeric:
        for k in ("evidence", "reasoning", "severity_fit", "actionability"):
            vals = [s[k] for s in numeric if isinstance(s.get(k), int)]
            if vals:
                print(f"  mean {k:<14} = {sum(vals)/len(vals):.2f} ({len(vals)} reports)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

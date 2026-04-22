"""
Prompt compression.

Shrinks the prompts sent to the LLM without dropping load-bearing info:
  - verbose JSON dumps of flow records -> key:value summaries of the N most
    informative fields
  - flow_history.db tables -> the most recent K rows plus aggregate counts
  - HexStrike narrative -> first paragraph plus bullet highlights

Goal: cut input tokens by 40-70%. Every token saved on input is faster
inference AND lower cost on commercial APIs.

Used by BaseAgent._stream_with_config and TierAnalystAgent._process_tier1 via
`compress_prompt(prompt)`.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List


_MAX_JSON_CHARS = int(os.getenv("IDS_LLM_MAX_JSON_CHARS", "800"))
_MAX_PROMPT_CHARS = int(os.getenv("IDS_LLM_MAX_PROMPT_CHARS", "6000"))
_ENABLED = os.getenv("IDS_LLM_COMPRESS", "true").lower() in ("1", "true", "yes")

# Fields that always carry signal in a flow record. Everything else gets
# collapsed unless the caller overrides.
_SIGNAL_FIELDS = {
    "Attack", "attack_type", "predicted_label", "confidence",
    "Source IP", "SourceIP", "IPV4_SRC_ADDR", "src_ip",
    "Destination IP", "DestinationIP", "IPV4_DST_ADDR", "dst_ip",
    "Protocol", "PROTOCOL", "L4_SRC_PORT", "L4_DST_PORT", "L7_PROTO",
    "IN_BYTES", "OUT_BYTES", "IN_PKTS", "OUT_PKTS",
    "FLOW_DURATION_MILLISECONDS", "severity", "Severity",
    "TCP_FLAGS", "MIN_TTL", "MAX_TTL",
}


def summarise_json(obj: Any, max_keys: int = 8, max_str: int = 160) -> str:
    """
    Render a dict/list in a way that preserves the key signal but drops
    boilerplate. Returns a short multi-line string.
    """
    if obj is None:
        return "(none)"
    if isinstance(obj, (int, float, bool)):
        return str(obj)
    if isinstance(obj, str):
        return obj if len(obj) <= max_str else obj[:max_str] + "..."
    if isinstance(obj, list):
        if not obj:
            return "[]"
        head = obj[:3]
        preview = "; ".join(summarise_json(x, max_keys, max_str) for x in head)
        suffix = "" if len(obj) <= 3 else f" (+{len(obj) - 3} more)"
        return f"[{preview}{suffix}]"
    if isinstance(obj, dict):
        # Signal fields first, then anything else until cap
        items: List[str] = []
        seen: set[str] = set()
        for k in _SIGNAL_FIELDS:
            if k in obj and obj[k] not in (None, "", 0, "0", "0.0"):
                items.append(f"{k}={summarise_json(obj[k], max_keys, max_str)}")
                seen.add(k)
                if len(items) >= max_keys:
                    return "{" + ", ".join(items) + "}"
        for k, v in obj.items():
            if k in seen or v in (None, "", 0, "0", "0.0"):
                continue
            items.append(f"{k}={summarise_json(v, max_keys, max_str)}")
            if len(items) >= max_keys:
                items.append(f"... (+{len(obj) - len(items)} more keys)")
                break
        return "{" + ", ".join(items) + "}"
    return str(obj)[:max_str]


def compress_prompt(prompt: str) -> str:
    """
    Apply heuristic compression to a tier prompt without breaking the
    structural markers (`### ...`, `[ACTIONABLE_RULES]`, code fences).

    Rules:
      1. Collapse JSON fenced blocks larger than _MAX_JSON_CHARS to a
         one-line summary.
      2. Strip runs of 3+ blank lines.
      3. Truncate flow-history excerpts past a sensible length.
      4. Hard cap at _MAX_PROMPT_CHARS so we never send a novel.
    """
    if not _ENABLED or not prompt:
        return prompt

    # 1. Compress fenced JSON/code blocks when oversized
    def _collapse_block(match: "re.Match[str]") -> str:
        body = match.group(1)
        if len(body) < _MAX_JSON_CHARS:
            return match.group(0)
        try:
            parsed = json.loads(body)
            summary = summarise_json(parsed, max_keys=12, max_str=180)
            return f"```\n(compressed from {len(body)} chars) {summary}\n```"
        except Exception:
            # Not valid JSON — just truncate
            head = body[: _MAX_JSON_CHARS // 2]
            tail = body[-200:]
            return f"```\n{head}\n... [{len(body) - len(head) - len(tail)} chars omitted] ...\n{tail}\n```"

    compressed = re.sub(
        r"```(?:json)?\s*([\s\S]*?)\s*```",
        _collapse_block,
        prompt,
    )

    # 2. Collapse 3+ blank lines to one
    compressed = re.sub(r"\n\s*\n\s*\n+", "\n\n", compressed)

    # 3. Strip ANSI escapes (occasionally leaked from subprocess output)
    compressed = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", compressed)

    # 4. Hard cap
    if len(compressed) > _MAX_PROMPT_CHARS:
        head = compressed[: int(_MAX_PROMPT_CHARS * 0.7)]
        tail = compressed[-int(_MAX_PROMPT_CHARS * 0.25):]
        compressed = f"{head}\n\n... [prompt truncated for speed] ...\n\n{tail}"

    return compressed


def compression_stats(before: str, after: str) -> Dict[str, Any]:
    if not before:
        return {"before": 0, "after": len(after), "ratio": 0.0}
    return {
        "before": len(before),
        "after": len(after),
        "ratio": round(len(after) / max(1, len(before)), 4),
    }

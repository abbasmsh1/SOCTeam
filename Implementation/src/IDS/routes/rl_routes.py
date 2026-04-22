"""
RL feedback endpoints — extracted from IDS.py.

Call register(app, verify_api_key, verify_admin_api_key, base_dir) once at
startup to attach the routes.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
from typing import Optional

from fastapi import Depends, HTTPException
from pydantic import BaseModel

logger = logging.getLogger(__name__)


class _RLFeedbackBody(BaseModel):
    src_ip: str
    decision: str            # allow | deny
    predicted_label: Optional[str] = ""


class _RLTrainBody(BaseModel):
    limit: int = 500
    epochs: int = 3
    lr: float = 1e-4
    dry_run: bool = False


def register(app, *, verify_api_key, verify_admin_api_key, base_dir: str, policy_factory) -> None:
    @app.get("/rl/stats", dependencies=[Depends(verify_api_key)])
    def rl_stats():
        from Implementation.src.IDS.rl import FeedbackHook
        hook = FeedbackHook.instance()
        stats = hook.stats()
        try:
            policy = policy_factory()
            policy.refresh_from_buffer(stats)
            stats["policy"] = policy.snapshot()
        except Exception as exc:
            stats["policy_error"] = str(exc)
        return stats

    @app.post("/rl/feedback", dependencies=[Depends(verify_admin_api_key)])
    def rl_manual_feedback(body: _RLFeedbackBody):
        if body.decision.lower() not in ("allow", "deny"):
            raise HTTPException(status_code=400, detail="decision must be allow|deny")
        from Implementation.src.IDS.rl import FeedbackHook
        result = FeedbackHook.instance().on_quarantine_decision(
            src_ip=body.src_ip,
            decision=body.decision.lower(),
            predicted_label=body.predicted_label or "",
        )
        return {"status": "recorded", "signal": result}

    @app.post("/rl/train", dependencies=[Depends(verify_admin_api_key)])
    def rl_trigger_training(body: _RLTrainBody):
        cmd = [
            sys.executable, "-m", "Implementation.src.IDS.rl.trainer",
            "--limit", str(body.limit),
            "--epochs", str(body.epochs),
            "--lr", str(body.lr),
        ]
        if body.dry_run:
            cmd.append("--dry-run")
        try:
            proc = subprocess.run(cmd, cwd=base_dir, capture_output=True, text=True, timeout=900)
        except subprocess.TimeoutExpired:
            raise HTTPException(status_code=504, detail="RL training subprocess timed out after 15m")
        stdout = (proc.stdout or "").strip()
        try:
            parsed = json.loads(stdout.splitlines()[-1]) if stdout else {}
        except Exception:
            parsed = {"raw_stdout": stdout[:4000]}
        return {
            "exit": proc.returncode,
            "result": parsed,
            "stderr_tail": (proc.stderr or "")[-1500:],
        }

    @app.get("/rl/policy", dependencies=[Depends(verify_api_key)])
    def rl_policy_snapshot():
        try:
            return policy_factory().snapshot()
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc))

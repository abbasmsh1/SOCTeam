"""
Feedback hook — glue between the SOC workflow / quarantine UI and the
RL experience buffer.

Call sites (wired from IDS.py + SOCWorkflow._finalize_node):
  - on_prediction(features, predicted_label, confidence, src_ip, alert_id)
  - on_workflow_finalize(alert_id, tier1, tier2, predicted_label)
  - on_quarantine_decision(src_ip, decision, predicted_label)

All errors are swallowed — RL is a passive observer and must never break the
inference / workflow paths.
"""

from __future__ import annotations

import logging
import os
import threading
from typing import Any, Dict, Optional

from .experience_buffer import ExperienceBuffer
from .reward import RewardCalculator

logger = logging.getLogger(__name__)

_FeedbackLock = threading.Lock()


class FeedbackHook:
    """
    Singleton-ish wrapper so the rest of the backend can import & call once.
    Use `FeedbackHook.instance()` — first call constructs with defaults.
    """

    _instance: Optional["FeedbackHook"] = None

    def __init__(self, buffer: ExperienceBuffer, calculator: Optional[RewardCalculator] = None, enabled: bool = True):
        self.buffer = buffer
        self.calc = calculator or RewardCalculator()
        self.enabled = enabled

    @classmethod
    def instance(cls) -> "FeedbackHook":
        if cls._instance is None:
            with _FeedbackLock:
                if cls._instance is None:
                    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
                    base_dir = os.path.dirname(base_dir)  # project root
                    db_path = os.getenv(
                        "IDS_RL_DB_PATH",
                        os.path.join(base_dir, "Reports", "rl_experience.db"),
                    )
                    enabled = os.getenv("IDS_RL_ENABLED", "true").lower() in ("1", "true", "yes")
                    buf = ExperienceBuffer(db_path) if enabled else _NoopBuffer()  # type: ignore[arg-type]
                    cls._instance = cls(buf, enabled=enabled)
                    logger.info("FeedbackHook initialised: enabled=%s db=%s", enabled, db_path if enabled else "<disabled>")
        return cls._instance

    # -- write paths ----------------------------------------------------------

    def on_prediction(
        self,
        features: Dict[str, Any],
        predicted_label: str,
        predicted_idx: Optional[int],
        predicted_confidence: float,
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        alert_id: Optional[str] = None,
    ) -> Optional[int]:
        if not self.enabled:
            return None
        try:
            return self.buffer.record_prediction(
                features=features,
                predicted_label=predicted_label,
                predicted_idx=predicted_idx,
                predicted_confidence=predicted_confidence,
                src_ip=src_ip,
                dst_ip=dst_ip,
                alert_id=alert_id,
            )
        except Exception as exc:
            logger.debug("FeedbackHook.on_prediction failed: %s", exc)
            return None

    def on_workflow_finalize(
        self,
        alert_id: str,
        predicted_label: str,
        tier1: Optional[Dict[str, Any]] = None,
        tier2: Optional[Dict[str, Any]] = None,
        workflow_failed: bool = False,
        failure_reason: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Flip a pending RL row based on workflow verdict.

        workflow_failed=True is the escape hatch for "workflow crashed before
        producing any tier output". Without it, crashed workflows left their
        RL rows pending forever (observed pattern: 18 Brute Force rows at
        conf=1.0 stuck pending after Mistral 401s in DevSecOps sub-steps).
        Sets agent_label="WORKFLOW_FAILED", reward=-0.1 so the trainer sees
        a weak negative signal rather than silence.
        """
        if not self.enabled or not alert_id:
            return None
        try:
            if workflow_failed:
                self.buffer.label_by_alert(
                    alert_id=alert_id,
                    agent_label="WORKFLOW_FAILED",
                    agent_severity=None,
                    is_false_positive=None,
                    reward=-0.1,
                )
                logger.info(
                    "RL feedback: workflow failed for alert_id=%s (%s)  reason=%s",
                    alert_id, predicted_label, failure_reason or "unknown",
                )
                return {"status": "workflow_failed", "reward": -0.1, "alert_id": alert_id}

            signal = self.calc.from_workflow(predicted_label, tier1=tier1, tier2=tier2)
            if signal.reward == 0.0 and signal.true_label is None and signal.false_positive is None:
                # Tier outputs were missing/malformed but workflow reached
                # finalize. Previously we left the row pending; now we flip
                # it to labeled with a very weak signal so the trainer sees
                # the outcome (agent produced nothing useful) rather than
                # the row lingering forever. Downstream human quarantine
                # allow/deny can still override this via label_by_src_ip.
                self.buffer.label_by_alert(
                    alert_id=alert_id,
                    agent_label="NO_TIER_OUTPUT",
                    agent_severity=None,
                    is_false_positive=None,
                    reward=0.0,
                )
                return {"status": "no_tier_output", "reward": 0.0, "alert_id": alert_id}
            self.buffer.label_by_alert(
                alert_id=alert_id,
                agent_label=signal.true_label,
                agent_severity=signal.severity,
                is_false_positive=signal.false_positive,
                reward=signal.reward,
            )
            return signal.to_dict()
        except Exception as exc:
            logger.debug("FeedbackHook.on_workflow_finalize failed: %s", exc)
            return None

    def on_quarantine_decision(
        self,
        src_ip: str,
        decision: str,
        predicted_label: str = "",
    ) -> Optional[Dict[str, Any]]:
        """decision in {'allow', 'deny'}. Backfills up to 5 recent pending rows for this IP."""
        if not self.enabled or not src_ip:
            return None
        try:
            decision = decision.lower()
            if decision == "allow":
                signal = self.calc.from_human_allow(predicted_label)
            elif decision == "deny":
                signal = self.calc.from_human_deny(predicted_label)
            else:
                return None
            n = self.buffer.label_by_src_ip(
                src_ip=src_ip,
                human_decision=decision,
                reward=signal.reward,
                max_rows=5,
            )
            logger.info("RL feedback: human %s on %s labeled %d rows", decision.upper(), src_ip, n)
            return {**signal.to_dict(), "rows_updated": n}
        except Exception as exc:
            logger.debug("FeedbackHook.on_quarantine_decision failed: %s", exc)
            return None

    def stats(self) -> Dict[str, Any]:
        try:
            return {"enabled": self.enabled, **self.buffer.stats()}
        except Exception as exc:
            return {"enabled": self.enabled, "error": str(exc)}

    def heuristic_sweep(self, **kwargs: Any) -> Dict[str, int]:
        """Proxy to ExperienceBuffer.heuristic_sweep; returns {} when disabled."""
        if not self.enabled:
            return {}
        try:
            return self.buffer.heuristic_sweep(**kwargs)
        except Exception as exc:
            logger.warning("FeedbackHook.heuristic_sweep failed: %s", exc)
            return {"error": 1}


class _NoopBuffer:
    """Drop-in when RL is disabled — every call is a no-op."""
    def record_prediction(self, **_: Any) -> Optional[int]: return None
    def label_by_alert(self, **_: Any) -> int: return 0
    def label_by_src_ip(self, **_: Any) -> int: return 0
    def heuristic_sweep(self, **_: Any) -> Dict[str, int]: return {}
    def stats(self) -> Dict[str, Any]: return {"disabled": True}
    def fetch_training_batch(self, limit: int = 500) -> list: return []
    def mark_trained(self, ids: Any) -> int: return 0

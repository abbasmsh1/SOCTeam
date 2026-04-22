"""
Reward + relabel rules for the IDS RL pipeline.

Input signals (each is optional):
  - Tier 1 triage output  -> severity, escalate, false_positive, recommended_actions
  - Tier 2 investigation  -> validated_severity, incident_classification
  - Tier 3 response plan  -> credible_threat bool
  - Quarantine decision   -> allow / deny from the analyst UI

Output:
  RewardSignal(
    reward: float in [-1, +1],
    true_label: Optional[str]     # agents' corrected label if they disagree
    severity: Optional[str],
    false_positive: Optional[bool],
  )
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional


_BENIGN = {"BENIGN", "NORMAL", "BENIGN_", ""}
_FP_TIER1_MARK = "false_positive"


@dataclass
class RewardSignal:
    reward: float
    true_label: Optional[str]
    severity: Optional[str]
    false_positive: Optional[bool]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "reward": self.reward,
            "true_label": self.true_label,
            "severity": self.severity,
            "false_positive": self.false_positive,
        }


class RewardCalculator:
    """
    Deterministic, agent-feedback-driven reward.

    Principles
    ----------
    1. Tier 1 marked false_positive → strong negative (-1): we classified a
       benign flow as a threat.
    2. Tier 1 confirms + escalates  → +0.6, Tier 2 validates  → bonus +0.3 if
       the classification matches the predicted label.
    3. Severity mismatch between prediction and Tier 2-validated severity
       penalises by -0.3 (we were directionally right but miscalibrated).
    4. Human quarantine ALLOW → -1 (analyst overrode to benign).
    5. Human quarantine DENY  → +1 (analyst confirmed block).

    Neutral rewards (0.0) are skipped by the trainer — only |reward| >= 0.3
    contributes to the fine-tune loss.
    """

    def from_workflow(
        self,
        predicted_label: str,
        tier1: Optional[Dict[str, Any]] = None,
        tier2: Optional[Dict[str, Any]] = None,
    ) -> RewardSignal:
        tier1 = tier1 or {}
        tier2 = tier2 or {}

        predicted_upper = (predicted_label or "").upper()
        is_fp = bool(tier1.get(_FP_TIER1_MARK, False))
        escalate = bool(tier1.get("escalate", False))
        severity = tier1.get("severity")

        # (1) False positive
        if is_fp:
            return RewardSignal(reward=-1.0, true_label="BENIGN", severity="low", false_positive=True)

        # Tier 2's validated classification wins when present
        t2_label = self._tier2_attack_label(tier2)
        t2_severity = tier2.get("validated_severity") or severity
        if t2_label:
            matches_prediction = predicted_upper != "" and predicted_upper in t2_label.upper()
            base = 0.8 if matches_prediction else 0.3
            # Severity miscalibration penalty
            if self._severity_mismatch(predicted_label, t2_severity):
                base -= 0.3
            return RewardSignal(
                reward=max(-1.0, min(1.0, base)),
                true_label=t2_label if not matches_prediction else predicted_label,
                severity=t2_severity,
                false_positive=False,
            )

        # Tier 1 only — weaker confirmation
        if escalate:
            return RewardSignal(
                reward=0.5,
                true_label=predicted_label if predicted_upper not in _BENIGN else None,
                severity=severity,
                false_positive=False,
            )

        # No escalation, no FP flag — ambiguous, low-value signal
        return RewardSignal(reward=0.0, true_label=None, severity=severity, false_positive=None)

    def from_human_allow(self, predicted_label: str) -> RewardSignal:
        """Analyst whitelisted the IP — treat as false positive."""
        return RewardSignal(reward=-1.0, true_label="BENIGN", severity="low", false_positive=True)

    def from_human_deny(self, predicted_label: str) -> RewardSignal:
        """Analyst confirmed the block — strong positive."""
        return RewardSignal(
            reward=1.0,
            true_label=predicted_label if (predicted_label or "").upper() not in _BENIGN else None,
            severity="high",
            false_positive=False,
        )

    # -- helpers --------------------------------------------------------------

    @staticmethod
    def _tier2_attack_label(tier2: Dict[str, Any]) -> Optional[str]:
        if not isinstance(tier2, dict):
            return None
        for k in ("incident_classification", "attack_type", "validated_label"):
            v = tier2.get(k)
            if v and isinstance(v, str) and v.strip() and v.strip().lower() not in ("n/a", "unknown"):
                return v
        return None

    @staticmethod
    def _severity_mismatch(predicted_label: str, severity: Optional[str]) -> bool:
        """Predicted a critical-class attack but Tier 2 graded it low, or vice-versa."""
        if not severity:
            return False
        lo = severity.lower()
        label = (predicted_label or "").upper()
        critical_classes = {"DDOS", "BOTNET", "RANSOMWARE", "EXPLOIT", "INFILTRATION"}
        label_is_critical = any(c in label for c in critical_classes)
        if label_is_critical and lo in ("low", "informational"):
            return True
        if not label_is_critical and lo in ("critical",):
            return True
        return False

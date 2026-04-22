"""
Adaptive confidence-threshold policy.

Per attack class, track the empirical false-positive rate observed from
agent feedback. If a class's FP rate exceeds a threshold, raise the minimum
confidence required to auto-queue its SOC workflow. This prevents noisy
classes from drowning the workflow queue while still letting clean classes
fire at the global AUTO_WORKFLOW_CONFIDENCE default.

The policy is read-only from the prediction hot path — refresh runs in a
background thread every `refresh_sec`.

Persistence: Reports/rl_policy.json, so thresholds survive restarts.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


class AdaptiveConfidencePolicy:
    """
    Per-class `min_confidence` thresholds derived from agent FP feedback.

    Parameters
    ----------
    base_threshold: float
        Fallback threshold for classes with too few observations.
    min_samples: int
        Don't adjust a class's threshold until we've seen at least this many
        labeled samples for it.
    max_threshold: float
        Cap on how high a threshold can climb, so a misbehaving class still
        gets *some* triage traffic for re-evaluation.
    """

    def __init__(
        self,
        base_threshold: float = 0.85,
        min_samples: int = 20,
        max_threshold: float = 0.98,
        persistence_path: Optional[str] = None,
    ):
        self.base_threshold = base_threshold
        self.min_samples = min_samples
        self.max_threshold = max_threshold
        self._lock = threading.RLock()
        self._thresholds: Dict[str, float] = {}
        self._fp_rates: Dict[str, float] = {}
        self._sample_counts: Dict[str, int] = {}
        self._last_refresh: float = 0.0
        self.persistence_path = persistence_path
        self._load()

    # -- public API -----------------------------------------------------------

    def threshold_for(self, attack_label: str) -> float:
        """Get the current confidence threshold for an attack label."""
        if not attack_label:
            return self.base_threshold
        with self._lock:
            return self._thresholds.get(attack_label.upper(), self.base_threshold)

    def refresh_from_buffer(self, buffer_stats: Dict[str, Any]) -> Dict[str, float]:
        """
        Recompute thresholds from an `ExperienceBuffer.stats()` snapshot.

        Returns the per-class threshold map so the caller can log changes.
        """
        fp_map = buffer_stats.get("fp_rate_by_class") or {}
        per_class = buffer_stats.get("per_class") or {}
        changes: Dict[str, float] = {}
        with self._lock:
            for label, fp_rate in fp_map.items():
                label_u = label.upper()
                n = per_class.get(label, {}).get("n", 0) if isinstance(per_class, dict) else 0
                self._fp_rates[label_u] = float(fp_rate or 0.0)
                self._sample_counts[label_u] = int(n)
                if n < self.min_samples:
                    continue
                # Sigmoid-style ramp — higher FP → higher threshold, capped.
                extra = min(self.max_threshold - self.base_threshold, 0.13 * fp_rate * 1.5)
                new_threshold = round(min(self.max_threshold, self.base_threshold + extra), 3)
                previous = self._thresholds.get(label_u)
                if previous is None or abs(previous - new_threshold) > 0.005:
                    self._thresholds[label_u] = new_threshold
                    changes[label_u] = new_threshold
            self._last_refresh = time.time()
        if changes:
            logger.info("[rl-policy] thresholds updated: %s", changes)
            self._save()
        return dict(self._thresholds)

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "base_threshold": self.base_threshold,
                "min_samples": self.min_samples,
                "max_threshold": self.max_threshold,
                "thresholds": dict(self._thresholds),
                "fp_rates": {k: round(v, 4) for k, v in self._fp_rates.items()},
                "sample_counts": dict(self._sample_counts),
                "last_refresh": self._last_refresh,
            }

    # -- persistence ----------------------------------------------------------

    def _load(self) -> None:
        if not self.persistence_path or not os.path.exists(self.persistence_path):
            return
        try:
            with open(self.persistence_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            with self._lock:
                self._thresholds = dict(data.get("thresholds") or {})
                self._fp_rates = dict(data.get("fp_rates") or {})
                self._sample_counts = dict(data.get("sample_counts") or {})
            logger.info("[rl-policy] loaded %d thresholds from %s",
                        len(self._thresholds), self.persistence_path)
        except Exception as exc:
            logger.warning("[rl-policy] load failed: %s", exc)

    def _save(self) -> None:
        if not self.persistence_path:
            return
        try:
            os.makedirs(os.path.dirname(self.persistence_path), exist_ok=True)
            tmp = self.persistence_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.snapshot(), f, indent=2, default=str)
            os.replace(tmp, self.persistence_path)
        except Exception as exc:
            logger.warning("[rl-policy] save failed: %s", exc)

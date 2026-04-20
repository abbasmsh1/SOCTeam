"""
Feature drift monitoring via Population Stability Index (PSI).

Keeps a rolling in-memory window of recent feature values and compares it
against a frozen baseline (typically the training distribution). PSI is
computed per feature:

    PSI = sum( (p_live - p_base) * ln(p_live / p_base) )

Rule of thumb:
    PSI < 0.1   → no drift
    0.1–0.25    → moderate drift (investigate)
    > 0.25      → significant drift
"""

from __future__ import annotations

import json
import logging
import os
import threading
from collections import defaultdict, deque
from typing import Any, Deque, Dict, Iterable, Optional

import numpy as np

logger = logging.getLogger(__name__)

_EPS = 1e-6


def _histogram(values: np.ndarray, edges: np.ndarray) -> np.ndarray:
    counts, _ = np.histogram(values, bins=edges)
    total = counts.sum()
    if total == 0:
        return np.full(len(counts), _EPS)
    return counts.astype(float) / total


def psi(baseline: np.ndarray, live: np.ndarray, n_bins: int = 10) -> float:
    """Population Stability Index for a single feature."""
    if baseline.size == 0 or live.size == 0:
        return 0.0
    edges = np.linspace(
        float(min(baseline.min(), live.min())),
        float(max(baseline.max(), live.max())) + _EPS,
        n_bins + 1,
    )
    p_base = np.maximum(_histogram(baseline, edges), _EPS)
    p_live = np.maximum(_histogram(live, edges), _EPS)
    return float(np.sum((p_live - p_base) * np.log(p_live / p_base)))


class DriftMonitor:
    """In-memory drift monitor for numeric features."""

    def __init__(self, window_size: int = 500, baseline_path: Optional[str] = None):
        self.window_size = window_size
        self.baseline_path = baseline_path
        self._windows: Dict[str, Deque[float]] = defaultdict(lambda: deque(maxlen=window_size))
        self._baselines: Dict[str, np.ndarray] = {}
        self._lock = threading.RLock()
        if baseline_path and os.path.exists(baseline_path):
            self.load_baseline(baseline_path)

    def observe(self, features: Dict[str, Any]) -> None:
        with self._lock:
            for key, value in features.items():
                try:
                    v = float(value)
                except (TypeError, ValueError):
                    continue
                if np.isnan(v) or np.isinf(v):
                    continue
                self._windows[key].append(v)

    def load_baseline(self, path: str) -> None:
        with self._lock, open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
            self._baselines = {k: np.asarray(v, dtype=float) for k, v in data.items()}
        logger.info("[drift] loaded baseline for %d feature(s) from %s", len(self._baselines), path)

    def save_baseline(self, path: str, samples: Dict[str, Iterable[float]]) -> None:
        payload = {k: list(map(float, v)) for k, v in samples.items()}
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh)
        self._baselines = {k: np.asarray(v, dtype=float) for k, v in payload.items()}
        logger.info("[drift] saved baseline with %d feature(s) to %s", len(payload), path)

    def report(self, n_bins: int = 10) -> Dict[str, Any]:
        with self._lock:
            out = {}
            for key, window in self._windows.items():
                baseline = self._baselines.get(key)
                if baseline is None or len(window) < 10:
                    continue
                score = psi(baseline, np.asarray(window, dtype=float), n_bins=n_bins)
                out[key] = {
                    "psi": round(score, 4),
                    "severity": (
                        "significant" if score > 0.25
                        else "moderate" if score > 0.1
                        else "stable"
                    ),
                    "live_n": len(window),
                }
            worst = max(out.values(), key=lambda r: r["psi"], default=None)
            return {
                "features": out,
                "window_size": self.window_size,
                "worst_psi": worst["psi"] if worst else 0.0,
            }

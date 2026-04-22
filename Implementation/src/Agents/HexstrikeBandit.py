"""
Multi-armed bandit for HexStrike enrichment tool selection.

Each attack class has a small set of available enrichment tools:
  - analyze_target        (cheap, AI narrative only)
  - analyze_target_comp   (full AI analysis)
  - nmap_scan             (real port scan)
  - nuclei_scan           (web vuln scan, for web targets)
  - check_ip_reputation   (AbuseIPDB, near-instant)

This bandit observes which tool yields useful output (non-empty, no error)
and biases future selections toward productive ones using epsilon-greedy.

Reward signal (per tool call):
  +1 if tool returned a non-empty dict with "success":true or substantive data
  -0.5 if tool errored or returned only an "error" key
   0  if tool returned an empty but non-error payload

State persists to Reports/hexstrike_bandit.json so stats survive restarts.
"""

from __future__ import annotations

import json
import logging
import os
import random
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

TOOLS = ("analyze_target", "nmap_scan", "nuclei_scan", "check_ip_reputation")


@dataclass
class ArmStats:
    pulls: int = 0
    total_reward: float = 0.0

    @property
    def mean(self) -> float:
        return self.total_reward / self.pulls if self.pulls else 0.0


@dataclass
class ClassPolicy:
    arms: Dict[str, ArmStats] = field(default_factory=lambda: {t: ArmStats() for t in TOOLS})


class HexstrikeBandit:
    """Per-attack-class epsilon-greedy bandit over enrichment tools."""

    def __init__(self, persistence_path: Optional[str] = None, epsilon: float = 0.15):
        self.epsilon = epsilon
        self.persistence_path = persistence_path
        self._lock = threading.RLock()
        self._policies: Dict[str, ClassPolicy] = {}
        self._load()

    # -- API ------------------------------------------------------------------

    def select(self, attack_class: str, available: Optional[List[str]] = None) -> str:
        """Choose a tool. epsilon-greedy over per-class means."""
        available = [t for t in (available or TOOLS) if t in TOOLS]
        if not available:
            return TOOLS[0]
        cls = (attack_class or "UNKNOWN").upper()
        with self._lock:
            pol = self._policies.setdefault(cls, ClassPolicy())
            # epsilon-greedy exploration
            if random.random() < self.epsilon:
                return random.choice(available)
            # Pick arm with best empirical mean (break ties by pulls)
            best = max(
                available,
                key=lambda t: (pol.arms[t].mean, pol.arms[t].pulls),
            )
            return best

    def reward(self, attack_class: str, tool: str, result: Any) -> float:
        """Called with the tool's raw return value; computes + records reward."""
        r = self._compute_reward(result)
        cls = (attack_class or "UNKNOWN").upper()
        with self._lock:
            pol = self._policies.setdefault(cls, ClassPolicy())
            arm = pol.arms.setdefault(tool, ArmStats())
            arm.pulls += 1
            arm.total_reward += r
        self._save()
        return r

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "epsilon": self.epsilon,
                "policies": {
                    cls: {t: {"pulls": a.pulls, "mean": round(a.mean, 3)}
                          for t, a in pol.arms.items()}
                    for cls, pol in self._policies.items()
                },
            }

    # -- helpers --------------------------------------------------------------

    @staticmethod
    def _compute_reward(result: Any) -> float:
        if not isinstance(result, dict):
            return 0.0
        if "error" in result and len(result) <= 2:
            return -0.5
        # Any of these keys signal substantive data
        substantive_keys = ("analysis", "target_profile", "open_ports", "vulnerabilities",
                            "score", "total_reports", "services", "results")
        if any(k in result for k in substantive_keys):
            return 1.0
        if result.get("success"):
            return 1.0
        return 0.0

    def _load(self) -> None:
        if not self.persistence_path or not os.path.exists(self.persistence_path):
            return
        try:
            with open(self.persistence_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            with self._lock:
                for cls, arms_data in (data.get("policies") or {}).items():
                    pol = self._policies.setdefault(cls, ClassPolicy())
                    for t, stats in arms_data.items():
                        pol.arms[t] = ArmStats(
                            pulls=int(stats.get("pulls", 0)),
                            total_reward=float(stats.get("mean", 0.0)) * int(stats.get("pulls", 0)),
                        )
        except Exception as exc:
            logger.warning("[hex-bandit] load failed: %s", exc)

    def _save(self) -> None:
        if not self.persistence_path:
            return
        try:
            os.makedirs(os.path.dirname(self.persistence_path), exist_ok=True)
            tmp = self.persistence_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.snapshot(), f, indent=2)
            os.replace(tmp, self.persistence_path)
        except Exception as exc:
            logger.debug("[hex-bandit] save failed: %s", exc)


# Process-wide singleton
_singleton: Optional[HexstrikeBandit] = None
_sing_lock = threading.Lock()


def get_bandit() -> HexstrikeBandit:
    global _singleton
    if _singleton is None:
        with _sing_lock:
            if _singleton is None:
                base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
                path = os.path.join(os.path.dirname(base_dir), "Reports", "hexstrike_bandit.json")
                _singleton = HexstrikeBandit(persistence_path=path)
    return _singleton

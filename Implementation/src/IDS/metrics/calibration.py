"""
Calibration metrics: reliability curve, Expected Calibration Error (ECE),
and Brier score.

Usage (CLI):
    python -m Implementation.src.IDS.metrics.calibration \
        --predictions Reports/predictions.csv \
        --output      Reports/calibration.json

The CSV must contain columns: y_true, y_prob (probability of the positive /
predicted class). Multi-class callers should pass the per-row maximum
softmax probability and a binary "was_correct" column (0/1) as y_true.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
from typing import Dict, List

import numpy as np

logger = logging.getLogger(__name__)


def reliability_curve(y_true: np.ndarray, y_prob: np.ndarray, n_bins: int = 10) -> Dict[str, List[float]]:
    """Return bin centres, mean predicted prob, and observed accuracy per bin."""
    bins = np.linspace(0.0, 1.0, n_bins + 1)
    bin_ids = np.digitize(y_prob, bins) - 1
    bin_ids = np.clip(bin_ids, 0, n_bins - 1)
    centres, mean_pred, mean_obs, counts = [], [], [], []
    for b in range(n_bins):
        mask = bin_ids == b
        if not mask.any():
            continue
        centres.append(float((bins[b] + bins[b + 1]) / 2))
        mean_pred.append(float(y_prob[mask].mean()))
        mean_obs.append(float(y_true[mask].mean()))
        counts.append(int(mask.sum()))
    return {"bin_center": centres, "mean_predicted": mean_pred, "mean_observed": mean_obs, "count": counts}


def expected_calibration_error(y_true: np.ndarray, y_prob: np.ndarray, n_bins: int = 10) -> float:
    bins = np.linspace(0.0, 1.0, n_bins + 1)
    bin_ids = np.digitize(y_prob, bins) - 1
    bin_ids = np.clip(bin_ids, 0, n_bins - 1)
    total = len(y_prob)
    if total == 0:
        return 0.0
    ece = 0.0
    for b in range(n_bins):
        mask = bin_ids == b
        n = int(mask.sum())
        if n == 0:
            continue
        gap = abs(y_true[mask].mean() - y_prob[mask].mean())
        ece += (n / total) * gap
    return float(ece)


def brier_score(y_true: np.ndarray, y_prob: np.ndarray) -> float:
    if len(y_prob) == 0:
        return 0.0
    return float(np.mean((y_prob - y_true) ** 2))


def compute_calibration_report(y_true: np.ndarray, y_prob: np.ndarray, n_bins: int = 10) -> Dict[str, object]:
    return {
        "n_samples": int(len(y_prob)),
        "n_bins": n_bins,
        "ece": expected_calibration_error(y_true, y_prob, n_bins),
        "brier": brier_score(y_true, y_prob),
        "reliability_curve": reliability_curve(y_true, y_prob, n_bins),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--predictions", required=True, help="CSV with y_true,y_prob columns")
    parser.add_argument("--output", required=True, help="Output JSON path")
    parser.add_argument("--bins", type=int, default=10)
    args = parser.parse_args()

    import pandas as pd

    df = pd.read_csv(args.predictions)
    if "y_true" not in df or "y_prob" not in df:
        raise SystemExit("CSV must contain y_true and y_prob columns")

    report = compute_calibration_report(
        df["y_true"].to_numpy().astype(float),
        df["y_prob"].to_numpy().astype(float),
        n_bins=args.bins,
    )
    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    logger.info("Calibration report written to %s (ECE=%.4f, Brier=%.4f)",
                args.output, report["ece"], report["brier"])


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()

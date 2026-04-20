"""
Class imbalance inspection and per-class F1 scoring.

Usage (CLI):
    python -m Implementation.src.IDS.metrics.class_balance \
        --predictions Reports/predictions.csv \
        --output      Reports/class_balance.json

Expected CSV columns: y_true (label), y_pred (label).

Resampling / focal-loss recommendation appears in the output JSON under
`recommendation` whenever the tail class support is < 1% of total samples.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
from collections import Counter
from typing import Dict

logger = logging.getLogger(__name__)


def per_class_f1(y_true, y_pred) -> Dict[str, float]:
    """Macro-free per-class F1 using only the stdlib (no sklearn dep here)."""
    labels = sorted(set(y_true) | set(y_pred))
    scores: Dict[str, float] = {}
    for label in labels:
        tp = sum(1 for t, p in zip(y_true, y_pred) if t == label and p == label)
        fp = sum(1 for t, p in zip(y_true, y_pred) if t != label and p == label)
        fn = sum(1 for t, p in zip(y_true, y_pred) if t == label and p != label)
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
        scores[str(label)] = round(f1, 4)
    return scores


def compute_report(y_true, y_pred) -> Dict[str, object]:
    support = Counter(map(str, y_true))
    total = sum(support.values())
    if total == 0:
        return {"error": "no samples"}

    shares = {k: v / total for k, v in support.items()}
    f1 = per_class_f1(list(map(str, y_true)), list(map(str, y_pred)))
    tail = [k for k, share in shares.items() if share < 0.01]
    recommendation = (
        "Consider class reweighting or focal loss; tail classes detected: " + ", ".join(tail)
        if tail
        else "Class balance within tolerance (>= 1% support per class)."
    )

    return {
        "n_samples": int(total),
        "support": dict(support),
        "share": {k: round(v, 4) for k, v in shares.items()},
        "f1_per_class": f1,
        "tail_classes": tail,
        "recommendation": recommendation,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--predictions", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    import pandas as pd

    df = pd.read_csv(args.predictions)
    if "y_true" not in df or "y_pred" not in df:
        raise SystemExit("CSV must contain y_true and y_pred columns")

    report = compute_report(df["y_true"].tolist(), df["y_pred"].tolist())
    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    logger.info("Class balance report written to %s", args.output)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()

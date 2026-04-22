"""
Temperature scaling — learns a single scalar T to divide the ANN's logits by,
so the softmax confidences match the empirical accuracy on a held-out set.

After calibration, saved to Models/calibration.json:
    { "temperature": 1.8, "ece_before": 0.23, "ece_after": 0.04 }

Callers (IDSPredictor) read this file and apply `logits / T` before softmax.

Usage:
    python -m Implementation.src.IDS.metrics.calibration_tuner \
        --predictions Reports/predictions.csv \
        --model Models/best_ids_model.pth \
        --out Models/calibration.json

CSV must contain per-row columns: y_true (class index) + y_logits (space-sep
floats) OR y_prob (softmax already applied).
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from typing import Any, Dict

logger = logging.getLogger(__name__)


def _ece(probs, labels, n_bins: int = 15) -> float:
    """Expected Calibration Error."""
    import numpy as np
    bins = np.linspace(0, 1, n_bins + 1)
    top_prob = probs.max(axis=1)
    preds = probs.argmax(axis=1)
    correct = (preds == labels).astype(float)
    ece = 0.0
    N = len(labels)
    for lo, hi in zip(bins[:-1], bins[1:]):
        mask = (top_prob > lo) & (top_prob <= hi) if lo > 0 else (top_prob >= 0) & (top_prob <= hi)
        if not mask.any():
            continue
        acc = correct[mask].mean()
        conf = top_prob[mask].mean()
        ece += (mask.sum() / N) * abs(acc - conf)
    return float(ece)


def tune_temperature(logits, labels, init_T: float = 1.0, max_iter: int = 100) -> float:
    """LBFGS on NLL with a single temperature scalar."""
    import torch

    logits_t = torch.tensor(logits, dtype=torch.float32)
    labels_t = torch.tensor(labels, dtype=torch.long)
    T = torch.tensor([init_T], requires_grad=True)
    optim = torch.optim.LBFGS([T], lr=0.1, max_iter=max_iter)
    nll = torch.nn.CrossEntropyLoss()

    def closure():
        optim.zero_grad()
        loss = nll(logits_t / T.clamp(min=0.05), labels_t)
        loss.backward()
        return loss

    optim.step(closure)
    return float(T.detach().clamp(min=0.05).item())


def calibrate_from_csv(csv_path: str, out_path: str) -> Dict[str, Any]:
    import numpy as np
    import pandas as pd

    df = pd.read_csv(csv_path)
    if "y_true" not in df.columns:
        raise ValueError("CSV must contain a y_true column")

    labels = df["y_true"].astype(int).values
    # Accept either raw logits or probabilities — temperature scaling is on logits only.
    if "y_logits" in df.columns:
        logits = np.array([[float(x) for x in s.split()] for s in df["y_logits"].astype(str)])
    elif "y_prob" in df.columns:
        # Invert softmax: log(probs) is equivalent up to a constant per-row, OK for T-scaling
        probs = np.array([[float(x) for x in s.split()] for s in df["y_prob"].astype(str)])
        logits = np.log(np.clip(probs, 1e-12, 1.0))
    else:
        raise ValueError("CSV needs y_logits or y_prob column")

    # Before
    import numpy as _np
    probs_before = _np.exp(logits) / _np.exp(logits).sum(axis=1, keepdims=True)
    ece_before = _ece(probs_before, labels)

    T = tune_temperature(logits, labels)

    # After
    scaled = logits / T
    probs_after = _np.exp(scaled) / _np.exp(scaled).sum(axis=1, keepdims=True)
    ece_after = _ece(probs_after, labels)

    result = {
        "temperature": T,
        "ece_before": round(ece_before, 4),
        "ece_after": round(ece_after, 4),
        "samples": int(len(labels)),
    }
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)
    return result


def _cli() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--predictions", required=True)
    ap.add_argument("--out", default=os.path.join("Models", "calibration.json"))
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO)
    result = calibrate_from_csv(args.predictions, args.out)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(_cli())

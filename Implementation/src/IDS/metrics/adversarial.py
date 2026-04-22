"""
Fast Gradient Sign Method (FGSM) adversarial robustness evaluation.

Produces small perturbations to the input feature vector to try to flip the
ANN's prediction. Measures attack success rate (ASR) at several epsilon
magnitudes. Output goes to Reports/adversarial_report.json.

This matters for an IDS because attackers can pad packets, adjust IAT, etc.
to move flows toward benign-looking feature vectors. ASR > 30% at eps=0.05
is a red flag for production use.

Usage:
    python -m Implementation.src.IDS.metrics.adversarial \
        --predictions Reports/predictions.csv \
        --model Models/best_ids_model.pth

CSV needs: y_true + per-feature columns matching the preprocessor output.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

DEFAULT_EPS = (0.0, 0.01, 0.02, 0.05, 0.1)


def run_fgsm(csv_path: str, out_path: str, eps_list: List[float] = None) -> Dict[str, Any]:
    import numpy as np
    import pandas as pd
    import torch
    import torch.nn.functional as F
    import joblib

    eps_list = eps_list or list(DEFAULT_EPS)
    df = pd.read_csv(csv_path)
    if "y_true" not in df.columns:
        raise ValueError("CSV must contain y_true")

    y = torch.tensor(df["y_true"].astype(int).values, dtype=torch.long)
    feature_cols = [c for c in df.columns if c != "y_true"]
    X = torch.tensor(df[feature_cols].astype(float).values, dtype=torch.float32)

    from Implementation.src.IDS.ann_model import IDSModel

    # Load model & label-encoder classes for count
    project_root = os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.dirname(os.path.abspath(__file__)))))
    project_root = os.path.dirname(project_root)  # repo root
    models_dir = os.path.join(project_root, "Models")
    label_encoder = joblib.load(os.path.join(models_dir, "label_encoder.joblib"))
    n_classes = int(len(label_encoder.classes_))

    model = IDSModel(input_size=X.shape[1], hidden_size=256, output_size=n_classes)
    ckpt_path = os.path.join(models_dir, "best_ids_model.pth")
    ckpt = torch.load(ckpt_path, map_location="cpu", weights_only=False)
    state = ckpt.get("model_state") if isinstance(ckpt, dict) else ckpt
    model.load_state_dict(state, strict=False)
    model.eval()

    per_eps: List[Dict[str, Any]] = []
    for eps in eps_list:
        X_adv = X.clone().detach().requires_grad_(True)
        out = model(X_adv)
        loss = F.cross_entropy(out, y)
        loss.backward()
        grad_sign = X_adv.grad.sign()
        with torch.no_grad():
            perturbed = X_adv + float(eps) * grad_sign
            adv_preds = model(perturbed).argmax(dim=1)
            clean_preds = model(X).argmax(dim=1)
            asr = float(((adv_preds != clean_preds) & (clean_preds == y)).float().mean().item())
            clean_acc = float((clean_preds == y).float().mean().item())
            adv_acc = float((adv_preds == y).float().mean().item())
        per_eps.append({
            "eps": float(eps),
            "clean_acc": round(clean_acc, 4),
            "adv_acc": round(adv_acc, 4),
            "attack_success_rate": round(asr, 4),
        })

    result = {
        "n_samples": int(len(y)),
        "n_features": int(X.shape[1]),
        "per_eps": per_eps,
    }
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)
    return result


def _cli() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--predictions", required=True)
    ap.add_argument("--out", default=os.path.join("Reports", "adversarial_report.json"))
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO)
    result = run_fgsm(args.predictions, args.out)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(_cli())

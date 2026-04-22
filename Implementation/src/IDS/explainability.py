"""
Flow-level explainability for IDS predictions.

Given a preprocessed feature tensor and the trained ANN, returns the top-k
features that most influenced the predicted class — using a simple
gradient × input attribution. This is the cheapest flavour of explainability
that still produces useful signal on tabular MLPs.

Usage (from IDSPredictor):
    from .explainability import explain_top_features
    attrs = explain_top_features(model, feature_tensor, feature_names, pred_idx, k=5)

Returns a list of (feature_name, attribution) sorted by |attribution| desc.
"""

from __future__ import annotations

from typing import List, Tuple


def explain_top_features(model, x_tensor, feature_names: List[str],
                         target_idx: int, k: int = 5) -> List[Tuple[str, float]]:
    """
    Gradient-based feature attribution.

    Args:
        model: PyTorch nn.Module already in eval mode.
        x_tensor: 2-D torch tensor shape (1, n_features).
        feature_names: list matching columns in x_tensor.
        target_idx: predicted class index to attribute toward.
        k: number of top features to return.

    Returns:
        list of (feature_name, signed attribution) — largest |value| first.
    """
    import torch

    if x_tensor is None or getattr(x_tensor, "ndim", 0) < 2:
        return []
    was_training = model.training
    model.eval()
    x = x_tensor.clone().detach().requires_grad_(True)
    try:
        out = model(x)
        # Target logit for the predicted class
        score = out[0, target_idx]
        score.backward()
        grad = x.grad[0].detach().cpu().numpy()  # (n_features,)
        val = x.detach().cpu().numpy()[0]
        attribution = grad * val  # input × gradient
    finally:
        if was_training:
            model.train()

    # Rank by absolute magnitude
    import numpy as _np
    order = _np.argsort(_np.abs(attribution))[::-1]
    return [(feature_names[i], float(attribution[i])) for i in order[: max(1, int(k))]]

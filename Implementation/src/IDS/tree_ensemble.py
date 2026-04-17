from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

import numpy as np

try:
    import joblib
except Exception:  # pragma: no cover
    joblib = None

from sklearn.metrics import f1_score

try:
    from sklearn.ensemble import HistGradientBoostingClassifier
except Exception:  # pragma: no cover
    HistGradientBoostingClassifier = None


@dataclass(frozen=True)
class EnsembleTuningResult:
    best_weight: float
    best_macro_f1: float
    ann_macro_f1: float
    tree_macro_f1: float


def _softmax(logits: np.ndarray) -> np.ndarray:
    logits = logits - np.max(logits, axis=1, keepdims=True)
    exp = np.exp(logits)
    return exp / np.sum(exp, axis=1, keepdims=True)


def train_tree_model(
    X_train: np.ndarray,
    y_train: np.ndarray,
    *,
    random_state: int = 42,
) -> Any:
    """
    Train a tree-based multiclass classifier.

    Uses sklearn HistGradientBoostingClassifier by default to avoid heavyweight
    external deps. Can be swapped for LightGBM/XGBoost later.
    """
    if HistGradientBoostingClassifier is None:
        raise RuntimeError("HistGradientBoostingClassifier unavailable; ensure scikit-learn is installed.")

    # Reasonable defaults for tabular IDS features
    clf = HistGradientBoostingClassifier(
        learning_rate=0.1,
        max_depth=None,
        max_iter=300,
        max_leaf_nodes=63,
        l2_regularization=0.0,
        random_state=random_state,
    )
    clf.fit(X_train, y_train)
    return clf


def save_tree_model(model: Any, path: str) -> None:
    if joblib is None:
        raise RuntimeError("joblib is required to save tree model.")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    joblib.dump(model, path)


def load_tree_model(path: str) -> Any:
    if joblib is None:
        raise RuntimeError("joblib is required to load tree model.")
    return joblib.load(path)


def predict_proba_tree(model: Any, X: np.ndarray) -> np.ndarray:
    if not hasattr(model, "predict_proba"):
        raise ValueError("Tree model must implement predict_proba().")
    return model.predict_proba(X)


def tune_ensemble_weight(
    ann_logits: np.ndarray,
    tree_proba: np.ndarray,
    y_true: np.ndarray,
    *,
    weight_grid: Optional[np.ndarray] = None,
) -> EnsembleTuningResult:
    """
    Tune fusion weight w in proba = w*ann + (1-w)*tree to maximize macro F1.
    """
    if weight_grid is None:
        weight_grid = np.linspace(0.0, 1.0, 11)

    ann_proba = _softmax(ann_logits)
    tree_proba = np.asarray(tree_proba, dtype=float)
    if ann_proba.shape != tree_proba.shape:
        raise ValueError(f"Shape mismatch: ann={ann_proba.shape} tree={tree_proba.shape}")

    ann_pred = ann_proba.argmax(axis=1)
    tree_pred = tree_proba.argmax(axis=1)
    ann_f1 = float(f1_score(y_true, ann_pred, average="macro"))
    tree_f1 = float(f1_score(y_true, tree_pred, average="macro"))

    best_w = 0.5
    best_f1 = -1.0
    for w in weight_grid:
        fused = (w * ann_proba) + ((1.0 - w) * tree_proba)
        pred = fused.argmax(axis=1)
        score = float(f1_score(y_true, pred, average="macro"))
        if score > best_f1:
            best_f1 = score
            best_w = float(w)

    return EnsembleTuningResult(
        best_weight=best_w,
        best_macro_f1=best_f1,
        ann_macro_f1=ann_f1,
        tree_macro_f1=tree_f1,
    )


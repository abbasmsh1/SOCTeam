"""
Policy distillation: train a small sklearn DecisionTreeClassifier on the RL
experience buffer, producing an interpretable "pre-filter" model.

Use cases
---------
1. Fast pre-filter: tree inference is O(depth) per flow — a few microseconds —
   so route benign predictions straight through, send only ambiguous flows to
   the ANN.
2. Explainability: `tree.tree_` exposes the decision path, which is readable
   in a way the ANN's weights are not.
3. Cross-check: a tree that agrees with the ANN on a flow is extra
   confirmation; disagreement is an audit trigger.

Usage (CLI)
-----------
python -m Implementation.src.IDS.rl.distillation \
    --db Reports/rl_experience.db \
    --out Models/distilled_tree.pkl \
    --max-depth 8
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import pickle
import sys
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


def distill(db_path: str, out_path: str, max_depth: int = 8, min_rows: int = 64) -> Dict[str, Any]:
    import numpy as np
    from sklearn.tree import DecisionTreeClassifier, export_text

    from .experience_buffer import ExperienceBuffer

    buf = ExperienceBuffer(db_path)
    rows = buf.fetch_training_batch(limit=10000)
    if len(rows) < min_rows:
        return {"status": "skipped", "rows": len(rows), "reason": f"need >= {min_rows}"}

    # Build feature matrix — union of all seen numeric feature keys
    feature_keys: List[str] = []
    seen = set()
    for r in rows:
        for k, v in (r.get("features") or {}).items():
            if k in seen:
                continue
            try:
                float(v)
                feature_keys.append(k)
                seen.add(k)
            except Exception:
                continue
    if not feature_keys:
        return {"status": "skipped", "reason": "no numeric features in buffer"}

    X: List[List[float]] = []
    y: List[str] = []
    weights: List[float] = []
    for r in rows:
        feats = r.get("features") or {}
        label = r.get("agent_label") or r.get("predicted_label")
        if not label:
            continue
        row = []
        for k in feature_keys:
            try:
                row.append(float(feats.get(k, 0) or 0))
            except Exception:
                row.append(0.0)
        X.append(row)
        y.append(label)
        weights.append(max(abs(float(r.get("reward") or 0.0)), 0.1))

    X_arr = np.array(X, dtype=np.float32)
    y_arr = np.array(y)
    tree = DecisionTreeClassifier(
        max_depth=max_depth,
        min_samples_leaf=3,
        class_weight="balanced",
        random_state=0,
    )
    tree.fit(X_arr, y_arr, sample_weight=weights)
    acc = float(tree.score(X_arr, y_arr, sample_weight=weights))

    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "wb") as f:
        pickle.dump({"tree": tree, "feature_keys": feature_keys, "acc": acc}, f)

    # Also emit a human-readable ruleset
    try:
        rules_path = os.path.splitext(out_path)[0] + ".rules.txt"
        with open(rules_path, "w", encoding="utf-8") as f:
            f.write(export_text(tree, feature_names=feature_keys, max_depth=max_depth))
    except Exception:
        rules_path = None

    return {
        "status": "trained",
        "rows": len(X),
        "features": len(feature_keys),
        "weighted_accuracy": round(acc, 4),
        "classes": tree.classes_.tolist(),
        "depth": int(tree.get_depth()),
        "leaves": int(tree.get_n_leaves()),
        "out": out_path,
        "rules": rules_path,
    }


def _cli() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default=os.path.join("Reports", "rl_experience.db"))
    ap.add_argument("--out", default=os.path.join("Models", "distilled_tree.pkl"))
    ap.add_argument("--max-depth", type=int, default=8)
    ap.add_argument("--min-rows", type=int, default=64)
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO)
    result = distill(args.db, args.out, max_depth=args.max_depth, min_rows=args.min_rows)
    print(json.dumps(result, indent=2, default=str))
    return 0 if result.get("status") == "trained" else 1


if __name__ == "__main__":
    sys.exit(_cli())

"""
Offline RL fine-tuner.

Usage
-----
python -m Implementation.src.IDS.rl.trainer --limit 500 --epochs 3 --lr 1e-4

Steps
-----
1. Pull up to `limit` labeled rows from the experience buffer.
2. Rebuild a supervised dataset: feature-vector X + target-label y, where y is
   the agent_label if present, else the predicted label flipped to BENIGN when
   is_false_positive is True.
3. Load the active IDS ANN checkpoint (Models/manifest.json).
4. Fine-tune with a small LR (default 1e-4) for a few epochs, weighted by |reward|.
5. Save the new checkpoint as Models/best_ids_model_rl_<timestamp>.pth and
   update manifest.json's active_checkpoint.
6. Mark the used rows as status='trained' so they aren't reused next round.

Guard-rails
-----------
- Refuses to train if labeled rows < MIN_ROWS (default 32).
- Keeps the old checkpoint as Models/best_ids_model_rl_<ts>.prev.pth in case
  calibration drifts. Manifest update is atomic (tmp + replace).
- No effect on the running backend until it restarts (hot-swap would race the
  predictor singleton lock).
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import logging
import os
import shutil
import sys
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


def _find_project_root() -> str:
    here = os.path.dirname(os.path.abspath(__file__))
    # rl -> IDS -> src -> Implementation -> project
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(here))))


PROJECT_ROOT = _find_project_root()
MODELS_DIR = os.path.join(PROJECT_ROOT, "Models")
MANIFEST_PATH = os.path.join(MODELS_DIR, "manifest.json")
DEFAULT_DB = os.path.join(PROJECT_ROOT, "Reports", "rl_experience.db")
MIN_ROWS = int(os.getenv("IDS_RL_MIN_ROWS", "32"))


def _load_manifest() -> Dict[str, Any]:
    if not os.path.exists(MANIFEST_PATH):
        return {"active_checkpoint": "best_ids_model.pth"}
    with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def _write_manifest(manifest: Dict[str, Any]) -> None:
    tmp = MANIFEST_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    os.replace(tmp, MANIFEST_PATH)


def _resolve_label_encoder():
    import joblib
    return joblib.load(os.path.join(MODELS_DIR, "label_encoder.joblib"))


def _build_dataset(rows: List[Dict[str, Any]], label_encoder, feature_names: List[str]):
    """Convert buffered rows → (X_tensor, y_tensor, sample_weights)."""
    import numpy as np
    import torch

    X_rows: List[List[float]] = []
    y_rows: List[int] = []
    weights: List[float] = []

    known_labels = set(label_encoder.classes_) if hasattr(label_encoder, "classes_") else set()
    benign_idx = None
    if "BENIGN" in known_labels:
        benign_idx = int(label_encoder.transform(["BENIGN"])[0])

    for r in rows:
        feats = r.get("features") or {}
        # Target: agent_label if set, else flip to BENIGN on false-positive, else predicted
        target = r.get("agent_label") or r.get("predicted_label")
        if not target:
            continue
        if r.get("is_false_positive") and benign_idx is not None:
            target = "BENIGN"
        if target not in known_labels:
            # Unknown target: skip (model can't learn a class it doesn't have)
            continue

        vec: List[float] = []
        bad = False
        for col in feature_names:
            v = feats.get(col, feats.get(col.upper(), 0))
            try:
                vec.append(float(v))
            except Exception:
                vec.append(0.0)
                bad = True
        if bad and all(x == 0.0 for x in vec):
            # Row has no usable features — skip
            continue

        X_rows.append(vec)
        y_rows.append(int(label_encoder.transform([target])[0]))
        weights.append(max(abs(float(r.get("reward") or 0.0)), 0.1))

    if not X_rows:
        return None, None, None

    X = torch.tensor(np.array(X_rows, dtype=np.float32))
    y = torch.tensor(y_rows, dtype=torch.long)
    w = torch.tensor(weights, dtype=torch.float32)
    return X, y, w


def run_training(limit: int = 500, epochs: int = 3, lr: float = 1e-4,
                 db_path: str = DEFAULT_DB, dry_run: bool = False) -> Dict[str, Any]:
    import torch
    import torch.nn.functional as F
    from Implementation.src.IDS.ann_model import IDSModel
    from Implementation.src.IDS.preprocess import InferencePreprocessor
    from .experience_buffer import ExperienceBuffer

    logger.info("Loading experience buffer from %s", db_path)
    buf = ExperienceBuffer(db_path)
    rows = buf.fetch_training_batch(limit=limit)
    logger.info("Fetched %d labeled rows", len(rows))

    if len(rows) < MIN_ROWS:
        return {
            "status": "skipped",
            "reason": f"only {len(rows)} labeled rows, need >= {MIN_ROWS}",
            "rows_available": len(rows),
        }

    # Load artifacts
    manifest = _load_manifest()
    active_ckpt = manifest.get("active_checkpoint", "best_ids_model.pth")
    active_path = os.path.join(MODELS_DIR, active_ckpt)
    logger.info("Active checkpoint: %s", active_path)

    label_encoder = _resolve_label_encoder()
    preproc = InferencePreprocessor(artifacts_dir=MODELS_DIR)
    feature_names = list(preproc.feature_names)
    n_classes = int(len(getattr(label_encoder, "classes_", [])))

    X, y, weights = _build_dataset(rows, label_encoder, feature_names)
    if X is None:
        return {"status": "skipped", "reason": "no usable training samples"}

    logger.info("Training tensor shape: X=%s y=%s classes=%d", tuple(X.shape), tuple(y.shape), n_classes)

    # Build model + load weights
    device = "cuda" if torch.cuda.is_available() else "cpu"
    model = IDSModel(input_size=len(feature_names), hidden_size=256, output_size=n_classes)
    ckpt = torch.load(active_path, map_location=device, weights_only=False)
    state = ckpt.get("model_state") if isinstance(ckpt, dict) else ckpt
    model.load_state_dict(state, strict=False)
    model.to(device).train()

    optim = torch.optim.Adam(model.parameters(), lr=lr)
    X, y, weights = X.to(device), y.to(device), weights.to(device)

    history = []
    for ep in range(epochs):
        optim.zero_grad()
        logits = model(X)
        loss_per = F.cross_entropy(logits, y, reduction="none")
        loss = (loss_per * weights).mean()
        loss.backward()
        torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
        optim.step()
        with torch.no_grad():
            acc = (logits.argmax(dim=1) == y).float().mean().item()
        history.append({"epoch": ep + 1, "loss": float(loss.item()), "acc": round(acc, 4)})
        logger.info("epoch %d  loss=%.4f  weighted_acc=%.4f", ep + 1, loss.item(), acc)

    if dry_run:
        return {
            "status": "dry_run",
            "rows_used": len(rows),
            "history": history,
        }

    # Save new checkpoint
    ts = _dt.datetime.utcnow().strftime("%Y%m%dT%H%M%S")
    new_ckpt = f"best_ids_model_rl_{ts}.pth"
    new_path = os.path.join(MODELS_DIR, new_ckpt)
    torch.save({
        "model_state": model.state_dict(),
        "source_checkpoint": active_ckpt,
        "rl_rows": len(rows),
        "history": history,
        "trained_at": ts,
    }, new_path)
    # Snapshot the previous one
    try:
        shutil.copy2(active_path, active_path + ".prev")
    except Exception:
        pass

    # Update manifest atomically
    manifest["active_checkpoint"] = new_ckpt
    manifest["previous_checkpoint"] = active_ckpt
    manifest["rl_last_trained"] = ts
    manifest["rl_history"] = (manifest.get("rl_history") or [])[-9:] + [{
        "checkpoint": new_ckpt,
        "ts": ts,
        "rows": len(rows),
        "history": history,
    }]
    _write_manifest(manifest)

    # Mark rows trained
    buf.mark_trained([r["id"] for r in rows])

    logger.info("Training complete. New checkpoint: %s", new_ckpt)
    return {
        "status": "trained",
        "checkpoint": new_ckpt,
        "rows_used": len(rows),
        "history": history,
        "restart_required": True,
    }


def _cli() -> int:
    ap = argparse.ArgumentParser(description="RL fine-tuner for IDS ANN")
    ap.add_argument("--limit", type=int, default=500)
    ap.add_argument("--epochs", type=int, default=3)
    ap.add_argument("--lr", type=float, default=1e-4)
    ap.add_argument("--db", type=str, default=DEFAULT_DB)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    result = run_training(
        limit=args.limit, epochs=args.epochs, lr=args.lr,
        db_path=args.db, dry_run=args.dry_run,
    )
    print(json.dumps(result, indent=2, default=str))
    return 0 if result.get("status") in ("trained", "dry_run") else 1


if __name__ == "__main__":
    sys.exit(_cli())

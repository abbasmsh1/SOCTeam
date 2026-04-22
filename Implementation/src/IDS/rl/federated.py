"""
Federated fine-tuning scaffold.

Design: each SOC instance computes local gradient deltas from its own RL
experience buffer, serialises them, and POSTs them to an aggregator. The
aggregator averages (FedAvg) and returns a merged delta that clients apply
to their local model. Raw flow features never leave the client.

This file provides the minimum viable pieces:
  - LocalClient: computes gradient delta over a local batch
  - FedAvgAggregator: averages deltas from multiple clients, returns merged
  - Plain HTTP transport (requests) is sketched in the CLI demo.

Security notes (deliberately out of scope for this scaffold):
  - Production would layer in differential privacy noise at the client, secure
    aggregation (e.g. Bonawitz masking), and TLS + client authentication.
  - Treat this as a proof-of-concept for the paper / thesis chapter, NOT as
    hardened federated infrastructure.

Usage (demo):
    python -m Implementation.src.IDS.rl.federated --role client --server http://...
    python -m Implementation.src.IDS.rl.federated --role server --port 7070
"""

from __future__ import annotations

import argparse
import base64
import io
import json
import logging
import os
import sys
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


def _serialize_state(state_dict: Dict[str, Any]) -> str:
    import torch
    buf = io.BytesIO()
    torch.save(state_dict, buf)
    return base64.b64encode(buf.getvalue()).decode("ascii")


def _deserialize_state(blob: str) -> Dict[str, Any]:
    import torch
    return torch.load(io.BytesIO(base64.b64decode(blob)), map_location="cpu", weights_only=False)


class LocalClient:
    """Client side — trains one round on the local buffer and emits a delta."""

    def __init__(self, checkpoint_path: str, buffer_db: str, lr: float = 1e-4, batch: int = 128):
        self.checkpoint_path = checkpoint_path
        self.buffer_db = buffer_db
        self.lr = lr
        self.batch = batch

    def compute_delta(self) -> Dict[str, Any]:
        import torch
        import torch.nn.functional as F

        from Implementation.src.IDS.ann_model import IDSModel
        from Implementation.src.IDS.preprocess import InferencePreprocessor
        from .experience_buffer import ExperienceBuffer

        buf = ExperienceBuffer(self.buffer_db)
        rows = buf.fetch_training_batch(limit=self.batch)
        if len(rows) < 8:
            return {"status": "skipped", "rows": len(rows)}

        ckpt = torch.load(self.checkpoint_path, map_location="cpu", weights_only=False)
        state_before = ckpt.get("model_state") if isinstance(ckpt, dict) else ckpt

        # Quick sanity check — same shape as federated trainer expects
        if not isinstance(state_before, dict):
            return {"status": "skipped", "reason": "unexpected checkpoint format"}

        # Build X/y from buffer using the same pipeline as trainer.py
        import joblib, numpy as _np
        models_dir = os.path.dirname(os.path.abspath(self.checkpoint_path))
        label_encoder = joblib.load(os.path.join(models_dir, "label_encoder.joblib"))
        preproc = InferencePreprocessor(artifacts_dir=models_dir)
        feature_names = list(preproc.feature_names)

        X_rows, y_rows = [], []
        for r in rows:
            feats = r.get("features") or {}
            target = r.get("agent_label") or r.get("predicted_label")
            if not target or target not in set(label_encoder.classes_):
                continue
            vec = [float(feats.get(c, feats.get(c.upper(), 0)) or 0) for c in feature_names]
            X_rows.append(vec)
            y_rows.append(int(label_encoder.transform([target])[0]))

        if not X_rows:
            return {"status": "skipped", "reason": "no usable rows"}

        X = torch.tensor(_np.array(X_rows, dtype=_np.float32))
        y = torch.tensor(y_rows, dtype=torch.long)

        model = IDSModel(input_size=len(feature_names), hidden_size=256,
                         output_size=int(len(label_encoder.classes_)))
        model.load_state_dict(state_before, strict=False)
        model.train()
        optim = torch.optim.Adam(model.parameters(), lr=self.lr)
        optim.zero_grad()
        loss = F.cross_entropy(model(X), y)
        loss.backward()
        optim.step()

        state_after = model.state_dict()
        # Delta = after - before, param-by-param
        delta = {k: (state_after[k] - state_before.get(k, state_after[k])).cpu()
                 for k in state_after.keys()}
        return {
            "status": "ok",
            "rows_used": len(X_rows),
            "loss": float(loss.item()),
            "delta_b64": _serialize_state(delta),
        }


class FedAvgAggregator:
    """Server side — averages deltas from multiple clients (FedAvg)."""

    def __init__(self):
        self._rounds: List[Dict[str, Any]] = []

    def aggregate(self, client_deltas_b64: List[str]) -> str:
        """
        Average the supplied deltas, return merged delta as b64-serialised state.
        """
        import torch
        if not client_deltas_b64:
            raise ValueError("no client deltas submitted")
        deltas = [_deserialize_state(b) for b in client_deltas_b64]
        # Average each tensor
        merged: Dict[str, Any] = {}
        for key in deltas[0].keys():
            tensors = [d[key] for d in deltas if key in d]
            merged[key] = torch.stack(tensors, dim=0).mean(dim=0)
        self._rounds.append({"clients": len(client_deltas_b64)})
        return _serialize_state(merged)


def _cli_client(args) -> int:
    import requests
    client = LocalClient(
        checkpoint_path=args.checkpoint,
        buffer_db=args.db,
        lr=args.lr,
    )
    payload = client.compute_delta()
    if payload.get("status") != "ok":
        print(json.dumps(payload))
        return 1
    resp = requests.post(
        f"{args.server.rstrip('/')}/submit",
        json={"delta_b64": payload["delta_b64"]},
        timeout=60,
    )
    print(json.dumps({"client": payload.get("rows_used"), "server": resp.status_code}))
    return 0 if resp.ok else 2


def _cli_server(args) -> int:
    """Tiny FastAPI aggregator — accepts /submit and periodically /round."""
    import uvicorn
    from fastapi import FastAPI
    from pydantic import BaseModel
    app = FastAPI(title="FedAvg aggregator")
    aggregator = FedAvgAggregator()
    pending: List[str] = []

    class SubmitBody(BaseModel):
        delta_b64: str

    @app.post("/submit")
    def submit(body: SubmitBody):
        pending.append(body.delta_b64)
        return {"status": "queued", "pending": len(pending)}

    @app.post("/round")
    def run_round(min_clients: int = 2):
        if len(pending) < min_clients:
            return {"status": "waiting", "pending": len(pending)}
        merged = aggregator.aggregate(pending)
        pending.clear()
        return {"status": "merged", "delta_b64": merged}

    uvicorn.run(app, host="127.0.0.1", port=args.port)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--role", choices=("client", "server"), required=True)
    ap.add_argument("--server", default="http://127.0.0.1:7070", help="client: aggregator URL")
    ap.add_argument("--port", type=int, default=7070)
    ap.add_argument("--checkpoint", default=os.path.join("Models", "best_ids_model.pth"))
    ap.add_argument("--db", default=os.path.join("Reports", "rl_experience.db"))
    ap.add_argument("--lr", type=float, default=1e-4)
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO)
    return _cli_server(args) if args.role == "server" else _cli_client(args)


if __name__ == "__main__":
    sys.exit(main())

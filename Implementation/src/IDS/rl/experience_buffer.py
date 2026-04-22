"""
SQLite-backed replay buffer for RL feedback.

Every /predict call appends a "pending" row. The SOC workflow finalize hook
and quarantine allow/deny endpoints update the same row with an agent verdict
+ reward once the tiered analysis (or human) produces a judgment.

Schema
------
experience(
    id INTEGER PK,
    ts TEXT,                -- ISO timestamp of prediction
    alert_id TEXT,          -- SOC workflow's UNK-xxxx id if queued
    src_ip TEXT,
    dst_ip TEXT,
    features TEXT,          -- JSON of normalised flow features
    predicted_label TEXT,
    predicted_idx INTEGER,
    predicted_confidence REAL,
    agent_label TEXT,       -- filled post-workflow (tier-validated label)
    agent_severity TEXT,    -- low/medium/high/critical
    is_false_positive INTEGER,  -- 0/1 from Tier 1
    human_decision TEXT,    -- allow/deny from quarantine
    reward REAL,            -- numeric reward in [-1, +1]
    status TEXT,            -- pending | labeled | trained | validated
    updated_ts TEXT
)
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import sqlite3
import threading
from typing import Any, Dict, Iterable, List, Optional


class ExperienceBuffer:
    """Thread-safe SQLite-backed RL experience buffer."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._lock = threading.RLock()
        os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
        self._ensure_schema()

    # -- connection helpers ---------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    def _ensure_schema(self) -> None:
        with self._lock, self._connect() as c:
            c.executescript(
                """
                CREATE TABLE IF NOT EXISTS experience (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT NOT NULL,
                    alert_id TEXT,
                    src_ip TEXT,
                    dst_ip TEXT,
                    features TEXT NOT NULL,
                    predicted_label TEXT NOT NULL,
                    predicted_idx INTEGER,
                    predicted_confidence REAL,
                    agent_label TEXT,
                    agent_severity TEXT,
                    is_false_positive INTEGER,
                    human_decision TEXT,
                    reward REAL,
                    status TEXT NOT NULL DEFAULT 'pending',
                    updated_ts TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_exp_status ON experience(status);
                CREATE INDEX IF NOT EXISTS idx_exp_src_ip ON experience(src_ip);
                CREATE INDEX IF NOT EXISTS idx_exp_alert ON experience(alert_id);
                CREATE INDEX IF NOT EXISTS idx_exp_ts ON experience(ts);
                """
            )

    # -- writes ---------------------------------------------------------------

    def record_prediction(
        self,
        features: Dict[str, Any],
        predicted_label: str,
        predicted_idx: Optional[int],
        predicted_confidence: float,
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        alert_id: Optional[str] = None,
    ) -> int:
        """Insert an experience row. Returns its id.

        BENIGN predictions are auto-labeled on insert (status='labeled',
        agent_label='BENIGN', is_false_positive=0, reward=0) so that the
        trainer has a clean negative class without waiting for a workflow
        or human to touch them. Disable with IDS_RL_AUTO_LABEL_BENIGN=false.
        """
        now = _dt.datetime.utcnow().isoformat()
        auto_label_benign = os.getenv("IDS_RL_AUTO_LABEL_BENIGN", "true").lower() not in ("false", "0", "no")
        is_benign = auto_label_benign and str(predicted_label).upper() == "BENIGN"

        status = "labeled" if is_benign else "pending"
        agent_label = "BENIGN" if is_benign else None
        is_fp = 0 if is_benign else None      # correct BENIGN is a TRUE NEGATIVE, not FP
        reward = 0.0 if is_benign else None   # zero-reward anchor; trainer can re-weight

        with self._lock, self._connect() as c:
            cur = c.execute(
                "INSERT INTO experience("
                "ts, alert_id, src_ip, dst_ip, features, predicted_label, "
                "predicted_idx, predicted_confidence, agent_label, "
                "is_false_positive, reward, status, updated_ts) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    now, alert_id, src_ip, dst_ip,
                    json.dumps(self._json_safe(features)),
                    predicted_label,
                    predicted_idx,
                    float(predicted_confidence or 0.0),
                    agent_label,
                    is_fp,
                    reward,
                    status,
                    now,
                ),
            )
            return int(cur.lastrowid)

    def label_by_alert(
        self,
        alert_id: str,
        agent_label: Optional[str] = None,
        agent_severity: Optional[str] = None,
        is_false_positive: Optional[bool] = None,
        reward: Optional[float] = None,
    ) -> int:
        """Update the row(s) tagged with this SOC alert id. Returns row count updated."""
        now = _dt.datetime.utcnow().isoformat()
        with self._lock, self._connect() as c:
            cur = c.execute(
                "UPDATE experience SET "
                "agent_label = COALESCE(?, agent_label), "
                "agent_severity = COALESCE(?, agent_severity), "
                "is_false_positive = COALESCE(?, is_false_positive), "
                "reward = COALESCE(?, reward), "
                "status = CASE WHEN ? IS NOT NULL OR ? IS NOT NULL "
                "              THEN 'labeled' ELSE status END, "
                "updated_ts = ? "
                "WHERE alert_id = ?",
                (
                    agent_label,
                    agent_severity,
                    None if is_false_positive is None else int(bool(is_false_positive)),
                    reward,
                    agent_label, reward,
                    now,
                    alert_id,
                ),
            )
            return cur.rowcount

    def label_by_src_ip(
        self,
        src_ip: str,
        human_decision: str,
        reward: float,
        max_rows: int = 5,
    ) -> int:
        """
        Backfill labels onto the most recent pending rows for an IP based on a
        human allow/deny decision. Limits how far back we attribute the signal
        so one late decision doesn't overwrite ancient predictions.
        """
        now = _dt.datetime.utcnow().isoformat()
        with self._lock, self._connect() as c:
            ids = [
                r["id"] for r in c.execute(
                    "SELECT id FROM experience WHERE src_ip = ? AND status = 'pending' "
                    "ORDER BY id DESC LIMIT ?",
                    (src_ip, max_rows),
                ).fetchall()
            ]
            if not ids:
                return 0
            placeholders = ",".join("?" for _ in ids)
            c.execute(
                f"UPDATE experience SET "
                f"human_decision = ?, reward = ?, status = 'labeled', updated_ts = ? "
                f"WHERE id IN ({placeholders})",
                (human_decision, reward, now, *ids),
            )
            return len(ids)

    def heuristic_sweep(
        self,
        *,
        whitelist_ips: Optional[Iterable[str]] = None,
        blocklist_ips: Optional[Iterable[str]] = None,
        reputation_lookup: Optional[Any] = None,    # callable: ip -> reputation obj w/ .abuse_score
        max_age_days: Optional[int] = None,
        max_rows: int = 500,
    ) -> Dict[str, int]:
        """
        Auto-label pending rows based on side-signal heuristics — a cheap,
        low-quality fallback for when no SOC workflow fires and no human
        touches the quarantine page. The signals, in priority order:

          1. src_ip in `whitelist_ips`  → true positive? No — whitelist is
             operator-attested benign, so the prediction was a FALSE POSITIVE.
             reward = -0.4 (negative: model was wrong).
          2. src_ip in `blocklist_ips`  → operator-attested malicious, so
             the prediction (whatever the label) is a true positive on the
             flow being bad. reward = +0.4.
          3. reputation_lookup(ip).abuse_score >= 75 (AbuseIPDB-high) →
             strong external signal the IP is malicious. reward = +0.3.
          4. reputation_lookup(ip).abuse_score < 10 AND row older than
             `max_age_days`  → probably a benign noise row that nothing
             ever cared about. reward = 0. Label as 'abandoned' via
             agent_label so the trainer can optionally exclude it.

        Returns per-bucket counts. Rows already labeled are never touched.
        """
        reward_wl = -0.4
        reward_bl = 0.4
        reward_rep_high = 0.3
        counts = {"whitelist_fp": 0, "blocklist_tp": 0, "reputation_tp": 0, "abandoned": 0, "skipped": 0}

        wl = set(whitelist_ips or [])
        bl = set(blocklist_ips or [])
        now = _dt.datetime.utcnow()
        now_iso = now.isoformat()
        cutoff_iso = (
            (now - _dt.timedelta(days=max_age_days)).isoformat()
            if max_age_days is not None
            else None
        )

        with self._lock, self._connect() as c:
            pending = c.execute(
                "SELECT id, src_ip, predicted_label, predicted_confidence, ts "
                "FROM experience WHERE status = 'pending' "
                "ORDER BY id DESC LIMIT ?",
                (max_rows,),
            ).fetchall()

            for row in pending:
                rid = row["id"]
                ip = (row["src_ip"] or "").strip()
                updated = False

                # 1. Whitelist → false positive
                if ip and ip in wl:
                    c.execute(
                        "UPDATE experience SET agent_label = ?, is_false_positive = 1, "
                        "reward = ?, status = 'labeled', updated_ts = ?, "
                        "human_decision = COALESCE(human_decision, 'heuristic_whitelist') "
                        "WHERE id = ?",
                        ("BENIGN", reward_wl, now_iso, rid),
                    )
                    counts["whitelist_fp"] += 1
                    continue

                # 2. Blocklist → true positive
                if ip and ip in bl:
                    c.execute(
                        "UPDATE experience SET agent_label = ?, is_false_positive = 0, "
                        "reward = ?, status = 'labeled', updated_ts = ?, "
                        "human_decision = COALESCE(human_decision, 'heuristic_blocklist') "
                        "WHERE id = ?",
                        (row["predicted_label"], reward_bl, now_iso, rid),
                    )
                    counts["blocklist_tp"] += 1
                    continue

                # 3. External reputation
                score = None
                if reputation_lookup and ip:
                    try:
                        rep = reputation_lookup(ip)
                        score = getattr(rep, "abuse_score", None)
                    except Exception:
                        score = None

                if score is not None and score >= 75:
                    c.execute(
                        "UPDATE experience SET agent_label = ?, is_false_positive = 0, "
                        "reward = ?, status = 'labeled', updated_ts = ?, "
                        "human_decision = COALESCE(human_decision, 'heuristic_reputation') "
                        "WHERE id = ?",
                        (row["predicted_label"], reward_rep_high, now_iso, rid),
                    )
                    counts["reputation_tp"] += 1
                    continue

                # 4. Abandonment — benign-ish and old enough
                if cutoff_iso and row["ts"] < cutoff_iso and (score is None or score < 10):
                    c.execute(
                        "UPDATE experience SET agent_label = ?, is_false_positive = 1, "
                        "reward = 0, status = 'labeled', updated_ts = ?, "
                        "human_decision = COALESCE(human_decision, 'heuristic_abandoned') "
                        "WHERE id = ?",
                        ("ABANDONED", now_iso, rid),
                    )
                    counts["abandoned"] += 1
                    continue

                counts["skipped"] += 1

        return counts

    def mark_trained(self, row_ids: Iterable[int]) -> int:
        now = _dt.datetime.utcnow().isoformat()
        row_ids = list(row_ids)
        if not row_ids:
            return 0
        placeholders = ",".join("?" for _ in row_ids)
        with self._lock, self._connect() as c:
            c.execute(
                f"UPDATE experience SET status = 'trained', updated_ts = ? "
                f"WHERE id IN ({placeholders})",
                (now, *row_ids),
            )
        return len(row_ids)

    # -- reads ----------------------------------------------------------------

    def stats(self) -> Dict[str, Any]:
        with self._lock, self._connect() as c:
            by_status = {
                r["status"]: r["n"] for r in c.execute(
                    "SELECT status, COUNT(*) AS n FROM experience GROUP BY status"
                ).fetchall()
            }
            total = sum(by_status.values())
            avg_reward = c.execute(
                "SELECT AVG(reward) AS r FROM experience WHERE reward IS NOT NULL"
            ).fetchone()["r"] or 0.0
            latest = c.execute(
                "SELECT ts FROM experience ORDER BY id DESC LIMIT 1"
            ).fetchone()
            per_class = {
                r["predicted_label"]: {"n": r["n"], "avg_conf": round(r["c"] or 0, 3)}
                for r in c.execute(
                    "SELECT predicted_label, COUNT(*) AS n, "
                    "AVG(predicted_confidence) AS c FROM experience "
                    "GROUP BY predicted_label ORDER BY n DESC LIMIT 15"
                ).fetchall()
            }
            fp_by_class = {
                r["predicted_label"]: r["fp_rate"]
                for r in c.execute(
                    "SELECT predicted_label, "
                    "AVG(CAST(is_false_positive AS REAL)) AS fp_rate "
                    "FROM experience WHERE is_false_positive IS NOT NULL "
                    "GROUP BY predicted_label"
                ).fetchall()
            }
        return {
            "total": total,
            "by_status": by_status,
            "avg_reward": round(avg_reward, 4),
            "latest_ts": latest["ts"] if latest else None,
            "per_class": per_class,
            "fp_rate_by_class": {k: round(v, 4) for k, v in fp_by_class.items()},
        }

    def fetch_training_batch(self, limit: int = 500) -> List[Dict[str, Any]]:
        """
        Pull labeled rows ready for training. Prefers rows with an explicit
        agent_label, falling back to reward-only rows (training target inferred
        from is_false_positive + predicted_label).
        """
        with self._lock, self._connect() as c:
            rows = c.execute(
                "SELECT * FROM experience WHERE status = 'labeled' "
                "ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        out: List[Dict[str, Any]] = []
        for r in rows:
            d = dict(r)
            try:
                d["features"] = json.loads(d["features"])
            except Exception:
                d["features"] = {}
            out.append(d)
        return out

    # -- helpers --------------------------------------------------------------

    @staticmethod
    def _json_safe(obj: Any) -> Any:
        """Recursively coerce obj into something json.dumps can handle."""
        if isinstance(obj, dict):
            return {str(k): ExperienceBuffer._json_safe(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [ExperienceBuffer._json_safe(v) for v in obj]
        if isinstance(obj, (str, int, float, bool)) or obj is None:
            return obj
        return str(obj)

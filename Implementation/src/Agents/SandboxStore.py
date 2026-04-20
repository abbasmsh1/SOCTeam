"""
SQLite-backed persistent store for DefensiveActionSandbox.

Replaces the prior single-JSON-file persistence with a small SQLite DAO so
read/modify/write cycles survive concurrent requests. The public API matches
what DefensiveActionSandbox.load_state()/save_state() already return — a dict
with the same keys — so the swap is transparent to callers.

Schema (all rows keyed by a short `kind` discriminator in the `entities`
table, plus a single `history` append-only table):

  entities(kind TEXT, id TEXT, data JSON, PRIMARY KEY(kind, id))
  history(seq INTEGER PRIMARY KEY AUTOINCREMENT, data JSON, ts TEXT)

The `kind` takes one of:
  blocked_ips, blocked_subnets, isolation_network, rate_limits,
  isolated_hosts, firewall_rules

Append-only lists (`tcp_resets`, `enrichment_queue`, `password_resets`,
`siem_tuning`, `threat_escalations`) are stored as history rows too, using a
`kind` prefix like `queue:tcp_resets`.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from typing import Any, Dict, List, Optional

_MAP_KINDS = (
    "blocked_ips",
    "blocked_subnets",
    "isolation_network",
    "rate_limits",
    "isolated_hosts",
)

_QUEUE_KINDS = (
    "tcp_resets",
    "enrichment_queue",
    "password_resets",
    "siem_tuning",
    "threat_escalations",
)


class SandboxStore:
    """SQLite persistence for DefensiveActionSandbox state."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._lock = threading.RLock()
        os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
        self._ensure_schema()

    # -- Connection management ------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, isolation_level=None)  # autocommit
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    def _ensure_schema(self) -> None:
        with self._lock, self._connect() as c:
            c.executescript(
                """
                CREATE TABLE IF NOT EXISTS entities (
                    kind TEXT NOT NULL,
                    id   TEXT NOT NULL,
                    data TEXT NOT NULL,
                    PRIMARY KEY (kind, id)
                );
                CREATE TABLE IF NOT EXISTS history (
                    seq  INTEGER PRIMARY KEY AUTOINCREMENT,
                    kind TEXT NOT NULL,
                    data TEXT NOT NULL,
                    ts   TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_history_kind ON history(kind);
                """
            )

    # -- Snapshot helpers -----------------------------------------------------

    def load_state(self) -> Dict[str, Any]:
        """Return state dict shaped like the legacy JSON file."""
        state: Dict[str, Any] = {k: {} for k in _MAP_KINDS}
        state["firewall_rules"] = []
        for q in _QUEUE_KINDS:
            state[q] = []
        state["history"] = []

        with self._lock, self._connect() as c:
            for row in c.execute("SELECT kind, id, data FROM entities"):
                data = json.loads(row["data"])
                kind = row["kind"]
                if kind in _MAP_KINDS:
                    state[kind][row["id"]] = data
                elif kind == "firewall_rules":
                    state["firewall_rules"].append(data)
            for q in _QUEUE_KINDS:
                cur = c.execute(
                    "SELECT data FROM history WHERE kind = ? ORDER BY seq ASC",
                    (f"queue:{q}",),
                )
                state[q] = [json.loads(r["data"]) for r in cur.fetchall()]
            cur = c.execute(
                "SELECT data FROM history WHERE kind = ? ORDER BY seq DESC LIMIT 100",
                ("action",),
            )
            state["history"] = list(reversed([json.loads(r["data"]) for r in cur.fetchall()]))

        state["firewall_rules"].sort(key=lambda x: x.get("priority", 100))
        return state

    def save_state(self, state: Dict[str, Any]) -> None:
        """Replace persisted state with the provided snapshot (used for clear/migrate)."""
        with self._lock, self._connect() as c:
            c.execute("BEGIN")
            try:
                c.execute("DELETE FROM entities")
                c.execute("DELETE FROM history")

                for kind in _MAP_KINDS:
                    for entry_id, entry in (state.get(kind) or {}).items():
                        c.execute(
                            "INSERT INTO entities(kind, id, data) VALUES(?, ?, ?)",
                            (kind, entry_id, json.dumps(entry)),
                        )
                for rule in state.get("firewall_rules", []) or []:
                    if not isinstance(rule, dict):
                        continue
                    c.execute(
                        "INSERT OR REPLACE INTO entities(kind, id, data) VALUES(?, ?, ?)",
                        ("firewall_rules", rule.get("id", f"rule-{id(rule)}"), json.dumps(rule)),
                    )
                for q in _QUEUE_KINDS:
                    for item in state.get(q, []) or []:
                        c.execute(
                            "INSERT INTO history(kind, data, ts) VALUES(?, ?, ?)",
                            (f"queue:{q}", json.dumps(item), item.get("timestamp", "")),
                        )
                for entry in (state.get("history") or [])[-100:]:
                    c.execute(
                        "INSERT INTO history(kind, data, ts) VALUES(?, ?, ?)",
                        ("action", json.dumps(entry), entry.get("timestamp", "")),
                    )
                c.execute("COMMIT")
            except Exception:
                c.execute("ROLLBACK")
                raise

    # -- Fine-grained mutations (used by DefensiveActionSandbox handlers) ----

    def upsert_entity(self, kind: str, entity_id: str, data: Dict[str, Any]) -> None:
        with self._lock, self._connect() as c:
            c.execute(
                "INSERT OR REPLACE INTO entities(kind, id, data) VALUES(?, ?, ?)",
                (kind, entity_id, json.dumps(data)),
            )

    def delete_entity(self, kind: str, entity_id: str) -> None:
        with self._lock, self._connect() as c:
            c.execute("DELETE FROM entities WHERE kind = ? AND id = ?", (kind, entity_id))

    def append_queue(self, queue_name: str, item: Dict[str, Any]) -> None:
        with self._lock, self._connect() as c:
            c.execute(
                "INSERT INTO history(kind, data, ts) VALUES(?, ?, ?)",
                (f"queue:{queue_name}", json.dumps(item), item.get("timestamp", "")),
            )

    def append_history(self, entry: Dict[str, Any]) -> None:
        with self._lock, self._connect() as c:
            c.execute(
                "INSERT INTO history(kind, data, ts) VALUES(?, ?, ?)",
                ("action", json.dumps(entry), entry.get("timestamp", "")),
            )
            c.execute(
                "DELETE FROM history WHERE kind = 'action' AND seq NOT IN "
                "(SELECT seq FROM history WHERE kind = 'action' ORDER BY seq DESC LIMIT 100)"
            )

    # -- Migration ------------------------------------------------------------

    def migrate_from_json(self, json_path: str) -> bool:
        """If `json_path` exists and the DB is empty, import it. Returns True on import."""
        if not os.path.exists(json_path):
            return False
        with self._lock, self._connect() as c:
            count = c.execute("SELECT COUNT(*) AS n FROM entities").fetchone()["n"]
            if count:
                return False
        try:
            with open(json_path, "r", encoding="utf-8") as fh:
                snapshot = json.load(fh)
        except (OSError, json.JSONDecodeError):
            return False
        self.save_state(snapshot)
        try:
            os.replace(json_path, json_path + ".migrated")
        except OSError:
            pass
        return True

    def clear(self) -> None:
        with self._lock, self._connect() as c:
            c.execute("DELETE FROM entities")
            c.execute("DELETE FROM history")

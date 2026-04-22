"""
Incident graph — lightweight NetworkX-backed store of relationships between
IPs, attack types, sandbox rules, and analyst decisions.

Purpose: enable queries like "show me all incidents involving X", "which IPs
attacked this destination", "what rules were derived from this attack class"
without touching the relational DB.

Kept deliberately small (pure in-memory, thread-safe via a single lock) so it
serves as a reference implementation — swap in Neo4j / Memgraph if the graph
grows beyond ~50k nodes.

Node kinds: ip, attack, rule, incident, analyst
Edge kinds: involved_in, classified_as, triggered, decided
"""

from __future__ import annotations

import datetime as _dt
import threading
from typing import Any, Dict, Iterable, List, Optional

try:
    import networkx as nx
except ImportError:  # pragma: no cover
    nx = None  # type: ignore


class IncidentGraph:
    """Thread-safe in-memory incident graph."""

    def __init__(self) -> None:
        if nx is None:
            raise ImportError("networkx is required for IncidentGraph. pip install networkx")
        self._g = nx.MultiDiGraph()
        self._lock = threading.RLock()

    # -- ingest ---------------------------------------------------------------

    def record_incident(
        self,
        incident_id: str,
        src_ip: Optional[str],
        dst_ip: Optional[str],
        attack_type: Optional[str],
        severity: Optional[str] = None,
        rule_ids: Optional[Iterable[str]] = None,
        analyst: Optional[str] = None,
        decision: Optional[str] = None,
    ) -> None:
        ts = _dt.datetime.utcnow().isoformat()
        with self._lock:
            self._g.add_node(incident_id, kind="incident", severity=severity, ts=ts)
            for ip, role in ((src_ip, "source"), (dst_ip, "target")):
                if ip and ip != "Unknown":
                    self._g.add_node(ip, kind="ip")
                    self._g.add_edge(ip, incident_id, kind="involved_in", role=role, ts=ts)
            if attack_type:
                self._g.add_node(attack_type, kind="attack")
                self._g.add_edge(incident_id, attack_type, kind="classified_as", ts=ts)
            for rid in (rule_ids or []):
                self._g.add_node(rid, kind="rule")
                self._g.add_edge(incident_id, rid, kind="triggered", ts=ts)
            if analyst and decision:
                self._g.add_node(analyst, kind="analyst")
                self._g.add_edge(
                    analyst, incident_id, kind="decided",
                    decision=decision, ts=ts,
                )

    # -- queries --------------------------------------------------------------

    def incidents_for_ip(self, ip: str, limit: int = 25) -> List[Dict[str, Any]]:
        with self._lock:
            if ip not in self._g:
                return []
            out: List[Dict[str, Any]] = []
            for _, nbr, data in self._g.out_edges(ip, data=True):
                if data.get("kind") == "involved_in":
                    node = self._g.nodes[nbr]
                    out.append({
                        "incident_id": nbr,
                        "role": data.get("role"),
                        "severity": node.get("severity"),
                        "ts": node.get("ts"),
                    })
            out.sort(key=lambda r: r.get("ts") or "", reverse=True)
            return out[:limit]

    def ips_for_attack(self, attack_type: str, limit: int = 25) -> List[str]:
        with self._lock:
            if attack_type not in self._g:
                return []
            incident_ids = [
                u for u, _, d in self._g.in_edges(attack_type, data=True)
                if d.get("kind") == "classified_as"
            ]
            ips: Dict[str, int] = {}
            for inc in incident_ids:
                for ip, _, d in self._g.in_edges(inc, data=True):
                    if self._g.nodes[ip].get("kind") == "ip":
                        ips[ip] = ips.get(ip, 0) + 1
            return [ip for ip, _ in sorted(ips.items(), key=lambda x: -x[1])[:limit]]

    def summary(self) -> Dict[str, Any]:
        with self._lock:
            kinds: Dict[str, int] = {}
            for _, d in self._g.nodes(data=True):
                kinds[d.get("kind", "unknown")] = kinds.get(d.get("kind", "unknown"), 0) + 1
            return {
                "nodes": self._g.number_of_nodes(),
                "edges": self._g.number_of_edges(),
                "by_kind": kinds,
            }


# Process-wide singleton (lazy)
_singleton: Optional[IncidentGraph] = None
_sing_lock = threading.Lock()


def get_incident_graph() -> IncidentGraph:
    global _singleton
    if _singleton is None:
        with _sing_lock:
            if _singleton is None:
                _singleton = IncidentGraph()
    return _singleton

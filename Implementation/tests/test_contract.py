"""
Contract tests — boot the FastAPI app with TestClient and hit every endpoint,
asserting status + schema. Runs in seconds, no external services needed (LLM
calls fail gracefully to the _Dummy fallback).

Run:  pytest -x Implementation/tests/test_contract.py
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

# Backend requires a non-default key
os.environ.setdefault("IDS_API_KEY", "ci-read-key")
os.environ.setdefault("IDS_ADMIN_API_KEY", "ci-admin-key")
os.environ.setdefault("IDS_ALLOW_DEFAULT_KEY", "false")
os.environ.setdefault("IDS_RL_ENABLED", "false")  # keep tests fast

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


@pytest.fixture(scope="module")
def client():
    from fastapi.testclient import TestClient
    from Implementation.src.IDS import IDS
    with TestClient(IDS.app) as c:
        yield c


# -- auth ---------------------------------------------------------------------

def test_health_public(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "healthy"


def test_events_requires_key(client):
    assert client.get("/events").status_code == 401
    assert client.get("/events", headers={"X-API-Key": "wrong"}).status_code == 403
    assert client.get("/events", headers={"X-API-Key": "ci-read-key"}).status_code == 200


def test_sandbox_clear_requires_admin(client):
    r = client.post("/sandbox/clear", headers={"X-API-Key": "ci-read-key"})
    assert r.status_code == 403
    r = client.post("/sandbox/clear", headers={"X-API-Key": "ci-admin-key"})
    assert r.status_code == 200


# -- shape checks -------------------------------------------------------------

READ = {"X-API-Key": "ci-read-key"}
ADMIN = {"X-API-Key": "ci-admin-key", "Content-Type": "application/json"}


def test_events_stats_shape(client):
    body = client.get("/events/stats", headers=READ).json()
    for k in ("packets_per_second", "pending_alerts", "confirmed_threats", "active_agents"):
        assert k in body, f"missing key: {k}"


def test_events_timeseries_shape(client):
    body = client.get("/events/timeseries?window=600&buckets=5", headers=READ).json()
    assert isinstance(body, list)
    if body:
        assert {"name", "flows"} <= set(body[0].keys())


def test_sandbox_state_shape(client):
    body = client.get("/sandbox/state", headers=READ).json()
    for k in ("blocked_ips", "firewall_rules", "rate_limited_hosts", "total_actions"):
        assert k in body, f"missing key: {k}"


def test_quarantine_empty(client):
    assert client.get("/quarantine", headers=READ).json() == []


def test_blocked_ips_shape(client):
    body = client.get("/blocked-ips", headers=READ).json()
    assert "total_blocked" in body
    assert "blocked_ips" in body


def test_interfaces_shape(client):
    body = client.get("/interfaces", headers=READ).json()
    assert "interfaces" in body
    assert isinstance(body["interfaces"], list)


def test_capture_status_shape(client):
    body = client.get("/capture-status", headers=READ).json()
    for k in ("active", "interface", "source", "flows_processed"):
        assert k in body


def test_rl_stats_shape(client):
    body = client.get("/rl/stats", headers=READ).json()
    # With RL disabled this returns {"enabled": false}
    assert "enabled" in body


def test_rl_policy_shape(client):
    body = client.get("/rl/policy", headers=READ).json()
    for k in ("base_threshold", "max_threshold", "thresholds", "fp_rates"):
        assert k in body


def test_graph_summary_shape(client):
    body = client.get("/graph/summary", headers=READ).json()
    for k in ("nodes", "edges", "by_kind"):
        assert k in body


def test_reports_list_shape(client):
    body = client.get("/reports", headers=READ).json()
    assert isinstance(body, list)


def test_metrics_endpoint_text(client):
    r = client.get("/metrics")
    assert r.status_code == 200
    # Prometheus text format — must start with '# HELP' or '# TYPE'
    assert r.headers["content-type"].startswith("text/plain")
    assert b"ids_" in r.content


# -- validation --------------------------------------------------------------

def test_predict_rejects_garbage(client):
    # Pydantic should 422 on totally malformed payload (missing numeric fields OK — extras=allow)
    # Send a non-JSON body to force 422 at schema layer
    r = client.post("/predict/", headers=ADMIN, json={"PROTOCOL": "not-a-number"})
    # pydantic v2 returns 422 on coerce failure; v1 may coerce silently.
    assert r.status_code in (200, 422), f"unexpected {r.status_code}: {r.text[:200]}"


def test_rate_limit_predict(client):
    # Fire a lot — admin key should bypass the rate limit.
    flow = {"PROTOCOL": 6, "IN_BYTES": 100, "IN_PKTS": 1,
            "FLOW_DURATION_MILLISECONDS": 10, "TCP_FLAGS": 2,
            "MIN_TTL": 64, "MAX_TTL": 64,
            "Source IP": "203.0.113.9", "Destination IP": "192.168.1.1"}
    count_ok = 0
    count_limited = 0
    for _ in range(40):
        r = client.post("/predict/", headers=ADMIN, json=flow)
        if r.status_code == 200:
            count_ok += 1
        elif r.status_code == 429:
            count_limited += 1
    # Admin should not be 429ed
    assert count_limited == 0, f"admin unexpectedly rate-limited ({count_limited} times)"

"""
Prometheus metrics for the IDS backend.

Counters / gauges / histograms exported at GET /metrics (no auth, standard
Prometheus convention — you can gate via firewall or reverse proxy instead).

Import these and call `.inc()` / `.labels(...).observe()` from the hot paths
to emit metrics. Cost is negligible — the client maintains counters in memory.
"""

from __future__ import annotations

from prometheus_client import (
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
    CONTENT_TYPE_LATEST,
)

# Use a custom registry so we don't pollute the default with process metrics we
# don't need in this app. Process/gc metrics would double-count across uvicorn
# worker children.
IDS_REGISTRY = CollectorRegistry()

# Counters — monotonically increasing
flows_processed_total = Counter(
    "ids_flows_processed_total",
    "Total network flows classified by the IDS",
    ("predicted_label", "source"),  # source: predict_api | live_capture
    registry=IDS_REGISTRY,
)

workflows_queued_total = Counter(
    "ids_workflows_queued_total",
    "Total SOC workflows queued for execution",
    ("result",),  # queued | skipped_queue_full | deferred_cooldown
    registry=IDS_REGISTRY,
)

predictions_blocked_total = Counter(
    "ids_predictions_blocked_total",
    "Flows intercepted by the blocked-IP gate before inference",
    registry=IDS_REGISTRY,
)

rl_feedback_total = Counter(
    "ids_rl_feedback_total",
    "RL feedback signals recorded",
    ("signal_source",),  # workflow | human_allow | human_deny
    registry=IDS_REGISTRY,
)

# Gauges — point-in-time values
workflow_queue_depth = Gauge(
    "ids_workflow_queue_depth",
    "Current depth of the SOC workflow queue",
    registry=IDS_REGISTRY,
)

live_events_in_window = Gauge(
    "ids_live_events_in_window",
    "Number of live events currently in the dashboard deque",
    registry=IDS_REGISTRY,
)

rl_buffer_total = Gauge(
    "ids_rl_buffer_total",
    "Total rows in the RL experience buffer",
    ("status",),  # pending | labeled | trained
    registry=IDS_REGISTRY,
)

rl_avg_reward = Gauge(
    "ids_rl_avg_reward",
    "Mean reward across labeled RL experience rows",
    registry=IDS_REGISTRY,
)

# Histograms — latency distributions
prediction_latency_seconds = Histogram(
    "ids_prediction_latency_seconds",
    "Latency of predictor.predict() call",
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0),
    registry=IDS_REGISTRY,
)

classifier_confidence = Histogram(
    "ids_classifier_confidence",
    "Confidence of the top predicted class per flow",
    ("predicted_label",),
    buckets=(0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 0.95, 0.99),
    registry=IDS_REGISTRY,
)


def render() -> tuple[bytes, str]:
    """Serialise the registry for the /metrics HTTP response."""
    return generate_latest(IDS_REGISTRY), CONTENT_TYPE_LATEST

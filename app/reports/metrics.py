"""
Reports Module - Prometheus Metrics
Phase 2-8: 安全报表/用户画像

Exposes metrics for the reports subsystem:
  - clickhouse_query_duration_seconds  : Histogram by query_type, status
  - clickhouse_lag_seconds              : Gauge (Kafka→ClickHouse sink lag)
  - export_queue_size                   : Gauge by tenant_id, format
  - clickhouse_ingest_total             : Counter by status
  - clickhouse_ingest_errors_total       : Counter by table, error_type
  - report_export_duration_seconds      : Histogram by format, status

[RP-4] These metrics feed Alertmanager alerting rules defined in the design doc.
"""
from __future__ import annotations

import time
import uuid
from contextlib import contextmanager
from functools import wraps
from typing import Callable

try:
    from prometheus_client import (
        Counter,
        Gauge,
        Histogram,
        generate_latest,
        CONTENT_TYPE_LATEST,
        CollectorRegistry,
        REGISTRY,
    )
except ImportError:
    # Dev environment without prometheus_client
    REGISTRY = None
    Counter = Gauge = Histogram = None

# ---------------------------------------------------------------------------
# Metric definitions
# ---------------------------------------------------------------------------

METRIC_DEFS = {
    # ClickHouse query latency
    "clickhouse_query_duration_seconds": {
        "type": "Histogram",
        "documentation": "ClickHouse query duration in seconds",
        "label_names": ["query_type", "status"],
        "buckets": [0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0],
    },
    # Kafka → ClickHouse sink lag
    "clickhouse_lag_seconds": {
        "type": "Gauge",
        "documentation": "Lag of Kafka to ClickHouse data pipeline in seconds",
        "label_names": ["table"],
    },
    # Export job queue depth
    "export_queue_size": {
        "type": "Gauge",
        "documentation": "Current number of pending/processing export jobs",
        "label_names": ["tenant_id", "format"],
    },
    # Total events ingested into ClickHouse
    "clickhouse_ingest_total": {
        "type": "Counter",
        "documentation": "Total number of events ingested into ClickHouse",
        "label_names": ["status"],
    },
    # Ingest errors
    "clickhouse_ingest_errors_total": {
        "type": "Counter",
        "documentation": "Total number of ClickHouse ingest errors",
        "label_names": ["table", "error_type"],
    },
    # Export job duration
    "report_export_duration_seconds": {
        "type": "Histogram",
        "documentation": "Report export job duration in seconds",
        "label_names": ["format", "status"],
        "buckets": [1.0, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0, 600.0],
    },
}

# ---------------------------------------------------------------------------
# Metrics registry
# ---------------------------------------------------------------------------

_metrics: dict = {}


def _init_metrics():
    global _metrics
    if REGISTRY is None or Counter is None:
        return
    for name, spec in METRIC_DEFS.items():
        mtype = spec["type"]
        labels = tuple(spec.get("label_names", []))
        if mtype == "Counter":
            _metrics[name] = Counter(
                name, spec["documentation"], labels, registry=REGISTRY
            )
        elif mtype == "Gauge":
            _metrics[name] = Gauge(
                name, spec["documentation"], labels, registry=REGISTRY
            )
        elif mtype == "Histogram":
            _metrics[name] = Histogram(
                name,
                spec["documentation"],
                labels,
                buckets=spec.get("buckets", Histogram.DEFAULT_BUCKETS),
                registry=REGISTRY,
            )


_init_metrics()


# ---------------------------------------------------------------------------
# Metric helpers
# ---------------------------------------------------------------------------

def record_clickhouse_query(
    query_type: str,
    status: str,
    duration_seconds: float,
):
    """Record a ClickHouse query duration."""
    if "clickhouse_query_duration_seconds" in _metrics:
        _metrics["clickhouse_query_duration_seconds"].labels(
            query_type=query_type, status=status
        ).observe(duration_seconds)


def set_clickhouse_lag(table: str, lag_seconds: float):
    """Set current Kafka→ClickHouse sink lag."""
    if "clickhouse_lag_seconds" in _metrics:
        _metrics["clickhouse_lag_seconds"].labels(table=table).set(lag_seconds)


def set_export_queue_size(tenant_id: str, format: str, size: int):
    """Set current export queue depth."""
    if "export_queue_size" in _metrics:
        _metrics["export_queue_size"].labels(
            tenant_id=tenant_id, format=format
        ).set(size)


def inc_clickhouse_ingest(status: str):
    """Increment ClickHouse ingest counter."""
    if "clickhouse_ingest_total" in _metrics:
        _metrics["clickhouse_ingest_total"].labels(status=status).inc()


def inc_clickhouse_ingest_error(table: str, error_type: str):
    """Increment ClickHouse ingest error counter."""
    if "clickhouse_ingest_errors_total" in _metrics:
        _metrics["clickhouse_ingest_errors_total"].labels(
            table=table, error_type=error_type
        ).inc()


def record_export_duration(format: str, status: str, duration_seconds: float):
    """Record export job duration."""
    if "report_export_duration_seconds" in _metrics:
        _metrics["report_export_duration_seconds"].labels(
            format=format, status=status
        ).observe(duration_seconds)


# ---------------------------------------------------------------------------
# Context managers
# ---------------------------------------------------------------------------

@contextmanager
def track_clickhouse_query(query_type: str):
    """Context manager to time a ClickHouse query and record the metric."""
    start = time.perf_counter()
    status = "ok"
    try:
        yield
    except Exception:
        status = "error"
        raise
    finally:
        duration = time.perf_counter() - start
        record_clickhouse_query(query_type, status, duration)


@contextmanager
def track_export_duration(format: str):
    """Context manager to time an export job."""
    start = time.perf_counter()
    status = "ok"
    try:
        yield
    except Exception:
        status = "error"
        raise
    finally:
        duration = time.perf_counter() - start
        record_export_duration(format, status, duration)


# ---------------------------------------------------------------------------
# Metrics endpoint
# ---------------------------------------------------------------------------

async def metrics_endpoint(request=None):
    """
    FastAPI endpoint to expose Prometheus metrics.
    GET /metrics
    """
    if REGISTRY is None:
        return b"", 200, {"Content-Type": "text/plain"}
    return (
        generate_latest(REGISTRY),
        200,
        {"Content-Type": CONTENT_TYPE_LATEST},
    )

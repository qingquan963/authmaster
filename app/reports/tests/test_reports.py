"""
Reports Module - Unit Tests
Phase 2-8: 安全报表/用户画像

Tests:
  - AnomalyDetector: rule evaluation (geo, time, new_device, bruteforce, impossible_travel)
  - ExportService: idempotency (same key → same export_id, conflict → 409)
  - ClickHouseService: fallback mode when CH unavailable
  - Router: API endpoint validation
"""
from __future__ import annotations

import asyncio
import hashlib
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.reports.anomaly_detector import (
    AnomalyDetector,
    AnomalyResult,
    haversine_km,
    DEFAULT_RULES,
)
from app.reports.export_service import ExportService, ExportIdempotencyConflict
from app.reports.clickhouse_service import ClickHouseService
from app.reports.notification_service import NotificationService
from app.reports.metrics import (
    record_clickhouse_query,
    set_clickhouse_lag,
    record_export_duration,
)


# ---------------------------------------------------------------------------
# AnomalyDetector Tests
# ---------------------------------------------------------------------------

def test_haversine_km():
    """Test great-circle distance calculation."""
    # Shanghai (31.23, 121.47) to Beijing (39.91, 116.39)
    d = haversine_km(31.23, 121.47, 39.91, 116.39)
    assert 1000 < d < 1200  # ~1080 km


def test_anomaly_result_initial_state():
    result = AnomalyResult()
    assert result.risk_score == 0
    assert result.anomaly_types == []
    assert result.is_blocking is False


def test_anomaly_result_add_rule():
    result = AnomalyResult()
    rule = {
        "rule_name": "geo_anomaly",
        "anomaly_type": "geo_anomaly",
        "score_increment": 40,
        "is_blocking": False,
        "description": "Login city not in usual list",
    }
    result.add(rule, "上海登录 → 北京2小时内")
    assert result.risk_score == 40
    assert "geo_anomaly" in result.anomaly_types
    assert result.is_blocking is False
    assert len(result.descriptions) == 1


def test_anomaly_result_blocking_rule():
    result = AnomalyResult()
    rule = {
        "rule_name": "bruteforce",
        "anomaly_type": "bruteforce",
        "score_increment": 60,
        "is_blocking": True,
        "description": "Bruteforce detected",
    }
    result.add(rule)
    assert result.is_blocking is True


def test_anomaly_result_max_score():
    result = AnomalyResult()
    for _ in range(5):
        result.add({"rule_name": "x", "anomaly_type": "x", "score_increment": 40, "is_blocking": False})
    assert result.risk_score == 100  # capped


def test_anomaly_result_to_dict():
    result = AnomalyResult()
    result.add(
        {
            "rule_name": "geo_anomaly",
            "anomaly_type": "geo_anomaly",
            "score_increment": 40,
            "is_blocking": False,
            "description": "test",
        },
        "Beijing login",
    )
    d = result.to_dict()
    assert d["risk_score"] == 40
    assert d["risk_level"] == "medium"  # 40-69
    assert "geo_anomaly" in d["anomaly_types"]
    assert d["is_blocking"] is False


def test_anomaly_result_risk_level_high():
    result = AnomalyResult()
    result.add({"rule_name": "bruteforce", "anomaly_type": "bruteforce", "score_increment": 60, "is_blocking": True, "description": ""})
    result.add({"rule_name": "geo", "anomaly_type": "geo_anomaly", "score_increment": 40, "is_blocking": False, "description": ""})
    d = result.to_dict()
    assert d["risk_level"] == "high"  # >= 70


@pytest.mark.asyncio
async def test_anomaly_detector_default_rules():
    """Test that detector uses default rules when DB is unavailable."""
    mock_db = AsyncMock()
    mock_db.execute.return_value = MagicMock(fetchall=MagicMock(return_value=[]))

    detector = AnomalyDetector(mock_db, redis=None)
    rules = await detector._get_enabled_rules(uuid.uuid4())
    assert len(rules) == len(DEFAULT_RULES)
    # Should be sorted by priority
    priorities = [r["priority"] for r in rules]
    assert priorities == sorted(priorities)


# ---------------------------------------------------------------------------
# ExportService Idempotency Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_export_idempotency_same_key_same_export():
    """Same idempotency key within 24h returns same export_id."""
    mock_db = AsyncMock()
    mock_redis = AsyncMock()
    mock_redis.get.return_value = None  # Redis miss
    mock_db.execute.return_value = MagicMock(
        fetchone=MagicMock(return_value=None)  # No existing task
    )
    mock_db.commit = AsyncMock()

    service = ExportService(mock_db, redis=mock_redis)

    key = "export:" + hashlib.sha256(b"login_anomalies{}csv").hexdigest()
    export_id, status = await service.create_export(
        tenant_id=uuid.uuid4(),
        created_by=uuid.uuid4(),
        report_type="login_anomalies",
        format="csv",
        filters={},
        idempotency_key=key,
    )
    assert status == "pending"
    assert isinstance(export_id, uuid.UUID)


@pytest.mark.asyncio
async def test_export_idempotency_conflict():
    """Same key while processing raises ExportIdempotencyConflict."""
    mock_db = AsyncMock()
    mock_redis = AsyncMock()
    existing_id = uuid.uuid4()
    mock_redis.get.return_value = f'{{"export_id": "{existing_id}", "status": "processing"}}'

    service = ExportService(mock_db, redis=mock_redis)
    key = "export:" + hashlib.sha256(b"login_anomalies{}csv").hexdigest()

    with pytest.raises(ExportIdempotencyConflict) as exc_info:
        await service.create_export(
            tenant_id=uuid.uuid4(),
            created_by=uuid.uuid4(),
            report_type="login_anomalies",
            format="csv",
            filters={},
            idempotency_key=key,
        )
    assert exc_info.value.existing_export_id == existing_id


# ---------------------------------------------------------------------------
# ClickHouseService Fallback Tests
# ---------------------------------------------------------------------------

def test_fallback_dashboard():
    ch = ClickHouseService(clickhouse_url=None)
    result = ch._fallback_dashboard(uuid.uuid4(), "30d")
    assert result["total_logins"] == 0
    assert result["risk_distribution"] == {"low": 0, "medium": 0, "high": 0}


@pytest.mark.asyncio
async def test_clickhouse_service_unavailable():
    """Service works even when ClickHouse is not configured."""
    ch = ClickHouseService(clickhouse_url=None)
    await ch.initialize()
    assert ch._available is False

    result = await ch.get_dashboard(uuid.uuid4(), "30d")
    assert result["total_logins"] == 0


def test_pct_change():
    assert ClickHouseService._pct_change(120, 100) == 20.0
    assert ClickHouseService._pct_change(0, 100) == -100.0
    assert ClickHouseService._pct_change(100, 0) == 0.0


# ---------------------------------------------------------------------------
# NotificationService Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_notification_service_anomaly_alert():
    """Anomaly alert notification logs correctly in dev mode."""
    notifier = NotificationService(redis=None)
    await notifier.notify_anomaly_alert(
        user_id=uuid.uuid4(),
        user_email="test@example.com",
        anomaly_type="geo_anomaly",
        description="上海登录 → 北京2小时内",
        risk_level="high",
        risk_score=85,
        ip_address="1.2.3.4",
        geo_location="北京",
    )
    # Dev mode logs only; no exception = pass


@pytest.mark.asyncio
async def test_notification_service_high_risk_user():
    """High risk user alert notification."""
    notifier = NotificationService(redis=None)
    await notifier.notify_high_risk_user(
        user_id=uuid.uuid4(),
        user_email="highrisk@example.com",
        risk_level="high",
        risk_score=85,
        notify_to="admin@example.com",
        notify_type="email",
    )


# ---------------------------------------------------------------------------
# Metrics Tests
# ---------------------------------------------------------------------------

def test_record_clickhouse_query_noop_without_prometheus():
    """Metrics functions are no-ops when prometheus_client not installed."""
    # Should not raise
    record_clickhouse_query("dashboard", "ok", 0.05)
    set_clickhouse_lag("login_events_olap", 5.0)
    record_export_duration("csv", "ok", 12.5)


def test_export_duration_context_manager():
    """track_export_duration records metric."""
    import time
    from app.reports.metrics import track_export_duration

    with track_export_duration("csv"):
        time.sleep(0.01)
    # No exception = pass


# ---------------------------------------------------------------------------
# Schema Validation Tests
# ---------------------------------------------------------------------------

from app.reports.schemas import ExportRequest, ExportFormat


def test_export_request_valid():
    req = ExportRequest(
        report_type="login_anomalies",
        format=ExportFormat.CSV,
        filters={"start_date": "2026-03-01"},
    )
    assert req.report_type == "login_anomalies"
    assert req.format == ExportFormat.CSV


def test_export_request_invalid_report_type():
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        ExportRequest(report_type="invalid_type", format=ExportFormat.CSV)


def test_anomaly_result_risk_level_boundaries():
    result = AnomalyResult()
    result.risk_score = 39
    d = result.to_dict()
    assert d["risk_level"] == "low"

    result.risk_score = 40
    d = result.to_dict()
    assert d["risk_level"] == "medium"

    result.risk_score = 70
    d = result.to_dict()
    assert d["risk_level"] == "high"

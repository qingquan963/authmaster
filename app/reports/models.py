"""
Reports Module - SQLAlchemy Models
Phase 2-8: 安全报表/用户画像
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from sqlalchemy import (
    Boolean,
    BigInteger,
    CheckConstraint,
    DateTime,
    Enum as SAEnum,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------
class ExportStatus(str, Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"


class ExportFormat(str, Enum):
    CSV = "csv"
    XLSX = "xlsx"
    PDF = "pdf"


class AnomalyType(str, Enum):
    GEO_ANOMALY = "geo_anomaly"
    TIME_ANOMALY = "time_anomaly"
    NEW_DEVICE = "new_device"
    BRUTEFORCE = "bruteforce"
    IMPOSSIBLE_TRAVEL = "impossible_travel"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class AnomalyStatus(str, Enum):
    PENDING_REVIEW = "pending_review"
    REVIEWED = "reviewed"
    FALSE_POSITIVE = "false_positive"
    CONFIRMED = "confirmed"


# ---------------------------------------------------------------------------
# Tables (PostgreSQL)
# ---------------------------------------------------------------------------

class ReportExportTask(Base):
    """
    [RP-3] 导出任务表，含幂等Key哈希约束。
    UNIQUE(tenant_id, idempotency_key_hash) 保证同一租户内相同幂等Key不重复创建。
    """

    __tablename__ = "report_export_tasks"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("auth_tenants.id"), nullable=False
    )
    created_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("auth_users.id"), nullable=False
    )
    report_type: Mapped[str] = mapped_column(String(32), nullable=False)
    format: Mapped[str] = mapped_column(
        String(8), nullable=False,
        CheckConstraint("format IN ('csv', 'xlsx', 'pdf')", name="ck_export_format")
    )
    filters: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    idempotency_key_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default=ExportStatus.PENDING.value,
        CheckConstraint(
            "status IN ('pending', 'processing', 'completed', 'failed')",
            name="ck_export_status"
        )
    )
    file_path: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    file_size_bytes: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)
    download_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    download_expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc)
    )
    started_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    __table_args__ = (
        UniqueConstraint("tenant_id", "idempotency_key_hash", name="uq_export_idem_key"),
        Index("idx_export_tasks_tenant", "tenant_id", "status", "created_at"),
    )


class AnomalyRule(Base):
    """
    可配置的异常检测规则。
    管理员可在数据库中增删改规则，规则配置缓存 60s 实时生效。
    """

    __tablename__ = "anomaly_rules"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    tenant_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("auth_tenants.id"), nullable=True
    )
    rule_name: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    anomaly_type: Mapped[str] = mapped_column(
        String(32), nullable=False,
        CheckConstraint(
            "anomaly_type IN ('geo_anomaly', 'time_anomaly', 'new_device', 'bruteforce', 'impossible_travel')",
            name="ck_anomaly_type"
        )
    )
    score_increment: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    is_blocking: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    threshold_value: Mapped[Optional[float]] = mapped_column(Numeric(10, 2), nullable=True)
    threshold_unit: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    priority: Mapped[int] = mapped_column(Integer, nullable=False, default=100)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc)
    )

    __table_args__ = (
        Index("idx_anomaly_rules_enabled", "enabled", "priority"),
    )


class AnomalyEvent(Base):
    """
    检测到的异常事件（由 anomaly_detector 写入，供查询 API 使用）。
    """

    __tablename__ = "anomaly_events"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("auth_tenants.id"), nullable=False
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("auth_users.id"), nullable=False
    )
    event_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), nullable=False
    )
    anomaly_type: Mapped[str] = mapped_column(String(32), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    risk_level: Mapped[str] = mapped_column(
        String(8), nullable=False, default=RiskLevel.LOW.value,
        CheckConstraint("risk_level IN ('low', 'medium', 'high')", name="ck_risk_level")
    )
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    geo_country: Mapped[Optional[str]] = mapped_column(String(8), nullable=True)
    geo_city: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    device_fp_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    extra_data: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default=AnomalyStatus.PENDING_REVIEW.value,
        CheckConstraint(
            "status IN ('pending_review', 'reviewed', 'false_positive', 'confirmed')",
            name="ck_anomaly_status"
        )
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc)
    )
    reviewed_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("auth_users.id"), nullable=True
    )
    reviewed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    __table_args__ = (
        Index("idx_anomaly_events_user", "user_id", "created_at"),
        Index("idx_anomaly_events_tenant_status", "tenant_id", "status", "created_at"),
        Index("idx_anomaly_events_type", "anomaly_type", "created_at"),
    )


# ---------------------------------------------------------------------------
# ClickHouse DDL (documented here, applied via migration/scripts)
# ---------------------------------------------------------------------------
CLICKHOUSE_LOGIN_EVENTS_DDL = """
CREATE TABLE login_events_olap (
    event_id          UUID,
    tenant_id         UUID,
    user_id           UUID,
    user_email        VARCHAR(255),
    status            VARCHAR(16),
    login_method      VARCHAR(32),
    ip_address        INET,
    geo_country       VARCHAR(8),
    geo_city          VARCHAR(64),
    geo_latitude      DECIMAL(9,6),
    geo_longitude     DECIMAL(9,6),
    user_agent        TEXT,
    device_fp_hash    VARCHAR(64),
    risk_score        INTEGER,
    risk_level        VARCHAR(8),
    mfa_used          BOOLEAN,
    login_hour        SMALLINT,
    login_weekday     VARCHAR(12),
    is_anomalous      BOOLEAN,
    anomaly_types     ARRAY[VARCHAR(32)],
    created_at        TIMESTAMPTZ
) ENGINE = MergeTree()
PARTITION BY (toYYYYMM(created_at))
ORDER BY (tenant_id, user_id, created_at)
TTL created_at + INTERVAL 90 DAY;
"""

CLICKHOUSE_USER_BEHAVIOR_PROFILE_MV = """
CREATE MATERIALIZED VIEW user_behavior_profile
ENGINE = SummingMergeTree()
ORDER BY (user_id, tenant_id)
AS SELECT
    user_id,
    tenant_id,
    COUNT(*) FILTER (WHERE status = 'success' AND created_at > NOW() - INTERVAL '7 days') AS logins_7d,
    COUNT(*) FILTER (WHERE status = 'success' AND created_at > NOW() - INTERVAL '30 days') AS logins_30d,
    COUNT(DISTINCT device_fp_hash) FILTER (WHERE created_at > NOW() - INTERVAL '30 days') AS devices_30d,
    COUNT(DISTINCT geo_city) FILTER (WHERE status = 'success' AND created_at > NOW() - INTERVAL '30 days') AS cities_30d,
    AVG(risk_score) FILTER (WHERE created_at > NOW() - INTERVAL '30 days') AS avg_risk_score_30d,
    MAX(risk_score) FILTER (WHERE created_at > NOW() - INTERVAL '30 days') AS max_risk_score_30d,
    COUNT(*) FILTER (WHERE is_anomalous = TRUE AND created_at > NOW() - INTERVAL '30 days') AS anomaly_count_30d
FROM login_events_olap
GROUP BY user_id, tenant_id;
"""

"""
SDK Module - SQLAlchemy Async Models
Phase 2-6: Auth SDK

Tables:
  - api_keys       : API key storage and management
  - api_call_logs  : API call audit log
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum

from sqlalchemy import (
    BigInteger, Boolean, CheckConstraint, Column, DateTime,
    Enum as SAEnum, ForeignKey, Index, Integer, String, Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import INET, JSONB, UUID
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------
class APIKeyStatus(str, Enum):
    ACTIVE = "active"
    REVOKED = "revoked"


# ---------------------------------------------------------------------------
# API Keys
# ---------------------------------------------------------------------------
class APIKey(Base):
    __tablename__ = "api_keys"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(
        UUID(as_uuid=True),
        ForeignKey("auth_tenants.id", ondelete="CASCADE"),
        nullable=False,
    )
    api_key = Column(String(64), nullable=False, unique=True)
    api_secret_hash = Column(String(64), nullable=False)
    app_name = Column(String(128), nullable=False)
    scopes = Column(JSONB, nullable=False, default=list)
    rate_limit_rps = Column(Integer, nullable=False, default=100)
    rate_limit_burst = Column(Integer, nullable=False, default=200)
    monthly_quota = Column(BigInteger, nullable=True)
    monthly_used = Column(BigInteger, nullable=False, default=0)
    quota_reset_at = Column(DateTime(timezone=True), nullable=True)
    allowed_ips = Column(JSONB, nullable=True)
    enabled = Column(Boolean, nullable=False, default=True)
    last_used_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    created_by = Column(UUID(as_uuid=True), ForeignKey("auth_users.id"), nullable=True)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    revoked_by = Column(UUID(as_uuid=True), ForeignKey("auth_users.id"), nullable=True)

    tenant = relationship("AuthTenant")
    creator = relationship("AuthUser", foreign_keys=[created_by])
    revoker = relationship("AuthUser", foreign_keys=[revoked_by])

    __table_args__ = (
        UniqueConstraint("tenant_id", "app_name", name="uq_tenant_app"),
        Index("idx_api_keys_key", "api_key"),
        Index("idx_api_keys_tenant", "tenant_id", "enabled"),
        CheckConstraint("enabled IN (TRUE, FALSE)", name="ck_api_keys_enabled"),
    )


# ---------------------------------------------------------------------------
# API Call Logs
# ---------------------------------------------------------------------------
class APICallLog(Base):
    __tablename__ = "api_call_logs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    api_key_id = Column(
        UUID(as_uuid=True),
        ForeignKey("api_keys.id", ondelete="CASCADE"),
        nullable=False,
    )
    tenant_id = Column(
        UUID(as_uuid=True),
        ForeignKey("auth_tenants.id", ondelete="CASCADE"),
        nullable=False,
    )
    request_id = Column(String(64), nullable=False, unique=True)
    endpoint = Column(String(128), nullable=False)
    method = Column(String(8), nullable=False)
    status_code = Column(Integer, nullable=True)
    response_time_ms = Column(Integer, nullable=True)
    ip_address = Column(INET, nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

    api_key = relationship("APIKey")

    __table_args__ = (
        Index("idx_api_call_logs_key", "api_key_id", "created_at"),
        Index("idx_api_call_logs_tenant", "tenant_id", "created_at"),
    )

"""
Rate Limiting Models
Phase 2-7: 百万级 QOS 高并发架构

Tables:
  - rate_limit_rules: Configurable rate limit rules per endpoint/tenant

Reference: see design doc Phase 2-7 Section 4.4
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum

from sqlalchemy import (
    Boolean, CheckConstraint, Column, DateTime, ForeignKey,
    Index, Integer, String, UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class KeyType(str, Enum):
    """Rate limit key extraction strategy."""
    IP = "ip"              # Client IP address
    USER = "user"         # Authenticated user ID
    API_KEY = "api_key"   # API key
    TENANT = "tenant"     # Tenant ID
    GLOBAL = "global"     # No key (global counter)


class RateLimitRule(Base):
    __tablename__ = "rate_limit_rules"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(
        UUID(as_uuid=True),
        ForeignKey("auth_tenants.id", ondelete="CASCADE"),
        nullable=True,  # NULL = applies to all tenants (global rule)
        default=None,
    )
    # e.g., "/api/v1/auth/login", "/api/v1/sdk/*"
    endpoint_pattern = Column(String(128), nullable=False)
    # How to extract the rate limit key (ip/user/api_key/tenant/global)
    key_type = Column(String(16), nullable=False, default=KeyType.IP.value)
    # Max requests allowed per window
    rate = Column(Integer, nullable=False)
    # Window size in seconds
    window = Column(Integer, nullable=False)
    # Burst capacity (for token bucket, optional)
    burst = Column(Integer, nullable=True)
    # Whether this rule is active
    enabled = Column(Boolean, nullable=False, default=True)
    # Priority for rule matching (higher = first)
    priority = Column(Integer, nullable=False, default=0)
    # Extra config as JSONB (e.g., {"strategy": "sliding_window"})
    extra_config = Column(JSONB, default=dict)
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        # Unique: one active rule per (tenant, endpoint, key_type)
        UniqueConstraint(
            "tenant_id", "endpoint_pattern", "key_type",
            name="uq_ratelimit_tenant_endpoint_keytype"
        ),
        Index("idx_ratelimit_pattern_priority", "endpoint_pattern", "priority"),
        Index("idx_ratelimit_enabled", "enabled"),
        CheckConstraint(
            "key_type IN ('ip','user','api_key','tenant','global')",
            name="ck_key_type"
        ),
        CheckConstraint("rate > 0", name="ck_rate_positive"),
        CheckConstraint("window > 0", name="ck_window_positive"),
    )

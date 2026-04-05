"""
SSO Module - SQLAlchemy Async Models
Phase 2-9: SSO 统一登出
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum

from sqlalchemy import (
    Boolean, BigInteger, CheckConstraint, Column, DateTime, Enum as SAEnum,
    ForeignKey, Index, Integer, String, Text, UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


class Protocol(str, Enum):
    OIDC = "oidc"
    SAML = "saml"


class LogoutStatus(str, Enum):
    PENDING = "pending"
    NOTIFYING = "notifying"
    COMPLETED = "completed"
    FAILED = "failed"


class OutboxStatus(str, Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    DEAD = "dead"


# ---------------------------------------------------------------------------
# OIDC Clients
# ---------------------------------------------------------------------------
class OIDCClient(Base):
    __tablename__ = "oidc_clients"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("auth_tenants.id"), nullable=False)
    client_id = Column(String(128), unique=True, nullable=False)
    client_secret_hash = Column(String(64))
    client_name = Column(String(256), nullable=False)
    redirect_uris = Column(JSONB, nullable=False, default=list)
    post_logout_uris = Column(JSONB, default=list)
    front_channel_uris = Column(JSONB, default=list)
    allowed_scopes = Column(JSONB, default=["openid", "profile"])
    policy = Column(JSONB, default=dict)
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        Index("idx_oidc_clients_tenant", "tenant_id"),
    )


# ---------------------------------------------------------------------------
# Auth Sessions (IdP sessions) - minimal definition for FK reference
# ---------------------------------------------------------------------------
class AuthSession(Base):
    __tablename__ = "auth_sessions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("auth_users.id", ondelete="CASCADE"), nullable=False)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("auth_tenants.id", ondelete="CASCADE"), nullable=False)
    revoked = Column(Boolean, nullable=False, default=False)
    revoked_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    last_active_at = Column(DateTime(timezone=True))

    sp_sessions = relationship("SPSession", back_populates="idp_session", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_auth_sessions_user", "user_id", "revoked"),
    )


# ---------------------------------------------------------------------------
# Auth Users - minimal definition for FK reference
# ---------------------------------------------------------------------------
class AuthUser(Base):
    __tablename__ = "auth_users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String(255), nullable=False)
    status = Column(String(16), nullable=False, default="active")
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

    sp_sessions = relationship("SPSession", back_populates="user", cascade="all, delete-orphan")


# ---------------------------------------------------------------------------
# Auth Tenants - minimal definition for FK reference
# ---------------------------------------------------------------------------
class AuthTenant(Base):
    __tablename__ = "auth_tenants"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(256), nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# SP Sessions (OIDC/SAML session mappings)
# ---------------------------------------------------------------------------
class SPSession(Base):
    __tablename__ = "sp_sessions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    idp_session_id = Column(
        UUID(as_uuid=True),
        ForeignKey("auth_sessions.id", ondelete="CASCADE"),
        nullable=False,
    )
    user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("auth_users.id", ondelete="CASCADE"),
        nullable=False,
    )
    tenant_id = Column(
        UUID(as_uuid=True),
        ForeignKey("auth_tenants.id", ondelete="CASCADE"),
        nullable=False,
    )
    client_id = Column(
        String(128),
        ForeignKey("oidc_clients.client_id", ondelete="RESTRICT"),
        nullable=False,
    )
    sp_session_id = Column(String(512))
    protocol = Column(String(16), nullable=False)
    # NOTE[SSO-9-NOTE1]: id_token_hint should be ≤ 4096 bytes per OIDC spec
    id_token_hint = Column(Text)
    front_channel_uri = Column(Text)
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime(timezone=True))
    revoked_at = Column(DateTime(timezone=True))
    # [Fix4] Idempotent logout ID
    logout_id = Column(UUID(as_uuid=True))
    # [Fix4] Logout status
    logout_status = Column(
        String(16),
        default=None,
    )

    idp_session = relationship("AuthSession", back_populates="sp_sessions")
    user = relationship("AuthUser", back_populates="sp_sessions")

    __table_args__ = (
        UniqueConstraint("client_id", "sp_session_id", "protocol", name="uq_sp_session"),
        # [Fix5] Composite unique: ensures same SP session is not notified twice
        UniqueConstraint("logout_id", "id", name="uq_logout_id_sp"),
        # [Fix1] Composite index for querying user sessions
        Index("idx_sp_sessions_user_protocol_revoke", "user_id", "protocol", "revoked_at",
              postgresql_where=(Column("revoked_at").is_(None))),
        Index("idx_sp_sessions_idp", "idp_session_id", "revoked_at"),
        Index("idx_sp_sessions_user", "user_id", "revoked_at"),
        # [Fix3] Index for retry candidates
        Index("idx_sp_sessions_retry", "logout_status", "revoked_at",
              postgresql_where=(Column("logout_status") == "failed")),
        CheckConstraint(
            "protocol IN ('oidc', 'saml')",
            name="ck_sp_sessions_protocol",
        ),
        CheckConstraint(
            "logout_status IS NULL OR logout_status IN ('pending', 'notifying', 'completed', 'failed')",
            name="ck_sp_sessions_logout_status",
        ),
    )


# ---------------------------------------------------------------------------
# Logout Outbox (Outbox pattern for idempotent SLO notifications)
# ---------------------------------------------------------------------------
class LogoutOutbox(Base):
    __tablename__ = "logout_outbox"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    logout_id = Column(UUID(as_uuid=True), nullable=False)
    sp_session_id = Column(UUID(as_uuid=True), nullable=False)
    client_id = Column(String(128), nullable=False)
    protocol = Column(String(16), nullable=False)
    logout_uri = Column(Text, nullable=False)
    attempt = Column(Integer, nullable=False, default=0)
    status = Column(String(16), nullable=False, default=OutboxStatus.PENDING.value)
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    next_retry_at = Column(DateTime(timezone=True))

    __table_args__ = (
        # [Fix5] Composite unique: same (logout_id, sp_session_id) not written twice
        UniqueConstraint("logout_id", "sp_session_id", name="uq_outbox_sp"),
        Index("idx_outbox_pending", "status", "next_retry_at",
              postgresql_where=(Column("status").in_([OutboxStatus.PENDING.value, OutboxStatus.PROCESSING.value]))),
        CheckConstraint("protocol IN ('oidc', 'saml')", name="ck_outbox_protocol"),
        CheckConstraint(
            "status IN ('pending', 'processing', 'completed', 'dead')",
            name="ck_outbox_status",
        ),
    )


# ---------------------------------------------------------------------------
# Dead Letter Queue for permanently failed SLO notifications
# ---------------------------------------------------------------------------
class LogoutDeadLetter(Base):
    __tablename__ = "logout_dead_letters"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    logout_id = Column(UUID(as_uuid=True), nullable=False)
    sp_session_id = Column(
        UUID(as_uuid=True),
        ForeignKey("sp_sessions.id", ondelete="CASCADE"),
        nullable=False,
    )
    client_id = Column(String(128), nullable=False)
    protocol = Column(String(16), nullable=False)
    logout_uri = Column(Text)
    error_message = Column(Text)
    attempt_count = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    last_failed_at = Column(DateTime(timezone=True))

    __table_args__ = (
        Index("idx_dl_logout_id", "logout_id"),
        # [Fix6] Index for TTL cleanup
        Index("idx_dl_created", "created_at"),
        CheckConstraint("protocol IN ('oidc', 'saml')", name="ck_dl_protocol"),
    )

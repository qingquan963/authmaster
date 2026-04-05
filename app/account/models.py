"""
Account Module - SQLAlchemy Async Models
Phase 2-5: 账号合并/解绑

Tables:
  - user_credentials       : Credential binding (手机号/邮箱/第三方OAuth)
  - account_merge_requests : Account merge request state machine
  - account_change_log     : Audit log for all account changes
  - auth_users (extended)  : merged_into, merged_at, merge_locked columns
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum

from sqlalchemy import (
    Boolean, CheckConstraint, Column, DateTime, Enum as SAEnum,
    ForeignKey, Index, Integer, String, Text, UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------
class CredentialType(str, Enum):
    PHONE = "phone"
    EMAIL = "email"
    WECHAT = "wechat"
    ALIPAY = "alipay"
    SAML = "saml"
    GITHUB = "github"
    GOOGLE = "google"
    OIDC = "oidc"


class CredentialStatus(str, Enum):
    ACTIVE = "active"
    UNBOUND = "unbound"
    PENDING_VERIFY = "pending_verify"
    MERGED = "merged"


class MergeStatus(str, Enum):
    """Full state machine for account merge requests."""
    PENDING = "pending"
    SOURCE_VERIFIED = "source_verified"
    TARGET_PENDING = "target_pending"
    EXECUTING = "executing"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    EXPIRED = "expired"
    FAILED = "failed"


class MergeEventType(str, Enum):
    """Audit event types for merge operations."""
    MERGE_INITIATED = "account.merge_initiated"
    MERGE_SOURCE_VERIFIED = "account.merge_source_verified"
    MERGE_TARGET_SENT = "account.merge_target_sent"
    MERGE_COMPLETED = "account.merge_completed"
    MERGE_CANCELLED = "account.merge_cancelled"
    MERGE_EXPIRED = "account.merge_expired"
    MERGE_FAILED = "account.merge_failed"


# ---------------------------------------------------------------------------
# Auth Users (Extension) — minimal model for FK reference
# ---------------------------------------------------------------------------
class AuthUser(Base):
    __tablename__ = "auth_users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String(255), nullable=False)
    phone = Column(String(32), default=None)
    password_hash = Column(String(128), default=None)
    status = Column(String(16), nullable=False, default="active")
    # [Fix5] Account merge fields
    merged_into = Column(UUID(as_uuid=True), ForeignKey("auth_users.id"), default=None)
    merged_at = Column(DateTime(timezone=True), default=None)
    # [Fix4] Merge lock for concurrency control
    merge_locked = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

    credentials = relationship("UserCredential", back_populates="user", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_auth_users_status", "status"),
        CheckConstraint("status IN ('active', 'merged', 'suspended', 'deleted')", name="ck_auth_users_status"),
    )


# ---------------------------------------------------------------------------
# User Credentials (Binding Model)
# ---------------------------------------------------------------------------
class UserCredential(Base):
    __tablename__ = "user_credentials"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("auth_users.id", ondelete="CASCADE"),
        nullable=False,
    )
    credential_type = Column(String(32), nullable=False)
    # 原始标识符 (e.g., "+86-138-0000-0000" or "user@example.com")
    identifier = Column(String(255), nullable=False)
    # [Fix6] identifier_hash: SHA256(normalized_identifier)
    #   - phone: remove non-digits, strip +86 prefix
    #   - email: lowercase
    #   - others: raw value
    identifier_hash = Column(String(64), nullable=False)
    is_verified = Column(Boolean, nullable=False, default=False)
    verified_at = Column(DateTime(timezone=True), default=None)
    bound_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    unbound_at = Column(DateTime(timezone=True), default=None)
    is_primary = Column(Boolean, nullable=False, default=False)
    status = Column(String(16), nullable=False, default=CredentialStatus.ACTIVE.value)
    extra_data = Column(JSONB, default=dict)

    user = relationship("AuthUser", back_populates="credentials")

    __table_args__ = (
        # [Fix2] Unique constraint: one (credential_type, identifier) per active binding
        UniqueConstraint("credential_type", "identifier", name="uq_credential_type_identifier"),
        # [Fix6] Unique constraint on normalized hash
        UniqueConstraint("identifier_hash", name="uq_identifier_hash"),
        Index("idx_credential_lookup", "identifier_hash", "status"),
        Index("idx_credential_user", "user_id", "status"),
        CheckConstraint(
            "credential_type IN ('phone','email','wechat','alipay','saml','github','google','oidc')",
            name="ck_credential_type",
        ),
        CheckConstraint(
            "status IN ('active','unbound','pending_verify','merged')",
            name="ck_credential_status",
        ),
    )


# ---------------------------------------------------------------------------
# Account Merge Requests (State Machine)
# ---------------------------------------------------------------------------
class AccountMergeRequest(Base):
    __tablename__ = "account_merge_requests"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    source_user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("auth_users.id", ondelete="CASCADE"),
        nullable=False,
    )
    target_user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("auth_users.id", ondelete="CASCADE"),
        nullable=False,
    )
    # [Fix7] Full state machine: pending → source_verified → target_pending → executing → completed
    status = Column(
        String(16),
        nullable=False,
        default=MergeStatus.PENDING.value,
    )
    merge_token = Column(String(64), nullable=False, unique=True)
    initiated_by = Column(
        UUID(as_uuid=True),
        ForeignKey("auth_users.id", ondelete="CASCADE"),
        nullable=False,
    )
    initiated_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    source_verified_at = Column(DateTime(timezone=True), default=None)
    target_verified_at = Column(DateTime(timezone=True), default=None)
    completed_at = Column(DateTime(timezone=True), default=None)
    cancelled_at = Column(DateTime(timezone=True), default=None)
    cancelled_by = Column(UUID(as_uuid=True), ForeignKey("auth_users.id"), default=None)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    # [Fix3] Retry fields
    failed_at = Column(DateTime(timezone=True), default=None)
    retry_count = Column(Integer, nullable=False, default=0)
    max_retries = Column(Integer, nullable=False, default=3)
    next_retry_at = Column(DateTime(timezone=True), default=None)

    source_user = relationship("AuthUser", foreign_keys=[source_user_id])
    target_user = relationship("AuthUser", foreign_keys=[target_user_id])
    initiator = relationship("AuthUser", foreign_keys=[initiated_by])
    canceller = relationship("AuthUser", foreign_keys=[cancelled_by])

    __table_args__ = (
        Index("idx_merge_requests_token", "merge_token"),
        Index("idx_merge_requests_status", "status", "expires_at"),
        # [Fix3] Index for scheduler to find retry candidates
        Index(
            "idx_merge_retry_candidates",
            "status", "retry_count", "next_retry_at",
            postgresql_where=(Column("status") == MergeStatus.FAILED.value),
        ),
        CheckConstraint(
            "status IN ('pending','source_verified','target_pending','executing',"
            "'completed','cancelled','expired','failed')",
            name="ck_merge_status",
        ),
    )


# ---------------------------------------------------------------------------
# Account Change Log (Audit)
# ---------------------------------------------------------------------------
class AccountChangeLog(Base):
    __tablename__ = "account_change_log"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("auth_users.id", ondelete="CASCADE"),
        nullable=False,
    )
    event_type = Column(String(32), nullable=False)
    event_detail = Column(JSONB, nullable=False, default=dict)
    changed_by = Column(UUID(as_uuid=True), ForeignKey("auth_users.id"), default=None)
    ip_address = Column(String(48), default=None)
    user_agent = Column(Text, default=None)
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

    user = relationship("AuthUser", foreign_keys=[user_id])
    changer = relationship("AuthUser", foreign_keys=[changed_by])

    __table_args__ = (
        Index("idx_change_log_user", "user_id", "created_at"),
        Index("idx_change_log_type", "event_type", "created_at"),
    )

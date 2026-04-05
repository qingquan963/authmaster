"""
Account Module - Audit Event Definitions
Phase 2-5: 账号合并/解绑

Centralized audit event type constants and a helper function for writing
audit log entries into the account_change_log table.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


class AuditEventType(str, Enum):
    """All account-related audit event types."""

    # Credential events
    CREDENTIAL_ADDED = "account.credential_added"
    CREDENTIAL_REMOVED = "account.credential_removed"
    CREDENTIAL_CONFLICT = "account.credential_conflict"
    PHONE_CHANGED = "account.phone_changed"
    EMAIL_CHANGED = "account.email_changed"

    # Merge events
    MERGE_INITIATED = "account.merge_initiated"
    MERGE_SOURCE_VERIFIED = "account.merge_source_verified"
    MERGE_TARGET_SENT = "account.merge_target_sent"
    MERGE_COMPLETED = "account.merge_completed"
    MERGE_CANCELLED = "account.merge_cancelled"
    MERGE_EXPIRED = "account.merge_expired"
    MERGE_FAILED = "account.merge_failed"

    # Unbind events
    CREDENTIAL_UNBOUND = "account.credential_unbound"
    LAST_CREDENTIAL_BLOCKED = "account.last_credential_blocked"
    MERGE_TOKEN_GENERATED = "account.merge_token_generated"


async def log_audit_event(
    db: "AsyncSession",
    user_id: uuid.UUID,
    event_type: str,
    event_detail: dict,
    *,
    changed_by: Optional[uuid.UUID] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> uuid.UUID:
    """
    Write a single audit log entry to account_change_log.

    Args:
        db: AsyncSession
        user_id: The user whose account is being changed
        event_type: One of AuditEventType values
        event_detail: JSON-serializable dict with event specifics
        changed_by: The user or admin performing the action (None = system)
        ip_address: Client IP address
        user_agent: Client User-Agent string

    Returns:
        The UUID of the inserted log entry
    """
    from sqlalchemy import text

    log_id = uuid.uuid4()
    await db.execute(
        text("""
            INSERT INTO account_change_log
                (id, user_id, event_type, event_detail, changed_by, ip_address, user_agent, created_at)
            VALUES
                (:id, :user_id, :event_type, :event_detail, :changed_by, :ip_address, :user_agent, :created_at)
        """),
        {
            "id": str(log_id),
            "user_id": str(user_id),
            "event_type": event_type,
            "event_detail": event_detail,  # SQLAlchemy handles JSONB serialization
            "changed_by": str(changed_by) if changed_by else None,
            "ip_address": ip_address,
            "user_agent": user_agent,
            "created_at": datetime.now(timezone.utc),
        },
    )
    return log_id

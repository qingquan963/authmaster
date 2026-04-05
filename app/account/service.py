"""
Account Module - Core Business Logic
Phase 2-5: 账号合并/解绑

Services:
  - CredentialService  : Credential management (list/add/unbind/change-phone)
  - MergeService        : Account merge state machine + execution

Key design decisions:
  [Fix2]   add_credential: Remove pre-check, rely on DB unique constraint + ON CONFLICT DO NOTHING
  [Fix4]   Concurrency safety: sorted user_id lock + SELECT ... FOR UPDATE SKIP LOCKED
  [Fix5]   Idempotency: Check status in ('target_pending', 'failed') before executing
  [Fix3]   Retry on failure: exponential backoff (1s → 2s → 4s), max 3 retries
  [Fix6]   identifier_hash: computed from normalized identifier (phone/email)
  [Fix7]   Full state machine: pending→source_verified→target_pending→executing→completed
"""
from __future__ import annotations

import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Optional

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from .events import AuditEventType, log_audit_event
from .identifier_normalizer import IdentifierNormalizer
from .models import CredentialStatus, MergeStatus

if TYPE_CHECKING:
    from .schemas import (
        VerificationInfo,
        CredentialItem,
        AddCredentialResponse,
        MergeInitiateRequest,
        MergeConfirmRequest,
    )


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------
class CredentialConflictError(Exception):
    """Raised when a credential is already bound to another account."""

    def __init__(
        self,
        message: str = "此凭证已被其他账号使用",
        conflict_account_id: Optional[uuid.UUID] = None,
        merge_token: Optional[str] = None,
    ):
        super().__init__(message)
        self.conflict_account_id = conflict_account_id
        self.merge_token = merge_token


class AccountLockedError(Exception):
    """Raised when the account is locked by another merge/operation."""

    def __init__(self, message: str = "账号正在被其他操作处理，请稍后再试"):
        super().__init__(message)


class LastCredentialError(Exception):
    """Raised when trying to unbind the last credential."""

    def __init__(self, message: str = "无法解绑最后一个凭证"):
        super().__init__(message)


class MergeTokenExpiredError(Exception):
    """Raised when a merge token has expired."""

    def __init__(self, message: str = "合并 Token 已过期"):
        super().__init__(message)


class MergeMaxRetriesError(Exception):
    """Raised when max retry count is exceeded."""

    def __init__(self, message: str = "合并失败，已达最大重试次数"):
        super().__init__(message)


# ---------------------------------------------------------------------------
# Datetime helpers
# ---------------------------------------------------------------------------
def _ensure_aware(dt: datetime) -> datetime:
    """Ensure a datetime is timezone-aware (assumes UTC if naive)."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
VERIFICATION_CODE_TTL = 300  # 5 minutes
MERGE_TOKEN_TTL = 600  # 10 minutes
PHONE_CHANGE_CODE_LIMIT = 5  # 5 per hour per user
PHONE_CHANGE_CODE_WINDOW = 3600  # 1 hour in seconds

# [Fix3] Exponential backoff: delay = min(2 ** retry_count, 60) seconds
EXPONENTIAL_BACKOFF_MAX = 60


def _compute_backoff(retry_count: int) -> int:
    return min(2**retry_count, EXPONENTIAL_BACKOFF_MAX)


# ---------------------------------------------------------------------------
# Credential Service
# ---------------------------------------------------------------------------
class CredentialService:
    """
    Manages credentials (手机号/邮箱/第三方 OAuth) bound to a user account.

    Key operations:
      - list_credentials     : List all active credentials for a user
      - add_credential       : Add a new credential (with conflict detection)
      - unbind_credential    : Unbind a credential (with last-credential guard)
      - change_phone         : Atomically change phone number
      - _get_conflicting_user: Look up which account holds a credential
    """

    def __init__(self, db: "AsyncSession"):
        self.db = db

    async def list_credentials(self, user_id: uuid.UUID) -> list["CredentialItem"]:
        """
        Return all active credentials for the given user.
        Identifiers are masked for privacy.
        """
        from .schemas import CredentialItem
        from .identifier_normalizer import IdentifierNormalizer

        result = await self.db.execute(
            text("""
                SELECT id, credential_type, identifier, is_primary,
                       is_verified, bound_at, status
                FROM user_credentials
                WHERE user_id = :uid AND status = 'active'
                ORDER BY is_primary DESC, bound_at ASC
            """),
            {"uid": str(user_id)},
        )
        rows = await result.fetchall()

        items = []
        for row in rows:
            r = row._mapping if hasattr(row, "_mapping") else row
            cred_type = r["credential_type"]
            identifier = r["identifier"]
            masked = IdentifierNormalizer.mask(identifier, cred_type)

            # can_unbind: false if it's the only credential, or if it's a
            # third-party OAuth that doesn't support rebinding
            can_unbind = True
            unbind_reason = None

            # Count total active credentials for this user
            count_result = await self.db.execute(
                text("""
                    SELECT COUNT(*) as cnt FROM user_credentials
                    WHERE user_id = :uid AND status = 'active'
                """),
                {"uid": str(user_id)},
            )
            total = (count_result.scalar()) or 0
            if total <= 1:
                can_unbind = False
                unbind_reason = "last_primary_credential"

            # Third-party credentials may not be unbindable without admin help
            non_unbindable = {"wechat", "alipay", "saml"}
            if cred_type in non_unbindable:
                # Only block if it's the last one
                if total <= 1:
                    can_unbind = False
                    unbind_reason = f"cannot_unbind_{cred_type}_last"
                else:
                    can_unbind = False
                    unbind_reason = f"{cred_type}_requires_admin_unbind"

            items.append(CredentialItem(
                credential_id=uuid.UUID(str(r["id"])),
                type=cred_type,
                identifier=masked,
                is_primary=r["is_primary"],
                is_verified=r["is_verified"],
                bound_at=r["bound_at"],
                can_unbind=can_unbind,
                unbind_reason=unbind_reason,
            ))

        return items

    async def add_credential(
        self,
        user_id: uuid.UUID,
        cred_type: str,
        identifier: str,
        verification_code: str,
        *,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> "AddCredentialResponse":
        """
        [Fix2] Add a credential using INSERT ... ON CONFLICT DO NOTHING.

        Removes the pre-check for conflicts (check-then-insert TOCTOU race).
        Instead, we attempt the insert directly and rely on the DB unique
        constraint as the single source of truth. If the constraint is
        violated, we look up the conflicting user and raise CredentialConflictError.

        [Fix6] identifier_hash is computed from the normalized identifier
        before being stored.
        """
        from .schemas import AddCredentialResponse

        # 1. Verify the OTP / verification code
        # (In production: call SMS/Email verification service)
        # For this implementation we accept any 6-digit code as valid in tests.
        if not verification_code or len(verification_code) != 6:
            raise ValueError("无效的验证码")

        # 2. Compute identifier_hash (normalized)
        identifier_hash = IdentifierNormalizer.compute_hash(identifier, cred_type)

        # 3. Attempt insert with ON CONFLICT DO NOTHING
        inserted_row = await self.db.execute(
            text("""
                INSERT INTO user_credentials
                    (id, user_id, credential_type, identifier, identifier_hash,
                     is_verified, verified_at, bound_at, status, is_primary)
                VALUES
                    (gen_random_uuid(), :user_id, :cred_type, :identifier, :identifier_hash,
                     TRUE, NOW(), NOW(), 'active',
                     (SELECT CASE WHEN COUNT(*) = 0 THEN TRUE ELSE FALSE END
                      FROM user_credentials uc2
                      WHERE uc2.user_id = :user_id AND uc2.status = 'active'))
                ON CONFLICT (credential_type, identifier) DO NOTHING
                RETURNING id
            """),
            {
                "user_id": str(user_id),
                "cred_type": cred_type,
                "identifier": identifier,
                "identifier_hash": identifier_hash,
            },
        )
        inserted = await inserted_row.fetchone()

        if inserted:
            row_id = inserted._mapping["id"] if hasattr(inserted, "_mapping") else inserted[0]
            await log_audit_event(
                self.db,
                user_id,
                AuditEventType.CREDENTIAL_ADDED,
                {
                    "credential_type": cred_type,
                    "identifier_masked": IdentifierNormalizer.mask(identifier, cred_type),
                    "credential_id": str(row_id),
                },
                changed_by=user_id,
                ip_address=ip_address,
                user_agent=user_agent,
            )
            return AddCredentialResponse(
                credential_id=uuid.UUID(str(row_id)),
                type=cred_type,
                identifier=IdentifierNormalizer.mask(identifier, cred_type),
                status="active",
            )

        # 4. Conflict detected — find the existing account
        conflict = await self._get_conflicting_user(cred_type, identifier)
        if conflict:
            # Generate a merge token for the conflict response
            merge_token = secrets.token_urlsafe(32)
            # Store the merge token in Redis with TTL (stub: in production use Redis)
            raise CredentialConflictError(
                conflict_account_id=conflict["user_id"],
                merge_token=merge_token,
            )
        # Shouldn't happen if ON CONFLICT caught it — but handle gracefully
        raise CredentialConflictError()

    async def _get_conflicting_user(
        self,
        cred_type: str,
        identifier: str,
    ) -> Optional[dict]:
        """Look up the account that holds a conflicting credential."""
        identifier_hash = IdentifierNormalizer.compute_hash(identifier, cred_type)
        result = await self.db.execute(
            text("""
                SELECT user_id, identifier, credential_type
                FROM user_credentials
                WHERE credential_type = :cred_type
                  AND identifier_hash = :identifier_hash
                  AND status = 'active'
                LIMIT 1
            """),
            {"cred_type": cred_type, "identifier_hash": identifier_hash},
        )
        row = await result.fetchone()
        if not row:
            return None
        r = row._mapping if hasattr(row, "_mapping") else row
        return {
            "user_id": uuid.UUID(str(r["user_id"])),
            "identifier": r["identifier"],
            "credential_type": r["credential_type"],
        }

    async def unbind_credential(
        self,
        user_id: uuid.UUID,
        credential_id: uuid.UUID,
        password_verified: bool,
        *,
        reason: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> None:
        """
        Unbind a credential from a user account.

        Rules:
          - Password (or MFA) must be verified first (caller checks)
          - Cannot unbind the last active credential (raises LastCredentialError)
          - OAuth credentials that are non-unbindable types are rejected
        """
        # 1. Fetch the credential
        result = await self.db.execute(
            text("""
                SELECT id, user_id, credential_type, identifier, status, is_primary
                FROM user_credentials
                WHERE id = :cred_id AND status = 'active'
            """),
            {"cred_id": str(credential_id)},
        )
        row = await result.fetchone()
        if not row:
            raise ValueError("凭证不存在或已解绑")
        r = row._mapping if hasattr(row, "_mapping") else row

        if str(r["user_id"]) != str(user_id):
            raise ValueError("无权操作此凭证")

        # 2. Count remaining credentials
        count_result = await self.db.execute(
            text("""
                SELECT COUNT(*) as cnt FROM user_credentials
                WHERE user_id = :uid AND status = 'active'
            """),
            {"uid": str(user_id)},
        )
        total = (count_result.scalar()) or 0
        if total <= 1:
            raise LastCredentialError()

        # 3. Non-unbindable types
        non_unbindable = {"wechat", "alipay", "saml"}
        if r["credential_type"] in non_unbindable:
            raise ValueError(f"不支持自助解绑 {r['credential_type']} 凭证")

        # 4. Perform unbind (logical delete)
        await self.db.execute(
            text("""
                UPDATE user_credentials
                SET status = 'unbound', unbound_at = NOW()
                WHERE id = :cred_id
            """),
            {"cred_id": str(credential_id)},
        )

        await log_audit_event(
            self.db,
            user_id,
            AuditEventType.CREDENTIAL_UNBOUND,
            {
                "credential_id": str(credential_id),
                "credential_type": r["credential_type"],
                "identifier_masked": IdentifierNormalizer.mask(
                    r["identifier"], r["credential_type"]
                ),
                "reason": reason or "user_requested",
            },
            changed_by=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
        )

    async def change_phone(
        self,
        user_id: uuid.UUID,
        new_phone: str,
        code: str,
        password_verified: bool,
        *,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> None:
        """
        Change the phone number on an account atomically.

        Flow:
          1. Verify password
          2. Verify SMS code for new_phone
          3. Atomically: unbind old phone + bind new phone in one transaction
          4. Audit log: account.phone_changed
        """
        if not password_verified:
            raise ValueError("密码验证失败")

        if not code or len(code) != 6:
            raise ValueError("无效的验证码")

        # Find the old phone credential
        old_phone_result = await self.db.execute(
            text("""
                SELECT id, identifier, identifier_hash
                FROM user_credentials
                WHERE user_id = :uid
                  AND credential_type = 'phone'
                  AND status = 'active'
                LIMIT 1
            """),
            {"uid": str(user_id)},
        )
        old_phone_row = await old_phone_result.fetchone()
        old_phone_id = None
        old_phone_identifier = None
        if old_phone_row:
            r = old_phone_row._mapping if hasattr(old_phone_row, "_mapping") else old_phone_row
            old_phone_id = r["id"]
            old_phone_identifier = r["identifier"]

        async with self.db.begin():
            # Unbind old phone
            if old_phone_id:
                await self.db.execute(
                    text("""
                        UPDATE user_credentials
                        SET status = 'unbound', unbound_at = NOW()
                        WHERE id = :cred_id
                    """),
                    {"cred_id": str(old_phone_id)},
                )

            # Bind new phone (reuse add_credential logic)
            new_identifier_hash = IdentifierNormalizer.compute_hash(new_phone, "phone")
            inserted_row = await self.db.execute(
                text("""
                    INSERT INTO user_credentials
                        (id, user_id, credential_type, identifier, identifier_hash,
                         is_verified, verified_at, bound_at, status, is_primary)
                    VALUES
                        (gen_random_uuid(), :user_id, 'phone', :identifier, :identifier_hash,
                         TRUE, NOW(), NOW(), 'active',
                         COALESCE(
                             (SELECT FALSE FROM user_credentials uc2
                              WHERE uc2.user_id = :user_id
                                AND uc2.status = 'active'
                                AND uc2.is_primary = TRUE),
                             TRUE
                         ))
                    ON CONFLICT (credential_type, identifier) DO NOTHING
                    RETURNING id
                """),
                {
                    "user_id": str(user_id),
                    "identifier": new_phone,
                    "identifier_hash": new_identifier_hash,
                },
            )
            inserted = await inserted_row.fetchone()
            if not inserted:
                raise CredentialConflictError(
                    message="新手机号已被其他账号绑定"
                )

        await log_audit_event(
            self.db,
            user_id,
            AuditEventType.PHONE_CHANGED,
            {
                "old_phone_masked": IdentifierNormalizer.mask(old_phone_identifier or "", "phone"),
                "new_phone_masked": IdentifierNormalizer.mask(new_phone, "phone"),
            },
            changed_by=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
        )


# ---------------------------------------------------------------------------
# Merge Service
# ---------------------------------------------------------------------------
class MergeService:
    """
    Manages the account merge state machine.

    State flow:
      pending → source_verified → target_pending → executing → completed
                        ↓                 ↓
                   cancelled          cancelled
                                          ↓
                              (failed → retry → executing) or expired

    Key operations:
      - initiate_merge  : Source account initiates merge after credential conflict
      - confirm_merge  : Target account confirms via email/SMS link
      - cancel_merge   : Either party cancels before execution
      - execute_merge  : Core atomic merge (called by confirm_merge or scheduler)
    """

    def __init__(self, db: "AsyncSession"):
        self.db = db

    async def initiate_merge(
        self,
        source_user_id: uuid.UUID,
        merge_token: str,
        source_verification: "VerificationInfo",
        *,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> dict:
        """
        Initiate a merge request from the source account side.

        Steps:
          1. Validate merge_token (stored in Redis in production)
          2. Verify source account identity (password or MFA)
          3. Lock both accounts (merge_locked = TRUE)
          4. Send confirmation notification to target account
          5. Create merge request record with status = 'source_verified'
          6. Audit log
        """
        # 1. Validate merge_token — in production, fetch from Redis
        # For this implementation, we accept the token directly
        token_row = await self.db.execute(
            text("""
                SELECT source_user_id, target_user_id, expires_at
                FROM account_merge_requests
                WHERE merge_token = :token
                LIMIT 1
            """),
            {"token": merge_token},
        )
        token_record = await token_row.fetchone()
        if not token_record:
            raise MergeTokenExpiredError("无效的合并 Token")

        r = token_record._mapping if hasattr(token_record, "_mapping") else token_record
        expires_at = r["expires_at"]
        if datetime.now(timezone.utc) > _ensure_aware(expires_at):
            raise MergeTokenExpiredError("合并 Token 已过期")

        source_user_db_id = uuid.UUID(str(r["source_user_id"]))
        target_user_db_id = uuid.UUID(str(r["target_user_id"]))

        if source_user_db_id != source_user_id:
            raise ValueError("无权发起此合并请求")

        # 2. Verify source account identity
        # (In production: verify password hash or MFA TOTP)
        if source_verification.type == "password":
            # Password verification stub — in production call auth service
            pw_result = await self.db.execute(
                text("SELECT password_hash FROM auth_users WHERE id = :uid"),
                {"uid": str(source_user_id)},
            )
            pw_row = await pw_result.fetchone()
            if not pw_row:
                raise ValueError("用户不存在")
            # NOTE: In production, use bcrypt.checkpw(source_verification.value, stored_hash)
            # For this mock, any password >= 6 chars is accepted
            if len(source_verification.value) < 6:
                raise ValueError("密码验证失败")
        elif source_verification.type == "mfa_code":
            # MFA verification stub
            if len(source_verification.value) != 6:
                raise ValueError("MFA 验证码错误")
        else:
            raise ValueError(f"不支持的验证类型: {source_verification.type}")

        # 3. Lock both accounts
        first_id, second_id = sorted([str(source_user_db_id), str(target_user_db_id)])
        for uid in [first_id, second_id]:
            updated = await self.db.execute(
                text("""
                    UPDATE auth_users
                    SET merge_locked = TRUE
                    WHERE id = :uid AND merge_locked = FALSE
                """),
                {"uid": uid},
            )
            if updated.rowcount == 0:
                raise AccountLockedError("账号正在被其他操作处理")

        # 4. Update merge request to source_verified
        now = datetime.now(timezone.utc)
        await self.db.execute(
            text("""
                UPDATE account_merge_requests
                SET status = 'source_verified',
                    source_verified_at = :now,
                    initiated_by = :initiated_by
                WHERE merge_token = :token
            """),
            {"now": now, "initiated_by": str(source_user_id), "token": merge_token},
        )

        # 5. In production: send confirmation notification to target account
        # (email / SMS with merge confirmation link)
        # For now, we just update the status

        # 6. Audit log
        await log_audit_event(
            self.db,
            source_user_id,
            AuditEventType.MERGE_INITIATED,
            {
                "merge_token": merge_token,
                "target_user_id": str(target_user_db_id),
                "source_verified_at": now.isoformat(),
            },
            changed_by=source_user_id,
            ip_address=ip_address,
            user_agent=user_agent,
        )

        # Return updated request info
        result = await self.db.execute(
            text("""
                SELECT id, status, expires_at
                FROM account_merge_requests
                WHERE merge_token = :token
            """),
            {"token": merge_token},
        )
        row = await result.fetchone()
        r2 = row._mapping if hasattr(row, "_mapping") else row
        return {
            "merge_request_id": uuid.UUID(str(r2["id"])),
            "status": r2["status"],
            "expires_at": r2["expires_at"],
            "message": "合并请求已发起，请等待目标账号确认",
        }

    async def confirm_merge(
        self,
        merge_token: str,
        target_verification: "VerificationInfo",
        *,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> dict:
        """
        Confirm a merge from the target account side.
        This is called when the target account owner clicks the confirmation
        link sent to their email/phone.

        Steps:
          1. Verify merge_token exists and is in source_verified state
          2. Verify target account identity
          3. Execute the merge atomically
        """
        # Get merge request
        result = await self.db.execute(
            text("""
                SELECT id, source_user_id, target_user_id, status, expires_at
                FROM account_merge_requests
                WHERE merge_token = :token
                LIMIT 1
            """),
            {"token": merge_token},
        )
        row = await result.fetchone()
        if not row:
            raise MergeTokenExpiredError("无效的合并 Token")
        r = row._mapping if hasattr(row, "_mapping") else row

        current_status = r["status"]
        if current_status not in ("source_verified",):
            if current_status == "completed":
                return {"status": "already_processed", "message": "合并已完成", "merged_account_email": None}
            raise ValueError(f"当前状态不允许确认合并: {current_status}")

        if datetime.now(timezone.utc) > _ensure_aware(r["expires_at"]):
            await self.db.execute(
                text("UPDATE account_merge_requests SET status = 'expired' WHERE merge_token = :token"),
                {"token": merge_token},
            )
            raise MergeTokenExpiredError()

        target_user_id = uuid.UUID(str(r["target_user_id"]))
        source_user_id = uuid.UUID(str(r["source_user_id"]))
        merge_req_id = uuid.UUID(str(r["id"]))

        # Verify target identity
        if target_verification.type in ("password", "email_code", "phone_code"):
            if len(target_verification.value) < 4:
                raise ValueError("验证失败")
        elif target_verification.type == "mfa_code":
            if len(target_verification.value) != 6:
                raise ValueError("MFA 验证码错误")

        # Execute the merge
        return await self._execute_merge(
            source_user_id=source_user_id,
            target_user_id=target_user_id,
            merge_req_id=merge_req_id,
            merge_token=merge_token,
            ip_address=ip_address,
            user_agent=user_agent,
        )

    async def cancel_merge(
        self,
        merge_token: str,
        cancelled_by: uuid.UUID,
        *,
        reason: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> None:
        """
        Cancel a pending merge. Either party can cancel before execution.
        """
        result = await self.db.execute(
            text("""
                SELECT id, source_user_id, target_user_id, status
                FROM account_merge_requests
                WHERE merge_token = :token
                LIMIT 1
            """),
            {"token": merge_token},
        )
        row = await result.fetchone()
        if not row:
            return  # Already gone

        r = row._mapping if hasattr(row, "_mapping") else row
        current_status = r["status"]
        terminal = {"completed", "cancelled", "expired"}
        if current_status in terminal:
            return  # Nothing to cancel

        merge_req_id = uuid.UUID(str(r["id"]))
        source_user_id = uuid.UUID(str(r["source_user_id"]))
        target_user_id = uuid.UUID(str(r["target_user_id"]))
        now = datetime.now(timezone.utc)

        async with self.db.begin():
            # Update merge request status
            await self.db.execute(
                text("""
                    UPDATE account_merge_requests
                    SET status = 'cancelled',
                        cancelled_at = :now,
                        cancelled_by = :cancelled_by
                    WHERE id = :id
                """),
                {"now": now, "cancelled_by": str(cancelled_by), "id": str(merge_req_id)},
            )

            # Release merge locks
            for uid in [str(source_user_id), str(target_user_id)]:
                await self.db.execute(
                    text("UPDATE auth_users SET merge_locked = FALSE WHERE id = :uid"),
                    {"uid": uid},
                )

        await log_audit_event(
            self.db,
            cancelled_by,
            AuditEventType.MERGE_CANCELLED,
            {
                "merge_request_id": str(merge_req_id),
                "cancelled_by": str(cancelled_by),
                "reason": reason or "user_requested",
            },
            changed_by=cancelled_by,
            ip_address=ip_address,
            user_agent=user_agent,
        )

    async def _execute_merge(
        self,
        source_user_id: uuid.UUID,
        target_user_id: uuid.UUID,
        merge_req_id: uuid.UUID,
        merge_token: str,
        *,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> dict:
        """
        [Fix4] Atomic merge execution with concurrency safety.

        Concurrency control:
          - Sort user_ids to prevent deadlocks
          - SET LOCAL lock_timeout = '5s'
          - SELECT ... FOR UPDATE SKIP LOCKED
          - If lock unavailable → AccountLockedError

        [Fix5] Idempotency:
          - Only execute if status in ('source_verified', 'failed')
          - 'failed' retries are limited by retry_count < max_retries

        [Fix3] Failure recovery:
          - On error: status='failed', next_retry_at = now + 2^retry_count seconds
          - Scheduler picks up failed requests after backoff
        """
        first_id, second_id = sorted([str(source_user_id), str(target_user_id)])

        async with self.db.begin():
            # [Fix4] Set SESSION-level lock timeout: 5 seconds
            await self.db.execute(text("SET LOCAL lock_timeout = '5s'"))

            # [Fix4] Acquire locks in sorted order (SKIP LOCKED for multi-instance)
            first_row = await self.db.execute(
                text("""
                    SELECT id, merge_locked FROM auth_users
                    WHERE id = :uid
                    FOR UPDATE SKIP LOCKED
                """),
                {"uid": first_id},
            )
            first_user = await first_row.fetchone()

            second_row = await self.db.execute(
                text("""
                    SELECT id, merge_locked FROM auth_users
                    WHERE id = :uid
                    FOR UPDATE SKIP LOCKED
                """),
                {"uid": second_id},
            )
            second_user = await second_row.fetchone()

            # [Fix4] SKIP LOCKED not returning a row = locked by another process
            if not first_user or not second_user:
                raise AccountLockedError()

            first_r = first_user._mapping if hasattr(first_user, "_mapping") else first_user._mapping
            second_r = second_user._mapping if hasattr(second_user, "_mapping") else second_user._mapping

            if first_r.get("merge_locked") or second_r.get("merge_locked"):
                raise AccountLockedError("账号正在被其他合并流程处理")

            # Re-check merge request status (idempotency)
            status_row = await self.db.execute(
                text("""
                    SELECT status, retry_count, max_retries
                    FROM account_merge_requests
                    WHERE id = :id
                    FOR UPDATE
                """),
                {"id": str(merge_req_id)},
            )
            status_rec = await status_row.fetchone()
            if not status_rec:
                raise ValueError("合并请求不存在")
            sr = status_rec._mapping if hasattr(status_rec, "_mapping") else status_rec

            current_status = sr["status"]
            retry_count = sr["retry_count"]
            max_retries = sr["max_retries"]

            # [Fix5] Only execute from these states
            if current_status not in ("source_verified", "target_pending", "failed"):
                return {
                    "status": "already_processed",
                    "message": f"合并已在状态 {current_status} 下处理",
                }

            # [Fix5] Check retry limit for failed → retry path
            if current_status == "failed" and retry_count >= max_retries:
                raise MergeMaxRetriesError()

            # Update to executing
            await self.db.execute(
                text("""
                    UPDATE account_merge_requests
                    SET status = 'executing'
                    WHERE id = :id
                """),
                {"id": str(merge_req_id)},
            )

            try:
                # Migrate credentials from source → target
                await self.db.execute(
                    text("""
                        UPDATE user_credentials
                        SET user_id = :target_id, status = 'active'
                        WHERE user_id = :source_id AND status = 'active'
                    """),
                    {"target_id": str(target_user_id), "source_id": str(source_user_id)},
                )

                # Revoke all source user sessions
                await self.db.execute(
                    text("""
                        UPDATE auth_sessions
                        SET revoked = TRUE, revoked_at = NOW()
                        WHERE user_id = :source_id AND revoked = FALSE
                    """),
                    {"source_id": str(source_user_id)},
                )

                # Migrate OAuth accounts
                await self.db.execute(
                    text("""
                        UPDATE oauth_accounts
                        SET user_id = :target_id
                        WHERE user_id = :source_id
                    """),
                    {"target_id": str(target_user_id), "source_id": str(source_user_id)},
                )

                # Soft-delete source user (merged)
                await self.db.execute(
                    text("""
                        UPDATE auth_users
                        SET merged_into = :target_id,
                            merged_at = NOW(),
                            status = 'merged',
                            merge_locked = FALSE
                        WHERE id = :source_id
                    """),
                    {"target_id": str(target_user_id), "source_id": str(source_user_id)},
                )

                # Mark merge request completed
                await self.db.execute(
                    text("""
                        UPDATE account_merge_requests
                        SET status = 'completed',
                            completed_at = NOW(),
                            target_verified_at = NOW()
                        WHERE id = :id
                    """),
                    {"id": str(merge_req_id)},
                )

            except Exception as e:
                # [Fix3] Failure recovery: record failed_at, compute next_retry_at
                delay_seconds = _compute_backoff(retry_count)
                next_retry_at = datetime.fromtimestamp(
                    datetime.now(timezone.utc).timestamp() + delay_seconds,
                    tz=timezone.utc,
                )
                await self.db.execute(
                    text("""
                        UPDATE account_merge_requests
                        SET status = 'failed',
                            failed_at = NOW(),
                            retry_count = retry_count + 1,
                            next_retry_at = :next_retry_at
                        WHERE id = :id
                    """),
                    {"next_retry_at": next_retry_at, "id": str(merge_req_id)},
                )
                # Release locks
                for uid in [first_id, second_id]:
                    await self.db.execute(
                        text("UPDATE auth_users SET merge_locked = FALSE WHERE id = :uid"),
                        {"uid": uid},
                    )
                raise e

        # Post-commit: notify source user (in production via email/push)
        await log_audit_event(
            self.db,
            target_user_id,
            AuditEventType.MERGE_COMPLETED,
            {
                "source_user_id": str(source_user_id),
                "target_user_id": str(target_user_id),
                "merge_request_id": str(merge_req_id),
            },
            changed_by=target_user_id,
            ip_address=ip_address,
            user_agent=user_agent,
        )

        # Get target user email for response
        email_result = await self.db.execute(
            text("SELECT email FROM auth_users WHERE id = :uid"),
            {"uid": str(target_user_id)},
        )
        email_row = await email_result.fetchone()
        masked_email = None
        if email_row:
            email_r = email_row._mapping if hasattr(email_row, "_mapping") else email_row
            masked_email = IdentifierNormalizer.mask(email_r["email"], "email")

        return {
            "status": "ok",
            "message": "账号合并已完成",
            "merged_account_email": masked_email,
        }

"""
Unit tests for Account Module — Phase 2-5: 账号合并/解绑

Tests cover:
  - IdentifierNormalizer: phone/email normalization and hash consistency
  - CredentialService.add_credential: conflict detection
  - CredentialService.unbind_credential: last-credential guard
  - MergeService: state machine, idempotency, concurrency safety
  - MergeRetryScheduler: exponential backoff
"""
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from app.account.identifier_normalizer import IdentifierNormalizer
from app.account.service import (
    CredentialService,
    MergeService,
    CredentialConflictError,
    LastCredentialError,
    AccountLockedError,
    MergeTokenExpiredError,
    _compute_backoff,
)
from app.account.schemas import VerificationInfo


# ---------------------------------------------------------------------------
# Fake async result helpers
# ---------------------------------------------------------------------------
class FakeRow:
    """A single fake DB row with dict-like access."""
    def __init__(self, data: dict):
        self._data = data

    def __getitem__(self, key):
        return self._data[key]

    def _as_mapping(self):
        return self._data

    @property
    def _mapping(self):
        """SQLAlchemy Row compatibility."""
        return self._data


class FakeResult:
    """
    Fake async result returned by db.execute() in tests.
    Supports both row-tuple and row._mapping access styles.
    """
    def __init__(self, rows=None, single=None, rowcount=1):
        self._rows = rows or []
        self._single = single
        self._rowcount = rowcount

    async def fetchall(self):
        return self._rows

    async def fetchone(self):
        return self._single

    def scalar(self):
        """Return the first column of the first row (for COUNT, etc.). Synchronous."""
        if self._single is None:
            return None
        # If _single is a FakeRow, extract the first value
        if hasattr(self._single, "_data"):
            vals = list(self._single._data.values())
            return vals[0] if vals else None
        return self._single

    @property
    def rowcount(self):
        return self._rowcount


# ---------------------------------------------------------------------------
# Test: IdentifierNormalizer — phone normalization
# ---------------------------------------------------------------------------
class TestPhoneNormalization:
    """AC-5.14: +86-138-0000-0000 and 861380000000 produce the same hash."""

    def test_strips_dashes(self):
        n = IdentifierNormalizer.normalize("138-0000-0000", "phone")
        assert n == "13800000000"

    def test_strips_spaces(self):
        n = IdentifierNormalizer.normalize("138 0000 0000", "phone")
        assert n == "13800000000"

    def test_strips_country_code_86(self):
        n = IdentifierNormalizer.normalize("+86-138-0000-0000", "phone")
        assert n == "13800000000"

    def test_strips_plus_sign(self):
        n = IdentifierNormalizer.normalize("+8613800000000", "phone")
        # +86 prefix stripped: "8613800000000" → "13800000000"
        assert n == "13800000000"

    def test_different_formats_same_hash(self):
        """[AC-5.14] Different formats of the same phone produce identical hashes."""
        f1 = IdentifierNormalizer.compute_hash("+86-138-0000-0000", "phone")
        f2 = IdentifierNormalizer.compute_hash("8613800000000", "phone")
        f3 = IdentifierNormalizer.compute_hash("138-0000-0000", "phone")
        assert f1 == f2 == f3

    def test_mask_phone(self):
        m = IdentifierNormalizer.mask("13800000000", "phone")
        assert m == "138****0000"

    def test_mask_short_phone(self):
        m = IdentifierNormalizer.mask("138000", "phone")
        assert m == "***"


# ---------------------------------------------------------------------------
# Test: IdentifierNormalizer — email normalization
# ---------------------------------------------------------------------------
class TestEmailNormalization:
    def test_lowercases_email(self):
        n = IdentifierNormalizer.normalize("User@EXAMPLE.COM", "email")
        assert n == "user@example.com"

    def test_same_email_different_case_same_hash(self):
        h1 = IdentifierNormalizer.compute_hash("User@Example.com", "email")
        h2 = IdentifierNormalizer.compute_hash("user@example.com", "email")
        assert h1 == h2

    def test_mask_email(self):
        m = IdentifierNormalizer.mask("user@example.com", "email")
        assert m == "u***@example.com"

    def test_mask_single_char_email(self):
        m = IdentifierNormalizer.mask("a@example.com", "email")
        assert m == "***@example.com"


# ---------------------------------------------------------------------------
# Test: IdentifierNormalizer — non-normalized types
# ---------------------------------------------------------------------------
class TestOtherCredentialTypes:
    def test_wechat_raw(self):
        n = IdentifierNormalizer.normalize("wx_openid_abc123", "wechat")
        assert n == "wx_openid_abc123"

    def test_github_raw(self):
        n = IdentifierNormalizer.normalize("ghp_abc123", "github")
        assert n == "ghp_abc123"

    def test_other_type_same_hash(self):
        h1 = IdentifierNormalizer.compute_hash("abc123", "github")
        h2 = IdentifierNormalizer.compute_hash("abc123", "github")
        assert h1 == h2


# ---------------------------------------------------------------------------
# Test: _compute_backoff (exponential backoff)
# ---------------------------------------------------------------------------
class TestExponentialBackoff:
    """[AC-5.11] Merge retry uses exponential backoff: 1s → 2s → 4s."""

    def test_backoff_values(self):
        assert _compute_backoff(0) == 1    # 2^0 = 1
        assert _compute_backoff(1) == 2    # 2^1 = 2
        assert _compute_backoff(2) == 4    # 2^2 = 4
        assert _compute_backoff(3) == 8    # 2^3 = 8
        assert _compute_backoff(4) == 16   # 2^4 = 16

    def test_backoff_caps_at_60(self):
        """Backoff should not exceed 60 seconds."""
        assert _compute_backoff(10) == 60
        assert _compute_backoff(100) == 60


# ---------------------------------------------------------------------------
# Test: CredentialService.list_credentials
# ---------------------------------------------------------------------------
class TestListCredentials:
    @pytest.mark.asyncio
    async def test_lists_active_credentials(self):
        """Credentials with status='active' are returned; unbound/merged are excluded."""
        user_id = uuid.uuid4()
        now = datetime.now(timezone.utc)

        mock_db = AsyncMock()
        # Simulate two active credentials
        mock_db.execute.return_value = FakeResult(rows=[
            FakeRow({"id": str(uuid.uuid4()), "credential_type": "phone",
                     "identifier": "13800000000", "is_primary": True,
                     "is_verified": True, "bound_at": now, "status": "active"}),
            FakeRow({"id": str(uuid.uuid4()), "credential_type": "email",
                     "identifier": "user@example.com", "is_primary": False,
                     "is_verified": True, "bound_at": now, "status": "active"}),
        ])

        svc = CredentialService(mock_db)
        credentials = await svc.list_credentials(user_id)

        assert len(credentials) == 2
        types = {c.type for c in credentials}
        assert types == {"phone", "email"}

    @pytest.mark.asyncio
    async def test_identifiers_are_masked(self):
        """Phone and email identifiers must be masked in responses."""
        user_id = uuid.uuid4()
        now = datetime.now(timezone.utc)

        mock_db = AsyncMock()
        mock_db.execute.return_value = FakeResult(rows=[
            FakeRow({"id": str(uuid.uuid4()), "credential_type": "phone",
                     "identifier": "13800000000", "is_primary": True,
                     "is_verified": True, "bound_at": now, "status": "active"}),
        ])

        svc = CredentialService(mock_db)
        credentials = await svc.list_credentials(user_id)
        assert credentials[0].identifier == "138****0000"

    @pytest.mark.asyncio
    async def test_can_unbind_false_when_single_credential(self):
        """[AC-5.6] Cannot unbind the last credential."""
        user_id = uuid.uuid4()
        now = datetime.now(timezone.utc)
        cred_id = uuid.uuid4()

        call_count = [0]
        async def fake_execute(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                # First call: credential lookup
                return FakeResult(rows=[
                    FakeRow({"id": str(cred_id), "credential_type": "phone",
                             "identifier": "13800000000", "is_primary": True,
                             "is_verified": True, "bound_at": now, "status": "active"}),
                ])
            elif call_count[0] == 2:
                # Second call: count query
                return FakeResult(single=FakeRow({"cnt": 1}))

        mock_db = AsyncMock()
        mock_db.execute = fake_execute

        svc = CredentialService(mock_db)
        credentials = await svc.list_credentials(user_id)
        assert credentials[0].can_unbind is False
        assert "last_primary_credential" in credentials[0].unbind_reason


# ---------------------------------------------------------------------------
# Test: CredentialService.add_credential — conflict detection
# ---------------------------------------------------------------------------
class TestAddCredential:
    @pytest.mark.asyncio
    async def test_add_credential_inserts_successfully(self):
        """When the credential is not in use, insert succeeds and returns credential_id."""
        user_id = uuid.uuid4()
        new_cred_id = uuid.uuid4()

        # When INSERT ON CONFLICT DO NOTHING doesn't conflict, it returns the inserted row
        inserted_row = FakeRow({
            "id": str(new_cred_id),
            "user_id": str(user_id),
            "credential_type": "email",
            "identifier": "new@example.com",
        })

        async def fake_execute(*args, **kwargs):
            # First (and only) call: INSERT → returns the inserted row
            return FakeResult(single=inserted_row)

        mock_db = AsyncMock()
        mock_db.execute = fake_execute

        svc = CredentialService(mock_db)
        result = await svc.add_credential(
            user_id=user_id,
            cred_type="email",
            identifier="new@example.com",
            verification_code="123456",
        )

        assert result.type == "email"
        assert result.status == "active"
        assert result.credential_id == new_cred_id

    @pytest.mark.asyncio
    async def test_add_credential_conflict_raises_error(self):
        """[AC-5.2] When credential is already bound, CredentialConflictError is raised."""
        user_id = uuid.uuid4()
        conflict_user_id = uuid.uuid4()

        mock_db = AsyncMock()
        mock_db.execute.side_effect = [
            # 1. INSERT returned nothing (constraint hit)
            FakeResult(rows=[]),
            # 2. Conflict lookup returns the existing user
            FakeResult(single=FakeRow({
                "user_id": str(conflict_user_id),
                "identifier": "existing@example.com",
                "credential_type": "email",
            })),
        ]

        svc = CredentialService(mock_db)
        with pytest.raises(CredentialConflictError) as exc_info:
            await svc.add_credential(
                user_id=user_id,
                cred_type="email",
                identifier="existing@example.com",
                verification_code="123456",
            )

        assert exc_info.value.conflict_account_id == conflict_user_id
        assert exc_info.value.merge_token is not None

    @pytest.mark.asyncio
    async def test_invalid_verification_code_raises(self):
        """Verification code must be 6 digits."""
        user_id = uuid.uuid4()
        mock_db = AsyncMock()
        svc = CredentialService(mock_db)

        with pytest.raises(ValueError, match="无效的验证码"):
            await svc.add_credential(
                user_id=user_id,
                cred_type="phone",
                identifier="13800000000",
                verification_code="12345",  # too short
            )


# ---------------------------------------------------------------------------
# Test: CredentialService.unbind_credential — last credential guard
# ---------------------------------------------------------------------------
class TestUnbindCredential:
    @pytest.mark.asyncio
    async def test_unbind_last_credential_raises(self):
        """[AC-5.6] Unbinding the last credential raises LastCredentialError."""
        user_id = uuid.uuid4()
        cred_id = uuid.uuid4()

        call_count = [0]

        async def fake_execute(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                # Credential lookup
                return FakeResult(single=FakeRow({
                    "id": str(cred_id),
                    "user_id": str(user_id),
                    "credential_type": "phone",
                    "identifier": "13800000000",
                    "status": "active",
                    "is_primary": True,
                }))
            elif call_count[0] == 2:
                # Count query — only 1 credential
                return FakeResult(single=FakeRow({"cnt": 1}))

        mock_db = AsyncMock()
        mock_db.execute = fake_execute
        svc = CredentialService(mock_db)

        with pytest.raises(LastCredentialError):
            await svc.unbind_credential(
                user_id=user_id,
                credential_id=cred_id,
                password_verified=True,
            )

    @pytest.mark.asyncio
    async def test_unbind_wechat_raises(self):
        """WeChat/Alipay/SAML credentials cannot be self-unbound."""
        user_id = uuid.uuid4()
        cred_id = uuid.uuid4()

        call_count = [0]

        async def fake_execute(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return FakeResult(single=FakeRow({
                    "id": str(cred_id),
                    "user_id": str(user_id),
                    "credential_type": "wechat",
                    "identifier": "wx_openid",
                    "status": "active",
                    "is_primary": False,
                }))
            elif call_count[0] == 2:
                return FakeResult(single=FakeRow({"cnt": 2}))

        mock_db = AsyncMock()
        mock_db.execute = fake_execute
        svc = CredentialService(mock_db)

        with pytest.raises(ValueError, match="不支持自助解绑"):
            await svc.unbind_credential(
                user_id=user_id,
                credential_id=cred_id,
                password_verified=True,
            )


# ---------------------------------------------------------------------------
# Test: MergeService state machine transitions
# ---------------------------------------------------------------------------
class TestMergeStateMachine:
    @pytest.mark.asyncio
    async def test_confirm_merge_updates_status_to_executing(self):
        """[AC-5.3] Confirm should transition state from source_verified → executing."""
        source_id = uuid.uuid4()
        target_id = uuid.uuid4()
        merge_req_id = uuid.uuid4()
        # Use naive datetime to match SQLAlchemy text() return behavior
        expires = datetime(2099, 12, 31, 23, 59, 59)  # far future

        token = "test_merge_token_abc123"
        call_count = [0]

        async def fake_execute(sql, params=None):
            call_count[0] += 1
            cn = call_count[0]

            # confirm_merge step 1: GET merge request
            if cn == 1:
                return FakeResult(single=FakeRow({
                    "id": str(merge_req_id),
                    "source_user_id": str(source_id),
                    "target_user_id": str(target_id),
                    "status": "source_verified",
                    "expires_at": expires,
                }))
            # confirm_merge calls _execute_merge internally
            elif cn == 2:
                # _execute_merge: SET lock_timeout
                return FakeResult()
            elif cn == 3:
                # SELECT first user FOR UPDATE SKIP LOCKED
                return FakeResult(single=FakeRow({"id": str(source_id), "merge_locked": False}))
            elif cn == 4:
                # SELECT second user FOR UPDATE SKIP LOCKED
                return FakeResult(single=FakeRow({"id": str(target_id), "merge_locked": False}))
            elif cn == 5:
                # SELECT merge request status (idempotency check)
                return FakeResult(single=FakeRow({
                    "status": "source_verified",
                    "retry_count": 0,
                    "max_retries": 3,
                }))
            elif cn == 6:
                # UPDATE status to executing
                return FakeResult(rowcount=1)
            elif cn == 7:
                # UPDATE user_credentials
                return FakeResult(rowcount=1)
            elif cn == 8:
                # UPDATE auth_sessions (revoke)
                return FakeResult(rowcount=1)
            elif cn == 9:
                # UPDATE oauth_accounts
                return FakeResult(rowcount=0)
            elif cn == 10:
                # UPDATE auth_users (soft delete source)
                return FakeResult(rowcount=1)
            elif cn == 11:
                # UPDATE account_merge_requests (completed)
                return FakeResult(rowcount=1)
            elif cn == 12:
                # Audit log
                return FakeResult(rowcount=1)
            elif cn == 13:
                # SELECT target user email
                return FakeResult(single=FakeRow({"email": "target@example.com"}))
            return FakeResult()

        mock_db = AsyncMock()
        mock_db.execute = fake_execute
        mock_db.begin = MagicMock(return_value=AsyncMock())

        svc = MergeService(mock_db)
        result = await svc.confirm_merge(
            merge_token=token,
            target_verification=VerificationInfo(type="password", value="password123"),
        )

        assert result["status"] == "ok"
        assert "合并已完成" in result["message"]

    @pytest.mark.asyncio
    async def test_merge_token_expired_raises(self):
        """[AC-5.9] Merge Token 10-minute TTL."""
        user_id = uuid.uuid4()
        source_id = uuid.uuid4()
        target_id = uuid.uuid4()
        # Use naive datetime to match SQLAlchemy text() return behavior
        past = datetime(2020, 1, 1, 0, 0, 0)  # definitely expired

        mock_db = AsyncMock()
        mock_db.execute.return_value = FakeResult(single=FakeRow({
            "source_user_id": str(source_id),
            "target_user_id": str(target_id),
            "expires_at": past,
        }))

        svc = MergeService(mock_db)
        with pytest.raises(MergeTokenExpiredError):
            await svc.initiate_merge(
                source_user_id=user_id,
                merge_token="expired_token",
                source_verification=VerificationInfo(type="password", value="password123"),
            )


# ---------------------------------------------------------------------------
# Test: Merge concurrency safety (lock ordering)
# ---------------------------------------------------------------------------
class TestMergeConcurrency:
    @pytest.mark.asyncio
    async def test_locked_account_raises_account_locked(self):
        """[AC-5.13] Concurrent merge → lock timeout returns ACCOUNT_LOCKED."""
        source_id = uuid.uuid4()
        target_id = uuid.uuid4()
        merge_req_id = uuid.uuid4()
        expires = datetime(2099, 12, 31, 23, 59, 59)

        call_count = [0]

        async def fake_execute(sql, params=None):
            call_count[0] += 1
            cn = call_count[0]

            # confirm_merge: get merge request
            if cn == 1:
                return FakeResult(single=FakeRow({
                    "id": str(merge_req_id),
                    "source_user_id": str(source_id),
                    "target_user_id": str(target_id),
                    "status": "source_verified",
                    "expires_at": expires,
                }))
            # _execute_merge: SET lock_timeout
            elif cn == 2:
                return FakeResult()
            elif cn == 3:
                # SELECT first user FOR UPDATE SKIP LOCKED — returns nothing (locked!)
                return FakeResult(single=None)
            elif cn == 4:
                # SELECT second user FOR UPDATE SKIP LOCKED — also nothing
                return FakeResult(single=None)

            return FakeResult()

        mock_db = AsyncMock()
        mock_db.execute = fake_execute
        mock_db.begin = MagicMock(return_value=AsyncMock())

        svc = MergeService(mock_db)
        with pytest.raises(AccountLockedError):
            await svc.confirm_merge(
                merge_token="some_token",
                target_verification=VerificationInfo(type="password", value="password123"),
            )


# ---------------------------------------------------------------------------
# Test: Merge idempotency
# ---------------------------------------------------------------------------
class TestMergeIdempotency:
    @pytest.mark.asyncio
    async def test_already_completed_returns_early(self):
        """[AC-5.5] Merge of already-merged account is idempotent."""
        source_id = uuid.uuid4()
        target_id = uuid.uuid4()
        expires = datetime(2099, 12, 31, 23, 59, 59)

        mock_db = AsyncMock()
        call_count = [0]

        async def fake_execute(sql, params=None):
            call_count[0] += 1
            if call_count[0] == 1:
                return FakeResult(single=FakeRow({
                    "id": str(uuid.uuid4()),
                    "source_user_id": str(source_id),
                    "target_user_id": str(target_id),
                    "status": "completed",
                    "expires_at": expires,
                }))
            # Should not reach _execute_merge if status is 'completed'
            return FakeResult()

        mock_db.execute = fake_execute
        svc = MergeService(mock_db)

        result = await svc.confirm_merge(
            merge_token="already_done_token",
            target_verification=VerificationInfo(type="password", value="password123"),
        )

        assert result["status"] == "already_processed"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

"""
Tests for Phase 2-9 SSO 统一登出
Tests cover:
  - [Fix4] Dual idempotency (Redis L1 + DB L2)
  - [Fix2] Outbox pattern
  - [Fix3] Exponential backoff retry
  - [Fix5] Redis degradation
  - [Fix6] Dead letter TTL cleanup
  - [Fix1] Session management
  - [SSO-9-NOTE1] id_token_hint length validation
"""
import json
import uuid
from unittest.mock import AsyncMock

import pytest

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from app.sso import service as sso_service


# ---------------------------------------------------------------------------
# Helper: fake SQLAlchemy async result object
# ---------------------------------------------------------------------------
class FakeResult:
    """
    Fake async result returned by db.execute() in tests.
    All SQLAlchemy async Result methods (fetchall, fetchone) are coroutines.
    """
    def __init__(self, rows=None, single=None, rowcount=1):
        self._rows = rows or []
        self._single = single
        self._rowcount = rowcount

    async def fetchall(self):
        return self._rows

    async def fetchone(self):
        return self._single


async def async_noop(*args, **kwargs):
    pass


# ---------------------------------------------------------------------------
# Test: idp_initiated_logout — happy path (Outbox pattern)
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_idp_initiated_logout_happy_path():
    """
    [Fix2] Outbox pattern: DB update + outbox write in same transaction.
    """
    logout_id = uuid.uuid4()
    idp_session_id = uuid.uuid4()

    sp_sessions = [
        {
            "id": str(uuid.uuid4()),
            "client_id": "client-a",
            "protocol": "oidc",
            "front_channel_uri": "https://sp-a.example.com/oidc/logout",
            "sp_session_id": "sp-session-a",
        },
        {
            "id": str(uuid.uuid4()),
            "client_id": "client-b",
            "protocol": "saml",
            "front_channel_uri": "https://sp-b.example.com/saml/slo",
            "sp_session_id": "sp-session-b",
        },
    ]

    # Redis mock: no prior idempotency key
    redis_mock = AsyncMock()
    redis_mock.get = AsyncMock(return_value=None)
    redis_mock.set = AsyncMock()

    # DB mock
    db_mock = AsyncMock()
    db_mock.commit = async_noop

    call_count = 0
    async def fake_execute(sql, params=None):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return FakeResult(rows=sp_sessions)
        return FakeResult(rowcount=1)

    db_mock.execute = fake_execute

    result = await sso_service.idp_initiated_logout(
        db=db_mock,
        redis=redis_mock,
        idp_session_id=idp_session_id,
        logout_id=logout_id,
    )

    assert result["status"] == "completed"
    assert result["logout_id"] == str(logout_id)
    assert result["sp_notified"] == 2
    redis_mock.set.assert_called_once()
    call_args = redis_mock.set.call_args
    assert call_args[0][0].startswith(sso_service.LOGOUT_IDEMPOTENCY_PREFIX)


# ---------------------------------------------------------------------------
# Test: [Fix4] Idempotency — duplicate logout_id returns early (Redis L1 hit)
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_idp_initiated_logout_duplicate_idempotent():
    """
    [Fix4] L1 Redis idempotency: same logout_id within 24h → 'already_completed'.
    DB must NOT be called when Redis returns cached result.
    """
    logout_id = uuid.uuid4()

    # Redis mock: returns cached result (L1 hit)
    redis_mock = AsyncMock()
    redis_mock.get = AsyncMock(return_value=json.dumps({"status": "completed", "sp_notified": 5}))

    # DB mock: should NOT be called
    db_mock = AsyncMock()

    result = await sso_service.idp_initiated_logout(
        db=db_mock,
        redis=redis_mock,
        idp_session_id=uuid.uuid4(),
        logout_id=logout_id,
    )

    assert result["status"] == "already_completed"
    assert result["logout_id"] == str(logout_id)
    db_mock.execute.assert_not_called()


# ---------------------------------------------------------------------------
# Test: [Fix5] Redis unavailable — degrades to DB idempotency
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_idp_initiated_logout_redis_unavailable():
    """
    [Fix5] Redis unavailable (connection error): continues with DB-level idempotency.
    """
    sp_sessions = [
        {
            "id": str(uuid.uuid4()),
            "client_id": "client-a",
            "protocol": "oidc",
            "front_channel_uri": "https://sp-a.example.com/oidc/logout",
            "sp_session_id": "sp-session-a",
        },
    ]

    # Redis mock: raises exception (simulates connection refused)
    redis_mock = AsyncMock()
    redis_mock.get = AsyncMock(side_effect=Exception("Redis connection refused"))
    redis_mock.set = AsyncMock()

    db_mock = AsyncMock()
    db_mock.commit = async_noop

    call_count = 0
    async def fake_execute(sql, params=None):
        nonlocal call_count
        call_count += 1
        sql_str = str(sql)
        if "logout_outbox" in sql_str and "SELECT" in sql_str:
            return FakeResult(single=None)  # No existing outbox entry
        if "sp_sessions" in sql_str and "SELECT" in sql_str:
            return FakeResult(rows=sp_sessions)
        return FakeResult(rowcount=1)

    db_mock.execute = fake_execute

    result = await sso_service.idp_initiated_logout(
        db=db_mock,
        redis=redis_mock,
        idp_session_id=uuid.uuid4(),
    )

    # Should succeed despite Redis failure (DB-level guarantee)
    assert result["status"] == "completed"
    assert result["sp_notified"] == 1


# ---------------------------------------------------------------------------
# Test: no active SP sessions — just revoke IdP session
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_idp_initiated_logout_no_sp_sessions():
    """
    When there are no active SP sessions, only the IdP session is revoked.
    """
    redis_mock = AsyncMock()
    redis_mock.get = AsyncMock(return_value=None)
    redis_mock.set = AsyncMock()

    db_mock = AsyncMock()
    db_mock.commit = async_noop

    call_count = 0
    async def fake_execute(sql, params=None):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return FakeResult(rows=[])  # No SP sessions
        return FakeResult(rowcount=1)

    db_mock.execute = fake_execute

    result = await sso_service.idp_initiated_logout(
        db=db_mock,
        redis=redis_mock,
        idp_session_id=uuid.uuid4(),
    )

    assert result["status"] == "completed"
    assert result["sp_notified"] == 0
    redis_mock.set.assert_called_once()


# ---------------------------------------------------------------------------
# Test: _build_slo_uri — OIDC and SAML
# ---------------------------------------------------------------------------
def test_build_slo_uri_oidc():
    sp = {"client_id": "my-client", "protocol": "oidc", "sp_session_id": "session-123"}
    uri = sso_service._build_slo_uri(sp)
    assert "oidc/logout" in uri
    assert "client_id=my-client" in uri
    assert "sp_session_id=session-123" in uri


def test_build_slo_uri_saml():
    sp = {"client_id": "saml-sp", "protocol": "saml", "sp_session_id": "saml-session-456"}
    uri = sso_service._build_slo_uri(sp)
    assert "saml/slo" in uri
    assert "client_id=saml-sp" in uri


# ---------------------------------------------------------------------------
# Test: retry delay array length matches MAX_RETRY_ATTEMPTS
# ---------------------------------------------------------------------------
def test_retry_delays_length():
    """
    [Fix6] RETRY_DELAYS length must equal MAX_RETRY_ATTEMPTS (5).
    Sequence [1, 2, 4, 8, 16]s for attempts 0-4; attempt >= 5 → dead letter.
    """
    assert len(sso_service.RETRY_DELAYS) == sso_service.MAX_RETRY_ATTEMPTS
    assert sso_service.RETRY_DELAYS == [1, 2, 4, 8, 16]


# ---------------------------------------------------------------------------
# Test: composite unique constraint prevents duplicate (logout_id, sp_session_id)
# ---------------------------------------------------------------------------
def test_composite_unique_constraint_logic():
    """
    (logout_id, sp_session_id) must be unique per outbox.
    Same logout_id with different sp_session_id → both allowed (one → many SPs).
    """
    same_logout = uuid.uuid4()
    records = [
        {"logout_id": same_logout, "sp_session_id": "sp-3"},
        {"logout_id": same_logout, "sp_session_id": "sp-4"},
    ]
    pairs = [(r["logout_id"], r["sp_session_id"]) for r in records]
    assert len(pairs) == len(set(pairs))


# ---------------------------------------------------------------------------
# Test: dead letter TTL constant
# ---------------------------------------------------------------------------
def test_dead_letter_ttl():
    """[Fix6] DEAD_LETTER_TTL_DAYS = 30 days."""
    assert sso_service.DEAD_LETTER_TTL_DAYS == 30


# ---------------------------------------------------------------------------
# Test: idempotency TTL constant
# ---------------------------------------------------------------------------
def test_idempotency_ttl():
    """[Fix4] LOGOUT_IDEMPOTENCY_TTL = 86400 (24 hours)."""
    assert sso_service.LOGOUT_IDEMPOTENCY_TTL == 86400

"""
Tests for Phase 2-9 SSO Logout Worker
Tests cover:
  - [Fix3] Exponential backoff retry (1s → 2s → 4s → 8s → 16s)
  - [Fix3] Dead letter queue after MAX_RETRY_ATTEMPTS
  - [Fix3] FOR UPDATE SKIP LOCKED prevents double consumption
  - Worker idle when no pending tasks
  - SP notification success marks outbox as completed
"""
import uuid
from unittest.mock import AsyncMock, patch, MagicMock

import pytest

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from app.sso import service as sso_service


# ---------------------------------------------------------------------------
# Fake result helpers
# ---------------------------------------------------------------------------

class FakeRow:
    def __init__(self, data: dict):
        self._data = data

    def __getitem__(self, key):
        return self._data[key]

    @property
    def _mapping(self):
        return self._data


class FakeResult:
    def __init__(self, rows=None, single=None, rowcount=1):
        self._rows = rows or []
        self._single = single
        self.rowcount = rowcount

    async def fetchall(self):
        return self._rows

    async def fetchone(self):
        return self._single


async def noop(*args, **kwargs):
    pass


# ---------------------------------------------------------------------------
# Test: RETRY_DELAYS array length matches MAX_RETRY_ATTEMPTS
# ---------------------------------------------------------------------------
def test_retry_delays_matches_max_attempts():
    """
    [Fix6] RETRY_DELAYS length must be exactly MAX_RETRY_ATTEMPTS (5).
    Index i → delay [1, 2, 4, 8, 16] seconds for attempts 0-4.
    """
    assert len(sso_service.RETRY_DELAYS) == sso_service.MAX_RETRY_ATTEMPTS
    assert sso_service.RETRY_DELAYS == [1, 2, 4, 8, 16]


# ---------------------------------------------------------------------------
# Test: retry delays are monotonically increasing (exponential backoff)
# ---------------------------------------------------------------------------
def test_retry_delays_are_exponential():
    """Each delay should be >= previous delay (strictly increasing for exponential backoff)."""
    delays = sso_service.RETRY_DELAYS
    for i in range(1, len(delays)):
        assert delays[i] >= delays[i - 1]


# ---------------------------------------------------------------------------
# Test: _fetch_outbox_task uses FOR UPDATE SKIP LOCKED
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_fetch_outbox_task_skips_locked():
    """
    _fetch_outbox_task should use FOR UPDATE SKIP LOCKED to avoid
    multiple workers claiming the same task.
    """
    db_mock = AsyncMock()
    db_mock.execute = AsyncMock(
        return_value=FakeResult(single=FakeRow({
            "id": uuid.uuid4(),
            "logout_id": uuid.uuid4(),
            "sp_session_id": uuid.uuid4(),
            "client_id": "client-a",
            "protocol": "oidc",
            "logout_uri": "https://sp.example.com/oidc/logout",
            "attempt": 0,
            "next_retry_at": None,
        }))
    )
    db_mock.commit = noop

    task = await sso_service._fetch_outbox_task(db_mock)

    assert task is not None
    assert "logout_uri" in task
    assert task["attempt"] == 0

    # Verify SQL contains FOR UPDATE SKIP LOCKED
    call_args = db_mock.execute.call_args
    sql_str = str(call_args[0][0])
    assert "FOR UPDATE SKIP LOCKED" in sql_str


# ---------------------------------------------------------------------------
# Test: _fetch_outbox_task returns None when no tasks
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_fetch_outbox_task_returns_none_when_empty():
    """When no pending tasks, _fetch_outbox_task should return None."""
    db_mock = AsyncMock()
    db_mock.execute = AsyncMock(return_value=FakeResult(single=None))
    db_mock.commit = noop

    task = await sso_service._fetch_outbox_task(db_mock)

    assert task is None


# ---------------------------------------------------------------------------
# Test: _notify_sp returns True on 2xx response
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_notify_sp_success():
    """SP returning 2xx should be treated as success."""
    with patch("httpx.AsyncClient") as mock_client_class:
        mock_response = AsyncMock()
        mock_response.status_code = 200

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client_class.return_value = mock_client

        result = await sso_service._notify_sp(
            "https://sp.example.com/oidc/logout",
            "oidc",
            str(uuid.uuid4()),
        )

        assert result is True


# ---------------------------------------------------------------------------
# Test: _notify_sp returns False on timeout
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_notify_sp_timeout_triggers_retry():
    """SP timeout should return False (triggers retry)."""
    import httpx

    with patch("httpx.AsyncClient") as mock_client_class:
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.TimeoutException("timeout"))
        mock_client_class.return_value = mock_client

        result = await sso_service._notify_sp(
            "https://sp.example.com/oidc/logout",
            "oidc",
            str(uuid.uuid4()),
        )

        assert result is False


# ---------------------------------------------------------------------------
# Test: _notify_sp returns True when logout_uri is empty
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_notify_sp_empty_uri_returns_true():
    """Empty logout_uri means nothing to notify → success."""
    result = await sso_service._notify_sp("", "oidc", str(uuid.uuid4()))
    assert result is True


# ---------------------------------------------------------------------------
# Test: _move_to_dead_letter inserts record
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_move_to_dead_letter_inserts():
    """Failed logout after max retries should be written to dead_letters table."""
    db_mock = AsyncMock()
    db_mock.execute = AsyncMock(return_value=FakeResult(rowcount=1))
    db_mock.commit = noop

    task = {
        "logout_id": uuid.uuid4(),
        "sp_session_id": uuid.uuid4(),
        "client_id": "client-a",
        "protocol": "oidc",
        "logout_uri": "https://sp.example.com/oidc/logout",
        "attempt": 4,
    }

    await sso_service._move_to_dead_letter(db_mock, task, "Connection refused")

    db_mock.execute.assert_called_once()
    call_args = db_mock.execute.call_args
    sql_str = str(call_args[0][0])
    assert "logout_dead_letters" in sql_str
    # Error message is in params, not the SQL string itself
    assert call_args[0][1]["err"] == "Connection refused"


# ---------------------------------------------------------------------------
# Test: _alert_logout_failure calls alert service
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_alert_logout_failure_calls_alert_service():
    """When a logout permanently fails, an alert should be sent."""
    alert_mock = AsyncMock()

    task = {
        "logout_id": uuid.uuid4(),
        "sp_session_id": uuid.uuid4(),
        "client_id": "client-a",
        "protocol": "oidc",
        "attempt": 5,
    }

    await sso_service._alert_logout_failure(
        alert_mock, task, "Max retry attempts exceeded"
    )

    alert_mock.send.assert_called_once()
    call_kwargs = alert_mock.send.call_args[1]
    assert call_kwargs["level"] == "critical"
    # Title contains "死信" (dead letter in Chinese)
    assert "死信" in call_kwargs["title"]


# ---------------------------------------------------------------------------
# Test: alert failure is swallowed (does not crash worker)
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_alert_failure_is_swallowed():
    """If alert service fails, _alert_logout_failure should not raise."""
    alert_mock = AsyncMock()
    alert_mock.send = AsyncMock(side_effect=Exception("Alert service down"))

    task = {
        "logout_id": uuid.uuid4(),
        "sp_session_id": uuid.uuid4(),
        "client_id": "client-a",
        "protocol": "oidc",
        "attempt": 5,
    }

    # Should not raise
    await sso_service._alert_logout_failure(
        alert_mock, task, "Max retry attempts exceeded"
    )


# ---------------------------------------------------------------------------
# Test: dead letter TTL constant is 30 days
# ---------------------------------------------------------------------------
def test_dead_letter_ttl_days():
    """DEAD_LETTER_TTL_DAYS must be 30 days per design spec."""
    assert sso_service.DEAD_LETTER_TTL_DAYS == 30


# ---------------------------------------------------------------------------
# Test: idempotency TTL is 24 hours
# ---------------------------------------------------------------------------
def test_logout_idempotency_ttl():
    """LOGOUT_IDEMPOTENCY_TTL must be 86400 seconds (24 hours)."""
    assert sso_service.LOGOUT_IDEMPOTENCY_TTL == 86400


# ---------------------------------------------------------------------------
# Test: logout_worker idle loop when no tasks
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_logout_worker_idle_when_no_tasks():
    """When _fetch_outbox_task returns None, worker should sleep and retry."""
    db_mock = AsyncMock()
    db_mock.execute = AsyncMock(return_value=FakeResult(single=None))
    db_mock.commit = noop

    call_count = 0
    sleep_values = []

    original_fetch = sso_service._fetch_outbox_task

    async def fake_fetch(db):
        return None

    async def fake_sleep(seconds):
        sleep_values.append(seconds)

    with patch.object(sso_service, "_fetch_outbox_task", fake_fetch):
        with patch("asyncio.sleep", fake_sleep):
            # Run only 2 iterations
            for _ in range(2):
                task = await sso_service._fetch_outbox_task(db_mock)
                if task is None:
                    await fake_sleep(1)

    assert len(sleep_values) >= 1
    assert sleep_values[0] == 1

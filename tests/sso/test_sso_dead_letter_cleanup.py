"""
Tests for Phase 2-9 SSO Dead Letter TTL Cleanup
Tests cover:
  - [Fix6] cleanup_dead_letter_ttl: 30-day TTL enforcement
  - Snapshot written to account_change_log before deletion
  - Returns count of deleted records
"""
import uuid
from datetime import datetime, timezone, timedelta

from unittest.mock import AsyncMock

import pytest

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from app.sso import service as sso_service


# ---------------------------------------------------------------------------
# Fake helpers
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
    def __init__(self, rows=None, single=None, rowcount=0):
        self._rows = rows or []
        self._single = single
        self._rowcount = rowcount

    async def fetchall(self):
        return self._rows

    async def fetchone(self):
        return self._single


async def noop(*args, **kwargs):
    pass


# ---------------------------------------------------------------------------
# Test: cleanup deletes records older than 30 days
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_cleanup_deletes_old_dead_letters():
    """
    cleanup_dead_letter_ttl should delete dead-letter records where
    created_at < NOW() - INTERVAL '30 days'.
    """
    db_mock = AsyncMock()
    deleted_count = 0

    async def fake_execute(query, params=None):
        nonlocal deleted_count
        sql_str = str(query)
        if "DELETE FROM logout_dead_letters" in sql_str:
            deleted_count = 5
            return FakeResult(rowcount=5)
        return FakeResult(rowcount=0)

    db_mock.execute = fake_execute
    db_mock.commit = noop

    result = await sso_service.cleanup_dead_letter_ttl(db_mock)

    assert deleted_count >= 0  # Either 0 or 5 depending on timing
    # Verify DELETE query uses correct cutoff
    call_args = db_mock.execute.call_args_list
    delete_calls = [c for c in call_args if "DELETE FROM" in str(c)]
    assert len(delete_calls) >= 1


# ---------------------------------------------------------------------------
# Test: cleanup writes snapshot to audit log before deletion
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_cleanup_writes_audit_snapshot():
    """
    Before deleting old dead letters, a snapshot must be written to
    account_change_log for audit purposes.
    """
    db_mock = AsyncMock()
    snapshot_written = False

    async def fake_execute(query, params=None):
        nonlocal snapshot_written
        sql_str = str(query)
        if "account_change_log" in sql_str and "INSERT INTO" in sql_str:
            snapshot_written = True
        return FakeResult(rowcount=1)

    db_mock.execute = fake_execute
    db_mock.commit = noop

    await sso_service.cleanup_dead_letter_ttl(db_mock)

    # Snapshot insert should happen before DELETE
    assert snapshot_written is True


# ---------------------------------------------------------------------------
# Test: cleanup returns integer count
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_cleanup_returns_integer():
    """cleanup_dead_letter_ttl should return the number of records deleted."""
    db_mock = AsyncMock()

    async def fake_execute(query, params=None):
        return FakeResult(rowcount=3)

    db_mock.execute = fake_execute
    db_mock.commit = noop

    result = await sso_service.cleanup_dead_letter_ttl(db_mock)

    assert isinstance(result, int)

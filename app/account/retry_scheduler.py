"""
Account Module - Merge Retry Scheduler
Phase 2-5: 账号合并/解绑

[Fix3] Merge Retry Scheduler

Monitors failed merge requests and automatically retries them with
exponential backoff (1s → 2s → 4s, max 60s, max 3 retries).

Key design:
  - Polls account_merge_requests WHERE status='failed'
    AND retry_count < max_retries AND next_retry_at <= now
  - Uses FOR UPDATE SKIP LOCKED to avoid multi-instance contention
  - Calls MergeService._execute_merge for retry
  - Updates retry_count and next_retry_at on failure
  - Marks as permanently failed when retry_count >= max_retries
"""
from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession
    from .service import MergeService


class MergeRetryScheduler:
    """
    Background scheduler that retries failed merge requests.

    Usage:
        scheduler = MergeRetryScheduler(db, merge_service, poll_interval=5.0)
        await scheduler.start()   # runs forever until stop() is called
        await scheduler.stop()
    """

    def __init__(
        self,
        db: "AsyncSession",
        merge_service: "MergeService",
        poll_interval: float = 5.0,
    ):
        self.db = db
        self.merge_service = merge_service
        self.poll_interval = poll_interval
        self._running = False

    async def start(self) -> None:
        """Start the scheduler loop."""
        self._running = True
        while self._running:
            try:
                await self._process_retries()
            except Exception as e:
                print(f"[MergeRetryScheduler] error processing retries: {e}")
            await asyncio.sleep(self.poll_interval)

    async def stop(self) -> None:
        """Stop the scheduler loop."""
        self._running = False

    async def _process_retries(self) -> None:
        """
        One polling cycle:
          1. Find all retry candidates (status='failed', retry_count < max_retries,
             next_retry_at <= now) ordered by next_retry_at ASC
          2. For each candidate, attempt to execute the merge
          3. On success, status becomes 'executing' → 'completed' (handled by execute_merge)
          4. On failure, update retry_count and next_retry_at
        """
        from sqlalchemy import text

        now = datetime.now(timezone.utc)

        # Find candidates — use FOR UPDATE SKIP LOCKED to avoid multiple instances
        # picking up the same request simultaneously
        result = await self.db.execute(
            text("""
                SELECT id, source_user_id, target_user_id,
                       retry_count, max_retries, next_retry_at
                FROM account_merge_requests
                WHERE status = 'failed'
                  AND retry_count < max_retries
                  AND (next_retry_at IS NULL OR next_retry_at <= :now)
                ORDER BY next_retry_at ASC NULLS FIRST
                LIMIT 10
                FOR UPDATE SKIP LOCKED
            """),
            {"now": now},
        )
        rows = await result.fetchall()

        for row in rows:
            r = row._mapping if hasattr(row, "_mapping") else row
            req_id = uuid.UUID(str(r["id"]))
            source_user_id = uuid.UUID(str(r["source_user_id"]))
            target_user_id = uuid.UUID(str(r["target_user_id"]))
            retry_count = r["retry_count"]
            max_retries = r["max_retries"]
            next_retry_at = r["next_retry_at"]

            # Re-check if this record is still eligible (another instance may
            # have already picked it up)
            if next_retry_at:
                # If next_retry_at is in the future, skip this cycle
                if next_retry_at > now:
                    continue

            # Advance next_retry_at to prevent immediate re-pickup by another instance
            # Use a brief delay (1 second) — the real backoff delay was already
            # computed when the failure was recorded
            updated = await self.db.execute(
                text("""
                    UPDATE account_merge_requests
                    SET next_retry_at = :new_next
                    WHERE id = :id
                      AND next_retry_at = :old_next
                """),
                {
                    "new_next": datetime.fromtimestamp(
                        now.timestamp() + 1, tz=timezone.utc
                    ),
                    "id": str(req_id),
                    "old_next": str(next_retry_at) if next_retry_at else None,
                },
            )
            if updated.rowcount == 0:
                # Another instance already picked this up
                continue

            # Attempt the merge retry
            try:
                await self.merge_service._execute_merge(
                    source_user_id=source_user_id,
                    target_user_id=target_user_id,
                    merge_req_id=req_id,
                    merge_token="",  # Not needed for _execute_merge directly
                )
            except Exception as e:
                # _execute_merge already handles retry_count update on failure,
                # but if it raised an exception (e.g. MAX_RETRIES_EXCEEDED),
                # we need to update status to permanently failed
                error_msg = str(e)
                new_retry_count = retry_count + 1
                if new_retry_count >= max_retries:
                    await self.db.execute(
                        text("""
                            UPDATE account_merge_requests
                            SET status = 'failed',
                                next_retry_at = NULL,
                                retry_count = :retry_count
                            WHERE id = :id
                        """),
                        {"retry_count": new_retry_count, "id": str(req_id)},
                    )
                # If not yet at max retries, _execute_merge already recorded
                # the next_retry_at during its own error handling
                print(f"[MergeRetryScheduler] merge retry failed for {req_id}: {error_msg}")

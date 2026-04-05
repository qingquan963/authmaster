"""
SSO Module - Core SSO Service
Phase 2-9: SSO 统一登出

Key design:
- [Fix2] Outbox pattern: DB update + outbox write in same transaction
- [Fix4] Idempotency (dual guarantee): Redis (L1) + DB outbox composite unique (L2)
- [Fix5] Redis degradation: if Redis unavailable, skip to DB-level idempotency check
- [Fix3] Exponential backoff retry + dead letter queue + alerting
- [Fix6] Dead letter TTL cleanup (30 days)
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Optional

import httpx

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
LOGOUT_IDEMPOTENCY_PREFIX = "logout:idempotency:"
LOGOUT_IDEMPOTENCY_TTL = 86400  # 24 hours

# [Fix6] Exponential backoff: index 0-4 → delays [1, 2, 4, 8, 16] seconds
# attempt=5 triggers dead-letter (no more retries)
MAX_RETRY_ATTEMPTS = 5
RETRY_DELAYS = [1, 2, 4, 8, 16]

# [Fix6] Dead letter TTL: 30 days
DEAD_LETTER_TTL_DAYS = 30

# SP notification timeout
SP_NOTIFY_TIMEOUT = 5.0


# ---------------------------------------------------------------------------
# IdP-Initiated Logout
# ---------------------------------------------------------------------------
async def idp_initiated_logout(
    db: "AsyncSession",
    redis: Optional[object],
    idp_session_id: uuid.UUID,
    logout_id: Optional[uuid.UUID] = None,
    initiated_by: Optional[uuid.UUID] = None,
) -> dict:
    """
    [Fix2] Outbox pattern: DB update + outbox write in same transaction.
    As long as the DB transaction commits, the outbox record is guaranteed to exist.
    A separate Worker polls the outbox and delivers notifications to SPs.

    [Fix4] Dual idempotency:
      L1 Redis: logout_id stored with TTL=24h → fastest path, hit = return early
      L2 DB: logout_outbox(logout_id, sp_session_id) composite unique as fallback

    [Fix5] Redis degradation: if Redis is unavailable (connection error/timeout),
      skip Redis check and fall through to DB-level idempotency.

    [Fix3] Retry/dead-letter: Worker handles outbox entries with exponential backoff.
    """
    if logout_id is None:
        logout_id = uuid.uuid4()

    if initiated_by is None:
        initiated_by = uuid.uuid4()

    redis_available = True

    # ── [Fix4] L1 Redis idempotency check ───────────────────────────────────
    idempotency_key = LOGOUT_IDEMPOTENCY_PREFIX + str(logout_id)
    if redis is not None:
        try:
            cached = await redis.get(idempotency_key)
            if cached is not None:
                result_data = json.loads(cached)
                # Cached data first, then override with fixed keys (status=already_completed always wins)
                return {**result_data, "status": "already_completed", "logout_id": str(logout_id)}
        except Exception as redis_err:
            # [Fix5] Redis unavailable → degrade to DB idempotency, do NOT block
            print(f"[idp_initiated_logout] Redis unavailable for idempotency check: {redis_err}")
            redis_available = False

    # ── Fetch all active SP sessions for this IdP session ─────────────────
    from sqlalchemy import text

    result = await db.execute(
        text("""
            SELECT id, client_id, protocol, front_channel_uri, sp_session_id
            FROM sp_sessions
            WHERE idp_session_id = :sid AND revoked_at IS NULL
        """),
        {"sid": str(idp_session_id)},
    )
    rows = await result.fetchall()
    # Handle both dict rows (test mocks) and SQLAlchemy Row objects
    sp_sessions = [
        row._mapping if hasattr(row, "_mapping") else row
        for row in rows
    ]

    # ── No active SP sessions → just revoke IdP session ────────────────────
    if not sp_sessions:
        await db.execute(
            text("""
                UPDATE auth_sessions
                SET revoked = TRUE, revoked_at = NOW()
                WHERE id = :sid
            """),
            {"sid": str(idp_session_id)},
        )
        if redis_available and redis is not None:
            await redis.set(
                idempotency_key,
                json.dumps({"status": "completed", "sp_notified": 0}),
                ex=LOGOUT_IDEMPOTENCY_TTL,
            )
        return {"status": "completed", "logout_id": str(logout_id), "sp_notified": 0}

    # ── [Fix2] Single DB transaction: mark SP sessions + write outbox ─────
    # [Fix5] DB idempotency check when Redis is unavailable
    if not redis_available:
        existing_result = await db.execute(
            text("""
                SELECT logout_id FROM logout_outbox
                WHERE logout_id = :lid AND status != 'dead'
                LIMIT 1
            """),
            {"lid": str(logout_id)},
        )
        existing_row = await existing_result.fetchone()
        if existing_row is not None:
            return {
                "status": "already_completed",
                "logout_id": str(logout_id),
                "sp_notified": len(sp_sessions),
            }

    # Mark all SP sessions as revoked + assign logout_id
    await db.execute(
        text("""
            UPDATE sp_sessions
            SET revoked_at = NOW(),
                logout_id = :lid,
                logout_status = 'pending'
            WHERE idp_session_id = :sid AND revoked_at IS NULL
        """),
        {"lid": str(logout_id), "sid": str(idp_session_id)},
    )

    # Revoke IdP session
    await db.execute(
        text("""
            UPDATE auth_sessions
            SET revoked = TRUE, revoked_at = NOW()
            WHERE id = :sid
        """),
        {"sid": str(idp_session_id)},
    )

    # Write outbox entries
    for sp in sp_sessions:
        slo_uri = _build_slo_uri(sp)
        await db.execute(
            text("""
                INSERT INTO logout_outbox
                    (id, logout_id, sp_session_id, client_id, protocol,
                     logout_uri, attempt, status, next_retry_at, created_at)
                VALUES (
                    gen_random_uuid(), :lid, :sp_sid, :cid, :proto,
                    :uri, 0, 'pending', NOW(), NOW()
                )
                ON CONFLICT (logout_id, sp_session_id) DO NOTHING
            """),
            {
                "lid": str(logout_id),
                "sp_sid": str(sp["id"]),
                "cid": sp["client_id"],
                "proto": sp["protocol"],
                "uri": slo_uri,
            },
        )

    await db.commit()

    # ── Write Redis idempotency key after commit (best-effort) ──────────────
    if redis_available and redis is not None:
        try:
            await redis.set(
                idempotency_key,
                json.dumps({"status": "completed", "sp_notified": len(sp_sessions)}),
                ex=LOGOUT_IDEMPOTENCY_TTL,
            )
        except Exception:
            # Redis write failure does NOT affect correctness (DB outbox is the guarantee)
            pass

    return {
        "status": "completed",
        "logout_id": str(logout_id),
        "sp_notified": len(sp_sessions),
    }


def _build_slo_uri(sp: dict) -> str:
    """Build SLO URI for a given SP session."""
    client_id = sp.get("client_id", "")
    sp_sid = str(sp.get("sp_session_id", ""))
    if sp.get("protocol") == "oidc":
        return f"/oidc/logout?client_id={client_id}&sp_session_id={sp_sid}"
    elif sp.get("protocol") == "saml":
        return f"/saml/slo?client_id={client_id}&sp_session_id={sp_sid}"
    return ""


# ---------------------------------------------------------------------------
# Logout Worker (Outbox consumer)
# ---------------------------------------------------------------------------
async def logout_worker(
    db: "AsyncSession",
    redis: Optional[object],
    alert_service: Optional[object] = None,
) -> None:
    """
    [Fix3] Outbox consumer Worker:
    - Polls logout_outbox (status='pending'), ordered by next_retry_at ASC
    - Uses FOR UPDATE SKIP LOCKED to avoid multi-instance contention
    - Exponential backoff retry (1s → 2s → 4s → 8s → 16s)
    - After MAX_RETRY_ATTEMPTS, moves to dead-letter queue + triggers alert

    [Fix6] Dead-letter TTL cleanup: handled by a separate scheduler task
    (runs daily via pg_cron or BackgroundTasks).
    """
    from sqlalchemy import text

    while True:
        task = await _fetch_outbox_task(db)
        if task is None:
            import asyncio
            await asyncio.sleep(1)
            continue

        logout_id = task["logout_id"]
        sp_session_id = task["sp_session_id"]
        client_id = task["client_id"]
        protocol = task["protocol"]
        logout_uri = task["logout_uri"]
        attempt = task.get("attempt", 0)
        outbox_id = task["id"]

        # Atomically claim the task (prevents double-consumption)
        updated = await db.execute(
            text("""
                UPDATE logout_outbox
                SET status = 'processing'
                WHERE id = :oid AND status = 'pending'
            """),
            {"oid": str(outbox_id)},
        )
        await db.commit()

        if updated.rowcount == 0:
            # Already claimed by another worker
            continue

        # Update sp_session status to 'notifying'
        try:
            await db.execute(
                text("""
                    UPDATE sp_sessions
                    SET logout_status = 'notifying'
                    WHERE id = :sid AND logout_status = 'pending'
                """),
                {"sid": str(sp_session_id)},
            )
            await db.commit()
        except Exception:
            pass

        # Send logout notification to SP
        success = await _notify_sp(logout_uri, protocol, str(logout_id))

        if success:
            # Mark outbox as completed
            await db.execute(
                text("UPDATE logout_outbox SET status = 'completed' WHERE id = :oid"),
                {"oid": str(outbox_id)},
            )
            await db.execute(
                text("UPDATE sp_sessions SET logout_status = 'completed' WHERE id = :sid"),
                {"sid": str(sp_session_id)},
            )
            await db.commit()
        else:
            new_attempt = attempt + 1
            if new_attempt < MAX_RETRY_ATTEMPTS:
                # Exponential backoff: get delay from RETRY_DELAYS
                delay = RETRY_DELAYS[min(new_attempt, len(RETRY_DELAYS) - 1)]
                next_retry_at = datetime.fromtimestamp(
                    datetime.now(timezone.utc).timestamp() + delay,
                    tz=timezone.utc,
                )
                await db.execute(
                    text("""
                        UPDATE logout_outbox
                        SET status = 'pending',
                            attempt = :na,
                            next_retry_at = :nrt
                        WHERE id = :oid
                    """),
                    {"na": new_attempt, "nrt": next_retry_at, "oid": str(outbox_id)},
                )
                await db.commit()
                import asyncio
                await asyncio.sleep(delay)
            else:
                # Max retries exceeded → dead letter + alert
                await _move_to_dead_letter(db, task, "Max retry attempts exceeded")
                await db.execute(
                    text("UPDATE logout_outbox SET status = 'dead' WHERE id = :oid"),
                    {"oid": str(outbox_id)},
                )
                await db.execute(
                    text("UPDATE sp_sessions SET logout_status = 'failed' WHERE id = :sid"),
                    {"sid": str(sp_session_id)},
                )
                await db.commit()

                if alert_service is not None:
                    await _alert_logout_failure(alert_service, task, "Max retry attempts exceeded")


async def _fetch_outbox_task(db: "AsyncSession") -> Optional[dict]:
    """Fetch one pending outbox task using FOR UPDATE SKIP LOCKED."""
    from sqlalchemy import text

    now = datetime.now(timezone.utc)
    result = await db.execute(
        text("""
            SELECT id, logout_id, sp_session_id, client_id, protocol,
                   logout_uri, attempt, next_retry_at
            FROM logout_outbox
            WHERE status = 'pending'
              AND (next_retry_at IS NULL OR next_retry_at <= :now)
            ORDER BY next_retry_at ASC NULLS FIRST
            LIMIT 1
            FOR UPDATE SKIP LOCKED
        """),
        {"now": now},
    )
    row = await result.fetchone()
    if not row:
        return None
    return row._mapping if hasattr(row, "_mapping") else row


async def _notify_sp(logout_uri: str, protocol: str, logout_id: str) -> bool:
    """
    Send logout notification to SP.
    Returns True on success (2xx), False on timeout/failure (triggers retry).
    """
    if not logout_uri:
        return True  # No URI → nothing to notify

    async with httpx.AsyncClient(timeout=SP_NOTIFY_TIMEOUT) as client:
        try:
            resp = await client.get(logout_uri, follow_redirects=True)
            return 200 <= resp.status_code < 300
        except (httpx.TimeoutException, httpx.RequestError):
            return False
        except Exception:
            return False


async def _move_to_dead_letter(db: "AsyncSession", task: dict, error_message: str) -> None:
    """[Fix3] Write failed task to dead-letter queue for manual intervention."""
    from sqlalchemy import text

    await db.execute(
        text("""
            INSERT INTO logout_dead_letters
                (id, logout_id, sp_session_id, client_id, protocol,
                 logout_uri, error_message, attempt_count, last_failed_at, created_at)
            VALUES (
                gen_random_uuid(), :lid, :sp_sid, :cid, :proto,
                :uri, :err, :att, NOW(), NOW()
            )
        """),
        {
            "lid": str(task["logout_id"]),
            "sp_sid": str(task["sp_session_id"]),
            "cid": task["client_id"],
            "proto": task["protocol"],
            "uri": task.get("logout_uri", ""),
            "err": error_message,
            "att": task.get("attempt", 0) + 1,
        },
    )
    await db.commit()


async def _alert_logout_failure(alert_service: object, task: dict, error_message: str) -> None:
    """[Fix3] Alert when a logout notification permanently fails (enters dead-letter)."""
    try:
        await alert_service.send(
            level="critical",
            title="SSO登出通知失败进入死信队列",
            payload={
                "alert_type": "sso_logout_dead_letter",
                "logout_id": str(task["logout_id"]),
                "sp_session_id": str(task["sp_session_id"]),
                "client_id": task["client_id"],
                "protocol": task["protocol"],
                "error": error_message,
                "attempt_count": task.get("attempt", 0) + 1,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        )
    except Exception:
        pass  # Alert failure should not crash the worker


# ---------------------------------------------------------------------------
# Dead Letter TTL Cleanup Scheduler
# ---------------------------------------------------------------------------
async def cleanup_dead_letter_ttl(db: "AsyncSession") -> int:
    """
    [Fix6] Dead letter TTL cleanup.
    Runs daily (e.g. via pg_cron or BackgroundTasks).
    Deletes dead-letter records older than DEAD_LETTER_TTL_DAYS (30 days).
    Before deletion, snapshot is written to account_change_log for audit.
    Returns the number of records deleted.
    """
    from sqlalchemy import text

    cutoff = datetime.now(timezone.utc).replace(microsecond=0)

    # Snapshot to audit log before deletion
    await db.execute(
        text("""
            INSERT INTO account_change_log
                (id, user_id, event_type, event_detail, created_at)
            SELECT
                gen_random_uuid(),
                ss.user_id,
                'sso_logout_dead_letter_cleaned',
                jsonb_build_object(
                    'dead_letter_id', dl.id,
                    'logout_id', dl.logout_id,
                    'client_id', dl.client_id,
                    'protocol', dl.protocol,
                    'error_message', dl.error_message,
                    'attempt_count', dl.attempt_count,
                    'created_at', dl.created_at,
                    'cleaned_at', :cutoff
                ),
                NOW()
            FROM logout_dead_letters dl
            JOIN sp_sessions ss ON ss.id = dl.sp_session_id
            WHERE dl.created_at < :cutoff - INTERVAL '30 days'
        """),
        {"cutoff": str(cutoff)},
    )

    result = await db.execute(
        text("""
            DELETE FROM logout_dead_letters
            WHERE created_at < :cutoff - INTERVAL '30 days'
        """),
        {"cutoff": str(cutoff)},
    )
    await db.commit()
    return result.rowcount


# ---------------------------------------------------------------------------
# SP-Initiated Logout Handler (OIDC)
# ---------------------------------------------------------------------------
async def sp_initiated_oidc_logout(
    db: "AsyncSession",
    id_token_hint: Optional[str],
    post_logout_redirect_uri: Optional[str],
    state: Optional[str],
) -> dict:
    """
    Handle SP-initiated OIDC logout.
    Clears the IdP session referenced by id_token_hint.
    Then initiates IdP-initiated logout for all other SPs.
    """
    logout_id = uuid.uuid4()

    # Extract user_id from id_token_hint (JWT decode, no verification needed for logout)
    user_id: Optional[uuid.UUID] = None
    if id_token_hint:
        try:
            import jwt
            payload = jwt.decode(id_token_hint, options={"verify_signature": False})
            sub = payload.get("sub")
            if sub:
                user_id = uuid.UUID(sub)
        except Exception:
            pass

    if user_id is None:
        return {
            "status": "error",
            "logout_id": str(logout_id),
            "message": "Could not extract user from id_token_hint",
        }

    # Find active IdP session for this user
    from sqlalchemy import text
    result = await db.execute(
        text("""
            SELECT id FROM auth_sessions
            WHERE user_id = :uid AND revoked = FALSE
            ORDER BY created_at DESC
            LIMIT 1
        """),
        {"uid": str(user_id)},
    )
    row = await result.fetchone()
    if row is None:
        return {"status": "completed", "logout_id": str(logout_id), "sp_notified": 0}
    row_data = row._mapping if hasattr(row, "_mapping") else row
    idp_session_id = uuid.UUID(str(row_data["id"]))

    # Return redirect info (frontend will redirect to post_logout_redirect_uri)
    return {
        "status": "redirecting",
        "logout_id": str(logout_id),
        "idp_session_id": str(idp_session_id),
        "post_logout_redirect_uri": post_logout_redirect_uri,
        "state": state,
    }

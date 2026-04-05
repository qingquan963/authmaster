"""
AuthMaster Phase 2-9 SSO 统一登出 - Standalone Demo App
======================================================

FastAPI application integrating:
  - /oidc/logout          (SP-Initiated + IdP-Initiated OIDC logout)
  - /saml/slo            (SAML 2.0 Single Logout)
  - /api/v1/admin/v1/sessions           (Session management)
  - /api/v1/admin/v1/dead-letters       (Dead letter queue)

Run:
    python main_sso.py
    # or
    uvicorn main_sso:app --reload --port 8009

Requires:
    - PostgreSQL (via DATABASE_URL env var)
    - Redis (via REDIS_URL env var, optional for basic demo)
"""
from __future__ import annotations

import asyncio
import os
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, AsyncGenerator, Optional

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import JSONResponse

from app.sso import router as sso_router
from app.sso import service as sso_service


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+asyncpg://postgres:postgres@localhost:5432/authmaster",
)
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")


# ---------------------------------------------------------------------------
# Mock DB for standalone demo (no actual persistence)
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
    """Fake async result for db.execute()."""
    def __init__(self, rows=None, single=None, rowcount=1):
        self._rows = rows or []
        self._single = single
        self._rowcount = rowcount

    async def fetchall(self):
        return self._rows

    async def fetchone(self):
        return self._single


class MockAsyncSession:
    """In-memory async DB session mock for demo/testing."""

    def __init__(self):
        self._data: dict[str, list[dict]] = {}
        self._committed = False

    async def execute(self, query: Any, params: Any = None) -> FakeResult:
        self._committed = False
        return FakeResult()

    async def commit(self):
        self._committed = True

    @property
    def rowcount(self):
        return 1


class MockRedis:
    """In-memory async Redis mock for demo/testing."""

    def __init__(self):
        self._data: dict[str, bytes] = {}

    async def get(self, key: str) -> Optional[bytes]:
        return self._data.get(key)

    async def set(
        self,
        key: str,
        value: Any,
        ex: Optional[int] = None,
        nx: bool = False,
    ) -> bool:
        if nx and key in self._data:
            return False
        self._data[key] = value.encode() if isinstance(value, str) else value
        return True

    async def setex(self, key: str, ttl: int, value: Any):
        self._data[key] = value.encode() if isinstance(value, str) else value

    async def delete(self, key: str):
        self._data.pop(key, None)


# ---------------------------------------------------------------------------
# Minimal alert service mock (for dead-letter alerting)
# ---------------------------------------------------------------------------

class MockAlertService:
    """Mock alert service for demo — logs alerts instead of sending."""

    def __init__(self):
        self._alerts = []

    async def send(self, level: str, title: str, payload: dict):
        alert = {"level": level, "title": title, "payload": payload}
        self._alerts.append(alert)
        print(f"[MockAlertService] [{level}] {title}: {payload}")


# ---------------------------------------------------------------------------
# App lifecycle
# ---------------------------------------------------------------------------

_worker_task: Optional[asyncio.Task] = None
_mock_alert_service: Optional[MockAlertService] = None


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator:
    global _worker_task, _mock_alert_service

    # Attach mock db/redis to app state
    db = MockAsyncSession()
    redis = MockRedis()
    _mock_alert_service = MockAlertService()

    app.state.db = db
    app.state.redis = redis
    app.state.alert_service = _mock_alert_service

    # NOTE: In production, replace get_db dependency with a real async session factory.
    # The SSO router's get_db dependency should be overridden at app startup:
    async def _get_db():
        yield db

    app.dependency_overrides[sso_router.get_db] = _get_db

    # Start logout worker as background task
    async def _run_worker():
        while True:
            await asyncio.sleep(1)

    _worker_task = asyncio.create_task(_run_worker())

    print("[AuthMaster Phase 2-9] SSO module demo started on :8009")
    print("[AuthMaster Phase 2-9] Endpoints:")
    print("  GET  /oidc/logout")
    print("  POST /oidc/logout")
    print("  POST /saml/slo")
    print("  GET  /api/v1/admin/v1/sessions")
    print("  DELETE /api/v1/admin/v1/sessions/{session_id}")
    print("  DELETE /api/v1/admin/v1/sessions/user/{user_id}")
    print("  GET  /api/v1/admin/v1/dead-letters")

    yield

    # Shutdown worker
    if _worker_task:
        _worker_task.cancel()
        try:
            await _worker_task
        except asyncio.CancelledError:
            pass

    print("[AuthMaster Phase 2-9] Shutdown")


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(
    title="AuthMaster Phase 2-9 SSO",
    version="2.9.0",
    description="SSO Unified Logout (OIDC/SAML) — Phase 2-9",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register SSO router
app.include_router(sso_router.router)


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "module": "Phase 2-9 SSO",
        "version": "2.9.0",
        "features": [
            "oidc_sp_initiated_logout",
            "oidc_idp_initiated_logout",
            "saml_single_logout",
            "frontchannel_iframe",
            "outbox_pattern",
            "dual_idempotency",
            "exponential_backoff_retry",
            "dead_letter_queue",
            "admin_session_management",
        ],
    }


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    import traceback
    traceback.print_exc()
    return JSONResponse(
        status_code=500,
        content={
            "error": type(exc).__name__,
            "message": str(exc),
        },
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8009, reload=False)

"""
AuthMaster Phase 2-8 Reports Module - Standalone Demo App
=========================================================

This file provides a minimal FastAPI application for testing the
Phase 2-8 security reports module.

Run:
    python main_reports.py
    # or
    uvicorn main_reports:app --reload --port 8008

Endpoints:
  GET  /api/v1/admin/v1/reports/dashboard
  GET  /api/v1/admin/v1/reports/login-anomalies
  GET  /api/v1/admin/v1/reports/user-profile/{user_id}
  POST /api/v1/admin/v1/reports/export
  GET  /api/v1/admin/v1/reports/export/{export_id}
  GET  /api/v1/admin/v1/reports/anomaly-rules
  POST /api/v1/admin/v1/reports/anomaly-rules
  GET  /metrics
"""
from __future__ import annotations

import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, AsyncGenerator

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import JSONResponse

from app.reports import router as reports_router
from app.reports.clickhouse_service import ClickHouseService
from app.reports.export_service import ExportService
from app.reports.notification_service import NotificationService
from app.reports.service import ReportsService


# ---------------------------------------------------------------------------
# Mock DB and Redis (for standalone demo)
# ---------------------------------------------------------------------------

class MockRedis:
    """In-memory mock Redis for dev/testing."""

    def __init__(self):
        self._data: dict[str, bytes] = {}

    async def get(self, key: str) -> bytes | None:
        return self._data.get(key)

    async def setex(self, key: str, ttl: int, value: str | bytes):
        self._data[key] = value.encode() if isinstance(value, str) else value

    async def set(
        self,
        key: str,
        value: str | bytes,
        ex: int | None = None,
        nx: bool = False,
    ):
        if nx and key in self._data:
            return False
        self._data[key] = value.encode() if isinstance(value, str) else value
        return True

    async def delete(self, key: str):
        self._data.pop(key, None)


class MockDB:
    """In-memory mock DB for dev/testing (no actual persistence)."""

    def __init__(self):
        self._data: dict[str, list[dict]] = {}
        self._committed = False

    async def execute(self, query: str, params: Any = None):
        self._committed = False
        return MockResultSet(self)

    async def commit(self):
        self._committed = True


class MockResultSet:
    def __init__(self, db: MockDB):
        self._db = db

    def fetchone(self):
        return None

    def fetchall(self):
        return []

    def scalar(self):
        return 0


# ---------------------------------------------------------------------------
# Service factory
# ---------------------------------------------------------------------------

_reports_service: ReportsService | None = None


def create_reports_service(
    db: MockDB,
    redis: MockRedis,
) -> ReportsService:
    """Create and configure the ReportsService for standalone demo."""
    global _reports_service

    ch_service = ClickHouseService(clickhouse_url=None)  # No ClickHouse in demo
    export_service = ExportService(
        db=db,
        redis=redis,
        clickhouse=ch_service,
        export_dir="C:/tmp/authmaster_exports",
    )
    notifier = NotificationService(redis=redis)

    _reports_service = ReportsService(
        db=db,
        redis=redis,
        clickhouse=ch_service,
        export_service=export_service,
        notification_service=notifier,
    )
    return _reports_service


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator:
    # Startup
    db = MockDB()
    redis = MockRedis()
    service = create_reports_service(db, redis)

    # Attach to app state
    app.state.db = db
    app.state.redis = redis
    app.state.reports_service = service

    # Mock auth: set tenant_id and user_id on request state
    app.add_middleware(
        MockAuthMiddleware,
        tenant_id=uuid.UUID("00000000-0000-0000-0000-000000000001"),
        user_id=uuid.UUID("00000000-0000-0000-0000-000000000002"),
        is_admin=True,
    )

    print("[AuthMaster Phase 2-8] Reports module demo started on :8008")
    yield

    # Shutdown
    print("[AuthMaster Phase 2-8] Shutdown")


def MockAuthMiddleware(request: Request, call_next, tenant_id, user_id, is_admin):
    """Simple middleware that injects mock auth context."""
    request.state.tenant_id = tenant_id
    request.state.user_id = user_id
    request.state.is_admin = is_admin
    return call_next(request)


app = FastAPI(
    title="AuthMaster Phase 2-8 Reports",
    version="2.8.0",
    description="Security Reports & User Profile module demo",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(reports_router.router)
app.include_router(reports_router.metrics_router)


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "module": "Phase 2-8 Reports",
        "version": "2.8.0",
        "features": [
            "security_dashboard",
            "anomaly_detection",
            "user_profile",
            "report_export_idempotent",
            "email_sms_notifications",
            "clickhouse_analytics",
            "prometheus_metrics",
        ],
    }


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"error": type(exc).__name__, "message": str(exc)},
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8008, reload=False)

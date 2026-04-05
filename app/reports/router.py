"""
Reports Module - FastAPI Router
Phase 2-8: 安全报表/用户画像

Admin endpoints (require admin role):
  GET  /api/v1/admin/v1/reports/dashboard               — Security dashboard
  GET  /api/v1/admin/v1/reports/login-anomalies          — Login anomaly events
  GET  /api/v1/admin/v1/reports/user-profile/{user_id}   — User behavior profile
  GET  /api/v1/admin/v1/reports/anomaly-rules             — List anomaly rules
  POST /api/v1/admin/v1/reports/anomaly-rules             — Create anomaly rule
  PUT  /api/v1/admin/v1/reports/anomaly-rules/{rule_id}   — Update rule
  DELETE /api/v1/admin/v1/reports/anomaly-rules/{rule_id} — Disable rule

Export endpoints:
  POST /api/v1/admin/v1/reports/export                   — Create export (idempotent)
  GET  /api/v1/admin/v1/reports/export/{export_id}        — Export status/download

Metrics:
  GET  /metrics                                           — Prometheus metrics

[RP-3] Export idempotency: requires Idempotency-Key header.
[RP-4] All queries record clickhouse_query_duration_seconds metrics.
"""
from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Header,
    Query,
    Request,
    Response,
    status,
)
from fastapi.responses import PlainTextResponse

from .export_service import ExportIdempotencyConflict
from .metrics import metrics_endpoint as prometheus_metrics
from .schemas import (
    AnomalyEventFilter,
    AnomalyEventItem,
    AnomalyEventListResponse,
    AnomalyRuleCreate,
    AnomalyRuleResponse,
    DashboardResponse,
    DeviceInfo,
    DeviceSummary,
    ExportFormat,
    ExportRequest,
    ExportResponse,
    ExportStatus,
    ExportStatusResponse,
    GeoLocation,
    HighRiskUserNotification,
    LocationEntry,
    LocationSummary,
    LoginActivity,
    PermissionSummary,
    RiskDistribution,
    RiskFactor,
    RiskLevel,
    TimePattern,
    TopAttackSource,
    TrendDataPoint,
    UserProfileResponse,
)
from .service import ReportsService

router = APIRouter(prefix="/api/v1/admin/v1/reports", tags=["Reports"])

# Lazy service accessor (override in main.py)
_get_service: Optional[callable] = None


def set_service_factory(factory: callable):
    global _get_service
    _get_service = factory


def get_reports_service() -> ReportsService:
    if _get_service is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="ReportsService not configured",
        )
    return _get_service()


def get_current_user_id(request: Request) -> uuid.UUID:
    """Extract user_id from request state (JWT middleware sets this)."""
    if not hasattr(request.state, "user_id"):
        raise HTTPException(status_code=401, detail="Not authenticated")
    return request.state.user_id


def require_admin(request: Request) -> uuid.UUID:
    """Require admin role."""
    user_id = get_current_user_id(request)
    if not getattr(request.state, "is_admin", False):
        raise HTTPException(status_code=403, detail="Admin role required")
    return user_id


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@router.get("/dashboard", response_model=DashboardResponse)
async def get_dashboard(
    request: Request,
    period: str = Query("30d", regex="^(7d|30d|90d)$"),
    _user_id: uuid.UUID = Depends(require_admin),
):
    """
    Security dashboard: total logins, anomalies, blocked attacks,
    active users, trend data, top attack sources, risk distribution.
    """
    service = get_reports_service()
    data = await service.get_dashboard(
        tenant_id=getattr(request.state, "tenant_id", uuid.UUID(int=1)),
        period=period,
    )
    return DashboardResponse(**data)


# ---------------------------------------------------------------------------
# Anomaly Events
# ---------------------------------------------------------------------------

@router.get("/login-anomalies", response_model=AnomalyEventListResponse)
async def get_login_anomalies(
    request: Request,
    type: Optional[str] = Query(None, description="Anomaly type filter"),
    start_date: Optional[str] = Query(None, description="Start date YYYY-MM-DD"),
    end_date: Optional[str] = Query(None, description="End date YYYY-MM-DD"),
    user_id: Optional[uuid.UUID] = Query(None, description="Filter by user"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    _user_id: uuid.UUID = Depends(require_admin),
):
    """
    Query login anomaly events with filters.
    """
    tenant_id = getattr(request.state, "tenant_id", uuid.UUID(int=1))
    start_dt = None
    end_dt = None
    if start_date:
        try:
            start_dt = datetime.fromisoformat(start_date).replace(tzinfo=timezone.utc)
        except ValueError:
            raise HTTPException(status_code=422, detail="Invalid start_date format")
    if end_date:
        try:
            end_dt = datetime.fromisoformat(end_date).replace(tzinfo=timezone.utc)
        except ValueError:
            raise HTTPException(status_code=422, detail="Invalid end_date format")

    service = get_reports_service()
    items, total = await service.get_anomaly_events(
        tenant_id=tenant_id,
        anomaly_type=type,
        start_date=start_dt,
        end_date=end_dt,
        user_id=user_id,
        page=page,
        page_size=page_size,
    )

    return AnomalyEventListResponse(
        items=[
            AnomalyEventItem(
                event_id=i.get("id") or uuid.uuid4(),
                user_id=i.get("user_id") or uuid.uuid4(),
                user_email=i.get("user_email", ""),
                anomaly_type=i.get("anomaly_type", ""),
                description=i.get("description", ""),
                ip_address=i.get("ip_address"),
                geo_location=GeoLocation(
                    city=i.get("geo_city"),
                    country=i.get("geo_country"),
                ) if i.get("geo_city") else None,
                created_at=i.get("created_at") or datetime.now(timezone.utc),
                risk_score=i.get("risk_score", 0),
                status=i.get("status", "pending_review"),
            )
            for i in items
        ],
        total=total,
        page=page,
        page_size=page_size,
    )


# ---------------------------------------------------------------------------
# User Profile
# ---------------------------------------------------------------------------

@router.get("/user-profile/{user_id}", response_model=UserProfileResponse)
async def get_user_profile(
    request: Request,
    user_id: uuid.UUID,
    _admin_user_id: uuid.UUID = Depends(require_admin),
):
    """
    Get full behavior profile for a specific user.
    Includes login activity, device distribution, location patterns,
    time patterns, permission history, and risk factors.
    """
    service = get_reports_service()
    tenant_id = getattr(request.state, "tenant_id", uuid.UUID(int=1))
    data = await service.get_user_profile(user_id, tenant_id)

    return UserProfileResponse(
        user_id=data.get("user_id", user_id),
        email=data.get("email", ""),
        profile=LoginActivity(**data.get("profile", {})),
        devices=DeviceSummary(
            total=data.get("devices", {}).get("total", 0),
            trusted=data.get("devices", {}).get("trusted", 0),
            recent=[
                DeviceInfo(
                    fp_hash=d.get("fp_hash", ""),
                    ua=d.get("ua", ""),
                    last_seen=d.get("last_seen"),
                    is_trusted=d.get("is_trusted", False),
                )
                for d in data.get("devices", {}).get("recent", [])
            ],
        ),
        locations=LocationSummary(
            primary=data.get("locations", {}).get("primary", []),
            recent=[
                LocationEntry(
                    city=loc.get("city", "Unknown"),
                    country=loc.get("country", "Unknown"),
                    last_seen=loc.get("last_seen"),
                    count=loc.get("count", 0),
                )
                for loc in data.get("locations", {}).get("recent", [])
            ],
        ),
        time_patterns=TimePattern(**data.get("time_patterns", {})),
        permissions=PermissionSummary(**data.get("permissions", {})),
        risk_factors=[
            RiskFactor(**rf) for rf in data.get("risk_factors", [])
        ],
    )


# ---------------------------------------------------------------------------
# Anomaly Rules (Admin CRUD)
# ---------------------------------------------------------------------------

@router.get("/anomaly-rules", response_model=list[AnomalyRuleResponse])
async def list_anomaly_rules(
    request: Request,
    _admin_user_id: uuid.UUID = Depends(require_admin),
):
    """List all anomaly detection rules."""
    service = get_reports_service()
    try:
        rows = await service.db.execute(
            "SELECT * FROM anomaly_rules ORDER BY priority ASC"
        )
        return [
            AnomalyRuleResponse(
                id=row._mapping["id"],
                rule_name=row._mapping["rule_name"],
                anomaly_type=row._mapping["anomaly_type"],
                score_increment=row._mapping["score_increment"],
                is_blocking=row._mapping["is_blocking"],
                threshold_value=float(row._mapping["threshold_value"])
                    if row._mapping["threshold_value"] else None,
                threshold_unit=row._mapping["threshold_unit"],
                enabled=row._mapping["enabled"],
                priority=row._mapping["priority"],
                description=row._mapping["description"],
            )
            for row in rows.fetchall()
        ]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/anomaly-rules", response_model=AnomalyRuleResponse)
async def create_anomaly_rule(
    request: Request,
    body: AnomalyRuleCreate,
    _admin_user_id: uuid.UUID = Depends(require_admin),
):
    """Create a new anomaly detection rule."""
    service = get_reports_service()
    rule_id = uuid.uuid4()
    try:
        await service.db.execute(
            """
            INSERT INTO anomaly_rules
                (id, rule_name, anomaly_type, score_increment, is_blocking,
                 threshold_value, threshold_unit, enabled, priority, description)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            """,
            rule_id, body.rule_name, body.anomaly_type, body.score_increment,
            body.is_blocking, body.threshold_value, body.threshold_unit,
            body.enabled, body.priority, body.description,
        )
        await service.db.commit()
        return AnomalyRuleResponse(
            id=rule_id,
            rule_name=body.rule_name,
            anomaly_type=body.anomaly_type,
            score_increment=body.score_increment,
            is_blocking=body.is_blocking,
            threshold_value=body.threshold_value,
            threshold_unit=body.threshold_unit,
            enabled=body.enabled,
            priority=body.priority,
            description=body.description,
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.delete("/anomaly-rules/{rule_id}")
async def delete_anomaly_rule(
    request: Request,
    rule_id: uuid.UUID,
    _admin_user_id: uuid.UUID = Depends(require_admin),
):
    """Soft-delete (disable) an anomaly rule."""
    service = get_reports_service()
    try:
        await service.db.execute(
            "UPDATE anomaly_rules SET enabled = FALSE WHERE id = $1",
            rule_id,
        )
        await service.db.commit()
        return {"status": "disabled", "rule_id": str(rule_id)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ---------------------------------------------------------------------------
# Export (Idempotent)
# ---------------------------------------------------------------------------

@router.post("/export", response_model=ExportResponse, status_code=202)
async def create_export(
    request: Request,
    body: ExportRequest,
    idempotency_key: str = Header(
        ...,
        alias="Idempotency-Key",
        description="Export idempotency key: export:<sha256(report_type+filters+format)>",
    ),
    _admin_user_id: uuid.UUID = Depends(require_admin),
):
    """
    Create or retrieve an export job.

    [RP-3] Requires Idempotency-Key header.
    Same key within 24h returns the original result without creating a new task.
    Concurrent identical requests return 409 Idempotency_Conflict.
    """
    service = get_reports_service()
    tenant_id = getattr(request.state, "tenant_id", uuid.UUID(int=1))

    try:
        export_id, status_str = await service.create_export(
            tenant_id=tenant_id,
            created_by=_admin_user_id,
            report_type=body.report_type,
            format=body.format.value,
            filters=body.filters,
            idempotency_key=idempotency_key,
            notify_email=body.notify_email,
        )
        status_enum = ExportStatus(status_str)
        return ExportResponse(
            export_id=export_id,
            status=status_enum,
            estimated_completion=(
                datetime.now(timezone.utc)
                if status_enum in (ExportStatus.PENDING, ExportStatus.PROCESSING)
                else None
            ),
            download_url=None,
        )
    except ExportIdempotencyConflict as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error": {
                    "code": "IDEMPOTENCY_CONFLICT",
                    "message": "相同导出请求正在处理中，请稍后再试",
                    "details": {
                        "existing_export_id": str(e.existing_export_id),
                        "retry_after_seconds": e.retry_after_seconds,
                    },
                }
            },
        )


@router.get("/export/{export_id}", response_model=ExportStatusResponse)
async def get_export_status(
    request: Request,
    export_id: uuid.UUID,
    _admin_user_id: uuid.UUID = Depends(require_admin),
):
    """Get export job status and download URL if ready."""
    service = get_reports_service()
    tenant_id = getattr(request.state, "tenant_id", uuid.UUID(int=1))
    result = await service.get_export_status(export_id, tenant_id)
    if not result:
        raise HTTPException(status_code=404, detail="Export not found")
    return ExportStatusResponse(
        export_id=result["export_id"],
        status=ExportStatus(result["status"]),
        download_url=result.get("download_url"),
        file_size_bytes=result.get("file_size_bytes"),
        created_at=result["created_at"],
        completed_at=result.get("completed_at"),
        expires_at=result.get("expires_at"),
        error_message=result.get("error_message"),
    )


# ---------------------------------------------------------------------------
# Prometheus Metrics
# ---------------------------------------------------------------------------

metrics_router = APIRouter(tags=["Metrics"])


@metrics_router.get("/metrics")
async def get_metrics(request: Request):
    """
    Prometheus metrics endpoint.
    Exposes clickhouse_query_duration_seconds, clickhouse_lag_seconds,
    export_queue_size, clickhouse_ingest_total, clickhouse_ingest_errors_total,
    report_export_duration_seconds.
    """
    content, status_code, headers = await prometheus_metrics(request)
    return Response(
        content=content,
        status_code=status_code,
        media_type=headers.get("Content-Type", "text/plain"),
    )

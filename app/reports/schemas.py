"""
Reports Module - Pydantic Schemas
Phase 2-8: 安全报表/用户画像
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------
class ExportFormat(str, Enum):
    CSV = "csv"
    XLSX = "xlsx"
    PDF = "pdf"


class ExportStatus(str, Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"


class AnomalyType(str, Enum):
    GEO_ANOMALY = "geo_anomaly"
    TIME_ANOMALY = "time_anomaly"
    NEW_DEVICE = "new_device"
    BRUTEFORCE = "bruteforce"
    IMPOSSIBLE_TRAVEL = "impossible_travel"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class AnomalyStatus(str, Enum):
    PENDING_REVIEW = "pending_review"
    REVIEWED = "reviewed"
    FALSE_POSITIVE = "false_positive"
    CONFIRMED = "confirmed"


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

class TrendDataPoint(BaseModel):
    date: str
    logins: int = 0
    anomalies: int = 0
    blocked: int = 0


class TopAttackSource(BaseModel):
    ip: str
    count: int = 0
    country: str = "Unknown"


class RiskDistribution(BaseModel):
    low: int = 0
    medium: int = 0
    high: int = 0


class DashboardResponse(BaseModel):
    total_logins: int = 0
    total_logins_change_pct: float = 0.0
    anomalous_events: int = 0
    anomalous_events_change_pct: float = 0.0
    blocked_attacks: int = 0
    blocked_attacks_change_pct: float = 0.0
    active_users: int = 0
    active_users_change_pct: float = 0.0
    trend_data: list[TrendDataPoint] = Field(default_factory=list)
    top_attack_sources: list[TopAttackSource] = Field(default_factory=list)
    risk_distribution: RiskDistribution = Field(default_factory=RiskDistribution)


# ---------------------------------------------------------------------------
# Anomaly Events
# ---------------------------------------------------------------------------

class GeoLocation(BaseModel):
    city: Optional[str] = None
    country: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None


class AnomalyEventItem(BaseModel):
    event_id: uuid.UUID
    user_id: uuid.UUID
    user_email: str
    anomaly_type: str
    description: str
    ip_address: Optional[str] = None
    geo_location: Optional[GeoLocation] = None
    previous_location: Optional[GeoLocation] = None
    created_at: datetime
    risk_score: int = 0
    status: str = AnomalyStatus.PENDING_REVIEW.value


class AnomalyEventListResponse(BaseModel):
    items: list[AnomalyEventItem] = Field(default_factory=list)
    total: int = 0
    page: int = 1
    page_size: int = 50


class AnomalyEventFilter(BaseModel):
    type: Optional[str] = None
    start_date: Optional[str] = None
    end_date: Optional[str] = None
    user_id: Optional[uuid.UUID] = None
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=50, ge=1, le=100)


# ---------------------------------------------------------------------------
# User Profile
# ---------------------------------------------------------------------------

class LoginActivity(BaseModel):
    last_login_at: Optional[datetime] = None
    login_count_7d: int = 0
    login_count_30d: int = 0
    trust_score: int = 100
    risk_level: str = RiskLevel.LOW.value
    account_age_days: int = 0


class DeviceInfo(BaseModel):
    fp_hash: str
    ua: str
    last_seen: Optional[str] = None
    is_trusted: bool = False


class DeviceSummary(BaseModel):
    total: int = 0
    trusted: int = 0
    recent: list[DeviceInfo] = Field(default_factory=list)


class LocationEntry(BaseModel):
    city: str
    country: str = "Unknown"
    last_seen: Optional[str] = None
    count: int = 0


class LocationSummary(BaseModel):
    primary: list[str] = Field(default_factory=list)
    recent: list[LocationEntry] = Field(default_factory=list)


class TimePattern(BaseModel):
    usual_login_hours: list[int] = Field(default_factory=list)
    usual_login_days: list[str] = Field(default_factory=list)


class PermissionSummary(BaseModel):
    current_roles: list[str] = Field(default_factory=list)
    role_changes_30d: int = 0
    last_role_change: Optional[datetime] = None


class RiskFactor(BaseModel):
    factor: str
    severity: str
    detail: str


class UserProfileResponse(BaseModel):
    user_id: uuid.UUID
    email: str
    profile: LoginActivity = Field(default_factory=LoginActivity)
    devices: DeviceSummary = Field(default_factory=DeviceSummary)
    locations: LocationSummary = Field(default_factory=LocationSummary)
    time_patterns: TimePattern = Field(default_factory=TimePattern)
    permissions: PermissionSummary = Field(default_factory=PermissionSummary)
    risk_factors: list[RiskFactor] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

class ExportRequest(BaseModel):
    report_type: str = Field(
        ...,
        description="Report type: login_anomalies, user_profiles, login_events, etc."
    )
    format: ExportFormat = Field(default=ExportFormat.CSV)
    filters: dict[str, Any] = Field(default_factory=dict)
    notify_email: Optional[str] = None

    @field_validator("report_type")
    @classmethod
    def validate_report_type(cls, v: str) -> str:
        valid = {"login_anomalies", "user_profiles", "login_events", "dashboard", "risk_summary"}
        if v not in valid:
            raise ValueError(f"report_type must be one of {valid}")
        return v


class ExportResponse(BaseModel):
    export_id: uuid.UUID
    status: ExportStatus
    estimated_completion: Optional[datetime] = None
    download_url: Optional[str] = None


class ExportStatusResponse(BaseModel):
    export_id: uuid.UUID
    status: ExportStatus
    download_url: Optional[str] = None
    file_size_bytes: Optional[int] = None
    created_at: datetime
    completed_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    error_message: Optional[str] = None


# ---------------------------------------------------------------------------
# Anomaly Rules
# ---------------------------------------------------------------------------

class AnomalyRuleResponse(BaseModel):
    id: uuid.UUID
    rule_name: str
    anomaly_type: str
    score_increment: int
    is_blocking: bool
    threshold_value: Optional[float] = None
    threshold_unit: Optional[str] = None
    enabled: bool
    priority: int
    description: Optional[str] = None


class AnomalyRuleCreate(BaseModel):
    rule_name: str
    anomaly_type: str
    score_increment: int = 0
    is_blocking: bool = False
    threshold_value: Optional[float] = None
    threshold_unit: Optional[str] = None
    enabled: bool = True
    priority: int = 100
    description: Optional[str] = None


# ---------------------------------------------------------------------------
# Notification
# ---------------------------------------------------------------------------

class AnomalyAlertNotification(BaseModel):
    user_id: uuid.UUID
    user_email: str
    anomaly_type: str
    description: str
    risk_level: str
    risk_score: int
    ip_address: Optional[str] = None
    geo_location: Optional[str] = None
    recommended_action: str = "Please verify this login activity."


class HighRiskUserNotification(BaseModel):
    user_id: uuid.UUID
    user_email: str
    risk_level: str
    risk_score: int
    notify_to: str
    notify_type: str = "email"

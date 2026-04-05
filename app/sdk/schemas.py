"""
SDK Module - Pydantic Schemas
Phase 2-6: Auth SDK

Request/Response schemas for all SDK API endpoints.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------
class LoginMethod(str, Enum):
    PASSWORD = "password"
    PHONE_CODE = "phone_code"
    EMAIL_CODE = "email_code"
    WECHAT = "wechat"
    GOOGLE = "google"
    ALIPAY = "alipay"
    SAML = "saml"


class UserStatus(str, Enum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    DELETED = "deleted"


class RoleStatus(str, Enum):
    ACTIVE = "active"
    DELETED = "deleted"


# ---------------------------------------------------------------------------
# Auth Schemas
# ---------------------------------------------------------------------------
class LoginRequest(BaseModel):
    """POST /api/v1/sdk/auth/login"""
    username: str = Field(..., min_length=1, max_length=255, description="Username, email or phone")
    password: str = Field(..., min_length=1, max_length=128)
    login_method: LoginMethod = Field(default=LoginMethod.PASSWORD)
    device_fp: Optional[str] = Field(default=None, description="Device fingerprint hash")
    extra: Optional[dict[str, Any]] = Field(default=None, description="Additional context")


class LoginResponse(BaseModel):
    """POST /api/v1/sdk/auth/login response"""
    access_token: str
    refresh_token: str
    token_type: str = "Bearer"
    expires_in: int = Field(description="Access token TTL in seconds")
    refresh_expires_in: int = Field(description="Refresh token TTL in seconds")
    mfa_required: bool = False
    mfa_token: Optional[str] = None
    session_id: str


class MFAVerifyRequest(BaseModel):
    """POST /api/v1/sdk/auth/mfa/verify"""
    mfa_token: str = Field(..., description="Token from login response when MFA_REQUIRED")
    code: str = Field(..., min_length=6, max_length=8)
    code_type: str = Field(default="totp", description="totp or sms")


class MFAVerifyResponse(BaseModel):
    """POST /api/v1/sdk/auth/mfa/verify response"""
    access_token: str
    refresh_token: str
    token_type: str = "Bearer"
    expires_in: int
    refresh_expires_in: int
    session_id: str


class LogoutRequest(BaseModel):
    """POST /api/v1/sdk/auth/logout"""
    session_id: Optional[str] = None
    revoke_all: bool = Field(default=False, description="Revoke all sessions for this user")


class LogoutResponse(BaseModel):
    """POST /api/v1/sdk/auth/logout response"""
    success: bool
    revoked_count: int = 0


class RefreshRequest(BaseModel):
    """POST /api/v1/sdk/auth/refresh"""
    refresh_token: str


class RefreshResponse(BaseModel):
    """POST /api/v1/sdk/auth/refresh response"""
    access_token: str
    refresh_token: str
    token_type: str = "Bearer"
    expires_in: int
    refresh_expires_in: int


class SessionInfoResponse(BaseModel):
    """GET /api/v1/sdk/auth/session response"""
    session_id: str
    user_id: uuid.UUID
    email: str
    login_method: str
    created_at: datetime
    last_active_at: datetime
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    is_active: bool = True


# ---------------------------------------------------------------------------
# User Schemas
# ---------------------------------------------------------------------------
class UserCreate(BaseModel):
    """POST /api/v1/sdk/users"""
    username: str = Field(..., min_length=2, max_length=64)
    email: str = Field(..., max_length=255)
    password: str = Field(..., min_length=8, max_length=128)
    phone: Optional[str] = Field(default=None, max_length=32)
    status: UserStatus = Field(default=UserStatus.ACTIVE)
    extra: Optional[dict[str, Any]] = None

    @field_validator("email")
    @classmethod
    def email_lowercase(cls, v: str) -> str:
        return v.lower()


class UserUpdate(BaseModel):
    """PUT /api/v1/sdk/users/{id}"""
    email: Optional[str] = Field(default=None, max_length=255)
    phone: Optional[str] = Field(default=None, max_length=32)
    status: Optional[UserStatus] = None
    password: Optional[str] = Field(default=None, min_length=8, max_length=128)
    extra: Optional[dict[str, Any]] = None

    @field_validator("email")
    @classmethod
    def email_lowercase(cls, v: Optional[str]) -> Optional[str]:
        return v.lower() if v else v


class UserItem(BaseModel):
    """GET /api/v1/sdk/users/{id} response"""
    id: uuid.UUID
    username: str
    email: str
    phone: Optional[str] = None
    status: UserStatus
    created_at: datetime
    updated_at: datetime
    extra: Optional[dict[str, Any]] = None

    model_config = {"from_attributes": True}


class UserListResponse(BaseModel):
    """GET /api/v1/sdk/users response"""
    items: list[UserItem]
    total: int
    page: int
    page_size: int
    has_more: bool


class UserDeleteResponse(BaseModel):
    """DELETE /api/v1/sdk/users/{id} response"""
    success: bool
    deleted_user_id: uuid.UUID


# ---------------------------------------------------------------------------
# Role Schemas
# ---------------------------------------------------------------------------
class RoleCreate(BaseModel):
    """POST /api/v1/sdk/roles"""
    name: str = Field(..., min_length=2, max_length=64)
    description: Optional[str] = Field(default="", max_length=512)
    permissions: list[str] = Field(default_factory=list)
    status: RoleStatus = Field(default=RoleStatus.ACTIVE)


class RoleUpdate(BaseModel):
    """PUT /api/v1/sdk/roles/{id}"""
    name: Optional[str] = Field(default=None, min_length=2, max_length=64)
    description: Optional[str] = Field(default=None, max_length=512)
    status: Optional[RoleStatus] = None


class RoleItem(BaseModel):
    """GET /api/v1/sdk/roles/{id} response"""
    id: uuid.UUID
    name: str
    description: Optional[str] = None
    permissions: list[str] = []
    status: RoleStatus
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class RoleListResponse(BaseModel):
    """GET /api/v1/sdk/roles response"""
    items: list[RoleItem]
    total: int


class PermissionAssignRequest(BaseModel):
    """POST /api/v1/sdk/roles/{id}/permissions"""
    permission: str = Field(..., description="Permission string, e.g. 'users:read'")
    resource: Optional[str] = Field(default=None)
    action: Optional[str] = Field(default=None)


class PermissionRemoveResponse(BaseModel):
    """DELETE /api/v1/sdk/roles/{id}/permissions/{perm} response"""
    success: bool
    role_id: uuid.UUID
    removed_permission: str


# ---------------------------------------------------------------------------
# Quota Schemas
# ---------------------------------------------------------------------------
class QuotaResponse(BaseModel):
    """GET /api/v1/sdk/quota response"""
    monthly_quota: Optional[int] = None
    monthly_used: int
    remaining: Optional[int] = None
    reset_at: Optional[datetime] = None
    rate_limit_rps: int
    rate_limit_burst: int


class QuotaUsageDetail(BaseModel):
    day: str
    count: int


class QuotaUsageResponse(BaseModel):
    """GET /api/v1/sdk/quota/usage response"""
    period: str = Field(description="daily, weekly, or monthly")
    usage: list[QuotaUsageDetail]
    total: int


# ---------------------------------------------------------------------------
# Unified Error Response
# ---------------------------------------------------------------------------
class ErrorDetail(BaseModel):
    code: str
    message: str
    details: Optional[dict[str, Any]] = None
    request_id: Optional[str] = None


class ErrorResponse(BaseModel):
    """Standard error response wrapper for all SDK API errors"""
    error: ErrorDetail

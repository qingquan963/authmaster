"""
SSO Module - Pydantic Schemas
Phase 2-9: SSO 统一登出
"""
from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, HttpUrl, field_validator


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------
class Protocol(str, Enum):
    OIDC = "oidc"
    SAML = "saml"


class LogoutStatus(str, Enum):
    PENDING = "pending"
    NOTIFYING = "notifying"
    COMPLETED = "completed"
    FAILED = "failed"


class OutboxStatus(str, Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    DEAD = "dead"


# ---------------------------------------------------------------------------
# OIDC Logout
# ---------------------------------------------------------------------------
class OIDCLogoutGet(BaseModel):
    """GET /oidc/logout query params"""
    id_token_hint: Optional[str] = Field(None, max_length=4096, description="OIDC id_token_hint (≤4096 bytes recommended)")
    post_logout_redirect_uri: Optional[str] = Field(None, max_length=2048)
    state: Optional[str] = Field(None, max_length=512)

    @field_validator("id_token_hint")
    @classmethod
    def validate_id_token_hint_length(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and len(v.encode("utf-8")) > 4096:
            raise ValueError("id_token_hint exceeds 4096 bytes limit")
        return v


class OIDCLogoutPost(BaseModel):
    """POST /oidc/logout body"""
    id_token_hint: Optional[str] = Field(None, max_length=4096)
    action: str = Field(..., description="logout action, e.g. 'logout_confirmed'")
    logout_id: Optional[uuid.UUID] = None


class OIDCLogoutResponse(BaseModel):
    status: str
    logout_id: Optional[str] = None
    sp_notified: int = 0
    message: Optional[str] = None


# ---------------------------------------------------------------------------
# SAML SLO
# ---------------------------------------------------------------------------
class SAMLSLOResponse(BaseModel):
    """SAML LogoutResponse wrapper"""
    SAMLResponse: Optional[str] = None
    RelayState: Optional[str] = None


class SAMLSLORequest(BaseModel):
    """SAML SLO request params (SAMLRequest + RelayState in body or query)"""
    SAMLRequest: Optional[str] = Field(None, description="Base64-encoded SAML LogoutRequest")
    RelayState: Optional[str] = None
    client_id: Optional[str] = Field(None, description="SAML SP client_id for IdP-initiated SLO")
    sp_session_id: Optional[str] = Field(None, description="SP session ID for SP-initiated SLO")


# ---------------------------------------------------------------------------
# Session Management API
# ---------------------------------------------------------------------------
class SPSessionItem(BaseModel):
    session_id: uuid.UUID
    user_id: uuid.UUID
    user_email: str
    login_method: str
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    created_at: datetime
    last_active_at: Optional[datetime] = None
    sp_count: int = 0
    protocol: Optional[str] = None

    model_config = {"from_attributes": True}


class SessionListResponse(BaseModel):
    items: list[SPSessionItem]
    total: int
    page: int = 1
    page_size: int = 50


# ---------------------------------------------------------------------------
# IdP-Initiated Logout Response
# ---------------------------------------------------------------------------
class IdPInitiatedLogoutResponse(BaseModel):
    status: str = Field(..., description="'completed' or 'already_completed'")
    logout_id: str
    sp_notified: int = 0
    sp_failed: int = 0
    message: Optional[str] = None


# ---------------------------------------------------------------------------
# Dead Letter Response
# ---------------------------------------------------------------------------
class DeadLetterItem(BaseModel):
    id: uuid.UUID
    logout_id: uuid.UUID
    sp_session_id: uuid.UUID
    client_id: str
    protocol: str
    logout_uri: Optional[str] = None
    error_message: Optional[str] = None
    attempt_count: int
    created_at: datetime
    last_failed_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# Admin Force Logout
# ---------------------------------------------------------------------------
class ForceLogoutResponse(BaseModel):
    status: str
    sessions_revoked: int
    sp_notified: int = 0


# ---------------------------------------------------------------------------
# Error Responses
# ---------------------------------------------------------------------------
class SSOErrorResponse(BaseModel):
    error: str
    error_description: str
    request_id: Optional[str] = None

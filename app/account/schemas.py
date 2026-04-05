"""
Account Module - Pydantic Schemas
Phase 2-5: 账号合并/解绑

Request/Response schemas for:
  - Credential listing, adding, unbinding
  - Phone change (换绑)
  - Account merge (initiate / confirm / cancel)
"""
from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------
class CredentialType(str, Enum):
    PHONE = "phone"
    EMAIL = "email"
    WECHAT = "wechat"
    ALIPAY = "alipay"
    SAML = "saml"
    GITHUB = "github"
    GOOGLE = "google"
    OIDC = "oidc"


class CredentialStatus(str, Enum):
    ACTIVE = "active"
    UNBOUND = "unbound"
    PENDING_VERIFY = "pending_verify"
    MERGED = "merged"


class MergeStatus(str, Enum):
    PENDING = "pending"
    SOURCE_VERIFIED = "source_verified"
    TARGET_PENDING = "target_pending"
    EXECUTING = "executing"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    EXPIRED = "expired"
    FAILED = "failed"


class VerificationType(str, Enum):
    PASSWORD = "password"
    MFA_CODE = "mfa_code"
    EMAIL_CODE = "email_code"
    PHONE_CODE = "phone_code"


# ---------------------------------------------------------------------------
# Credential Schemas
# ---------------------------------------------------------------------------
class CredentialItem(BaseModel):
    """A single credential bound to an account."""
    credential_id: uuid.UUID
    type: str  # e.g. "phone", "email"
    identifier: str  # masked for privacy
    is_primary: bool
    is_verified: bool
    bound_at: datetime
    can_unbind: bool
    unbind_reason: Optional[str] = None

    model_config = {"from_attributes": True}


class CredentialListResponse(BaseModel):
    user_id: uuid.UUID
    credentials: list[CredentialItem]


class AddCredentialRequest(BaseModel):
    """Request to add a new credential to the current account."""
    type: str = Field(..., description="Credential type: phone | email | wechat | ...")
    value: str = Field(..., description="Raw identifier value")
    verification_code: str = Field(..., min_length=6, max_length=6)

    @field_validator("type")
    @classmethod
    def validate_type(cls, v: str) -> str:
        allowed = {"phone", "email", "wechat", "alipay", "saml", "github", "google", "oidc"}
        if v not in allowed:
            raise ValueError(f"type must be one of {allowed}")
        return v


class AddCredentialResponse(BaseModel):
    credential_id: uuid.UUID
    type: str
    identifier: str  # masked
    status: str = "active"


class CredentialConflictError(BaseModel):
    """Returned when the credential is already bound to another account."""
    error: str = "credential_conflict"
    message: str = "此凭证已被其他账号使用，如需合并请使用合并流程"
    conflict_account_id: uuid.UUID
    merge_token: str  # can be used to initiate merge


class UnbindRequest(BaseModel):
    """Request to unbind a credential from the current account."""
    password: str = Field(..., description="Current account password for verification")
    reason: Optional[str] = Field(None, description="Optional reason for unbinding")


class ChangePhoneRequest(BaseModel):
    """Request to change (re-bind) the phone number on the account."""
    new_phone: str = Field(..., description="New phone number with country code, e.g. +86-139-0000-0000")
    code: str = Field(..., min_length=6, max_length=6, description="Verification code sent to new_phone")
    password: str = Field(..., description="Current account password")


class ChangePhoneResponse(BaseModel):
    status: str = "ok"
    message: str = "手机号已更换"


# ---------------------------------------------------------------------------
# Merge Schemas
# ---------------------------------------------------------------------------
class MergeInitiateRequest(BaseModel):
    """Initiate an account merge (source account side)."""
    merge_token: str = Field(..., description="Token received from credential conflict response")
    source_account_verification: "VerificationInfo" = Field(
        ..., description="Verification of source account identity"
    )


class VerificationInfo(BaseModel):
    type: VerificationType
    value: str  # password string or OTP code


class MergeInitiateResponse(BaseModel):
    merge_request_id: uuid.UUID
    status: MergeStatus
    expires_at: datetime
    message: str = "合并请求已发起，请等待目标账号确认"


class MergeConfirmRequest(BaseModel):
    """Confirm a merge (target account side — user clicks email/SMS link)."""
    merge_token: str
    target_verification: "VerificationInfo"


class MergeConfirmResponse(BaseModel):
    status: str = "ok"
    message: str = "账号合并已完成"
    merged_account_email: Optional[str] = None  # masked


class MergeCancelRequest(BaseModel):
    """Cancel a pending merge."""
    merge_token: str
    reason: Optional[str] = None


class MergeCancelResponse(BaseModel):
    status: str = "ok"
    message: str = "合并已取消"


# ---------------------------------------------------------------------------
# Merge State Machine
# ---------------------------------------------------------------------------
class MergeStateMachine(BaseModel):
    """
    Represents the full state machine for a merge request.
    Used in admin views and merge status queries.
    """
    merge_request_id: uuid.UUID
    source_user_id: uuid.UUID
    target_user_id: uuid.UUID
    status: MergeStatus
    merge_token: str
    initiated_at: datetime
    source_verified_at: Optional[datetime] = None
    target_verified_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    cancelled_at: Optional[datetime] = None
    expires_at: datetime
    retry_count: int = 0
    max_retries: int = 3
    next_retry_at: Optional[datetime] = None


# ---------------------------------------------------------------------------
# Verification Code Schema (for SMS/Email OTP)
# ---------------------------------------------------------------------------
class SendCodeRequest(BaseModel):
    """Request to send a verification code (used in phone change flow)."""
    phone: str = Field(..., description="Phone number to send code to")


class SendCodeResponse(BaseModel):
    status: str = "sent"
    expires_in_seconds: int = 300  # 5 minutes


# ---------------------------------------------------------------------------
# Error Responses
# ---------------------------------------------------------------------------
class AccountErrorResponse(BaseModel):
    error: str
    message: str
    code: str  # machine-readable error code
    details: Optional[dict] = None


# ---------------------------------------------------------------------------
# Forward reference resolution
# ---------------------------------------------------------------------------
MergeInitiateRequest.model_rebuild()

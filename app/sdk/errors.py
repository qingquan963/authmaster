"""
SDK Module - Unified Error Codes
Phase 2-6: Auth SDK

All SDK API error responses follow a consistent format:
  {
    "error": {
      "code": "ERROR_CODE",
      "message": "Human-readable message",
      "details": { ... },
      "request_id": "req_xxxxxxxxxxxx"
    }
  }

Error code classification:
  - RETRY_CODES    : Server-side transient errors — SDK should auto-retry with backoff
  - NO_RETRY_CODES : Client errors — SDK should NOT retry
  - TOKEN_CODES    : Auth-related errors — trigger token refresh flow
"""
from __future__ import annotations

from enum import Enum
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Error Code Definitions
# ---------------------------------------------------------------------------
class ErrorCode(str, Enum):
    # Auth errors (HTTP 401)
    INVALID_CREDENTIALS = "INVALID_CREDENTIALS"
    TOKEN_EXPIRED = "TOKEN_EXPIRED"
    REFRESH_TOKEN_EXPIRED = "REFRESH_TOKEN_EXPIRED"
    MFA_REQUIRED = "MFA_REQUIRED"
    API_KEY_DISABLED = "API_KEY_DISABLED"
    API_KEY_REVOKED = "API_KEY_REVOKED"

    # Permission errors (HTTP 403)
    PERMISSION_DENIED = "PERMISSION_DENIED"
    SCOPE_INSUFFICIENT = "SCOPE_INSUFFICIENT"
    IP_NOT_ALLOWED = "IP_NOT_ALLOWED"

    # Not found errors (HTTP 404)
    NOT_FOUND = "NOT_FOUND"
    USER_NOT_FOUND = "USER_NOT_FOUND"
    ROLE_NOT_FOUND = "ROLE_NOT_FOUND"

    # Rate limit / quota (HTTP 429)
    RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED"
    QUOTA_EXCEEDED = "QUOTA_EXCEEDED"

    # Validation errors (HTTP 422)
    VALIDATION_ERROR = "VALIDATION_ERROR"
    IDEMPOTENCY_CONFLICT = "IDEMPOTENCY_CONFLICT"

    # Server errors (HTTP 5xx)
    INTERNAL_ERROR = "INTERNAL_ERROR"
    SERVER_UNAVAILABLE = "SERVER_UNAVAILABLE"

    # SDK-specific errors
    INVALID_API_KEY = "INVALID_API_KEY"
    INVALID_SIGNATURE = "INVALID_SIGNATURE"
    TIMESTAMP_EXPIRED = "TIMESTAMP_EXPIRED"


# ---------------------------------------------------------------------------
# Error classification for SDK retry logic
# ---------------------------------------------------------------------------
# Transient errors — SDK should auto-retry with exponential backoff
RETRY_CODES = {
    ErrorCode.RATE_LIMIT_EXCEEDED,
    ErrorCode.INTERNAL_ERROR,
    ErrorCode.SERVER_UNAVAILABLE,
}

# Client errors — SDK should NOT retry
NO_RETRY_CODES = {
    ErrorCode.INVALID_CREDENTIALS,
    ErrorCode.INVALID_API_KEY,
    ErrorCode.INVALID_SIGNATURE,
    ErrorCode.TIMESTAMP_EXPIRED,
    ErrorCode.TOKEN_EXPIRED,
    ErrorCode.REFRESH_TOKEN_EXPIRED,
    ErrorCode.MFA_REQUIRED,
    ErrorCode.API_KEY_DISABLED,
    ErrorCode.API_KEY_REVOKED,
    ErrorCode.PERMISSION_DENIED,
    ErrorCode.SCOPE_INSUFFICIENT,
    ErrorCode.IP_NOT_ALLOWED,
    ErrorCode.NOT_FOUND,
    ErrorCode.USER_NOT_FOUND,
    ErrorCode.ROLE_NOT_FOUND,
    ErrorCode.QUOTA_EXCEEDED,
    ErrorCode.VALIDATION_ERROR,
    ErrorCode.IDEMPOTENCY_CONFLICT,
}

# Token-related errors — trigger token refresh
TOKEN_CODES = {
    ErrorCode.TOKEN_EXPIRED,
    ErrorCode.REFRESH_TOKEN_EXPIRED,
}


# ---------------------------------------------------------------------------
# SDK API Error
# ---------------------------------------------------------------------------
class SDKAPIError(Exception):
    """
    Unified SDK API error.

    Attributes:
        code: Error code string (e.g. "INVALID_CREDENTIALS")
        message: Human-readable message
        details: Additional error details (e.g. rate limit info)
        request_id: Unique request identifier for tracing
        status_code: HTTP status code
    """

    def __init__(
        self,
        code: str,
        message: str,
        details: Optional[dict[str, Any]] = None,
        request_id: Optional[str] = None,
        status_code: int = 500,
    ):
        self.code = code
        self.message = message
        self.details = details or {}
        self.request_id = request_id
        self.status_code = status_code
        super().__init__(message)

    def to_dict(self) -> dict:
        """Serialize to API error response format."""
        error_body: dict[str, Any] = {
            "code": self.code,
            "message": self.message,
        }
        if self.details:
            error_body["details"] = self.details
        if self.request_id:
            error_body["request_id"] = self.request_id
        return {"error": error_body}

    @classmethod
    def from_response(cls, resp_data: dict, status_code: int) -> "SDKAPIError":
        """Construct from an API error response body."""
        error = resp_data.get("error", {})
        return cls(
            code=error.get("code", "UNKNOWN_ERROR"),
            message=error.get("message", "An unknown error occurred"),
            details=error.get("details"),
            request_id=error.get("request_id"),
            status_code=status_code,
        )

    def is_retryable(self) -> bool:
        return self.code in RETRY_CODES

    def is_token_error(self) -> bool:
        return self.code in TOKEN_CODES


# ---------------------------------------------------------------------------
# Error factory helpers
# ---------------------------------------------------------------------------
def invalid_credentials(request_id: Optional[str] = None) -> SDKAPIError:
    return SDKAPIError(
        code=ErrorCode.INVALID_CREDENTIALS.value,
        message="Invalid username or password",
        status_code=401,
        request_id=request_id,
    )


def token_expired(request_id: Optional[str] = None) -> SDKAPIError:
    return SDKAPIError(
        code=ErrorCode.TOKEN_EXPIRED.value,
        message="Access token has expired",
        status_code=401,
        request_id=request_id,
    )


def mfa_required(request_id: Optional[str] = None, details: Optional[dict] = None) -> SDKAPIError:
    return SDKAPIError(
        code=ErrorCode.MFA_REQUIRED.value,
        message="Multi-factor authentication is required",
        status_code=403,
        details=details,
        request_id=request_id,
    )


def rate_limit_exceeded(
    limit: int,
    remaining: int,
    reset_at: str,
    retry_after: int,
    request_id: Optional[str] = None,
) -> SDKAPIError:
    return SDKAPIError(
        code=ErrorCode.RATE_LIMIT_EXCEEDED.value,
        message="Request rate limit exceeded",
        status_code=429,
        details={
            "limit": limit,
            "remaining": remaining,
            "reset_at": reset_at,
            "retry_after_seconds": retry_after,
        },
        request_id=request_id,
    )


def permission_denied(
    message: str = "You do not have permission to perform this action",
    request_id: Optional[str] = None,
) -> SDKAPIError:
    return SDKAPIError(
        code=ErrorCode.PERMISSION_DENIED.value,
        message=message,
        status_code=403,
        request_id=request_id,
    )


def not_found(resource: str, request_id: Optional[str] = None) -> SDKAPIError:
    return SDKAPIError(
        code=ErrorCode.NOT_FOUND.value,
        message=f"{resource} not found",
        status_code=404,
        request_id=request_id,
    )


def validation_error(
    message: str,
    field_errors: Optional[list[dict]] = None,
    request_id: Optional[str] = None,
) -> SDKAPIError:
    details = {}
    if field_errors:
        details["field_errors"] = field_errors
    return SDKAPIError(
        code=ErrorCode.VALIDATION_ERROR.value,
        message=message,
        status_code=422,
        details=details,
        request_id=request_id,
    )


def internal_error(request_id: Optional[str] = None) -> SDKAPIError:
    return SDKAPIError(
        code=ErrorCode.INTERNAL_ERROR.value,
        message="An internal server error occurred",
        status_code=500,
        request_id=request_id,
    )


def invalid_api_key(request_id: Optional[str] = None) -> SDKAPIError:
    return SDKAPIError(
        code=ErrorCode.INVALID_API_KEY.value,
        message="Invalid or malformed API key",
        status_code=401,
        request_id=request_id,
    )


def invalid_signature(request_id: Optional[str] = None) -> SDKAPIError:
    return SDKAPIError(
        code=ErrorCode.INVALID_SIGNATURE.value,
        message="Invalid HMAC signature",
        status_code=401,
        request_id=request_id,
    )


def timestamp_expired(request_id: Optional[str] = None) -> SDKAPIError:
    return SDKAPIError(
        code=ErrorCode.TIMESTAMP_EXPIRED.value,
        message="Request timestamp is too old or in the future",
        status_code=401,
        request_id=request_id,
    )

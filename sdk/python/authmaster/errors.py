"""
AuthMaster Python SDK - Error Classes
======================================

All error codes from the unified error response map to a specific
SDKException subclass for programmatic error handling.

Retry classification:
  - RETRY_CODES:    Transient errors 鈥?auto-retry with exponential backoff
  - NO_RETRY_CODES: Client errors 鈥?do not retry
  - TOKEN_CODES:    Auth errors 鈥?trigger token refresh flow
"""
from __future__ import annotations

from typing import Any, Optional


# ---------------------------------------------------------------------------
# Error code classification
# ---------------------------------------------------------------------------
# Transient errors 鈥?SDK should auto-retry with backoff
RETRY_CODES = {
    "RATE_LIMIT_EXCEEDED",
    "INTERNAL_ERROR",
    "SERVER_UNAVAILABLE",
}

# Client errors 鈥?SDK should NOT retry
NO_RETRY_CODES = {
    "INVALID_CREDENTIALS",
    "INVALID_API_KEY",
    "INVALID_SIGNATURE",
    "TIMESTAMP_EXPIRED",
    "TOKEN_EXPIRED",
    "REFRESH_TOKEN_EXPIRED",
    "MFA_REQUIRED",
    "API_KEY_DISABLED",
    "API_KEY_REVOKED",
    "PERMISSION_DENIED",
    "SCOPE_INSUFFICIENT",
    "IP_NOT_ALLOWED",
    "NOT_FOUND",
    "USER_NOT_FOUND",
    "ROLE_NOT_FOUND",
    "QUOTA_EXCEEDED",
    "VALIDATION_ERROR",
    "IDEMPOTENCY_CONFLICT",
}

# Token-related errors 鈥?trigger token refresh
TOKEN_CODES = {
    "TOKEN_EXPIRED",
    "REFRESH_TOKEN_EXPIRED",
}


# ---------------------------------------------------------------------------
# Base Exception
# ---------------------------------------------------------------------------
class AuthMasterError(Exception):
    """
    Base exception for all AuthMaster SDK errors.

    Attributes:
        code: Error code string (e.g. "INVALID_CREDENTIALS")
        message: Human-readable error message
        details: Additional error details (e.g. rate limit info)
        request_id: Unique request identifier for tracing
        status_code: HTTP status code
    """

    retryable: bool = False
    """Whether this error should trigger an automatic retry."""

    token_error: bool = False
    """Whether this error is a token-related error triggering a refresh."""

    def __init__(
        self,
        message: str = "",
        code: str = "",
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

    def __repr__(self) -> str:
        return (
            f"<{self.__class__.__name__} "
            f"code={self.code!r} status={self.status_code} "
            f"message={self.message!r}>"
        )

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


# ---------------------------------------------------------------------------
# Auth Errors (401)
# ---------------------------------------------------------------------------
class InvalidCredentialsError(AuthMasterError):
    """Invalid username or password. (HTTP 401)"""

    def __init__(self, message: str = "Invalid username or password", **kwargs):
        super().__init__(code="INVALID_CREDENTIALS", message=message, status_code=401, **kwargs)


class TokenExpiredError(AuthMasterError):
    """Access token has expired. (HTTP 401)"""

    token_error = True

    def __init__(self, message: str = "Access token has expired", **kwargs):
        super().__init__(code="TOKEN_EXPIRED", message=message, status_code=401, **kwargs)


class RefreshTokenExpiredError(AuthMasterError):
    """Refresh token has expired. Requires re-login. (HTTP 401)"""

    def __init__(self, message: str = "Refresh token has expired", **kwargs):
        super().__init__(code="REFRESH_TOKEN_EXPIRED", message=message, status_code=401, **kwargs)


class InvalidAPIKeyError(AuthMasterError):
    """API key is invalid or malformed. (HTTP 401)"""

    def __init__(self, message: str = "Invalid or malformed API key", **kwargs):
        super().__init__(code="INVALID_API_KEY", message=message, status_code=401, **kwargs)


class InvalidSignatureError(AuthMasterError):
    """HMAC signature verification failed. (HTTP 401)"""

    def __init__(self, message: str = "Invalid HMAC signature", **kwargs):
        super().__init__(code="INVALID_SIGNATURE", message=message, status_code=401, **kwargs)


class TimestampExpiredError(AuthMasterError):
    """Request timestamp is too old or in the future. (HTTP 401)"""

    def __init__(self, message: str = "Request timestamp expired", **kwargs):
        super().__init__(code="TIMESTAMP_EXPIRED", message=message, status_code=401, **kwargs)


class APIKeyDisabledError(AuthMasterError):
    """API key has been disabled. (HTTP 401)"""

    def __init__(self, message: str = "API key is disabled", **kwargs):
        super().__init__(code="API_KEY_DISABLED", message=message, status_code=401, **kwargs)


class APIKeyRevokedError(AuthMasterError):
    """API key has been revoked. (HTTP 401)"""

    def __init__(self, message: str = "API key has been revoked", **kwargs):
        super().__init__(code="API_KEY_REVOKED", message=message, status_code=401, **kwargs)


# ---------------------------------------------------------------------------
# MFA Error (403)
# ---------------------------------------------------------------------------
class MFARequiredError(AuthMasterError):
    """Multi-factor authentication is required. (HTTP 403)"""

    def __init__(
        self,
        message: str = "Multi-factor authentication is required",
        mfa_token: Optional[str] = None,
        **kwargs,
    ):
        details = {}
        if mfa_token:
            details["mfa_token"] = mfa_token
        super().__init__(
            code="MFA_REQUIRED",
            message=message,
            details=details,
            status_code=403,
            **kwargs,
        )


# ---------------------------------------------------------------------------
# Permission Errors (403)
# ---------------------------------------------------------------------------
class PermissionDeniedError(AuthMasterError):
    """Insufficient permissions to perform this action. (HTTP 403)"""

    def __init__(self, message: str = "Permission denied", **kwargs):
        super().__init__(code="PERMISSION_DENIED", message=message, status_code=403, **kwargs)


class ScopeInsufficientError(AuthMasterError):
    """API key lacks required scope. (HTTP 403)"""

    def __init__(
        self,
        required: list[str],
        granted: list[str],
        **kwargs,
    ):
        super().__init__(
            code="SCOPE_INSUFFICIENT",
            message="API key does not have required scope",
            details={"required": required, "granted": granted},
            status_code=403,
            **kwargs,
        )


class IPNotAllowedError(AuthMasterError):
    """Client IP is not in the allowed list. (HTTP 403)"""

    def __init__(self, client_ip: str, **kwargs):
        super().__init__(
            code="IP_NOT_ALLOWED",
            message=f"IP address {client_ip} is not in the allowed list",
            status_code=403,
            **kwargs,
        )


# ---------------------------------------------------------------------------
# Not Found Errors (404)
# ---------------------------------------------------------------------------
class NotFoundError(AuthMasterError):
    """The requested resource was not found. (HTTP 404)"""

    def __init__(self, resource: str = "Resource", **kwargs):
        super().__init__(
            code="NOT_FOUND",
            message=f"{resource} not found",
            status_code=404,
            **kwargs,
        )


class UserNotFoundError(NotFoundError):
    def __init__(self, user_id: Optional[str] = None, **kwargs):
        msg = f"User not found: {user_id}" if user_id else "User not found"
        super().__init__(message=msg, **kwargs)
        self.code = "USER_NOT_FOUND"


class RoleNotFoundError(NotFoundError):
    def __init__(self, role_id: Optional[str] = None, **kwargs):
        msg = f"Role not found: {role_id}" if role_id else "Role not found"
        super().__init__(message=msg, **kwargs)
        self.code = "ROLE_NOT_FOUND"


# ---------------------------------------------------------------------------
# Rate Limit / Quota (429)
# ---------------------------------------------------------------------------
class RateLimitError(AuthMasterError):
    """Request rate limit exceeded. Retry after specified delay. (HTTP 429)"""

    retryable = True

    def __init__(
        self,
        limit: int = 0,
        remaining: int = 0,
        reset_at: Optional[str] = None,
        retry_after_seconds: int = 30,
        **kwargs,
    ):
        super().__init__(
            code="RATE_LIMIT_EXCEEDED",
            message="Request rate limit exceeded",
            details={
                "limit": limit,
                "remaining": remaining,
                "reset_at": reset_at,
                "retry_after_seconds": retry_after_seconds,
            },
            status_code=429,
            **kwargs,
        )
        self.retry_after = retry_after_seconds


class QuotaExceededError(AuthMasterError):
    """Monthly API quota has been exceeded. (HTTP 429)"""

    def __init__(self, monthly_quota: int, monthly_used: int, **kwargs):
        super().__init__(
            code="QUOTA_EXCEEDED",
            message="Monthly API quota exceeded",
            details={"monthly_quota": monthly_quota, "monthly_used": monthly_used},
            status_code=429,
            **kwargs,
        )


# ---------------------------------------------------------------------------
# Validation Error (422)
# ---------------------------------------------------------------------------
class ValidationError(AuthMasterError):
    """Request parameters are invalid. (HTTP 422)"""

    def __init__(
        self,
        message: str = "Validation error",
        field_errors: Optional[list[dict]] = None,
        **kwargs,
    ):
        details = {}
        if field_errors:
            details["field_errors"] = field_errors
        super().__init__(
            code="VALIDATION_ERROR",
            message=message,
            details=details,
            status_code=422,
            **kwargs,
        )


# ---------------------------------------------------------------------------
# Idempotency Conflict (409)
# ---------------------------------------------------------------------------
class IdempotencyConflictError(AuthMasterError):
    """Idempotency key conflict 鈥?request is being processed. (HTTP 409)"""

    def __init__(self, existing_export_id: str, retry_after_seconds: int = 60, **kwargs):
        super().__init__(
            code="IDEMPOTENCY_CONFLICT",
            message="Request with this idempotency key is already being processed",
            details={
                "existing_export_id": existing_export_id,
                "retry_after_seconds": retry_after_seconds,
            },
            status_code=409,
            **kwargs,
        )


# ---------------------------------------------------------------------------
# Server Errors (5xx)
# ---------------------------------------------------------------------------
class InternalError(AuthMasterError):
    """Internal server error. (HTTP 500)"""

    retryable = True

    def __init__(self, message: str = "Internal server error", **kwargs):
        super().__init__(code="INTERNAL_ERROR", message=message, status_code=500, **kwargs)


class ServerUnavailableError(AuthMasterError):
    """Service temporarily unavailable. (HTTP 503)"""

    retryable = True

    def __init__(self, message: str = "Service unavailable", **kwargs):
        super().__init__(code="SERVER_UNAVAILABLE", message=message, status_code=503, **kwargs)


# ---------------------------------------------------------------------------
# Error factory
# ---------------------------------------------------------------------------
_CODE_TO_CLASS: dict[str, type[AuthMasterError]] = {
    # Auth
    "INVALID_CREDENTIALS": InvalidCredentialsError,
    "TOKEN_EXPIRED": TokenExpiredError,
    "REFRESH_TOKEN_EXPIRED": RefreshTokenExpiredError,
    "INVALID_API_KEY": InvalidAPIKeyError,
    "INVALID_SIGNATURE": InvalidSignatureError,
    "TIMESTAMP_EXPIRED": TimestampExpiredError,
    "API_KEY_DISABLED": APIKeyDisabledError,
    "API_KEY_REVOKED": APIKeyRevokedError,
    # MFA
    "MFA_REQUIRED": MFARequiredError,
    # Permission
    "PERMISSION_DENIED": PermissionDeniedError,
    "SCOPE_INSUFFICIENT": ScopeInsufficientError,
    "IP_NOT_ALLOWED": IPNotAllowedError,
    # Not Found
    "NOT_FOUND": NotFoundError,
    "USER_NOT_FOUND": UserNotFoundError,
    "ROLE_NOT_FOUND": RoleNotFoundError,
    # Rate Limit
    "RATE_LIMIT_EXCEEDED": RateLimitError,
    "QUOTA_EXCEEDED": QuotaExceededError,
    # Validation
    "VALIDATION_ERROR": ValidationError,
    "IDEMPOTENCY_CONFLICT": IdempotencyConflictError,
    # Server
    "INTERNAL_ERROR": InternalError,
    "SERVER_UNAVAILABLE": ServerUnavailableError,
}


def from_error_response(
    error_dict: dict,
    status_code: int,
) -> AuthMasterError:
    """
    Factory: construct the appropriate AuthMasterError subclass from an API error response.

    Args:
        error_dict: The "error" object from the API response
        status_code: HTTP status code

    Returns:
        An instance of the matching AuthMasterError subclass
    """
    code = error_dict.get("code", "")
    message = error_dict.get("message", "An unknown error occurred")
    details = error_dict.get("details")
    request_id = error_dict.get("request_id")

    error_class = _CODE_TO_CLASS.get(code, AuthMasterError)

    if code == "SCOPE_INSUFFICIENT" and details:
        return error_class(
            required=details.get("required", []),
            granted=details.get("granted", []),
            message=message,
            request_id=request_id,
            status_code=status_code,
        )

    if code == "RATE_LIMIT_EXCEEDED" and details:
        return error_class(
            limit=details.get("limit", 0),
            remaining=details.get("remaining", 0),
            reset_at=details.get("reset_at"),
            retry_after_seconds=details.get("retry_after_seconds", 30),
            message=message,
            request_id=request_id,
            status_code=status_code,
        )

    if code == "QUOTA_EXCEEDED" and details:
        return error_class(
            monthly_quota=details.get("monthly_quota", 0),
            monthly_used=details.get("monthly_used", 0),
            message=message,
            request_id=request_id,
            status_code=status_code,
        )

    if code == "MFA_REQUIRED" and details:
        return error_class(
            message=message,
            mfa_token=details.get("mfa_token"),
            request_id=request_id,
            status_code=status_code,
        )

    return error_class(
        message=message,
        code=code,
        details=details,
        request_id=request_id,
        status_code=status_code,
    )

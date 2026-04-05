"""
AuthMaster SDK - Exceptions Module

Unified error code hierarchy for all AuthMaster API errors.
Error codes that trigger auto-retry: TOKEN_EXPIRED, RATE_LIMIT_EXCEEDED,
INTERNAL_ERROR, SERVER_UNAVAILABLE.
"""

from __future__ import annotations

import sys
from typing import Any, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .client import AuthMasterClient

# ---------------------------------------------------------------------------
# Error Code Constants
# ---------------------------------------------------------------------------

# --- Auto-retry codes (idempotent-safe) ---
_RETRY_CODES: frozenset[str] = frozenset({
    "TOKEN_EXPIRED",
    "RATE_LIMIT_EXCEEDED",
    "INTERNAL_ERROR",
    "SERVER_UNAVAILABLE",
})

# --- No-retry codes (fail fast) ---
_NO_RETRY_CODES: frozenset[str] = frozenset({
    "INVALID_CREDENTIALS",
    "PERMISSION_DENIED",
    "NOT_FOUND",
    "VALIDATION_ERROR",
    "MFA_REQUIRED",
    "QUOTA_EXCEEDED",
    "IDEMPOTENCY_CONFLICT",
})


# ---------------------------------------------------------------------------
# Exception Hierarchy
# ---------------------------------------------------------------------------

class AuthMasterError(Exception):
    """
    Base exception for all AuthMaster SDK errors.

    Attributes
    ----------
    code : str
        Machine-readable error code, e.g. ``"RATE_LIMIT_EXCEEDED"``.
    message : str
        Human-readable error message in Chinese (default) or English.
    details : dict
        Additional structured details from the API (rate limits, retry
        windows, etc.).
    request_id : str | None
        Server-side request tracing ID, useful when filing a support ticket.
    """

    # Class-level registry so that callers can catch specific subtypes.
    _SUB_CLASSES: dict[str, type["AuthMasterError"]] = {}

    def __init__(
        self,
        message: str = "",
        code: str = "",
        details: Optional[dict[str, Any]] = None,
        request_id: Optional[str] = None,
        *,
        http_status: int = 0,
    ):
        # If code wasn't explicitly passed, look for a class-level code attribute
        # (set by subclasses via the code= decorator).
        if not code and hasattr(type(self), "code"):
            code = type(self).code
        self.code = code or "UNKNOWN_ERROR"
        self.message = message or "An unknown error occurred."
        self.details = details or {}
        self.request_id = request_id
        self.http_status = http_status
        super().__init__(self.message)

    def __init_subclass__(cls, code: str = "", **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        if code:
            cls.code = code
            cls._SUB_CLASSES[code] = cls

    @classmethod
    def from_response(cls, payload: dict[str, Any], http_status: int = 0) -> "AuthMasterError":
        """
        Construct the most specific AuthMasterError from an API error response.

        Parameters
        ----------
        payload : dict
            Parsed JSON body of the error response. Expected structure::

                {
                    "error": {
                        "code": "RATE_LIMIT_EXCEEDED",
                        "message": "...",
                        "details": {...},
                        "request_id": "req_xxx"
                    }
                }

            Falls back to ``{"error": payload}`` for top-level error shapes.
        """
        error_obj = payload.get("error", payload)
        raw_code = error_obj.get("code", "")
        raw_message = error_obj.get("message", "")

        # Look up the registered concrete subclass.
        exc_cls = cls._SUB_CLASSES.get(raw_code, cls)

        return exc_cls(
            message=raw_message,
            code=raw_code,
            details=error_obj.get("details") or {},
            request_id=error_obj.get("request_id"),
            http_status=http_status,
        )

    @property
    def should_retry(self) -> bool:
        """Return True when the error is transient and safe to retry."""
        return self.code in _RETRY_CODES

    @property
    def should_not_retry(self) -> bool:
        """Return True when the error is permanent and must not be retried."""
        return self.code in _NO_RETRY_CODES

    def __repr__(self) -> str:
        return (
            f"<{self.__class__.__name__}[{self.code}] "
            f"status={self.http_status} request_id={self.request_id!r} "
            f"message={self.message!r}>"
        )


# --- 400-level client errors (no auto-retry) ---

class InvalidCredentialsError(AuthMasterError, code="INVALID_CREDENTIALS"):
    """Username or password is incorrect."""

    def __init__(
        self,
        message: str = "账号或密码错误",
        **kwargs: Any,
    ):
        super().__init__(message=message, **kwargs)


class PermissionDeniedError(AuthMasterError, code="PERMISSION_DENIED"):
    """The API key / token lacks the required scope for this operation."""

    def __init__(
        self,
        message: str = "权限不足",
        **kwargs: Any,
    ):
        super().__init__(message=message, **kwargs)


class NotFoundError(AuthMasterError, code="NOT_FOUND"):
    """The requested resource does not exist."""

    def __init__(
        self,
        message: str = "资源不存在",
        **kwargs: Any,
    ):
        super().__init__(message=message, **kwargs)


class ValidationError(AuthMasterError, code="VALIDATION_ERROR"):
    """Request parameters failed validation."""

    def __init__(
        self,
        message: str = "请求参数错误",
        **kwargs: Any,
    ):
        super().__init__(message=message, **kwargs)


class MFARequiredError(AuthMasterError, code="MFA_REQUIRED"):
    """
    MFA verification is required before the operation can proceed.
    Call :meth:`AuthMasterClient.verify_mfa` to complete the flow.
    """

    def __init__(
        self,
        message: str = "需要 MFA 验证",
        **kwargs: Any,
    ):
        super().__init__(message=message, **kwargs)


class QuotaExceededError(AuthMasterError, code="QUOTA_EXCEEDED"):
    """Monthly API quota exhausted. Upgrade the plan or wait for reset."""

    def __init__(
        self,
        message: str = "月度配额已用尽",
        **kwargs: Any,
    ):
        super().__init__(message=message, **kwargs)


class IdempotencyConflictError(AuthMasterError, code="IDEMPOTENCY_CONFLICT"):
    """A request with the same Idempotency-Key is already being processed."""

    def __init__(
        self,
        message: str = "相同 Idempotency-Key 的请求正在处理中",
        **kwargs: Any,
    ):
        super().__init__(message=message, **kwargs)


# --- 429 Too Many Requests ---

class RateLimitExceededError(AuthMasterError, code="RATE_LIMIT_EXCEEDED"):
    """
    Request rate limit hit. SDK will automatically back off and retry.

    Attributes
    ----------
    retry_after_seconds : int
        Seconds to wait before the next retry (from ``Retry-After`` header).
    limit : int
        The rate limit ceiling for this endpoint.
    remaining : int
        Remaining requests allowed in the current window.
    reset_at : str
        ISO-8601 timestamp when the rate limit window resets.
    """

    def __init__(
        self,
        message: str = "请求频率超出限制，请降低调用频率",
        details: Optional[dict[str, Any]] = None,
        **kwargs: Any,
    ):
        d = details or {}
        self.retry_after_seconds: int = d.get("retry_after_seconds", 30)
        self.limit: int = d.get("limit", 0)
        self.remaining: int = d.get("remaining", 0)
        self.reset_at: str = d.get("reset_at", "")
        super().__init__(
            message=message,
            details=d,
            **kwargs,
        )


# --- 500-level server errors (auto-retry) ---

class InternalServerError(AuthMasterError, code="INTERNAL_ERROR"):
    """Unexpected server-side error. Safe to retry with back-off."""

    def __init__(
        self,
        message: str = "服务端内部错误",
        **kwargs: Any,
    ):
        super().__init__(message=message, **kwargs)


class ServerUnavailableError(AuthMasterError, code="SERVER_UNAVAILABLE"):
    """Service temporarily unavailable (503). Safe to retry."""

    def __init__(
        self,
        message: str = "服务暂不可用",
        **kwargs: Any,
    ):
        super().__init__(message=message, **kwargs)


class TokenExpiredError(AuthMasterError, code="TOKEN_EXPIRED"):
    """
    Access token has expired. The SDK will automatically attempt to refresh
    the token when a refresh token is available.
    """

    def __init__(
        self,
        message: str = "Access Token 已过期",
        **kwargs: Any,
    ):
        super().__init__(message=message, **kwargs)


class RefreshTokenExpiredError(AuthMasterError, code="REFRESH_TOKEN_EXPIRED"):
    """Refresh token has expired. User must re-authenticate."""

    def __init__(
        self,
        message: str = "Refresh Token 已过期，请重新登录",
        **kwargs: Any,
    ):
        super().__init__(message=message, **kwargs)


# ---------------------------------------------------------------------------
# SDK-level errors (not from the API)
# ---------------------------------------------------------------------------

class SDKConfigurationError(AuthMasterError):
    """Raised when the SDK is mis-configured (bad base_url, missing secret, etc.)."""

    def __init__(self, message: str = "SDK 配置错误"):
        super().__init__(message=message, code="SDK_CONFIG_ERROR")


class APIMarshalError(AuthMasterError):
    """Raised when the SDK cannot parse the server's response."""

    def __init__(self, message: str = "响应解析失败"):
        super().__init__(message=message, code="API_MARSHAL_ERROR")


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------

def is_retryable(error: AuthMasterError) -> bool:
    """Return True when the error should trigger an automatic retry."""
    return error.should_retry


def is_not_retryable(error: AuthMasterError) -> bool:
    """Return True when the error must NOT be retried."""
    return error.should_not_retry

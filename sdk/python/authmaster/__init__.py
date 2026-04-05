"""
AuthMaster Python SDK
=====================

Official Python SDK for the AuthMaster authentication and authorization API.

Usage:
    from authmaster import AuthMasterClient

    client = AuthMasterClient(
        api_key="ak_xxxxx",
        api_secret="your_api_secret",
        base_url="https://auth.example.com/api/v1",
    )

    # Login
    result = client.login(username="user@example.com", password="password123")
    print(result["access_token"])

    # List users
    users = client.list_users(page=1, page_size=20)
    for user in users["items"]:
        print(user["email"])
"""

__version__ = "1.0.0"
__author__ = "AuthMaster Team"

# Main client
from .client import AuthMasterClient, AuthMasterAsyncClient

# Error classes (primary)
from .errors import (
    AuthMasterError,
    # Auth errors
    InvalidCredentialsError,
    TokenExpiredError,
    RefreshTokenExpiredError,
    InvalidAPIKeyError,
    InvalidSignatureError,
    TimestampExpiredError,
    APIKeyDisabledError,
    APIKeyRevokedError,
    # MFA
    MFARequiredError,
    # Permission
    PermissionDeniedError,
    ScopeInsufficientError,
    IPNotAllowedError,
    # Not Found
    NotFoundError,
    UserNotFoundError,
    RoleNotFoundError,
    # Rate limit / Quota
    RateLimitError,
    QuotaExceededError,
    # Validation
    ValidationError,
    IdempotencyConflictError,
    # Server
    InternalError,
    ServerUnavailableError,
    # Factory
    from_error_response,
)

# Backward compatibility — pre-existing exceptions module
from .exceptions import (
    AuthMasterError as AuthMasterErrorBase,
    InvalidCredentialsError as InvalidCredentialsErrorBase,
    PermissionDeniedError as PermissionDeniedErrorBase,
    NotFoundError as NotFoundErrorBase,
    ValidationError as ValidationErrorBase,
    MFARequiredError as MFARequiredErrorBase,
    QuotaExceededError as QuotaExceededErrorBase,
    IdempotencyConflictError as IdempotencyConflictErrorBase,
    RateLimitExceededError,
    InternalServerError,
    ServerUnavailableError,
    TokenExpiredError as TokenExpiredErrorBase,
    RefreshTokenExpiredError as RefreshTokenExpiredErrorBase,
    SDKConfigurationError,
    APIMarshalError,
)
from .decorators import auto_retry, retry_on_rate_limit

__all__ = [
    "__version__",
    # Clients
    "AuthMasterClient",
    "AuthMasterAsyncClient",
    # Primary errors
    "AuthMasterError",
    "InvalidCredentialsError",
    "TokenExpiredError",
    "RefreshTokenExpiredError",
    "InvalidAPIKeyError",
    "InvalidSignatureError",
    "TimestampExpiredError",
    "APIKeyDisabledError",
    "APIKeyRevokedError",
    "MFARequiredError",
    "PermissionDeniedError",
    "ScopeInsufficientError",
    "IPNotAllowedError",
    "NotFoundError",
    "UserNotFoundError",
    "RoleNotFoundError",
    "RateLimitError",
    "QuotaExceededError",
    "ValidationError",
    "IdempotencyConflictError",
    "InternalError",
    "ServerUnavailableError",
    "from_error_response",
    # Pre-existing / backward compat
    "AuthMasterErrorBase",
    "InvalidCredentialsErrorBase",
    "PermissionDeniedErrorBase",
    "NotFoundErrorBase",
    "ValidationErrorBase",
    "MFARequiredErrorBase",
    "QuotaExceededErrorBase",
    "IdempotencyConflictErrorBase",
    "RateLimitExceededError",
    "InternalServerError",
    "ServerUnavailableError",
    "TokenExpiredErrorBase",
    "RefreshTokenExpiredErrorBase",
    "SDKConfigurationError",
    "APIMarshalError",
    "auto_retry",
    "retry_on_rate_limit",
]

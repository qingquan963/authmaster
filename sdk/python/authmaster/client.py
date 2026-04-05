"""
AuthMaster Python SDK - Client
===============================

Main client class for the AuthMaster API.

Features:
  - HMAC-SHA256 request signing
  - Automatic token refresh
  - Automatic retry with exponential backoff for transient errors
  - Idempotency key support for safe retries
  - Comprehensive error handling with typed exceptions

Usage:
    >>> from authmaster import AuthMasterClient
    >>> client = AuthMasterClient(
    ...     api_key="ak_xxxxx",
    ...     api_secret="your_secret",
    ...     base_url="https://auth.example.com/api/v1",
    ... )
    >>> result = client.login(username="user@example.com", password="secret")
    >>> print(result["access_token"])
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time
import uuid
from typing import Any, Optional

import aiohttp
import requests
from requests import PreparedRequest, Response

from .errors import (
    AuthMasterError,
    InternalError,
    RateLimitError,
    RefreshTokenExpiredError,
    TokenExpiredError,
    from_error_response,
)

__version__ = "1.0.0"

# ---------------------------------------------------------------------------
# Retry classification
# ---------------------------------------------------------------------------
# Transient errors that warrant automatic retry
_RETRY_CODES = {"RATE_LIMIT_EXCEEDED", "INTERNAL_ERROR", "SERVER_UNAVAILABLE"}
# Non-retryable client errors
_NO_RETRY_CODES = {
    "INVALID_CREDENTIALS", "INVALID_API_KEY", "INVALID_SIGNATURE",
    "TIMESTAMP_EXPIRED", "MFA_REQUIRED", "API_KEY_DISABLED", "API_KEY_REVOKED",
    "PERMISSION_DENIED", "SCOPE_INSUFFICIENT", "IP_NOT_ALLOWED",
    "NOT_FOUND", "USER_NOT_FOUND", "ROLE_NOT_FOUND",
    "QUOTA_EXCEEDED", "VALIDATION_ERROR", "IDEMPOTENCY_CONFLICT",
    "REFRESH_TOKEN_EXPIRED",
}
# Token errors that trigger automatic refresh
_TOKEN_CODES = {"TOKEN_EXPIRED", "REFRESH_TOKEN_EXPIRED"}

# ---------------------------------------------------------------------------
# Default configuration
# ---------------------------------------------------------------------------
_DEFAULT_BASE_URL = "https://auth.example.com/api/v1"
_DEFAULT_TIMEOUT = 30  # seconds
_DEFAULT_MAX_RETRIES = 3
_BACKOFF_BASE = 2.0  # exponential backoff base


# ---------------------------------------------------------------------------
# AuthMasterClient
# ---------------------------------------------------------------------------
class AuthMasterClient:
    """
    Python SDK client for AuthMaster authentication API.

    Attributes:
        version: SDK version string
        base_url: Base URL for the AuthMaster API
        api_key: The API key used for authentication
        timeout: Default request timeout in seconds
        max_retries: Maximum number of retry attempts for transient errors

    Example:
        >>> client = AuthMasterClient(
        ...     api_key="ak_xxxxxxxxxxxx",
        ...     api_secret="your_api_secret",
        ... )
        >>> token = client.login("user@example.com", "password")
    """

    VERSION = __version__

    def __init__(
        self,
        api_key: str,
        api_secret: str,
        base_url: str = _DEFAULT_BASE_URL,
        timeout: int = _DEFAULT_TIMEOUT,
        max_retries: int = _DEFAULT_MAX_RETRIES,
        session: Optional[requests.Session] = None,
        # Token management
        access_token: Optional[str] = None,
        refresh_token: Optional[str] = None,
        _auto_refresh: bool = True,
    ):
        """
        Initialize the AuthMaster client.

        Args:
            api_key: The API key (ak_xxxxx format)
            api_secret: The API secret for HMAC signing
            base_url: Base URL of the AuthMaster API (default: production URL)
            timeout: Default timeout for all HTTP requests in seconds
            max_retries: Maximum retry attempts for transient errors
            session: Optional requests.Session for connection pooling
            access_token: Pre-set access token (from prior login)
            refresh_token: Pre-set refresh token (from prior login)
        """
        if not api_key:
            raise ValueError("api_key is required")
        if not api_secret:
            raise ValueError("api_secret is required")

        self.api_key = api_key
        self.api_secret = api_secret
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.max_retries = max_retries
        self._auto_refresh = _auto_refresh

        # Token management
        self._access_token: Optional[str] = access_token
        self._refresh_token: Optional[str] = refresh_token
        self._session_id: Optional[str] = None

        # HTTP session
        self._http = session or requests.Session()
        self._http.headers.update({
            "User-Agent": f"AuthMaster-SDK-Python/{self.VERSION}",
            "Content-Type": "application/json",
        })

    # -------------------------------------------------------------------------
    # Token management
    # -------------------------------------------------------------------------
    @property
    def access_token(self) -> Optional[str]:
        """Current access token, if any."""
        return self._access_token

    @property
    def refresh_token_value(self) -> Optional[str]:
        """Current refresh token, if any."""
        return self._refresh_token

    @property
    def session_id(self) -> Optional[str]:
        """Current session ID, if any."""
        return self._session_id

    def set_tokens(
        self,
        access_token: str,
        refresh_token: str,
        session_id: Optional[str] = None,
    ) -> None:
        """Manually set access and refresh tokens (e.g., from storage)."""
        self._access_token = access_token
        self._refresh_token = refresh_token
        self._session_id = session_id

    def clear_tokens(self) -> None:
        """Clear all stored tokens (logout)."""
        self._access_token = None
        self._refresh_token = None
        self._session_id = None

    # -------------------------------------------------------------------------
    # HMAC Signature
    # -------------------------------------------------------------------------
    def _sign(
        self,
        method: str,
        path: str,
        timestamp: int,
        body: str = "",
    ) -> str:
        """
        Generate HMAC-SHA256 signature for request authentication.

        Message format: METHOD + PATH + TIMESTAMP + BODY

        Args:
            method: HTTP method (GET, POST, etc.)
            path: Request path (e.g., /sdk/auth/login)
            timestamp: Unix epoch seconds
            body: Request body string (empty for GET)

        Returns:
            Hexadecimal signature string
        """
        msg = method.upper() + path + str(timestamp) + body
        return hmac.new(
            self.api_secret.encode("utf-8"),
            msg.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    # -------------------------------------------------------------------------
    # HTTP request with retry and auto-refresh
    # -------------------------------------------------------------------------
    def _build_headers(
        self,
        method: str,
        path: str,
        data: Optional[dict] = None,
        idempotency_key: Optional[str] = None,
        access_token: Optional[str] = None,
    ) -> dict[str, str]:
        """Build request headers including authentication and signature."""
        timestamp = int(time.time())
        body = json.dumps(data) if data else ""
        signature = self._sign(method, path, timestamp, body)

        headers: dict[str, str] = {
            "X-API-Key": self.api_key,
            "X-API-Signature": signature,
            "X-Timestamp": str(timestamp),
        }

        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key

        if access_token:
            headers["Authorization"] = f"Bearer {access_token}"

        return headers

    def _request(
        self,
        method: str,
        path: str,
        data: Optional[dict] = None,
        idempotency_key: Optional[str] = None,
        _retry_count: int = 0,
    ) -> dict[str, Any]:
        """
        Make an authenticated HTTP request with automatic retry.

        Args:
            method: HTTP method
            path: API path (e.g., /sdk/auth/login)
            data: Request body dict
            idempotency_key: Optional idempotency key for safe retries
            _retry_count: Internal retry counter

        Returns:
            Parsed JSON response dict

        Raises:
            AuthMasterError: On any API error
        """
        url = f"{self.base_url}/{path.lstrip('/')}"
        headers = self._build_headers(method, path, data, idempotency_key)

        try:
            resp: Response = self._http.request(
                method,
                url,
                json=data,
                headers=headers,
                timeout=self.timeout,
            )
        except requests.Timeout:
            if _retry_count < self.max_retries:
                time.sleep(_BACKOFF_BASE ** _retry_count)
                return self._request(method, path, data, idempotency_key, _retry_count + 1)
            raise InternalError("Request timed out after retries")
        except requests.RequestException as e:
            raise InternalError(f"Request failed: {e}")

        # Handle rate limiting with retry
        if resp.status_code == 429:
            if _retry_count < self.max_retries:
                retry_after = int(resp.headers.get("Retry-After", 30))
                time.sleep(retry_after)
                return self._request(method, path, data, idempotency_key, _retry_count + 1)
            raise RateLimitError(
                status_code=429,
                message="Rate limit exceeded after retries",
            )

        # Handle server errors with retry
        if resp.status_code in (500, 503):
            if _retry_count < self.max_retries:
                time.sleep(_BACKOFF_BASE ** _retry_count)
                return self._request(method, path, data, idempotency_key, _retry_count + 1)
            raise InternalError(
                message="Server error after retries",
                request_id=resp.headers.get("X-Request-ID"),
                status_code=resp.status_code,
            )

        # Parse error response
        if resp.status_code >= 400:
            try:
                error_data = resp.json()
            except ValueError:
                raise InternalError(
                    message=f"Server returned {resp.status_code}",
                    status_code=resp.status_code,
                )

            error_obj = error_data.get("error", {})
            code = error_obj.get("code", "UNKNOWN_ERROR")

            # Auto-refresh token on TOKEN_EXPIRED
            if code in _TOKEN_CODES and self._refresh_token and self._auto_refresh:
                if code == "TOKEN_EXPIRED":
                    self._do_refresh()
                    return self._request(method, path, data, idempotency_key, 0)
                elif code == "REFRESH_TOKEN_EXPIRED":
                    raise RefreshTokenExpiredError(
                        message=error_obj.get("message", "Refresh token expired"),
                        request_id=error_obj.get("request_id"),
                    )

            exc = from_error_response(error_obj, resp.status_code)
            raise exc

        # Success
        if resp.status_code == 204 or not resp.content:
            return {}
        return resp.json()

    def _do_refresh(self) -> None:
        """Refresh the access token using the stored refresh token."""
        if not self._refresh_token:
            raise TokenExpiredError(message="No refresh token available")

        result = self._request(
            "POST",
            "/sdk/auth/refresh",
            data={"refresh_token": self._refresh_token},
            _retry_count=0,
        )
        self._access_token = result["access_token"]
        self._refresh_token = result["refresh_token"]

    # -------------------------------------------------------------------------
    # Auth API
    # -------------------------------------------------------------------------
    def login(
        self,
        username: str,
        password: str,
        login_method: str = "password",
        device_fp: Optional[str] = None,
        extra: Optional[dict] = None,
    ) -> dict[str, Any]:
        """
        Authenticate a user with username (email/phone) and password.

        Args:
            username: User's email or phone number
            password: User's password
            login_method: Login method (default: "password")
            device_fp: Optional device fingerprint hash
            extra: Optional additional context dict

        Returns:
            dict with access_token, refresh_token, session_id, expires_in, etc.

        Raises:
            InvalidCredentialsError: Wrong username or password
            MFARequiredError: MFA verification required

        Example:
            >>> result = client.login("user@example.com", "password123")
            >>> print(result["access_token"])
        """
        data: dict[str, Any] = {
            "username": username,
            "password": password,
            "login_method": login_method,
        }
        if device_fp:
            data["device_fp"] = device_fp
        if extra:
            data["extra"] = extra

        result = self._request("POST", "/sdk/auth/login", data=data)

        # Store tokens for subsequent requests
        self._access_token = result.get("access_token")
        self._refresh_token = result.get("refresh_token")
        self._session_id = result.get("session_id")

        return result

    def login_with_mfa(
        self,
        mfa_token: str,
        code: str,
        code_type: str = "totp",
    ) -> dict[str, Any]:
        """
        Complete login with MFA verification code.

        Args:
            mfa_token: Token from login response when MFA_REQUIRED
            code: 6-digit TOTP or SMS code
            code_type: "totp" or "sms"

        Returns:
            dict with access_token, refresh_token, session_id
        """
        result = self._request(
            "POST",
            "/sdk/auth/mfa/verify",
            data={"mfa_token": mfa_token, "code": code, "code_type": code_type},
        )
        self._access_token = result.get("access_token")
        self._refresh_token = result.get("refresh_token")
        self._session_id = result.get("session_id")
        return result

    def logout(self, session_id: Optional[str] = None, revoke_all: bool = False) -> dict[str, Any]:
        """
        Logout and revoke session(s).

        Args:
            session_id: Specific session to revoke
            revoke_all: Revoke all sessions for this user

        Returns:
            dict with success=True and revoked_count
        """
        result = self._request(
            "POST",
            "/sdk/auth/logout",
            data={"session_id": session_id, "revoke_all": revoke_all},
        )
        if revoke_all or session_id == self._session_id:
            self.clear_tokens()
        return result

    def refresh(self) -> dict[str, Any]:
        """
        Refresh the access token using the stored refresh token.

        Returns:
            dict with new access_token, refresh_token

        Raises:
            RefreshTokenExpiredError: Refresh token has expired
        """
        result = self._request(
            "POST",
            "/sdk/auth/refresh",
            data={"refresh_token": self._refresh_token},
        )
        self._access_token = result["access_token"]
        self._refresh_token = result["refresh_token"]
        return result

    def get_session(self) -> dict[str, Any]:
        """
        Get information about the current session.

        Requires self._access_token to be set.

        Returns:
            dict with session_id, user_id, email, login_method, etc.
        """
        if not self._access_token:
            raise TokenExpiredError(message="No access token available")
        return self._request(
            "GET",
            "/sdk/auth/session",
            idempotency_key=None,
        )

    # -------------------------------------------------------------------------
    # User API
    # -------------------------------------------------------------------------
    def list_users(
        self,
        page: int = 1,
        page_size: int = 20,
        idempotency_key: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        List users with pagination.

        Requires scope: users:read

        Args:
            page: Page number (1-indexed)
            page_size: Items per page (max 100)
            idempotency_key: Optional idempotency key

        Returns:
            dict with items, total, page, page_size, has_more
        """
        return self._request(
            "GET",
            "/sdk/users",
            data={"filter": {"page": page, "page_size": page_size}},
            idempotency_key=idempotency_key,
        )

    def create_user(
        self,
        username: str,
        email: str,
        password: str,
        phone: Optional[str] = None,
        status: str = "active",
        extra: Optional[dict] = None,
        idempotency_key: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        Create a new user.

        Requires scope: users:write

        Args:
            username: Unique username
            email: User's email address
            password: Initial password (min 8 chars)
            phone: Optional phone number
            status: User status (default: "active")
            extra: Optional extra data dict
            idempotency_key: Optional idempotency key to prevent duplicates

        Returns:
            dict with created user object

        Example:
            >>> user = client.create_user(
            ...     username="john_doe",
            ...     email="john@example.com",
            ...     password="SecurePass123!",
            ... )
            >>> print(user["id"])
        """
        data: dict[str, Any] = {
            "username": username,
            "email": email,
            "password": password,
            "status": status,
        }
        if phone:
            data["phone"] = phone
        if extra:
            data["extra"] = extra

        return self._request(
            "POST",
            "/sdk/users",
            data=data,
            idempotency_key=idempotency_key or f"create_user:{username}",
        )

    def get_user(self, user_id: str) -> dict[str, Any]:
        """
        Get a user by ID.

        Requires scope: users:read

        Args:
            user_id: UUID of the user

        Returns:
            dict with user object
        """
        return self._request("GET", f"/sdk/users/{user_id}")

    def update_user(
        self,
        user_id: str,
        email: Optional[str] = None,
        phone: Optional[str] = None,
        status: Optional[str] = None,
        password: Optional[str] = None,
        extra: Optional[dict] = None,
    ) -> dict[str, Any]:
        """
        Update a user's fields.

        Requires scope: users:write

        Args:
            user_id: UUID of the user
            email: New email address
            phone: New phone number
            status: New status ("active" or "suspended")
            password: New password
            extra: New extra data dict

        Returns:
            dict with updated user object
        """
        data: dict[str, Any] = {}
        if email is not None:
            data["email"] = email
        if phone is not None:
            data["phone"] = phone
        if status is not None:
            data["status"] = status
        if password is not None:
            data["password"] = password
        if extra is not None:
            data["extra"] = extra

        return self._request("PUT", f"/sdk/users/{user_id}", data=data)

    def delete_user(self, user_id: str) -> dict[str, Any]:
        """
        Soft-delete a user.

        Requires scope: users:write

        Args:
            user_id: UUID of the user

        Returns:
            dict with success=True and deleted_user_id
        """
        return self._request("DELETE", f"/sdk/users/{user_id}")

    # -------------------------------------------------------------------------
    # Role API
    # -------------------------------------------------------------------------
    def list_roles(self) -> dict[str, Any]:
        """
        List all roles for the tenant.

        Requires scope: roles:read

        Returns:
            dict with items list and total count
        """
        return self._request("GET", "/sdk/roles")

    def create_role(
        self,
        name: str,
        description: str = "",
        permissions: Optional[list[str]] = None,
        status: str = "active",
        idempotency_key: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        Create a new role.

        Requires scope: roles:write

        Args:
            name: Role name (unique within tenant)
            description: Role description
            permissions: List of permission strings (e.g., ["users:read", "users:write"])
            status: Role status (default: "active")
            idempotency_key: Optional idempotency key

        Returns:
            dict with created role object
        """
        data: dict[str, Any] = {
            "name": name,
            "description": description,
            "permissions": permissions or [],
            "status": status,
        }
        return self._request(
            "POST",
            "/sdk/roles",
            data=data,
            idempotency_key=idempotency_key or f"create_role:{name}",
        )

    def assign_permission(
        self,
        role_id: str,
        permission: str,
    ) -> dict[str, Any]:
        """
        Assign a permission to a role.

        Requires scope: roles:write

        Args:
            role_id: UUID of the role
            permission: Permission string (e.g., "users:read")

        Returns:
            dict with role_id and updated permissions list
        """
        return self._request(
            "POST",
            f"/sdk/roles/{role_id}/permissions",
            data={"permission": permission},
        )

    def remove_permission(
        self,
        role_id: str,
        permission: str,
    ) -> dict[str, Any]:
        """
        Remove a permission from a role.

        Requires scope: roles:write

        Args:
            role_id: UUID of the role
            permission: Permission string to remove

        Returns:
            dict with success=True, role_id, removed_permission
        """
        return self._request("DELETE", f"/sdk/roles/{role_id}/permissions/{permission}")

    # -------------------------------------------------------------------------
    # Quota API
    # -------------------------------------------------------------------------
    def get_quota(self) -> dict[str, Any]:
        """
        Get current API quota usage and rate limits.

        Requires scope: quota:read

        Returns:
            dict with monthly_quota, monthly_used, remaining, reset_at,
            rate_limit_rps, rate_limit_burst
        """
        return self._request("GET", "/sdk/quota")

    def get_quota_usage(self, period: str = "daily") -> dict[str, Any]:
        """
        Get detailed API usage breakdown.

        Requires scope: quota:read

        Args:
            period: "daily", "weekly", or "monthly"

        Returns:
            dict with usage list and total count
        """
        return self._request(
            "GET",
            "/sdk/quota/usage",
            data={"period": period},
        )

    # -------------------------------------------------------------------------
    # Context manager
    # -------------------------------------------------------------------------
    def __enter__(self) -> "AuthMasterClient":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self._http.close()

    def close(self) -> None:
        """Close the underlying HTTP session."""
        self._http.close()


# ---------------------------------------------------------------------------
# Async client
# ---------------------------------------------------------------------------
class AuthMasterAsyncClient:
    """
    Async version of the AuthMaster client using aiohttp.

    Example:
        >>> async with AuthMasterAsyncClient(api_key="ak_xxx", api_secret="secret") as client:
        ...     result = await client.login("user@example.com", "password")
        ...     print(result["access_token"])
    """

    VERSION = __version__

    def __init__(
        self,
        api_key: str,
        api_secret: str,
        base_url: str = _DEFAULT_BASE_URL,
        timeout: int = _DEFAULT_TIMEOUT,
        max_retries: int = _DEFAULT_MAX_RETRIES,
        access_token: Optional[str] = None,
        refresh_token: Optional[str] = None,
        _auto_refresh: bool = True,
    ):
        if not api_key or not api_secret:
            raise ValueError("api_key and api_secret are required")
        self.api_key = api_key
        self.api_secret = api_secret
        self.base_url = base_url.rstrip("/")
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.max_retries = max_retries
        self._auto_refresh = _auto_refresh
        self._access_token: Optional[str] = access_token
        self._refresh_token: Optional[str] = refresh_token
        self._session_id: Optional[str] = None
        self._client: Optional[aiohttp.ClientSession] = None

    def _sign(self, method: str, path: str, timestamp: int, body: str = "") -> str:
        msg = method.upper() + path + str(timestamp) + body
        return hmac.new(
            self.api_secret.encode("utf-8"),
            msg.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    async def _ensure_session(self) -> aiohttp.ClientSession:
        if self._client is None or self._client.closed:
            self._client = aiohttp.ClientSession(
                timeout=self.timeout,
                headers={
                    "User-Agent": f"AuthMaster-SDK-Python-Async/{self.VERSION}",
                    "Content-Type": "application/json",
                },
            )
        return self._client

    async def _request(
        self,
        method: str,
        path: str,
        data: Optional[dict] = None,
        idempotency_key: Optional[str] = None,
        _retry_count: int = 0,
    ) -> dict[str, Any]:
        url = f"{self.base_url}/{path.lstrip('/')}"
        timestamp = int(time.time())
        body = json.dumps(data) if data else ""
        signature = self._sign(method, path, timestamp, body)

        headers: dict[str, str] = {
            "X-API-Key": self.api_key,
            "X-API-Signature": signature,
            "X-Timestamp": str(timestamp),
        }
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key

        session = await self._ensure_session()

        try:
            async with session.request(method, url, json=data, headers=headers) as resp:
                if resp.status == 429:
                    if _retry_count < self.max_retries:
                        import asyncio
                        await asyncio.sleep(int(resp.headers.get("Retry-After", 30)))
                        return await self._request(method, path, data, idempotency_key, _retry_count + 1)
                    raise RateLimitError(status_code=429)

                if resp.status in (500, 503):
                    if _retry_count < self.max_retries:
                        import asyncio
                        await asyncio.sleep(_BACKOFF_BASE ** _retry_count)
                        return await self._request(method, path, data, idempotency_key, _retry_count + 1)
                    raise InternalError(status_code=resp.status)

                if resp.status >= 400:
                    error_data = await resp.json()
                    error_obj = error_data.get("error", {})
                    code = error_obj.get("code", "UNKNOWN_ERROR")

                    if code in _TOKEN_CODES and self._refresh_token and self._auto_refresh:
                        if code == "TOKEN_EXPIRED":
                            await self._do_refresh()
                            return await self._request(method, path, data, idempotency_key, 0)
                        elif code == "REFRESH_TOKEN_EXPIRED":
                            from .errors import RefreshTokenExpiredError
                            raise RefreshTokenExpiredError(
                                message=error_obj.get("message", "Refresh token expired"),
                            )

                    raise from_error_response(error_obj, resp.status)

                if resp.status == 204:
                    return {}
                return await resp.json()

        except aiohttp.ClientError as e:
            raise InternalError(f"Request failed: {e}")

    async def _do_refresh(self) -> None:
        if not self._refresh_token:
            raise TokenExpiredError(message="No refresh token available")
        result = await self._request(
            "POST", "/sdk/auth/refresh",
            data={"refresh_token": self._refresh_token},
        )
        self._access_token = result["access_token"]
        self._refresh_token = result["refresh_token"]

    async def login(self, username: str, password: str, **kwargs) -> dict[str, Any]:
        """Async login — see AuthMasterClient.login()"""
        result = await self._request(
            "POST", "/sdk/auth/login",
            data={"username": username, "password": password, **kwargs},
        )
        self._access_token = result.get("access_token")
        self._refresh_token = result.get("refresh_token")
        self._session_id = result.get("session_id")
        return result

    async def close(self) -> None:
        if self._client and not self._client.closed:
            await self._client.close()

    async def __aenter__(self) -> "AuthMasterAsyncClient":
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.close()

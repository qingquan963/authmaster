"""
SDK Module - API Key Authentication Middleware
Phase 2-6: Auth SDK

Middleware and dependencies for SDK API endpoint authentication.
Supports:
  - API Key + HMAC-SHA256 signature verification
  - Access token Bearer authentication
  - Scope-based authorization
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import time
import uuid
from typing import Annotated, Optional

from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from .errors import (
    SDKAPIError,
    invalid_api_key,
    invalid_signature,
    permission_denied,
    timestamp_expired,
)
from .models import APIKey
from . import service as sdk_service


# ---------------------------------------------------------------------------
# Dependency: get_db
# ---------------------------------------------------------------------------
async def get_db() -> AsyncSession:
    """Override in your application to provide a real AsyncSession."""
    raise NotImplementedError("Override get_db dependency in your application")


# ---------------------------------------------------------------------------
# Dependency: require_api_key_auth
# ---------------------------------------------------------------------------
async def require_api_key_auth(
    request: Request,
    x_api_key: Annotated[str, Header()],
    x_api_signature: Annotated[str, Header()],
    x_timestamp: Annotated[str, Header()],
    authorization: Annotated[Optional[str], Header()] = None,
    db: AsyncSession = Depends(get_db),
) -> tuple[APIKey, Optional[str]]:
    """
    Verify API Key and HMAC-SHA256 signature for SDK API requests.

    Request headers required:
      X-API-Key:        The API key string (ak_xxxxx)
      X-API-Signature:   HMAC-SHA256 signature
      X-Timestamp:       Unix epoch seconds as string

    Optional:
      Authorization:    Bearer <access_token> (for user-context endpoints)

    Returns:
      Tuple of (APIKey model, access_token or None)

    Raises:
      HTTPException 401 on auth failure
    """
    request_id = getattr(request.state, "request_id", None)

    # Lookup API key
    api_key = await sdk_service.get_api_key_by_key(db, x_api_key)
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=invalid_api_key(request_id).to_dict()["error"],
        )

    # Check API key is not revoked
    if api_key.revoked_at is not None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "code": "API_KEY_REVOKED",
                "message": "This API key has been revoked",
                "request_id": request_id,
            },
        )

    # Check timestamp freshness (5 minute window)
    try:
        ts = int(x_timestamp)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=invalid_signature(request_id).to_dict()["error"],
        )

    current_time = int(time.time())
    if abs(current_time - ts) > 300:  # 5 minutes
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=timestamp_expired(request_id).to_dict()["error"],
        )

    # Verify HMAC signature
    # Message format: METHOD + PATH + TIMESTAMP + BODY
    method = request.method.upper()
    path = request.url.path
    body = ""
    if request.method in ("POST", "PUT", "PATCH"):
        body_bytes = await request.body()
        body = body_bytes.decode("utf-8", errors="")

    # Use stored hash as HMAC key for verification
    is_valid = sdk_service.verify_hmac_signature(
        api_key.api_secret_hash,
        method,
        path,
        ts,
        body,
        x_api_signature,
    )

    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=invalid_signature(request_id).to_dict()["error"],
        )

    # Check allowed IPs
    if api_key.allowed_ips:
        client_ip = _get_client_ip(request)
        if client_ip not in api_key.allowed_ips:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "code": "IP_NOT_ALLOWED",
                    "message": f"IP address {client_ip} is not in the allowed list",
                    "request_id": request_id,
                },
            )

    # Update last used timestamp (fire-and-forget)
    await sdk_service.update_api_key_last_used(db, api_key.id)

    # Extract access token if present
    access_token = None
    if authorization and authorization.startswith("Bearer "):
        access_token = authorization[7:]

    return api_key, access_token


# ---------------------------------------------------------------------------
# Dependency: require_scope
# ---------------------------------------------------------------------------
def require_scope(*required_scopes: str):
    """
    Dependency factory: require that the API key has all of the specified scopes.

    Usage:
        @router.get("/users", dependencies=[Depends(require_scope("users:read"))])
    """
    async def scope_checker(
        api_key: APIKey = Depends(require_api_key_auth),
    ) -> APIKey:
        key_scopes = set(api_key.scopes or [])
        for scope in required_scopes:
            if scope not in key_scopes:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail={
                        "code": "SCOPE_INSUFFICIENT",
                        "message": f"API key does not have required scope: {scope}",
                        "details": {
                            "required": list(required_scopes),
                            "granted": list(key_scopes),
                        },
                    },
                )
        return api_key

    return scope_checker


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _get_client_ip(request: Request) -> str:
    """Extract client IP from request, respecting X-Forwarded-For."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"


# ---------------------------------------------------------------------------
# Request ID middleware
# ---------------------------------------------------------------------------
async def request_id_middleware(request: Request, call_next):
    """Inject a unique request_id into every request state."""
    request_id = f"req_{secrets.token_hex(8)}"
    request.state.request_id = request_id
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    return response

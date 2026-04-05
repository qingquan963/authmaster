"""
Rate Limit Middleware
Phase 2-7: 百万级 QOS 高并发架构

FastAPI middleware for transparent rate limiting.
Extracts request context, checks rate limits, and returns appropriate
responses (200 OK or 429 Too Many Requests).

Reference: see design doc Phase 2-7 Section 4.1
"""
from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime, timezone
from typing import Callable, Optional

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.status import HTTP_429_TOO_MANY_REQUESTS

from app.core.ratelimit.service import RateLimitService, RequestContext
from app.core.ratelimit.circuit_breaker import CircuitOpenError

logger = logging.getLogger(__name__)


# Paths that should skip rate limiting
SKIP_PATHS = frozenset({
    "/health",
    "/healthz",
    "/ready",
    "/metrics",
    "/favicon.ico",
})


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    FastAPI middleware for rate limiting.

    Integrates with RateLimitService to check requests against
    configured rules. Adds standard rate limit headers to responses.

    Response headers added:
      - X-RateLimit-Limit: Max requests per window
      - X-RateLimit-Remaining: Remaining requests in window
      - X-RateLimit-Reset: Reset time (ISO 8601)
      - Retry-After: Seconds until retry (only on 429)

    Args:
        app: FastAPI application
        rate_limit_service: RateLimitService instance
        skip_paths: Set of paths to skip rate limiting
    """

    def __init__(
        self,
        app,
        rate_limit_service: RateLimitService,
        skip_paths: frozenset = SKIP_PATHS,
    ):
        super().__init__(app)
        self._service = rate_limit_service
        self._skip_paths = skip_paths

    async def dispatch(
        self,
        request: Request,
        call_next: Callable,
    ) -> Response:
        """Process request through rate limiting."""
        # Skip health checks and other non-rate-limited paths
        if request.url.path in self._skip_paths:
            return await call_next(request)

        # Build request context
        ctx = self._build_context(request)

        # Check rate limit
        try:
            decision = await self._service.check(ctx)
        except Exception as e:
            # On error, fail open (allow request) to avoid blocking
            # the entire service due to rate limiting infrastructure issues
            logger.error(f"Rate limit check error: {e}")
            return await call_next(request)

        if not decision.allowed:
            return self._rate_limited_response(decision)

        # Add rate limit headers to response
        response = await call_next(request)
        self._add_headers(response, decision)
        return response

    def _build_context(self, request: Request) -> RequestContext:
        """Extract request context for rate limiting."""
        # Extract client IP (handle X-Forwarded-For for proxies)
        ip = self._get_client_ip(request)

        # Extract user ID from auth context (if available)
        user_id = self._get_user_id(request)

        # Extract API key (for SDK endpoints)
        api_key = request.headers.get("X-API-Key")

        # Extract tenant ID (from JWT or header)
        tenant_id = self._get_tenant_id(request)

        return RequestContext(
            endpoint=request.url.path,
            ip=ip,
            user_id=user_id,
            api_key=api_key,
            tenant_id=tenant_id,
            method=request.method,
        )

    def _get_client_ip(self, request: Request) -> Optional[str]:
        """Get client IP, considering X-Forwarded-For header."""
        # Check X-Forwarded-For first (proxy/load balancer)
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            # Take the first IP in the chain (original client)
            return forwarded.split(",")[0].strip()

        # Check X-Real-IP
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip

        # Fall back to direct client IP
        if request.client:
            return request.client.host
        return None

    def _get_user_id(self, request: Request) -> Optional[str]:
        """
        Extract user ID from request context.
        
        For FastAPI, user ID is typically stored in request.state
        after authentication middleware runs.
        """
        # Check if auth middleware stored user in state
        if hasattr(request.state, "user_id"):
            return str(request.state.user_id)
        if hasattr(request.state, "user"):
            user = request.state.user
            if hasattr(user, "id"):
                return str(user.id)
        return None

    def _get_tenant_id(self, request: Request) -> Optional[str]:
        """
        Extract tenant ID from request context.
        
        Typically from JWT claim or X-Tenant-ID header.
        """
        # Check header first
        tenant_header = request.headers.get("X-Tenant-ID")
        if tenant_header:
            return tenant_header

        # Check state (if set by auth middleware)
        if hasattr(request.state, "tenant_id"):
            return str(request.state.tenant_id)
        return None

    def _rate_limited_response(self, decision) -> JSONResponse:
        """Create a 429 rate limited response."""
        headers = {
            "Content-Type": "application/json",
            "X-RateLimit-Limit": str(decision.limit),
            "X-RateLimit-Remaining": "0",
            "Retry-After": str(decision.retry_after or 60),
        }
        if decision.reset_at:
            headers["X-RateLimit-Reset"] = decision.reset_at.isoformat()

        body = {
            "error": {
                "code": "RATE_LIMIT_EXCEEDED",
                "message": "请求频率超出限制，请降低调用频率",
                "details": {
                    "limit": decision.limit,
                    "remaining": 0,
                    "retry_after_seconds": decision.retry_after or 60,
                    "reset_at": decision.reset_at.isoformat() if decision.reset_at else None,
                },
            }
        }

        return JSONResponse(
            status_code=HTTP_429_TOO_MANY_REQUESTS,
            content=body,
            headers=headers,
        )

    def _add_headers(self, response: Response, decision):
        """Add rate limit headers to response."""
        response.headers["X-RateLimit-Limit"] = str(decision.limit)
        response.headers["X-RateLimit-Remaining"] = str(decision.remaining)
        if decision.reset_at:
            response.headers["X-RateLimit-Reset"] = decision.reset_at.isoformat()


# ---------------------------------------------------------------------------
# Dependency for FastAPI routes (for manual rate limit checks)
# ---------------------------------------------------------------------------

async def check_rate_limit(
    request: Request,
    service: RateLimitService,
) -> Optional[JSONResponse]:
    """
    FastAPI dependency for manual rate limit checks.

    Use this in routes that need explicit rate limit checking
    (e.g., after authentication, before a sensitive operation).

    Returns:
        JSONResponse with 429 if rate limited, None if allowed.

    Usage:
        @app.post("/api/v1/auth/login")
        async def login(request: Request, rt: None = Depends(check_rate_limit)):
            # rt is None if allowed, or JSONResponse 429 if limited
            ...
    """
    ctx = RequestContext(
        endpoint=request.url.path,
        ip=_get_ip(request),
        user_id=_get_user_id_from_request(request),
        api_key=request.headers.get("X-API-Key"),
        tenant_id=request.headers.get("X-Tenant-ID"),
        method=request.method,
    )

    try:
        decision = await service.check(ctx)
    except Exception as e:
        logger.error(f"Rate limit check error: {e}")
        return None

    if not decision.allowed:
        return _make_429_response(decision)
    return None


def _get_ip(request: Request) -> Optional[str]:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client:
        return request.client.host
    return None


def _get_user_id_from_request(request: Request) -> Optional[str]:
    if hasattr(request.state, "user_id"):
        return str(request.state.user_id)
    if hasattr(request.state, "user"):
        user = request.state.user
        if hasattr(user, "id"):
            return str(user.id)
    return None


def _make_429_response(decision) -> JSONResponse:
    headers = {
        "Content-Type": "application/json",
        "X-RateLimit-Limit": str(decision.limit),
        "X-RateLimit-Remaining": "0",
        "Retry-After": str(decision.retry_after or 60),
    }
    if decision.reset_at:
        headers["X-RateLimit-Reset"] = decision.reset_at.isoformat()

    body = {
        "error": {
            "code": "RATE_LIMIT_EXCEEDED",
            "message": "请求频率超出限制，请降低调用频率",
            "details": {
                "limit": decision.limit,
                "remaining": 0,
                "retry_after_seconds": decision.retry_after or 60,
            },
        }
    }
    return JSONResponse(
        status_code=HTTP_429_TOO_MANY_REQUESTS,
        content=body,
        headers=headers,
    )

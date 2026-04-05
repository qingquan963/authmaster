"""
Rate Limiting Module
Phase 2-7: 百万级 QOS 高并发架构

Components:
  - token_bucket   : Local token bucket (L1)
  - sliding_window : Redis-based sliding window (L2 distributed)
  - circuit_breaker: Circuit breaker for fault tolerance
  - cache          : L1 (local) + L2 (Redis) multi-level cache
  - middleware     : FastAPI rate limit middleware
  - service        : Rate limit orchestration service
  - models         : SQLAlchemy models (rate_limit_rules table)
  - schemas        : Pydantic schemas
  - config_loader  : Load rules from DB
"""
from __future__ import annotations

from app.core.ratelimit.token_bucket import TokenBucket
from app.core.ratelimit.sliding_window import SlidingWindowRateLimiter, LUA_SLIDING_WINDOW
from app.core.ratelimit.circuit_breaker import CircuitBreaker, CircuitState, CircuitOpenError
from app.core.ratelimit.cache import MultilevelCache, get_jittered_ttl
from app.core.ratelimit.service import RateLimitService
from app.core.ratelimit.middleware import RateLimitMiddleware

__all__ = [
    "TokenBucket",
    "SlidingWindowRateLimiter",
    "LUA_SLIDING_WINDOW",
    "CircuitBreaker",
    "CircuitState",
    "CircuitOpenError",
    "MultilevelCache",
    "get_jittered_ttl",
    "RateLimitService",
    "RateLimitMiddleware",
]

"""
Rate Limit Service
Phase 2-7: 百万级 QOS 高并发架构

Orchestrates all rate limiting components:
  - Config loader (rule matching)
  - Tiered rate limiter (local bucket + Redis sliding window)
  - Circuit breaker for Redis protection
  - Multilevel cache for user/permission caching

Reference: see design doc Phase 2-7 Section 4
"""
from __future__ import annotations

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass
from typing import Optional, Tuple

from app.core.ratelimit.token_bucket import AsyncTokenBucket
from app.core.ratelimit.sliding_window import (
    SlidingWindowRateLimiter,
    TieredRateLimiter,
    LUA_SLIDING_WINDOW,
)
from app.core.ratelimit.circuit_breaker import CircuitBreaker, CircuitState, CircuitOpenError
from app.core.ratelimit.cache import (
    MultilevelCache,
    LocalCache,
    get_jittered_ttl,
)
from app.core.ratelimit.config_loader import RateLimitConfigLoader, RuleConfig, MatchingRule
from app.core.ratelimit.schemas import RateLimitDecision, CacheStats

logger = logging.getLogger(__name__)


@dataclass
class RequestContext:
    """Context for a single request being rate-limited."""
    endpoint: str           # Request path (e.g., "/api/v1/auth/login")
    ip: Optional[str]       # Client IP address
    user_id: Optional[str]  # Authenticated user ID (if logged in)
    api_key: Optional[str]  # API key (for SDK endpoints)
    tenant_id: Optional[str] # Tenant ID (for multi-tenant)
    method: str = "GET"     # HTTP method


class RateLimitService:
    """
    Main rate limiting orchestration service.

    Combines:
      - Local token bucket (L1, fast reject)
      - Redis sliding window (L2, distributed enforcement)
      - Config loader (rule matching)
      - Circuit breaker (Redis fault protection)
      - Multilevel cache (user/permission caching)

    Usage:
        service = RateLimitService(redis_client, db_factory)
        decision = await service.check(request_ctx)
        if not decision.allowed:
            raise RateLimitExceeded(detail=decision)
    """

    def __init__(
        self,
        redis_client,
        db_session_factory,
        config_cache_ttl: int = 60,
        # Per-instance local cache for token buckets
        local_bucket_cache_size: int = 1000,
    ):
        self.redis = redis_client
        self._db_factory = db_session_factory

        # Config loader (rule matching)
        self._config_loader = RateLimitConfigLoader(
            db_session_factory=db_session_factory,
            config_cache_ttl=config_cache_ttl,
        )

        # L1 local cache (shared across all rate limiters)
        self._local_cache = LocalCache(max_size=local_bucket_cache_size)

        # L1+L2 multilevel cache (for user/permission data)
        self._cache = MultilevelCache(
            redis_client=redis_client,
            local_cache=self._local_cache,
        )

        # Circuit breaker for Redis failures
        self._redis_breaker = CircuitBreaker(
            name="redis",
            failure_threshold=5,
            recovery_timeout=30.0,
            half_open_max_calls=3,
        )

        # Per-rule rate limiters (endpoint:key -> TieredRateLimiter)
        # Reuse limiters to avoid creating too many Redis connections
        self._limiters: dict[str, TieredRateLimiter] = {}
        self._limiters_lock = asyncio.Lock()

        # Cleanup task
        self._cleanup_task: Optional[asyncio.Task] = None
        self._running = False

    # -------------------------------------------------------------------------
    # Lifecycle
    # -------------------------------------------------------------------------

    async def start(self):
        """Start background cleanup task."""
        self._running = True
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
        logger.info("RateLimitService started")

    async def stop(self):
        """Stop background cleanup task."""
        self._running = False
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
        logger.info("RateLimitService stopped")

    async def _cleanup_loop(self):
        """Background loop: cleanup expired cache entries."""
        while self._running:
            try:
                await asyncio.sleep(10)
                await self._cache.cleanup_local()
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.error(f"Cleanup loop error: {e}")

    # -------------------------------------------------------------------------
    # Rate Limit Check
    # -------------------------------------------------------------------------

    async def check(self, ctx: RequestContext) -> RateLimitDecision:
        """
        Check if a request should be allowed under rate limits.

        Args:
            ctx: Request context (endpoint, IP, user, etc.)

        Returns:
            RateLimitDecision with allowed/denied and metadata
        """
        # Match rule
        key_type = self._resolve_key_type(ctx)
        key_value = self._resolve_key_value(ctx, key_type)

        matching = await self._config_loader.match_rule(
            endpoint=ctx.endpoint,
            key_type=key_type,
            key_value=key_value,
            tenant_id=ctx.tenant_id,
        )

        if matching is None:
            # Use default rule
            default = await self._config_loader.get_default_rule()
            rule = default
        else:
            rule = matching.rule

        # Get or create limiter for this rule
        limiter = await self._get_limiter(rule, key_value)

        # Try with circuit breaker protection
        try:
            allowed, reason = await limiter.is_allowed()
        except CircuitOpenError:
            allowed = False
            reason = "circuit_open"

        if not allowed:
            # Calculate retry_after
            retry_after = await self._get_retry_after(limiter)
            return RateLimitDecision(
                allowed=False,
                reason=reason,
                limit=rule.rate,
                remaining=0,
                reset_at=None,
                retry_after=retry_after,
            )

        # Allowed - calculate remaining
        current = await limiter.redis.get_current_count()
        remaining = max(0, rule.rate - current)
        reset_at = self._calculate_reset_at(rule.window)

        return RateLimitDecision(
            allowed=True,
            reason="allowed",
            limit=rule.rate,
            remaining=remaining,
            reset_at=reset_at,
            retry_after=None,
        )

    async def _get_limiter(
        self,
        rule: RuleConfig,
        key_value: str,
    ) -> TieredRateLimiter:
        """
        Get or create a tiered rate limiter for a rule.

        Limiters are cached by (rule_id:key_value) to reuse
        Redis connections and avoid recreating limiters.
        """
        cache_key = f"{rule.rule_id}:{key_value}"

        async with self._limiters_lock:
            if cache_key in self._limiters:
                return self._limiters[cache_key]

            # Create new limiter
            rate = rule.rate
            window = rule.window
            burst = rule.burst or rate * 2

            # L1: local token bucket
            # rate = requests per second (divide by window for per-window rate)
            tokens_per_second = rate / window if window > 0 else rate
            local_bucket = AsyncTokenBucket(rate=tokens_per_second, capacity=float(burst))

            # L2: Redis sliding window
            redis_key = f"ratelimit:{rule.rule_id}:{key_value}"
            redis_limiter = SlidingWindowRateLimiter(
                redis_client=self.redis,
                key=redis_key,
                rate=rate,
                window=window,
            )

            limiter = TieredRateLimiter(
                local_bucket=local_bucket,
                redis_limiter=redis_limiter,
            )

            # Evict old limiters if cache is too large
            if len(self._limiters) >= 1000:
                # Remove ~10% of oldest entries
                keys_to_remove = list(self._limiters.keys())[:100]
                for k in keys_to_remove:
                    del self._limiters[k]

            self._limiters[cache_key] = limiter
            return limiter

    def _resolve_key_type(self, ctx: RequestContext) -> str:
        """Determine which key type to use based on context."""
        if ctx.api_key:
            return "api_key"
        elif ctx.user_id:
            return "user"
        elif ctx.tenant_id:
            return "tenant"
        return "ip"

    def _resolve_key_value(self, ctx: RequestContext, key_type: str) -> str:
        """Extract the actual key value based on key type."""
        if key_type == "api_key":
            return ctx.api_key or "unknown"
        elif key_type == "user":
            return ctx.user_id or "anonymous"
        elif key_type == "tenant":
            return ctx.tenant_id or "default"
        elif key_type == "ip":
            return ctx.ip or "unknown"
        return "global"

    async def _get_retry_after(self, limiter: TieredRateLimiter) -> int:
        """Get seconds until a slot opens (approximate)."""
        try:
            return await limiter.redis.get_retry_after()
        except Exception:
            return 1  # Conservative default

    def _calculate_reset_at(self, window: int) -> Optional[datetime]:
        """Calculate when the current window resets."""
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc)
        # Estimate reset time (start of next window)
        # This is approximate since we don't track exact window start
        reset_ts = time.time() + window
        return datetime.fromtimestamp(reset_ts, tz=timezone.utc)

    # -------------------------------------------------------------------------
    # Admin / Monitoring
    # -------------------------------------------------------------------------

    async def get_circuit_breaker_stats(self) -> dict:
        """Get circuit breaker statistics."""
        return self._redis_breaker.get_stats()

    async def get_cache_stats(self) -> CacheStats:
        """Get L1 cache statistics."""
        stats = self._local_cache.stats()
        return CacheStats(
            l1_size=stats["size"],
            l1_max_size=stats["max_size"],
            l1_expired_pending=stats["expired_pending"],
        )

    async def invalidate_rules(self):
        """Invalidate rule cache (call after updating rules in DB)."""
        await self._config_loader.invalidate_cache()
        # Also clear limiter cache
        async with self._limiters_lock:
            self._limiters.clear()

    # -------------------------------------------------------------------------
    # User/Permission Caching (multilevel)
    # -------------------------------------------------------------------------

    async def get_cached_user_profile(self, user_id: str, loader):
        """Get user profile with L1+L2 caching."""
        key = self._cache.user_profile_key(user_id)
        return await self._cache.get(
            cache_key=key,
            loader=loader,
            l1_ttl=60,   # L1: 60s (local)
            l2_ttl=300,  # L2: 300s (Redis)
        )

    async def get_cached_user_permissions(
        self,
        user_id: str,
        loader,
    ):
        """Get user permissions with L1+L2 caching."""
        key = self._cache.user_permissions_key(user_id)
        return await self._cache.get(
            cache_key=key,
            loader=loader,
            l1_ttl=60,
            l2_ttl=300,
        )

    async def invalidate_user_cache(self, user_id: str):
        """Invalidate all cache entries for a user."""
        await self._cache.invalidate_user(user_id)

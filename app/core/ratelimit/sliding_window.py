"""
Redis Sliding Window Rate Limiter (Distributed L2)
Phase 2-7: 百万级 QOS 高并发架构

Redis-based sliding window log algorithm for distributed rate limiting.
Uses Redis sorted sets with timestamps as score for O(log N) operations.

Reference: see design doc Phase 2-7 Section 4.2
"""
from __future__ import annotations

import time
from typing import Optional, Tuple


# Lua script for atomic sliding window rate limit check
# KEYS[1] = rate limit key
# ARGV[1] = window size in seconds (integer)
# ARGV[2] = rate limit (integer)
# ARGV[3] = current timestamp in milliseconds (integer)
# Returns: 1 if allowed, 0 if rate limited
LUA_SLIDING_WINDOW = """
local key = KEYS[1]
local window = tonumber(ARGV[1])
local limit = tonumber(ARGV[2])
local now_ms = tonumber(ARGV[3])

-- Remove expired entries outside the window
redis.call('ZREMRANGEBYSCORE', key, 0, now_ms - window * 1000)

-- Count current entries in window
local count = redis.call('ZCARD', key)

-- Allow if under limit
if count < limit then
    -- Add current request with unique member (timestamp:random)
    local member = now_ms .. ':' .. math.random(1000000, 9999999)
    redis.call('ZADD', key, now_ms, member)
    redis.call('EXPIRE', key, window)
    return 1
end

return 0
"""


class SlidingWindowRateLimiter:
    """
    Redis-based sliding window rate limiter.

    Uses Redis sorted sets with timestamp as score.
    Each request is stored as a member with current timestamp.
    Window slides continuously - only requests within the last `window`
    seconds are counted.

    Features:
      - Atomic Lua script for race-condition-free check-and-increment
      - TTL on keys prevents memory leak
      - Jittered cleanup for stale entries

    Args:
        redis_client: Redis async client (e.g., aioredis.Redis)
        key: Base rate limit key (e.g., "ratelimit:login:ip")
        rate: Max requests allowed per window
        window: Window size in seconds
    """

    def __init__(
        self,
        redis_client,
        key: str,
        rate: int,
        window: int,
    ):
        self.redis = redis_client
        self.key = key
        self.rate = rate
        self.window = window

    async def is_allowed(self) -> bool:
        """
        Check and record a request. Atomic via Lua script.

        Returns:
            True if request is allowed (under limit)
            False if rate limited
        """
        now_ms = int(time.time() * 1000)
        result = await self.redis.eval(
            LUA_SLIDING_WINDOW,
            1,  # number of keys
            self.key,
            self.window,
            self.rate,
            now_ms,
        )
        return result == 1

    async def get_current_count(self) -> int:
        """
        Get current request count within the sliding window.
        For monitoring/debugging only (not atomic with is_allowed).
        """
        now_ms = int(time.time() * 1000)
        cutoff = now_ms - self.window * 1000
        await self.redis.zremrangebyscore(self.key, 0, cutoff)
        count = await self.redis.zcard(self.key)
        return count

    async def reset(self):
        """Clear the rate limit counter (for testing/admin)."""
        await self.redis.delete(self.key)

    async def get_ttl(self) -> int:
        """Get remaining TTL on the rate limit key."""
        return await self.redis.ttl(self.key)

    async def get_retry_after(self) -> int:
        """
        Get seconds until a new request slot opens.
        Returns 0 if under limit.
        """
        now_ms = int(time.time() * 1000)
        # Get the oldest entry's score (timestamp of earliest request)
        oldest = await self.redis.zrange(self.key, 0, 0, withscores=True)
        if not oldest:
            return 0
        oldest_ts = int(oldest[0][1])
        retry_after_ms = (oldest_ts + self.window * 1000) - now_ms
        if retry_after_ms < 0:
            return 0
        return (retry_after_ms // 1000) + 1


class FixedWindowRateLimiter:
    """
    Simpler fixed-window counter in Redis.
    Uses INCR + EXPIRE for O(1) operations.
    Less accurate than sliding window but faster.

    Use for high-throughput paths where slight overage is acceptable.
    """

    def __init__(
        self,
        redis_client,
        key: str,
        rate: int,
        window: int,
    ):
        self.redis = redis_client
        self.key = key
        self.rate = rate
        self.window = window

    def _window_key(self) -> str:
        """Append window identifier to key (e.g., ratelimit:login:ip:60)."""
        return f"{self.key}:{self.window}"

    async def is_allowed(self) -> bool:
        """Atomically increment and check."""
        k = self._window_key()
        current = await self.redis.incr(k)
        if current == 1:
            # First request in this window - set expiry
            await self.redis.expire(k, self.window)
        return current <= self.rate

    async def get_current_count(self) -> int:
        k = self._window_key()
        val = await self.redis.get(k)
        return int(val) if val else 0

    async def reset(self):
        await self.redis.delete(self._window_key())


class TieredRateLimiter:
    """
    Tiered rate limiter combining local (TokenBucket) + Redis (SlidingWindow).

    Strategy:
      - Local bucket: absorbs burst traffic without Redis round-trip
      - Redis window: enforces global limit across all instances

    Flow:
      1. Check local TokenBucket (fast path, no network)
      2. If local allows, check Redis sliding window (distributed check)
      3. If both allow, request proceeds

    Args:
        local_bucket: AsyncTokenBucket for local burst control
        redis_limiter: SlidingWindowRateLimiter for distributed enforcement
    """

    def __init__(
        self,
        local_bucket: "AsyncTokenBucket",
        redis_limiter: SlidingWindowRateLimiter,
    ):
        self.local = local_bucket
        self.redis = redis_limiter

    async def is_allowed(self) -> Tuple[bool, str]:
        """
        Check rate limit in two tiers.

        Returns:
            (allowed: bool, reason: str)
            reason: "allowed" | "local_limited" | "global_limited"
        """
        # Tier 1: Local token bucket (fast reject)
        if not await self.local.consume(1.0):
            return False, "local_limited"

        # Tier 2: Redis sliding window (distributed check)
        if not await self.redis.is_allowed():
            return False, "global_limited"

        return True, "allowed"

    async def reset(self):
        """Reset both local and global counters."""
        await self.local.reset()
        await self.redis.reset()

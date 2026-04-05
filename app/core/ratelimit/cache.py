"""
Multi-Level Cache (L1 Local + L2 Redis)
Phase 2-7: 百万级 QOS 高并发架构

L1: Local in-memory cache (dict/LRU) - TTL 60s
L2: Redis distributed cache - TTL 300s
L3: PostgreSQL (source of truth)

Cache penetration protection:
  - Lock key + double-check pattern
  - Jittered TTL to prevent simultaneous expiration

Cache key design (from design doc Section 3.2):
  - session:{session_jti}         -> 3600s
  - token:{access_token_hash}      -> 300s
  - user:profile:{user_id}        -> 60s (L1) / 300s (L2)
  - user:permissions:{user_id}    -> 300s
  - ratelimit:{endpoint}:{key}    -> sliding window
  - quota:daily:{api_key_id}      -> 86400s

Reference: see design doc Phase 2-7 Section 3.3
"""
from __future__ import annotations

import asyncio
import json
import logging
import random
from typing import Any, Callable, Optional, TypeVar
from dataclasses import dataclass

logger = logging.getLogger(__name__)

T = TypeVar("T")

# Default TTL configuration
CACHE_TTL_BASE = 300          # Base TTL in seconds
CACHE_TTL_JITTER = 30         # Random jitter range (-30 to +30)
CACHE_TTL_NULL = 60            # TTL for NULL/None cache (cache negative lookups)
LOCAL_CACHE_MAX_SIZE = 1000   # Max entries in L1 local cache


@dataclass
class CacheEntry:
    """Single entry in the local L1 cache."""
    value: Any
    expires_at: float  # Unix timestamp when this entry expires


class LocalCache:
    """
    Simple in-memory L1 cache with TTL support.
    
    Thread-safe for async use with asyncio.Lock.
    Does NOT use TTL-based eviction on access (no lazy deletion).
    Background task periodically cleans up expired entries.
    """

    def __init__(self, max_size: int = LOCAL_CACHE_MAX_SIZE):
        self._store: dict[str, CacheEntry] = {}
        self._max_size = max_size
        self._lock = asyncio.Lock()

    def get(self, key: str) -> Optional[Any]:
        """Get value if exists and not expired (synchronous)."""
        entry = self._store.get(key)
        if entry is None:
            return None
        import time
        if time.monotonic() > entry.expires_at:
            # Expired - will be cleaned up lazily
            return None
        return entry.value

    def set(self, key: str, value: Any, ttl: int):
        """Set value with TTL in seconds (synchronous)."""
        import time
        # Evict oldest if at capacity
        if len(self._store) >= self._max_size and key not in self._store:
            self._evict_oldest()
        self._store[key] = CacheEntry(
            value=value,
            expires_at=time.monotonic() + ttl,
        )

    def delete(self, key: str):
        """Delete a key."""
        self._store.pop(key, None)

    def clear(self):
        """Clear all entries."""
        self._store.clear()

    def _evict_oldest(self):
        """Evict the oldest entry by expires_at."""
        if not self._store:
            return
        oldest_key = min(self._store, key=lambda k: self._store[k].expires_at)
        del self._store[oldest_key]

    async def cleanup_expired(self):
        """Remove all expired entries (call periodically)."""
        import time
        now = time.monotonic()
        expired_keys = [
            k for k, e in self._store.items()
            if now > e.expires_at
        ]
        for k in expired_keys:
            del self._store[k]
        if expired_keys:
            logger.debug(f"LocalCache: cleaned up {len(expired_keys)} expired entries")

    def stats(self) -> dict:
        """Return cache statistics."""
        import time
        now = time.monotonic()
        expired = sum(1 for e in self._store.values() if now > e.expires_at)
        return {
            "size": len(self._store),
            "max_size": self._max_size,
            "expired_pending": expired,
        }


def get_jittered_ttl(base_ttl: int = CACHE_TTL_BASE) -> int:
    """
    Add random jitter to TTL to prevent cache stampede.

    Without jitter, all entries set at the same time would expire simultaneously,
    causing a "thundering herd" problem where many requests hit the DB at once.

    Returns:
        base_ttl + random.randint(-CACHE_TTL_JITTER, +CACHE_TTL_JITTER)
        Clamped to minimum 1 second.
    """
    jitter = random.randint(-CACHE_TTL_JITTER, CACHE_TTL_JITTER)
    return max(1, base_ttl + jitter)


class MultilevelCache:
    """
    L1 (Local) + L2 (Redis) multi-level cache.

    Read flow:
      1. Check L1 local cache -> hit return immediately
      2. Check L2 Redis -> hit: populate L1, return
      3. L2 miss -> call loader (DB read), populate both L1 and L2

    Write flow:
      1. Write to L2 (Redis)
      2. Write to L1 (local)

    Cache penetration protection:
      - lock_key pattern: SETNX on "lock:{cache_key}" before loading
      - NULL caching: cache "NULL" for non-existent keys to prevent
        repeated DB lookups for missing records

    Args:
        redis_client: Async Redis client (aioredis / redis-py async)
        local_cache: LocalCache instance (L1)
        lock_timeout: Seconds to hold a lock when loading (default 5s)
    """

    def __init__(
        self,
        redis_client,
        local_cache: Optional[LocalCache] = None,
        lock_timeout: int = 5,
    ):
        self.redis = redis_client
        self.local = local_cache or LocalCache()
        self.lock_timeout = lock_timeout
        # Separator for compound keys
        self._null_marker = "__NULL__"

    # -------------------------------------------------------------------------
    # Key patterns (from design doc Section 3.2)
    # -------------------------------------------------------------------------
    @staticmethod
    def session_key(session_jti: str) -> str:
        return f"session:{session_jti}"

    @staticmethod
    def token_key(token_hash: str) -> str:
        return f"token:{token_hash}"

    @staticmethod
    def user_profile_key(user_id: str) -> str:
        return f"user:profile:{user_id}"

    @staticmethod
    def user_permissions_key(user_id: str) -> str:
        return f"user:permissions:{user_id}"

    @staticmethod
    def ratelimit_key(endpoint: str, key: str, window: str) -> str:
        return f"ratelimit:{endpoint}:{key}:{window}"

    @staticmethod
    def quota_daily_key(api_key_id: str) -> str:
        return f"quota:daily:{api_key_id}"

    # -------------------------------------------------------------------------
    # Core operations
    # -------------------------------------------------------------------------

    async def get(
        self,
        cache_key: str,
        loader: Optional[Callable[[], Any]] = None,
        l1_ttl: int = 60,
        l2_ttl: Optional[int] = None,
    ) -> Optional[Any]:
        """
        Get from cache with optional loader on miss.

        Args:
            cache_key: Redis key
            loader: Async callable to load data on L2 miss
            l1_ttl: TTL for L1 local cache (default 60s)
            l2_ttl: TTL for L2 Redis cache (default: use jittered base)

        Returns:
            Cached value, or result of loader(), or None
        """
        # L1: local cache
        l1_val = self.local.get(cache_key)
        if l1_val is not None:
            return l1_val

        # L2: Redis
        l2_val = await self.redis.get(cache_key)
        if l2_val is not None:
            # Populate L1 from L2
            parsed = self._deserialize(l2_val)
            if parsed is not None:
                self.local.set(cache_key, parsed, l1_ttl)
            return parsed

        # L2 miss - need to load
        if loader is None:
            return None

        # Cache penetration protection: try to acquire lock
        lock_key = f"lock:{cache_key}"
        acquired = await self.redis.set(lock_key, "1", nx=True, ex=self.lock_timeout)
        try:
            if acquired:
                # Double-check L2 after acquiring lock
                l2_val = await self.redis.get(cache_key)
                if l2_val is not None:
                    parsed = self._deserialize(l2_val)
                    if parsed is not None:
                        self.local.set(cache_key, parsed, l1_ttl)
                    return parsed

                # Load from source (DB)
                data = await loader()
                if data is not None:
                    await self.set(cache_key, data, l1_ttl=l1_ttl, l2_ttl=l2_ttl)
                else:
                    # Cache NULL to prevent repeated lookups for missing keys
                    await self._set_null(cache_key, l1_ttl=l1_ttl)
                return data
            else:
                # Another process is loading - wait and retry
                await asyncio.sleep(0.1)
                l2_val = await self.redis.get(cache_key)
                if l2_val is not None:
                    parsed = self._deserialize(l2_val)
                    return parsed
                return None
        finally:
            if acquired:
                await self.redis.delete(lock_key)

    async def set(
        self,
        cache_key: str,
        value: Any,
        l1_ttl: int = 60,
        l2_ttl: Optional[int] = None,
    ):
        """
        Set value in both L1 and L2 caches.

        Args:
            cache_key: Redis key
            value: Value to cache (must be JSON-serializable)
            l1_ttl: TTL for L1 local cache
            l2_ttl: TTL for L2 Redis cache (default: jittered 300s)
        """
        if value is None:
            await self._set_null(cache_key, l1_ttl=l1_ttl)
            return

        # L2: Redis (use jittered TTL)
        redis_ttl = l2_ttl if l2_ttl is not None else get_jittered_ttl(CACHE_TTL_BASE)
        serialized = self._serialize(value)
        await self.redis.set(cache_key, serialized, ex=redis_ttl)

        # L1: local cache
        self.local.set(cache_key, value, l1_ttl)

    async def _set_null(self, cache_key: str, l1_ttl: int = CACHE_TTL_NULL):
        """Cache a NULL marker to prevent cache penetration."""
        redis_ttl = get_jittered_ttl(CACHE_TTL_NULL)
        await self.redis.set(cache_key, self._null_marker, ex=redis_ttl)
        self.local.set(cache_key, self._null_marker, l1_ttl)

    def is_null_marker(self, value: Any) -> bool:
        """Check if value is the NULL marker."""
        return value == self._null_marker

    async def delete(self, cache_key: str):
        """Delete from both L1 and L2."""
        self.local.delete(cache_key)
        await self.redis.delete(cache_key)

    async def invalidate_user(self, user_id: str):
        """
        Invalidate all cache entries for a user.
        Called on user profile/permission updates.
        """
        keys = [
            self.user_profile_key(user_id),
            self.user_permissions_key(user_id),
        ]
        for key in keys:
            await self.delete(key)

    # -------------------------------------------------------------------------
    # Utility
    # -------------------------------------------------------------------------

    def _serialize(self, value: Any) -> str:
        """Serialize value to JSON string."""
        return json.dumps(value, default=str)

    def _deserialize(self, data: str) -> Any:
        """Deserialize JSON string to Python object."""
        try:
            return json.loads(data)
        except (json.JSONDecodeError, TypeError):
            return data

    async def cleanup_local(self):
        """Run L1 cache cleanup of expired entries."""
        await self.local.cleanup_expired()

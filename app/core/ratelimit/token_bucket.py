"""
Token Bucket Rate Limiter (Local L1)
Phase 2-7: 百万级 QOS 高并发架构

Token bucket algorithm for local (in-process) rate limiting.
Each instance maintains its own bucket - suitable for burst control
within a single process/instance.
"""
from __future__ import annotations

import threading
import time
from typing import Optional


class TokenBucket:
    """
    Thread-safe token bucket rate limiter for local use.

    Algorithm:
      - Bucket capacity = max tokens that can accumulate
      - Refill rate = tokens per second added
      - Consume: if tokens >= requested, deduct and allow

    Args:
        rate: Tokens added per second (float)
        capacity: Maximum tokens in bucket (float)
    """

    def __init__(self, rate: float, capacity: float):
        self.rate = rate
        self.capacity = capacity
        self._tokens = capacity
        self._last_refill = time.monotonic()
        self._lock = threading.Lock()

    def consume(self, tokens: float = 1.0) -> bool:
        """
        Attempt to consume tokens from the bucket.

        Returns:
            True if tokens were consumed (request allowed)
            False if insufficient tokens (request denied)
        """
        with self._lock:
            self._refill_unlocked()
            if self._tokens >= tokens:
                self._tokens -= tokens
                return True
            return False

    def _refill_unlocked(self):
        """Refill tokens based on elapsed time (must hold lock)."""
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)
        self._last_refill = now

    def reset(self):
        """Reset bucket to full capacity."""
        with self._lock:
            self._tokens = self.capacity
            self._last_refill = time.monotonic()

    @property
    def available_tokens(self) -> float:
        """Current available tokens (approximate, for monitoring)."""
        with self._lock:
            self._refill_unlocked()
            return self._tokens

    @property
    def fill_percentage(self) -> float:
        """Bucket fill percentage 0.0-1.0 (for monitoring)."""
        return self.available_tokens / self.capacity

    @property
    def fill_percentage(self) -> float:
        """Bucket fill percentage 0.0-1.0 (for monitoring)."""
        return self.available_tokens / self.capacity


class AsyncTokenBucket:
    """
    Async-compatible token bucket using per-task locking.
    """

    def __init__(self, rate: float, capacity: float):
        self.rate = rate
        self.capacity = capacity
        self._tokens = capacity
        self._last_refill = time.monotonic()
        self._lock = None  # Lazy init for asyncio

    def _get_lock(self):
        import asyncio
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock

    async def consume(self, tokens: float = 1.0) -> bool:
        async with self._get_lock():
            self._refill()
            if self._tokens >= tokens:
                self._tokens -= tokens
                return True
            return False

    def _refill(self):
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)
        self._last_refill = now

    async def reset(self):
        async with self._get_lock():
            self._tokens = self.capacity
            self._last_refill = time.monotonic()

    @property
    def available_tokens(self) -> float:
        """Current available tokens (for monitoring)."""
        self._refill()
        return self._tokens

    @property
    def fill_percentage(self) -> float:
        """Bucket fill percentage 0.0-1.0 (for monitoring)."""
        return self.available_tokens / self.capacity

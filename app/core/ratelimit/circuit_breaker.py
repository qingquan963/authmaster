"""
Circuit Breaker
Phase 2-7: 百万级 QOS 高并发架构

Circuit breaker pattern for fault tolerance.
Prevents cascading failures by short-circuiting calls to failing services.

Reference: see design doc Phase 2-7 Section 4.3
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from enum import Enum
from typing import Callable, Any, TypeVar, Optional
from functools import wraps
import logging

logger = logging.getLogger(__name__)

T = TypeVar("T")


class CircuitState(Enum):
    CLOSED = "closed"       # Normal operation, requests pass through
    OPEN = "open"           # Failure threshold exceeded, requests rejected
    HALF_OPEN = "half_open"  # Recovery timeout elapsed, testing with limited calls


class CircuitOpenError(Exception):
    """Raised when circuit breaker is OPEN and request is rejected."""

    def __init__(self, message: str = "Circuit breaker is OPEN"):
        self.message = message
        super().__init__(self.message)


class CircuitBreaker:
    """
    Async-compatible circuit breaker.

    State transitions:
      CLOSED -> OPEN: failure_count >= failure_threshold
      OPEN -> HALF_OPEN: recovery_timeout elapsed
      HALF_OPEN -> CLOSED: call succeeds
      HALF_OPEN -> OPEN: call fails or max_half_open_calls reached

    Args:
        name: Identifier for this breaker (e.g., "redis", "postgres")
        failure_threshold: Failures to trigger OPEN (default 5)
        recovery_timeout: Seconds before attempting HALF_OPEN (default 30)
        half_open_max_calls: Max test calls in HALF_OPEN before deciding (default 3)
        success_threshold: Successes in CLOSED to reset failure count (default 2)
    """

    def __init__(
        self,
        name: str = "default",
        failure_threshold: int = 5,
        recovery_timeout: float = 30.0,
        half_open_max_calls: int = 3,
        success_threshold: int = 2,
    ):
        self.name = name
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.half_open_max_calls = half_open_max_calls
        self.success_threshold = success_threshold

        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._last_failure_time: Optional[datetime] = None
        self._half_open_calls = 0
        self._lock = asyncio.Lock()

    @property
    def state(self) -> CircuitState:
        return self._state

    @property
    def failure_count(self) -> int:
        return self._failure_count

    async def call(self, func: Callable[..., Any], *args, **kwargs) -> Any:
        """
        Execute func with circuit breaker protection.

        Args:
            func: Async callable to execute
            *args, **kwargs: Arguments to pass to func

        Returns:
            Result of func

        Raises:
            CircuitOpenError: When circuit is OPEN
        """
        async with self._lock:
            if self._state == CircuitState.OPEN:
                if self._should_attempt_reset():
                    await self._to_half_open()
                else:
                    raise CircuitOpenError(
                        f"Circuit breaker '{self.name}' is OPEN"
                    )

            if self._state == CircuitState.HALF_OPEN:
                if self._half_open_calls >= self.half_open_max_calls:
                    raise CircuitOpenError(
                        f"Circuit breaker '{self.name}' is HALF_OPEN (max calls reached)"
                    )
                self._half_open_calls += 1

        try:
            result = await func(*args, **kwargs)
            await self._on_success()
            return result
        except Exception as e:
            await self._on_failure()
            raise

    def _should_attempt_reset(self) -> bool:
        """Check if recovery timeout has elapsed."""
        if self._last_failure_time is None:
            return True
        elapsed = (datetime.now(timezone.utc) - self._last_failure_time).total_seconds()
        return elapsed >= self.recovery_timeout

    async def _to_half_open(self):
        """Transition from OPEN to HALF_OPEN."""
        self._state = CircuitState.HALF_OPEN
        self._half_open_calls = 0
        logger.info(f"Circuit breaker '{self.name}' OPEN -> HALF_OPEN")

    async def _on_success(self):
        async with self._lock:
            self._failure_count = 0
            if self._state == CircuitState.HALF_OPEN:
                self._success_count += 1
                if self._success_count >= self.success_threshold:
                    self._state = CircuitState.CLOSED
                    self._success_count = 0
                    logger.info(f"Circuit breaker '{self.name}' HALF_OPEN -> CLOSED")

    async def _on_failure(self):
        async with self._lock:
            self._failure_count += 1
            self._last_failure_time = datetime.now(timezone.utc)
            self._success_count = 0

            if self._state == CircuitState.HALF_OPEN:
                self._state = CircuitState.OPEN
                self._half_open_calls = 0
                logger.warning(
                    f"Circuit breaker '{self.name}' HALF_OPEN -> OPEN (failure in half-open)"
                )
            elif self._failure_count >= self.failure_threshold:
                self._state = CircuitState.OPEN
                logger.warning(
                    f"Circuit breaker '{self.name}' CLOSED -> OPEN "
                    f"(failures={self._failure_count})"
                )

    async def reset(self):
        """Manually reset circuit breaker to CLOSED."""
        async with self._lock:
            self._state = CircuitState.CLOSED
            self._failure_count = 0
            self._success_count = 0
            self._half_open_calls = 0
            self._last_failure_time = None
            logger.info(f"Circuit breaker '{self.name}' manually reset to CLOSED")

    def get_stats(self) -> dict:
        """Get current circuit breaker statistics."""
        return {
            "name": self.name,
            "state": self._state.value,
            "failure_count": self._failure_count,
            "success_count": self._success_count,
            "half_open_calls": self._half_open_calls,
            "last_failure_time": (
                self._last_failure_time.isoformat()
                if self._last_failure_time else None
            ),
        }


def circuit_breaker_protected(breaker: CircuitBreaker):
    """
    Decorator to protect an async function with a circuit breaker.

    Usage:
        @circuit_breaker_protected(my_breaker)
        async def call_external_service():
            ...
    """
    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            return await breaker.call(func, *args, **kwargs)
        return wrapper
    return decorator

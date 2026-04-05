"""
AuthMaster SDK - Decorators Module

Provides the :func:`auto_retry` decorator that wraps SDK method calls with
automatic exponential-back-off retry logic based on the error code returned
by the API.
"""

from __future__ import annotations

import logging
import time
from functools import wraps
from typing import Any, Callable, Optional, TypeVar, Union

from .exceptions import (
    AuthMasterError,
    InternalServerError,
    RateLimitExceededError,
    ServerUnavailableError,
    TokenExpiredError,
)

if True:
    # Allow `from authmaster.decorators import auto_retry` without circular import.
    pass

logger = logging.getLogger("authmaster")

# ---------------------------------------------------------------------------
# Retry strategy
# ---------------------------------------------------------------------------

# Error codes that are safe to auto-retry (idempotent or transient).
_RETRYABLE_CODES: frozenset[str] = frozenset({
    "TOKEN_EXPIRED",
    "RATE_LIMIT_EXCEEDED",
    "INTERNAL_ERROR",
    "SERVER_UNAVAILABLE",
})

# Error codes that must NOT be retried (permanent failures).
_NON_RETRYABLE_CODES: frozenset[str] = frozenset({
    "INVALID_CREDENTIALS",
    "PERMISSION_DENIED",
    "NOT_FOUND",
    "VALIDATION_ERROR",
    "MFA_REQUIRED",
    "QUOTA_EXCEEDED",
    "REFRESH_TOKEN_EXPIRED",
    "IDEMPOTENCY_CONFLICT",
    "SDK_CONFIG_ERROR",
    "API_MARSHAL_ERROR",
    "UNKNOWN_ERROR",
})


F = TypeVar("F", bound=Callable[..., Any])


def auto_retry(
    max_attempts: int = 3,
    backoff_base: float = 2.0,
    initial_delay: float = 0.5,
    max_delay: float = 60.0,
    retry_on: Optional[set[str]] = None,
    never_retry_on: Optional[set[str]] = None,
) -> Callable[[F], F]:
    """
    Decorator that automatically retries SDK method calls on transient errors.

    The decorator implements **exponential back-off with jitter**::

        delay = min(max_delay, initial_delay * (backoff_base ** attempt)) + random_jitter

    Parameters
    ----------
    max_attempts : int, default 3
        Maximum number of attempts (including the first call).
        A value of 1 means no retries.
    backoff_base : float, default 2.0
        Exponential base.  Each retry waits ``backoff_base ** attempt`` seconds.
    initial_delay : float, default 0.5
        Initial delay in seconds before the first retry.
    max_delay : float, default 60.0
        Maximum delay cap between retries (prevents unbounded waits).
    retry_on : set[str] | None
        If provided, only these error codes trigger a retry.
        If ``None``, retry on the default safe-to-retry set.
    never_retry_on : set[str] | None
        If provided, these error codes are never retried regardless of
        ``retry_on``.  Takes priority over ``retry_on``.

    Examples
    --------
    >>> client = AuthMasterClient(api_key="ak_xxx", api_secret="sk_xxx")
    >>> with auto_retry(max_attempts=5):
    ...     client.list_users(page=1)

    The decorator can also be applied at the class-method level::

        class AuthMasterClient:
            @auto_retry(max_attempts=3)
            def create_user(self, username, email, password):
                ...
    """

    if retry_on is not None:
        retryable = retry_on
    else:
        retryable = _RETRYABLE_CODES

    if never_retry_on is not None:
        never_retryable = never_retry_on
    else:
        never_retryable = _NON_RETRYABLE_CODES

    def decorator(func: F) -> F:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            last_exception: Optional[AuthMasterError] = None

            for attempt in range(max_attempts):
                try:
                    return func(*args, **kwargs)
                except AuthMasterError as exc:
                    # --- permanent failure: give up immediately ---
                    if exc.code in never_retryable:
                        logger.debug(
                            "[auto_retry] %s: code=%s is non-retryable, re-raising",
                            func.__name__,
                            exc.code,
                        )
                        raise

                    # --- check allow-list ---
                    if retry_on is not None and exc.code not in retryable:
                        logger.debug(
                            "[auto_retry] %s: code=%s not in retry_on set, re-raising",
                            func.__name__,
                            exc.code,
                        )
                        raise

                    # --- out of attempts ---
                    if attempt == max_attempts - 1:
                        logger.warning(
                            "[auto_retry] %s: exhausted %d attempts (last error: %s), re-raising",
                            func.__name__,
                            max_attempts,
                            exc,
                        )
                        raise

                    # --- compute back-off delay ---
                    base_delay = min(
                        max_delay,
                        initial_delay * (backoff_base ** attempt),
                    )
                    # Add jitter (±25%) to avoid thundering herd.
                    import random
                    jitter = base_delay * 0.25 * (random.random() * 2 - 1)
                    delay = base_delay + jitter

                    # Honour Retry-After from rate-limit errors.
                    if isinstance(exc, RateLimitExceededError):
                        delay = max(delay, exc.retry_after_seconds)
                        logger.info(
                            "[auto_retry] %s: RATE_LIMIT_EXCEEDED, backing off %.1fs (attempt %d/%d)",
                            func.__name__,
                            delay,
                            attempt + 1,
                            max_attempts,
                        )
                    else:
                        logger.info(
                            "[auto_retry] %s: %s, backing off %.1fs (attempt %d/%d)",
                            func.__name__,
                            exc.code,
                            delay,
                            attempt + 1,
                            max_attempts,
                        )

                    time.sleep(delay)

                except Exception as exc:
                    # Non-AuthMasterError: re-raise immediately.
                    logger.warning(
                        "[auto_retry] %s: unexpected %s, re-raising",
                        func.__name__,
                        exc,
                    )
                    raise

            # Should never reach here, but mypy needs it.
            raise last_exception or RuntimeError(
                f"{func.__name__} failed after {max_attempts} attempts"
            )

        return wrapper  # type: ignore[return-value]

    return decorator


class retry_on_rate_limit:
    """
    Context manager / decorator that retries the wrapped block only when a
    ``RateLimitExceededError`` is raised.

    Uses the ``retry_after_seconds`` value from the exception to wait the
    minimum necessary time.

    Examples
    --------
    >>> with retry_on_rate_limit(max_attempts=5):
    ...     client.list_users()
    """

    def __init__(self, max_attempts: int = 5):
        self.max_attempts = max_attempts

    def __enter__(self) -> "retry_on_rate_limit":
        return self

    def __exit__(
        self,
        exc_type: Any,
        exc_val: Any,
        exc_tb: Any,
    ) -> bool:
        if isinstance(exc_val, RateLimitExceededError):
            delay = exc_val.retry_after_seconds
            for attempt in range(self.max_attempts - 1):
                logger.info(
                    "[retry_on_rate_limit] rate-limit hit, sleeping %.1fs then retrying (%d/%d)",
                    delay,
                    attempt + 2,
                    self.max_attempts,
                )
                time.sleep(delay)
                # Re-invoke the last operation – caller must re-execute the block.
                return True  # suppress the exception, caller re-runs
        return False  # re-raise other exceptions

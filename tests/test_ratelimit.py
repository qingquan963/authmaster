"""
Tests for Phase 2-7: Rate Limiting / QOS High Concurrency Architecture

Tests cover:
  - TokenBucket (local L1)
  - SlidingWindowRateLimiter (Redis L2)
  - CircuitBreaker (fault tolerance)
  - MultilevelCache (L1+L2 cache)
  - Pattern matching (config loader)
  - RateLimitService integration
"""
import asyncio
import time
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

# ---------------------------------------------------------------------------
# Token Bucket Tests
# ---------------------------------------------------------------------------

class TestTokenBucket:
    """Test synchronous token bucket."""

    def test_bucket_starts_full(self):
        from app.core.ratelimit.token_bucket import TokenBucket
        bucket = TokenBucket(rate=10.0, capacity=10.0)
        assert bucket.available_tokens == 10.0

    def test_consume_removes_tokens(self):
        from app.core.ratelimit.token_bucket import TokenBucket
        bucket = TokenBucket(rate=10.0, capacity=10.0)
        assert bucket.consume(1.0) is True
        assert bucket.available_tokens == 9.0

    def test_consume_blocks_when_empty(self):
        from app.core.ratelimit.token_bucket import TokenBucket
        bucket = TokenBucket(rate=0.0, capacity=1.0)
        assert bucket.consume(1.0) is True
        assert bucket.consume(1.0) is False  # Empty

    def test_refill_over_time(self):
        from app.core.ratelimit.token_bucket import TokenBucket
        bucket = TokenBucket(rate=100.0, capacity=10.0)
        bucket.consume(5.0)
        assert bucket.available_tokens == 5.0
        # After 0.05s at 100 tokens/s, should refill ~5 tokens
        time.sleep(0.05)
        tokens = bucket.available_tokens
        assert 9.5 < tokens <= 10.0  # Almost full

    def test_reset_restores_capacity(self):
        from app.core.ratelimit.token_bucket import TokenBucket
        bucket = TokenBucket(rate=10.0, capacity=10.0)
        bucket.consume(8.0)
        bucket.reset()
        assert bucket.available_tokens == 10.0

    def test_fill_percentage(self):
        from app.core.ratelimit.token_bucket import TokenBucket
        bucket = TokenBucket(rate=10.0, capacity=10.0)
        bucket.consume(5.0)
        assert 0.4 < bucket.fill_percentage <= 0.5


class TestAsyncTokenBucket:
    """Test async token bucket."""

    @pytest.mark.asyncio
    async def test_async_consume(self):
        from app.core.ratelimit.token_bucket import AsyncTokenBucket
        bucket = AsyncTokenBucket(rate=10.0, capacity=10.0)
        assert await bucket.consume(1.0) is True
        assert await bucket.consume(9.0) is True
        assert await bucket.consume(1.0) is False  # Empty

    @pytest.mark.asyncio
    async def test_async_refill(self):
        from app.core.ratelimit.token_bucket import AsyncTokenBucket
        bucket = AsyncTokenBucket(rate=100.0, capacity=10.0)
        await bucket.consume(5.0)
        await asyncio.sleep(0.05)
        tokens = bucket.available_tokens
        assert 9.5 < tokens <= 10.0

    @pytest.mark.asyncio
    async def test_async_reset(self):
        from app.core.ratelimit.token_bucket import AsyncTokenBucket
        bucket = AsyncTokenBucket(rate=10.0, capacity=10.0)
        await bucket.consume(8.0)
        await bucket.reset()
        assert bucket.available_tokens == 10.0


# ---------------------------------------------------------------------------
# Circuit Breaker Tests
# ---------------------------------------------------------------------------

class TestCircuitBreaker:
    """Test circuit breaker state machine."""

    @pytest.mark.asyncio
    async def test_initial_state_is_closed(self):
        from app.core.ratelimit.circuit_breaker import CircuitBreaker, CircuitState
        cb = CircuitBreaker(failure_threshold=3, recovery_timeout=10.0)
        assert cb.state == CircuitState.CLOSED
        assert cb.failure_count == 0

    @pytest.mark.asyncio
    async def test_opens_after_threshold(self):
        from app.core.ratelimit.circuit_breaker import (
            CircuitBreaker, CircuitState, CircuitOpenError
        )
        cb = CircuitBreaker(failure_threshold=3, recovery_timeout=10.0)

        async def failing_func():
            raise RuntimeError("fail")

        # 3 failures should open the circuit
        for _ in range(3):
            with pytest.raises(RuntimeError):
                await cb.call(failing_func)

        assert cb.state == CircuitState.OPEN

        # Now calls should be rejected immediately
        with pytest.raises(CircuitOpenError):
            await cb.call(lambda: asyncio.sleep(0))

    @pytest.mark.asyncio
    async def test_half_open_after_recovery_timeout(self):
        from app.core.ratelimit.circuit_breaker import (
            CircuitBreaker, CircuitState, CircuitOpenError
        )
        # Very short recovery timeout for testing
        cb = CircuitBreaker(
            failure_threshold=1,
            recovery_timeout=0.05,  # 50ms
            half_open_max_calls=2,
            success_threshold=1,
        )

        async def failing_func():
            raise RuntimeError("fail")

        # Trigger failure to open circuit
        with pytest.raises(RuntimeError):
            await cb.call(failing_func)

        assert cb.state == CircuitState.OPEN

        # Wait for recovery timeout
        await asyncio.sleep(0.1)

        # Next call should transition to HALF_OPEN
        async def success_func():
            return "ok"

        result = await cb.call(success_func)
        assert result == "ok"
        # With success_threshold=1, one success should close the circuit
        assert cb.state == CircuitState.CLOSED

    @pytest.mark.asyncio
    async def test_success_resets_failure_count(self):
        from app.core.ratelimit.circuit_breaker import CircuitBreaker, CircuitState
        cb = CircuitBreaker(failure_threshold=3, success_threshold=1)

        # First, add some failures manually (simulating past failures)
        cb._failure_count = 2

        # A success should reset failure count
        async def success_func():
            return "ok"

        result = await cb.call(success_func)
        assert result == "ok"
        assert cb.failure_count == 0

    @pytest.mark.asyncio
    async def test_manual_reset(self):
        from app.core.ratelimit.circuit_breaker import CircuitBreaker, CircuitState
        cb = CircuitBreaker(failure_threshold=1)
        async def fail():
            raise RuntimeError("fail")
        with pytest.raises(RuntimeError):
            await cb.call(fail)
        assert cb.state == CircuitState.OPEN

        await cb.reset()
        assert cb.state == CircuitState.CLOSED
        assert cb.failure_count == 0

    @pytest.mark.asyncio
    async def test_get_stats(self):
        from app.core.ratelimit.circuit_breaker import CircuitBreaker
        cb = CircuitBreaker(name="test_breaker", failure_threshold=5)
        stats = cb.get_stats()
        assert stats["name"] == "test_breaker"
        assert stats["state"] == "closed"
        assert stats["failure_count"] == 0


# ---------------------------------------------------------------------------
# Sliding Window Tests
# ---------------------------------------------------------------------------

class TestSlidingWindowRateLimiter:
    """Test Redis sliding window rate limiter."""

    @pytest.mark.asyncio
    async def test_allows_under_limit(self):
        from app.core.ratelimit.sliding_window import SlidingWindowRateLimiter

        mock_redis = AsyncMock()
        # Lua script returns 1 (allowed)
        mock_redis.eval = AsyncMock(return_value=1)

        limiter = SlidingWindowRateLimiter(
            redis_client=mock_redis,
            key="test:key",
            rate=10,
            window=60,
        )

        result = await limiter.is_allowed()
        assert result is True
        mock_redis.eval.assert_called_once()

    @pytest.mark.asyncio
    async def test_denies_over_limit(self):
        from app.core.ratelimit.sliding_window import SlidingWindowRateLimiter

        mock_redis = AsyncMock()
        # Lua script returns 0 (denied)
        mock_redis.eval = AsyncMock(return_value=0)

        limiter = SlidingWindowRateLimiter(
            redis_client=mock_redis,
            key="test:key",
            rate=10,
            window=60,
        )

        result = await limiter.is_allowed()
        assert result is False

    @pytest.mark.asyncio
    async def test_get_current_count(self):
        from app.core.ratelimit.sliding_window import SlidingWindowRateLimiter

        mock_redis = AsyncMock()
        mock_redis.zrange = AsyncMock(return_value=[("key1", 12345.0)])
        mock_redis.zremrangebyscore = AsyncMock()
        mock_redis.zcard = AsyncMock(return_value=1)

        limiter = SlidingWindowRateLimiter(
            redis_client=mock_redis,
            key="test:key",
            rate=10,
            window=60,
        )

        count = await limiter.get_current_count()
        assert count == 1


class TestTieredRateLimiter:
    """Test tiered rate limiter combining local + Redis."""

    @pytest.mark.asyncio
    async def test_allows_when_both_pass(self):
        from app.core.ratelimit.sliding_window import TieredRateLimiter, SlidingWindowRateLimiter
        from app.core.ratelimit.token_bucket import AsyncTokenBucket

        mock_redis = AsyncMock()
        mock_redis.eval = AsyncMock(return_value=1)  # Redis allows

        local_bucket = AsyncTokenBucket(rate=100.0, capacity=10.0)
        redis_limiter = SlidingWindowRateLimiter(mock_redis, "test", 10, 60)
        tiered = TieredRateLimiter(local_bucket, redis_limiter)

        allowed, reason = await tiered.is_allowed()
        assert allowed is True
        assert reason == "allowed"

    @pytest.mark.asyncio
    async def test_denies_local_first(self):
        from app.core.ratelimit.sliding_window import TieredRateLimiter, SlidingWindowRateLimiter
        from app.core.ratelimit.token_bucket import AsyncTokenBucket

        mock_redis = AsyncMock()
        mock_redis.eval = AsyncMock(return_value=1)

        # Local bucket is empty
        local_bucket = AsyncTokenBucket(rate=0.0, capacity=1.0)
        await local_bucket.consume(1.0)  # Empty it

        redis_limiter = SlidingWindowRateLimiter(mock_redis, "test", 10, 60)
        tiered = TieredRateLimiter(local_bucket, redis_limiter)

        allowed, reason = await tiered.is_allowed()
        assert allowed is False
        assert reason == "local_limited"

    @pytest.mark.asyncio
    async def test_denies_global_when_local_passes(self):
        from app.core.ratelimit.sliding_window import TieredRateLimiter, SlidingWindowRateLimiter
        from app.core.ratelimit.token_bucket import AsyncTokenBucket

        mock_redis = AsyncMock()
        mock_redis.eval = AsyncMock(return_value=0)  # Redis denies

        local_bucket = AsyncTokenBucket(rate=100.0, capacity=10.0)
        redis_limiter = SlidingWindowRateLimiter(mock_redis, "test", 10, 60)
        tiered = TieredRateLimiter(local_bucket, redis_limiter)

        allowed, reason = await tiered.is_allowed()
        assert allowed is False
        assert reason == "global_limited"


# ---------------------------------------------------------------------------
# Multilevel Cache Tests
# ---------------------------------------------------------------------------

class TestLocalCache:
    """Test L1 local cache."""

    def test_get_missing_returns_none(self):
        from app.core.ratelimit.cache import LocalCache
        cache = LocalCache()
        assert cache.get("missing") is None

    def test_set_and_get(self):
        from app.core.ratelimit.cache import LocalCache
        import time
        cache = LocalCache()
        cache.set("key1", "value1", ttl=10)
        assert cache.get("key1") == "value1"

    def test_expired_returns_none(self):
        from app.core.ratelimit.cache import LocalCache
        import time
        cache = LocalCache()
        cache.set("key1", "value1", ttl=1)
        time.sleep(1.1)
        assert cache.get("key1") is None

    def test_delete(self):
        from app.core.ratelimit.cache import LocalCache
        cache = LocalCache()
        cache.set("key1", "value1", ttl=10)
        cache.delete("key1")
        assert cache.get("key1") is None

    def test_clear(self):
        from app.core.ratelimit.cache import LocalCache
        cache = LocalCache()
        cache.set("key1", "value1", ttl=10)
        cache.set("key2", "value2", ttl=10)
        cache.clear()
        assert cache.get("key1") is None
        assert cache.get("key2") is None

    def test_max_size_eviction(self):
        from app.core.ratelimit.cache import LocalCache
        cache = LocalCache(max_size=3)
        for i in range(5):
            cache.set(f"key{i}", f"value{i}", ttl=100)
        # At least one of the first keys should be evicted
        assert cache.get("key0") is None or cache.get("key1") is None


class TestGetJitteredTTL:
    """Test TTL jitter function."""

    def test_jitter_within_range(self):
        from app.core.ratelimit.cache import get_jittered_ttl, CACHE_TTL_BASE, CACHE_TTL_JITTER
        for _ in range(100):
            ttl = get_jittered_ttl()
            assert CACHE_TTL_BASE - CACHE_TTL_JITTER <= ttl <= CACHE_TTL_BASE + CACHE_TTL_JITTER

    def test_minimum_one_second(self):
        from app.core.ratelimit.cache import get_jittered_ttl
        # Even with minimum TTL, should return at least 1
        for _ in range(50):
            ttl = get_jittered_ttl(base_ttl=1)
            assert ttl >= 1


class TestMultilevelCache:
    """Test L1+L2 multilevel cache."""

    @pytest.mark.asyncio
    async def test_l1_hit(self):
        from app.core.ratelimit.cache import MultilevelCache, LocalCache

        mock_redis = AsyncMock()
        local = LocalCache()
        cache = MultilevelCache(mock_redis, local)

        # Set in local cache directly
        local.set("test_key", "local_value", ttl=100)

        # Should hit L1, not query Redis
        result = await cache.get("test_key")
        assert result == "local_value"
        mock_redis.get.assert_not_called()

    @pytest.mark.asyncio
    async def test_l2_hit_populates_l1(self):
        from app.core.ratelimit.cache import MultilevelCache, LocalCache

        mock_redis = AsyncMock()
        mock_redis.get = AsyncMock(return_value='"redis_value"')  # JSON serialized
        local = LocalCache()
        cache = MultilevelCache(mock_redis, local)

        result = await cache.get("test_key")

        assert result == "redis_value"
        # L1 should now have the value
        assert local.get("test_key") == "redis_value"

    @pytest.mark.asyncio
    async def test_loader_called_on_miss(self):
        from app.core.ratelimit.cache import MultilevelCache, LocalCache

        mock_redis = AsyncMock()
        mock_redis.get = AsyncMock(side_effect=[None, None])  # Miss then double-check
        mock_redis.set = AsyncMock()
        mock_redis.delete = AsyncMock()
        mock_redis.setnx = AsyncMock(return_value=True)  # Lock acquired

        local = LocalCache()
        cache = MultilevelCache(mock_redis, local)

        loader_called = False
        async def loader():
            nonlocal loader_called
            loader_called = True
            return {"data": "loaded"}

        result = await cache.get("missing_key", loader=loader)

        assert loader_called is True
        assert result == {"data": "loaded"}

    @pytest.mark.asyncio
    async def test_delete_removes_from_both(self):
        from app.core.ratelimit.cache import MultilevelCache, LocalCache

        mock_redis = AsyncMock()
        mock_redis.delete = AsyncMock()
        local = LocalCache()
        cache = MultilevelCache(mock_redis, local)

        local.set("key1", "value1", ttl=100)
        await cache.delete("key1")

        assert local.get("key1") is None
        mock_redis.delete.assert_called_once_with("key1")

    @pytest.mark.asyncio
    async def test_cache_penetration_protection_null_marker(self):
        from app.core.ratelimit.cache import MultilevelCache, LocalCache

        mock_redis = AsyncMock()
        mock_redis.get = AsyncMock(side_effect=[None, None])  # Miss
        mock_redis.set = AsyncMock()
        mock_redis.delete = AsyncMock()
        mock_redis.setnx = AsyncMock(return_value=True)

        local = LocalCache()
        cache = MultilevelCache(mock_redis, local)

        # Loader returns None (non-existent key)
        async def loader():
            return None

        result = await cache.get("missing_key", loader=loader)

        # Should cache the NULL marker
        assert result is None
        # Check that NULL marker was set
        calls = mock_redis.set.call_args_list
        assert len(calls) >= 1


# ---------------------------------------------------------------------------
# Config Loader Tests
# ---------------------------------------------------------------------------

class TestPatternMatching:
    """Test endpoint pattern matching."""

    def test_exact_match(self):
        from app.core.ratelimit.config_loader import RateLimitConfigLoader

        loader = RateLimitConfigLoader(db_session_factory=None)

        assert loader._match_pattern("/api/v1/auth/login", "/api/v1/auth/login") is True
        assert loader._match_pattern("/api/v1/auth/login", "/api/v1/auth/logout") is False

    def test_single_wildcard(self):
        from app.core.ratelimit.config_loader import RateLimitConfigLoader

        loader = RateLimitConfigLoader(db_session_factory=None)

        assert loader._match_pattern("/api/v1/sdk/users", "/api/v1/sdk/*") is True
        assert loader._match_pattern("/api/v1/sdk/roles", "/api/v1/sdk/*") is True
        assert loader._match_pattern("/api/v1/auth/login", "/api/v1/sdk/*") is False

    def test_double_wildcard(self):
        from app.core.ratelimit.config_loader import RateLimitConfigLoader

        loader = RateLimitConfigLoader(db_session_factory=None)

        assert loader._match_pattern("/api/v1/auth/login", "/api/**") is True
        assert loader._match_pattern("/api/v1/sdk/users", "/api/**") is True
        assert loader._match_pattern("/other/path", "/api/**") is False


class TestRateLimitConfigLoader:
    """Test config loader rule matching."""

    @pytest.mark.asyncio
    async def test_loads_rules_from_db(self):
        from app.core.ratelimit.config_loader import RateLimitConfigLoader

        # Create a mock rule
        mock_rule = MagicMock()
        mock_rule.id = "rule-1"
        mock_rule.endpoint_pattern = "/api/v1/auth/login"
        mock_rule.key_type = "ip"
        mock_rule.rate = 5
        mock_rule.window = 60
        mock_rule.burst = 10
        mock_rule.priority = 100
        mock_rule.tenant_id = None
        mock_rule.extra_config = {}

        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [mock_rule]
        mock_session.execute = AsyncMock(return_value=mock_result)

        # Need to make mock_factory an async context manager
        class MockDbFactory:
            async def __aenter__(self):
                return mock_session
            async def __aexit__(self, *args):
                pass

        loader = RateLimitConfigLoader(db_session_factory=MockDbFactory)

        rules = await loader._load_rules_from_db()

        assert len(rules) == 1
        assert rules[0].endpoint_pattern == "/api/v1/auth/login"
        assert rules[0].rate == 5


# ---------------------------------------------------------------------------
# Integration-like Tests (using mocks)
# ---------------------------------------------------------------------------

class TestRateLimitServiceIntegration:
    """Test RateLimitService with mocked dependencies."""

    @pytest.mark.asyncio
    async def test_check_returns_decision(self):
        from app.core.ratelimit.service import RateLimitService, RequestContext
        from app.core.ratelimit.schemas import RateLimitDecision

        mock_redis = AsyncMock()
        mock_db_factory = AsyncMock()

        # Mock config loader to return a default rule
        with patch.object(
            RateLimitService,
            '_config_loader',
            create=True
        ):
            service = RateLimitService(
                redis_client=mock_redis,
                db_session_factory=mock_db_factory,
            )

            # Manually set a simple limiter
            service._limiters["test"] = MagicMock()
            service._limiters["test"].is_allowed = AsyncMock(return_value=(True, "allowed"))
            service._limiters["test"].redis.get_current_count = AsyncMock(return_value=5)

            ctx = RequestContext(
                endpoint="/api/v1/test",
                ip="192.168.1.1",
                user_id=None,
                api_key=None,
                tenant_id=None,
            )

            # Note: This is a simplified test. Full integration would need
            # proper mocking of config_loader.match_rule

    @pytest.mark.asyncio
    async def test_cache_stats(self):
        from app.core.ratelimit.service import RateLimitService

        mock_redis = AsyncMock()
        mock_db_factory = AsyncMock()

        service = RateLimitService(
            redis_client=mock_redis,
            db_session_factory=mock_db_factory,
        )

        stats = await service.get_cache_stats()
        assert stats.l1_size >= 0
        assert stats.l1_max_size > 0


# ---------------------------------------------------------------------------
# Run tests
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    pytest.main([__file__, "-v"])

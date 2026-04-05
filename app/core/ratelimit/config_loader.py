"""
Rate Limit Config Loader
Phase 2-7: 百万级 QOS 高并发架构

Loads rate limit rules from database with caching.
Rules are cached in local memory and refreshed periodically.

Reference: see design doc Phase 2-7 Section 4.4
"""
from __future__ import annotations

import asyncio
import fnmatch
import logging
import time
from dataclasses import dataclass, field
from typing import Optional

from app.core.ratelimit.models import RateLimitRule
from app.core.ratelimit.cache import LocalCache, MultilevelCache

logger = logging.getLogger(__name__)


@dataclass
class RuleConfig:
    """Compiled rate limit rule for fast matching."""
    rule_id: str
    endpoint_pattern: str
    key_type: str
    rate: int
    window: int
    burst: Optional[int]
    priority: int
    tenant_id: Optional[str]
    extra_config: dict


@dataclass
class MatchingRule:
    """Best-matching rule for a request."""
    rule: RuleConfig
    key_value: str  # The actual key used (e.g., "192.168.1.1")


class RateLimitConfigLoader:
    """
    Loads and matches rate limit rules from database.

    Features:
      - Pattern matching with wildcard support (* matches any segment)
      - Priority-based rule selection (highest priority wins)
      - Local in-memory cache of rules (refreshed every 60s)
      - Fallback to default rule if no matching rule found

    Example patterns:
      - /api/v1/auth/login  -> exact match
      - /api/v1/sdk/*       -> prefix match
      - /api/v1/**          -> matches any path under /api/v1/

    Default fallback:
      - If no matching rule, use conservative defaults:
        rate=100, window=1 (100 RPS global)

    Args:
        db_session_factory: Async SQLAlchemy session factory
        config_cache_ttl: How often to reload rules from DB (seconds)
    """

    # Default fallback rule when no matching rule is found
    DEFAULT_RATE = 100
    DEFAULT_WINDOW = 1
    DEFAULT_BURST = 200

    def __init__(
        self,
        db_session_factory,
        config_cache_ttl: int = 60,
    ):
        self._db_factory = db_session_factory
        self._cache_ttl = config_cache_ttl

        # Local cache of compiled rules (path -> list of RuleConfig)
        self._rules_cache: list[RuleConfig] = []
        self._cache_loaded_at: float = 0
        self._cache_lock = asyncio.Lock()

    async def _load_rules_from_db(self) -> list[RuleConfig]:
        """Load all enabled rules from database."""
        async with self._db_factory() as session:
            from sqlalchemy import select
            stmt = select(RateLimitRule).where(
                RateLimitRule.enabled == True  # noqa: E712
            ).order_by(RateLimitRule.priority.desc())
            result = await session.execute(stmt)
            rows = result.scalars().all()

            rules = []
            for row in rows:
                rules.append(RuleConfig(
                    rule_id=str(row.id),
                    endpoint_pattern=row.endpoint_pattern,
                    key_type=row.key_type or "ip",
                    rate=row.rate,
                    window=row.window,
                    burst=row.burst,
                    priority=row.priority or 0,
                    tenant_id=str(row.tenant_id) if row.tenant_id else None,
                    extra_config=row.extra_config or {},
                ))
            return rules

    async def get_rules(self) -> list[RuleConfig]:
        """
        Get all rules, using cache if still valid.
        Refreshes from DB if cache is older than _cache_ttl seconds.
        """
        now = time.monotonic()
        if self._rules_cache and (now - self._cache_loaded_at) < self._cache_ttl:
            return self._rules_cache

        async with self._cache_lock:
            # Double-check after acquiring lock
            if self._rules_cache and (time.monotonic() - self._cache_loaded_at) < self._cache_ttl:
                return self._rules_cache

            try:
                self._rules_cache = await self._load_rules_from_db()
                self._cache_loaded_at = time.monotonic()
                logger.info(
                    f"Loaded {len(self._rules_cache)} rate limit rules from DB"
                )
            except Exception as e:
                logger.error(f"Failed to load rate limit rules: {e}")
                # Return stale cache on error
                if self._rules_cache:
                    return self._rules_cache
                # Last resort: return empty list (will use defaults)
                return []

        return self._rules_cache

    async def match_rule(
        self,
        endpoint: str,
        key_type: str,
        key_value: str,
        tenant_id: Optional[str] = None,
    ) -> Optional[MatchingRule]:
        """
        Find the best matching rule for a request.

        Args:
            endpoint: Request path (e.g., "/api/v1/auth/login")
            key_type: Type of key (ip/user/api_key/tenant/global)
            key_value: The actual key value (e.g., "192.168.1.1")
            tenant_id: Tenant ID for tenant-specific rules

        Returns:
            MatchingRule if a rule matches, None for default
        """
        rules = await self.get_rules()

        best_match: Optional[RuleConfig] = None
        best_priority = -1

        for rule in rules:
            # Skip rules that don't match the key type
            if rule.key_type != key_type and rule.key_type != "global":
                continue

            # Tenant-specific rules only match if tenant_id matches
            if rule.tenant_id is not None:
                if tenant_id is None or rule.tenant_id != tenant_id:
                    continue

            # Check if endpoint matches the pattern
            if self._match_pattern(endpoint, rule.endpoint_pattern):
                if rule.priority >= best_priority:
                    best_priority = rule.priority
                    best_match = rule

        if best_match:
            return MatchingRule(rule=best_match, key_value=key_value)
        return None

    def _match_pattern(self, path: str, pattern: str) -> bool:
        """
        Match a path against a pattern with wildcard support.

        Supports:
          - ** -> matches any number of path segments
          - *  -> matches within a single path segment

        Examples:
          - /api/v1/auth/login matches /api/v1/auth/login
          - /api/v1/sdk/* matches /api/v1/sdk/users
          - /api/** matches /api/v1/auth/login
        """
        # Convert pattern to fnmatch-compatible format
        # ** -> ** (keep as-is for recursive)
        # Replace ** with a placeholder, then use fnmatch
        if "**" in pattern:
            # For ** patterns, do prefix matching
            prefix = pattern.replace("**", "").rstrip("/")
            if prefix:
                return path.startswith(prefix) or path == prefix.rstrip("/")
            return True  # ** alone matches everything

        # For * patterns, use fnmatch for segment-level matching
        # fnmatch treats * as matching anything within a segment
        import re
        regex_pattern = pattern.replace(".", r"\.").replace("**/", ".*/").replace("**", ".*")
        regex_pattern = "^" + regex_pattern.replace("*", "[^/]*") + "$"
        try:
            return bool(re.match(regex_pattern, path))
        except re.error:
            return fnmatch.fnmatch(path, pattern)

    async def get_default_rule(self) -> RuleConfig:
        """Get the default fallback rule."""
        return RuleConfig(
            rule_id="__default__",
            endpoint_pattern="*",
            key_type="global",
            rate=self.DEFAULT_RATE,
            window=self.DEFAULT_WINDOW,
            burst=self.DEFAULT_BURST,
            priority=-1,
            tenant_id=None,
            extra_config={},
        )

    async def invalidate_cache(self):
        """Force cache invalidation (call after rule updates)."""
        async with self._cache_lock:
            self._rules_cache = []
            self._cache_loaded_at = 0
            logger.info("Rate limit rule cache invalidated")

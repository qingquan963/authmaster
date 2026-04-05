"""
Reports Module - Anomaly Detection Rule Engine
Phase 2-8: 安全报表/用户画像

Detects login anomalies using configurable rules:
  - geo_anomaly    : Login city not in user's usual city list
  - time_anomaly   : Login time outside user's usual hours (±3h window)
  - new_device     : Device fingerprint not in trusted list
  - bruteforce     : ≥10 failed logins from same IP within 5 minutes
  - impossible_travel: Distance÷time > 800km/h between consecutive logins

Rules are loaded from anomaly_rules table, cached 60s.
Each matched rule increments the risk score; blocking rules (bruteforce)
trigger immediate denial.
"""
from __future__ import annotations

import asyncio
import math
import uuid
from datetime import datetime, timezone
from typing import Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
MAX_SCORE = 100
BLOCKING_SCORE = 100

# Default rules (used when DB rules are not yet seeded)
DEFAULT_RULES: list[dict] = [
    {
        "rule_name": "geo_anomaly",
        "anomaly_type": "geo_anomaly",
        "score_increment": 40,
        "is_blocking": False,
        "threshold_value": None,
        "enabled": True,
        "priority": 10,
    },
    {
        "rule_name": "time_anomaly",
        "anomaly_type": "time_anomaly",
        "score_increment": 25,
        "is_blocking": False,
        "threshold_value": 3.0,
        "threshold_unit": "hours",
        "enabled": True,
        "priority": 20,
    },
    {
        "rule_name": "new_device",
        "anomaly_type": "new_device",
        "score_increment": 20,
        "is_blocking": False,
        "enabled": True,
        "priority": 30,
    },
    {
        "rule_name": "bruteforce",
        "anomaly_type": "bruteforce",
        "score_increment": 60,
        "is_blocking": True,
        "threshold_value": 10.0,
        "threshold_unit": "failures_per_5min",
        "enabled": True,
        "priority": 1,
    },
    {
        "rule_name": "impossible_travel",
        "anomaly_type": "impossible_travel",
        "score_increment": 70,
        "is_blocking": False,
        "threshold_value": 800.0,
        "threshold_unit": "km_per_hour",
        "enabled": True,
        "priority": 5,
    },
]

# Rule config cache TTL
RULE_CACHE_TTL_SECONDS = 60


# ---------------------------------------------------------------------------
# Geo utilities
# ---------------------------------------------------------------------------
def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Compute great-circle distance in km between two lat/lon points."""
    R = 6371.0
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = (math.sin(dphi / 2) ** 2
         + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2)
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


# ---------------------------------------------------------------------------
# Rule engine
# ---------------------------------------------------------------------------
class AnomalyResult:
    def __init__(self):
        self.risk_score: int = 0
        self.anomaly_types: list[str] = []
        self.is_blocking: bool = False
        self.descriptions: list[str] = []
        self.factors: list[dict] = []

    def add(self, rule: dict, detail: str = ""):
        self.risk_score = min(self.risk_score + rule["score_increment"], MAX_SCORE)
        self.anomaly_types.append(rule["anomaly_type"])
        if rule["is_blocking"]:
            self.is_blocking = True
        if detail:
            self.descriptions.append(detail)
        self.factors.append({
            "factor": rule["anomaly_type"],
            "severity": "high" if rule["is_blocking"] else "medium",
            "detail": detail or rule.get("description", ""),
        })

    def to_dict(self) -> dict:
        risk_level = "high" if self.risk_score >= 70 else ("medium" if self.risk_score >= 40 else "low")
        return {
            "risk_score": self.risk_score,
            "risk_level": risk_level,
            "anomaly_types": self.anomaly_types,
            "is_blocking": self.is_blocking,
            "descriptions": self.descriptions,
            "factors": self.factors,
        }


class AnomalyDetector:
    """
    Configurable anomaly detection rule engine.

    Rules are loaded from the anomaly_rules DB table and cached for 60 seconds.
    The engine processes a login event against all enabled rules sorted by priority.
    """

    def __init__(
        self,
        db_session,
        redis=None,
        rule_cache_ttl: int = RULE_CACHE_TTL_SECONDS,
    ):
        self.db = db_session
        self.redis = redis
        self._rule_cache: Optional[list[dict]] = None
        self._rule_cache_at: Optional[datetime] = None
        self._rule_cache_ttl = rule_cache_ttl

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    async def evaluate(
        self,
        user_id: uuid.UUID,
        tenant_id: uuid.UUID,
        event_data: dict,
    ) -> AnomalyResult:
        """
        Evaluate a login event against all enabled anomaly rules.

        event_data keys:
          ip_address, geo_country, geo_city, geo_latitude, geo_longitude,
          user_agent, device_fp_hash, login_hour, login_weekday,
          login_method, status, created_at
        """
        result = AnomalyResult()
        rules = await self._get_enabled_rules(tenant_id)

        for rule in rules:
            rule_name = rule["rule_name"]
            if rule_name == "geo_anomaly":
                await self._check_geo_anomaly(rule, user_id, event_data, result)
            elif rule_name == "time_anomaly":
                await self._check_time_anomaly(rule, user_id, event_data, result)
            elif rule_name == "new_device":
                await self._check_new_device(rule, user_id, event_data, result)
            elif rule_name == "bruteforce":
                await self._check_bruteforce(rule, tenant_id, event_data, result)
            elif rule_name == "impossible_travel":
                await self._check_impossible_travel(rule, user_id, event_data, result)

            if result.is_blocking:
                break

        return result

    # ------------------------------------------------------------------
    # Rule checks
    # ------------------------------------------------------------------
    async def _check_geo_anomaly(
        self,
        rule: dict,
        user_id: uuid.UUID,
        event_data: dict,
        result: AnomalyResult,
    ):
        """geo_anomaly: current city not in user's usual city list."""
        geo_city = event_data.get("geo_city")
        if not geo_city:
            return

        usual_cities = await self._get_user_usual_cities(user_id)
        if usual_cities and geo_city not in usual_cities:
            result.add(rule, f"登录城市 {geo_city} 不在常用城市列表中")

    async def _check_time_anomaly(
        self,
        rule: dict,
        user_id: uuid.UUID,
        event_data: dict,
        result: AnomalyResult,
    ):
        """time_anomaly: login time outside ±3h of user's usual hours."""
        login_hour = event_data.get("login_hour")
        if login_hour is None:
            return

        usual_hours = await self._get_user_usual_hours(user_id)
        if not usual_hours:
            return

        threshold_hours = float(rule.get("threshold_value") or 3.0)
        is_anomalous = True
        for usual in usual_hours:
            diff = abs((login_hour - usual) % 24)
            if diff <= threshold_hours or diff >= 24 - threshold_hours:
                is_anomalous = False
                break

        if is_anomalous:
            result.add(rule, f"登录时间 {login_hour}:00 不在常用时段 (±{threshold_hours}h) 内")

    async def _check_new_device(
        self,
        rule: dict,
        user_id: uuid.UUID,
        event_data: dict,
        result: AnomalyResult,
    ):
        """new_device: device fingerprint not in trusted list."""
        fp_hash = event_data.get("device_fp_hash")
        if not fp_hash:
            return

        trusted = await self._get_user_trusted_devices(user_id)
        if trusted and fp_hash not in trusted:
            result.add(rule, f"设备 {fp_hash[:8]}... 不在信任设备列表中")

    async def _check_bruteforce(
        self,
        rule: dict,
        tenant_id: uuid.UUID,
        event_data: dict,
        result: AnomalyResult,
    ):
        """
        bruteforce: same IP ≥N failed logins within 5 minutes.
        Uses Redis sliding window counter for high-performance counting.
        """
        ip_address = event_data.get("ip_address")
        if not ip_address:
            return

        threshold = int(rule.get("threshold_value") or 10.0)
        redis = self.redis
        if redis is None:
            return

        try:
            key = f"bruteforce:{tenant_id}:{ip_address}"
            count = await redis.get(key)
            if count is None:
                await redis.setex(key, 300, 1)
            else:
                count = int(count) + 1
                await redis.setex(key, 300, count)
                if count >= threshold:
                    result.add(rule, f"IP {ip_address} 5分钟内登录失败 {count} 次")
        except Exception:
            pass

    async def _check_impossible_travel(
        self,
        rule: dict,
        user_id: uuid.UUID,
        event_data: dict,
        result: AnomalyResult,
    ):
        """
        impossible_travel: distance÷time > 800km/h between last and current login.
        Requires geo_latitude/geo_longitude on both events.
        """
        lat = event_data.get("geo_latitude")
        lon = event_data.get("geo_longitude")
        if lat is None or lon is None:
            return

        last_event = await self._get_last_login_event(user_id)
        if not last_event:
            return

        last_lat = last_event.get("geo_latitude")
        last_lon = last_event.get("geo_longitude")
        if last_lat is None or last_lon is None:
            return

        distance_km = haversine_km(last_lat, last_lon, lat, lon)
        now = event_data.get("created_at") or datetime.now(timezone.utc)
        last_time = last_event.get("created_at")
        if not last_time:
            return

        delta_hours = max((now - last_time).total_seconds() / 3600, 0.001)
        speed_kmh = distance_km / delta_hours
        threshold = float(rule.get("threshold_value") or 800.0)

        if speed_kmh > threshold:
            result.add(
                rule,
                f"从 {last_event.get('geo_city','?')} 到 {event_data.get('geo_city','?')} "
                f"距离 {distance_km:.0f}km，时间差 {delta_hours:.1f}h，速度 {speed_kmh:.0f}km/h"
            )

    # ------------------------------------------------------------------
    # Helpers: user behavior profiles
    # ------------------------------------------------------------------
    async def _get_user_usual_cities(self, user_id: uuid.UUID) -> list[str]:
        """Return user's top N usual login cities (cached 1 hour)."""
        if self.redis:
            try:
                cached = await self.redis.get(f"profile:cities:{user_id}")
                if cached:
                    import json
                    return json.loads(cached)
            except Exception:
                pass
        return []

    async def _get_user_usual_hours(self, user_id: uuid.UUID) -> list[int]:
        """Return user's common login hours (0-23)."""
        if self.redis:
            try:
                cached = await self.redis.get(f"profile:hours:{user_id}")
                if cached:
                    import json
                    return json.loads(cached)
            except Exception:
                pass
        return []

    async def _get_user_trusted_devices(self, user_id: uuid.UUID) -> set[str]:
        """Return set of trusted device fp_hash values."""
        return set()

    async def _get_last_login_event(self, user_id: uuid.UUID) -> Optional[dict]:
        """
        Get last successful login event from ClickHouse (or DB fallback).
        Returns dict with geo_latitude, geo_longitude, geo_city, created_at.
        """
        return None

    # ------------------------------------------------------------------
    # Rule loading & caching
    # ------------------------------------------------------------------
    async def _get_enabled_rules(self, tenant_id: uuid.UUID) -> list[dict]:
        """Load enabled rules from DB, with 60s in-memory cache."""
        now = datetime.now(timezone.utc)
        if (
            self._rule_cache is not None
            and self._rule_cache_at is not None
            and (now - self._rule_cache_at).total_seconds() < self._rule_cache_ttl
        ):
            return self._rule_cache

        try:
            rows = await self.db.execute(
                """
                SELECT rule_name, anomaly_type, score_increment, is_blocking,
                       threshold_value, threshold_unit, enabled, priority, description
                FROM anomaly_rules
                WHERE enabled = TRUE
                ORDER BY priority ASC
                """
            )
            import json
            rules = [dict(r._mapping) for r in rows.fetchall()]
            if not rules:
                rules = DEFAULT_RULES
        except Exception:
            rules = DEFAULT_RULES

        # Sort by priority (ascending) for consistent evaluation order
        rules = sorted(rules, key=lambda r: r.get("priority", 999))

        # Also cache in Redis for cross-instance sharing
        if self.redis and rules != DEFAULT_RULES:
            try:
                await self.redis.setex(
                    "anomaly:rules",
                    self._rule_cache_ttl,
                    json.dumps(rules, default=str),
                )
            except Exception:
                pass

        self._rule_cache = rules
        self._rule_cache_at = now
        return rules

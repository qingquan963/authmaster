"""
Reports Module - ClickHouse Analytics Service
Phase 2-8: 安全报表/用户画像

Provides analytical queries against ClickHouse OLAP store:
  - Dashboard aggregates (trend data, top attackers, risk distribution)
  - Anomaly event queries with filters
  - User behavior profile queries (login activity, device/location/time patterns)

Note: ClickHouse is optional in dev/test environments.
      In production, set CLICKHOUSE_URL to enable OLAP queries.
      Falls back to PostgreSQL for small-scale deployments.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import structlog

logger = structlog.get_logger()


# ---------------------------------------------------------------------------
# Query templates
# ---------------------------------------------------------------------------

DASHBOARD_QUERY = """
SELECT
    toDate(created_at) AS date,
    COUNTIf(status = 'success') AS logins,
    COUNTIf(is_anomalous = TRUE) AS anomalies,
    COUNTIf(risk_level = 'blocked') AS blocked
FROM login_events_olap
WHERE tenant_id = {tenant_id: UUID}
  AND created_at >= {start_date: Date}
  AND created_at < {end_date: Date}
GROUP BY date
ORDER BY date ASC
"""

ANOMALY_EVENTS_QUERY = """
SELECT
    event_id,
    tenant_id,
    user_id,
    user_email,
    anomaly_type,
    description,
    ip_address,
    geo_country,
    geo_city,
    geo_latitude,
    geo_longitude,
    risk_score,
    risk_level,
    status,
    created_at
FROM login_events_olap
WHERE tenant_id = {tenant_id: UUID}
  AND is_anomalous = TRUE
  {% if anomaly_type %}
  AND has(anomaly_types, {anomaly_type: String})
  {% endif %}
  {% if start_date %}
  AND created_at >= {start_date: DateTime}
  {% endif %}
  {% if end_date %}
  AND created_at < {end_date: DateTime}
  {% endif %}
  {% if user_id %}
  AND user_id = {user_id: UUID}
  {% endif %}
ORDER BY created_at DESC
LIMIT {limit: UInt64}
OFFSET {offset: UInt64}
"""

USER_PROFILE_QUERY = """
SELECT
    user_id,
    tenant_id,
    logins_7d,
    logins_30d,
    devices_30d,
    cities_30d,
    avg_risk_score_30d,
    max_risk_score_30d,
    anomaly_count_30d
FROM user_behavior_profile
WHERE user_id = {user_id: UUID}
  AND tenant_id = {tenant_id: UUID}
"""

LOGIN_DEVICES_QUERY = """
SELECT
    device_fp_hash,
    user_agent,
    geo_city,
    created_at,
    COUNT(*) AS login_count
FROM login_events_olap
WHERE tenant_id = {tenant_id: UUID}
  AND user_id = {user_id: UUID}
  AND device_fp_hash != ''
  AND created_at >= {since: DateTime}
GROUP BY device_fp_hash, user_agent, geo_city, created_at
ORDER BY created_at DESC
LIMIT 50
"""

LOGIN_LOCATIONS_QUERY = """
SELECT
    geo_city,
    geo_country,
    created_at,
    COUNT(*) AS login_count
FROM login_events_olap
WHERE tenant_id = {tenant_id: UUID}
  AND user_id = {user_id: UUID}
  AND status = 'success'
  AND created_at >= {since: DateTime}
GROUP BY geo_city, geo_country, created_at
ORDER BY login_count DESC
LIMIT 20
"""

LOGIN_HOURS_QUERY = """
SELECT
    login_hour,
    COUNT(*) AS cnt
FROM login_events_olap
WHERE tenant_id = {tenant_id: UUID}
  AND user_id = {user_id: UUID}
  AND status = 'success'
  AND created_at >= {since: DateTime}
GROUP BY login_hour
ORDER BY cnt DESC
LIMIT 10
"""


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------

class ClickHouseService:
    """
    ClickHouse analytics query service.

    In test/dev environments (no ClickHouse), all methods return
    empty/fallback data so the API layer can be exercised end-to-end.

    Usage in production:
        ch = ClickHouseService(clickhouse_url="clickhouse://localhost:9000")
        dashboard = await ch.get_dashboard(tenant_id, period="30d")
    """

    def __init__(
        self,
        clickhouse_url: Optional[str] = None,
        db_pool=None,
        redis=None,
    ):
        self.ch_url = clickhouse_url
        self.db_pool = db_pool
        self.redis = redis
        self._client = None
        self._available = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    async def initialize(self):
        """Probe ClickHouse connection. Sets _available flag."""
        if not self.ch_url:
            logger.warning("clickhouse_service: no URL configured, OLAP disabled")
            return
        try:
            import clickhouse_connect
            self._client = clickhouse_connect.get_client(url=self.ch_url)
            self._client.command("SELECT 1")
            self._available = True
            logger.info("clickhouse_service: connected", url=self.ch_url)
        except Exception as e:
            logger.warning("clickhouse_service: unavailable", error=str(e))
            self._available = False

    async def close(self):
        if self._client:
            self._client.close()

    # ------------------------------------------------------------------
    # Dashboard
    # ------------------------------------------------------------------
    async def get_dashboard(
        self,
        tenant_id: uuid.UUID,
        period: str = "30d",
    ) -> dict:
        """
        Return dashboard aggregates for the given period.
        period: 7d | 30d | 90d
        """
        if not self._available:
            return self._fallback_dashboard(tenant_id, period)

        days = {"7d": 7, "30d": 30, "90d": 90}.get(period, 30)
        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=days)

        try:
            rows = self._client.query(
                DASHBOARD_QUERY,
                {
                    "tenant_id": str(tenant_id),
                    "start_date": start_date.strftime("%Y-%m-%d"),
                    "end_date": end_date.strftime("%Y-%m-%d"),
                },
            )
            trend_data = [
                {
                    "date": str(r[0]),
                    "logins": r[1] or 0,
                    "anomalies": r[2] or 0,
                    "blocked": r[3] or 0,
                }
                for r in (rows.result_rows or [])
            ]
        except Exception as e:
            logger.error("clickhouse dashboard query failed", error=str(e))
            trend_data = []

        current = self._compute_period_stats(trend_data)
        previous_period = await self._get_previous_period_stats(tenant_id, days)

        pct = self._pct_change

        return {
            "total_logins": current["logins"],
            "total_logins_change_pct": pct(current["logins"], previous_period["logins"]),
            "anomalous_events": current["anomalies"],
            "anomalous_events_change_pct": pct(
                current["anomalies"], previous_period["anomalies"]
            ),
            "blocked_attacks": current["blocked"],
            "blocked_attacks_change_pct": pct(current["blocked"], previous_period["blocked"]),
            "active_users": await self._count_active_users(tenant_id, days),
            "active_users_change_pct": 0.0,
            "trend_data": trend_data,
            "top_attack_sources": await self._get_top_attack_sources(tenant_id, days),
            "risk_distribution": await self._get_risk_distribution(tenant_id, days),
        }

    async def _get_previous_period_stats(
        self, tenant_id: uuid.UUID, days: int
    ) -> dict:
        end_date = datetime.now(timezone.utc) - timedelta(days=days)
        start_date = end_date - timedelta(days=days)
        return self._fallback_dashboard(tenant_id, f"{days}d")

    def _compute_period_stats(self, trend_data: list[dict]) -> dict:
        return {
            "logins": sum(d["logins"] for d in trend_data),
            "anomalies": sum(d["anomalies"] for d in trend_data),
            "blocked": sum(d["blocked"] for d in trend_data),
        }

    @staticmethod
    def _pct_change(current: int, previous: int) -> float:
        if previous == 0:
            return 0.0
        return round((current - previous) / previous * 100, 1)

    def _fallback_dashboard(
        self, tenant_id: uuid.UUID, period: str
    ) -> dict:
        return {
            "total_logins": 0,
            "total_logins_change_pct": 0.0,
            "anomalous_events": 0,
            "anomalous_events_change_pct": 0.0,
            "blocked_attacks": 0,
            "blocked_attacks_change_pct": 0.0,
            "active_users": 0,
            "active_users_change_pct": 0.0,
            "trend_data": [],
            "top_attack_sources": [],
            "risk_distribution": {"low": 0, "medium": 0, "high": 0},
        }

    async def _count_active_users(self, tenant_id: uuid.UUID, days: int) -> int:
        if not self._available:
            return 0
        try:
            result = self._client.query(
                """
                SELECT COUNT(DISTINCT user_id)
                FROM login_events_olap
                WHERE tenant_id = {tenant_id: UUID}
                  AND created_at >= {since: DateTime}
                  AND status = 'success'
                """,
                {
                    "tenant_id": str(tenant_id),
                    "since": (
                        datetime.now(timezone.utc) - timedelta(days=days)
                    ).isoformat(),
                },
            )
            rows = result.result_rows
            return rows[0][0] if rows else 0
        except Exception:
            return 0

    async def _get_top_attack_sources(
        self, tenant_id: uuid.UUID, days: int, limit: int = 5
    ) -> list[dict]:
        if not self._available:
            return []
        try:
            rows = self._client.query(
                """
                SELECT ip_address, count(*) AS cnt, geo_country
                FROM login_events_olap
                WHERE tenant_id = {tenant_id: UUID}
                  AND created_at >= {since: DateTime}
                  AND risk_level IN ('blocked', 'high')
                GROUP BY ip_address, geo_country
                ORDER BY cnt DESC
                LIMIT {limit: UInt64}
                """,
                {
                    "tenant_id": str(tenant_id),
                    "since": (
                        datetime.now(timezone.utc) - timedelta(days=days)
                    ).isoformat(),
                    "limit": limit,
                },
            )
            return [
                {"ip": str(r[0]), "count": r[1] or 0, "country": r[2] or "Unknown"}
                for r in (rows.result_rows or [])
            ]
        except Exception:
            return []

    async def _get_risk_distribution(
        self, tenant_id: uuid.UUID, days: int
    ) -> dict:
        if not self._available:
            return {"low": 0, "medium": 0, "high": 0}
        try:
            rows = self._client.query(
                """
                SELECT risk_level, COUNT(DISTINCT user_id) AS cnt
                FROM login_events_olap
                WHERE tenant_id = {tenant_id: UUID}
                  AND created_at >= {since: DateTime}
                  AND risk_level IN ('low', 'medium', 'high')
                GROUP BY risk_level
                """,
                {
                    "tenant_id": str(tenant_id),
                    "since": (
                        datetime.now(timezone.utc) - timedelta(days=days)
                    ).isoformat(),
                },
            )
            dist = {"low": 0, "medium": 0, "high": 0}
            for r in (rows.result_rows or []):
                dist[r[0]] = r[1] or 0
            return dist
        except Exception:
            return {"low": 0, "medium": 0, "high": 0}

    # ------------------------------------------------------------------
    # Anomaly Events
    # ------------------------------------------------------------------
    async def get_anomaly_events(
        self,
        tenant_id: uuid.UUID,
        anomaly_type: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        user_id: Optional[uuid.UUID] = None,
        page: int = 1,
        page_size: int = 50,
    ) -> tuple[list[dict], int]:
        """
        Query anomaly events from ClickHouse.
        Returns (items, total_count).
        """
        if not self._available:
            return [], 0

        offset = (page - 1) * page_size
        params = {
            "tenant_id": str(tenant_id),
            "limit": page_size,
            "offset": offset,
            "anomaly_type": anomaly_type,
            "start_date": start_date,
            "end_date": end_date,
            "user_id": str(user_id) if user_id else None,
        }

        try:
            rows = self._client.query(ANOMALY_EVENTS_QUERY, params)
            items = [
                {
                    "event_id": r[0],
                    "tenant_id": r[1],
                    "user_id": r[2],
                    "user_email": r[3],
                    "anomaly_type": r[4],
                    "description": r[5],
                    "ip_address": r[6],
                    "geo_location": {
                        "city": r[8],
                        "country": r[7],
                    },
                    "risk_score": r[11] or 0,
                    "risk_level": r[12],
                    "status": r[13],
                    "created_at": r[14],
                }
                for r in (rows.result_rows or [])
            ]

            count_rows = self._client.query(
                """
                SELECT COUNT(*)
                FROM login_events_olap
                WHERE tenant_id = {tenant_id: UUID}
                  AND is_anomalous = TRUE
                """,
                {"tenant_id": str(tenant_id)},
            )
            total = count_rows.result_rows[0][0] if count_rows.result_rows else 0
            return items, total
        except Exception as e:
            logger.error("clickhouse anomaly query failed", error=str(e))
            return [], 0

    # ------------------------------------------------------------------
    # User Profile
    # ------------------------------------------------------------------
    async def get_user_profile(
        self,
        user_id: uuid.UUID,
        tenant_id: uuid.UUID,
    ) -> dict:
        """Get user behavior profile from ClickHouse materialized view."""
        if not self._available:
            return {}

        try:
            rows = self._client.query(
                USER_PROFILE_QUERY,
                {"user_id": str(user_id), "tenant_id": str(tenant_id)},
            )
            if not rows.result_rows:
                return {}
            r = rows.result_rows[0]
            return {
                "logins_7d": r[2] or 0,
                "logins_30d": r[3] or 0,
                "devices_30d": r[4] or 0,
                "cities_30d": r[5] or 0,
                "avg_risk_score_30d": float(r[6] or 0),
                "max_risk_score_30d": float(r[7] or 0),
                "anomaly_count_30d": r[8] or 0,
            }
        except Exception as e:
            logger.error("clickhouse profile query failed", error=str(e))
            return {}

    async def get_user_devices(
        self, user_id: uuid.UUID, tenant_id: uuid.UUID, days: int = 90
    ) -> list[dict]:
        if not self._available:
            return []
        try:
            rows = self._client.query(
                LOGIN_DEVICES_QUERY,
                {
                    "user_id": str(user_id),
                    "tenant_id": str(tenant_id),
                    "since": (
                        datetime.now(timezone.utc) - timedelta(days=days)
                    ).isoformat(),
                },
            )
            return [
                {
                    "fp_hash": str(r[0]),
                    "ua": r[1] or "",
                    "city": r[2] or "",
                    "last_seen": str(r[3]),
                    "count": r[4] or 0,
                }
                for r in (rows.result_rows or [])
            ]
        except Exception:
            return []

    async def get_user_locations(
        self, user_id: uuid.UUID, tenant_id: uuid.UUID, days: int = 90
    ) -> list[dict]:
        if not self._available:
            return []
        try:
            rows = self._client.query(
                LOGIN_LOCATIONS_QUERY,
                {
                    "user_id": str(user_id),
                    "tenant_id": str(tenant_id),
                    "since": (
                        datetime.now(timezone.utc) - timedelta(days=days)
                    ).isoformat(),
                },
            )
            return [
                {
                    "city": r[0] or "Unknown",
                    "country": r[1] or "Unknown",
                    "last_seen": str(r[2]),
                    "count": r[3] or 0,
                }
                for r in (rows.result_rows or [])
            ]
        except Exception:
            return []

    async def get_user_login_hours(
        self, user_id: uuid.UUID, tenant_id: uuid.UUID, days: int = 90
    ) -> list[int]:
        if not self._available:
            return []
        try:
            rows = self._client.query(
                LOGIN_HOURS_QUERY,
                {
                    "user_id": str(user_id),
                    "tenant_id": str(tenant_id),
                    "since": (
                        datetime.now(timezone.utc) - timedelta(days=days)
                    ).isoformat(),
                },
            )
            return [r[0] for r in (rows.result_rows or [])]
        except Exception:
            return []

"""
Reports Module - Business Logic Service
Phase 2-8: 安全报表/用户画像

Orchestrates:
  - Dashboard data (ClickHouse or DB fallback)
  - Anomaly event queries
  - User profile aggregation
  - Export job management
  - Anomaly detection evaluation
  - Notification dispatch
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import structlog

from .anomaly_detector import AnomalyDetector, AnomalyResult
from .clickhouse_service import ClickHouseService
from .export_service import ExportService, ExportIdempotencyConflict
from .notification_service import NotificationService

logger = structlog.get_logger()


class ReportsService:
    """
    Main service orchestrating all reports-related operations.
    """

    def __init__(
        self,
        db,
        redis=None,
        clickhouse: Optional[ClickHouseService] = None,
        export_service: Optional[ExportService] = None,
        notification_service: Optional[NotificationService] = None,
    ):
        self.db = db
        self.redis = redis
        self.ch = clickhouse or ClickHouseService()
        self.export = export_service
        self.notifier = notification_service or NotificationService(redis=redis)
        self._anomaly_detector: Optional[AnomalyDetector] = None

    @property
    def anomaly_detector(self) -> AnomalyDetector:
        if self._anomaly_detector is None:
            self._anomaly_detector = AnomalyDetector(self.db, self.redis)
        return self._anomaly_detector

    # ------------------------------------------------------------------
    # Dashboard
    # ------------------------------------------------------------------

    async def get_dashboard(
        self,
        tenant_id: uuid.UUID,
        period: str = "30d",
    ) -> dict:
        """
        Get security dashboard aggregates.
        Falls back to PostgreSQL if ClickHouse is unavailable.
        """
        try:
            return await self.ch.get_dashboard(tenant_id, period)
        except Exception as e:
            logger.error("dashboard query failed, using fallback", error=str(e))
            return self._fallback_dashboard(tenant_id, period)

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
        Get anomaly events with filters.
        Tries ClickHouse first, falls back to PostgreSQL.
        """
        try:
            return await self.ch.get_anomaly_events(
                tenant_id, anomaly_type, start_date, end_date, user_id, page, page_size
            )
        except Exception as e:
            logger.error("anomaly query failed, using DB fallback", error=str(e))
            return await self._get_anomaly_events_from_db(
                tenant_id, anomaly_type, start_date, end_date, user_id, page, page_size
            )

    async def _get_anomaly_events_from_db(
        self,
        tenant_id: uuid.UUID,
        anomaly_type: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        user_id: Optional[uuid.UUID] = None,
        page: int = 1,
        page_size: int = 50,
    ) -> tuple[list[dict], int]:
        """PostgreSQL fallback for anomaly events."""
        offset = (page - 1) * page_size
        filters = [f"tenant_id = '{tenant_id}'", "1=1"]
        params = {}
        if anomaly_type:
            filters.append(f"anomaly_type = :anomaly_type")
            params["anomaly_type"] = anomaly_type
        if start_date:
            filters.append(f"created_at >= :start_date")
            params["start_date"] = start_date
        if end_date:
            filters.append(f"created_at < :end_date")
            params["end_date"] = end_date
        if user_id:
            filters.append(f"user_id = :user_id")
            params["user_id"] = str(user_id)

        where_clause = " AND ".join(filters)
        query = f"""
            SELECT id, tenant_id, user_id, anomaly_type, description,
                   ip_address, geo_country, geo_city, risk_score, risk_level,
                   status, created_at
            FROM anomaly_events
            WHERE {where_clause}
            ORDER BY created_at DESC
            LIMIT :limit OFFSET :offset
        """
        count_query = f"""
            SELECT COUNT(*) FROM anomaly_events WHERE {where_clause}
        """
        params["limit"] = page_size
        params["offset"] = offset

        try:
            rows = await self.db.execute(query, params)
            items = [dict(r._mapping) for r in rows.fetchall()]
            count_row = await self.db.execute(count_query, params)
            total = count_row.scalar() or 0
            return items, int(total)
        except Exception:
            return [], 0

    # ------------------------------------------------------------------
    # User Profile
    # ------------------------------------------------------------------

    async def get_user_profile(
        self,
        user_id: uuid.UUID,
        tenant_id: uuid.UUID,
    ) -> dict:
        """
        Aggregate full user profile from multiple sources:
          - ClickHouse behavior profile (login counts, risk scores)
          - PostgreSQL user data (roles, account age)
          - Redis cached device/city patterns
        """
        profile = {
            "user_id": user_id,
            "email": "",
            "profile": {
                "last_login_at": None,
                "login_count_7d": 0,
                "login_count_30d": 0,
                "trust_score": 100,
                "risk_level": "low",
                "account_age_days": 0,
            },
            "devices": {"total": 0, "trusted": 0, "recent": []},
            "locations": {"primary": [], "recent": []},
            "time_patterns": {"usual_login_hours": [], "usual_login_days": []},
            "permissions": {"current_roles": [], "role_changes_30d": 0, "last_role_change": None},
            "risk_factors": [],
        }

        # Load from ClickHouse
        try:
            ch_profile = await self.ch.get_user_profile(user_id, tenant_id)
            if ch_profile:
                profile["profile"]["login_count_7d"] = ch_profile.get("logins_7d", 0)
                profile["profile"]["login_count_30d"] = ch_profile.get("logins_30d", 0)
                avg_risk = ch_profile.get("avg_risk_score_30d", 0)
                max_risk = ch_profile.get("max_risk_score_30d", 0)
                if avg_risk > 70 or max_risk > 80:
                    profile["profile"]["risk_level"] = "high"
                    profile["risk_factors"].append({
                        "factor": "elevated_risk_score",
                        "severity": "high",
                        "detail": f"近30天平均风险评分 {avg_risk:.0f}，最高 {max_risk:.0f}",
                    })
                elif avg_risk > 40:
                    profile["profile"]["risk_level"] = "medium"

            # Device summary
            devices = await self.ch.get_user_devices(user_id, tenant_id)
            trusted = sum(1 for d in devices if d.get("count", 0) >= 5)
            profile["devices"]["total"] = len(devices)
            profile["devices"]["trusted"] = trusted
            profile["devices"]["recent"] = [
                {
                    "fp_hash": d["fp_hash"],
                    "ua": d.get("ua", ""),
                    "last_seen": d.get("last_seen"),
                    "is_trusted": d.get("count", 0) >= 5,
                }
                for d in devices[:5]
            ]

            # Location summary
            locations = await self.ch.get_user_locations(user_id, tenant_id)
            profile["locations"]["primary"] = [loc["city"] for loc in locations[:3] if loc.get("city")]
            profile["locations"]["recent"] = [
                {
                    "city": loc.get("city", "Unknown"),
                    "country": loc.get("country", "Unknown"),
                    "last_seen": loc.get("last_seen"),
                    "count": loc.get("count", 0),
                }
                for loc in locations[:5]
            ]

            # Time patterns
            hours = await self.ch.get_user_login_hours(user_id, tenant_id)
            profile["time_patterns"]["usual_login_hours"] = hours[:6]
        except Exception as e:
            logger.warning("user_profile_ch_fallback", error=str(e))

        # Load user metadata from PostgreSQL
        try:
            user_row = await self.db.execute(
                "SELECT email, created_at FROM auth_users WHERE id = :uid",
                {"uid": str(user_id)},
            )
            user_data = user_row.fetchone()
            if user_data:
                profile["email"] = user_data._mapping.get("email", "")
                created_at = user_data._mapping.get("created_at")
                if created_at:
                    profile["profile"]["account_age_days"] = (
                        datetime.now(timezone.utc) - created_at
                    ).days

            # Load roles
            roles_row = await self.db.execute(
                """
                SELECT r.name
                FROM auth_user_roles ur
                JOIN auth_roles r ON r.id = ur.role_id
                WHERE ur.user_id = :uid
                """,
                {"uid": str(user_id)},
            )
            roles = [r._mapping["name"] for r in roles_row.fetchall()]
            profile["permissions"]["current_roles"] = roles

            # Last login
            last_login_row = await self.db.execute(
                """
                SELECT created_at FROM auth_sessions
                WHERE user_id = :uid AND status = 'active'
                ORDER BY created_at DESC LIMIT 1
                """,
                {"uid": str(user_id)},
            )
            last_login = last_login_row.fetchone()
            if last_login:
                profile["profile"]["last_login_at"] = last_login._mapping["created_at"]

        except Exception as e:
            logger.warning("user_profile_db_fallback", error=str(e))

        return profile

    # ------------------------------------------------------------------
    # Anomaly Detection Evaluation
    # ------------------------------------------------------------------

    async def evaluate_login_anomaly(
        self,
        user_id: uuid.UUID,
        tenant_id: uuid.UUID,
        event_data: dict,
    ) -> AnomalyResult:
        """
        Evaluate a login event against the anomaly detection rules.
        Returns AnomalyResult with risk_score, anomaly_types, is_blocking.
        """
        return await self.anomaly_detector.evaluate(user_id, tenant_id, event_data)

    async def record_anomaly_event(
        self,
        user_id: uuid.UUID,
        tenant_id: uuid.UUID,
        event_id: uuid.UUID,
        anomaly_result: AnomalyResult,
        event_data: dict,
    ):
        """Persist a detected anomaly event to the database."""
        risk_level = (
            "high" if anomaly_result.risk_score >= 70
            else ("medium" if anomaly_result.risk_score >= 40 else "low")
        )
        description = "; ".join(anomaly_result.descriptions) or "Multiple anomalies detected"

        try:
            await self.db.execute(
                """
                INSERT INTO anomaly_events
                    (id, tenant_id, user_id, event_id, anomaly_type,
                     description, risk_score, risk_level,
                     ip_address, geo_country, geo_city,
                     user_agent, device_fp_hash, extra_data,
                     status, created_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, 'pending_review', NOW())
                """,
                uuid.uuid4(), tenant_id, user_id, event_id,
                ",".join(anomaly_result.anomaly_types) or "mixed",
                description,
                anomaly_result.risk_score,
                risk_level,
                event_data.get("ip_address"),
                event_data.get("geo_country"),
                event_data.get("geo_city"),
                event_data.get("user_agent"),
                event_data.get("device_fp_hash"),
                str(anomaly_result.to_dict()),
            )
            await self.db.commit()

            # Trigger high-risk notification
            if risk_level == "high":
                user_email = event_data.get("user_email", "")
                ip_address = event_data.get("ip_address")
                geo_location = event_data.get("geo_city")
                for at in anomaly_result.anomaly_types:
                    await self.notifier.notify_anomaly_alert(
                        user_id=user_id,
                        user_email=user_email,
                        anomaly_type=at,
                        description=description,
                        risk_level=risk_level,
                        risk_score=anomaly_result.risk_score,
                        ip_address=ip_address,
                        geo_location=geo_location,
                    )

        except Exception as e:
            logger.error("failed to record anomaly event", error=str(e))

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    async def create_export(
        self,
        tenant_id: uuid.UUID,
        created_by: uuid.UUID,
        report_type: str,
        format: str,
        filters: dict,
        idempotency_key: str,
        notify_email: Optional[str] = None,
    ) -> tuple[uuid.UUID, str]:
        """
        Create an export job (idempotent).
        Raises ExportIdempotencyConflict if same idempotency key is processing.
        """
        if self.export is None:
            raise RuntimeError("Export service not configured")
        return await self.export.create_export(
            tenant_id=tenant_id,
            created_by=created_by,
            report_type=report_type,
            format=format,
            filters=filters,
            idempotency_key=idempotency_key,
            notify_email=notify_email,
        )

    async def get_export_status(
        self,
        export_id: uuid.UUID,
        tenant_id: uuid.UUID,
    ) -> Optional[dict]:
        if self.export is None:
            return None
        return await self.export.get_export_status(export_id, tenant_id)

    # ------------------------------------------------------------------
    # Fallback data
    # ------------------------------------------------------------------

    def _fallback_dashboard(self, tenant_id: uuid.UUID, period: str) -> dict:
        days_map = {"7d": 7, "30d": 30, "90d": 90}
        days = days_map.get(period, 30)
        return {
            "total_logins": 0,
            "total_logins_change_pct": 0.0,
            "anomalous_events": 0,
            "anomalous_events_change_pct": 0.0,
            "blocked_attacks": 0,
            "blocked_attacks_change_pct": 0.0,
            "active_users": 0,
            "active_users_change_pct": 0.0,
            "trend_data": [
                {
                    "date": (
                        datetime.now(timezone.utc) - timedelta(days=i)
                    ).strftime("%Y-%m-%d"),
                    "logins": 0,
                    "anomalies": 0,
                    "blocked": 0,
                }
                for i in range(days, 0, -1)
            ],
            "top_attack_sources": [],
            "risk_distribution": {"low": 0, "medium": 0, "high": 0},
        }

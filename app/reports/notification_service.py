"""
Reports Module - Notification Service
Phase 2-8: 安全报表/用户画像

Handles alert notifications:
  - High-risk user detection → role audit notification
  - Anomaly detected → email/SMS alert to user or admin
  - Export completed → email notification

Currently a simulated implementation (logs to structlog).
In production, integrate real providers:
  - Email: SendGrid, AWS SES, SMTP
  - SMS: Twilio, AWS SNS
  - Webhook: custom HTTP POST to configured endpoints
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Optional

import structlog

logger = structlog.get_logger()


class NotificationType:
    EMAIL = "email"
    SMS = "sms"
    WEBHOOK = "webhook"


class NotificationService:
    """
    Alert notification service.

    In dev/test: logs notifications via structlog.
    In production: swap _send_email / _send_sms / _send_webhook
    with real provider implementations.

    Supported notification types:
      - anomaly_alert       : User login anomaly detected
      - high_risk_user      : User risk level elevated to 'high'
      - export_completed    : Report export finished
      - role_change_audit   : Permission变更告警通知管理员
    """

    def __init__(
        self,
        redis=None,
        smtp_config: Optional[dict] = None,
        twilio_config: Optional[dict] = None,
        webhook_config: Optional[dict] = None,
    ):
        self.redis = redis
        self.smtp = smtp_config or {}
        self.twilio = twilio_config or {}
        self.webhook = webhook_config or {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def notify_anomaly_alert(
        self,
        user_id: uuid.UUID,
        user_email: str,
        anomaly_type: str,
        description: str,
        risk_level: str,
        risk_score: int,
        ip_address: Optional[str] = None,
        geo_location: Optional[str] = None,
    ):
        """
        Send anomaly alert to user (or admin if user_email not available).
        Simulates email/SMS delivery.
        """
        subject = f"[AuthMaster 安全提醒] 检测到异常登录 - {anomaly_type}"
        body = self._build_anomaly_email_body(
            user_email, anomaly_type, description,
            risk_level, risk_score, ip_address, geo_location,
        )
        await self._notify(
            notify_type=NotificationType.EMAIL,
            to=user_email,
            subject=subject,
            body=body,
            metadata={
                "user_id": str(user_id),
                "anomaly_type": anomaly_type,
                "risk_level": risk_level,
                "risk_score": risk_score,
            },
        )
        logger.warning(
            "anomaly_alert_sent",
            user_id=str(user_id),
            user_email=user_email,
            anomaly_type=anomaly_type,
            risk_level=risk_level,
        )

    async def notify_high_risk_user(
        self,
        user_id: uuid.UUID,
        user_email: str,
        risk_level: str,
        risk_score: int,
        notify_to: str,
        notify_type: str = NotificationType.EMAIL,
    ):
        """
        Notify admin when a user's risk level becomes 'high'.
        Triggers role audit review.
        """
        subject = f"[AuthMaster 高风险用户告警] 用户 {user_email} 风险等级: {risk_level}"
        body = self._build_high_risk_body(user_email, risk_level, risk_score)
        await self._notify(
            notify_type=notify_type,
            to=notify_to,
            subject=subject,
            body=body,
            metadata={
                "user_id": str(user_id),
                "user_email": user_email,
                "risk_level": risk_level,
                "risk_score": risk_score,
                "alert_type": "high_risk_user",
            },
        )
        logger.warning(
            "high_risk_user_alert_sent",
            user_id=str(user_id),
            user_email=user_email,
            risk_level=risk_level,
            notify_to=notify_to,
        )

    async def notify_export_completed(
        self,
        email: str,
        export_id: uuid.UUID,
        report_type: str,
        download_url: Optional[str] = None,
    ):
        """Notify user when their export is ready for download."""
        subject = f"[AuthMaster 报表导出完成] {report_type}"
        body = self._build_export_body(report_type, download_url)
        await self._notify(
            notify_type=NotificationType.EMAIL,
            to=email,
            subject=subject,
            body=body,
            metadata={
                "export_id": str(export_id),
                "report_type": report_type,
            },
        )

    async def notify_role_change_audit(
        self,
        admin_email: str,
        user_id: uuid.UUID,
        user_email: str,
        change_type: str,
        change_detail: str,
    ):
        """
        Notify administrators when a role/permission change is detected
        for a high-risk user (role escalation monitoring).
        """
        subject = f"[AuthMaster 权限变更审计] 用户 {user_email} 角色变更"
        body = self._build_role_change_body(
            user_email, change_type, change_detail,
        )
        await self._notify(
            notify_type=NotificationType.EMAIL,
            to=admin_email,
            subject=subject,
            body=body,
            metadata={
                "user_id": str(user_id),
                "change_type": change_type,
                "alert_type": "role_change_audit",
            },
        )

    # ------------------------------------------------------------------
    # Internal dispatch
    # ------------------------------------------------------------------

    async def _notify(
        self,
        notify_type: str,
        to: str,
        subject: str,
        body: str,
        metadata: Optional[dict] = None,
    ):
        """
        Dispatch notification via configured channel.
        Currently: simulated (logged). Replace with real send_* methods.
        """
        if notify_type == NotificationType.EMAIL:
            await self._send_email(to, subject, body, metadata)
        elif notify_type == NotificationType.SMS:
            await self._send_sms(to, body, metadata)
        elif notify_type == NotificationType.WEBHOOK:
            await self._send_webhook(to, body, metadata)
        else:
            logger.debug("unknown_notify_type", notify_type=notify_type)

    async def _send_email(
        self,
        to: str,
        subject: str,
        body: str,
        metadata: Optional[dict] = None,
    ):
        """
        Send email. Simulated in dev; production integrate SMTP/SendGrid/SES.
        """
        if self.smtp.get("enabled"):
            # Real SMTP send
            pass
        logger.info(
            "notification_email_simulated",
            to=to,
            subject=subject,
            body_preview=body[:100],
            metadata=metadata,
        )

    async def _send_sms(
        self,
        to: str,
        body: str,
        metadata: Optional[dict] = None,
    ):
        """
        Send SMS. Simulated in dev; production integrate Twilio/AWS SNS.
        """
        if self.twilio.get("enabled"):
            # Real Twilio send
            pass
        logger.info(
            "notification_sms_simulated",
            to=to,
            body_preview=body[:100],
            metadata=metadata,
        )

    async def _send_webhook(
        self,
        url: str,
        body: str,
        metadata: Optional[dict] = None,
    ):
        """
        Send webhook POST. Simulated in dev; production integrate HTTP client.
        """
        logger.info(
            "notification_webhook_simulated",
            url=url,
            body_preview=body[:100],
            metadata=metadata,
        )

    # ------------------------------------------------------------------
    # Template builders
    # ------------------------------------------------------------------

    @staticmethod
    def _build_anomaly_email_body(
        user_email: str,
        anomaly_type: str,
        description: str,
        risk_level: str,
        risk_score: int,
        ip_address: Optional[str],
        geo_location: Optional[str],
    ) -> str:
        anomaly_type_labels = {
            "geo_anomaly": "异地登录",
            "time_anomaly": "异常时间登录",
            "new_device": "新设备登录",
            "bruteforce": "暴力破解",
            "impossible_travel": "不可能的旅行",
        }
        label = anomaly_type_labels.get(anomaly_type, anomaly_type)
        location_str = f"登录地点: {geo_location}" if geo_location else ""
        ip_str = f"IP: {ip_address}" if ip_address else ""
        return f"""
AuthMaster 安全提醒

尊敬的用户您好，

我们检测到您的账号 {user_email} 存在异常登录行为：

异常类型：{label}
风险等级：{risk_level.upper()}（风险评分: {risk_score}/100）
描述：{description}
{location_str}
{ip_str}
时间：{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}

如果这不是您本人的操作，请立即前往 AuthMaster 安全中心修改密码并确认设备安全。

此致，
AuthMaster 安全团队
"""

    @staticmethod
    def _build_high_risk_body(
        user_email: str,
        risk_level: str,
        risk_score: int,
    ) -> str:
        return f"""
[AuthMaster 高风险用户告警]

用户 {user_email} 的风险等级已提升至：{risk_level.upper()}
风险评分：{risk_score}/100

建议立即审查该用户的最近登录活动，并确认是否存在账号被盗或恶意行为。

---
此邮件由 AuthMaster 自动发送
"""

    @staticmethod
    def _build_export_body(
        report_type: str,
        download_url: Optional[str],
    ) -> str:
        url_str = f"\n下载链接：{download_url}\n（链接7天内有效）" if download_url else ""
        return f"""
[AuthMaster 报表导出完成]

报表类型：{report_type}
完成时间：{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}
{url_str}

如有任何问题，请联系 AuthMaster 支持团队。

---
此邮件由 AuthMaster 自动发送
"""

    @staticmethod
    def _build_role_change_body(
        user_email: str,
        change_type: str,
        change_detail: str,
    ) -> str:
        return f"""
[AuthMaster 权限变更审计]

用户：{user_email}
变更类型：{change_type}
变更详情：{change_detail}
时间：{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}

请确认此变更是否经授权。如有疑问，请立即联系安全团队。

---
此邮件由 AuthMaster 自动发送
"""

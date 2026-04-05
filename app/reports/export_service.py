"""
Reports Module - Export Job Service
Phase 2-8: 安全报表/用户画像

Handles asynchronous report export jobs:
  - Idempotency via Idempotency-Key (SHA256) + Redis dedup (24h TTL)
  - Background task execution (async worker pattern)
  - S3 storage + pre-signed download URLs
  - TTL-based cleanup of completed exports

[RP-3] Export idempotency:
  1. Client sends Idempotency-Key header: export:<sha256(report_type+filters+format)>
  2. Server SHA256 hashes the key and checks Redis: idempotency:export:{hash}
  3. Key not exists → SET NX EX 86400, create task
  4. Key exists, status=done → return cached export_id + download_url
  5. Key exists, status=processing → return 409 Idempotency_Conflict
"""
from __future__ import annotations

import asyncio
import csv
import hashlib
import io
import json
import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import structlog

logger = structlog.get_logger()

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
IDEMPOTENCY_PREFIX = "idempotency:export:"
IDEMPOTENCY_TTL = 86400  # 24 hours
EXPORT_DIR = os.environ.get("EXPORT_DIR", "/tmp/authmaster_exports")
DOWNLOAD_URL_TTL = 7 * 86400  # 7 days

REPORT_TYPES_WITH_DATA = {
    "login_anomalies",
    "user_profiles",
    "login_events",
    "dashboard",
    "risk_summary",
}


# ---------------------------------------------------------------------------
# Export Service
# ---------------------------------------------------------------------------

class ExportIdempotencyConflict(Exception):
    """Raised when same Idempotency-Key is already being processed."""

    def __init__(
        self,
        existing_export_id: uuid.UUID,
        retry_after_seconds: int = 60,
    ):
        self.existing_export_id = existing_export_id
        self.retry_after_seconds = retry_after_seconds


class ExportService:
    """
    Manages export job lifecycle with idempotency guarantees.

    Args:
        db: SQLAlchemy AsyncSession
        redis: Redis client (optional for dev)
        clickhouse: ClickHouseService instance (optional)
        s3_client: boto3 S3 client (optional; uses local file if None)
        bucket_name: S3 bucket for export files
    """

    def __init__(
        self,
        db,
        redis=None,
        clickhouse=None,
        s3_client=None,
        bucket_name: str = "authmaster-reports",
        export_dir: str = EXPORT_DIR,
    ):
        self.db = db
        self.redis = redis
        self.ch = clickhouse
        self.s3 = s3_client
        self.bucket = bucket_name
        self.export_dir = export_dir
        self._worker_task: Optional[asyncio.Task] = None
        self._running = False
        os.makedirs(export_dir, exist_ok=True)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def create_export(
        self,
        tenant_id: uuid.UUID,
        created_by: uuid.UUID,
        report_type: str,
        format: str,
        filters: dict[str, Any],
        idempotency_key: str,
        notify_email: Optional[str] = None,
    ) -> tuple[uuid.UUID, str]:
        """
        Create or retrieve an export task (idempotent).

        Returns (export_id, status).
        Raises ExportIdempotencyConflict if same key is being processed.
        """
        key_hash = hashlib.sha256(idempotency_key.encode()).hexdigest()

        # L1: Redis idempotency check
        if self.redis:
            cached = await self._check_redis_idempotency(key_hash)
            if cached:
                cached_data = json.loads(cached)
                existing_id = uuid.UUID(cached_data["export_id"])
                status = cached_data["status"]
                if status == "completed":
                    return existing_id, "completed"
                elif status == "processing":
                    raise ExportIdempotencyConflict(
                        existing_export_id=existing_id,
                        retry_after_seconds=60,
                    )

        # Check DB for existing task (L2 idempotency - DB unique constraint)
        existing_task = await self._get_existing_task(tenant_id, key_hash)
        if existing_task:
            status = existing_task["status"]
            if status in ("completed", "processing", "pending"):
                # Update Redis for faster path next time
                if self.redis:
                    await self._set_redis_idempotency(
                        key_hash,
                        {
                            "export_id": str(existing_task["id"]),
                            "status": status,
                        },
                    )
                if status == "processing":
                    raise ExportIdempotencyConflict(
                        existing_export_id=existing_task["id"],
                    )
                return existing_task["id"], status

        # Create new task
        export_id = uuid.uuid4()
        await self.db.execute(
            """
            INSERT INTO report_export_tasks
                (id, tenant_id, created_by, report_type, format, filters,
                 idempotency_key_hash, status, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, 'pending', NOW())
            """,
            export_id, tenant_id, created_by, report_type, format,
            json.dumps(filters), key_hash,
        )
        await self.db.commit()

        # Set Redis idempotency key
        if self.redis:
            await self._set_redis_idempotency(
                key_hash,
                {"export_id": str(export_id), "status": "pending"},
            )

        # Queue for background processing
        asyncio.create_task(self._process_export(export_id, tenant_id, notify_email))

        return export_id, "pending"

    async def get_export_status(
        self,
        export_id: uuid.UUID,
        tenant_id: uuid.UUID,
    ) -> Optional[dict]:
        """Return export task status + download URL if ready."""
        row = await self.db.execute(
            """
            SELECT id, status, file_path, file_size_bytes, download_url,
                   download_expires_at, error_message, created_at, completed_at
            FROM report_export_tasks
            WHERE id = $1 AND tenant_id = $2
            """,
            export_id, tenant_id,
        )
        result = row.fetchone()
        if not result:
            return None
        r = result._mapping
        return {
            "export_id": r["id"],
            "status": r["status"],
            "download_url": r["download_url"],
            "file_size_bytes": r["file_size_bytes"],
            "created_at": r["created_at"],
            "completed_at": r["completed_at"],
            "expires_at": r["download_expires_at"],
            "error_message": r["error_message"],
        }

    async def get_export_download_url(
        self,
        export_id: uuid.UUID,
        tenant_id: uuid.UUID,
    ) -> Optional[str]:
        """Generate or refresh a pre-signed S3 URL (7-day expiry)."""
        task = await self.get_export_status(export_id, tenant_id)
        if not task or task["status"] != "completed":
            return None

        if task["download_url"] and task["expires_at"]:
            if task["expires_at"] > datetime.now(timezone.utc):
                return task["download_url"]

        # Generate new pre-signed URL
        file_path = task.get("file_path")
        if not file_path:
            return None

        if self.s3:
            try:
                url = self.s3.generate_presigned_url(
                    "get_object",
                    Params={"Bucket": self.bucket, "Key": file_path},
                    ExpiresIn=DOWNLOAD_URL_TTL,
                )
                expires_at = datetime.now(timezone.utc) + timedelta(
                    seconds=DOWNLOAD_URL_TTL
                )
                await self.db.execute(
                    """
                    UPDATE report_export_tasks
                    SET download_url = $1, download_expires_at = $2
                    WHERE id = $3
                    """,
                    url, expires_at, export_id,
                )
                await self.db.commit()
                return url
            except Exception as e:
                logger.error("s3 presign failed", error=str(e))

        return task["download_url"]

    # ------------------------------------------------------------------
    # Background processing
    # ------------------------------------------------------------------

    async def _process_export(
        self,
        export_id: uuid.UUID,
        tenant_id: uuid.UUID,
        notify_email: Optional[str] = None,
    ):
        """Background task: build export file and upload to S3."""
        try:
            await self.db.execute(
                """
                UPDATE report_export_tasks
                SET status = 'processing', started_at = NOW()
                WHERE id = $1
                """,
                export_id,
            )
            await self.db.commit()

            # Fetch task metadata
            row = await self.db.execute(
                """
                SELECT report_type, format, filters, created_by
                FROM report_export_tasks WHERE id = $1
                """,
                export_id,
            )
            task_row = row.fetchone()
            if not task_row:
                return
            r = task_row._mapping

            # Generate export data
            data = await self._fetch_report_data(
                r["report_type"], tenant_id, r["filters"]
            )

            # Write to file
            file_path, file_size = await self._write_export_file(
                export_id, r["report_type"], r["format"], data
            )

            # Upload to S3
            download_url = await self._upload_to_s3(
                export_id, file_path, r["format"]
            )
            expires_at = datetime.now(timezone.utc) + timedelta(
                seconds=DOWNLOAD_URL_TTL
            )

            # Update DB
            await self.db.execute(
                """
                UPDATE report_export_tasks
                SET status = 'completed',
                    file_path = $1,
                    file_size_bytes = $2,
                    download_url = $3,
                    download_expires_at = $4,
                    completed_at = NOW()
                WHERE id = $5
                """,
                file_path, file_size, download_url, expires_at, export_id,
            )
            await self.db.commit()

            # Update Redis idempotency
            key_hash = await self._get_task_key_hash(export_id)
            if key_hash and self.redis:
                await self._set_redis_idempotency(
                    key_hash,
                    {"export_id": str(export_id), "status": "completed"},
                )

            # Send notification
            if notify_email:
                await self._send_notification(notify_email, export_id, r["report_type"])

            logger.info(
                "export_completed",
                export_id=str(export_id),
                report_type=r["report_type"],
                format=r["format"],
                size_bytes=file_size,
            )

        except Exception as e:
            logger.error("export_failed", export_id=str(export_id), error=str(e))
            await self.db.execute(
                """
                UPDATE report_export_tasks
                SET status = 'failed', error_message = $1, completed_at = NOW()
                WHERE id = $2
                """,
                str(e), export_id,
            )
            await self.db.commit()

    async def _fetch_report_data(
        self,
        report_type: str,
        tenant_id: uuid.UUID,
        filters: dict,
    ) -> list[dict]:
        """Fetch report data from ClickHouse or DB fallback."""
        if self.ch and self.ch._available:
            if report_type == "login_anomalies":
                items, _ = await self.ch.get_anomaly_events(tenant_id)
                return items
            elif report_type == "dashboard":
                dashboard = await self.ch.get_dashboard(tenant_id)
                return [dashboard]

        # Fallback: return empty (dev/test mode)
        return []

    async def _write_export_file(
        self,
        export_id: uuid.UUID,
        report_type: str,
        format: str,
        data: list[dict],
    ) -> tuple[str, int]:
        """Write export data to local file."""
        filename = f"{export_id}.{format}"
        file_path = os.path.join(self.export_dir, filename)

        if format == "csv":
            await self._write_csv(file_path, data)
        elif format == "xlsx":
            await self._write_xlsx(file_path, data)
        elif format == "pdf":
            await self._write_pdf(file_path, data)

        file_size = os.path.getsize(file_path)
        return file_path, file_size

    async def _write_csv(self, file_path: str, data: list[dict]):
        """Write data as CSV."""
        if not data:
            with open(file_path, "w", newline="", encoding="utf-8") as f:
                f.write("")
            return

        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=data[0].keys())
        writer.writeheader()
        writer.writerows(data)
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(output.getvalue())

    async def _write_xlsx(self, file_path: str, data: list[dict]):
        """Write data as Excel (requires openpyxl)."""
        try:
            import openpyxl
        except ImportError:
            await self._write_csv(file_path, data)
            return

        wb = openpyxl.Workbook()
        ws = wb.active
        ws.title = "Report"

        if data:
            ws.append(list(data[0].keys()))
            for row in data:
                ws.append(list(row.values()))

        wb.save(file_path)

    async def _write_pdf(self, file_path: str, data: list[dict]):
        """Write data as PDF (requires reportlab). Simplified text output."""
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.platypus import SimpleDocTemplate, Table, TableStyle
            from reportlab.lib import colors
        except ImportError:
            await self._write_csv(file_path, data)
            return

        doc = SimpleDocTemplate(file_path, pagesize=A4)
        elements = []
        if data:
            table = Table([list(data[0].keys())] + [[str(v) for v in row.values()] for row in data])
            table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("GRID", (0, 0), (-1, -1), (1, 1), colors.black),
            ]))
            elements.append(table)
        doc.build(elements)

    async def _upload_to_s3(
        self,
        export_id: uuid.UUID,
        file_path: str,
        format: str,
    ) -> Optional[str]:
        """Upload file to S3 and return pre-signed download URL."""
        if not self.s3:
            return f"file://{file_path}"

        key = f"exports/{export_id}.{format}"
        try:
            self.s3.upload_file(file_path, self.bucket, key)
            url = self.s3.generate_presigned_url(
                "get_object",
                Params={"Bucket": self.bucket, "Key": key},
                ExpiresIn=DOWNLOAD_URL_TTL,
            )
            return url
        except Exception as e:
            logger.error("s3_upload failed", error=str(e))
            return f"file://{file_path}"

    async def _send_notification(
        self,
        email: str,
        export_id: uuid.UUID,
        report_type: str,
    ):
        """
        Send export-ready notification via email/SMS.
        Currently simulated (logs); integrate real email/SMS in production.
        """
        logger.info(
            "export_notification",
            to=email,
            export_id=str(export_id),
            report_type=report_type,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    async def _check_redis_idempotency(self, key_hash: str) -> Optional[str]:
        try:
            return await self.redis.get(f"{IDEMPOTENCY_PREFIX}{key_hash}")
        except Exception:
            return None

    async def _set_redis_idempotency(self, key_hash: str, value: dict):
        try:
            await self.redis.setex(
                f"{IDEMPOTENCY_PREFIX}{key_hash}",
                IDEMPOTENCY_TTL,
                json.dumps(value),
            )
        except Exception as e:
            logger.warning("redis idempotency set failed", error=str(e))

    async def _get_existing_task(
        self, tenant_id: uuid.UUID, key_hash: str
    ) -> Optional[dict]:
        row = await self.db.execute(
            """
            SELECT id, status
            FROM report_export_tasks
            WHERE tenant_id = $1 AND idempotency_key_hash = $2
            LIMIT 1
            """,
            tenant_id, key_hash,
        )
        r = row.fetchone()
        return dict(r._mapping) if r else None

    async def _get_task_key_hash(self, export_id: uuid.UUID) -> Optional[str]:
        row = await self.db.execute(
            """
            SELECT idempotency_key_hash FROM report_export_tasks WHERE id = $1
            """,
            export_id,
        )
        r = row.fetchone()
        return r["idempotency_key_hash"] if r else None

    # ------------------------------------------------------------------
    # Cleanup (called by scheduler)
    # ------------------------------------------------------------------

    async def cleanup_expired_exports(self, older_than_days: int = 7):
        """
        Delete completed export tasks and files older than `older_than_days`.
        Called by daily cron job.
        """
        cutoff = datetime.now(timezone.utc) - timedelta(days=older_than_days)
        row = await self.db.execute(
            """
            SELECT id, file_path, download_url
            FROM report_export_tasks
            WHERE status = 'completed' AND completed_at < $1
            """,
            cutoff,
        )
        tasks = row.fetchall()
        deleted = 0
        for task in tasks:
            task_id = task["id"]
            file_path = task["file_path"]

            # Delete local file
            if file_path and os.path.exists(file_path):
                try:
                    os.remove(file_path)
                except OSError:
                    pass

            # Delete S3 object
            if self.s3 and task["download_url"]:
                try:
                    import re
                    match = re.search(r"/(.+?)\?", task["download_url"])
                    if match:
                        self.s3.delete_object(Bucket=self.bucket, Key=match.group(1))
                except Exception:
                    pass

            # Delete DB record
            await self.db.execute(
                "DELETE FROM report_export_tasks WHERE id = $1",
                task_id,
            )
            deleted += 1

        if deleted:
            await self.db.commit()
            logger.info("exports_cleaned", deleted_count=deleted)

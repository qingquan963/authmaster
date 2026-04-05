"""
Reports Module - Security Reports & User Profile
Phase 2-8: 安全报表/用户画像

Core capabilities:
  - Security dashboard (login stats, anomalies, blocked attacks)
  - Login anomaly detection (geo/time/device/bruteforce)
  - User behavior profile (login activity, device, location, time patterns)
  - Anomaly rule engine (configurable thresholds)
  - Report export (CSV/Excel/PDF) with idempotency
  - ClickHouse OLAP storage for analytics
  - Prometheus metrics for monitoring
  - Email/SMS notification integration

Key design decisions:
  [RP-1]  Data pipeline: CDC → Kafka → ClickHouse Sink (< 10s latency)
  [RP-2]  Backup/Recovery: S3 + clickhouse-backup + PITR
  [RP-3]  Export idempotency: Idempotency-Key (SHA256) + Redis dedup 24h
  [RP-4]  Monitoring: clickhouse_query_duration_seconds, clickhouse_lag_seconds,
           export_queue_size metrics + Alertmanager rules
"""
from __future__ import annotations

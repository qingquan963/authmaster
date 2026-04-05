-- AuthMaster Phase 2-8: 安全报表/用户画像
-- Migration: PostgreSQL tables + ClickHouse DDL reference
-- ============================================================

-- ============================================================
-- PostgreSQL Tables
-- ============================================================

-- 导出任务表（含幂等Key哈希唯一约束）
CREATE TABLE IF NOT EXISTS report_export_tasks (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id               UUID NOT NULL REFERENCES auth_tenants(id),
    created_by              UUID NOT NULL REFERENCES auth_users(id),
    report_type             VARCHAR(32) NOT NULL,
    format                  VARCHAR(8) NOT NULL
        CHECK (format IN ('csv', 'xlsx', 'pdf')),
    filters                 JSONB NOT NULL DEFAULT '{}',
    idempotency_key_hash    VARCHAR(64) NOT NULL,
    status                  VARCHAR(16) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'processing', 'completed', 'failed')),
    file_path               TEXT,
    file_size_bytes         BIGINT,
    download_url            TEXT,
    download_expires_at     TIMESTAMPTZ,
    error_message           TEXT,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at              TIMESTAMPTZ,
    completed_at            TIMESTAMPTZ,

    CONSTRAINT uq_export_idem_key UNIQUE (tenant_id, idempotency_key_hash)
);

CREATE INDEX IF NOT EXISTS idx_export_tasks_tenant
    ON report_export_tasks(tenant_id, status, created_at DESC);


-- 可配置异常检测规则表
CREATE TABLE IF NOT EXISTS anomaly_rules (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID REFERENCES auth_tenants(id),
    rule_name           VARCHAR(64) NOT NULL UNIQUE,
    anomaly_type        VARCHAR(32) NOT NULL
        CHECK (anomaly_type IN (
            'geo_anomaly', 'time_anomaly', 'new_device',
            'bruteforce', 'impossible_travel'
        )),
    score_increment     INTEGER NOT NULL DEFAULT 0,
    is_blocking         BOOLEAN NOT NULL DEFAULT FALSE,
    threshold_value     NUMERIC(10, 2),
    threshold_unit      VARCHAR(16),
    enabled             BOOLEAN NOT NULL DEFAULT TRUE,
    priority           INTEGER NOT NULL DEFAULT 100,
    description         TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_anomaly_rules_enabled
    ON anomaly_rules(enabled, priority);


-- 异常事件记录表
CREATE TABLE IF NOT EXISTS anomaly_events (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL REFERENCES auth_tenants(id),
    user_id             UUID NOT NULL REFERENCES auth_users(id),
    event_id            UUID NOT NULL,
    anomaly_type        VARCHAR(32) NOT NULL,
    description         TEXT NOT NULL,
    risk_score          INTEGER NOT NULL DEFAULT 0,
    risk_level           VARCHAR(8) NOT NULL DEFAULT 'low'
        CHECK (risk_level IN ('low', 'medium', 'high')),
    ip_address          VARCHAR(45),
    geo_country         VARCHAR(8),
    geo_city            VARCHAR(64),
    user_agent          TEXT,
    device_fp_hash      VARCHAR(64),
    extra_data          JSONB,
    status              VARCHAR(16) NOT NULL DEFAULT 'pending_review'
        CHECK (status IN ('pending_review', 'reviewed', 'false_positive', 'confirmed')),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reviewed_by         UUID REFERENCES auth_users(id),
    reviewed_at         TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_anomaly_events_user
    ON anomaly_events(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_anomaly_events_tenant_status
    ON anomaly_events(tenant_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_anomaly_events_type
    ON anomaly_events(anomaly_type, created_at DESC);


-- ============================================================
-- Default Anomaly Rules Seed Data
-- ============================================================

INSERT INTO anomaly_rules
    (rule_name, anomaly_type, score_increment, is_blocking, threshold_value, threshold_unit, enabled, priority, description)
VALUES
    ('geo_anomaly', 'geo_anomaly', 40, FALSE, NULL, NULL, TRUE, 10,
     '登录城市不在用户常用城市列表'),
    ('time_anomaly', 'time_anomaly', 25, FALSE, 3.0, 'hours', TRUE, 20,
     '登录时间不在用户常用时段 ±3h 窗口内'),
    ('new_device', 'new_device', 20, FALSE, NULL, NULL, TRUE, 30,
     '设备指纹不在信任设备列表'),
    ('bruteforce', 'bruteforce', 60, TRUE, 10.0, 'failures_per_5min', TRUE, 1,
     '同一IP 5分钟内登录失败 ≥10 次'),
    ('impossible_travel', 'impossible_travel', 70, FALSE, 800.0, 'km_per_hour', TRUE, 5,
     '两次登录地点距离÷时间差 > 800km/h')
ON CONFLICT (rule_name) DO NOTHING;


-- ============================================================
-- ClickHouse DDL (Reference)
-- ============================================================
-- Run these commands directly on ClickHouse server or via clickhouse-client.
-- Note: ClickHouse is optional in dev/test; these are documented DDL only.
--
-- CREATE DATABASE IF NOT EXISTS authmaster;
--
-- CREATE TABLE IF NOT EXISTS authmaster.login_events_olap (
--     event_id          UUID,
--     tenant_id         UUID,
--     user_id           UUID,
--     user_email        VARCHAR(255),
--     status            VARCHAR(16),
--     login_method      VARCHAR(32),
--     ip_address        INET,
--     geo_country       VARCHAR(8),
--     geo_city          VARCHAR(64),
--     geo_latitude      DECIMAL(9,6),
--     geo_longitude     DECIMAL(9,6),
--     user_agent        TEXT,
--     device_fp_hash    VARCHAR(64),
--     risk_score        INTEGER,
--     risk_level        VARCHAR(8),
--     mfa_used          BOOLEAN,
--     login_hour        SMALLINT,
--     login_weekday     VARCHAR(12),
--     is_anomalous      BOOLEAN,
--     anomaly_types     ARRAY[VARCHAR(32)],
--     created_at        TIMESTAMPTZ
-- ) ENGINE = MergeTree()
-- PARTITION BY (toYYYYMM(created_at))
-- ORDER BY (tenant_id, user_id, created_at)
-- TTL created_at + INTERVAL 90 DAY;
--
-- CREATE MATERIALIZED VIEW IF NOT EXISTS authmaster.user_behavior_profile
-- ENGINE = SummingMergeTree()
-- ORDER BY (user_id, tenant_id)
-- AS SELECT
--     user_id,
--     tenant_id,
--     COUNT(*) FILTER (WHERE status = 'success' AND created_at > NOW() - INTERVAL '7 days') AS logins_7d,
--     COUNT(*) FILTER (WHERE status = 'success' AND created_at > NOW() - INTERVAL '30 days') AS logins_30d,
--     COUNT(DISTINCT device_fp_hash) FILTER (WHERE created_at > NOW() - INTERVAL '30 days') AS devices_30d,
--     COUNT(DISTINCT geo_city) FILTER (WHERE status = 'success' AND created_at > NOW() - INTERVAL '30 days') AS cities_30d,
--     AVG(risk_score) FILTER (WHERE created_at > NOW() - INTERVAL '30 days') AS avg_risk_score_30d,
--     MAX(risk_score) FILTER (WHERE created_at > NOW() - INTERVAL '30 days') AS max_risk_score_30d,
--     COUNT(*) FILTER (WHERE is_anomalous = TRUE AND created_at > NOW() - INTERVAL '30 days') AS anomaly_count_30d
-- FROM authmaster.login_events_olap
-- GROUP BY user_id, tenant_id;


-- ============================================================
-- Backup/Restore Commands Reference (for S3)
-- ============================================================
--
-- # Full backup to S3 (run as cron: daily 03:00 UTC)
-- clickhouse-backup create --s3-storage \
--   --name "authmaster-reports-$(date +%Y%m%d)" \
--   --tables "authmaster.login_events_olap" \
--   --compression "gzip"
--
-- # Restore from S3
-- clickhouse-backup restore --s3-storage \
--   --name "authmaster-reports-20260401" \
--   --tables "authmaster.login_events_olap"
--
-- # SQL BACKUP/RESTORE (ClickHouse 22.8+)
-- BACKUP TABLE authmaster.login_events_olap
-- TO S3('s3://authmaster-backups/clickhouse/{backup_name}/')
-- SETTINGS compression='gzip';
--
-- RESTORE TABLE authmaster.login_events_olap
-- FROM S3('s3://authmaster-backups/clickhouse/authmaster-reports-20260401/')
-- SETTINGS structure_only=false;

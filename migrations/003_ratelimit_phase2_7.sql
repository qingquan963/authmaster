-- Migration: 003_ratelimit_phase2_7
-- Phase 2-7: 百万级 QOS 高并发架构
-- Description: Creates rate_limit_rules table for configurable rate limiting
-- Created: 2026-04-05

BEGIN;

-- ---------------------------------------------------------------------------
-- Rate Limit Rules Table
-- ---------------------------------------------------------------------------
-- Stores configurable rate limit rules per endpoint/tenant.
-- Rules are loaded into memory on startup and refreshed periodically.
--
-- Reference: see design doc Phase 2-7 Section 4.4

CREATE TABLE IF NOT EXISTS rate_limit_rules (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID REFERENCES auth_tenants(id) ON DELETE CASCADE,
    -- URL pattern, supports * wildcard (e.g., "/api/v1/auth/login", "/api/v1/sdk/*")
    endpoint_pattern    VARCHAR(128) NOT NULL,
    -- How to extract the rate limit key: ip | user | api_key | tenant | global
    key_type            VARCHAR(16) NOT NULL DEFAULT 'ip',
    -- Max requests allowed per window
    rate                INTEGER NOT NULL,
    -- Window size in seconds
    window              INTEGER NOT NULL,
    -- Burst capacity for token bucket (optional, defaults to rate * 2)
    burst               INTEGER,
    -- Whether this rule is active
    enabled             BOOLEAN NOT NULL DEFAULT TRUE,
    -- Priority for rule matching (higher = first)
    priority            INTEGER NOT NULL DEFAULT 0,
    -- Extra config as JSONB (e.g., {"strategy": "sliding_window", "bypass_local": false})
    extra_config        JSONB DEFAULT '{}',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Unique: one active rule per (tenant, endpoint, key_type)
    CONSTRAINT uq_ratelimit_tenant_endpoint_keytype
        UNIQUE (tenant_id, endpoint_pattern, key_type),
    -- Rate and window must be positive
    CONSTRAINT ck_rate_positive CHECK (rate > 0),
    CONSTRAINT ck_window_positive CHECK (window > 0),
    CONSTRAINT ck_key_type CHECK (key_type IN ('ip', 'user', 'api_key', 'tenant', 'global'))
);

-- Index for fast pattern matching (sorted by priority descending)
CREATE INDEX IF NOT EXISTS idx_ratelimit_pattern_priority
    ON rate_limit_rules(endpoint_pattern, priority DESC);

-- Index for enabled filter
CREATE INDEX IF NOT EXISTS idx_ratelimit_enabled
    ON rate_limit_rules(enabled) WHERE enabled = TRUE;

COMMENT ON TABLE rate_limit_rules IS
    'Configurable rate limit rules for QOS high concurrency (Phase 2-7)';
COMMENT ON COLUMN rate_limit_rules.endpoint_pattern IS
    'URL pattern with wildcard support: /api/v1/auth/login or /api/v1/sdk/* or /api/**';
COMMENT ON COLUMN rate_limit_rules.key_type IS
    'Rate limit key type: ip (client IP), user (authenticated user ID), api_key (API key), tenant (tenant ID), global (no key)';
COMMENT ON COLUMN rate_limit_rules.burst IS
    'Token bucket burst capacity. If NULL, defaults to rate * 2';
COMMENT ON COLUMN rate_limit_rules.priority IS
    'Higher priority rules match first. Rules with same priority: most specific pattern wins';

-- ---------------------------------------------------------------------------
-- Default Rate Limit Rules
-- ---------------------------------------------------------------------------
-- Pre-configured rules for common endpoints

INSERT INTO rate_limit_rules (endpoint_pattern, key_type, rate, window, burst, priority, extra_config) VALUES
    -- Login endpoint: 5 attempts per minute per IP (strict)
    ('/api/v1/auth/login', 'ip', 5, 60, 10, 100,
     '{"strategy": "sliding_window", "description": "Login attempts per IP"}'),

    -- Login endpoint: 10 attempts per minute per user (if authenticated)
    ('/api/v1/auth/login', 'user', 10, 60, 20, 90,
     '{"strategy": "sliding_window", "description": "Login attempts per user"}'),

    -- Token verification: 30 per minute per IP (moderate)
    ('/api/v1/auth/verify', 'ip', 30, 60, 50, 80,
     '{"strategy": "sliding_window", "description": "Token verify per IP"}'),

    -- SDK endpoints: 100 per second per API key (high throughput)
    ('/api/v1/sdk/*', 'api_key', 100, 1, 200, 70,
     '{"strategy": "sliding_window", "description": "SDK API rate limit"}'),

    -- Password reset: 3 per hour per IP (very strict)
    ('/api/v1/auth/password/reset', 'ip', 3, 3600, 5, 95,
     '{"strategy": "sliding_window", "description": "Password reset per IP"}'),

    -- MFA verify: 10 per minute per user (moderate)
    ('/api/v1/auth/mfa/verify', 'user', 10, 60, 20, 85,
     '{"strategy": "sliding_window", "description": "MFA verify per user"}'),

    -- Admin API: 60 per minute per user (authenticated)
    ('/api/v1/admin/*', 'user', 60, 60, 100, 60,
     '{"strategy": "sliding_window", "description": "Admin API per user"}'),

    -- Default: 100 per second global (catch-all)
    ('*', 'global', 100, 1, 200, -1,
     '{"strategy": "sliding_window", "description": "Default global rate limit"}')
ON CONFLICT (tenant_id, endpoint_pattern, key_type) DO NOTHING;

-- ---------------------------------------------------------------------------
-- Trigger: auto-update updated_at
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER update_rate_limit_rules_updated_at
    BEFORE UPDATE ON rate_limit_rules
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

COMMIT;

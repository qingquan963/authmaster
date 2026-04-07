-- Phase 1 Base Tables for AuthMaster
-- These tables are prerequisites for Phase 2 migrations
-- Run this BEFORE Phase 2 migration files

BEGIN;

-- ---------------------------------------------------------------------------
-- 1. auth_tenants (租户表)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS auth_tenants (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        VARCHAR(128) NOT NULL,
    slug        VARCHAR(64) UNIQUE NOT NULL,
    plan        VARCHAR(32) DEFAULT 'free',
    status      VARCHAR(16) DEFAULT 'active',
    settings    JSONB DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ---------------------------------------------------------------------------
-- 2. auth_users (用户表)
-- Phase 2 migrations add: merged_into, merged_at, merge_locked
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS auth_users (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID REFERENCES auth_tenants(id) ON DELETE CASCADE,
    email               VARCHAR(255) NOT NULL,
    phone               VARCHAR(32),
    password_hash       VARCHAR(128),
    status              VARCHAR(16) NOT NULL DEFAULT 'active',
    is_superadmin       BOOLEAN NOT NULL DEFAULT FALSE,
    last_login_at       TIMESTAMPTZ,
    last_login_ip       VARCHAR(64),
    last_login_device   VARCHAR(255),
    failed_login_count  INTEGER NOT NULL DEFAULT 0,
    locked_until       TIMESTAMPTZ,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_auth_users_email ON auth_users(email);
CREATE INDEX IF NOT EXISTS idx_auth_users_tenant ON auth_users(tenant_id);

-- ---------------------------------------------------------------------------
-- 3. auth_sessions (会话表)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS auth_sessions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
    tenant_id       UUID REFERENCES auth_tenants(id) ON DELETE CASCADE,
    refresh_token   VARCHAR(256) UNIQUE,
    ip_address      VARCHAR(64),
    user_agent      VARCHAR(512),
    device_fingerprint VARCHAR(256),
    expires_at      TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_auth_sessions_user ON auth_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_refresh ON auth_sessions(refresh_token);

-- ---------------------------------------------------------------------------
-- 4. auth_roles (角色表)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS auth_roles (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID REFERENCES auth_tenants(id) ON DELETE CASCADE,
    name        VARCHAR(64) NOT NULL,
    description VARCHAR(256),
    permissions JSONB DEFAULT '[]',
    is_system   BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_auth_roles_tenant ON auth_roles(tenant_id);

-- ---------------------------------------------------------------------------
-- 5. api_keys (API Key表)
-- Phase 2-6 SDK需要
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS api_keys (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID REFERENCES auth_tenants(id) ON DELETE CASCADE,
    name        VARCHAR(128) NOT NULL,
    key_hash    VARCHAR(64) UNIQUE NOT NULL,
    secret_hash VARCHAR(64),
    scopes      JSONB DEFAULT '[]',
    rate_limit  INTEGER DEFAULT 1000,
    is_active   BOOLEAN NOT NULL DEFAULT TRUE,
    last_used_at TIMESTAMPTZ,
    expires_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_api_keys_tenant ON api_keys(tenant_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);

COMMIT;

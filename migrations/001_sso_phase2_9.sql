-- Migration: Phase 2-9 SSO 统一登出
-- AuthMaster Phase 2-9
-- [Fix1] Tables: oidc_clients, sp_sessions, logout_outbox, logout_dead_letters
-- [Fix3] FK ON DELETE CASCADE/SET NULL
-- [Fix5] Composite unique constraints for idempotency
-- [Fix6] idx_dl_created for TTL cleanup

BEGIN;

-- ---------------------------------------------------------------------------
-- OIDC Clients
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS oidc_clients (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL REFERENCES auth_tenants(id) ON DELETE CASCADE,
    client_id           VARCHAR(128) NOT NULL UNIQUE,
    client_secret_hash  VARCHAR(64),
    client_name         VARCHAR(256) NOT NULL,
    redirect_uris       JSONB NOT NULL DEFAULT '[]',
    post_logout_uris    JSONB DEFAULT '[]',
    front_channel_uris  JSONB DEFAULT '[]',
    allowed_scopes      JSONB DEFAULT '["openid","profile"]',
    policy              JSONB DEFAULT '{}',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_oidc_clients_tenant ON oidc_clients(tenant_id);

-- ---------------------------------------------------------------------------
-- SP Sessions (OIDC/SAML session mappings)
-- [Fix1] Added: logout_id, logout_status, composite unique constraints
-- [Fix3] FK ON DELETE CASCADE/SET NULL/RESTRICT
-- [Fix5] Composite unique (logout_id, id) replaces single logout_id unique
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sp_sessions (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    idp_session_id      UUID NOT NULL
        REFERENCES auth_sessions(id) ON DELETE CASCADE,
    user_id             UUID NOT NULL
        REFERENCES auth_users(id) ON DELETE CASCADE,
    tenant_id           UUID NOT NULL
        REFERENCES auth_tenants(id) ON DELETE CASCADE,
    client_id           VARCHAR(128) NOT NULL
        REFERENCES oidc_clients(client_id) ON DELETE RESTRICT,
    sp_session_id       VARCHAR(512),
    protocol            VARCHAR(16) NOT NULL
        CHECK (protocol IN ('oidc', 'saml')),
    -- [SSO-9-NOTE1] id_token_hint: OIDC spec recommends ≤ 4096 bytes; reject at entry layer
    id_token_hint       TEXT,
    front_channel_uri   TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at          TIMESTAMPTZ,
    revoked_at          TIMESTAMPTZ,
    -- [Fix4] Idempotent logout ID: same logout_id for all SP sessions in one logout op
    logout_id           UUID,
    -- [Fix4] Logout status
    logout_status       VARCHAR(16) DEFAULT NULL
        CHECK (logout_status IS NULL OR logout_status IN ('pending','notifying','completed','failed')),

    -- [Fix5] Unique: client_id + sp_session_id + protocol (prevent duplicate SP sessions)
    CONSTRAINT uq_sp_session UNIQUE (client_id, sp_session_id, protocol),
    -- [Fix5] Composite unique: (logout_id, id) ensures same SP session not notified twice
    CONSTRAINT uq_logout_id_sp UNIQUE (logout_id, id)
);

-- [Fix1] Composite index: query user sessions by protocol efficiently
CREATE INDEX IF NOT EXISTS idx_sp_sessions_user_protocol_revoke
    ON sp_sessions(user_id, protocol, revoked_at)
    WHERE revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_sp_sessions_idp
    ON sp_sessions(idp_session_id, revoked_at);

CREATE INDEX IF NOT EXISTS idx_sp_sessions_user
    ON sp_sessions(user_id, revoked_at);

-- [Fix3] Index for retry candidates (failed logout notifications)
CREATE INDEX IF NOT EXISTS idx_sp_sessions_retry
    ON sp_sessions(logout_status, revoked_at)
    WHERE logout_status = 'failed';

-- ---------------------------------------------------------------------------
-- Logout Outbox (Outbox pattern)
-- [Fix2] Guarantees DB transaction + outbox write atomicity
-- [Fix5] Composite unique (logout_id, sp_session_id) for DB-level idempotency
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS logout_outbox (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    logout_id           UUID NOT NULL,
    sp_session_id       UUID NOT NULL,
    client_id           VARCHAR(128) NOT NULL,
    protocol            VARCHAR(16) NOT NULL
        CHECK (protocol IN ('oidc', 'saml')),
    logout_uri          TEXT NOT NULL,
    attempt             INTEGER NOT NULL DEFAULT 0,
    status              VARCHAR(16) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'processing', 'completed', 'dead')),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    next_retry_at       TIMESTAMPTZ,

    -- [Fix5] Composite unique: prevents duplicate outbox entries for same (logout, sp_session)
    CONSTRAINT uq_outbox_sp UNIQUE (logout_id, sp_session_id)
);

-- Index for efficient polling of pending tasks
CREATE INDEX IF NOT EXISTS idx_outbox_pending
    ON logout_outbox(status, next_retry_at)
    WHERE status IN ('pending', 'processing');

-- ---------------------------------------------------------------------------
-- Logout Dead Letters
-- [Fix3] Stores permanently failed SLO notifications
-- [Fix4] FK ON DELETE CASCADE (sp_session deletion cascades to dead letters)
-- [Fix6] idx_dl_created for TTL cleanup (30 days)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS logout_dead_letters (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    logout_id           UUID NOT NULL,
    sp_session_id       UUID NOT NULL
        REFERENCES sp_sessions(id) ON DELETE CASCADE,
    client_id           VARCHAR(128) NOT NULL,
    protocol            VARCHAR(16) NOT NULL
        CHECK (protocol IN ('oidc', 'saml')),
    logout_uri          TEXT,
    error_message       TEXT,
    attempt_count       INTEGER NOT NULL DEFAULT 0,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_failed_at      TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_dl_logout_id ON logout_dead_letters(logout_id);
-- [Fix6] Index for 30-day TTL cleanup
CREATE INDEX IF NOT EXISTS idx_dl_created ON logout_dead_letters(created_at);

-- ---------------------------------------------------------------------------
-- Helper: Get SP count for a given IdP session
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION fn_sp_session_count(p_idp_session_id UUID)
RETURNS INTEGER STABLE AS $$
    SELECT COUNT(*)::INTEGER
    FROM sp_sessions
    WHERE idp_session_id = p_idp_session_id
      AND revoked_at IS NULL;
$$ LANGUAGE SQL;

COMMIT;

-- ---------------------------------------------------------------------------
-- Verification queries
-- ---------------------------------------------------------------------------
-- SELECT * FROM sp_sessions LIMIT 1;
-- SELECT * FROM logout_outbox LIMIT 1;
-- SELECT * FROM logout_dead_letters LIMIT 1;

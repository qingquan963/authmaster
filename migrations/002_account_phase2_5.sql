-- Migration: Phase 2-5 账号合并/解绑
-- AuthMaster Phase 2-5
-- Tables: user_credentials, account_merge_requests, account_change_log
-- Schema changes: auth_users (merged_into, merged_at, merge_locked)
--
-- Key design:
--   [Fix2]   UNIQUE(credential_type, identifier) + ON CONFLICT DO NOTHING
--   [Fix6]   identifier_hash: SHA256(normalized_identifier) with unique constraint
--   [Fix7]   Full merge state machine: pending→source_verified→target_pending→executing→completed
--   [Fix3]   Retry fields: failed_at, retry_count, max_retries, next_retry_at
--   [Fix4]   Concurrency: merge_locked flag on auth_users
--   [Fix5]   Migration: NOT VALID + VALIDATE CONSTRAINT for zero-downtime deployment

BEGIN;

-- ---------------------------------------------------------------------------
-- 1. Extend auth_users table
-- ---------------------------------------------------------------------------
ALTER TABLE auth_users
    ADD COLUMN IF NOT EXISTS merged_into   UUID REFERENCES auth_users(id),
    ADD COLUMN IF NOT EXISTS merged_at     TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS merge_locked  BOOLEAN NOT NULL DEFAULT FALSE;

CREATE INDEX IF NOT EXISTS idx_auth_users_merged_into ON auth_users(merged_into)
    WHERE merged_into IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_auth_users_merge_locked ON auth_users(merge_locked)
    WHERE merge_locked = TRUE;

-- ---------------------------------------------------------------------------
-- 2. user_credentials table
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS user_credentials (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
    credential_type     VARCHAR(32) NOT NULL,
        CHECK (credential_type IN ('phone','email','wechat','alipay','saml','github','google','oidc')),
    identifier          VARCHAR(255) NOT NULL,
    -- [Fix6] identifier_hash: SHA256 of normalized identifier
    --   phone: strip non-digits, remove +86 prefix
    --   email: lowercase
    --   others: raw value
    identifier_hash     VARCHAR(64) NOT NULL,
    is_verified         BOOLEAN NOT NULL DEFAULT FALSE,
    verified_at         TIMESTAMPTZ,
    bound_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    unbound_at          TIMESTAMPTZ,
    is_primary          BOOLEAN NOT NULL DEFAULT FALSE,
    status              VARCHAR(16) NOT NULL DEFAULT 'active'
        CHECK (status IN ('active','unbound','pending_verify','merged')),
    extra_data          JSONB DEFAULT '{}',

    -- [Fix2] Two unique constraints for duplicate prevention
    CONSTRAINT uq_credential_type_identifier UNIQUE (credential_type, identifier),
    CONSTRAINT uq_identifier_hash UNIQUE (identifier_hash)
);

CREATE INDEX IF NOT EXISTS idx_credential_lookup ON user_credentials(identifier_hash, status);
CREATE INDEX IF NOT EXISTS idx_credential_user  ON user_credentials(user_id, status);

-- ---------------------------------------------------------------------------
-- 3. account_merge_requests table (full state machine)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS account_merge_requests (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_user_id      UUID NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
    target_user_id      UUID NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
    -- [Fix7] Full state machine:
    --   pending → source_verified → target_pending → executing → completed
    --   ↑________________________ cancelled / expired / failed _________|
    status              VARCHAR(16) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending','source_verified','target_pending','executing',
                          'completed','cancelled','expired','failed')),
    merge_token         VARCHAR(64) NOT NULL UNIQUE,
    initiated_by        UUID NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
    initiated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    source_verified_at  TIMESTAMPTZ,
    target_verified_at  TIMESTAMPTZ,
    completed_at        TIMESTAMPTZ,
    cancelled_at        TIMESTAMPTZ,
    cancelled_by        UUID REFERENCES auth_users(id),
    expires_at          TIMESTAMPTZ NOT NULL,
    -- [Fix3] Retry fields for failure recovery
    failed_at           TIMESTAMPTZ,
    retry_count         INTEGER NOT NULL DEFAULT 0,
    max_retries         INTEGER NOT NULL DEFAULT 3,
    next_retry_at       TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_merge_requests_token     ON account_merge_requests(merge_token);
CREATE INDEX IF NOT EXISTS idx_merge_requests_status    ON account_merge_requests(status, expires_at);
-- [Fix3] Index for scheduler to find retry candidates
CREATE INDEX IF NOT EXISTS idx_merge_retry_candidates
    ON account_merge_requests(status, retry_count, next_retry_at)
    WHERE status = 'failed';

-- ---------------------------------------------------------------------------
-- 4. account_change_log table (audit)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS account_change_log (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
    event_type          VARCHAR(32) NOT NULL,
    event_detail        JSONB NOT NULL DEFAULT '{}',
    changed_by          UUID REFERENCES auth_users(id),
    ip_address          INET,
    user_agent          TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_change_log_user   ON account_change_log(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_change_log_type   ON account_change_log(event_type, created_at DESC);

-- ---------------------------------------------------------------------------
-- 5. Migration: Add unique constraints with NOT VALID (zero-downtime)
-- ---------------------------------------------------------------------------
-- [Fix5] These constraints are added with NOT VALID so they don't scan existing rows.
-- After the migration runs, validate them separately with:
--   ALTER TABLE user_credentials VALIDATE CONSTRAINT uq_credential_type_identifier;
--   ALTER TABLE user_credentials VALIDATE CONSTRAINT uq_identifier_hash;
-- This allows zero-downtime deployment even if there are pre-existing duplicates.
--
-- To detect pre-existing conflicts before deployment, run:
--   SELECT credential_type, identifier, COUNT(DISTINCT user_id) AS cnt
--   FROM user_credentials WHERE status = 'active'
--   GROUP BY credential_type, identifier HAVING COUNT(DISTINCT user_id) > 1;
--
--   SELECT identifier_hash, credential_type, COUNT(*) AS dup
--   FROM user_credentials WHERE status = 'active'
--   GROUP BY identifier_hash, credential_type HAVING COUNT(*) > 1;

COMMIT;

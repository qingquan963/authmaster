-- ============================================================================
-- AuthMaster Phase 2-4: SAML 2.0 SP 支持
-- Migration: 添加 SAML 相关表
-- ============================================================================

-- ---------------------------------------------------------------------------
-- 1. saml_idp_config: IdP 配置表
-- ---------------------------------------------------------------------------
CREATE TABLE saml_idp_config (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES auth_tenants(id) ON DELETE CASCADE,
    name            VARCHAR(255) NOT NULL,
    entity_id       VARCHAR(1024) NOT NULL,
    sso_url         VARCHAR(1024) NOT NULL,
    slo_url         VARCHAR(1024),
    x509_cert       TEXT NOT NULL,
    sign_algorithm  VARCHAR(20) NOT NULL DEFAULT 'RSA-SHA256',
    want_assertions_signed  BOOLEAN NOT NULL DEFAULT TRUE,
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,

    -- Attribute 映射配置（JSON）
    attribute_mapping JSONB NOT NULL DEFAULT '{
      "email": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
      "name": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"
    }',

    -- 高级配置
    name_id_format  VARCHAR(100) DEFAULT 'emailAddress',
    acs_url         VARCHAR(1024),
    metadata_xml    TEXT,
    metadata_url    VARCHAR(1024),

    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by      UUID REFERENCES auth_users(id),

    CONSTRAINT uq_tenant_idp_entity_id UNIQUE (tenant_id, entity_id),
    CONSTRAINT ck_idp_sign_algorithm CHECK (sign_algorithm IN ('RSA-SHA256', 'RSA-SHA512'))
);

CREATE INDEX ix_saml_idp_config_tenant ON saml_idp_config(tenant_id, enabled);
CREATE INDEX ix_saml_idp_config_entity_id ON saml_idp_config(entity_id);

-- ---------------------------------------------------------------------------
-- 2. saml_sp_config: SP 配置表（每租户 SP 设置）
-- ---------------------------------------------------------------------------
CREATE TABLE saml_sp_config (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID UNIQUE NOT NULL REFERENCES auth_tenants(id) ON DELETE CASCADE,

    entity_id           VARCHAR(1024) NOT NULL,

    -- SP 证书（SP 签名/加密密钥对）
    sp_cert_pem         TEXT NOT NULL,
    sp_key_pem          TEXT NOT NULL,
    cert_not_before     TIMESTAMPTZ,
    cert_not_after      TIMESTAMPTZ,

    -- Assertion 加密（可选）
    want_assertions_encrypted  BOOLEAN NOT NULL DEFAULT FALSE,
    encryption_algorithm VARCHAR(30) NOT NULL DEFAULT 'AES-256-CBC',

    -- SSO 行为配置
    auto_register_new_users   BOOLEAN NOT NULL DEFAULT TRUE,
    default_role_id   UUID REFERENCES auth_roles(id),

    -- IdP 发起登录是否允许（默认不允许）
    allow_idp_initiated   BOOLEAN NOT NULL DEFAULT FALSE,

    -- 签名配置
    sign_requests        BOOLEAN NOT NULL DEFAULT TRUE,
    sign_algorithm       VARCHAR(20) NOT NULL DEFAULT 'RSA-SHA256',

    -- 强认证要求
    require_mfa_for_saml BOOLEAN NOT NULL DEFAULT FALSE,

    -- NameID 格式偏好
    preferred_name_id_format VARCHAR(100) DEFAULT 'emailAddress',

    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT ck_sp_sign_algorithm CHECK (sign_algorithm IN ('RSA-SHA256', 'RSA-SHA512')),
    CONSTRAINT ck_sp_encryption_algorithm CHECK (encryption_algorithm IN ('AES-256-CBC', 'AES-128-CBC'))
);

-- ---------------------------------------------------------------------------
-- 3. saml_authn_requests: 请求状态表（用于 InResponseTo 验证）
-- ---------------------------------------------------------------------------
CREATE TABLE saml_authn_requests (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES auth_tenants(id) ON DELETE CASCADE,
    idp_config_id   UUID NOT NULL REFERENCES saml_idp_config(id) ON DELETE CASCADE,

    request_id      VARCHAR(256) NOT NULL,
    in_response_to  VARCHAR(256),

    -- 请求参数快照
    name_id_policy  VARCHAR(100),
    assertion_consumer_service_url VARCHAR(1024),
    protocol_binding VARCHAR(100),

    -- 状态
    status          VARCHAR(20) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'used', 'expired', 'cancelled')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ NOT NULL,
    used_at         TIMESTAMPTZ,

    CONSTRAINT uq_saml_request_id UNIQUE (request_id)
);

CREATE INDEX ix_authn_requests_expiry ON saml_authn_requests(expires_at) WHERE status = 'pending';
CREATE INDEX ix_authn_requests_in_response ON saml_authn_requests(in_response_to) WHERE status = 'pending';
CREATE INDEX ix_authn_requests_idp ON saml_authn_requests(idp_config_id, status);

-- ---------------------------------------------------------------------------
-- 4. saml_user_bindings: 用户与 IdP 绑定表
-- ---------------------------------------------------------------------------
CREATE TABLE saml_user_bindings (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
    idp_config_id   UUID NOT NULL REFERENCES saml_idp_config(id) ON DELETE CASCADE,
    name_id         VARCHAR(1024) NOT NULL,
    name_id_format  VARCHAR(100) NOT NULL,
    attributes_json JSONB NOT NULL DEFAULT '{}',
    linked_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_user_idp_nameid UNIQUE (user_id, idp_config_id, name_id)
);

CREATE INDEX ix_saml_bindings_user ON saml_user_bindings(user_id);
CREATE INDEX ix_saml_bindings_idp_nameid ON saml_user_bindings(idp_config_id, name_id);
CREATE INDEX ix_saml_bindings_user_idp ON saml_user_bindings(user_id, idp_config_id);

-- ---------------------------------------------------------------------------
-- 5. 现有表变更
-- ---------------------------------------------------------------------------
ALTER TABLE auth_users ADD COLUMN saml_last_login_idp UUID REFERENCES saml_idp_config(id);
ALTER TABLE auth_users ADD COLUMN saml_last_name_id VARCHAR(1024);
ALTER TABLE auth_tenants ADD COLUMN saml_enabled BOOLEAN NOT NULL DEFAULT FALSE;

-- Migration: 005_saml_phase2_4

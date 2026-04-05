# IAM/IDaaS 平台 MVP 架构设计文档

> 文档版本：v1.0
> 创建日期：2026-04-02
> 状态：MVP 架构初稿

---

## 一、项目概述

### 1.1 项目定位

**产品名称（候选）：** AuthMaster / OneAuth
**核心定位：** 面向中小企业的 SaaS 化统一身份认证与访问管理平台（IDaaS）
**目标客户：** 数字化转型中的中小企业，需要统一身份管理但无力自建 IAM 系统的企业

### 1.2 设计原则

| 原则 | 说明 |
|------|------|
| **最小化 MVP** | 先跑通核心链路，不求大而全 |
| **安全优先** | 身份认证产品，安全性是生命线 |
| **多租户隔离** | 数据隔离是卖给企业的底线 |
| **可扩展性** | Phase 2/3 功能预留接口，不做死设计 |
| **标准协议** | 采用 OAuth2.0 / OIDC 国际标准，降低集成成本 |

### 1.3 术语表

| 术语 | 定义 |
|------|------|
| **Tenant（租户）** | 一个企业/商户账号，独立数据空间 |
| **User（用户）** | 租户下的自然人账号 |
| **Role（角色）** | 一组权限的具名集合（如"管理员"、"普通员工"） |
| **Permission（权限）** | 对某个资源执行某个操作的能力 |
| **API Key** | 租户用于调用开发者 API 的密钥 |
| **Refresh Token** | 用于刷新 Access Token 的凭证，支持吊销 |

---

## 二、系统架构图

### 2.1 整体架构

```
┌─────────────────────────────────────────────────────────────────────┐
│                          客户端层 (Clients)                          │
│   [Web 管理后台]  [移动端 H5]  [业务系统（API 调用）]  [第三方 App]   │
└────────────────────────────┬────────────────────────────────────────┘
                             │ HTTPS
┌────────────────────────────▼────────────────────────────────────────┐
│                        网关层 (API Gateway)                          │
│   • 流量控制 / 限流                                                    │
│   • SSL 终结                                                           │
│   • 路由分发 (auth.* / api.* / admin.*)                              │
│   • 基础安全 (IP 黑名单/白名单)                                        │
└──────┬─────────────────────┬──────────────────────┬───────────────────┘
       │                     │                      │
┌──────▼──────┐    ┌─────────▼─────────┐   ┌───────▼───────┐
│  认证服务    │    │    业务 API 服务   │   │  管理后台 API  │
│ (Auth API)  │    │  (Business API)   │   │ (Admin API)   │
│             │    │                   │   │               │
│ • 登录/注册  │    │ • 用户管理        │   │ • 租户管理    │
│ • Token 签发 │    │ • 角色权限管理     │   │ • 系统配置    │
│ • OAuth2.0 │    │ • API Key 管理     │   │ • 审计日志    │
│ • Token 验证│    │ • 租户内数据查询   │   │               │
└──────┬──────┘    └─────────┬─────────┘   └───────┬───────┘
       │                     │                      │
       └─────────────────────┼──────────────────────┘
                             │
              ┌──────────────▼──────────────┐
              │        公共服务层            │
              │  • 全局异常处理               │
              │  • 审计日志记录               │
              │  • 租户上下文解析 (TenantCtx) │
              └──────────────┬──────────────┘
                             │
┌────────────────────────────▼────────────────────────────────────────┐
│                         数据层 (Data Layer)                           │
│                                                                       │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────┐ │
│  │   PostgreSQL    │  │      Redis       │  │    文件存储 (OSS)    │ │
│  │   (主数据存储)    │  │  (Token/会话缓存) │  │  (Logo/证书/配置)    │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────────┘ │
│                                                                       │
│  ┌─────────────────────────────────────────────────────────────────┐  │
│  │                    MinIO / 阿里云 OSS                            │  │
│  │              (OAuth 证书、用户头像、导出文件)                     │  │
│  └─────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

### 2.2 核心数据流

```
[用户登录流程]

用户 → 网关 → 认证服务 → Redis(验证码/频率限制)
                   ↓
              PostgreSQL(用户数据)
                   ↓
              生成 JWT Token 对
              (AccessToken + RefreshToken)
                   ↓
              Redis(RefreshToken 注册)
                   ↓
              返回 Token 给用户

[API 鉴权流程]

业务系统 → 网关 → 验证 AccessToken 签名
                  ↓ (通过)
              Redis 检查 Token 是否已吊销
                  ↓ (未吊销)
              提取 TenantID + UserID + Roles
                  ↓
              路由到业务 API → 检查 RBAC 权限
                  ↓
              返回业务数据
```

### 2.3 组件职责

| 组件 | 技术选型 | 职责 |
|------|---------|------|
| **API Gateway** | Nginx / Kong | HTTPS、路由、限流、SSL |
| **Auth Service** | FastAPI (Python) | 认证、Token 生命周期、OAuth2.0 |
| **Business API** | FastAPI (Python) | 用户管理、RBAC、租户业务 |
| **Admin API** | FastAPI (Python) | 系统管理、租户管理后台 |
| **PostgreSQL** | PostgreSQL 15+ | 主数据库 |
| **Redis** | Redis 7+ | Token 缓存、验证码、消息队列 |
| **MinIO** | MinIO / 阿里云 | 文件存储 |

---

## 三、数据库表结构

> 遵循原则：每个租户数据通过 `tenant_id` 字段隔离，系统级表（如租户本身）无 `tenant_id`。

### 3.1 ER 关系总览

```
Tenant (租户)
  ├── User (用户)
  │     ├── UserRole (用户-角色)
  │     └── UserOAuth (第三方绑定)
  │
  ├── Role (角色)
  │     └── RolePermission (角色-权限，通过 permissions JSONB 冗余存储)
  │
  ├── Permission (权限)
  │
  └── APIKey (API 密钥)

System: AuditLog (审计日志, 无租户隔离, 系统级)
System: AppConfig (系统配置, 无租户隔离)
```

### 3.2 详细表结构

#### 3.2.1 系统级表（平台运营用）

```sql
-- 租户表 (Tenant)
CREATE TABLE tenants (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(128) NOT NULL,          -- 企业名称
    slug            VARCHAR(64) UNIQUE NOT NULL,    -- 租户 slug，用于子域名
    plan            VARCHAR(32) DEFAULT 'free',     -- free/pro/enterprise
    status          VARCHAR(16) DEFAULT 'active',   -- active/suspended
    admin_user_id   UUID,                            -- 租户管理员 user_id
    expires_at      TIMESTAMP,                       -- 套餐过期时间
    settings        JSONB DEFAULT '{}',             -- 租户个性化配置
    created_at      TIMESTAMP DEFAULT NOW(),
    updated_at      TIMESTAMP DEFAULT NOW()
);

-- 系统配置表
CREATE TABLE system_configs (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key         VARCHAR(128) UNIQUE NOT NULL,
    value       JSONB NOT NULL,
    description VARCHAR(256),
    updated_at  TIMESTAMP DEFAULT NOW()
);

-- 审计日志表 (系统级，记录所有敏感操作)
CREATE TABLE audit_logs (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID REFERENCES tenants(id),         -- NULL 表示系统操作
    user_id     UUID,
    action      VARCHAR(64) NOT NULL,               -- login/logout/token_revoked/...
    resource    VARCHAR(128),                        -- 操作的资源类型
    resource_id VARCHAR(128),                        -- 操作的资源 ID
    ip_address  VARCHAR(45),
    user_agent  VARCHAR(512),
    request_id  UUID,                                -- 请求链路追踪 ID
    details     JSONB DEFAULT '{}',                  -- 额外详情
    created_at  TIMESTAMP DEFAULT NOW()
);
CREATE INDEX idx_audit_logs_tenant ON audit_logs(tenant_id);
CREATE INDEX idx_audit_logs_user ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_created ON audit_logs(created_at);
```

#### 3.2.2 认证相关表

```sql
-- 用户表 (User)
CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    username        VARCHAR(64),
    phone           VARCHAR(32) UNIQUE,              -- 全局唯一
    email           VARCHAR(128),                     -- 租户内唯一
    password_hash   VARCHAR(256),                    -- bcrypt 哈希
    password_algo   VARCHAR(16) DEFAULT 'bcrypt',     -- 算法标识
    nickname        VARCHAR(64),
    avatar_url      VARCHAR(512),
    status          VARCHAR(16) DEFAULT 'active',    -- active/disable/locked
    mfa_enabled     BOOLEAN DEFAULT FALSE,
    mfa_secret      VARCHAR(128),                    -- TOTP secret
    last_login_at   TIMESTAMP,
    last_login_ip   VARCHAR(45),
    login_count     INT DEFAULT 0,
    password_changed_at TIMESTAMP DEFAULT NOW(),
    created_at      TIMESTAMP DEFAULT NOW(),
    updated_at      TIMESTAMP DEFAULT NOW(),
    deleted_at      TIMESTAMP,                       -- 软删除
    CONSTRAINT chk_phone_email CHECK (phone IS NOT NULL OR email IS NOT NULL)
);
CREATE UNIQUE INDEX idx_users_tenant_email ON users(tenant_id, email) WHERE deleted_at IS NULL;
CREATE INDEX idx_users_phone ON users(phone);

-- 短信/邮箱验证码表 (Verification Codes)
CREATE TABLE verification_codes (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID REFERENCES tenants(id),
    target      VARCHAR(128) NOT NULL,               -- 手机号或邮箱
    type        VARCHAR(16) NOT NULL,                -- sms/email
    code        VARCHAR(16) NOT NULL,               -- 6位数字
    purpose     VARCHAR(32) NOT NULL,               -- login/register/reset_pwd/bind
    used        BOOLEAN DEFAULT FALSE,
    expires_at  TIMESTAMP NOT NULL,
    created_at  TIMESTAMP DEFAULT NOW()
);
CREATE INDEX idx_vc_target ON verification_codes(target, type, purpose);

-- 第三方登录绑定表 (User OAuth Bindings)
CREATE TABLE user_oauth (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    provider        VARCHAR(32) NOT NULL,            -- wechat/alipay/google
    provider_user_id VARCHAR(256) NOT NULL,          -- 第三方平台用户 ID
    union_id        VARCHAR(256),                    -- 微信 UnionID（跨应用唯一）
    access_token    TEXT,                            -- 加密存储
    refresh_token   TEXT,                            -- 加密存储
    expires_at      TIMESTAMP,
    created_at      TIMESTAMP DEFAULT NOW(),
    UNIQUE(provider, provider_user_id)
);
CREATE INDEX idx_oauth_user ON user_oauth(user_id);
```

#### 3.2.3 RBAC 相关表

```sql
-- 权限定义表 (Permission)
CREATE TABLE permissions (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id),
    code        VARCHAR(128) NOT NULL,               -- 权限代码，如 "user:create"
    name        VARCHAR(64) NOT NULL,                 -- 权限名称
    description VARCHAR(256),
    resource    VARCHAR(64) NOT NULL,                 -- 资源，如 "user"
    action      VARCHAR(32) NOT NULL,                 -- 操作，如 "create/read/update/delete"
    created_at  TIMESTAMP DEFAULT NOW(),
    UNIQUE(tenant_id, code)
);

-- 内置系统权限 (平台预定义，tenant_id 为 NULL 表示全局)
INSERT INTO permissions (id, tenant_id, code, name, resource, action) VALUES
(gen_random_uuid(), NULL, 'system:tenant:manage',    '管理租户',   'system', 'tenant:manage'),
(gen_random_uuid(), NULL, 'system:user:manage',       '管理用户',   'system', 'user:manage'),
(gen_random_uuid(), NULL, 'system:role:manage',       '管理角色',   'system', 'role:manage'),
(gen_random_uuid(), NULL, 'system:apikey:manage',    '管理APIKey', 'system', 'apikey:manage'),
(gen_random_uuid(), NULL, 'system:audit:read',       '查看审计日志','system', 'audit:read');

-- 角色表 (Role)
CREATE TABLE roles (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id),
    name        VARCHAR(64) NOT NULL,
    code        VARCHAR(64) NOT NULL,                -- 角色代码，如 "admin"
    description VARCHAR(256),
    is_system   BOOLEAN DEFAULT FALSE,               -- 是否系统内置角色，不可删除
    permissions JSONB DEFAULT '[]',                 -- 冗余存储，快速查询
    created_at  TIMESTAMP DEFAULT NOW(),
    updated_at  TIMESTAMP DEFAULT NOW(),
    UNIQUE(tenant_id, code)
);

-- 内置系统角色
INSERT INTO roles (id, tenant_id, name, code, is_system, permissions) VALUES
(gen_random_uuid(), NULL, '租户管理员', 'tenant_admin', TRUE, '["system:tenant:manage","system:user:manage","system:role:manage","system:apikey:manage","system:audit:read"]'),
(gen_random_uuid(), NULL, '普通用户',   'user',         TRUE, '[]');

-- 用户-角色关联表 (User Role Mapping)
CREATE TABLE user_roles (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id),
    role_id     UUID NOT NULL REFERENCES roles(id),
    granted_by  UUID REFERENCES users(id),
    granted_at  TIMESTAMP DEFAULT NOW(),
    expires_at  TIMESTAMP,                            -- 角色过期时间（可选）
    UNIQUE(user_id, role_id)
);
CREATE INDEX idx_user_roles_user ON user_roles(user_id);
CREATE INDEX idx_user_roles_role ON user_roles(role_id);
```

#### 3.2.4 Token / 会话表

```sql
-- Access Token 黑名单 (Token 吊销后写入 Redis，备份到 PG)
CREATE TABLE token_blacklist (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    jti         VARCHAR(64) UNIQUE NOT NULL,           -- JWT ID
    user_id     UUID NOT NULL,
    tenant_id   UUID NOT NULL REFERENCES tenants(id),
    revoked_at  TIMESTAMP DEFAULT NOW(),
    expires_at  TIMESTAMP NOT NULL,                    -- Token 原始过期时间
    reason      VARCHAR(128),
    created_by  UUID                                    -- 谁执行了吊销
);
CREATE INDEX idx_token_bl_jti ON token_blacklist(jti);
CREATE INDEX idx_token_bl_expires ON token_blacklist(expires_at);

-- Refresh Token 表 (支持 token 版本号，实现 Refresh Token 轮换)
CREATE TABLE refresh_tokens (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id),
    tenant_id   UUID NOT NULL REFERENCES tenants(id),
    token_hash  VARCHAR(128) NOT NULL UNIQUE,         -- Token 哈希存储
    device_info VARCHAR(256),                          -- 设备信息
    ip_address  VARCHAR(45),
    version     INT DEFAULT 1,                         -- Token 版本号
    last_used_at TIMESTAMP,
    last_used_ip VARCHAR(45),
    expires_at  TIMESTAMP NOT NULL,
    revoked_at  TIMESTAMP,
    revoked_reason VARCHAR(128),
    created_at  TIMESTAMP DEFAULT NOW()
);
CREATE INDEX idx_rt_user ON refresh_tokens(user_id);
CREATE INDEX idx_rt_token_hash ON refresh_tokens(token_hash);
```

#### 3.2.5 开发者 API 表

```sql
-- API Key 表
CREATE TABLE api_keys (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    name            VARCHAR(128) NOT NULL,            -- Key 名称，如 "生产环境 Key"
    key_id          VARCHAR(32) UNIQUE NOT NULL,     -- 公开 Key ID (key_xxx)
    key_hash        VARCHAR(256) NOT NULL,            -- Secret Key 哈希存储
    permissions     JSONB DEFAULT '[]',              -- 该 Key 的权限范围
    rate_limit      INT DEFAULT 1000,                 -- 每分钟请求限制
    last_used_at    TIMESTAMP,
    last_used_ip    VARCHAR(45),
    expires_at      TIMESTAMP,                        -- 可选过期时间
    status          VARCHAR(16) DEFAULT 'active',    -- active/disabled
    created_by      UUID REFERENCES users(id),
    created_at      TIMESTAMP DEFAULT NOW(),
    updated_at      TIMESTAMP DEFAULT NOW()
);
CREATE INDEX idx_api_keys_tenant ON api_keys(tenant_id);
CREATE INDEX idx_api_keys_key_id ON api_keys(key_id);

-- OAuth 应用表 (第三方登录用)
CREATE TABLE oauth_clients (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    name            VARCHAR(128) NOT NULL,
    client_id       VARCHAR(64) UNIQUE NOT NULL,
    client_secret   VARCHAR(256) NOT NULL,            -- 哈希存储
    redirect_uris   JSONB DEFAULT '[]',              -- 允许的回调地址
    scopes          JSONB DEFAULT '["openid","profile"]',
    grants          JSONB DEFAULT '["authorization_code","refresh_token"]',
    status          VARCHAR(16) DEFAULT 'active',
    created_at      TIMESTAMP DEFAULT NOW()
);
CREATE INDEX idx_oauth_client_tenant ON oauth_clients(tenant_id);
```

### 3.3 数据隔离策略

```
┌─────────────────────────────────────────────────────┐
│                  PostgreSQL: iam_db                  │
│                                                     │
│  ┌──────────────┐              ┌──────────────┐     │
│  │  tenants (A)  │              │  tenants (B)  │     │
│  │  users (*)    │              │  users (*)    │     │
│  │  roles (*)    │              │  roles (*)    │     │
│  └──────────────┘              └──────────────┘     │
│                                                     │
│  查询时强制带上 tenant_id 条件：                      │
│  SELECT * FROM users WHERE tenant_id = $1          │
└─────────────────────────────────────────────────────┘

Row-Level Security (RLS) 策略:
- PostgreSQL 开启 RLS，每个租户表设置 RLS 策略
- 应用层每次查询自动注入 tenant_id
- 防止越权访问
```

---

## 四、API 接口设计

### 4.1 API 分组

| 前缀 | 服务 | 说明 |
|------|------|------|
| `/auth/*` | Auth Service | 认证相关（登录/注册/OAuth） |
| `/oauth/*` | Auth Service | OAuth2.0 授权端点 |
| `/api/v1/*` | Business API | 业务 API（含 Token 校验） |
| `/admin/v1/*` | Admin API | 管理后台 API |
| `/open/v1/*` | Open API | 开发者 Open API（API Key 鉴权） |

### 4.2 认证服务 API (`/auth/*`)

| 方法 | 路径 | 说明 | 鉴权 |
|------|------|------|------|
| POST | `/auth/login/phone` | 手机号+验证码登录 | 无 |
| POST | `/auth/login/email` | 邮箱+密码登录 | 无 |
| POST | `/auth/register` | 用户注册 | 无 |
| POST | `/auth/logout` | 登出（吊销 Token） | AccessToken |
| POST | `/auth/refresh` | 刷新 AccessToken | RefreshToken |
| POST | `/auth/send_code` | 发送验证码（短信/邮箱） | 无 |
| POST | `/auth/verify_code` | 验证验证码 | 无 |
| POST | `/auth/token/revoke` | 主动吊销 Token | AccessToken |
| GET | `/auth/token/info` | 查询当前 Token 信息 | AccessToken |
| GET | `/auth/userinfo` | 获取当前用户信息 | AccessToken |
| PUT | `/auth/user/password` | 修改密码 | AccessToken |
| POST | `/auth/user/phone/bind` | 绑定手机号 | AccessToken |
| POST | `/auth/user/email/bind` | 绑定邮箱 | AccessToken |

### 4.3 OAuth2.0 API (`/oauth/*`)

| 方法 | 路径 | 说明 | 鉴权 |
|------|------|------|------|
| GET | `/oauth/authorize` | 授权码模式 - 授权页 | 无 |
| POST | `/oauth/token` | 获取 AccessToken | ClientSecret |
| POST | `/oauth/token/revoke` | 吊销 Token | ClientSecret |
| GET | `/oauth/userinfo` | 获取 OAuth 用户信息 | AccessToken |
| GET | `/oauth/.well-known/openid-configuration` | OIDC 发现文档 | 无 |

### 4.4 用户管理 API (`/api/v1/users/*`)

| 方法 | 路径 | 说明 | 鉴权 |
|------|------|------|------|
| GET | `/api/v1/users` | 列举用户（分页） | AccessToken + `user:read` |
| POST | `/api/v1/users` | 创建用户 | AccessToken + `user:create` |
| GET | `/api/v1/users/{id}` | 获取用户详情 | AccessToken + `user:read` |
| PUT | `/api/v1/users/{id}` | 更新用户 | AccessToken + `user:update` |
| DELETE | `/api/v1/users/{id}` | 删除用户（软删除） | AccessToken + `user:delete` |
| PUT | `/api/v1/users/{id}/status` | 启用/禁用用户 | AccessToken + `user:update` |
| GET | `/api/v1/users/me` | 获取自身信息 | AccessToken |

### 4.5 角色权限 API

| 方法 | 路径 | 说明 | 鉴权 |
|------|------|------|------|
| GET | `/api/v1/roles` | 列举角色 | AccessToken + `role:read` |
| POST | `/api/v1/roles` | 创建角色 | AccessToken + `role:create` |
| GET | `/api/v1/roles/{id}` | 角色详情 | AccessToken + `role:read` |
| PUT | `/api/v1/roles/{id}` | 更新角色 | AccessToken + `role:update` |
| DELETE | `/api/v1/roles/{id}` | 删除角色 | AccessToken + `role:delete` |
| POST | `/api/v1/roles/{id}/permissions` | 分配权限给角色 | AccessToken + `role:update` |
| GET | `/api/v1/permissions` | 列举所有权限 | AccessToken + `permission:read` |
| POST | `/api/v1/permissions` | 创建自定义权限 | AccessToken + `permission:create` |
| POST | `/api/v1/users/{id}/roles` | 分配角色给用户 | AccessToken + `role:assign` |
| DELETE | `/api/v1/users/{id}/roles/{roleId}` | 移除用户角色 | AccessToken + `role:assign` |
| GET | `/api/v1/users/{id}/permissions` | 查询用户有效权限 | AccessToken + `permission:read` |

### 4.6 开发者 Open API (`/open/v1/*`)

| 方法 | 路径 | 说明 | 鉴权 |
|------|------|------|------|
| GET | `/open/v1/keys` | 列举 API Key | API Key |
| POST | `/open/v1/keys` | 创建 API Key | API Key |
| DELETE | `/open/v1/keys/{id}` | 删除 API Key | API Key |
| PATCH | `/open/v1/keys/{id}` | 更新 API Key（限频/范围） | API Key |
| GET | `/open/v1/keys/{id}/usage` | 查看 API Key 使用量 | API Key |
| POST | `/open/v1/keys/rotate` | 轮换 API Key | API Key |

### 4.7 管理后台 API (`/admin/v1/*`)

| 方法 | 路径 | 说明 | 鉴权 |
|------|------|------|------|
| GET | `/admin/v1/tenants` | 列举租户 | 系统级 Token |
| POST | `/admin/v1/tenants` | 创建租户 | 系统级 Token |
| GET | `/admin/v1/tenants/{id}` | 租户详情 | 系统级 Token |
| PATCH | `/admin/v1/tenants/{id}` | 更新租户（套餐/状态） | 系统级 Token |
| GET | `/admin/v1/audit/logs` | 审计日志 | 系统级 Token |
| GET | `/admin/v1/stats` | 平台统计（用户数/API 调用量） | 系统级 Token |

### 4.8 请求/响应规范

```json
// 标准成功响应
{
  "code": 0,
  "message": "success",
  "data": { ... }
}

// 标准错误响应
{
  "code": 40001,
  "message": "验证码已过期",
  "request_id": "uuid"
}

// 分页响应
{
  "code": 0,
  "message": "success",
  "data": {
    "items": [...],
    "total": 100,
    "page": 1,
    "page_size": 20
  }
}
```

### 4.9 错误码规范

| 区间 | 含义 |
|------|------|
| 0 | 成功 |
| 40001-40099 | 参数/请求错误 |
| 40101-40199 | 认证失败 |
| 40301-40399 | 权限不足 |
| 40401-40499 | 资源不存在 |
| 42901-42999 | 请求过于频繁 |
| 50001-50099 | 系统错误 |

---

## 五、安全设计

### 5.1 Token 安全

#### 5.1.1 JWT Token 结构

```
AccessToken (JWT, 有效期 15 分钟 ~ 2 小时)
Header:
{
  "alg": "RS256",         // 生产环境用 RS256（RSA 签名），HS256 仅开发用
  "typ": "JWT",
  "kid": "key-2024-001"   // 密钥 ID
}
Payload:
{
  "iss": "auth.authmaster.com",           // 签发者
  "sub": "user-uuid",                      // 用户 ID
  "aud": ["api.authmaster.com"],          // 目标受众
  "exp": 1704067200,                       // 过期时间
  "iat": 1704063600,                       // 签发时间
  "jti": "unique-token-id",                // JWT ID（用于吊销）
  "tenant_id": "tenant-uuid",              // 租户 ID
  "roles": ["admin", "user"],              // 角色列表
  "permissions": ["user:read"],            // 权限列表（可选冗余）
  "scope": "openid profile"                // OAuth Scope
}

RefreshToken (不透明 Token，存 Redis)
- 格式: 随机 64 字符十六进制字符串
- 存储: Redis Key = `refresh:{hash(token)}`，TTL = 7~30 天
- 每个 RefreshToken 有 version 字段，支持轮换和单点登出
```

#### 5.1.2 Token 吊销机制

```
实时吊销（通过 Redis + PostgreSQL 双写）:

1. 用户主动登出 / 管理员禁用用户:
   → 删除 Redis 中的 RefreshToken
   → 写入 AccessToken JTI 到 Redis Blacklist 集合
   → 异步写入 PostgreSQL token_blacklist 表（持久化）

2. Token 验证时:
   Redis Check:
   ✓ 检查 JTI 是否在 Blacklist 集合 → 拒绝
   ✓ 检查 RefreshToken 是否存在 → 拒绝（如已登出）

3. Redis 故障时降级:
   → 查询 PostgreSQL token_blacklist（延迟增加，但可用）

4. 批量吊销（改密/禁用用户）:
   → 将用户所有 RefreshToken 版本 +1，旧 Token 自动失效
```

#### 5.1.3 Token 安全最佳实践

| 实践 | 说明 |
|------|------|
| RS256 签名 | 生产环境使用 RSA 私钥签名，私钥严格保管 |
| 短期 AccessToken | 15 分钟，最大不超过 2 小时 |
| RefreshToken 轮换 | 每次 refresh 生成新的 RefreshToken（旧的一律作废） |
| Token 绑定设备 | RefreshToken 与设备指纹绑定，异常使用告警 |
| 并发刷新限制 | 同一 Token 同时只能有一个有效 RefreshToken |
| 登录失败锁定 | 连续 5 次失败锁定 15 分钟 |

### 5.2 API 安全

#### 5.2.1 鉴权方式

| API 类型 | 鉴权方式 | 位置 |
|---------|---------|------|
| 前端调用 API | Bearer AccessToken | `Authorization: Bearer <token>` |
| 后端服务间调用 | Service-to-Service Token | `X-Service-Token: <token>` |
| 开发者 Open API | API Key + Signature | `X-API-Key: <key_id>` + HMAC 签名 |
| OAuth 回调 | State 参数 | URL 参数，防 CSRF |

#### 5.2.2 API Key 签名算法（Open API）

```
申请 API Key → 获得 key_id + secret_key
调用时需要 HMAC-SHA256 签名:

Headers:
  X-API-Key: key_abc123
  X-Timestamp: 1704067200
  X-Nonce: random-16-chars
  X-Signature: HMAC-SHA256(secret_key, method + path + timestamp + nonce + body)

服务端验证:
1. 检查时间戳与服务器偏差 < 5 分钟（防重放）
2. 检查 Nonce 是否已使用（防重放）
3. 验证 HMAC 签名
4. 检查 API Key 状态和权限范围
```

#### 5.2.3 限流策略

| 级别 | 维度 | 默认限制 |
|------|------|---------|
| 全局 | 所有请求 | 10000 req/min |
| 认证接口 | `/auth/login/*` | 10 req/min/IP |
| 验证码发送 | `/auth/send_code` | 5 req/min/手机号 |
| Open API | 按 API Key | 100~10000 req/min（按套餐） |

### 5.3 传输加密

```
HTTPS 强制:
- 所有环境强制 TLS 1.2+
- HSTS 头强制 HTTPS
- 证书: Let's Encrypt 或商业证书（Digicert）

内部通信:
- 微服务间 mTLS（可选，Phase 2 实施）
- Redis 启用 TLS（生产环境）
- PostgreSQL 启用 TLS

敏感数据加密存储:
- 密码: bcrypt（cost factor ≥ 12）
- OAuth Token: AES-256-GCM 加密后存储
- 用户手机号: AES-256 加密存储
- API Secret Key: bcrypt 哈希存储
```

### 5.4 安全防护措施

| 攻击类型 | 防护措施 |
|---------|---------|
| 暴力破解 | IP 限流 + 验证码 + 账户锁定 |
| CSRF | SameSite Cookie + State 参数 |
| XSS | 输出编码 + CSP |
| SQL 注入 | ORM 参数化查询 |
| 重放攻击 | Nonce + Timestamp |
| Token 窃取 | HTTPS + 安全存储（HttpOnly Cookie） |
| 越权访问 | 租户 ID 强制校验 + RLS |

---

## 六、技术选型

### 6.1 技术栈总览

| 层级 | 技术 | 版本 | 说明 |
|------|------|------|------|
| **后端框架** | FastAPI | 0.109+ | Python 高性能 ASGI 框架 |
| **语言** | Python | 3.11+ | 开发效率高，生态丰富 |
| **ORM** | SQLAlchemy 2.0 | 2.0+ | 类型安全，异步支持 |
| **数据库** | PostgreSQL | 15+ | 关系型，RLS 多租户 |
| **缓存** | Redis | 7+ | Token、验证码、会话 |
| **消息队列** | Redis Streams | 7+ | 异步任务（邮件/短信） |
| **Web 服务器** | Nginx | 1.25+ | 反向代理、SSL |
| **API 文档** | OpenAPI/Swagger | 3.0 | 自动生成 |
| **容器化** | Docker | 24+ | 一键部署 |
| **编排** | Docker Compose | 2.0+ | 本地/轻量部署 |
| **配置管理** | Pydantic Settings | - | 类型安全配置 |
| **定时任务** | APScheduler | - | 清理过期 Token |

### 6.2 为什么选择 FastAPI

| 对比项 | FastAPI | Go (Gin/Echo) | Spring Boot |
|-------|---------|---------------|-------------|
| 开发速度 | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐ |
| 性能 | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ |
| 类型安全 | ⭐⭐⭐⭐⭐ (原生) | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ |
| 自动 API 文档 | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ |
| 生态 | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| 学习曲线 | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐ |

> **选型理由：** MVP 阶段开发速度优先，Python + FastAPI 能在最短时间内上线。同时 Pydantic 提供了极佳的请求验证体验，减少线上 bug。

### 6.3 替代方案备选

- **高性能版本迁移：** 当 QPS > 5000 时，可将认证核心逻辑用 Go 重写
- **数据库：** PostgreSQL → TiDB（超大规模）
- **缓存：** Redis → Dragonfly（更高性能）

---

## 七、部署架构

### 7.1 容器化部署结构

```
iam-platform/
├── docker-compose.yml          # 全量编排
├── docker-compose.prod.yml     # 生产环境覆盖
├── services/
│   ├── auth-api/               # 认证服务
│   │   ├── Dockerfile
│   │   └── app/
│   ├── business-api/           # 业务 API 服务
│   │   └── app/
│   └── admin-api/              # 管理后台 API
│       └── app/
├── nginx/
│   ├── conf.d/
│   │   ├── auth.conf
│   │   ├── api.conf
│   │   └── admin.conf
│   └── Dockerfile
├── postgres/
│   └── init/
│       └── 01-init.sql          # 数据库初始化脚本
├── redis/
│   └── redis.conf
└── volumes/                    # 持久化数据目录
```

### 7.2 Docker Compose 单机部署

```yaml
# docker-compose.yml 核心结构
services:
  nginx:
    image: nginx:1.25-alpine
    ports: ["443:443", "80:80"]
    volumes:
      - ./nginx/conf.d:/etc/nginx/conf.d
      - ./certs:/etc/nginx/certs
    depends_on: [auth-api, business-api, admin-api]

  auth-api:
    build: ./services/auth-api
    environment:
      - DATABASE_URL=postgresql+asyncpg://iam:password@postgres:5432/iam_db
      - REDIS_URL=redis://redis:6379/0
    depends_on: [postgres, redis]

  business-api:
    build: ./services/business-api
    depends_on: [postgres, redis]

  admin-api:
    build: ./services/admin-api
    depends_on: [postgres]

  postgres:
    image: postgres:15-alpine
    environment:
      - POSTGRES_DB=iam_db
      - POSTGRES_USER=iam
      - POSTGRES_PASSWORD=password
    volumes:
      - ./postgres/data:/var/lib/postgresql/data
      - ./postgres/init:/docker-entrypoint-initdb.d
    ports: ["5432:5432"]

  redis:
    image: redis:7-alpine
    volumes:
      - ./redis/data:/data
    ports: ["6379:6379"]
```

### 7.3 高可用部署架构（Phase 2+）

```
                         ┌─────────────────┐
                         │   负载均衡器      │
                         │ (SLB/ALB/Nginx) │
                         └────────┬────────┘
                                  │
              ┌───────────────────┼───────────────────┐
              │                   │                   │
     ┌────────▼────────┐ ┌───────▼────────┐ ┌───────▼────────┐
     │  Auth API Pod   │ │ Business API   │ │  Admin API     │
     │  (N Pods)        │ │ Pod (N Pods)   │ │  Pod (N Pods)  │
     └────────┬────────┘ └───────┬────────┘ └───────┬────────┘
              │                   │                   │
              └───────────────────┼───────────────────┘
                                  │
                    ┌─────────────┴─────────────┐
                    │                           │
           ┌────────▼────────┐        ┌─────────▼────────┐
           │  PostgreSQL     │        │     Redis        │
           │  (主从/读写分离) │        │   (主从/Sentinel) │
           └─────────────────┘        └──────────────────┘
```

**扩展性设计：**
- **水平扩展：** 各 API 服务无状态，可随时增加 Pod 数量
- **Redis 集群：** Phase 2 升级到 Redis Cluster，支持分片
- **PostgreSQL 主从：** 读写分离，主库写入，从库读取
- **数据库连接池：** PgBouncer 管理 PostgreSQL 连接池

### 7.4 环境划分

| 环境 | 用途 | 规模 |
|------|------|------|
| **开发环境** | 本地 Docker Compose | 单机 |
| **测试环境** | CI/CD 自动部署 | 2 核 4G 最低配置 |
| **预发布环境** | 生产前验收 | 2 核 8G |
| **生产环境** | 正式对外服务 | 按需扩展 |

### 7.5 CI/CD 流程

```
Code Push → GitHub/Gitea
    ↓
GitHub Actions / Jenkins
    ↓
1. 单元测试 + 代码质量检查
    ↓
2. Docker 镜像构建 + 推送镜像仓库
    ↓
3. 部署到测试环境 → 集成测试
    ↓
4. (手动确认) 部署到预发布环境
    ↓
5. (手动确认) 滚动部署到生产环境
```

---

## 八、MVP 实现路径

### 8.1 Sprint 规划

#### Sprint 1（2 周）：基础设施 + 核心认证
**目标：** 能跑通登录/注册流程

| 任务 | 说明 |
|------|------|
| 项目脚手架搭建 | FastAPI 项目结构、依赖管理、配置管理 |
| 数据库迁移 | PostgreSQL 表创建、数据初始化 |
| Redis 连接 | Token 存储、验证码存储 |
| 手机号+验证码登录 | `/auth/login/phone` |
| 邮箱+密码登录 | `/auth/login/email` |
| 验证码发送 | `/auth/send_code`（接入短信/邮箱服务商） |
| JWT Token 签发 | AccessToken + RefreshToken |
| Token 验证中间件 | 鉴权中间件 |
| 注册流程 | `/auth/register` |
| 登出 | `/auth/logout`（Token 吊销） |

**交付物：** 用户能注册账号并登录，获取 Token

#### Sprint 2（2 周）：Token 深化 + 基础 RBAC
**目标：** Token 体系完整，RBAC 可用

| 任务 | 说明 |
|------|------|
| RefreshToken 轮换 | 每次 refresh 生成新 RefreshToken |
| Token 吊销机制 | Redis Blacklist + PG 持久化 |
| 登录失败锁定 | 连续失败锁定账户 |
| 角色管理 CRUD | `/api/v1/roles/*` |
| 权限管理 CRUD | `/api/v1/permissions/*` |
| 分配角色给用户 | `/api/v1/users/{id}/roles` |
| 权限校验中间件 | 在 API 网关校验用户权限 |
| 用户管理 CRUD | `/api/v1/users/*` |
| 修改密码 | `/auth/user/password` |

**交付物：** 完整的用户管理和权限控制体系

#### Sprint 3（2 周）：第三方登录 + API Key
**目标：** OAuth2.0 接入，开发者 API 可用

| 任务 | 说明 |
|------|------|
| OAuth2.0 授权码流程 | `/oauth/authorize` + `/oauth/token` |
| 微信登录接入 | 微信 OAuth2.0 |
| Google 登录接入 | Google OAuth2.0 |
| 支付宝登录接入 | 支付宝 OAuth2.0 |
| OAuth 用户绑定/解绑 | 已有账号绑定第三方 |
| API Key 管理 | `/open/v1/keys/*` |
| API Key 签名验证 | HMAC-SHA256 |
| Open API 限流 | 按 API Key 限流 |
| OIDC 发现文档 | `/.well-known/openid-configuration` |

**交付物：** 支持三种 OAuth 登录，开发者可申请 API Key

#### Sprint 4（2 周）：多租户 + 管理后台
**目标：** 完整的租户隔离和管理能力

| 任务 | 说明 |
|------|------|
| 租户创建（注册流程） | 租户注册 |
| 租户管理 CRUD | `/admin/v1/tenants/*` |
| 租户配置 | Logo/主题/套餐限制 |
| 审计日志 | 记录所有敏感操作 |
| 平台统计 | 用户数、API 调用量统计 |
| 套餐限制逻辑 | 免费版限制租户数/API 调用 |
| Redis 清理任务 | 过期 Token 定期清理 |
| Docker Compose 部署 | 一键部署 |
| 基础运维脚本 | 备份、监控启动 |

**交付物：** 可对外运营的 SaaS 平台

### 8.2 MVP 验收标准

| # | 功能 | 验收条件 |
|---|------|---------|
| 1 | 手机号登录 | 用户输入手机号+验证码，成功获取 AccessToken + RefreshToken |
| 2 | 邮箱登录 | 用户输入邮箱+密码，成功登录 |
| 3 | Token 刷新 | 用 RefreshToken 换取新的 AccessToken |
| 4 | 登出吊销 | 登出后原 Token 无法使用 |
| 5 | 用户管理 | 管理员可增删改查用户 |
| 6 | 角色分配 | 可给用户分配角色 |
| 7 | 权限校验 | 无权限用户访问受保护 API 返回 403 |
| 8 | 租户隔离 | 租户 A 无法看到租户 B 的数据 |
| 9 | 微信登录 | 可通过微信授权登录 |
| 10 | API Key | 开发者可申请 API Key 并调用 API |
| 11 | Docker 部署 | `docker-compose up` 可启动完整服务 |
| 12 | OpenAPI 文档 | Swagger UI 可访问并测试所有接口 |

### 8.3 Phase 2 迭代计划（不在 MVP 范围）

| 功能 | 优先级 | 说明 |
|------|--------|------|
| SSO 单点登录 | P1 | SAML2 / OIDC 联邦登录 |
| MFA/2FA | P1 | TOTP + 短信二次认证 |
| 审计日志查询 | P1 | 登录审计、操作日志 |
| 设备指纹 | P2 | 异地登录告警 |
| ABAC 动态权限 | P2 | 基于属性动态判断 |
| 多语言 SDK | P2 | Python / Go / Java / JS SDK |
| WebAuthn / FIDO2 | P2 | 无密码认证 |
|  LDAP / AD 集成 | P3 | 企业已有账户体系对接 |
| 社交登录扩展 | P3 | 钉钉、企业微信、飞书 |

---

## 九、非功能性设计

### 9.1 性能目标

| 指标 | 目标值 |
|------|--------|
| API P99 延迟 | < 200ms |
| Token 验证延迟 | < 10ms |
| 登录成功率 | > 99.9% |
| 系统可用性 | > 99.5% |
| 最大并发用户 | 1000（MVP），水平扩展无上限 |

### 9.2 监控与告警

```
监控体系:
├── Metrics: Prometheus + Grafana
│   ├── API QPS / 延迟 / 错误率
│   ├── Redis 内存 / 连接数
│   └── PostgreSQL 连接池 / QPS
├── Logs: 结构化日志 → Loki / ELK
│   └── 请求链路追踪 (RequestID)
└── Alerts: AlertManager + 钉钉/企业微信
    └── CPU > 80%、错误率 > 1%、Token 吊销异常
```

### 9.3 备份策略

| 数据 | 频率 | 保留 |
|------|------|------|
| PostgreSQL 全量备份 | 每天 | 30 天 |
| PostgreSQL 增量备份（WAL） | 每 15 分钟 | 7 天 |
| Redis 数据 | RDB + AOF 混合 | 从库保障 |
| 审计日志 | 写入后不可修改 | 永久保留（加密） |

---

## 十、风险与对策

| 风险 | 等级 | 对策 |
|------|------|------|
| 验证码被刷 | 高 | IP 限流 + 行为验证码 + 图形验证码 |
| JWT 私钥泄露 | 极高 | 私钥使用云 KMS/HSM 管理，不存代码库 |
| 第三方 OAuth 回调被伪造 | 中 | 严格校验 state 参数 + PKCE |
| 数据库被拖库 | 极高 | 敏感字段 AES-256 加密 + 密码 bcrypt |
| Redis 被攻击 | 高 | 强密码 + ACL + 网络隔离 |
| 租户数据泄露 | 极高 | PostgreSQL RLS + 代码 review 强制检查 tenant_id |
| 登录密码被爆破 | 中 | 限流 + 账户锁定 + 密码强度策略 |

---

## 附录

### A. 命名规范

```
表名: snake_case, 复数形式
  users, roles, permissions, audit_logs

字段名: snake_case
  user_id, created_at, tenant_id

API 路径: kebab-case
  /api/v1/user-roles, /auth/login/phone

权限代码: resource:action
  user:create, role:read, system:tenant:manage
```

### B. 参考资料

- [OAuth 2.0 RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749)
- [OIDC Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [JWT RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519)
- [PostgreSQL Row Level Security](https://www.postgresql.org/docs/current/ddl-rowsecurity.html)
- [FastAPI Documentation](https://fastapi.tiangolo.com/)

---

> 文档结束
> 如有疑问请联系架构设计团队

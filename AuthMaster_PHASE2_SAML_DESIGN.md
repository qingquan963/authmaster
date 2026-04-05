# AuthMaster SAML 2.0 协议支持 — 架构设计文档
> Phase 2-4 | 版本 1.0 | 2026-04-03

---

## 目录

1. [概述与目标](#1-概述与目标)
2. [技术架构总览](#2-技术架构总览)
3. [数据库设计](#3-数据库设计)
4. [SAML 2.0 SP 端点实现](#4-saml-20-sp-端点实现)
5. [IdP 配置管理](#5-idp-配置管理)
6. [SAML Response 验证流程](#6-saml-response-验证流程)
7. [用户映射与绑定](#7-用户映射与绑定)
8. [SP 元数据](#8-sp-元数据)
9. [API 规格](#9-api-规格)
10. [安全考量](#10-安全考量)
11. [依赖与库选型](#11-依赖与库选型)
12. [目录结构](#12-目录结构)
13. [实现阶段规划](#13-实现阶段规划)

---

## 1. 概述与目标

### 1.1 背景

AuthMaster 已完成：
- Sprint 1-4：核心认证、RBAC
- MFA（多因素认证）
- ABAC（基于属性的访问控制）
- 主动防御（暴力破解检测、异常登录告警）
- OAuth2.0/OIDC 第三方登录（Sprint 3）

### 1.2 目标

实现 **SAML 2.0 SP（Service Provider）** 功能，使 AuthMaster 能够：
- 作为受信任的 SP，接入企业级 IdP（Okta、Azure AD、Keycloak、Shibboleth 等）
- 支持企业用户通过 SSO 单点登录
- 管理员可配置和管理多个 IdP

### 1.3 核心能力

| 能力 | 说明 |
|------|------|
| SP 元数据暴露 | `/saml/metadata` 提供符合规范的 XML 元数据 |
| SSO 登录发起 | `/saml/login?Idp=xxx` 初始化 SAML AuthnRequest，重定向至 IdP |
| ACS 处理 | `POST /saml/acs` 接收并验证 SAML Response，创建/关联会话 |
| SLO 支持 | `GET/POST /saml/slo` 支持 Single Logout |
| IdP 配置管理 | 管理员可 CRUD 多 IdP 配置，支持 XML 元数据上传 |
| 用户绑定 | SAML NameID ↔ 本地用户账号绑定，支持自动注册 |
| 加密/签名 | Assertion 加密（可选）、Response/Assertion 签名验证 |

---

## 2. 技术架构总览

```
Browser/Client
    │
    │ HTTPS
    ▼
┌──────────────────────────────────────────────────────┐
│               AuthMaster (SP)                         │
│  ┌────────────────────────────────────────────────┐  │
│  │           FastAPI Application                   │  │
│  │  ┌────────────┐  ┌────────────┐  ┌──────────┐  │  │
│  │  │ SAML Router│  │ Admin API  │  │  Auth    │  │  │
│  │  │ /saml/*   │  │ /admin/*   │  │ /auth/*  │  │  │
│  │  └────────────┘  └────────────┘  └──────────┘  │  │
│  │                                                 │  │
│  │  ┌──────────────────────────────────────────┐  │  │
│  │  │          SAML Service Layer               │  │  │
│  │  │  - SamlContext (request state management) │  │  │
│  │  │  - IdpConfigService (IdP 配置读写)        │  │  │
│  │  │  - ResponseValidator (签名/时效验证)      │  │  │
│  │  │  - AttributeMapper (SAML Attr → User字段) │  │  │
│  │  │  - UserBindingService (绑定管理)           │  │  │
│  │  └──────────────────────────────────────────┘  │  │
│  └────────────────────────────────────────────────┘  │
│                     │                                │
│         ┌───────────┼───────────┐                   │
│         ▼           ▼           ▼                   │
│  ┌────────────┐ ┌──────────┐ ┌────────────┐          │
│  │ PostgreSQL │ │  Redis   │ │ Filesystem │          │
│  │  (async)   │ │(sessions)│ │ (SP密钥对)  │          │
│  └────────────┘ └──────────┘ └────────────┘          │
└──────────────────────────────────────────────────────┘
    │                      ▲
    │  SAML Redirect/POST  │
    ▼                      │
┌──────────────────────────────────────────────────────┐
│        Enterprise IdP (Okta/Azure AD/Keycloak)     │
└──────────────────────────────────────────────────────┘
```

### 2.1 核心组件

| 组件 | 职责 | 技术选型 |
|------|------|---------|
| `SamlContext` | 管理 SAML 会话状态（AuthnRequest、InResponseTo 等） | Redis + 5min TTL |
| `ResponseValidator` | SAML Response 完整验证链 | `python3-saml` / 手写 XMLsec |
| `AttributeMapper` | SAML Attribute → User 字段映射规则引擎 | Pydantic + JSONPath |
| `SpMetadataGenerator` | 生成/签名 SP XML 元数据文档 | lxml + `python3-saml` |
| `IdpConfigService` | IdP 配置的 CRUD + XML 解析 | SQLAlchemy async |

---

## 3. 数据库设计

### 3.1 新增表

#### `saml_idp_config` — IdP 配置表

```sql
CREATE TABLE saml_idp_config (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES auth_tenants(id) ON DELETE CASCADE,
    name            VARCHAR(255) NOT NULL,                    -- 展示名称，如 "Okta Production"
    entity_id       VARCHAR(1024) NOT NULL,                  -- IdP EntityID (唯一)
    sso_url         VARCHAR(1024) NOT NULL,                 -- IdP SSO Endpoint
    slo_url         VARCHAR(1024),                          -- IdP SLO Endpoint (可选)
    x509_cert       TEXT NOT NULL,                          -- IdP X.509 证书（PEM）
    sign_algorithm  VARCHAR(20) NOT NULL DEFAULT 'RSA-SHA256', -- RSA-SHA256 / RSA-SHA512
    want_assertions_signed  BOOLEAN NOT NULL DEFAULT TRUE,  -- 要求 IdP 签名 Assertion
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,

    -- Attribute 映射配置（JSON）
    attribute_mapping JSONB NOT NULL DEFAULT '{
      "email": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
      "name": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
      "department": "department"
    }',

    -- 高级配置
    name_id_format  VARCHAR(100) DEFAULT 'emailAddress',     -- 期望的 NameID 格式
    acs_url         VARCHAR(1024),                          -- 覆盖默认 ACS URL
    metadata_xml    TEXT,                                    -- 原始 IdP 元数据 XML
    metadata_url    VARCHAR(1024),                          -- IdP 元数据 URL（可选）

    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by      UUID REFERENCES auth_users(id),

    CONSTRAINT uq_tenant_idp_entity_id UNIQUE (tenant_id, entity_id)
);

CREATE INDEX ix_saml_idp_config_tenant ON saml_idp_config(tenant_id, enabled);
```

#### `saml_user_bindings` — 用户与 IdP 绑定表

```sql
CREATE TABLE saml_user_bindings (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
    idp_config_id   UUID NOT NULL REFERENCES saml_idp_config(id) ON DELETE CASCADE,
    name_id         VARCHAR(1024) NOT NULL,                 -- IdP 返回的 NameID 值
    name_id_format  VARCHAR(100) NOT NULL,                   -- NameID Format
    attributes_json JSONB NOT NULL DEFAULT '{}',            -- 本次登录捕获的 SAML Attributes
    linked_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_user_idp_nameid UNIQUE (user_id, idp_config_id, name_id)
);

CREATE INDEX ix_saml_bindings_user ON saml_user_bindings(user_id);
CREATE INDEX ix_saml_bindings_idp_nameid ON saml_user_bindings(idp_config_id, name_id);
```

#### `saml_sp_config` — SP 配置表（每租户 SP 设置）

```sql
CREATE TABLE saml_sp_config (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID UNIQUE NOT NULL REFERENCES auth_tenants(id) ON DELETE CASCADE,

    -- SP EntityID（默认使用 URL 推导，可覆盖）
    entity_id           VARCHAR(1024) NOT NULL,

    -- SP 证书（SP 签名/加密密钥对）
    sp_cert_pem         TEXT NOT NULL,      -- SP X.509 证书
    sp_key_pem          TEXT NOT NULL,      -- SP 私钥（加密存储或从 KMS 读取）
    cert_not_before     TIMESTAMPTZ,
    cert_not_after      TIMESTAMPTZ,

    -- Assertion 加密（可选，默认只签名不加密）
    want_assertions_encrypted  BOOLEAN NOT NULL DEFAULT FALSE,
    encryption_algorithm VARCHAR(30) NOT NULL DEFAULT 'AES-256-CBC',

    -- SSO 行为配置
    auto_register_new_users   BOOLEAN NOT NULL DEFAULT TRUE,
    default_role_id   UUID REFERENCES auth_roles(id),

    -- IdP 发起登录是否允许（默认不允许，只允许 SP 发起）
    allow_idp_initiated   BOOLEAN NOT NULL DEFAULT FALSE,

    -- 签名配置
    sign_requests        BOOLEAN NOT NULL DEFAULT TRUE,
    sign_algorithm       VARCHAR(20) NOT NULL DEFAULT 'RSA-SHA256',

    -- 强认证要求
    require_mfa_for_saml BOOLEAN NOT NULL DEFAULT FALSE,

    -- NameID 格式偏好
    preferred_name_id_format VARCHAR(100) DEFAULT 'emailAddress',

    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

#### `saml_authn_requests` — 请求状态表（用于 InResponseTo 验证）

```sql
CREATE TABLE saml_authn_requests (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    idp_config_id   UUID NOT NULL,

    request_id      VARCHAR(256) NOT NULL,      -- SAML AuthnRequest ID (_xx)
    in_response_to  VARCHAR(256),                -- 期望的 InResponseTo 值

    -- 请求参数快照
    name_id_policy  VARCHAR(100),
    assertion_consumer_service_url VARCHAR(1024),
    protocol_binding VARCHAR(100),

    -- 状态
    status          VARCHAR(20) NOT NULL DEFAULT 'pending',  -- pending / used / expired / cancelled
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ NOT NULL,       -- 请求有效期（默认 10 分钟）
    used_at         TIMESTAMPTZ,

    CONSTRAINT uq_saml_request_id UNIQUE (request_id)
);

CREATE INDEX ix_authn_requests_expiry ON saml_authn_requests(expires_at) WHERE status = 'pending';
CREATE INDEX ix_authn_requests_in_response ON saml_authn_requests(in_response_to) WHERE status = 'pending';
```

### 3.2 现有表必要改动

```sql
-- auth_users 表新增字段
ALTER TABLE auth_users ADD COLUMN saml_last_login_idp  UUID REFERENCES saml_idp_config(id);
ALTER TABLE auth_users ADD COLUMN saml_last_name_id    VARCHAR(1024);

-- auth_tenants 表新增字段（可选，方便全局开关）
ALTER TABLE auth_tenants ADD COLUMN saml_enabled  BOOLEAN NOT NULL DEFAULT FALSE;
```

---

## 4. SAML 2.0 SP 端点实现

### 4.1 SP 元数据端点

```
GET /saml/metadata
```

返回符合 SAML 2.0 SP 元数据规范的 XML 文档：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     entityID="https://authmaster.example.com/saml/metadata">
    <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"
                        AuthnRequestsSigned="true"
                        WantAssertionsSigned="true">
        <md:KeyDescriptor use="signing">
            <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                <ds:X509Data>
                    <ds:X509Certificate>...SP_CERT_CONTENT...</ds:X509Certificate>
                </ds:X509Data>
            </ds:KeyInfo>
        </md:KeyDescriptor>
        <md:KeyDescriptor use="encryption">
            <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                <ds:X509Data>
                    <ds:X509Certificate>...SP_ENCRYPT_CERT_CONTENT...</ds:X509Certificate>
                </ds:X509Data>
            </ds:KeyInfo>
            <md:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes256-cbc"/>
        </md:KeyDescriptor>
        <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
        <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>
        <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>
        <md:AssertionConsumerService index="0"
                                     Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                     Location="https://authmaster.example.com/saml/acs"/>
        <md:AssertionConsumerService index="1"
                                     Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"
                                     Location="https://authmaster.example.com/saml/acs"/>
        <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                                Location="https://authmaster.example.com/saml/slo"/>
        <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                Location="https://authmaster.example.com/saml/slo"/>
    </md:SPSSODescriptor>
</md:EntityDescriptor>
```

**实现要点：**
- XML 必须包含正确的 namespace
- 支持 HTTP-POST 和 HTTP-Redirect（Artifact 可选）绑定
- NameIDFormat 按 SP 配置列出支持格式
- 签名：可对整个元数据文档签名（使用 SP 私钥）

### 4.2 SSO 登录初始化

```
GET /saml/login?Idp=<entity_id>&ReturnUrl=<url>&NameIDFormat=<format>
```

**流程：**

1. 根据 `Idp` 查询 `saml_idp_config`，获取 IdP 配置
2. 生成 `AuthnRequest`（SAML 2.0 XML）
3. 将 `request_id` 存入 `saml_authn_requests` 表（状态=pending，TTL=10min）
4. 将 `request_id` → `ReturnUrl` 映射存入 Redis（TTL=10min）
5. 使用 HTTP-Redirect 绑定（Deflate 压缩 + Base64 编码）或 HTTP-POST 绑定重定向到 IdP

**AuthnRequest 关键字段：**

```xml
<samlp:AuthnRequest
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="_<unique_request_id>"
    Version="2.0"
    IssueInstant="<timestamp>"
    Destination="<IdP SSO URL>"
    AssertionConsumerServiceURL="<SP ACS URL>"
    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
    <saml:Issuer><SP EntityID></saml:Issuer>
    <samlp:NameIDPolicy Format="<NameIDFormat>" AllowCreate="true"/>
</samlp:AuthnRequest>
```

**注意：** `InResponseTo` 值等于 `AuthnRequest` 的 `ID`

### 4.3 ACS (Assertion Consumer Service)

```
POST /saml/acs
Content-Type: application/x-www-form-urlencoded

SAMLResponse=<base64_encoded_saml_response>&RelayState=<optional_relay_state>
```

**流程：**

```
1. 解析 SAMLResponse（Base64 解码 → XML）
2. 查找 InResponseTo，对应 saml_authn_requests 中 pending 记录
   → 不存在且不允许 IdP-Initiated → 拒绝
   → 存在但已过期 → 拒绝
   → 存在且未使用 → 标记为 used
3. 调用 ResponseValidator 完整验证（见第 6 节）
4. 提取 NameID + Attributes
5. 调用 AttributeMapper 映射用户字段
6. 调用 UserBindingService 完成用户登录/注册
7. 创建本地会话（写入 Redis）
8. 返回 RelayState 中的 ReturnUrl 或默认首页
```

### 4.4 SLO (Single Logout)

```
GET  /saml/slo?SAMLRequest=<encoded>&RelayState=<url>    # HTTP-Redirect
POST /saml/slo                                             # HTTP-POST
```

**SLO 流程支持两种模式：**

**SP-Initiated SLO：**
1. 用户在 AuthMaster 点击登出
2. AuthMaster 生成 `LogoutRequest` → 重定向到 IdP SLO URL
3. IdP 处理后重定向回 `SLOReturnUrl`

**IdP-Initiated SLO：**
1. IdP 发起 `LogoutRequest` → AuthMaster SLO 端点
2. AuthMaster 验证请求，查找对应会话
3. 本地登出该用户（可选：向其他 SP 发起连锁登出）
4. 返回 `LogoutResponse`

### 4.5 IdP-Initiated 登录

当 `allow_idp_initiated=True` 时：
- ACS 端点直接接受无 `InResponseTo` 的 SAML Response
- 必须额外验证 `AudienceRestriction` 包含本 SP EntityID
- 需要白名单 IdP（通过 `entity_id` 识别）

---

## 5. IdP 配置管理

### 5.1 IdP 元数据 XML 解析

```python
class IdpMetadataParser:
    """解析 SAML 2.0 IdP 元数据 XML"""

    NAMESPACES = {
        'md':  'urn:oasis:names:tc:SAML:2.0:metadata',
        'ds':  'http://www.w3.org/2000/09/xmldsig#',
        'saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
    }

    def parse(self, metadata_xml: str) -> dict:
        """从 IdP 元数据 XML 提取关键字段"""
        root = etree.fromstring(metadata_xml.encode())
        idp_sso = root.find(f"{{{self.NAMESPACES['md']}}}IDPSSODescriptor")

        entity_id = root.get("entityID")

        # SSO URL（优先取 HTTP-Redirect 绑定）
        sso_services = idp_sso.findall(f"{{{self.NAMESPACES['md']}}}SingleSignOnService")
        sso_url = next(
            (s.get("Location") for s in sso_services
             if s.get("Binding") == "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"),
            None
        )

        # SLO URL
        slo_services = idp_sso.findall(f"{{{self.NAMESPACES['md']}}}SingleLogoutService")
        slo_url = next(
            (s.get("Location") for s in slo_services
             if s.get("Binding") == "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"),
            None
        )

        # X.509 签名证书
        signing_key = idp_sso.find(
            f"{{{self.NAMESPACES['md']}}}KeyDescriptor[@use='signing']/"
            f"{{{self.NAMESPACES['ds']}}}KeyInfo/"
            f"{{{self.NAMESPACES['ds']}}}X509Data/"
            f"{{{self.NAMESPACES['ds']}}}X509Certificate"
        )
        x509_cert = signing_key.text.strip() if signing_key is not None else None

        # NameID 格式
        name_id_formats = [
            f.text for f in idp_sso.findall(f"{{{self.NAMESPACES['md']}}}NameIDFormat")
        ]

        return {
            "entity_id": entity_id,
            "sso_url": sso_url,
            "slo_url": slo_url,
            "x509_cert": self._format_cert_pem(x509_cert),
            "name_id_formats": name_id_formats,
            "metadata_xml": metadata_xml,
        }

    def _format_cert_pem(self, cert_text: str | None) -> str:
        """将证书内容格式化为标准 PEM 格式"""
        if not cert_text:
            return ""
        # 移除空白和换行，重新格式化为每行 64 字符
        cert_b64 = cert_text.replace(" ", "").replace("\n", "")
        lines = [cert_b64[i:i+64] for i in range(0, len(cert_b64), 64)]
        return "-----BEGIN CERTIFICATE-----\n" + "\n".join(lines) + "\n-----END CERTIFICATE-----"
```

### 5.2 IdP 配置 CRUD

| 操作 | 方法 | 路径 |
|------|------|------|
| 列表 | `GET /admin/v1/saml/idp` | 返回租户下所有 IdP 配置 |
| 详情 | `GET /admin/v1/saml/idp/{id}` | 返回单个 IdP 配置 |
| 创建 | `POST /admin/v1/saml/idp` | 添加 IdP（支持 XML 上传） |
| 更新 | `PUT /admin/v1/saml/idp/{id}` | 更新 IdP 配置 |
| 删除 | `DELETE /admin/v1/saml/idp/{id}` | 删除 IdP（软删） |
| 测试 | `POST /admin/v1/saml/idp/{id}/test` | 发起测试 SSO 登录 |
| 元数据刷新 | `POST /admin/v1/saml/idp/{id}/refresh-metadata` | 从 metadata_url 重新拉取解析 |

### 5.3 IdP 配置验证

```python
class IdpConfigValidator:
    """IdP 配置验证"""

    SUPPORTED_ALGORITHMS = ["RSA-SHA256", "RSA-SHA512"]

    async def validate(self, config: IdpConfigCreate) -> list[str]:
        errors = []

        # 1. entity_id 唯一性（租户内）
        if await self._entity_id_exists(config.entity_id):
            errors.append(f"EntityID '{config.entity_id}' 已存在")

        # 2. SSO URL 格式 + HTTPS 强制
        if not config.sso_url.startswith("https://"):
            errors.append("SSO URL 必须使用 HTTPS")

        # 3. X.509 证书有效性
        try:
            from cryptography import x509
            cert = x509.load_pem_x509_certificate(config.x509_cert.encode())
        except Exception:
            errors.append("X.509 证书格式无效或不受支持")

        # 4. SLO URL 格式验证（如果提供）
        if config.slo_url and not config.slo_url.startswith("https://"):
            errors.append("SLO URL 必须使用 HTTPS")

        # 5. sign_algorithm 必须是支持列表中的值
        if config.sign_algorithm not in self.SUPPORTED_ALGORITHMS:
            errors.append(f"sign_algorithm 必须是 {self.SUPPORTED_ALGORITHMS} 之一")

        return errors
```

---

## 6. SAML Response 验证流程

`ResponseValidator` 必须按以下顺序执行所有检查，**任一步失败则拒绝整个 Response**：

```
Step 1:  [解码]       Base64 解码 SAMLResponse → XML 解析
Step 2:  [InResponseTo] 有值 → 必须在 saml_authn_requests 中存在且为 pending
                      无值   → 仅在 allow_idp_initiated=True 时允许
Step 3:  [Issuer]     SAMLResponse.Issuer == IdP Config 中的 entity_id
Step 4:  [Destination] SAMLResponse.Destination == SP ACS URL
Step 5:  [时间有效性]  NotBefore-5min ≤ now ≤ NotOnOrAfter
Step 6:  [Response签名] 用 IdP X.509 证书验签 <Response> 签名
Step 7:  [Assertion签名] WantAssertionsSigned=True 时必须有 Assertion 签名
Step 8:  [AudienceRestriction] Assertion.AudienceRestriction.Audience == SP EntityID
Step 9:  [NameID]     Format 必须在 IdP 支持列表中，值非空
Step 10: [解密]        若加密 → 用 SP 私钥 RSA-OAEP 解密 AES Key → AES-256-CBC 解密
Step 11: [重放防护]    Assertion ID 写入 Redis，TTL=Assertion 有效时长，已存在则拒绝
         ↓
✅ 全部通过 → 提取 NameID + Attributes
```

### 6.1 签名验证

```python
import xmlsec
from lxml import etree

class SamlSignatureVerifier:
    """SAML XML 签名验证器"""

    def verify_response_signature(self, response_xml: etree._Element, idp_cert_pem: str) -> bool:
        """验证 <Response> 或 <Assertion> 的 XML 签名"""
        sig = xmlsec.tree.find_node(response_xml, xmlsec.Node.SIGNATURE)
        if sig is None:
            return False

        key = xmlsec.Key.from_memory(idp_cert_pem.encode(), xmlsec.KeyFormat.CERT_PEM)
        dsig_ctx = xmlsec.SignatureContext()
        dsig_ctx.key = key
        try:
            dsig_ctx.verify(sig)
            return True
        except xmlsec.VerificationError:
            return False
```

### 6.2 Assertion 解密

```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.primitives import hashes
from cryptography import x509
import base64

class AssertionDecryptor:
    """使用 SP 私钥解密加密的 Assertion (AES-256-CBC)"""

    def decrypt_assertion(
        self,
        encrypted_data: etree._Element,
        sp_private_key_pem: str,
    ) -> etree._Element:
        ns_enc = "http://www.w3.org/2009/xmlenc11"

        # 1. RSA-OAEP 解密 AES Key
        encrypted_key_elem = encrypted_data.find(f".//{{{ns_enc}}}EncryptedKey")
        encrypted_key_b64 = encrypted_key_elem.find(
            f".//{{{ns_enc}}}CipherData/{{{ns_enc}}}CipherValue"
        ).text

        from cryptography.hazmat.primitives import serialization
        private_key = serialization.load_pem_private_key(
            sp_private_key_pem.encode(), password=None
        )

        encrypted_key = base64.b64decode(encrypted_key_b64)
        aes_key = private_key.decrypt(
            encrypted_key,
            rsa_padding.OAEP(
                mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            )
        )

        # 2. AES-256-CBC 解密 CipherData
        cipher_value_elem = encrypted_data.find(
            f".//{{{ns_enc}}}CipherData/{{{ns_enc}}}CipherValue"
        )
        cipher_value = base64.b64decode(cipher_value_elem.text)

        iv = cipher_value[:16]
        actual_ciphertext = cipher_value[16:]

        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

        return etree.fromstring(plaintext)
```

### 6.3 重放攻击防护

```python
class ReplayCache:
    """使用 Redis 防止 SAML Response 重放攻击"""

    def __init__(self, redis: Redis):
        self.redis = redis

    def check_and_mark(self, assertion_id: str, valid_until: datetime) -> bool:
        """
        检查 assertion_id 是否已使用。
        未使用 → 写入 Redis 并返回 True
        已存在 → 返回 False（拒绝重放）
        """
        redis_key = f"saml:assertion_used:{assertion_id}"
        ttl_seconds = int((valid_until - datetime.utcnow()).total_seconds())
        if ttl_seconds <= 0:
            return False  # 已过期，无需检查

        # SET NX: key 不存在才写入（原子操作）
        result = self.redis.set(redis_key, "1", nx=True, ex=ttl_seconds)
        return result is not None
```

---

## 7. 用户映射与绑定

### 7.1 Attribute 映射

```python
from pydantic import BaseModel
from typing import Optional

class AttributeMappingRule(BaseModel):
    """SAML Attribute → 用户字段映射规则"""
    saml_attribute: str           # e.g., "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
    user_field: str               # e.g., "email"
    required: bool = False
    default: Optional[str] = None

class AttributeMapper:
    """将 SAML Attributes 映射为用户字段"""

    def __init__(self, mapping_rules: list[AttributeMappingRule]):
        self.rules = mapping_rules

    def map(self, saml_attributes: dict[str, list[str]]) -> dict[str, Any]:
        result = {}
        for rule in self.rules:
            values = saml_attributes.get(rule.saml_attribute, [])
            if not values and rule.required:
                raise AttributeMappingError(f"缺少必填属性: {rule.saml_attribute}")
            result[rule.user_field] = values[0] if values else rule.default
        return result
```

**默认映射规则（可管理员配置）：**

```json
[
  { "saml_attribute": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", "user_field": "email", "required": true },
  { "saml_attribute": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname", "user_field": "first_name", "required": false },
  { "saml_attribute": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname", "user_field": "last_name", "required": false },
  { "saml_attribute": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name", "user_field": "full_name", "required": false },
  { "saml_attribute": "department", "user_field": "department", "required": false },
  { "saml_attribute": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/groups", "user_field": "groups", "required": false }
]
```

### 7.2 用户绑定流程

```
输入: NameID + mapped_attributes + idp_config_id

在 saml_user_bindings 中查找 (idp_config_id, name_id)
  │
  ├─ 存在 → 获取关联的 user_id
  │         → 更新 attributes_json + last_login_at
  │         → 返回已绑定用户
  │
  └─ 不存在
      │
      ├─ auto_register_new_users == False
      │   → 拒绝登录，要求管理员先绑定账号
      │
      └─ auto_register_new_users == True
          │
          ├─ 根据 email 查找已有 auth_users
          │   → 命中 → 绑定 → 返回该用户
          │   → 未命中 → 创建新用户 → 绑定 → 返回新用户
```

### 7.3 用户绑定管理 API

| 操作 | 方法 | 路径 |
|------|------|------|
| 用户已绑定 IdP 列表 | `GET /admin/v1/saml/bindings?user_id=<uuid>` | |
| 解绑 | `DELETE /admin/v1/saml/bindings/{binding_id}` | |
| 手动绑定 | `POST /admin/v1/saml/bindings` | 将已有账号绑定到 IdP |
| 批量绑定 | `POST /admin/v1/saml/bindings/bulk` | CSV 导入 NameID→用户映射 |

---

## 8. SP 元数据

### 8.1 SP 密钥对管理

```python
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from datetime import datetime, timedelta

class SpKeyManager:
    """管理 SP 签名/加密密钥对"""

    def __init__(self, storage_path: Path):
        self.cert_path = storage_path / "sp.crt"
        self.key_path = storage_path / "sp.key"
        self.storage_path = storage_path

    async def ensure_sp_keys(self, tenant_id: UUID) -> tuple[str, str]:
        """确保 SP 密钥对存在，不存在则生成（RSA 4096-bit）"""
        if self.cert_path.exists() and self.key_path.exists():
            return (self.cert_path.read_text(), self.key_path.read_text())

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)

        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"AuthMaster-{tenant_id}")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=730))
            .sign(private_key, hashes.SHA256())
        )

        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
        key_pem = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ).decode()

        self.storage_path.mkdir(parents=True, exist_ok=True)
        self.cert_path.write_text(cert_pem)
        self.key_path.write_text(key_pem)

        return (cert_pem, key_pem)

    async def rotate_keys(self, tenant_id: UUID) -> tuple[str, str]:
        """密钥轮换：生成新密钥对，保留旧密钥用于解密历史加密数据"""
        # 旧密钥移至 sp.key.old（保留以解密历史数据）
        old_key_path = self.storage_path / "sp.key.old"
        if self.key_path.exists():
            old_key_path.write_bytes(self.key_path.read_bytes())
        return await self.ensure_sp_keys(tenant_id)
```

### 8.2 元数据 XML 生成

```python
SAML_METADATA_NS = "urn:oasis:names:tc:SAML:2.0:metadata"
DS_NS = "http://www.w3.org/2000/09/xmldsig#"

class SpMetadataGenerator:
    """生成 SP 元数据 XML"""

    def generate(
        self,
        entity_id: str,
        acs_url: str,
        slo_url: str,
        sp_cert_pem: str,
        name_id_formats: list[str],
        sign_requests: bool = True,
        want_assertions_signed: bool = True,
        want_assertions_encrypted: bool = False,
    ) -> bytes:
        root = etree.Element(
            f"{{{SAML_METADATA_NS}}}EntityDescriptor",
            entityID=entity_id,
        )
        sp_sso = etree.SubElement(root, f"{{{SAML_METADATA_NS}}}SPSSODescriptor",
            protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol",
        )

        if sign_requests:
            sp_sso.set("AuthnRequestsSigned", "true")
        if want_assertions_signed:
            sp_sso.set("WantAssertionsSigned", "true")

        # KeyDescriptor (signing)
        self._add_key_descriptor(sp_sso, "signing", sp_cert_pem)

        # KeyDescriptor (encryption)
        if want_assertions_encrypted:
            self._add_key_descriptor(sp_sso, "encryption", sp_cert_pem)
            enc_method = etree.SubElement(
                etree.SubElement(sp_sso, f"{{{SAML_METADATA_NS}}}EncryptionMethod"),
                f"{{{SAML_METADATA_NS}}}EncryptionMethod"
            )
            enc_method.set("Algorithm", "http://www.w3.org/2009/xmlenc11#aes256-cbc")

        # NameIDFormat
        for fmt in name_id_formats:
            etree.SubElement(sp_sso, f"{{{SAML_METADATA_NS}}}NameIDFormat").text = fmt

        # AssertionConsumerService
        etree.SubElement(sp_sso, f"{{{SAML_METADATA_NS}}}AssertionConsumerService",
            index="0",
            Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            Location=acs_url,
        )

        # SingleLogoutService
        if slo_url:
            etree.SubElement(sp_sso, f"{{{SAML_METADATA_NS}}}SingleLogoutService",
                Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
                Location=slo_url,
            )

        return etree.tostring(root, xml_declaration=True, encoding="UTF-8", pretty_print=True)

    def _add_key_descriptor(self, parent: etree._Element, use: str, cert_pem: str) -> None:
        """添加 KeyDescriptor 节点"""
        cert_clean = cert_pem.replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "").replace("\n", "")
        cert_lines = [cert_clean[i:i+64] for i in range(0, len(cert_clean), 64)]
        cert_formatted = "\n".join(cert_lines)

        kd = etree.SubElement(parent, f"{{{SAML_METADATA_NS}}}KeyDescriptor", use=use)
        ki = etree.SubElement(kd, f"{{{DS_NS}}}KeyInfo")
        xd = etree.SubElement(ki, f"{{{DS_NS}}}X509Data")
        xc = etree.SubElement(xd, f"{{{DS_NS}}}X509Certificate")
        xc.text = cert_formatted
```

---

## 9. API 规格

### 9.1 SAML SP 端点

#### `GET /saml/metadata`

**描述：** 返回当前租户的 SP 元数据 XML

**响应：**
- `200 OK` — `Content-Type: application/samlmetadata+xml`
- `404 Not Found` — 租户未配置 SAML

#### `GET /saml/login`

**描述：** 发起 SAML SSO 登录，重定向到 IdP

**查询参数：**
| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `Idp` | string | 是 | IdP EntityID |
| `ReturnUrl` | string | 否 | 登录成功后跳转 URL（Base64 编码） |
| `NameIDFormat` | string | 否 | 覆盖默认 NameID 格式 |

**响应：** `302 Redirect` → IdP SSO URL（SAMLRequest + RelayState）

**错误：**
- `400` — 缺少 Idp 参数
- `404` — Idp 不存在或已禁用

#### `POST /saml/acs`

**描述：** 处理 IdP 返回的 SAML Response

**请求体：** `application/x-www-form-urlencoded`
```
SAMLResponse=<base64>&RelayState=<optional_base64>
```

**成功响应：** `302 Redirect` → ReturnUrl（用户会话已创建）

**错误响应：**
- `400 Bad Request` — SAMLResponse 解析失败
- `401 Unauthorized` — Response 验证失败（签名/时效等）
- `404 Not Found` — InResponseTo 无效

#### `GET /saml/slo`

**描述：** SLO 入口（支持 HTTP-Redirect 绑定）

**查询参数：** `SAMLRequest` 或 `SAMLResponse` + `RelayState`

#### `POST /saml/slo`

**描述：** SLO 入口（支持 HTTP-POST 绑定）

**请求体：** `application/x-www-form-urlencoded`

### 9.2 Admin API — IdP 配置

#### `GET /admin/v1/saml/idp`

**描述：** 列出当前租户所有 IdP 配置

**响应：** `200 OK`
```json
{
  "items": [
    {
      "id": "uuid",
      "name": "Okta Production",
      "entity_id": "http://www.okta.com/xxx",
      "sso_url": "https://company.okta.com/app/.../sso/saml",
      "enabled": true,
      "want_assertions_signed": true,
      "created_at": "2026-01-01T00:00:00Z"
    }
  ],
  "total": 1
}
```

#### `POST /admin/v1/saml/idp`

**描述：** 添加 IdP 配置（支持元数据 XML 上传）

**请求体（二选一）：**

*手动填写：*
```json
{
  "name": "Okta Production",
  "entity_id": "http://www.okta.com/xxx",
  "sso_url": "https://company.okta.com/app/.../sso/saml",
  "slo_url": "https://company.okta.com/app/.../slo/saml",
  "x509_cert": "-----BEGIN CERTIFICATE-----\n...",
  "sign_algorithm": "RSA-SHA256",
  "want_assertions_signed": true,
  "attribute_mapping": [...]
}
```

*上传元数据 XML：*
```json
{
  "name": "Okta Production",
  "metadata_xml": "<?xml version..."
}
```

**响应：** `201 Created` — 返回创建的 IdP 配置

#### `PUT /admin/v1/saml/idp/{id}`

**描述：** 更新 IdP 配置

#### `DELETE /admin/v1/saml/idp/{id}`

**描述：** 删除 IdP 配置（软删除）

### 9.3 Admin API — 用户绑定

#### `GET /admin/v1/saml/bindings`

**描述：** 查询用户绑定记录

**查询参数：** `user_id`（可选）、`idp_id`（可选）

#### `POST /admin/v1/saml/bindings`

**描述：** 手动绑定已有账号到 IdP

```json
{
  "user_id": "uuid",
  "idp_config_id": "uuid",
  "name_id": "user@company.com",
  "name_id_format": "emailAddress"
}
```

#### `DELETE /admin/v1/saml/bindings/{binding_id}`

**描述：** 解除绑定

### 9.4 Admin API — SP 配置

#### `GET /admin/v1/saml/sp-config`

**描述：** 获取当前租户 SP 配置

#### `PUT /admin/v1/saml/sp-config`

**描述：** 更新 SP 配置（如开启自动注册、加密等）

```json
{
  "auto_register_new_users": true,
  "allow_idp_initiated": false,
  "require_mfa_for_saml": false,
  "preferred_name_id_format": "emailAddress"
}
```

#### `POST /admin/v1/saml/sp-config/rotate-keys`

**描述：** 轮换 SP 签名密钥（生成新密钥对）

#### `GET /admin/v1/saml/sp-config/certificate`

**描述：** 下载 SP 证书（用于配置 IdP）

---

## 10. 安全考量

### 10.1 签名与加密

| 威胁 | 防护措施 |
|------|---------|
| Response 伪造 | Response + Assertion 必须有 IdP 有效签名 |
| Assertion 篡改 | `WantAssertionsSigned=True` 要求 Assertion 签名 |
| 中间人攻击 | 所有端点强制 HTTPS |
| 重放攻击 | Assertion ID 写入 Redis（TTL），InResponseTo 验证 |
| 密钥泄露 | SP 私钥加密存储，支持密钥轮换 |
| 旧加密数据无法解密 | 密钥轮换时保留旧私钥（sp.key.old） |

### 10.2 时间攻击防护

- NotBefore/NotOnOrAfter 验证引入 5 分钟 clock skew 容差
- 使用安全随机数生成 AuthnRequest ID

### 10.3 输入验证

- 所有 XML 输入必须先做 XML 解析（防止 XXE）
- IdP 元数据 XML 上传后进行 schema 验证
- entity_id / URL 参数必须通过正则白名单验证

### 10.4 审计日志

必须记录的 SAML 事件：

```python
class SamlAuditEvent(str, Enum):
    SSO_INITIATED = "saml.sso.initiated"          # 用户发起 SSO
    SSO_SUCCESS = "saml.sso.success"             # SSO 登录成功
    SSO_FAILED = "saml.sso.failed"                # SSO 登录失败（附失败原因）
    SLO_INITIATED = "saml.slo.initiated"          # SLO 发起
    SLO_COMPLETED = "saml.slo.completed"          # SLO 完成
    IDP_CREATED = "saml.idp.created"             # IdP 配置创建
    IDP_UPDATED = "saml.idp.updated"             # IdP 配置更新
    IDP_DELETED = "saml.idp.deleted"             # IdP 配置删除
    SP_KEY_ROTATED = "saml.sp.key_rotated"       # SP 密钥轮换
```

---

## 11. 依赖与库选型

### 11.1 核心依赖

```toml
# pyproject.toml

[project]
dependencies = [
    # SAML XML 处理
    "lxml>=5.0.0",           # XML 解析和操作
    "xmlsec>=1.3.14",       # XML 签名和加密（需要 libxml2 和 xmlsec1 系统库）
    # 或使用：
    # "python3-saml>=1.16.0",  # 完整的 python3-saml 实现（基于 lxml）
    
    # 密码学
    "cryptography>=42.0.0", # X.509 证书、RSA、AES 操作
    
    # HTTP
    "httpx>=0.27.0",        # 异步 HTTP 客户端（用于 IdP 元数据 URL 拉取）
    
    # 验证
    "pydantic>=2.5.0",
    
    # FastAPI 生态
    "fastapi>=0.110.0",
    "sqlalchemy[asyncio]>=2.0.0",
    "asyncpg>=0.29.0",
    "redis[hiredis]>=5.0.0",
]
```

### 11.2 xmlsec 系统依赖

```bash
# Ubuntu/Debian
apt-get install libxml2-dev libxmlsec1-dev libxmlsec1-openssl

# macOS
brew install libxml2 xmlsec1

# Windows — 使用预编译 wheel（xmlsec 包自带）
pip install xmlsec
```

### 11.3 替代方案：python3-saml

若自实现过于复杂，可使用 `python3-saml`（OneLogin 维护）：

```python
# 优势：完整的 SAML SP 实现，含元数据解析、签名、加密
# 劣势：依赖较多，学习曲线

from onelogin.saml2.auth import OneLogin_Saml2_Auth

# 需要提供 settings.py 格式配置
auth = OneLogin_Saml2_Auth(prepared_request, saml_settings)
auth.process_response()  # 完整验证流程
auth.get_attributes()    # 提取属性
auth.get_nameid()        # 提取 NameID
```

**推荐：** 初期使用 `python3-saml`，后期按需替换关键组件（加密库等）。

---

## 12. 目录结构

```
authmaster/
├── app/
│   ├── api/
│   │   ├── v1/
│   │   │   └── router.py              # API v1 路由汇总
│   │   └── admin/
│   │       └── v1/
│   │           ├── saml_idp.py        # IdP 配置 CRUD
│   │           ├── saml_bindings.py   # 用户绑定管理
│   │           └── saml_sp.py         # SP 配置管理
│   │
│   ├── saml/                          # 🌟 SAML 核心模块
│   │   ├── __init__.py
│   │   ├── router.py                   # /saml/* 路由
│   │   ├── context.py                  # SamlContext（请求状态管理）
│   │   ├── metadata.py                 # SP 元数据生成
│   │   ├── authn_request.py           # AuthnRequest 生成
│   │   ├── slo.py                     # SLO 处理
│   │   ├── services/
│   │   │   ├── __init__.py
│   │   │   ├── idp_config.py           # IdP 配置服务
│   │   │   ├── sp_config.py            # SP 配置服务
│   │   │   ├── user_binding.py         # 用户绑定服务
│   │   │   └── attribute_mapper.py     # Attribute 映射
│   │   ├── validators/
│   │   │   ├── __init__.py
│   │   │   ├── response.py             # Response 验证器
│   │   │   ├── signature.py             # 签名验证
│   │   │   ├── decryptor.py             # 解密器
│   │   │   └── replay.py               # 重放检测
│   │   ├── models/
│   │   │   ├── __init__.py
│   │   │   ├── idp_config.py           # SQLAlchemy model
│   │   │   ├── sp_config.py
│   │   │   ├── user_binding.py
│   │   │   └── authn_request.py
│   │   └── schemas/
│   │       ├── __init__.py
│   │       ├── idp_config.py           # Pydantic schemas
│   │       ├── sp_config.py
│   │       └── binding.py
│   │
│   ├── core/
│   │   └── security/
│   │       └── audit.py                 # 审计日志（已扩展 SAML 事件）
│   │
│   └── main.py
│
├── migrations/
│   └── versions/
│       ├── add_saml_idp_config.py
│       ├── add_saml_user_bindings.py
│       ├── add_saml_sp_config.py
│       └── add_saml_authn_requests.py
│
└── tests/
    ├── saml/
    │   ├── test_response_validation.py
    │   ├── test_signature_verification.py
    │   ├── test_attribute_mapping.py
    │   ├── test_metadata_parsing.py
    │   ├── test_sp_metadata.py
    │   └── test_end_to_end.py           # 模拟完整 SSO 流程
    └── conftest.py
```

---

## 13. 实现阶段规划

### Phase 2：SAML SP 核心（2-3 周）

**目标：** 实现最小可用 SAML SP（SP 发起的 SSO）

1. 数据库迁移（4 张新表）
2. SP 密钥对生成与管理
3. SP 元数据端点 `GET /saml/metadata`
4. `GET /saml/login` — AuthnRequest 生成 + Redirect
5. `POST /saml/acs` — Response 解析 + 基础验证（签名、时效）
6. 用户绑定（只读，依赖已有账号）
7. 集成测试（Mock IdP）

### Phase 3：IdP 配置管理 + 用户自动注册（1-2 周）

**目标：** 管理员可配置 IdP，支持新用户自动注册

1. IdP 元数据 XML 解析
2. Admin API — IdP CRUD
3. Attribute Mapper（管理员可配置映射规则）
4. 自动注册流程
5. IdP 配置验证（证书、URL 格式）

### Phase 4：高级功能（1-2 周）

**目标：** 完整 SAML 2.0 支持

1. SLO（SP-Initiated + IdP-Initiated）
2. IdP-Initiated 登录支持
3. Assertion 加密（AES-256-CBC 解密）
4. 重放攻击防护（Redis）
5. SP 密钥轮换
6. 审计日志完善
7. 与 MFA 模块集成（`require_mfa_for_saml`）

### 里程碑检查清单

```
□ SP 元数据 XML 符合 SAML 2.0 spec（通过 SAML 官方 validator）
□ Okta 集成测试通过
□ Azure AD 集成测试通过
□ Keycloak 集成测试通过
□ Assertion 加密/解密测试通过
□ 密钥轮换后历史加密数据解密测试通过
□ 重放攻击防护测试通过
□ 审计日志完整性验证
□ Load test：1000 concurrent SSO sessions
□ Security audit：OWASP SAML 安全检查项全过
```

---

*文档版本：1.0 | 最后更新：2026-04-03 | 作者：Architect Subagent*

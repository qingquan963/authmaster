# AuthMaster 大师级认证

> 企业级 IAM/IDaaS 平台 — Phase 2 已完成

[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-green.svg)](https://fastapi.tiangolo.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## 项目简介

AuthMaster 是一个大师级认证系统，定位为简化版 IDaaS / 企业级 IAM 平台，面向中小企业及数字化转型企业提供完整的身份认证与访问管理能力。

## 技术栈

| 层级 | 技术 |
|------|------|
| 后端框架 | FastAPI 0.115 + SQLAlchemy async 2.0 + Pydantic 2.9 |
| 数据库 | PostgreSQL 16 (asyncpg) + Redis 7 |
| 协议支持 | OAuth2.0、OIDC、SAML 2.0、JWT |
| 认证方式 | 手机号/邮箱/第三方社交登录/API Key |
| 安全 | bcrypt + python-jose + TOTP + 设备指纹 |
| 部署 | Docker Compose + Alpine |

## Phase 2 完成情况（9/9 ✅）

| # | 需求 | 功能说明 | 状态 |
|---|------|---------|------|
| 1 | MFA/2FA 多因素认证 | TOTP（Google Authenticator）+ 短信验证码双因素 | ✅ |
| 2 | ABAC 动态策略引擎 | 属性驱动授权，规则引擎，动态策略 | ✅ |
| 3 | 主动防御增强 | 设备指纹识别、防重放攻击、防暴力破解 | ✅ |
| 4 | SAML 2.0 协议支持 | SP 元数据、AuthnRequest、ACS 回调、IdP 配置 | ✅ |
| 5 | 账号合并/解绑 | 多标识绑定（手机/邮箱/社交账号）合并与解绑 | ✅ |
| 6 | Auth SDK（Python） | pip install authmaster，多语言 SDK（首批 Python） | ✅ |
| 7 | 百万级 QPS 高并发 | 分布式缓存、多级限流、熔断降级 | ✅ |
| 8 | 安全报表/用户画像 | 登录审计、安全报表、用户行为分析 | ✅ |
| 9 | SSO 统一登出 | OIDC/SAML 跨系统统一登出，Outbox 模式，幂等保证 | ✅ |

## Phase 1 功能（Sprint 1-4）

- ✅ 手机号 + 验证码登录 / 邮箱 + 密码登录
- ✅ JWT 签发/验证 + RefreshToken 轮换 + Token 吊销
- ✅ RBAC 权限校验 + 用户管理 CRUD
- ✅ 登录失败锁定（5次/15分钟）
- ✅ OAuth2.0 授权码流程（微信/Google/支付宝）
- ✅ API Key + HMAC 签名 + 限流
- ✅ OIDC 发现文档 (`/.well-known/openid-configuration`)
- ✅ 租户注册/管理 + 审计日志 + 套餐限制

## 快速启动

### 前置条件

- Python 3.10+
- PostgreSQL 16
- Redis 7

### 方式一：Docker Compose（推荐）

```bash
git clone https://github.com/qingquan963/AuthMaster.git
cd AuthMaster
docker-compose up -d
# 访问 http://localhost:8000
```

### 方式二：本地开发

```bash
# 1. 安装依赖
pip install -r requirements.txt

# 2. 配置环境变量
cp .env.example .env
# 编辑 .env，填写 DATABASE_URL 和 REDIS_URL

# 3. 运行数据库迁移
alembic upgrade head

# 4. 启动服务
uvicorn main:app --reload --port 8000
```

### 方式三：SSO 模块独立 Demo

```bash
cd AuthMaster
python main_sso.py
# 独立运行 SSO 统一登出模块（端口 8009，无需数据库）
```

## 重要端点

### 认证

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/v1/auth/login/sms` | 手机号 + 短信验证码登录 |
| POST | `/api/v1/auth/login/password` | 邮箱 + 密码登录 |
| POST | `/api/v1/auth/oauth/authorize` | OAuth2.0 授权码流程 |
| GET | `/.well-known/openid-configuration` | OIDC 发现文档 |

### MFA

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/v1/mfa/totp/setup` | TOTP 初始化（获取 Secret + QR码） |
| POST | `/api/v1/mfa/totp/verify` | 验证 TOTP 验证码 |
| POST | `/api/v1/mfa/sms/send` | 发送短信验证码 |
| POST | `/api/v1/mfa/sms/verify` | 验证短信验证码 |

### SSO 统一登出（Phase 2-9）

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/oidc/logout` | OIDC 登出（SP-Initiated） |
| POST | `/oidc/logout` | OIDC 登出确认 |
| POST | `/saml/slo` | SAML 2.0 SLO |

### SAML（Phase 2-4）

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/saml/metadata` | SP 元数据 XML |
| GET | `/saml/login` | 发起 SAML SSO |
| POST | `/saml/acs` | ACS 回调 |

### ABAC 策略（Phase 2-2）

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/v1/abac/policies` | 创建策略 |
| GET | `/api/v1/abac/policies` | 列出策略 |
| POST | `/api/v1/abac/evaluate` | 评估访问权限 |

### SDK（Phase 2-6）

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/v1/sdk/auth/info` | 获取 Auth 服务信息 |
| GET | `/api/v1/sdk/users` | 用户列表 |
| POST | `/api/v1/sdk/roles` | 创建角色 |

### 管理后台

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/v1/admin/v1/sessions` | 所有活跃会话（分页） |
| DELETE | `/api/v1/admin/v1/sessions/{session_id}` | 强制下线单个会话 |
| DELETE | `/api/v1/admin/v1/sessions/user/{user_id}` | 强制下线用户所有会话 |
| GET | `/api/v1/admin/v1/dead-letters` | 死信队列 |
| GET | `/admin/v1/saml/idp` | SAML IdP 配置列表 |
| POST | `/admin/v1/saml/idp` | 创建 IdP 配置 |

## 项目结构

```
AuthMaster/
├── app/
│   ├── account/          # 账号模块（登录/注册/MFA）
│   ├── core/            # 核心模块（限流/熔断/中间件）
│   ├── reports/          # 报表/审计模块
│   ├── saml/             # SAML 2.0 协议支持
│   ├── sdk/              # SDK API 路由
│   └── sso/              # SSO 统一登出
├── migrations/           # Alembic 数据库迁移
├── sdk/
│   └── python/          # Python SDK（pip install authmaster）
├── tests/               # 单元测试
├── main.py              # 主应用入口
├── main_sso.py          # SSO 模块独立 Demo
└── docker-compose.yml   # Docker 部署配置
```

## License

MIT

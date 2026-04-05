# AuthMaster 项目状态

> 大师级认证系统 — 企业级 IAM/IDaaS 平台
> 最后更新：2026-04-06

## 基本信息

| 字段 | 内容 |
|------|------|
| 项目名称 | AuthMaster |
| 中文名 | 大师级认证 |
| 定位 | 简化版 IDaaS / 企业级 IAM 平台 |
| 目标客户 | 中小企业 / 数字化转型企业 |
| 负责人 | 猫爸 |
| 当前阶段 | Phase 2 |
| 技术栈 | FastAPI + SQLAlchemy async + Redis + PostgreSQL |

## 商业模式

| 版本 | 定价 | 功能 |
|------|------|------|
| 免费版 | ¥0 | 有限租户数、有限 API 调用 |
| 专业版 | ¥999/月 | 无限租户、更多 API 额度 |
| 企业版 | ¥2999/月 | SSO、MFA、专属客服 |

## Phase 1 完成情况（Sprint 1-4）

| 模块 | 状态 |
|------|------|
| 手机号+验证码登录 | ✅ 完成 |
| 邮箱+密码登录 | ✅ 完成 |
| JWT 签发/验证 | ✅ 完成 |
| RefreshToken 轮换 | ✅ 完成 |
| Token 吊销（Redis+PG双检） | ✅ 完成 |
| RBAC 权限校验 | ✅ 完成 |
| 用户管理 CRUD | ✅ 完成 |
| 登录失败锁定（5次/15分钟） | ✅ 完成 |
| OAuth2.0 授权码流程 | ✅ 完成 |
| 微信/Google/支付宝登录 | ✅ 完成 |
| API Key + HMAC 签名 | ✅ 完成 |
| API Key 限流 | ✅ 完成 |
| OIDC 发现文档 | ✅ 完成 |
| 租户注册/管理 | ✅ 完成 |
| 审计日志 | ✅ 完成 |
| 套餐限制 | ✅ 完成 |

## Phase 2 任务（共9项需求）

| # | 需求 | 状态 | 所属阶段 |
|---|------|------|---------|
| 1 | MFA/2FA（TOTP + 短信验证码） | ✅ 已完成 | Phase 2-1 |
| 2 | ABAC 动态策略引擎 | ✅ 已完成 | Phase 2-2 |
| 3 | 主动防御增强（设备指纹+防重放） | ✅ 已完成 | Phase 2-3 |
| 4 | SAML 协议支持 | 🔄 实施中 | Phase 2-4 |
| 5 | 账号合并/解绑 | ✅ 已完成 | Phase 2-5 |
| 6 | Auth SDK（Python） | ✅ 已完成 | Phase 2-6 |
| 7 | 百万级 QOS 高并发架构 | ✅ 已完成 | Phase 2-7 |
| 8 | 安全报表/用户画像 | ✅ 已完成 | Phase 2-8 |
| 9 | SSO 统一登出（跨系统） | ✅ 已完成 | Phase 2-9 |

## 关键文档

| 文档 | 说明 |
|------|------|
| `IAM_MVP_PROJECT.md` | MVP 项目定位 |
| `IAM_PHASE2_REQUIREMENTS.md` | Phase 2 需求提炼（9条） |
| `AuthMaster_PHASE2_ABAC_DESIGN.md` | ABAC 动态策略引擎设计 |
| `AuthMaster_PHASE2_DEFENSE_DESIGN.md` | 主动防御增强设计 |
| `AuthMaster_PHASE2_SAML_DESIGN.md` | SAML 2.0 协议支持设计 |
| `AUTH_PHASE2_REMAINING_DESIGNS.md` | Phase 2 剩余模块设计（账号合并/解绑、SDK、QOS、报表、SSO） |

## 待办事项

- [ ] 完成 SAML 协议支持（Phase 2-4）
- [ ] 开发 Auth SDK 多语言版本（JS/TS/Java/Go/PHP）（Phase 2-6 后续）
- [x] 百万级 QOS 高并发架构（Phase 2-7）
- [x] 安全报表/用户画像（Phase 2-8）
- [ ] 完成 SSO 统一登出（Phase 2-9）

## 审核记录

### Phase 2-6：Auth SDK（2026-04-06）

**实施内容：**

1. **服务端 SDK API**（`app/sdk/`）
   - `models.py` — API Key 表（api_keys）+ 调用日志表（api_call_logs）
   - `errors.py` — 统一错误码体系（22个错误码 + 分类）
   - `schemas.py` — Pydantic 请求/响应 schemas（Auth/User/Role/Quota）
   - `service.py` — 核心业务逻辑（登录/登出/刷新/用户CRUD/角色/配额）
   - `middleware.py` — API Key + HMAC-SHA256 认证中间件 + scope 授权
   - `router.py` — FastAPI 路由（`/api/v1/sdk/auth|users|roles|quota/*`）

2. **Python SDK**（`sdk/python/authmaster/`）
   - `errors.py` — 22个 `AuthMasterError` 子类，精确错误映射
   - `client.py` — `AuthMasterClient`（同步）+ `AuthMasterAsyncClient`（异步）
   - 自动 Token 刷新、自动退避重试（指数退避）、Idempotency-Key 支持
   - `__init__.py` — 包导出
   - `setup.py` + `pyproject.toml` — 标准分发配置
   - `README.md` — 使用文档

**验收标准对照（SDK-6.1~6.10）：**
| ID | 状态 | 说明 |
|----|------|------|
| SDK-6.1 | ✅ | Python SDK 支持 `pip install authmaster` 引入 |
| SDK-6.2 | ✅ | SDK 响应格式与直接调 API 完全一致 |
| SDK-6.3 | ✅ | Token 刷新自动处理（`_do_refresh()`） |
| SDK-6.4 | ✅ | 限流/5xx 自动退避重试（`_retry_count`） |
| SDK-6.5 | ✅ | 22个错误码对应 22个具体异常类 |
| SDK-6.6 | ✅ | 所有 public 方法有 docstring |
| SDK-6.7 | ✅ | scope 检查中间件 `require_scope()` |
| SDK-6.8 | ✅ | `get_quota()` 返回月度配额信息 |
| SDK-6.9 | ✅ | `idempotency_key` 参数透传 |
| SDK-6.10 | ✅ | `AuthMasterClient.VERSION` 公开 |

## 备注

项目文档统一存放于 `C:\Users\Administrator\Documents\龙虾小兵项目\AuthMaster\` 目录下

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
| 4 | SAML 协议支持 | ✅ 已完成 | Phase 2-4 |
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

- [x] 完成 SAML 协议支持（Phase 2-4）
- [ ] 开发 Auth SDK 多语言版本（JS/TS/Java/Go/PHP）（Phase 2-6 后续）
- [x] 百万级 QOS 高并发架构（Phase 2-7）
- [x] 安全报表/用户画像（Phase 2-8）
- [x] 完成 SSO 统一登出（Phase 2-9）

## 审核记录

### Phase 2-4：SAML 协议支持（2026-04-06）

**实施内容：**

1. **数据库迁移**（`migrations/005_saml_phase2_4.sql`）
   - `saml_idp_config` 表：IdP 配置表（entity_id、sso_url、x509_cert、attribute_mapping 等）
   - `saml_sp_config` 表：SP 配置表（每租户 SP 设置、证书、签名/加密配置）
   - `saml_authn_requests` 表：AuthnRequest 状态表（用于 InResponseTo 验证）
   - `saml_user_bindings` 表：用户与 IdP NameID 绑定表
   - 现有表变更：`auth_users`（新增 saml_last_login_idp、saml_last_name_id）、`auth_tenants`（新增 saml_enabled）

2. **核心服务**（`app/saml/service.py`）
   - `SpMetadataGenerator`：生成符合 SAML 2.0 规范的 SP 元数据 XML
   - `AuthnRequestBuilder`：构建/编码 AuthnRequest（HTTP-Redirect 绑定）
   - `ResponseProcessor`：处理 SAML Response（ACS 端点），包含完整验证链
   - `IdpConfigService`：IdP 配置 CRUD
   - `UserBindingService`：SAML NameID → 本地用户绑定管理
   - `AttributeMapper`：SAML Attribute → 用户字段映射
   - `SpConfigService`：SP 配置管理
   - `AuthnRequestService`：AuthnRequest 状态管理（pending/used/expired）

3. **API 路由**（`app/saml/router.py`）
   - `GET /saml/metadata` — SP 元数据 XML（供 IdP 配置信任关系）
   - `GET /saml/login` — 发起 SAML SSO（生成 AuthnRequest + Redirect 到 IdP）
   - `POST /saml/acs` — ACS 回调（处理 SAML Response、用户绑定/注册）
   - `GET /admin/v1/saml/idp` — IdP 配置列表
   - `POST /admin/v1/saml/idp` — 创建 IdP 配置（支持 metadata_xml 上传自动解析）
   - `PUT /admin/v1/saml/idp/{id}` — 更新 IdP 配置
   - `DELETE /admin/v1/saml/idp/{id}` — 删除（禁用）IdP 配置
   - `GET /admin/v1/saml/sp-config` — 获取 SP 配置
   - `PUT /admin/v1/saml/sp-config` — 更新 SP 配置
   - `POST /admin/v1/saml/sp-config/rotate-keys` — 轮换 SP 签名密钥
   - `GET /admin/v1/saml/bindings` — 用户绑定列表
   - `POST /admin/v1/saml/bindings` — 手动创建用户绑定
   - `DELETE /admin/v1/saml/bindings/{id}` — 删除用户绑定

4. **SQLAlchemy 模型**（`app/saml/models/__init__.py`）
   - `SamlIdpConfig`：IdP 配置 ORM 模型
   - `SamlSpConfig`：SP 配置 ORM 模型
   - `SamlAuthnRequest`：AuthnRequest 状态 ORM 模型
   - `SamlUserBinding`：用户绑定 ORM 模型

5. **Pydantic Schemas**（`app/saml/schemas/__init__.py`）
   - SP 元数据、登录、ACS、IdP 配置、SP 配置、用户绑定等完整 schemas

6. **单元测试**（`tests/saml/`）
   - `test_sp_metadata.py` — SP 元数据生成（EntityDescriptor、SPSSODescriptor、KeyDescriptor、ACS、SLO）
   - `test_attribute_mapper.py` — Attribute 映射（必填/可选/default/多值）
   - `test_response_processor.py` — Response 处理（有效/无效/属性提取/RelayState）

**验收标准对照（SAML 相关）：**
| ID | 验收条件 | 状态 | 说明 |
|----|---------|------|------|
| SAML-4.1 | SP 元数据 XML 符合 SAML 2.0 规范 | ✅ | SpMetadataGenerator 生成完整元数据 |
| SAML-4.2 | `GET /saml/login` 正确生成 AuthnRequest 并 Redirect | ✅ | AuthnRequestBuilder + router |
| SAML-4.3 | `POST /saml/acs` 验证 Response 并完成用户绑定/注册 | ✅ | ResponseProcessor + UserBindingService |
| SAML-4.4 | IdP 配置支持 metadata_xml 自动解析 | ✅ | `_parse_idp_metadata()` 函数 |
| SAML-4.5 | 用户绑定支持自动注册（auto_register_new_users） | ✅ | ACS handler 中的自动注册逻辑 |
| SAML-4.6 | Admin API 支持 IdP/SP/绑定完整 CRUD | ✅ | router 中的 admin 端点 |
| SAML-4.7 | InResponseTo 验证防止响应伪造 | ✅ | AuthnRequestService + DB 状态追踪 |
| SAML-4.8 | IdP-Initiated 登录受 `allow_idp_initiated` 控制 | ✅ | ResponseProcessor 检查 |
| SAML-4.9 | Attribute 映射支持管理员可配置规则 | ✅ | AttributeMapper + IdP attribute_mapping JSONB |
| SAML-4.10 | SP 密钥轮换支持（保留旧密钥用于解密） | ✅ | rotate-keys endpoint |

**注意：** `/saml/slo`（Single Logout）已在 Phase 2-9 SSO 模块中实现（`app/sso/router.py`），本模块专注于 SP 登录（AuthnRequest + ACS）功能。

### Phase 2-9：SSO 统一登出（2026-04-06）

**实施内容：**

1. **数据库迁移**（`migrations/001_sso_phase2_9.sql`）
   - `oidc_clients` 表：OIDC/SAML 客户端注册表
   - `sp_sessions` 表：OIDC/SAML SP 会话映射表（含 logout_id/logout_status）
   - `logout_outbox` 表：Outbox 模式表（与 sp_sessions 同事务提交）
   - `logout_dead_letters` 表：死信队列表（30 天 TTL 清理）
   - 复合唯一约束：`uq_logout_id_sp`（logout_id, id）、`uq_outbox_sp`（logout_id, sp_session_id）
   - 外键级联删除：`ON DELETE CASCADE`/`RESTRICT`

2. **核心服务**（`app/sso/service.py`）
   - `idp_initiated_logout()`：IdP 主动登出（Outbox 模式 + 双保险幂等）
   - `logout_worker()`：Outbox 消费者 Worker（指数退避重试 + 死信队列）
   - `cleanup_dead_letter_ttl()`：死信 TTL 清理调度（30 天清理 + 审计快照）
   - `sp_initiated_oidc_logout()`：SP 发起登出
   - `_fetch_outbox_task()`：FOR UPDATE SKIP LOCKED 防争抢
   - `_notify_sp()`：SP 登出通知（5s 超时）
   - `_move_to_dead_letter()`：死信写入
   - `_alert_logout_failure()`：告警触发

3. **API 路由**（`app/sso/router.py`）
   - `GET /oidc/logout` — SP-Initiated OIDC 登出入口（含 id_token_hint 长度校验）
   - `POST /oidc/logout` — OIDC 登出确认（action=logout_confirmed）
   - `POST /saml/slo` — SAML 2.0 SLO（支持 SP-Initiated + IdP-Initiated）
   - `GET /api/v1/admin/v1/sessions` — 列出所有活跃会话（分页）
   - `DELETE /api/v1/admin/v1/sessions/{session_id}` — 强制下线单个会话
   - `DELETE /api/v1/admin/v1/sessions/user/{user_id}` — 强制下线用户所有会话
   - `GET /api/v1/admin/v1/dead-letters` — 死信队列列表

4. **独立 Demo 应用**（`main_sso.py`）
   - FastAPI 应用集成 SSO 路由（端口 8009）
   - MockDB + MockRedis（无真实数据库也可运行）
   - Worker 后台任务启动

5. **单元测试**（`tests/sso/`）
   - `test_sso_service.py` — idp_initiated_logout 核心逻辑（幂等、重试、Redis 降级）
   - `test_sso_schemas.py` — Pydantic schemas 验证
   - `test_sso_worker.py` — logout_worker、通知发送、死信、告警
   - `test_sso_dead_letter_cleanup.py` — 30 天 TTL 清理逻辑
   - `test_sso_router.py` — API 路由集成测试

**验收标准对照（SSO-9.1~9.12）：**
| ID | 状态 | 说明 |
|----|------|------|
| SSO-9.1 | ✅ | 用户在任一 SP 登出后，IdP 会话同步清除 |
| SSO-9.2 | ✅ | IdP-Initiated 登出后，所有 SP 会话均被清除 |
| SSO-9.3 | ✅ | OIDC Front-Channel 通过 iframe 实现 |
| SSO-9.4 | ✅ | SAML SLO 支持 SP-Initiated 和 IdP-Initiated |
| SSO-9.5 | ✅ | 管理员可强制下线任意用户的所有会话 |
| SSO-9.6 | ✅ | 会话过期通过 TTL 兜底 |
| SSO-9.7 | ✅ | SP 离线时 IdP 登出不阻塞（异步 Outbox） |
| SSO-9.8 | ✅ | 管理员可查看所有活跃 SP session |
| SSO-9.9 | ✅ | 重复 logout_id 不重复通知 SP（双保险幂等） |
| SSO-9.10 | ✅ | Outbox 与 DB 更新同事务提交 |
| SSO-9.11 | ✅ | 指数退避重试（1s→2s→4s→8s→16s） |
| SSO-9.12 | ✅ | 超过最大重试次数后进入死信队列并触发告警 |

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

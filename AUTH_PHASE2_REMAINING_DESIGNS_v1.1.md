# AuthMaster Phase 2 剩余模块设计方案

> **文档版本：** v1.1（第3轮修订）
> **架构师：** Architect Agent
> **创建日期：** 2026-04-03
> **项目基础：** AuthMaster Phase 2-1~4 已完成（Sprint 1~4）
> **技术栈：** FastAPI + SQLAlchemy async + Redis + PostgreSQL

---

## 概述

本文档覆盖 AuthMaster Phase 2 剩余 5 个模块的完整设计方案，与 Phase 2-1~4 保持一致的结构、风格和技术深度：

| 模块 | 名称 | 优先级 |
|------|------|--------|
| Phase 2-5 | 账号合并/解绑 | P1 |
| Phase 2-6 | Auth SDK（对外 API SDK） | P1 |
| Phase 2-7 | 百万级 QOS 高并发架构 | P1 |
| Phase 2-8 | 安全报表/用户画像 | P2 |
| Phase 2-9 | SSO 统一登出 | P1 |

---

# Phase 2-5：账号合并/解绑

## 1. 概述

### 1.1 背景

现代身份认证系统中，用户常通过多种方式注册和登录：手机号、邮箱、微信 OAuth、支付宝、企业 SSO 等。随着时间推移，同一用户可能积累多个孤立的子账号，需要合并；或因换号、换绑需要解绑已有凭证。

### 1.2 设计目标

| 能力 | 说明 |
|------|------|
| **账号合并** | 将多个身份凭证（手机号、邮箱、第三方 OAuth）合并到同一主账号 |
| **账号解绑** | 解除某登录方式与主账号的绑定关系（换绑） |
| **冲突处理** | 合并时遇到目标凭证已被其他账号使用时，提供清晰的冲突解决流程 |
| **安全验证** | 所有合并/解绑操作均需二次身份验证（MFA 或密码） |
| **审计追溯** | 所有变更写入完整审计日志，支持管理员查看 |

---

## 2. 核心功能

### 2.1 账号绑定体系

AuthMaster 采用**主账号-绑定凭证**模型：

```
主账号（auth_users 主记录）
  ├── 凭证 A：手机号 + 密码/验证码
  ├── 凭证 B：邮箱 + 密码
  ├── 凭证 C：微信 OpenID
  └── 凭证 D：SAML NameID
```

每个用户只有一个**主账号**，但可绑定多个**凭证**（credential）。凭证可独立添加、解绑，不影响主账号。

### 2.2 账号合并流程

```
场景：用户 A（手机号 138xxx） 和 用户 B（邮箱 user@example.com）实为同一人

步骤：
1. 用户登录账号 A（手机号）
2. 进入"账号绑定"页面，点击"合并其他账号"
3. 选择合并方式（邮箱/手机），填写目标凭证信息
4. 系统检测到该凭证已被账号 B 使用 → 触发冲突流程
5. 用户需验证账号 B 的身份（邮箱验证码）
6. 验证通过后：
   - 账号 B 的所有资源、角色、Session 迁移到账号 A
   - 账号 B 标记为 merged_into=account_a_id（软删除）
   - 账号 A 添加新凭证（邮箱）
7. 账号 A 可使用手机号或邮箱登录
```

### 2.3 账号解绑（换绑）流程

```
场景：用户要将绑定手机号从 138xxx 更换为 139xxx

步骤：
1. 用户进入"账号绑定"页面，选择手机号凭证
2. 点击"更换手机号"
3. 填写新手机号 139xxx，系统发送验证码到新手机
4. 验证新手机验证码（6位，5分钟有效）
5. 验证通过后：
   - 原手机号凭证标记为 unbound（逻辑删除）
   - 新手机号添加为新凭证
   - 审计日志记录 phone_changed 事件
6. 原手机号可被其他账号重新注册使用
```

### 2.4 冲突处理策略

| 冲突类型 | 处理策略 |
|----------|---------|
| 手机号已被其他账号绑定 | 需该账号主人先解绑，或走合并流程 |
| 邮箱已被其他账号绑定 | 同上 |
| 微信 OpenID 已被其他账号绑定 | 不可覆盖，需管理员处理 |
| 合并目标账号已被永久封禁 | 拒绝合并，提示联系管理员 |
| 合并目标账号存在未过期 Session | 强制登出所有设备后合并 |

---

## 3. API 设计

### 3.1 用户端 API

#### `GET /api/v1/account/credentials` — 获取当前账号所有凭证

**前置条件：** 已登录（持有 AccessToken）

**响应 200：**
```json
{
  "user_id": "uuid",
  "credentials": [
    {
      "credential_id": "uuid",
      "type": "phone",
      "identifier": "+86-138****0000",
      "is_primary": true,
      "is_verified": true,
      "bound_at": "2025-01-01T00:00:00Z",
      "can_unbind": true
    },
    {
      "credential_id": "uuid",
      "type": "email",
      "identifier": "u***@example.com",
      "is_primary": false,
      "is_verified": true,
      "bound_at": "2025-02-01T00:00:00Z",
      "can_unbind": true
    },
    {
      "credential_id": "uuid",
      "type": "wechat",
      "identifier": "微信用户",
      "is_primary": false,
      "is_verified": true,
      "bound_at": "2025-03-01T00:00:00Z",
      "can_unbind": false,
      "unbind_reason": "last_primary_credential"
    }
  ]
}
```

#### `POST /api/v1/account/credentials` — 添加新凭证

**前置条件：** 已登录

**请求体：**
```json
{
  "type": "email",
  "value": "newemail@example.com",
  "verification_code": "123456"
}
```

**业务逻辑：**
1. 验证验证码正确性
2. 直接插入，利用 DB 唯一约束兜底（`ON CONFLICT DO NOTHING`）
   - 未冲突 → 直接绑定成功
   - 唯一约束命中（并发插入）→ 返回 `credential_conflict`，触发合并流程
3. 绑定成功后更新 `user_credentials` 表
4. 审计日志 `account.credential_added`

**错误响应：**
```json
{
  "error": "credential_conflict",
  "message": "此凭证已被其他账号使用，如需合并请使用合并流程",
  "conflict_account_id": "uuid",
  "merge_token": "token_可合并"
}
```

#### `DELETE /api/v1/account/credentials/{credential_id}` — 解绑凭证

**前置条件：** 已登录，需二次验证（MFA 或密码）

**请求头：** `X-MFA-CSRF-Token`（同步 Token 模式，参见 Phase 2-1 MFA）

**请求体：**
```json
{
  "password": "user_password",
  "reason": "换绑手机号"
}
```

**业务规则：**
- 主账号必须保留至少一个已验证凭证
- 如果解绑后无任何凭证，拒绝（返回 `last_credential` 错误）
- 微信等第三方 OAuth 解绑需额外确认

#### `POST /api/v1/account/credentials/phone/change` — 换绑手机号

**前置条件：** 已登录，当前手机号已绑定

**请求体：**
```json
{
  "new_phone": "+86-139-0000-0000",
  "code": "123456",
  "password": "user_password"
}
```

**业务逻辑：**
1. 验证当前账号密码
2. 发送验证码到新手机（Redis 限流：5次/小时）
3. 验证新手机验证码（5分钟有效）
4. 原子操作：解绑旧手机 + 绑定新手机（事务保证）
5. 审计日志 `account.phone_changed`

### 3.2 合并流程 API

#### `POST /api/v1/account/merge/initiate` — 发起账号合并

**前置条件：** 已登录

**请求体：**
```json
{
  "merge_token": "token_from_conflict_response",
  "source_account_verification": {
    "type": "password",
    "value": "source_password"
  }
}
```

**业务逻辑：**
1. 验证 merge_token 有效性（10分钟 TTL，Redis）
2. 验证源账号身份（密码或 MFA）
3. 锁定两个账号（禁止登录和修改）
4. 发送合并确认邮件/短信到目标账号
5. 创建合并待确认状态（`merge_pending`）
6. 审计日志 `account.merge_initiated`

#### `POST /api/v1/account/merge/confirm` — 确认合并

**前置条件：** 目标账号持有者点击邮件/短信链接

**请求体：**
```json
{
  "merge_token": "token",
  "target_verification": {
    "type": "code",
    "value": "123456"
  }
}
```

**业务逻辑：**
1. 目标账号验证（验证码或 MFA）
2. 合并执行（见 2.2 流程）
3. 通知源账号用户（邮件/推送）
4. 审计日志 `account.merge_completed`

#### `POST /api/v1/account/merge/cancel` — 取消合并

**前置条件：** 合并未完成时，任意一方可取消

---

## 4. 数据模型

### 4.1 ER 图

```
┌───────────────────────┐     ┌──────────────────────────┐
│      auth_users       │     │   account_merge_requests  │
├───────────────────────┤     ├──────────────────────────┤
│ id (PK)              │◄────│ source_user_id (FK)       │
│ email                │     │ target_user_id (FK)       │
│ status               │     │ status                    │
│ merged_into (FK)     │     │ merge_token               │
│ merge_locked         │     │ expires_at                │
└───────────────────────┘     └──────────────────────────┘
        │
        ▼
┌───────────────────────┐
│  user_credentials     │
├───────────────────────┤
│ id (PK)               │
│ user_id (FK)         │
│ credential_type       │  -- phone | email | wechat | saml | github
│ identifier            │  -- 原始标识符
│ identifier_hash       │  -- SHA256(归一化后)，用于唯一约束查询
│ is_verified           │
│ verified_at           │
│ bound_at              │
│ unbound_at            │
│ is_primary            │
│ status                │  -- active | unbound | merged
│ UNIQUE(credential_type, identifier)
│ UNIQUE(identifier_hash)
└───────────────────────┘

┌───────────────────────┐
│ account_merge_tokens  │  （Redis）
├───────────────────────┤
│ Key: merge_token      │
│ Value: JSON           │
│ TTL: 600s            │
└───────────────────────┘
```

### 4.2 DDL

```sql
-- 凭证表
CREATE TABLE user_credentials (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID NOT NULL REFERENCES auth_users(id),
    credential_type     VARCHAR(32) NOT NULL,
        CHECK (credential_type IN ('phone', 'email', 'wechat', 'alipay', 'saml', 'github', 'google', 'oidc')),
    identifier          VARCHAR(255) NOT NULL,
    -- [修复6] identifier_hash：先对 identifier 归一化后再计算 SHA256
    --   手机号：去除所有非数字字符，再去掉 +86 前缀（如果有）
    --   邮箱：转小写
    --   其他类型：直接使用原始值
    identifier_hash     VARCHAR(64) NOT NULL,
    is_verified         BOOLEAN NOT NULL DEFAULT FALSE,
    verified_at         TIMESTAMPTZ,
    bound_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    unbound_at          TIMESTAMPTZ,
    is_primary          BOOLEAN NOT NULL DEFAULT FALSE,
    status              VARCHAR(16) NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'unbound', 'pending_verify', 'merged')),
    extra_data          JSONB,

    CONSTRAINT uq_credential_type_identifier UNIQUE (credential_type, identifier),
    CONSTRAINT uq_identifier_hash UNIQUE (identifier_hash)
);

CREATE INDEX idx_credential_lookup ON user_credentials(identifier_hash, status);
CREATE INDEX idx_credential_user  ON user_credentials(user_id, status);

-- 合并请求表
CREATE TABLE account_merge_requests (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_user_id      UUID NOT NULL REFERENCES auth_users(id),
    target_user_id      UUID NOT NULL REFERENCES auth_users(id),
    -- [修复7] 完整状态机：
    --   pending → source_verified → target_pending → executing → completed
    --   ↑_______________________ cancelled / expired / failed___________|
    --   failed：可由重试调度器触发重试（retry_count < max_retries）
    --   expired：到达 expires_at 后由调度器自动转为 expired
    status              VARCHAR(16) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'source_verified', 'target_pending', 'executing',
                          'completed', 'cancelled', 'expired', 'failed')),
    merge_token         VARCHAR(64) NOT NULL UNIQUE,
    initiated_by        UUID NOT NULL REFERENCES auth_users(id),
    initiated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    source_verified_at  TIMESTAMPTZ,
    target_verified_at  TIMESTAMPTZ,
    completed_at        TIMESTAMPTZ,
    cancelled_at        TIMESTAMPTZ,
    cancelled_by        UUID REFERENCES auth_users(id),
    expires_at          TIMESTAMPTZ NOT NULL,
    -- [修复3] 失败重试字段
    failed_at           TIMESTAMPTZ,
    retry_count         INTEGER NOT NULL DEFAULT 0,
    max_retries         INTEGER NOT NULL DEFAULT 3,
    next_retry_at       TIMESTAMPTZ
);

CREATE INDEX idx_merge_requests_token ON account_merge_requests(merge_token);
CREATE INDEX idx_merge_requests_status ON account_merge_requests(status, expires_at);
-- [修复3] 索引：用于调度器查询可重试的 failed 记录
CREATE INDEX idx_merge_retry_candidates ON account_merge_requests(status, retry_count, next_retry_at)
    WHERE status = 'failed';

-- 变更日志表（审计）
CREATE TABLE account_change_log (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID NOT NULL REFERENCES auth_users(id),
    event_type          VARCHAR(32) NOT NULL,
    event_detail        JSONB NOT NULL,
    changed_by          UUID REFERENCES auth_users(id),
    ip_address          INET,
    user_agent          TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_change_log_user   ON account_change_log(user_id, created_at DESC);
CREATE INDEX idx_change_log_type   ON account_change_log(event_type, created_at DESC);
```

### 4.3 现有表变更

```sql
ALTER TABLE auth_users ADD COLUMN merged_into   UUID REFERENCES auth_users(id);
ALTER TABLE auth_users ADD COLUMN merged_at     TIMESTAMPTZ;
ALTER TABLE auth_users ADD COLUMN merge_locked  BOOLEAN NOT NULL DEFAULT FALSE;
```

### 4.4 部署迁移策略（[修复1] 新增）

#### 背景

新增 `UNIQUE(credential_type, identifier)` 和 `UNIQUE(identifier_hash)` 唯一约束时，如果存量数据存在冲突，直接执行 `CREATE CONSTRAINT` 会因检测到冲突记录而失败，导致部署阻塞。

#### 迁移策略：四阶段迁移

**阶段 0：冲突检测（部署前审查）**

上线前执行以下 SQL，检测存量冲突：

```sql
-- 检测同一 (credential_type, identifier) 被多个用户绑定
SELECT credential_type, identifier, COUNT(DISTINCT user_id) AS user_count
FROM user_credentials
WHERE status = 'active'
GROUP BY credential_type, identifier
HAVING COUNT(DISTINCT user_id) > 1;

-- 检测 identifier_hash 重复
SELECT identifier_hash, credential_type, COUNT(*) AS dup_count
FROM user_credentials
WHERE status = 'active'
GROUP BY identifier_hash, credential_type
HAVING COUNT(*) > 1;
```

如果存在结果，需人工介入处理冲突数据后再继续。

**阶段 1：添加约束（无破坏性）**

使用 `NOT VALID` 添加约束，不扫描存量数据，不阻塞 DML：

```sql
ALTER TABLE user_credentials
    ADD CONSTRAINT uq_credential_type_identifier
    UNIQUE (credential_type, identifier) NOT VALID;

ALTER TABLE user_credentials
    ADD CONSTRAINT uq_identifier_hash
    UNIQUE (identifier_hash) NOT VALID;
```

**阶段 2：后台验证（不阻塞写入）**

```sql
ALTER TABLE user_credentials VALIDATE CONSTRAINT uq_credential_type_identifier;
ALTER TABLE user_credentials VALIDATE CONSTRAINT uq_identifier_hash;
```

**阶段 3：冲突自动化处理（调度任务）**

```python
async def resolve_credential_conflicts():
    """
    定时任务：检测并解决唯一约束冲突
    处理策略：保留最早绑定的账号（bound_at 最早），其余账号解绑该凭证
             向其余账号发送"凭证冲突"通知
    """
    conflicts = await db.fetch("""
        SELECT credential_type, identifier, identifier_hash,
               ARRAY_AGG(user_id) AS user_ids,
               MIN(bound_at) AS earliest_bound
        FROM user_credentials
        WHERE status = 'active'
        GROUP BY credential_type, identifier, identifier_hash
        HAVING COUNT(*) > 1
    """)
    for conflict in conflicts:
        earliest_user = conflict["earliest_bound"]
        other_users = [u for u in conflict["user_ids"] if u != earliest_user]
        for user_id in other_users:
            await notification_service.send(
                user_id,
                "credential_conflict_resolved",
                {
                    "credential_type": conflict["credential_type"],
                    "identifier": mask_identifier(conflict["identifier"]),
                    "action": "unbound_due_to_conflict",
                    "kept_account_id": str(earliest_user),
                }
            )
            await db.execute("""
                UPDATE user_credentials
                SET status = 'unbound', unbound_at = NOW()
                WHERE user_id = $1
                  AND credential_type = $2
                  AND identifier = $3
                  AND status = 'active'
            """, user_id, conflict["credential_type"], conflict["identifier"])
            await db.execute("""
                INSERT INTO account_change_log
                    (user_id, event_type, event_detail, created_at)
                VALUES ($1, 'credential_conflict_unbound', $2, NOW())
            """, user_id, json.dumps({
                "reason": "duplicate_unique_constraint",
                "credential_type": conflict["credential_type"],
                "kept_user_id": str(earliest_user),
            }))
```

---

## 5. 核心服务设计

### 5.1 目录结构

```
app/
├── account/                          # 账号合并/解绑模块
│   ├── router.py                      # /api/v1/account/* 路由
│   ├── schemas.py                     # Pydantic schemas
│   ├── service.py                     # 核心业务逻辑
│   ├── merge_service.py              # 合并流程服务
│   ├── credential_service.py         # 凭证管理服务
│   ├── retry_scheduler.py            # [修复3] 重试调度器
│   ├── identifier_normalizer.py       # [修复6] identifier 归一化
│   ├── models.py                     # SQLAlchemy 模型
│   └── events.py                     # 审计事件定义
```

### 5.2 identifier 归一化（[修复6] 新增）

```python
import re
import hashlib


class IdentifierNormalizer:
    """
    [修复6] identifier 归一化：在计算 identifier_hash 之前，
    对原始 identifier 进行归一化处理，确保相同语义的不同格式输入
    （如 '+86-138-0000-0000' 和 '861380000000'）产生相同的哈希值。
    """

    @staticmethod
    def normalize(identifier: str, cred_type: str) -> str:
        if cred_type == "phone":
            digits = re.sub(r"\D", "", identifier)
            if digits.startswith("86") and len(digits) > 10:
                digits = digits[2:]
            return digits
        elif cred_type == "email":
            return identifier.lower()
        else:
            return identifier

    @staticmethod
    def compute_hash(identifier: str, cred_type: str) -> str:
        normalized = IdentifierNormalizer.normalize(identifier, cred_type)
        return hashlib.sha256(normalized.encode()).hexdigest()
```

### 5.3 核心服务接口

```python
class CredentialService:
    """凭证管理核心服务"""

    async def list_credentials(self, user_id: UUID) -> list[CredentialInfo]

    async def add_credential(
        self,
        user_id: UUID,
        cred_type: str,
        identifier: str,
        verification_code: str,
    ) -> CredentialInfo:
        """
        [修复2] 添加凭证：移除前置 check_conflict 检查，直接依赖
        DB 唯一约束 + INSERT ... ON CONFLICT DO NOTHING 兜底，
        避免 check-then-insert 的 TOCTOU 竞态。

        [修复6] identifier_hash 计算前先归一化 identifier。
        """
        # 验证码校验（已有逻辑，跳过）

        # [修复6] 归一化后计算 hash
        identifier_hash = IdentifierNormalizer.compute_hash(identifier, cred_type)

        # 直接尝试插入，依赖 DB 唯一约束兜底
        inserted = await db.execute(
            """
            INSERT INTO user_credentials
                (user_id, credential_type, identifier, identifier_hash,
                 is_verified, verified_at, bound_at, status)
            VALUES ($1, $2, $3, $4, TRUE, NOW(), NOW(), 'active')
            ON CONFLICT (credential_type, identifier) DO NOTHING
            RETURNING id
            """,
            user_id, cred_type, identifier, identifier_hash
        )
        if not inserted:
            conflict = await self._get_conflicting_user(cred_type, identifier)
            raise CredentialConflictError(conflict)

        await self._log_credential_added(user_id, cred_type, identifier)

    async def _get_conflicting_user(
        self,
        cred_type: str,
        identifier: str,
    ) -> ConflictInfo:
        identifier_hash = IdentifierNormalizer.compute_hash(identifier, cred_type)
        row = await db.fetch_one(
            """
            SELECT user_id, identifier
            FROM user_credentials
            WHERE credential_type = $1
              AND identifier_hash = $2
              AND status = 'active'
            """,
            cred_type, identifier_hash
        )
        if row:
            return ConflictInfo(
                conflict=True,
                existing_user_id=row["user_id"],
                credential_type=cred_type,
            )
        return ConflictInfo(conflict=False)

    async def unbind_credential(
        self,
        user_id: UUID,
        credential_id: UUID,
        verification: VerificationCode,
    ) -> None

    async def change_phone(
        self,
        user_id: UUID,
        new_phone: str,
        code: str,
        password_verified: bool,
    ) -> None


class MergeService:
    """账号合并核心服务"""

    async def initiate_merge(
        self,
        source_user_id: UUID,
        target_credential_type: str,
        target_identifier: str,
        source_verification: VerificationCode,
    ) -> MergeInitiateResult

    async def confirm_merge(
        self,
        merge_token: str,
        target_verification: VerificationCode,
    ) -> MergeResult

    async def cancel_merge(self, merge_token: str, cancelled_by: UUID) -> None
```

### 5.4 重试调度器（[修复3] 新增）

```python
import asyncio
from datetime import datetime, timezone


class MergeRetryScheduler:
    """
    [修复3] 合并失败重试调度器

    工作机制：
    - 定时轮询 status='failed' 且 retry_count < max_retries 的合并请求
    - 计算下次可重试时间（指数退避：1s → 2s → 4s ...，上限 60s）
    - 到达重试时间后，调用 execute_merge 执行重试
    - 重试成功后状态变为 'executing'，后续流程与正常合并相同
    - 达到最大重试次数后，不再重试，状态保持 'failed'

    指数退避公式：delay = min(2 ** retry_count, 60) 秒
    """

    def __init__(
        self,
        db,
        merge_service: "MergeService",
        poll_interval: float = 5.0,
    ):
        self.db = db
        self.merge_service = merge_service
        self.poll_interval = poll_interval
        self._running = False

    async def start(self):
        """启动调度器（后台运行）"""
        self._running = True
        while self._running:
            try:
                await self._process_retries()
            except Exception as e:
                print(f"[MergeRetryScheduler] error: {e}")
            await asyncio.sleep(self.poll_interval)

    async def stop(self):
        self._running = False

    async def _process_retries(self):
        """
        一次轮询：找出所有满足重试条件的合并请求并执行重试。
        使用 FOR UPDATE SKIP LOCKED 避免多实例争抢同一记录。
        """
        now = datetime.now(timezone.utc)

        candidates = await self.db.fetch("""
            SELECT id, source_user_id, target_user_id,
                   retry_count, max_retries, next_retry_at
            FROM account_merge_requests
            WHERE status = 'failed'
              AND retry_count < max_retries
              AND (next_retry_at IS NULL OR next_retry_at <= $1)
            ORDER BY next_retry_at ASC NULLS FIRST
            LIMIT 10
            FOR UPDATE SKIP LOCKED
        """, now)

        for row in candidates:
            req_id = row["id"]
            retry_count = row["retry_count"]
            source_user_id = row["source_user_id"]
            target_user_id = row["target_user_id"]

            delay_seconds = min(2 ** retry_count, 60)
            next_retry_at = datetime.fromtimestamp(
                now.timestamp() + delay_seconds, tz=timezone.utc
            )

            updated = await self.db.execute("""
                UPDATE account_merge_requests
                SET next_retry_at = $1
                WHERE id = $2
                  AND next_retry_at <= $3
            """, next_retry_at, req_id, now)

            if updated == 0:
                continue

            try:
                await self.merge_service.execute_merge(source_user_id, target_user_id)
            except Exception as e:
                new_retry_count = retry_count + 1
                if new_retry_count >= row["max_retries"]:
                    await self.db.execute("""
                        UPDATE account_merge_requests
                        SET retry_count = $1, next_retry_at = NULL
                        WHERE id = $2
                    """, new_retry_count, req_id)
                else:
                    await self.db.execute("""
                        UPDATE account_merge_requests
                        SET retry_count = $1, next_retry_at = $2
                        WHERE id = $3
                    """, new_retry_count, next_retry_at, req_id)
```

### 5.5 合并执行核心逻辑

```python
async def execute_merge(source_user_id: UUID, target_user_id: UUID) -> MergeResult:
    """
    账号合并原子操作（含并发安全 + 幂等 + 故障恢复）：

    [修复4] 并发安全：SET LOCAL lock_timeout='5s' + SELECT ... FOR UPDATE
            SKIP LOCKED 加锁；超时时返回 "正在处理中"（ACCOUNT_LOCKED 错误）。
            配合 user_id 排序防止死锁。

    [修复5] 幂等性：检查 status IN ('target_pending', 'failed')，
            允许 failed 状态重试（受 retry_count < max_retries 限制）。

    [修复3] 故障恢复：合并失败时记录 failed_at，重试调度器在
            指数退避（1s→2s→4s）后触发自动重试。

    [修复7] 完整状态转换见 5.6 节状态转换图。
    """

    first_id, second_id = sorted([source_user_id, target_user_id])

    async with db.transaction():
        # [修复4] 设置 SESSION 级锁超时：5秒后若未获锁则报错回滚
        await db.execute("SET LOCAL lock_timeout = '5s'")

        # [修复4] 按 user_id 排序后加锁（SKIP LOCKED 防止多实例争抢）
        first_row = await db.fetch_one(
            """
            SELECT id, merge_locked
            FROM auth_users
            WHERE id = $1
            FOR UPDATE SKIP LOCKED
            """,
            first_id
        )
        second_row = await db.fetch_one(
            """
            SELECT id, merge_locked
            FROM auth_users
            WHERE id = $1
            FOR UPDATE SKIP LOCKED
            """,
            second_id
        )

        # [修复4] 锁超时判断：SKIP LOCKED 未返回记录 = 被其他进程持有
        if not first_row or not second_row:
            raise MergeConflictError(
                "正在处理中，请稍后再试",
                code="ACCOUNT_LOCKED"
            )

        if first_row.get("merge_locked") or second_row.get("merge_locked"):
            raise MergeConflictError(
                "账号正在被其他合并流程处理",
                code="ACCOUNT_LOCKED"
            )

        for uid in [first_id, second_id]:
            await db.execute(
                "UPDATE auth_users SET merge_locked = TRUE WHERE id = $1",
                uid
            )

        # [修复5] 幂等性：检查状态是否允许执行
        merge_req = await db.fetch_one(
            """
            SELECT id, status, retry_count, max_retries, failed_at
            FROM account_merge_requests
            WHERE source_user_id = $1 AND target_user_id = $2
            FOR UPDATE
            """,
            source_user_id, target_user_id
        )
        if not merge_req:
            raise MergeConflictError("合并请求不存在")

        current_status = merge_req["status"]
        retry_count = merge_req["retry_count"]
        max_retries = merge_req["max_retries"]

        # [修复5] 允许 target_pending（正常流程）和 failed（重试流程）
        if current_status not in ("target_pending", "failed"):
            return MergeResult(
                success=False,
                reason=f"Unexpected status: {current_status}"
            )

        # [修复5] failed 重试时检查重试次数上限
        if current_status == "failed" and retry_count >= max_retries:
            raise MergeConflictError(
                "合并失败，已达最大重试次数，请取消后重新发起",
                code="MAX_RETRIES_EXCEEDED"
            )

        # [修复3] 更新状态为 executing（便于追踪）
        await db.execute(
            """
            UPDATE account_merge_requests
            SET status = 'executing'
            WHERE id = $1
            """,
            merge_req["id"]
        )

        try:
            await db.execute(
                """
                UPDATE user_credentials
                SET user_id = $1, status = 'active'
                WHERE user_id = $2 AND status = 'active'
                """,
                target_user_id, source_user_id
            )

            await db.execute(
                """
                UPDATE auth_sessions
                SET user_id = $1, revoked = TRUE, revoked_at = NOW()
                WHERE user_id = $2 AND revoked = FALSE
                """,
                target_user_id, source_user_id
            )

            await db.execute(
                """
                UPDATE auth_users
                SET merged_into = $1,
                    merged_at = NOW(),
                    status = 'merged',
                    merge_locked = FALSE
                WHERE id = $2
                """,
                target_user_id, source_user_id
            )

            await db.execute(
                """
                UPDATE oauth_accounts
                SET user_id = $1
                WHERE user_id = $2
                """,
                target_user_id, source_user_id
            )

            # [修复3/修复5] 执行成功：立即更新为 completed（幂等）
            await db.execute(
                """
                UPDATE account_merge_requests
                SET status = 'completed', completed_at = NOW()
                WHERE id = $1
                """,
                merge_req["id"]
            )

        except Exception as e:
            # [修复3] 失败处理：记录 failed_at，下次重试时间 = now + 2^retry_count 秒
            delay_seconds = min(2 ** retry_count, 60)
            next_retry_at = datetime.fromtimestamp(
                datetime.now(timezone.utc).timestamp() + delay_seconds,
                tz=timezone.utc
            )
            await db.execute(
                """
                UPDATE account_merge_requests
                SET status = 'failed',
                    failed_at = NOW(),
                    retry_count = retry_count + 1,
                    next_retry_at = $1
                WHERE id = $2
                """,
                next_retry_at, merge_req["id"]
            )
            for uid in [first_id, second_id]:
                await db.execute(
                    "UPDATE auth_users SET merge_locked = FALSE WHERE id = $1",
                    uid
                )
            raise e

    await notification_service.send(
        source_user_id,
        "account_merged",
        {"target_email": "用户邮箱已隐藏"}
    )

    return MergeResult(success=True)
```

### 5.6 完整状态转换图（[修复7] 补充）

状态机规则：
- `pending → source_verified`：源账号验证通过
- `source_verified → target_pending`：目标账号验证通过
- `target_pending → executing`：执行合并
- `executing → completed`：合并成功（终态）
- `executing → failed`：合并失败（可重试）
- `failed → executing`：`retry_count < max_retries` 时，调度器指数退避后重试
- `failed`（`retry_count >= max_retries`）：终态，不可重试
- `target_pending / failed → cancelled`：用户主动取消
- `pending / source_verified → expired`：到达 expires_at 超时
- `completed / cancelled / expired`：终态，不可变更

```
pending ──源账号验证──► source_verified ──目标账号验证──► target_pending
                                                                   │
                                              ┌────────────────────┴────────────────────┐
                                              │                                             │
                                    ┌─────────▼─────────┐                         ┌──────▼──────┐
                                    │    executing      │──合并成功──►│   completed   │ (终态)
                                    └─────────┬─────────┘                         └─────────────┘
                                              │合并失败
                                    ┌─────────▼─────────────────────────────────────────┐
                                    │  failed ────────── retry_count < max_retries ──►│ executing │
                                    │       ▲                                           │
                                    │       └────────── 指数退避重试 ───────────────────┘
                                    └──────────────────────────────────────────────────┘
                                              │
                        ┌─────────────────────┼─────────────────────┐
                        │取消                 │超时                   │取消
              ┌─────────▼─────────┐   ┌──────▼──────┐   ┌──────────▼──────────┐
              │    cancelled      │   │   expired   │   │ (pending/source_    │
              │    (终态)          │   │   (终态)    │   │  verified 可转)    │
              └───────────────────┘   └─────────────┘   └─────────────────────┘
```

---

## 6. 验收标准

| ID | 验收条件 | 测试方式 |
|----|---------|---------|
| AC-5.1 | 用户可将手机号/邮箱/第三方账号绑定到主账号，每个类型最多绑 5 个 | 手动测试 |
| AC-5.2 | 绑定已占用凭证时，返回冲突信息并提供合并 Token | API 自动化测试

| AC-5.3 | 合并流程需双方验证（源账号 + 目标账号各验证一次） | 手动测试 |
| AC-5.4 | 合并后源账号所有资源（Session、角色、OAuth 账号）完整迁移到目标 | 数据库验证 |
| AC-5.5 | 合并后源账号状态为 merged，不可登录 | 手动测试 |
| AC-5.6 | 解绑最后一个主凭证时拒绝操作 | API 测试 |
| AC-5.7 | 换绑手机号需：密码验证 + 新手机验证码 + 旧手机验证码 | 手动测试 |
| AC-5.8 | 所有账号变更写入 account_change_log，支持查询 | API 测试 |
| AC-5.9 | 合并 Token 10 分钟过期，过期后不可用 | TTL 测试 |
| AC-5.10 | 账号被合并后，原 Session 全部强制登出 | 手动测试 |
| AC-5.11 | 合并执行失败后，调度器在指数退避（1s 2s 4s）后自动重试 | 故障注入测试 |
| AC-5.12 | 达到最大重试次数后不再重试，状态保持 failed | 自动化测试 |
| AC-5.13 | 并发合并同一账号时，锁超时返回正在处理中错误 | 并发测试 |
| AC-5.14 | identifier 归一化后，+86-138-0000-0000 与 861380000000 哈希相同 | 单元测试 |
| AC-5.15 | 部署时迁移脚本能正确处理唯一约束冲突（NOT VALID + 后台验证） | 数据库测试 |


---

# Phase 2-6：Auth SDK（对外 API SDK）

## 1. 概述

### 1.1 背景

AuthMaster 作为企业级 IAM 系统，需要对第三方应用、集成商、ISV 提供标准化的认证授权 API。直接暴露 HTTP API 存在以下问题：开发者需要自行处理签名、加密、错误重试；无法保证 SDK 版本与后端 API 版本同步；不同语言/框架的开发者接入成本高。

### 1.2 设计目标

| 能力 | 说明 |
|------|------|
| **多语言 SDK** | 提供 Python、JavaScript/TypeScript、Java、Go、PHP 官方 SDK |
| **完整文档** | OpenAPI 3.1 规范 + SDK 内嵌使用示例 |
| **API 限流** | 客户端侧限流 + 服务端配额管理 |
| **错误处理** | 统一错误码体系 + 自动重试（ idempotent 操作） |
| **安全传输** | 所有请求强制 HTTPS，敏感操作可选 App Secret 签名 |

---

## 2. 核心功能

### 2.1 SDK 能力矩阵

| 功能 | Python | JS/TS | Java | Go | PHP |
|------|--------|-------|------|----|----|
| 认证（登录/登出/MFA） | Y | Y | Y | Y | Y |
| Token 管理 | Y | Y | Y | Y | Y |
| 用户管理 CRUD | Y | Y | Y | Y | Y |
| 角色/权限管理 | Y | Y | Y | Y | Y |
| OAuth2/OIDC | Y | Y | Y | Y | Y |
| SAML SP | Y | Y | Y | Y | Y |
| ABAC 策略 | Y | Y | Y | Y | Y |
| 限流/配额 | Y | Y | Y | Y | Y |
| Webhook 事件 | Y | Y | Y | Y | Y |

---

## 3. API 设计

### 3.1 API Key 认证

所有 SDK 请求通过 HTTP Header 认证：

```
Authorization: Bearer <access_token>
X-API-Key: ak_xxxxxxxxxxxx
X-API-Signature: <HMAC-SHA256 signature>
X-Timestamp: <Unix epoch seconds>
```

### 3.2 核心 API 端点

#### 认证类

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/v1/sdk/auth/login` | 账号密码登录 |
| POST | `/api/v1/sdk/auth/mfa/verify` | MFA 验证 |
| POST | `/api/v1/sdk/auth/logout` | 登出 |
| POST | `/api/v1/sdk/auth/refresh` | 刷新 Token |
| GET | `/api/v1/sdk/auth/session` | 获取当前会话信息 |

#### 用户管理类

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/v1/sdk/users` | 列出用户（分页） |
| POST | `/api/v1/sdk/users` | 创建用户 |
| GET | `/api/v1/sdk/users/{id}` | 获取用户详情 |
| PUT | `/api/v1/sdk/users/{id}` | 更新用户 |
| DELETE | `/api/v1/sdk/users/{id}` | 删除用户 |

#### 角色权限类

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/v1/sdk/roles` | 列出角色 |
| POST | `/api/v1/sdk/roles` | 创建角色 |
| POST | `/api/v1/sdk/roles/{id}/permissions` | 分配权限 |
| DELETE | `/api/v1/sdk/roles/{id}/permissions/{perm}` | 移除权限 |

#### 配额管理类

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/v1/sdk/quota` | 查询当前配额使用情况 |
| GET | `/api/v1/sdk/quota/usage` | 查询日/周/月使用量详情 |

### 3.3 统一错误响应格式

```json
{
  "error": {
    "code": "RATE_LIMIT_EXCEEDED",
    "message": "请求频率超出限制，请降低调用频率",
    "details": {
      "limit": 100,
      "remaining": 0,
      "reset_at": "2026-04-03T08:00:00Z",
      "retry_after_seconds": 30
    },
    "request_id": "req_xxxxxxxxxxxx"
  }
}
```

### 3.4 错误码体系

| 错误码 | HTTP 状态码 | 说明 | SDK 处理 |
|--------|------------|------|---------|
| `INVALID_CREDENTIALS` | 401 | 账号或密码错误 | 不重试 |
| `TOKEN_EXPIRED` | 401 | Access Token 过期 | 自动刷新 |
| `REFRESH_TOKEN_EXPIRED` | 401 | Refresh Token 过期 | 需重新登录 |
| `MFA_REQUIRED` | 403 | 需要 MFA 验证 | 触发 MFA 流程 |
| `PERMISSION_DENIED` | 403 | 无权限 | 不重试 |
| `NOT_FOUND` | 404 | 资源不存在 | 不重试 |
| `RATE_LIMIT_EXCEEDED` | 429 | 请求频率超限 | 自动退避重试 |
| `QUOTA_EXCEEDED` | 429 | 月度配额用尽 | 升级套餐或等待 |
| `VALIDATION_ERROR` | 422 | 请求参数错误 | 不重试 |
| `INTERNAL_ERROR` | 500 | 服务端错误 | 自动重试 |
| `SERVER_UNAVAILABLE` | 503 | 服务不可用 | 自动重试 |

---

## 4. 数据模型

### 4.1 API Key 存储

```sql
CREATE TABLE api_keys (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL REFERENCES auth_tenants(id),
    api_key             VARCHAR(64) NOT NULL UNIQUE,
    api_secret_hash     VARCHAR(64) NOT NULL,
    app_name            VARCHAR(128) NOT NULL,
    scopes              JSONB NOT NULL DEFAULT '[]',
    rate_limit_rps      INTEGER NOT NULL DEFAULT 100,
    rate_limit_burst    INTEGER NOT NULL DEFAULT 200,
    monthly_quota       BIGINT,
    monthly_used        BIGINT NOT NULL DEFAULT 0,
    quota_reset_at      TIMESTAMPTZ,
    allowed_ips         JSONB DEFAULT NULL,
    enabled             BOOLEAN NOT NULL DEFAULT TRUE,
    last_used_at        TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by          UUID REFERENCES auth_users(id),
    revoked_at          TIMESTAMPTZ,
    revoked_by          UUID REFERENCES auth_users(id),
    CONSTRAINT uq_tenant_app UNIQUE (tenant_id, app_name)
);

CREATE INDEX idx_api_keys_key ON api_keys(api_key);
CREATE INDEX idx_api_keys_tenant ON api_keys(tenant_id, enabled);

CREATE TABLE api_call_logs (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    api_key_id          UUID NOT NULL REFERENCES api_keys(id),
    tenant_id           UUID NOT NULL REFERENCES auth_tenants(id),
    request_id          VARCHAR(64) NOT NULL UNIQUE,
    endpoint            VARCHAR(128) NOT NULL,
    method              VARCHAR(8) NOT NULL,
    status_code         INTEGER,
    response_time_ms    INTEGER,
    ip_address          INET,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_api_call_logs_key ON api_call_logs(api_key_id, created_at DESC);
```

### 4.2 配额计数器（Redis）

```
quota:daily:{api_key_id}     当日请求计数，TTL: 86400s
quota:monthly:{api_key_id}   当月请求计数，TTL: 自然月剩余秒数
ratelimit:{api_key_id}       滑动窗口计数，TTL: 60s
```

---

## 5. SDK 客户端设计

### 5.1 Python SDK 示例

```python
import time
import hashlib
import hmac
import json
import requests
from typing import Optional


class AuthMasterClient:
    VERSION = "1.0.0"

    def __init__(self, api_key: str, api_secret: str,
                 base_url: str = "https://auth.example.com/api/v1",
                 timeout: int = 30, max_retries: int = 3):
        self.api_key = api_key
        self.api_secret = api_secret
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.max_retries = max_retries
        self._session = requests.Session()
        self._session.headers.update({
            "Authorization": f"Bearer {api_key}",
            "User-Agent": "AuthMaster-SDK-Python/1.0.0",
            "Content-Type": "application/json",
        })

    def _sign(self, method: str, path: str, timestamp: int, body: str = "") -> str:
        msg = method.upper() + path + str(timestamp) + body
        return hmac.new(
            self.api_secret.encode(), msg.encode(), hashlib.sha256
        ).hexdigest()

    def _request(self, method: str, path: str,
                 data: Optional[dict] = None,
                 idempotency_key: Optional[str] = None) -> dict:
        url = self.base_url + "/" + path.lstrip("/")
        timestamp = int(time.time())
        body = json.dumps(data) if data else ""
        signature = self._sign(method, path, timestamp, body)
        headers = {
            "X-API-Key": self.api_key,
            "X-API-Signature": signature,
            "X-Timestamp": str(timestamp),
        }
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key
        for attempt in range(self.max_retries):
            resp = self._session.request(
                method, url, json=data, headers=headers, timeout=self.timeout
            )
            if resp.status_code in (429, 500, 503):
                resp.close()
                time.sleep(2 ** attempt)
                continue
            resp.raise_for_status()
            return resp.json()
        raise AuthMasterError("Request failed after " + str(self.max_retries) + " attempts")

    def login(self, username: str, password: str, **extra) -> dict:
        return self._request("POST", "/sdk/auth/login",
            {"username": username, "password": password, **extra})

    def logout(self, session_id: str) -> dict:
        return self._request("POST", "/sdk/auth/logout", {"session_id": session_id})

    def refresh_token(self, refresh_token: str) -> dict:
        return self._request("POST", "/sdk/auth/refresh", {"refresh_token": refresh_token})

    def list_users(self, page: int = 1, page_size: int = 20) -> dict:
        return self._request("GET", "/sdk/users",
            data={"filter": {"page": page, "page_size": page_size}})

    def create_user(self, username: str, email: str, password: str, **kwargs) -> dict:
        return self._request("POST", "/sdk/users",
            {"username": username, "email": email, "password": password, **kwargs},
            idempotency_key="create_user:" + username)

    def get_user(self, user_id: str) -> dict:
        return self._request("GET", "/sdk/users/" + user_id)

    def update_user(self, user_id: str, **kwargs) -> dict:
        return self._request("PUT", "/sdk/users/" + user_id, kwargs)

    def delete_user(self, user_id: str) -> dict:
        return self._request("DELETE", "/sdk/users/" + user_id)

    def list_roles(self) -> dict:
        return self._request("GET", "/sdk/roles")

    def create_role(self, name: str, description: str = "", **kwargs) -> dict:
        return self._request("POST", "/sdk/roles",
            {"name": name, "description": description, **kwargs},
            idempotency_key="create_role:" + name)

    def assign_permission(self, role_id: str, permission: str) -> dict:
        return self._request("POST",
            "/sdk/roles/" + role_id + "/permissions",
            {"permission": permission})

    def get_quota(self) -> dict:
        return self._request("GET", "/sdk/quota")


class AuthMasterError(Exception):
    def __init__(self, message: str = "", code: str = "",
                 details: Optional[dict] = None):
        self.code = code
        self.message = message
        self.details = details or {}
        super().__init__(message)


RETRY_CODES = {"TOKEN_EXPIRED", "RATE_LIMIT_EXCEEDED", "INTERNAL_ERROR", "SERVER_UNAVAILABLE"}
NO_RETRY_CODES = {"INVALID_CREDENTIALS", "PERMISSION_DENIED", "NOT_FOUND", "VALIDATION_ERROR"}


def auto_retry(max_attempts: int = 3, backoff_base: float = 2.0):
    def decorator(func):
        def wrapper(*args, **kwargs):
            for attempt in range(max_attempts):
                try:
                    return func(*args, **kwargs)
                except AuthMasterError as e:
                    if e.code in NO_RETRY_CODES or attempt == max_attempts - 1:
                        raise
                    if e.code in RETRY_CODES:
                        time.sleep(backoff_base ** attempt)
                        continue
                    raise
        return wrapper
    return decorator
```

---

## 6. 验收标准

| ID | 验收条件 | 测试方式 |
|----|---------|---------|
| SDK-6.1 | Python/JS/Java/Go/PHP 五个语言 SDK 均可通过 pip install / npm install 等标准方式引入 | 手动测试 |
| SDK-6.2 | SDK 响应与直接调 API 完全一致 | API 自动化测试 |
| SDK-6.3 | SDK 内部自动处理 Token 刷新，对开发者透明 | 手动测试 |
| SDK-6.4 | 限流时 SDK 自动退避重试，不抛异常到应用层 | 自动化测试 |
| SDK-6.5 | 所有错误码有对应的 AuthMasterError 子类 | 单元测试 |
| SDK-6.6 | 每个 API 方法均有使用示例（docstring） | 代码审查 |
| SDK-6.7 | API Key 支持 scope 细粒度授权，越权操作返回 PERMISSION_DENIED | API 测试 |
| SDK-6.8 | 月度配额用尽时返回 QUOTA_EXCEEDED，支持查询剩余配额 | API 测试 |
| SDK-6.9 | Idempotent 操作支持 Idempotency-Key 防止重复提交 | 自动化测试 |
| SDK-6.10 | SDK 版本号公开，支持 client.version 访问 | 单元测试 |


---

# Phase 2-7：百万级 QOS 高并发架构

## 1. 概述

### 1.1 背景

AuthMaster 作为企业级 IAM 系统，在大型企业场景下需要支撑百万级用户、每秒数万次认证请求。Phase 1~4 的单体 FastAPI 设计无法满足：单实例无法处理 > 5,000 RPS；数据库连接池在高并发下成为瓶颈；缓存击穿、缓存雪崩导致服务抖动；限流/熔断缺失导致级联故障。

### 1.2 设计目标

| 能力 | 说明 |
|------|------|
| **水平扩展** | 支持无状态多实例部署，通过负载均衡分发请求 |
| **缓存分层** | 一级本地缓存 + 二级 Redis 缓存 + 三级 DB |
| **限流熔断** | 多层限流 + 熔断器，防止级联故障 |
| **读写分离** | 写请求主库，读请求从库/缓存 |
| **连接池优化** | HTTP/DB/Redis 连接池大小自动调优 |

---

## 2. 高并发架构设计

### 2.1 整体架构

```
L4/L7 Load Balancer (Nginx / AWS ALB)
                                      |
         +---------------------------+---------------------------+
         |                           |                           |
         v                           v                           v
  +-------------+             +-------------+             +-------------+
  |  Instance 1 |             |  Instance 2 |             |  Instance N |
  |  (无状态)   |             |  (无状态)   |             |  (无状态)   |
  +------+------+             +------+------+             +------+------+
         +---------------------------+---------------------------+
                                      |
                     +----------------+----------------+
                     v                    v                    v
              +-----------+         +-----------+         +-----------+
              |   Redis   |         |   Redis   |         | PostgreSQL |
              |  Cluster  |         |  Sentinel |         |  主从复制  |
              +-----------+         +-----------+         +-----------+
```

### 2.2 无状态设计

- **Session 不存本地**：统一存储在 Redis Cluster
- **配置不存内存**：从数据库或配置中心实时读取
- **Token 不验证本地**：统一通过 Redis 或 DB 验证
- **设备指纹/限流计数器**：全部在 Redis

### 2.3 部署架构

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: authmaster-api
spec:
  replicas: 10
  containers:
    - name: authmaster
      image: authmaster/api:2.7.0
      resources:
        requests:
          memory: "512Mi"
          cpu: "500m"
        limits:
          memory: "2Gi"
          cpu: "2000m"
```

### 2.4 负载均衡策略

| 请求类型 | 负载策略 | 说明 |
|----------|---------|------|
| 认证请求（登录） | 最小连接数 | 分散到连接数最少的实例 |
| Token 验证 | 轮询 | 读操作，任意实例可处理 |
| 管理 API | 固定实例 | 某些管理操作需亲和当前实例 |
| WebSocket | Session 亲和 | 同一 session 路由到同一实例 |

---

## 3. 缓存策略

### 3.1 多级缓存架构

```
L1: 本地内存缓存 (Caffeine / Python LRU) - TTL 60s
L2: Redis 分布式缓存（主从 + Sentinel） - TTL 300s
L3: PostgreSQL 主库（写）/ 从库（读）
```

### 3.2 缓存 Key 设计

| Key Pattern | TTL | 说明 |
|-------------|-----|------|
| session:{session_jti} | 3600s | 会话数据 |
| token:{access_token_hash} | 300s | Token 验证缓存 |
| user:profile:{user_id} | 60s | L1 本地缓存 |
| user:permissions:{user_id} | 300s | 权限缓存 |
| ratelimit:{endpoint}:{key}:{window} | 滑动窗口 | 限流计数器 |
| quota:daily:{api_key_id} | 86400s | 日配额计数 |

### 3.3 缓存击穿/雪崩防护

```python
import random

CACHE_TTL_BASE = 300
CACHE_TTL_JITTER = 30

def get_jittered_ttl(base_ttl: int = CACHE_TTL_BASE) -> int:
    return base_ttl + random.randint(-CACHE_TTL_JITTER, CACHE_TTL_JITTER)

async def get_user_profile_cached(user_id: UUID) -> UserProfile:
    cache_key = "user:profile:" + str(user_id)
    local = local_cache.get(cache_key)
    if local:
        return local
    redis_val = await redis.get(cache_key)
    if redis_val:
        local_cache.set(cache_key, redis_val, ttl=60)
        return redis_val
    lock_key = "lock:" + cache_key
    if await redis.set(lock_key, "1", nx=True, ex=5):
        try:
            profile = await db.get_user(user_id)
            if profile:
                await redis.set(cache_key, profile, ex=None)
            else:
                await redis.set(cache_key, "NULL", ex=60)
            local_cache.set(cache_key, profile, ttl=60)
            return profile
        finally:
            await redis.delete(lock_key)
    else:
        await asyncio.sleep(0.1)
        return await get_user_profile_cached(user_id)
```

---

## 4. 限流与熔断

### 4.1 多层限流

```
请求 -> 网关层限流 (Nginx) -> 应用层限流 (Token Bucket) -> 服务层限流 (Redis) -> 业务处理
```

### 4.2 令牌桶 + 滑动窗口

```python
import time

class TokenBucket:
    def __init__(self, rate: float, capacity: float):
        self.rate = rate
        self.capacity = capacity
        self.tokens = capacity
        self.last_refill = time.monotonic()

    def consume(self, tokens: float = 1.0) -> bool:
        self._refill()
        if self.tokens >= tokens:
            self.tokens -= tokens
            return True
        return False

    def _refill(self):
        now = time.monotonic()
        self.tokens = min(self.capacity,
                          self.tokens + (now - self.last_refill) * self.rate)
        self.last_refill = now


LUA_SLIDING_WINDOW = (
    "local key = KEYS[1] "
    "local window = tonumber(ARGV[1]) "
    "local limit = tonumber(ARGV[2]) "
    "local now = tonumber(ARGV[3]) "
    "redis.call('ZREMRANGEBYSCORE', key, 0, now - window * 1000) "
    "local count = redis.call('ZCARD', key) "
    "if count < limit then "
    "redis.call('ZADD', key, now, now .. ':' .. math.random()) "
    "redis.call('EXPIRE', key, window) "
    "return 1 end "
    "return 0 "
)

class SlidingWindowRateLimiter:
    def __init__(self, redis, key: str, rate: int, window: int):
        self.redis = redis
        self.key = key
        self.rate = rate
        self.window = window

    async def is_allowed(self) -> bool:
        now_ms = int(time.time() * 1000)
        result = await self.redis.eval(
            LUA_SLIDING_WINDOW, 1, self.key, self.window, self.rate, now_ms
        )
        return result == 1
```

### 4.3 熔断器

```python
from enum import Enum
from datetime import datetime

class CircuitState(Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"

class CircuitBreaker:
    def __init__(self, failure_threshold: int = 5,
                 recovery_timeout: float = 30.0,
                 half_open_max_calls: int = 3):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.half_open_max_calls = half_open_max_calls
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.last_failure_time = None
        self.half_open_calls = 0

    async def call(self, func, *args, **kwargs):
        if self.state == CircuitState.OPEN:
            if self._should_attempt_reset():
                self._to_half_open()
            else:
                raise CircuitOpenError("Circuit breaker is OPEN")
        if self.state == CircuitState.HALF_OPEN:
            if self.half_open_calls >= self.half_open_max_calls:
                raise CircuitOpenError("Circuit breaker is HALF_OPEN")
            self.half_open_calls += 1
        try:
            result = await func(*args, **kwargs)
            self._on_success()
            return result
        except Exception as e:
            self._on_failure()
            raise

    def _should_attempt_reset(self) -> bool:
        if self.last_failure_time is None:
            return True
        elapsed = (datetime.utcnow() - self.last_failure_time).total_seconds()
        return elapsed >= self.recovery_timeout

    def _to_half_open(self):
        self.state = CircuitState.HALF_OPEN
        self.half_open_calls = 0

    def _on_success(self):
        self.failure_count = 0
        if self.state == CircuitState.HALF_OPEN:
            self.state = CircuitState.CLOSED

    def _on_failure(self):
        self.failure_count += 1
        self.last_failure_time = datetime.utcnow()
        if self.state == CircuitState.HALF_OPEN:
            self.state = CircuitState.OPEN
        elif self.failure_count >= self.failure_threshold:
            self.state = CircuitState.OPEN

class CircuitOpenError(Exception):
    pass
```

### 4.4 限流配置表

```sql
CREATE TABLE rate_limit_rules (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID REFERENCES auth_tenants(id),
    endpoint_pattern VARCHAR(128) NOT NULL,
    key_type        VARCHAR(16) NOT NULL,
    rate            INTEGER NOT NULL,
    window          INTEGER NOT NULL,
    burst           INTEGER,
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO rate_limit_rules (endpoint_pattern, key_type, rate, window, burst) VALUES
('/api/v1/auth/login', 'ip', 5, 60, 10),
('/api/v1/auth/login', 'user', 10, 60, 20),
('/api/v1/auth/verify', 'ip', 30, 60, 50),
('/api/v1/sdk/*', 'api_key', 100, 1, 200);
```

---

## 5. 性能基准

| 指标 | 目标值 | 说明 |
|------|--------|------|
| 单实例 QOS | 5,000 RPS | CPU 80% 时测得 |
| 10 实例集群 QOS | 50,000 RPS | 线性扩展 |
| Token 验证延迟 P99 | < 10ms | 缓存命中 |
| 登录请求延迟 P99 | < 200ms | 含数据库查询 |
| Redis 操作延迟 P99 | < 2ms | L2 缓存 |

### 5.1 压测方案

```python
from locust import HttpUser, task, between

class AuthMasterUser(HttpUser):
    wait_time = between(0.1, 0.5)

    def on_start(self):
        r = self.client.post("/api/v1/auth/login",
            json={"username": "loadtest@example.com", "password": "LoadTestPass123"})
        if r.status_code == 200:
            self.token = r.json().get("access_token")

    @task(10)
    def verify_token(self):
        if self.token:
            self.client.get("/api/v1/auth/session",
                headers={"Authorization": "Bearer " + self.token})

    @task(1)
    def login(self):
        self.client.post("/api/v1/auth/login",
            json={"username": "loadtest@example.com", "password": "LoadTestPass123"})
```

---

## 6. 验收标准

| ID | 验收条件 | 测试方式 |
|----|---------|---------|
| QOS-7.1 | 10 实例部署可处理 50,000 RPS（Token 验证），P99 < 10ms | Locust 压测 |
| QOS-7.2 | 登录请求在 5,000 RPS 负载下 P99 < 200ms | 自动化压测 |
| QOS-7.3 | 单实例故障不影响集群可用性（健康检查 + 自动摘除） | Chaos 测试 |
| QOS-7.4 | 缓存命中率 > 95%（Token 验证场景） | APM 监控 |
| QOS-7.5 | 限流触发时返回 HTTP 429 + Retry-After Header | API 测试 |
| QOS-7.6 | 熔断器在下游故障时 30 秒内自动开启，60 秒后半开试探 | 故障注入测试 |
| QOS-7.7 | 配额用尽时返回 QUOTA_EXCEEDED，不影响其他租户 | 多租户压测 |
| QOS-7.8 | 水平扩展时无需重启服务（Kubernetes HPA） | K8s 扩缩测试 |
| QOS-7.9 | PostgreSQL 从库读取延迟 < 50ms | DB 监控 |
| QOS-7.10 | 无状态设计：任意实例可处理任意请求 | 请求追踪测试 |


---



# Phase 2-8：安全报表/用户画像

## 1. 概述

### 1.1 背景

Phase 2-3 主动防御模块已构建风控事件采集能力，但缺少可视化报表和用户行为分析。管理员需要：全局安全态势仪表盘；登录异常检测报表；用户行为画像（UEBA）；自定义查询和导出。

### 1.2 设计目标

| 能力 | 说明 |
|------|------|
| **安全仪表盘** | 全局安全态势：实时攻击地图、Top 攻击源、风险趋势图 |
| **登录异常报表** | 异地登录、异常时间、暴力破解等事件报表 |
| **用户行为画像** | 用户活跃度、信任设备分布、权限变更历史 |
| **自定义查询** | 支持 SQL-like 查询引擎，按条件过滤 |
| **报表导出** | 支持 CSV/Excel/PDF 格式导出 |

---

## 2. 核心功能

### 2.1 安全态势仪表盘

- 本月登录次数、异常登录事件、被阻断攻击数、活跃用户数
- 攻击趋势图（折线图，近30天）
- Top 5 攻击来源 IP（柱状图）
- 实时告警列表

### 2.2 用户行为画像

| 维度 | 指标 | 说明 |
|------|------|------|
| **活跃度** | 最近登录时间、7天/30天登录次数 | 识别僵尸账号 |
| **设备分布** | 常用设备数量、信任设备比例 | 识别异常设备 |
| **位置特征** | 常用登录地点（城市） | 识别异地登录 |
| **时间特征** | 常用登录时段 | 识别异常时间 |
| **权限变更** | 近30天角色变更次数 | 识别权限滥用 |
| **风险暴露** | 当前风险评分、风险事件数 | 识别高风险用户 |

---

## 3. API 设计

### 3.1 仪表盘 API

#### GET /api/v1/admin/v1/reports/dashboard — 安全态势总览

**前置条件：** 管理员角色

**查询参数：** `period`: 7d / 30d / 90d（默认 30d）

**响应 200：**
```json
{
  "total_logins": 1234567,
  "total_logins_change_pct": 12.3,
  "anomalous_events": 1234,
  "anomalous_events_change_pct": -3.2,
  "blocked_attacks": 5678,
  "blocked_attacks_change_pct": 8.9,
  "active_users": 98765,
  "active_users_change_pct": 5.1,
  "trend_data": [
    {"date": "2026-04-01", "logins": 40000, "anomalies": 50, "blocked": 100}
  ],
  "top_attack_sources": [
    {"ip": "192.168.1.100", "count": 1234, "country": "CN"}
  ],
  "risk_distribution": {"low": 98000, "medium": 1500, "high": 265}
}
```

#### GET /api/v1/admin/v1/reports/login-anomalies — 登录异常报表

**查询参数：** `type` (geo/time/device/bruteforce)、`start_date`、`end_date`、`user_id`、`page`、`page_size`

**响应 200：**
```json
{
  "items": [
    {
      "event_id": "uuid",
      "user_id": "uuid",
      "user_email": "user@example.com",
      "anomaly_type": "geo_anomaly",
      "description": "异地登录：上海 -> 北京，2小时内",
      "ip_address": "1.2.3.4",
      "geo_location": {"city": "Beijing", "country": "CN"},
      "previous_location": {"city": "Shanghai", "country": "CN"},
      "created_at": "2026-04-03T08:00:00Z",
      "risk_score": 75,
      "status": "pending_review"
    }
  ],
  "total": 1234,
  "page": 1,
  "page_size": 50
}
```

#### GET /api/v1/admin/v1/reports/user-profile/{user_id} — 用户行为画像

**响应 200：**
```json
{
  "user_id": "uuid",
  "email": "user@example.com",
  "profile": {
    "last_login_at": "2026-04-03T08:00:00Z",
    "login_count_7d": 35,
    "login_count_30d": 150,
    "trust_score": 85,
    "risk_level": "low",
    "account_age_days": 365
  },
  "devices": {
    "total": 5,
    "trusted": 3,
    "recent": [
      {"fp_hash": "abc...", "ua": "Chrome/Windows", "last_seen": "2026-04-03", "is_trusted": true}
    ]
  },
  "locations": {
    "primary": ["Shanghai", "Beijing"],
    "recent": [
      {"city": "Shanghai", "country": "CN", "last_seen": "2026-04-03", "count": 100}
    ]
  },
  "time_patterns": {
    "usual_login_hours": [9, 10, 11, 14, 15, 16],
    "usual_login_days": ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]
  },
  "permissions": {
    "current_roles": ["admin"],
    "role_changes_30d": 2,
    "last_role_change": "2026-03-15T10:00:00Z"
  },
  "risk_factors": [
    {"factor": "new_device", "severity": "medium", "detail": "首次使用该设备登录"}
  ]
}
```

### 3.2 数据导出 API

#### POST /api/v1/admin/v1/reports/export — 导出报表

**请求体：**
```json
{
  "report_type": "login_anomalies",
  "format": "csv",
  "filters": {
    "start_date": "2026-03-01",
    "end_date": "2026-03-31",
    "type": "geo_anomaly"
  },
  "notify_email": "admin@example.com"
}
```

**响应 202：**
```json
{
  "export_id": "uuid",
  "status": "processing",
  "estimated_completion": "2026-04-03T09:00:00Z",
  "download_url": null
}
```

---

## 4. 数据模型

### 4.1 报表存储（ClickHouse / TimescaleDB）

```sql
-- 登录事件宽表（用于 OLAP 查询）
CREATE TABLE login_events_olap (
    event_id          UUID,
    tenant_id         UUID,
    user_id           UUID,
    user_email        VARCHAR(255),
    status            VARCHAR(16),
    login_method      VARCHAR(32),
    ip_address        INET,
    geo_country       VARCHAR(8),
    geo_city          VARCHAR(64),
    geo_latitude      DECIMAL(9,6),
    geo_longitude     DECIMAL(9,6),
    user_agent        TEXT,
    device_fp_hash    VARCHAR(64),
    risk_score        INTEGER,
    risk_level        VARCHAR(8),
    mfa_used          BOOLEAN,
    login_hour        SMALLINT,
    login_weekday     VARCHAR(12),
    is_anomalous      BOOLEAN,
    anomaly_types     ARRAY[VARCHAR(32)],
    created_at        TIMESTAMPTZ
) PARTITION BY (toYYYYMM(created_at));

CREATE INDEX idx_login_events_user ON login_events_olap(user_id, created_at DESC);
CREATE INDEX idx_login_events_ip ON login_events_olap(ip_address, created_at DESC);
CREATE INDEX idx_login_events_anomaly ON login_events_olap(tenant_id, is_anomalous, created_at DESC);

-- 用户画像物化视图（每日更新）
CREATE MATERIALIZED VIEW user_behavior_profile AS
SELECT
    user_id,
    tenant_id,
    COUNT(*) FILTER (WHERE status = 'success' AND created_at > NOW() - INTERVAL '7 days') AS logins_7d,
    COUNT(*) FILTER (WHERE status = 'success' AND created_at > NOW() - INTERVAL '30 days') AS logins_30d,
    COUNT(DISTINCT device_fp_hash) FILTER (WHERE created_at > NOW() - INTERVAL '30 days') AS devices_30d,
    COUNT(DISTINCT geo_city) FILTER (WHERE status = 'success' AND created_at > NOW() - INTERVAL '30 days') AS cities_30d,
    AVG(risk_score) FILTER (WHERE created_at > NOW() - INTERVAL '30 days') AS avg_risk_score_30d,
    MAX(risk_score) FILTER (WHERE created_at > NOW() - INTERVAL '30 days') AS max_risk_score_30d,
    COUNT(*) FILTER (WHERE is_anomalous = TRUE AND created_at > NOW() - INTERVAL '30 days') AS anomaly_count_30d
FROM login_events_olap
GROUP BY user_id, tenant_id;
```

---

## 5. 验收标准

| ID | 验收条件 | 测试方式 |
|----|---------|---------|
| RP-8.1 | 安全仪表盘可在 3 秒内加载 30 天数据 | 手动测试 |
| RP-8.2 | 登录异常报表支持按类型/时间/IP/用户过滤 | API 测试 |
| RP-8.3 | 用户画像数据每日凌晨 3 点自动刷新 | 定时任务检查 |
| RP-8.4 | 报表导出支持 CSV/Excel 格式，100MB 以内 5 分钟生成 | 手动测试 |
| RP-8.5 | 攻击趋势图数据支持近 90 天切换 | 手动测试 |
| RP-8.6 | 高风险用户（risk_level=high）红色标记高亮 | UI 测试 |


---

# Phase 2-9：SSO 统一登出

## 1. 概述

### 1.1 背景

企业用户通过 SSO（OIDC/SAML）登录多个应用后，注销时需要**一键登出所有应用**，而不是逐个登出。AuthMaster 需要作为 Identity Provider（IdP），支持 SP-Initiated 登出和 IdP-Initiated 登出两种场景。

### 1.2 设计目标

| 能力 | 说明 |
|------|------|
| **SP-Initiated 登出** | 用户在某个 SP 应用中发起登出，通知 IdP 登出 |
| **IdP-Initiated 登出** | 用户在 IdP（AuthMaster）发起登出，登出所有已登录 SP |
| **会话管理** | IdP 统一管理用户会话，支持强制下线 |
| **OIDC 登出** | 支持 OpenID Connect Front-Channel 登出 |
| **SAML 登出** | 支持 SAML 2.0 Single Logout |

---

## 2. 核心功能

### 2.1 SSO 会话管理

AuthMaster IdP 维护全局会话表：

```
用户登录 IdP（OIDC/SAML）
    ↓
IdP 创建主会话（auth_sessions 表，idp_session_id）
    ↓
IdP 生成授权码/Token，携带 session_state 跳转到 SP
    ↓
SP 验证 Token 并创建本地会话
    ↓
SP 将 session_state 回调 IdP（iframe/重定向）
    ↓
IdP 记录 SP session 映射（sp_sessions 表）
```

### 2.2 SP-Initiated 登出（OIDC）

```
用户点击 SP 应用"登出"按钮
    ↓
SP 向 IdP (AuthMaster) 发起 /oidc/logout 请求
    ↓
IdP 检查 session_state，清除本地会话
    ↓
IdP 向所有注册的 SP 发送 Front-Channel 登出通知（iframe）
    ↓
各 SP 清除本地会话
    ↓
IdP 重定向用户到 post_logout_redirect_uri
```

### 2.3 IdP-Initiated 登出

```
用户在 AuthMaster IdP 点击"登出所有应用"
    ↓
IdP 查询 sp_sessions 表中该用户的所有 SP session
    ↓
IdP 向所有 SP 发送批量登出请求（后台队列）
    ↓
IdP 清除本地所有会话（auth_sessions 表）
    ↓
返回"已登出"页面
```

---

## 3. API 设计

### 3.1 OIDC 登出

#### GET /oidc/logout — SP-Initiated 登出入口

**查询参数：** `id_token_hint`, `post_logout_redirect_uri`, `state`

#### POST /oidc/logout — 登出确认

**请求体：**
```json
{
  "id_token_hint": "eyJ...",
  "action": "logout_confirmed"
}
```

### 3.2 SAML 登出

#### POST /saml/slo — SAML Single Logout

支持 SAML 2.0 的 SP-Initiated 和 IdP-Initiated 两种 SLO 流程。

### 3.3 会话管理 API

#### GET /api/v1/admin/v1/sessions — 列出所有活跃会话

**前置条件：** 管理员角色

**响应 200：**
```json
{
  "items": [
    {
      "session_id": "uuid",
      "user_id": "uuid",
      "user_email": "user@example.com",
      "login_method": "oidc_google",
      "ip_address": "1.2.3.4",
      "user_agent": "Chrome/Windows",
      "created_at": "2026-04-03T08:00:00Z",
      "last_active_at": "2026-04-03T10:00:00Z",
      "sp_count": 5
    }
  ],
  "total": 1234
}
```

#### DELETE /api/v1/admin/v1/sessions/{session_id} — 强制下线（管理员）

#### DELETE /api/v1/admin/v1/sessions/user/{user_id} — 强制下线用户所有会话

---

## 4. 数据模型

### 4.1 SSO 会话表

```sql
-- OIDC/SAML SP Session 映射表
CREATE TABLE sp_sessions (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    idp_session_id      UUID NOT NULL REFERENCES auth_sessions(id),
    user_id             UUID NOT NULL REFERENCES auth_users(id),
    tenant_id           UUID NOT NULL REFERENCES auth_tenants(id),
    client_id           VARCHAR(128) NOT NULL,
    sp_session_id       VARCHAR(512),
    protocol            VARCHAR(16) NOT NULL CHECK (protocol IN ('oidc', 'saml')),
    id_token_hint       TEXT,
    front_channel_uri   TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at          TIMESTAMPTZ,
    revoked_at          TIMESTAMPTZ,

    CONSTRAINT uq_sp_session UNIQUE (client_id, sp_session_id, protocol)
);

CREATE INDEX idx_sp_sessions_idp ON sp_sessions(idp_session_id, revoked_at);
CREATE INDEX idx_sp_sessions_user ON sp_sessions(user_id, revoked_at);

-- OIDC 客户端注册表（新增）
CREATE TABLE oidc_clients (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL REFERENCES auth_tenants(id),
    client_id           VARCHAR(128) NOT NULL UNIQUE,
    client_secret_hash   VARCHAR(64),
    client_name         VARCHAR(256) NOT NULL,
    redirect_uris       JSONB NOT NULL DEFAULT '[]',
    post_logout_uris    JSONB DEFAULT '[]',
    front_channel_uris  JSONB DEFAULT '[]',
    allowed_scopes      JSONB DEFAULT '["openid","profile"]',
    policy              JSONB DEFAULT '{}',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_oidc_clients_tenant ON oidc_clients(tenant_id);
```

---

## 5. 实现要点

### 5.1 OIDC Front-Channel 登出

IdP 渲染隐藏 iframe，向每个已注册 SP 的 frontchannel_logout_uri 发送请求：

```html
<iframe src="https://sp1.example.com/oidc/logout/frontchannel">
</iframe>
<iframe src="https://sp2.example.com/oidc/logout/frontchannel">
</iframe>
```

### 5.2 批量登出队列

大量 SP 时，IdP-Initiated 登出采用异步队列：

```python
async def idp_initiated_logout(idp_session_id: UUID):
    sp_sessions = await db.fetch(
        "SELECT * FROM sp_sessions WHERE idp_session_id = $1 AND revoked_at IS NULL",
        idp_session_id
    )
    for sp in sp_sessions:
        await logout_queue.enqueue({
            "sp_session_id": sp["id"],
            "client_id": sp["client_id"],
            "protocol": sp["protocol"],
            "logout_uri": sp["front_channel_uri"] or build_slo_uri(sp),
        })

    # 清除 IdP 本地会话
    await db.execute(
        "UPDATE auth_sessions SET revoked = TRUE, revoked_at = NOW() WHERE id = $1",
        idp_session_id
    )

    # 标记 SP sessions 已登出
    await db.execute(
        "UPDATE sp_sessions SET revoked_at = NOW() WHERE idp_session_id = $1",
        idp_session_id
    )
```

---

## 6. 验收标准

| ID | 验收条件 | 测试方式 |
|----|---------|---------|
| SSO-9.1 | 用户在任一 SP 登出后，IdP 会话同步清除 | 手动测试（多浏览器） |
| SSO-9.2 | IdP-Initiated 登出后，所有 SP 会话均被清除 | 手动测试 |
| SSO-9.3 | OIDC Front-Channel 登出各 SP 可在 5 秒内收到通知 | 日志验证 |
| SSO-9.4 | SAML SP-Initiated SLO 正常完成 | SAML tracer 验证 |
| SSO-9.5 | 管理员可强制下线任意用户的所有会话 | API 测试 |
| SSO-9.6 | 会话过期后 SP session 自动失效（TTL 兜底） | 自动化测试 |
| SSO-9.7 | SP 离线或不可达时，IdP 登出不阻塞（异步通知） | 故障注入测试 |
| SSO-9.8 | 管理员可查看所有活跃 SP session，支持按用户筛选 | API 测试 |


---


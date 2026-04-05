# IAM MVP Phase 2 — MFA/2FA 多因素认证模块设计方案

> **编写角色：** 架构师（Architect）  
> **修订记录：** v4 — 第4轮修订（最后一轮，修复 CSRF 矛盾、IPv6 子网、地理定位可选、指纹容差简化、恢复码响应统一）  
> **输出路径：** `C:\Users\Administrator\Documents\龙虾小兵项目\IAM_PHASE2_MFA_DESIGN.md`  
> **项目基础：** IAM MVP Phase 1（Sprint 1-4），技术栈 FastAPI + SQLAlchemy async + Redis + PostgreSQL

---

## 1. 概述

### 1.1 模块目标

在已有手机号+验证码登录、邮箱+密码登录的基础上，新增**第二因素认证（2FA/MFA）**层，实现：

| 因素 | 类型 | 说明 |
|------|------|------|
| 第一因素 | 手机号+短信验证码 / 邮箱+密码 | 已有登录凭证 |
| 第二因素（TOTP） | TOTP（Google Authenticator 类） | 基于时间的一次性密码，6位数字 |
| 第二因素（短信） | SMS MFA | 登录时额外触发短信验证码 |
| 备份码 | 一次性备用码 | TOTP 绑定时生成，10个 bcrypt 加密 |

### 1.2 设计原则

- **渐进式绑定**：用户可选择性开启 TOTP 或 SMS MFA，灵活选择
- **向后兼容**：未开启 MFA 的用户登录流程保持不变
- **安全优先**：TOTP secret 加密存储，备份码 bcrypt 加密，Redis 防爆
- **记住设备**：30天免 MFA，降低重复验证摩擦
- **审计完整**：所有 MFA 操作写入审计日志
- **CSRF 防护**：所有 MFA 写操作接口均强制 CSRF 校验（同步 Token 模式）
- **恢复可应急**：用户丢失所有 MFA 凭证后可通过紧急恢复流程重获访问

---

## 2. 数据库变更

### 2.1 users 表改造

在现有 `users` 表上新增字段：

```sql
ALTER TABLE users ADD COLUMN mfa_enabled          BOOLEAN  DEFAULT FALSE;
ALTER TABLE users ADD COLUMN mfa_type             VARCHAR(16);  -- 'totp' | 'sms' | 'both'
ALTER TABLE users ADD COLUMN mfa_secret_encrypted VARCHAR(512);  -- 保留，渐进废弃
ALTER TABLE users ADD COLUMN mfa_phone            VARCHAR(32);  -- 绑定 MFA 专用手机号
ALTER TABLE users ADD COLUMN mfa_phone_verified   BOOLEAN DEFAULT FALSE;
```

> **迁移兼容性说明：** `mfa_enabled` 默认值为 `FALSE`，确保 Phase 1 已有的所有用户在 Phase 2 上线后登录流程完全不变（无需任何迁移脚本或强制激活）。Phase 3 视需求决定是否允许管理员批量启用。

### 2.2 新建表：mfa_totp

```sql
CREATE TABLE mfa_totp (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID NOT NULL UNIQUE REFERENCES users(id),
    secret_encrypted    VARCHAR(512) NOT NULL,   -- AES-256-GCM 加密后的 TOTP secret
    enabled             BOOLEAN DEFAULT FALSE,
    backup_codes_json   TEXT,
    verified_at         TIMESTAMP,
    created_at          TIMESTAMP DEFAULT NOW(),
    updated_at          TIMESTAMP DEFAULT NOW()
);
CREATE INDEX idx_mfa_totp_user ON mfa_totp(user_id);
```

### 2.3 新建表：mfa_sms_codes

```sql
CREATE TABLE mfa_sms_codes (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id),
    phone           VARCHAR(32) NOT NULL,
    code            VARCHAR(16) NOT NULL,   -- bcrypt 存储
    purpose         VARCHAR(32) DEFAULT 'mfa_verify',
    used            BOOLEAN DEFAULT FALSE,
    expires_at      TIMESTAMP NOT NULL,
    created_at      TIMESTAMP DEFAULT NOW()
);
CREATE INDEX idx_mfa_sms_user ON mfa_sms_codes(user_id);
CREATE INDEX idx_mfa_sms_phone ON mfa_sms_codes(phone);
CREATE INDEX idx_mfa_sms_expires ON mfa_sms_codes(expires_at);
```

### 2.4 新建表：mfa_backup_codes

```sql
CREATE TABLE mfa_backup_codes (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id),
    mfa_type        VARCHAR(16) NOT NULL,  -- 'totp'
    code_hash       VARCHAR(256) NOT NULL, -- bcrypt 加密
    used            BOOLEAN DEFAULT FALSE,
    used_at         TIMESTAMP,
    attempt_count   INTEGER DEFAULT 0,
    created_at      TIMESTAMP DEFAULT NOW()
);
CREATE INDEX idx_mfa_bc_user ON mfa_backup_codes(user_id);
CREATE UNIQUE INDEX idx_mfa_bc_code ON mfa_backup_codes(user_id, code_hash);
```

### 2.5 新建表：user_mfa_devices

```sql
CREATE TABLE user_mfa_devices (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id),
    device_token    VARCHAR(256) NOT NULL UNIQUE,
    device_salt     VARCHAR(64) NOT NULL,
    device_name     VARCHAR(256),
    user_agent      VARCHAR(512),
    ip_subnet       VARCHAR(45),  -- 存储 IP 的子网前缀（默认 /24，可配置至 /28）
    mfa_type        VARCHAR(16) NOT NULL,
    last_verified_at TIMESTAMP NOT NULL,
    expires_at      TIMESTAMP NOT NULL,
    created_at      TIMESTAMP DEFAULT NOW()
);
CREATE INDEX idx_mfa_device_user ON user_mfa_devices(user_id);
CREATE INDEX idx_mfa_device_token ON user_mfa_devices(device_token);
```

### 2.6 新建表：mfa_recovery_tokens（紧急恢复码）

```sql
CREATE TABLE mfa_recovery_tokens (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id),
    token_hash      VARCHAR(256) NOT NULL,         -- bcrypt 加密的恢复码
    delivery_channel VARCHAR(16) NOT NULL,          -- 'email' | 'sms'
    delivery_target  VARCHAR(128) NOT NULL,         -- 已验证的邮箱或手机号（脱敏）
    used            BOOLEAN DEFAULT FALSE,
    used_at         TIMESTAMP,
    expires_at      TIMESTAMP NOT NULL,             -- 生成后 15 分钟有效
    created_at      TIMESTAMP DEFAULT NOW()
);
CREATE INDEX idx_mfa_recovery_user ON mfa_recovery_tokens(user_id);
CREATE INDEX idx_mfa_recovery_expires ON mfa_recovery_tokens(expires_at);
```

---

## 3. Redis Key 设计

### 3.1 速率限制（防爆）

```
mfa:sms:count:{phone}        # 同一手机号 SMS MFA 验证码发送次数，TTL: 3600s，最大3次/小时
mfa:sms:rate:{phone}          # 上一次发送时间戳，TTL: 60s（发送间隔至少60秒）
mfa:verify:attempt:{user_id}  # MFA 验证失败次数（含 TOTP/SMS/备份码），TTL: 300s，阈值: 5次/5分钟
```

### 3.2 MFA 流程状态（防遍历）

```
mfa:pending:{random_suffix}:{session_jti}  # 随机后缀防遍历，JSON:
                             # {"user_id","tenant_id","mfa_type","created_at","fingerprint","csrf_token"}
                             # TTL: 600秒
                             # random_suffix: 16字节 os.urandom(16).hex()
                             # csrf_token: 32字节 secrets.token_hex(32)
                             # 异常访问监控：mfa.pending_access_anomaly

mfa:totp:secret:{user_id}    # 临时存储未激活 TOTP secret，TTL: 600s
```

### 3.3 备份码单独尝试计数（穷举防护）

```
mfa:bc:attempt:{user_id}:{code_hash_suffix}  # 单个备份码失败计数，TTL: 600s
                                              # 满3次则该备份码被永久锁定
```

### 3.4 CSRF Token（同步 Token 模式）

```
mfa:csrf:{session_jti}    # 32字节 CSRF Token，TTL: 600s，与 MFA pending 同步
                            # Token 在 JSON 响应体中返回给前端（不是 Cookie）
                            # Cookie 仅传输辅助：Set-Cookie: __mfa_csrf=<token>; Secure; SameSite=Strict; Max-Age=600
```

---

## 4. API 接口设计

### 4.1 TOTP 绑定流程

#### `POST /auth/mfa/totp/setup` — 初始化 TOTP

**前置条件：** 已通过第一步认证（持有有效 AccessToken）

**CSRF 防护：** 校验请求头 `X-MFA-CSRF-Token` 与 Redis `mfa:csrf:{session_jti}` 中存储的 token 一致（同步 Token 模式）

**请求体：** `{}`

**响应（200）：**
```json
{
  "totp_uri": "otpauth://totp/AuthMaster:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=AuthMaster&algorithm=SHA1&digits=6&period=30",
  "secret_base32": "JBSWY3DPEHPK3PXP",
  "qr_code_data_url": "data:image/png;base64,...",
  "backup_codes": [
    {"code": "ABCD-1234", "used": false},
    {"code": "EFGH-5678", "used": false}
  ],
  "csrf_token": "a1b2c3d4...",
  "expires_in_seconds": 600
}
```

**业务逻辑：**

1. 生成 20 字节随机 TOTP secret，编码为 Base32
2. 生成 10 个备份码（格式：`XXXX-XXXX`，字符集 A-Z0-9 共36个字符，使用 `secrets.choice` 密码学安全随机数）
3. 生成 32 字节 CSRF Token，写入 Redis `mfa:csrf:{session_jti}`（TTL 600s），同时在响应体中返回（前端存于内存变量，不落 localStorage）
4. TOTP secret 使用 AES-256-GCM 加密，存入 Redis `mfa:totp:secret:{user_id}`（10分钟TTL）
5. 备份码 bcrypt 加密后返回明文（仅此次可见）
6. 审计日志 `mfa.totp.setup_initiated`

---

#### `POST /auth/mfa/totp/verify` — 绑定确认

**前置条件：** 已调用 `/auth/mfa/totp/setup`，持有临时 secret

**CSRF 防护：** 校验请求头 `X-MFA-CSRF-Token` 与 Redis `mfa:csrf:{session_jti}` 一致（同步 Token 模式）

**请求体：**
```json
{
  "code": "123456"
}
```

**业务逻辑：**

1. 从 Redis 获取临时 TOTP secret，解密
2. 验证 6 位 TOTP 码（`window=1`，即当前时间前后各30秒 ±1 周期容差）
3. TOTP 验证通过后：
   - secret 加密后写入 `mfa_totp` 表，`enabled=True`
   - 备份码 bcrypt 加密后写入 `mfa_backup_codes` 表
   - 删除 Redis 临时 secret
   - 更新 `users.mfa_enabled=True`，`users.mfa_type='totp'`
4. 验证失败返回 400，记录失败次数

---

### 4.2 短信 MFA

#### `POST /auth/mfa/sms/enable` — 开启短信 MFA

**前置条件：** 已通过第一步认证

**CSRF 防护：** 校验 `X-MFA-CSRF-Token` 请求头与 Redis 一致（同步 Token 模式）

**请求体：**
```json
{
  "phone": "+86-138-0000-0000",
  "code": "123456"
}
```

**业务逻辑：**
1. 验证手机号格式
2. 从 `verification_codes` 表校验 `purpose='bind'` 的最新未使用验证码（5分钟有效）
3. 通过后更新 `users.mfa_phone`，`mfa_phone_verified=True`，`mfa_enabled=True`，`mfa_type='sms'`
4. 审计日志 `mfa.sms_enabled`

#### `POST /auth/mfa/sms/send` — 发送绑定手机号验证码

**CSRF 防护：** 校验 `X-MFA-CSRF-Token` 请求头与 Redis 一致（同步 Token 模式）

---

### 4.3 MFA 状态与管理

#### `GET /auth/mfa/status` — 当前用户 MFA 状态

**前置条件：** 已登录（持有 AccessToken）

**响应（200）：**
```json
{
  "mfa_enabled": true,
  "mfa_type": "totp",
  "totp_configured": true,
  "sms_mfa_configured": false,
  "mfa_phone": "+86-138****0000",
  "backup_codes_remaining": 7,
  "trusted_devices_count": 2,
  "trusted_devices": [
    {
      "device_name": "Chrome on Windows",
      "last_verified_at": "2025-03-01T10:00:00Z",
      "expires_at": "2025-03-31T10:00:00Z"
    }
  ]
}
```

---

#### `DELETE /auth/mfa/disable` — 关闭 MFA

**前置条件：** 已登录，需验证当前 MFA

**CSRF 防护：** 校验 `X-MFA-CSRF-Token` 请求头与 Redis 一致（同步 Token 模式）

**请求体（mfa_type='totp'）：**
```json
{
  "code": "123456",
  "reason": "user_requested"
}
```

**请求体（mfa_type='sms'）：**
```json
{
  "phone": "+86-138-0000-0000",
  "code": "123456",
  "reason": "user_requested"
}
```

**业务逻辑：**
1. 验证当前 MFA（TOTP 或 SMS）
2. 验证成功后：删除 `mfa_totp`、清空 `mfa_backup_codes`、删除 `user_mfa_devices`、更新 `users.mfa_enabled=False`，`mfa_type=NULL`
3. 审计日志 `mfa.disabled`

---

### 4.4 MFA 验证流程接口

#### `POST /auth/mfa/verify` — MFA 最终验证

**前置条件：** 已完成第一步登录，进入 MFA 验证阶段

**CSRF 防护：** 校验请求头 `X-MFA-CSRF-Token` 与 Redis `mfa:csrf:{session_jti}` 一致（同步 Token 模式）

**请求体（TOTP）：**
```json
{
  "mfa_type": "totp",
  "code": "123456",
  "remember_device": true
}
```

**请求体（SMS）：**
```json
{
  "mfa_type": "sms",
  "phone": "+86-138-0000-0000",
  "code": "123456",
  "remember_device": true
}
```

**请求体（备份码）：**
```json
{
  "mfa_type": "backup_code",
  "code": "ABCD-1234",
  "remember_device": true
}
```

**响应（200）：**
```json
{
  "access_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "mfa_verified": true,
  "remember_device_applied": true
}
```

**业务逻辑：**

1. **CSRF 校验**：从请求头 `X-MFA-CSRF-Token` 读取，与 Redis `mfa:csrf:{session_jti}` 比对（同步 Token），不匹配则 403
2. **TOTP 验证**：`window=1`（当前时间前后各30秒容差）
3. **SMS 验证**：5分钟有效，标记 `used=True`
4. **备份码验证**：单个码最多3次尝试后锁定；全局 `mfa:verify:attempt:{user_id}` 5次/5分钟上限
5. **记住设备**（`remember_device=true` 时）：
   - device_token = `HMAC-SHA256(key=device_salt, message=UA + "|" + ip_subnet(ipv4_prefix, ipv6_prefix))`
   - IPv4 子网前缀可配置（默认 `/24`，可收紧至 `/28`）
   - **IPv6 子网前缀可配置（v4 新增，默认 `/64`）**
6. 签发完整 AccessToken，清除 MFA pending 状态
7. 审计日志 `mfa.verified`

---

#### `POST /auth/mfa/send-code` — 触发 MFA 短信

**前置条件：** MFA 验证阶段，选择 SMS 方式

**CSRF 防护：** 校验 `X-MFA-CSRF-Token` 请求头与 Redis 一致（同步 Token 模式）

**请求体：**
```json
{
  "phone": "+86-138-0000-0000"
}
```

**Redis 防爆：** `mfa:sms:count:{phone}` 每小时最多 3 次；`mfa:sms:rate:{phone}` 发送间隔至少 60 秒

---

### 4.5 MFA 禁用恢复流程

> **问题背景：** 用户丢失 TOTP 设备且备份码已全部用完，将永远被锁定。本节补充紧急恢复机制（v3 新增，v4 统一恢复码错误响应）。

#### 4.5.1 恢复方式一：邮箱恢复码（首选）

**`POST /auth/mfa/recovery/request` — 请求紧急恢复码**

**前置条件：** 通过身份认证（邮箱+密码，或手机号+短信验证码）

**CSRF 防护：** 同步 Token 模式

**请求体：**
```json
{
  "channel": "email"
}
```

**响应（200）：**
```json
{
  "message": "Recovery code sent to your verified email address ****@example.com",
  "expires_in_seconds": 900
}
```

**业务逻辑：**
1. 确认用户有已验证邮箱且 `mfa_enabled=True`
2. 生成 8 位高熵恢复码：使用 `secrets.choice(A-Z0-9)` × 8（字符集36个，熵值约 `log2(36^8) ≈ 41.3 bits`）
3. 恢复码 bcrypt 加密后存入 `mfa_recovery_tokens`（15分钟有效，一次性）
4. 明文通过邮件发送（说明：15分钟有效，一次性使用，若非本人操作请联系管理员）
5. 审计日志 `mfa.recovery_requested`
6. 用户通过身份认证后，`mfa:verify:attempt:{user_id}` 重置

---

#### 4.5.2 恢复方式二：短信恢复码

**`POST /auth/mfa/recovery/request`（channel: "sms"）**

**前置条件：** 用户有已验证的 MFA 绑定手机号 `mfa_phone`

**业务逻辑：** 同邮箱恢复码，差异在于通过 SMS 发送，Redis 限流同样适用。

---

#### 4.5.3 恢复码验证

**`POST /auth/mfa/recovery/verify` — 提交恢复码**

**CSRF 防护：** 同步 Token 模式

**请求体：**
```json
{
  "recovery_code": "XK7M2P9Q"
}
```

**错误响应（v4 统一）：**
```json
{"error": "mfa_recovery_code_invalid", "message": "Invalid or expired recovery code"}
```

> **v4 修订说明（恢复码错误响应统一）：** 所有无效恢复码情况（已用、过期、不存在）统一返回 `mfa_recovery_code_invalid`，不在响应体中区分具体原因，防止攻击者通过响应差异推断恢复码状态。是否已使用、是否过期等细节仅记录于审计日志（`mfa.recovery_code_used`、`mfa.recovery_code_expired`）。

**验证成功业务逻辑：**
- 标记 `used=True`
- 删除 `mfa_totp`、`mfa_backup_codes`、`user_mfa_devices`
- 更新 `users.mfa_enabled=False`，`mfa_type=NULL`
- 删除该用户所有 `mfa_recovery_tokens` 记录
- 审计日志 `mfa.recovered_via_email` 或 `mfa.recovered_via_sms`

---

#### 4.5.4 恢复方式三：管理员人工审核

**`POST /auth/admin/mfa/recovery/approve` — 管理员审批紧急恢复**

**前置条件：** 管理员认证

**CSRF 防护：** 同步 Token 模式

**请求体：**
```json
{
  "user_id": "uuid-of-locked-user",
  "reason": "User provided identity documents via support ticket #12345",
  "admin_notes": "Identity verified via video call on 2026-04-03"
}
```

**业务逻辑：** 审批后执行与恢复码相同的禁用逻辑，审计日志 `mfa.admin_recovery`（记录 admin_id、user_id、reason）

---

### 4.6 CSRF 防护机制详解

> **修订说明（v4）：** 所有 MFA 写操作接口均强制 CSRF 校验，采用**同步 Token 模式（Synchronous Token Pattern）**。本方案彻底解决 HttpOnly 与 Double Submit 的互斥矛盾。

#### 4.6.1 同步 Token 模式（Synchronous Token Pattern）

**原理：**
- 服务端生成 32 字节 `secrets.token_hex(32)` CSRF Token
- Token 存储于 Redis `mfa:csrf:{session_jti}`（TTL 600s）
- Token 在需要 CSRF 保护的接口初始调用时，通过 **JSON 响应体**返回给前端（不是 Cookie）
- 前端将 token 存于内存变量（不写入 localStorage/cookie，避免 XSS 读取）
- 后续同会话的写操作请求，通过 `X-MFA-CSRF-Token` 请求头携带 token
- 服务端仅需比对请求头 token 与 Redis 中存储的 token 是否一致

**Cookie 仅做传输辅助（无安全依赖）：**
```
Set-Cookie: __mfa_csrf=<token>; Secure; SameSite=Strict; Path=/; Max-Age=600
```
Cookie 不设置 HttpOnly，允许前端读取（但前端不依赖此方式，仅作冗余传输），真正的 CSRF 保护依赖请求头 token 与 Redis 的比对。

**验证逻辑（伪代码）：**
```python
async def verify_csrf(request: Request, session_jti: str):
    header_token = request.headers.get("X-MFA-CSRF-Token")
    redis_token = await redis.get(f"mfa:csrf:{session_jti}")
    if not header_token or not redis_token:
        raise CSRFValidationFailed()  # 403
    if not hmac.compare_digest(header_token, redis_token):
        raise CSRFValidationFailed()  # 403
```

**为什么不用 Double Submit？**
Double Submit 要求 Cookie 中的 token 可被前端 JavaScript 读取（不得 HttpOnly），以作为请求头 token 的比对源。但 Cookie 设为 HttpOnly 是防止 XSS 读取的最佳实践，两者互斥。同步 Token 模式不存在此矛盾，且安全性更强（token 仅存于服务端 Redis，不依赖任何客户端状态猜测）。

**适用接口（均需 CSRF 校验）：**
| 接口 | 方法 |
|------|------|
| `/auth/mfa/totp/setup` | POST |
| `/auth/mfa/totp/verify` | POST |
| `/auth/mfa/sms/enable` | POST |
| `/auth/mfa/sms/send` | POST |
| `/auth/mfa/verify` | POST |
| `/auth/mfa/disable` | DELETE |
| `/auth/mfa/recovery/request` | POST |
| `/auth/mfa/recovery/verify` | POST |
| `/auth/admin/mfa/recovery/approve` | POST |

---

## 5. 登录流程改造

### 5.1 Phase 2 流程（MFA 增强）

```
第一步（现有登录）
  ↓
用户 → 手机号+验证码 / 邮箱+密码 → 验证通过
  ↓
检查 users.mfa_enabled？
  ├─ 否 → 直接签发完整 AccessToken（流程同 Phase 1）
  └─ 是 → 进入 MFA 验证阶段
            ↓
        检查 device_token 是否在 user_mfa_devices 表且未过期？
            ├─ 是 → 跳过 MFA，直接签发 AccessToken
            └─ 否 → 要求用户完成第二因素验证
                      ↓
                  TOTP / SMS / 备份码 验证
                      ↓
                  验证通过 → 签发完整 AccessToken
```

### 5.2 MFA Session 中间态

```
mfa:pending:{random_suffix}:{session_jti}  # JSON: user_id, tenant_id, mfa_type,
                                            #         created_at, fingerprint, csrf_token
                                            # TTL: 600s
                                            # fingerprint: SHA256(UA + Accept-Language + ...)
```

**Token 下发规则：**
- `session_jti`：UUIDv4，HttpOnly + Secure + SameSite=Strict Cookie，600秒 TTL
- `fingerprint`：客户端指纹，用于检测 Token 劫持后跨会话使用
- `csrf_token`：32字节随机，存入 Redis `mfa:csrf:{session_jti}`，通过 JSON 响应返回前端（内存存储，不落 localStorage）
- Redis Key 增加 16字节随机后缀防遍历
- 异常访问监控：`mfa.pending_access_anomaly`

---

## 6. TOTP 算法细节

### 6.1 AES-256-GCM 加密：IV/Nonce、存储格式、密钥轮换

**密钥生成与存储：**
- `MFA_SECRET_ENCRYPTION_KEY`：32字节密钥，从环境变量或 Vault 注入，与 JWT_SECRET_KEY 物理分离
- 密钥轮换策略：每 90 天轮换一次，旧密钥保留最近 2 个版本（用于解密历史数据）
- 轮换时新 TOTP secret 使用新密钥加密，旧 secret 在用户下次验证/重绑定时自动重新加密迁移

**IV/Nonce 生成：**
- 每次加密操作使用 `os.urandom(12)` 生成 12 字节随机 IV（GCM 标准 nonce 长度）
- 禁止重复使用 IV：因每次加密随机生成，天然防重放

**密文格式（`IV:ciphertext:tag` Base64 三段式）：**
```
Base64(IV).Base64(ciphertext).Base64(GCM_tag)
  12字节      20字节(原文)     16字节
```

**Python 参考实现：**
```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64, os

def encrypt_aes256gcm(plaintext: str) -> str:
    key = os.environ["MFA_SECRET_ENCRYPTION_KEY"].encode()  # 32字节
    iv = os.urandom(12)
    aesgcm = AESGCM(key)
    ct_tag = aesgcm.encrypt(iv, plaintext.encode(), None)
    ciphertext, tag = ct_tag[:-16], ct_tag[-16:]
    return (
        base64.b64encode(iv).decode() + "." +
        base64.b64encode(ciphertext).decode() + "." +
        base64.b64encode(tag).decode()
    )

def decrypt_aes256gcm(encrypted: str) -> str:
    iv_b64, ct_b64, tag_b64 = encrypted.split(".")
    iv, ciphertext, tag = base64.b64decode(iv_b64), base64.b64decode(ct_b64), base64.b64decode(tag_b64)
    key = os.environ["MFA_SECRET_ENCRYPTION_KEY"].encode()
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(iv, ciphertext + tag, None).decode()
```

### 6.2 otpauth:// URI 格式

```
otpauth://totp/{issuer}:{account}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits=6&period=30
```

### 6.3 参数选择

| 参数 | 值 | 说明 |
|------|----|------|
| 算法 | SHA1 | 符合 RFC 6238，与 Google Authenticator 兼容 |
| 位数 | 6 位 | 行业标准 |
| 周期 | 30 秒 | 行业标准 |
| **前向容差（v3修订）** | **±1 周期（window=1）** | **即当前时间前30秒~后30秒，前后各1个周期容差** |
| Secret 长度 | 20 字节 | 160bit，RFC 6238 推荐最小值 |
| 编码 | Base32 | RFC 4648 标准，A-Z + 2-7 |

> **TOTP 容差修订说明（v3）：** 旧版设计为"当前时间前30秒~后0秒"，现改为 ±1 周期（前后各30秒），`window=1`。用户因网络延迟或时钟偏差导致验证码恰好在有效期交界处时，仍可验证通过，减少用户摩擦。

---

## 7. 备份码设计

### 7.1 格式与熵值

- **格式：** `XXXX-XXXX`（8位，大写字母+数字）
- **字符集：** A-Z + 0-9，共 36 个字符（**v3 明确**）
- **生成方式：** `secrets.choice()` 密码学安全随机数（**v3 明确**）
- **数量：** 10 个
- **一次性：** 使用后标记 `used=True`，不可重用
- **熵值：** `log2(36^8) ≈ 41.3 bits`，安全

**Python 参考实现：**
```python
import secrets
import string

BACKUP_CODE_CHARSET = string.ascii_uppercase + string.digits  # A-Z0-9 共36个
BACKUP_CODE_FORMAT = "XXXX-XXXX"

def generate_backup_code() -> str:
    raw = ''.join(secrets.choice(BACKUP_CODE_CHARSET) for _ in range(8))
    return f"{raw[:4]}-{raw[4:]}"

def generate_recovery_code() -> str:
    # 紧急恢复码：8位无连字符，纯熵
    return ''.join(secrets.choice(BACKUP_CODE_CHARSET) for _ in range(8))
```

### 7.2 加密存储

备份码在数据库中以 bcrypt 摘要存储（cost factor = 12），即使用户数据库泄露也无法还原。

### 7.3 备份码穷举防护

**机制：**

1. 每个备份码单独计数：`mfa_backup_codes.attempt_count`（数据库）+ Redis `mfa:bc:attempt:{user_id}:{code_hash_suffix}`
2. 单个备份码最大失败尝试次数：**3 次**
3. 达到 3 次后，该备份码立即被锁定（`attempt_count=3`，`used=True`，不可再用），同时 `mfa:verify:attempt:{user_id}` 也已累加 3 次
4. 任何一次备份码验证失败（无论是否击中正确码），`mfa:verify:attempt:{user_id}` 全局计数器 +1
5. 全局限制：5 次验证失败（不限类型）后，整个 MFA 验证阶段锁定 5 分钟

**防护效果：** 攻击者最多对一个备份码尝试 3 次 → 10 个码 × 3 次 = 30 次尝试，远超 bcrypt 每秒约 10^4 次的验证速度，代价极高。

---

## 8. 记住设备与 IP 子网可配置

### 8.1 设备信任机制

```
device_token = HMAC-SHA256(key=device_salt, message=UA + "|" + ip_subnet(ipv4_prefix, ipv6_prefix))
```

- device_salt：32字节，`os.urandom(32).hex()`，每个设备独立不重用
- UA：User-Agent 字符串
- ip_subnet(ipv4_prefix, ipv6_prefix)：IP 的子网前缀字符串（IPv4 和 IPv6 分别可配置）

### 8.2 IP 子网前缀可配置（v3/v4 修订）

> **修订背景（v3）：** 原设计固定 `/24` 子网（256 地址），在共享网络（如企业内网、CGNAT）中过于宽松。
> **IPv6 补充（v4）：** 新增 `MFA_IPV6_PREFIX` 配置项，默认 `/64` 子网（覆盖同一 /64 链路本地内的所有设备）。

**配置项（`config.py`）：**
```python
MFA_TRUSTED_DEVICE_IP_PREFIX: int = 24   # IPv4 默认 /24，可收紧至 /28（16地址）
MFA_IP_PREFIX_MIN: int = 28              # IPv4 允许的最小前缀（防止过度宽松）
MFA_IPV6_PREFIX: int = 64                # IPv6 默认 /64（v4 新增）
```

**子网计算实现：**
```python
import ipaddress

def ip_subnet(ip_str: str, prefix: int = 24, ipv6_prefix: int = 64) -> str:
    """将 IP 转换为指定前缀的子网字符串"""
    try:
        ip = ipaddress.ip_address(ip_str)
        if isinstance(ip, ipaddress.IPv4Address):
            network = ipaddress.IPv4Network(f"{ip_str}/{prefix}", strict=False)
            return str(network.network_address)
        elif isinstance(ip, ipaddress.IPv6Address):
            network = ipaddress.IPv6Network(f"{ip_str}/{ipv6_prefix}", strict=False)
            return str(network.network_address)
    except ValueError:
        pass
    return ip_str  # 无效 IP 不做子网处理
```

**收紧场景示例：**
- 默认 IPv4：`/24`（如 `192.168.1.0/24`），同一 /24 网段内 IP 变化视为同一设备
- 收紧至 `/28`（如 `10.0.0.0/28`）：仅 16 地址，更严格，适用于高安全需求场景
- IPv6：默认 `/64`，大多数设备在同一 /64 链路本地内
- 建议：普通场景保持 IPv4 `/24` / IPv6 `/64`，高安全需求场景通过配置收紧至 IPv4 `/28`，同时触发地理位置通知

**地理定位验证（高安全场景的可选增强，v4 修订）：**

> **v4 修订：** 地理定位功能改为**可选**，默认关闭。通过 `MFA_GEOLOCATION_ENABLED: bool = False` 控制。启用时使用本地 MaxMind GeoIP2 数据库（文件路径通过 `MFA_GEOIP_DB_PATH` 配置），不调用外部 API，避免隐私泄露和外部依赖。

```python
# 配置项
MFA_GEOLOCATION_ENABLED: bool = False        # 默认关闭（v4 新增）
MFA_GEOIP_DB_PATH: str = "/data/geoip/GeoIP2-City.mmdb"  # MaxMind GeoIP2 数据库路径

async def check_geolocation_anomaly(user_id: str, current_ip: str, stored_ip_subnet: str):
    """检测地理位置异常，发送通知而非直接拒绝"""
    current_geo = await lookup_geoip(current_ip)  # 使用本地 MaxMind 数据库
    # 记录异常但不阻断，提供通知
    await send_security_notification(user_id, {
        "event": "mfa.device.geolocation_changed",
        "previous_subnet": stored_ip_subnet,
        "current_ip": current_ip,
        "current_geo": current_geo,
    })
    # 返回警告而非错误，用户仍可通过但管理员收到告警
```

---

## 9. 客户端指纹容差（v3 新增，v4 简化）

### 9.1 问题背景

设备指纹（UA + Accept-Language + ColorDepth 等）用于 MFA pending 状态防劫持检测。如果用户浏览器自动更新（如 Chrome 升级后 UA 小版本变化），指纹会变化导致误报。

### 9.2 容差策略（v4 简化）

> **v4 修订：** 简化 Accept-Language 比较逻辑，直接比较标准化后的字符串（忽略权重顺序差异，如 `en;q=0.9,zh;q=0.8` vs `zh;q=0.8,en;q=0.9` 视为相同）。UA 版本容差保留。

**允许小版本变化：** 仅对 UA 字符串中的小版本号字段允许有限变化（补丁版本如 120.0.1 → 120.0.2 忽略），主版本号（major）和次版本号（minor）变化仍触发告警。

**分字段容差（v4）：**

| 字段 | 容差策略 |
|------|---------|
| User-Agent minor/patch 版本 | 允许 ±2 范围内变化，忽略 |
| User-Agent major.minor | 严格匹配，变化触发告警 |
| **Accept-Language（v4 简化）** | **直接比较标准化后的字符串，忽略权重顺序差异** |
| ColorDepth | 严格匹配 |
| Screen resolution | 严格匹配 |
| Timezone | 严格匹配 |
| Platform | 严格匹配 |

**实现逻辑（伪代码，v4 简化 Accept-Language）：**
```python
def normalize_accept_language(al: str) -> str:
    """标准化 Accept-Language 字符串：提取语言标签，去除 q 值，排序"""
    parts = []
    for item in al.split(","):
        lang = item.split(";")[0].strip()
        if lang:
            parts.append(lang)
    return "|".join(parts)  # "en-US|zh-CN" 格式，顺序固定

def normalize_user_agent_for_comparison(ua: str) -> dict:
    """解析 UA，提取可比较字段"""
    parsed = parse_user_agent(ua)  # 使用 ua-parser
    return {
        "browser": parsed.browser,       # Chrome
        "major": parsed.major,           # 120
        "minor": parsed.minor,           # 0
        "patch": parsed.patch,           # 1234
        "platform": parsed.platform,       # Windows
    }

def compare_fingerprint(stored: dict, current: dict) -> FingerprintResult:
    """对比指纹，返回匹配/告警/拒绝"""
    # 严格字段必须完全匹配
    if stored["browser"] != current["browser"]:
        return REJECT
    if stored["major"] != current["major"] or stored["minor"] != current["minor"]:
        return REJECT
    if stored["platform"] != current["platform"]:
        return REJECT
    # patch 版本允许 ±2 变化
    if abs(int(stored["patch"]) - int(current["patch"])) > 2:
        return ALERT  # 告警但不阻断
    # Accept-Language：标准化后直接字符串比较，忽略顺序
    if stored.get("accept_language") != current.get("accept_language"):
        return ALERT  # 告警但不阻断
    return MATCH
```

**处理结果（v4）：**

| 结果 | 行为 |
|------|------|
| `MATCH` | 指纹匹配，继续 MFA 流程 |
| `ALERT` | 指纹有轻微变化（UA patch 版本或 Accept-Language 顺序），发送安全通知邮件给用户，但不阻断 MFA 流程 |
| `REJECT` | 指纹显著变化，阻断 MFA 流程，要求用户重新验证身份，记录 `mfa.fingerprint_rejected` 事件 |

**通知邮件内容（ALERT 场景）：**
> 主题：安全提醒：您的账户在新设备上完成 MFA 验证  
> 内容：检测到 MFA 验证请求来自新浏览器/设备。若不是您本人操作，请立即联系支持。

**审计日志事件（v4 新增 Accept-Language 相关）：**
- `mfa.fingerprint_matched` — 指纹完全匹配
- `mfa.fingerprint_alert` — 指纹轻微变化（UA patch 版本或 Accept-Language 顺序），触发通知但未阻断
- `mfa.fingerprint_rejected` — 指纹显著变化，MFA 流程阻断

---

## 10. 核心服务设计

### 10.1 目录结构（新增）

```
services/auth-api/app/
├── services/
│   └── mfa_service.py          # MFA 核心业务逻辑
├── routers/
│   └── auth/
│       └── mfa.py             # MFA 路由
├── schemas/
│   └── mfa.py                 # MFA Pydantic Schemas
├── db/
│   └── models/
│       ├── mfa_totp.py           # MFA TOTP Model
│       ├── mfa_sms_code.py       # MFA SMS Code Model
│       ├── mfa_backup_code.py    # MFA Backup Code Model
│       ├── mfa_device.py         # MFA Device Model
│       └── mfa_recovery_token.py # MFA Recovery Token Model
└── core/
    ├── config.py                 # 所有 MFA 配置项
    ├── security.py               # 所有 TOTP/备份码/设备指纹/CSRF 核心安全函数
    └── dependencies.py           # 所有 MFA 依赖注入
```

### 10.2 核心服务接口

**`mfa_service.py`：**

```python
# TOTP 相关
async def initiate_totp_setup(user_id: str) -> TotpSetupResult
async def confirm_totp_setup(user_id: str, code: str) -> TotpConfirmResult
async def verify_totp(user_id: str, code: str, window: int = 1) -> bool  # window=1: ±1周期
async def disable_totp(user_id: str) -> None

# SMS MFA
async def enable_sms_mfa(user_id: str, phone: str, code: str) -> SmsMfaEnableResult
async def send_mfa_sms_code(phone: str, user_id: str) -> SendSmsResult
async def verify_mfa_sms_code(user_id: str, phone: str, code: str) -> bool

# 备份码
async def verify_backup_code(user_id: str, code: str) -> bool
async def generate_backup_codes(count: int = 10) -> list[str]
    # 使用 secrets.choice(A-Z0-9) 密码学安全随机数
async def lock_backup_code(user_id: str, code_hash: str) -> None

# 设备信任
async def add_trusted_device(user_id: str, device_info: DeviceInfo) -> None
async def is_device_trusted(user_id: str, user_agent: str, ip_address: str) -> bool
    # 支持 configurable IPv4 prefix 和 IPv6 prefix（v4）
async def revoke_trusted_device(user_id: str, device_id: str) -> None

# 指纹比对
async def check_fingerprint(user_id: str, stored_fp: dict, current_fp: dict) -> FingerprintResult
    # 返回 MATCH / ALERT / REJECT，ALERT 发通知不阻断

# MFA 状态
async def get_mfa_status(user_id: str) -> MfaStatus
async def disable_mfa(user_id: str, verified_code: str, mfa_type: str) -> None

# MFA 紧急恢复
async def request_recovery(user_id: str, channel: str) -> RecoveryRequestResult
    # channel: "email" | "sms"，生成 8 位 secrets.choice 恢复码
async def verify_recovery_code(user_id: str, code: str) -> bool
    # v4：所有无效情况统一返回 False，错误原因仅记审计日志
async def disable_mfa_for_user(user_id: str) -> None  # 恢复成功后调用

# CSRF Token（同步 Token 模式）
async def generate_csrf_token(session_jti: str) -> str
    # 生成 32 字节 token，存入 Redis mfa:csrf:{session_jti}，返回给调用者
async def verify_csrf_token(session_jti: str, header_token: str) -> bool
    # 比对请求头 token 与 Redis 存储，仅返回 bool，不泄露差异
```

**`security.py` 核心安全函数（v3/v4 关键修订）：**

```python
import os, hmac, hashlib, base64, secrets, string
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

BACKUP_CODE_CHARSET = string.ascii_uppercase + string.digits  # A-Z0-9，共36个，v3明确

# === AES-256-GCM 加密 ===

def encrypt_aes256gcm(plaintext: str) -> str:
    key = os.environ["MFA_SECRET_ENCRYPTION_KEY"].encode()
    iv = os.urandom(12)
    aesgcm = AESGCM(key)
    ct_tag = aesgcm.encrypt(iv, plaintext.encode(), None)
    ciphertext, tag = ct_tag[:-16], ct_tag[-16:]
    return f"{base64.b64encode(iv)}.{base64.b64encode(ciphertext)}.{base64.b64encode(tag)}"

def decrypt_aes256gcm(encrypted: str) -> str:
    iv_b64, ct_b64, tag_b64 = encrypted.split(".")
    iv, ciphertext, tag = base64.b64decode(iv_b64), base64.b64decode(ct_b64), base64.b64decode(tag_b64)
    aesgcm = AESGCM(os.environ["MFA_SECRET_ENCRYPTION_KEY"].encode())
    return aesgcm.decrypt(iv, ciphertext + tag, None).decode()

# === TOTP ===

def generate_totp_secret() -> str:  # 20字节原始 secret，Base32 编码
def get_totp_uri(secret: str, account: str, issuer: str) -> str
def verify_totp_token(secret: str, token: str, window: int = 1) -> bool
    # window=1: ±1周期，前30秒~后30秒，v3修订

# === 备份码（v3明确） ===

def generate_backup_code() -> str:
    """生成 XXXX-XXXX 格式备份码，使用 secrets.choice 密码学安全随机数"""
    raw = ''.join(secrets.choice(BACKUP_CODE_CHARSET) for _ in range(8))
    return f"{raw[:4]}-{raw[4:]}"

def generate_recovery_code() -> str:
    """生成 8 位无分隔符恢复码，secrets.choice 密码学安全"""
    return ''.join(secrets.choice(BACKUP_CODE_CHARSET) for _ in range(8))

def hash_backup_code(code: str) -> str:    # bcrypt cost=12
def verify_backup_code_hash(code: str, hashed: str) -> bool

# === 设备指纹：HMAC-SHA256 + configurable IPv4/IPv6 prefix（v4 修订） ===

def generate_device_salt() -> str:
    return os.urandom(32).hex()

def ip_subnet(ip_str: str, prefix: int = 24, ipv6_prefix: int = 64) -> str:
    """将 IP 转换为指定前缀的子网字符串，v4 支持 IPv6 prefix"""
    import ipaddress
    try:
        ip = ipaddress.ip_address(ip_str)
        if isinstance(ip, ipaddress.IPv4Address):
            network = ipaddress.IPv4Network(f"{ip_str}/{prefix}", strict=False)
            return str(network.network_address)
        elif isinstance(ip, ipaddress.IPv6Address):
            network = ipaddress.IPv6Network(f"{ip_str}/{ipv6_prefix}", strict=False)
            return str(network.network_address)
    except ValueError:
        pass
    return ip_str

def generate_device_token(device_salt: str, user_agent: str, ip_address: str,
                          prefix: int = 24, ipv6_prefix: int = 64) -> str:
    subnet = ip_subnet(ip_address, prefix, ipv6_prefix)
    message = f"{user_agent}|{subnet}"
    return hmac.new(device_salt.encode(), message.encode(), hashlib.sha256).hexdigest()

def match_device_token(stored_token: str, stored_salt: str, user_agent: str,
                       current_ip: str, prefix: int = 24, ipv6_prefix: int = 64) -> bool:
    computed = generate_device_token(stored_salt, user_agent, current_ip, prefix, ipv6_prefix)
    return hmac.compare_digest(stored_token, computed)

# === CSRF Token（同步 Token 模式） ===

def generate_csrf_token() -> str:
    """生成 32 字节 CSRF Token，secrets.token_hex(32)"""
    return secrets.token_hex(32)

# === Fingerprint 比对（v4 简化 Accept-Language） ===

def normalize_accept_language(al: str) -> str:
    """标准化 Accept-Language：去除 q 值，排序，拼接"""
    parts = []
    for item in al.split(","):
        lang = item.split(";")[0].strip()
        if lang:
            parts.append(lang)
    return "|".join(sorted(parts))  # 顺序固定，忽略原始顺序差异

def normalize_user_agent(ua: str) -> dict:
    """解析 UA，提取可比较字段"""
    parsed = parse_user_agent(ua)  # 使用 ua-parser
    return {
        "browser": parsed.browser,
        "major": parsed.major,
        "minor": parsed.minor,
        "patch": parsed.patch,
        "platform": parsed.platform,
        "accept_language": normalize_accept_language(parsed.accept_language or ""),
    }

def compare_fingerprint(stored: dict, current: dict) -> str:
    """
    返回 MATCH / ALERT / REJECT
    - patch 版本 ±2 变化 → ALERT
    - major/minor 变化 → REJECT
    - Accept-Language 标准化后不同 → ALERT（v4 简化）
    """
    if stored["browser"] != current["browser"]:
        return "REJECT"
    if stored["major"] != current["major"] or stored["minor"] != current["minor"]:
        return "REJECT"
    if stored["platform"] != current["platform"]:
        return "REJECT"
    if abs(int(stored["patch"]) - int(current["patch"])) > 2:
        return "ALERT"
    if stored.get("accept_language") != current.get("accept_language"):
        return "ALERT"
    return "MATCH"
```

---

## 11. 安全分析

### 11.1 TOTP Secret 存储

- **加密**：AES-256-GCM，格式 `IV:ciphertext:tag` Base64 三段式
- **密钥**：物理分离于 JWT_SECRET_KEY，90天轮换，保留2个旧密钥版本
- **审计日志**：TOTP secret 不写入业务日志

### 11.2 MFA 验证次数限制

| 场景 | 限制 | 实现 |
|------|------|------|
| TOTP 重试 | 自然限制 | 30秒内最多3次（含），密码学安全 |
| 备份码重试 | 每码3次上限 | `attempt_count` + Redis 穷举防护 |
| SMS 验证码 | 同一手机 3次/小时 | Redis `mfa:sms:count:{phone}` |
| SMS 发送间隔 | 60秒/次 | Redis `mfa:sms:rate:{phone}` |
| MFA 验证失败 | 5次/5分钟 | Redis `mfa:verify:attempt:{user_id}` |

### 11.3 CSRF 防护（v4 同步 Token 模式）

- 所有 MFA 写操作接口均使用同步 Token 模式
- `secrets.token_hex(32)` 生成 CSRF Token，Redis 存储
- Token 通过 JSON 响应体返回前端（内存存储，不落 localStorage）
- `X-MFA-CSRF-Token` 请求头携带，服务端 Redis 比对
- Cookie 仅做冗余传输辅助（Secure + SameSite=Strict）

### 11.4 记住设备

- **Salt**：每设备 32 字节 `os.urandom(32).hex()`
- **Token 算法**：`HMAC-SHA256(key=device_salt, message=UA + "|" + ip_subnet(IPv4_prefix, IPv6_prefix))`
- **IP 前缀匹配**：IPv4 默认 /24，IPv6 默认 /64，可收紧
- **Token 存储**：HttpOnly Secure Cookie，防止 XSS 盗取
- **30天有效**：定期刷新

### 11.5 MFA 紧急恢复安全

| 措施 | 说明 |
|------|------|
| 身份认证前置 | 恢复前必须通过账号+密码或手机+短信验证身份 |
| 15分钟一次性 | 恢复码 15 分钟有效，一次使用即作废 |
| 密码学安全随机数 | 使用 `secrets.choice` 生成，防预测 |
| bcrypt 存储 | 恢复码在数据库 bcrypt 加密存储 |
| 管理员复核 | 支持人工审核流程，需管理员显式审批 |
| 错误响应统一（v4） | 所有无效恢复码统一返回 `mfa_recovery_code_invalid`，不泄露已用/过期差异 |

### 11.6 审计日志事件

| 事件 | 说明 |
|------|------|
| `mfa.totp.setup_initiated` | 用户开始 TOTP 绑定 |
| `mfa.totp.enabled` | TOTP 绑定成功完成 |
| `mfa.totp.verify_failed` | TOTP 验证失败 |
| `mfa.sms_enabled` | 开启短信 MFA |
| `mfa.sms_verify_failed` | 短信 MFA 验证失败 |
| `mfa.backup_code_used` | 使用备份码登录 |
| `mfa.backup_code_locked` | 备份码穷举攻击达到3次被锁定 |
| `mfa.device_trusted` | 设备信任记住（MFA 记住设备） |
| `mfa.device_revoked` | 撤销信任设备 |
| `mfa.fingerprint_matched` | 指纹安全匹配 |
| `mfa.fingerprint_alert` | 指纹轻微变化（UA patch 或 Accept-Language 顺序），通知但未阻断 |
| `mfa.fingerprint_rejected` | 指纹显著变化，MFA 流程阻断 |
| `mfa.disabled` | MFA 被禁用 |
| `mfa.challenge_started` | MFA 验证挑战开始 |
| `mfa.challenge_passed` | MFA 验证挑战通过 |
| `mfa.pending_access_anomaly` | 异常访问 MFA pending key |
| `mfa.recovery_requested` | 发起紧急恢复请求 |
| `mfa.recovery_verified` | 紧急恢复码验证成功（v4 统一：不管是否已用） |
| `mfa.recovery_code_used` | 恢复码已使用（v4 补充：审计日志区分，响应体不区分） |
| `mfa.recovery_code_expired` | 恢复码已过期（v4 补充：审计日志区分，响应体不区分） |
| `mfa.recovered_via_email` | 通过邮箱恢复码重获访问 |
| `mfa.recovered_via_sms` | 通过短信恢复码重获访问 |
| `mfa.admin_recovery` | 管理员人工审批紧急恢复 |

---

## 12. 配置项（config.py 新增所有项）

```python
# MFA 总开关
MFA_ENABLED: bool = True                                    # 全局 MFA 开关
MFA_TOTP_ISSUER: str = "AuthMaster"                        # QR Code 显示的发卡行
MFA_SECRET_ENCRYPTION_KEY: str = ""                         # AES-256-GCM 密钥（32字节）
MFA_KEY_ROTATION_DAYS: int = 90                            # 密钥轮换周期（天）
MFA_BACKUP_CODE_COUNT: int = 10                            # 备份码数量
MFA_BACKUP_CODE_FORMAT: str = "XXXX-XXXX"                  # 备份码格式
MFA_BACKUP_CODE_CHARSET: str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"  # 36字符集，v3明确
MFA_BACKUP_CODE_MAX_ATTEMPTS: int = 3                      # 单个备份码最大失败尝次
MFA_TOTP_WINDOW: int = 1                                    # TOTP 容差窗口：±1周期，前30秒~后30秒，v3修订
MFA_SMS_RATE_LIMIT: int = 3                                # 每小时发码次数上限
MFA_SMS_RATE_WINDOW: int = 3600                            # 短信限流时间窗口（秒）
MFA_VERIFY_ATTEMPT_LIMIT: int = 5                          # 验证失败计数上限
MFA_VERIFY_ATTEMPT_WINDOW: int = 300                        # 验证失败计数窗口（秒）
MFA_TRUSTED_DEVICE_EXPIRE_DAYS: int = 30                   # 设备信任有效期
MFA_TRUSTED_DEVICE_IP_PREFIX: int = 24                     # IPv4 子网前缀，默认 /24，v3修订，可收紧至 /28
MFA_IP_PREFIX_MIN: int = 28                                # IPv4 允许的最小前缀，v3新增
MFA_IPV6_PREFIX: int = 64                                 # IPv6 子网前缀，默认 /64，v4新增
MFA_SETUP_SECRET_TTL: int = 600                            # TOTP setup 临时 secret TTL（秒）
MFA_SMS_CODE_TTL: int = 300                                # SMS MFA 验证码 TTL（秒）
MFA_SMS_SEND_INTERVAL: int = 60                            # SMS 发送间隔（秒）
MFA_PENDING_KEY_RANDOM_SUFFIX_BYTES: int = 16              # Redis key 随机后缀字节数
MFA_RECOVERY_CODE_TTL_SECONDS: int = 900                   # 紧急恢复码有效期（15分钟），v3新增
MFA_RECOVERY_CODE_LENGTH: int = 8                          # 紧急恢复码长度，v3新增
# === v4 新增配置项 ===
MFA_GEOLOCATION_ENABLED: bool = False                       # 地理定位功能，默认关闭，v4新增
MFA_GEOIP_DB_PATH: str = "/data/geoip/GeoIP2-City.mmdb"   # MaxMind GeoIP2 数据库路径，v4新增
```

---

## 13. 错误码定义

| HTTP 状态码 | 错误码 | 说明 |
|-------------|--------|------|
| 400 | `mfa_invalid_code` | TOTP/备份码/恢复码验证失败 |
| 400 | `mfa_code_expired` | 验证码已过期 |
| 400 | `mfa_not_configured` | 用户未配置该种 MFA |
| 400 | `mfa_totp_already_setup` | TOTP 已经绑定完成 |
| 400 | `mfa_sms_phone_mismatch` | 验证手机号与绑定手机号不匹配 |
| 400 | `mfa_backup_code_locked` | 备份码已达到最大尝次，已被锁定 |
| **400** | **`mfa_recovery_code_invalid`** | **恢复码无效/已用/过期，v4 统一响应，不区分具体原因** |
| 401 | `mfa_required` | 需要进行 MFA 验证 |
| 403 | `mfa_csrf_invalid` | CSRF Token 校验失败，v3 新增（同步 Token 模式） |
| 429 | `mfa_sms_rate_limited` | 短信发送频率超出限制 |
| 429 | `mfa_verify_attempts_exceeded` | 验证失败次数超限，账户临时锁定 |

---

## 14. 依赖项（requirements.txt 新增）

```
pyotp>=2.9.0          # TOTP 算法实现，RFC 6238
qrcode[pil]>=7.4.2    # QR Code 生成
redis[hiredis]>=5.0.0 # Redis 异步客户端
bcrypt>=4.1.0         # 备份码及恢复码哈希
cryptography>=42.0.0  # AESGCM
ua-parser>=0.18.0     # User-Agent 解析库（v3 新增）
```

---

## 15. 实施优先级

| 阶段 | 内容 | 排期 |
|------|------|------|
| P1 | 数据库迁移 + TOTP Model + TOTP 绑定/激活核心函数 | 1 Sprint |
| P1 | `POST /auth/mfa/totp/setup` + `verify` 核心流程 | 1 Sprint |
| P1 | `POST /auth/mfa/verify` MFA 验证 + CSRF + 记住设备 | 1 Sprint |
| P2 | SMS MFA + Redis 限流 + 发码接口 | 0.5 Sprint |
| P2 | `GET /auth/mfa/status` + `DELETE /auth/mfa/disable` | 0.5 Sprint |
| P2 | 备份码穷举防护 + 审计日志完善 | 0.5 Sprint |
| P2 | 客户端指纹比对（ALERT/REJECT 分级）| 0.5 Sprint |
| P3 | MFA 紧急恢复流程（邮箱/短信/管理员人工）| 1 Sprint |
| P3 | IP 地理定位（可选 MaxMind）+ 地理位置通知 | 0.5 Sprint |
| P3 | 审计日志完善 + 安全透明化 | 1 Sprint |

---

## 16. 向后兼容性和迁移

- `users.mfa_enabled` 默认值为 `FALSE`，确保所有老用户无需强制迁移
- `users.mfa_secret` 字段保留，Phase 3 前不删除
- MFA 接口单独挂载于 `/auth/*` 路径，不影响 Phase 1 登录接口
- Phase 2 开发期间，Refresh Token 机制不变

### 16.1 数据库迁移兼容方案

| 场景 | 预期行为 |
|------|---------|
| Phase 1 用户，无 mfa_enabled=默认FALSE | 直接颁发 AccessToken，跳过 MFA |
| Phase 2 新用户首次登录 | mfa_enabled=FALSE，直接颁发 AccessToken |
| Phase 1 用户在 Phase 2 期间绑定 TOTP | mfa_totp 记录创建，开始使用 MFA |
| Phase 2 开发期间用户 DB 中 mfa_type=NULL | 等同于 mfa_enabled=FALSE，跳过 MFA |

---

## 17. 修订记录

| 版本 | 日期 | 修订内容 |
|------|------|---------|
| v1 | 2026-04-03 | 初始版本 |
| v2 | 2026-04-03 | 第二轮修订：<br>1. AES-256-GCM 加密 IV 生成、存储格式、密钥轮换<br>2. session_jti 改为 HttpOnly Secure Cookie，绑定客户端指纹，UUIDv4，TTL<br>3. 记住设备逻辑 HMAC-SHA256(key=salt, message=UA+IP)，salt 设备级复用，支持 /24 子网匹配<br>4. 备份码穷举防护：每码单独计数3次尝试，全局 mfa:verify:attempt 计数<br>5. Redis Key 增加随机后缀：mfa:pending 增加 16字节随机后缀，mfa.pending_access_anomaly 事件<br>6. 数据库迁移建议：mfa_enabled=FALSE 默认值，确保兼容性 |
| v3 | 2026-04-03 | 第三轮修订：<br>1. CSRF 防护：所有 MFA 写操作接口强制 Double Submit Cookie 方案，secrets.token_hex(32) 生成 Token，HttpOnly Secure SameSite=Strict Cookie<br>2. MFA 紧急恢复码：**新增 mfa_recovery_tokens 表**，恢复码（secrets.choice），15分钟一次性，邮箱/短信/管理员三条恢复路径<br>3. TOTP 容差窗口：window=1（±1 周期，前30秒~后30秒）<br>4. IP /24 子网前缀可配置：MFA_TRUSTED_DEVICE_IP_PREFIX 配置项，默认 /24，可收紧至 /28，地理位置/通知为辅助验证<br>5. 客户端指纹容差：UA patch 版本 ±2 变化 ALERT 通知，major/minor 变化 REJECT，提供 mfa.fingerprint_alert/rejected 事件<br>6. 备份码字符集：明确字符集 A-Z0-9，共36个，使用 secrets.choice 密码学安全随机数，明确 MFA_BACKUP_CODE_CHARSET |
| **v4** | **2026-04-03** | **第四轮最终修订：**<br>**1. CSRF 矛盾修复：** Double Submit 与 HttpOnly 互斥，改为**同步 Token 模式**，Token 在 JSON 响应体返回前端内存（不落 localStorage），Cookie 仅做传输辅助（Secure + SameSite=Strict），彻底解决安全依赖冲突<br>**2. IPv6 子网处理：** 新增 `MFA_IPV6_PREFIX: int = 64` 配置项，`ip_subnet()` 函数同时处理 IPv4/IPv6，`device_token` 计算纳入 IPv6 prefix<br>**3. 地理定位可选：** 新增 `MFA_GEOLOCATION_ENABLED: bool = False` 配置项，默认关闭。启用时使用本地 MaxMind GeoIP2 数据库（`MFA_GEOIP_DB_PATH`），不调用外部 API<br>**4. Accept-Language 容差简化：** 直接比较标准化后的字符串（去除 q 值后排序），忽略原始权重顺序差异，实现更简洁<br>**5. 恢复码错误响应统一：** 所有无效恢复码（已用、过期、不存在）统一返回 `mfa_recovery_code_invalid`，不在响应体区分，审计日志区分（`mfa.recovery_code_used`、`mfa.recovery_code_expired`） |

---

*本方案为实施参考，具体实现请以代码为准。*
*架构师：Architect | 日期：2026-04-03*

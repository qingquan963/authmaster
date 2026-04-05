# AuthMaster Phase 2-3: 主动防御增强设计

> 文档版本：v1.1（架构师第2轮修订）
> 架构师：Architect Agent
> 创建日期：2026-04-03
> 修订日期：2026-04-03
> 修订内容：CanvasHash 防伪造、client_secret 安全强化、风控权重可配置化、IP 封禁优化、风险分数 ABAC 集成
> 项目基础：AuthMaster Phase 1-4 + Phase 2-1 MFA + Phase 2-2 ABAC
> 技术栈：FastAPI + SQLAlchemy async + Redis + PostgreSQL

---

## 1. 概述

### 1.1 模块目标

构建**主动防御体系**，在身份认证入口层防止暴力破解、撞库、重放攻击、账户接管。

核心思路：**多层纵深防御**，每个登录请求经过设备指纹识别 → 请求签名验重 → 风控评分 → IP信誉 → 限流的完整链路，在造成实质伤害前阻断攻击。

### 1.2 设计原则

| 原则 | 说明 |
|------|------|
| **零信任** | 不信任任何请求，所有请求均需通过风控评估 |
| **分层拦截** | 各层独立运作，单层失效不影响整体防御 |
| **可观测** | 所有风控决策均完整记录，支持事后审计和模型优化 |
| **可配置** | 阈值、规则、评分权重均可运行时调整，无需重启 |
| **最小打扰** | 低风险用户无感知，高风险用户触发MFA，拒绝时才感知 |

### 1.3 整体防御链路

```
请求 → [1.限流防护] → [2.设备指纹] → [3.重放校验] → [4.风控引擎] → [5.IP信誉] → 认证通过/触发MFA/拒绝
```

---

## 2. 设备指纹识别

### 2.1 指纹采集（前端 SDK）

前端在登录表单渲染时通过 JS 采集以下维度：

| 字段 | 来源 | 示例 |
|------|------|------|
| `ua` | `navigator.userAgent` | `"Mozilla/5.0..."` |
| `accept_language` | `navigator.language` | `"zh-CN,zh;q=0.9"` |
| `color_depth` | `screen.colorDepth` | `24` |
| `screen_size` | `screen.width × screen.height` | `"1920×1080"` |
| `timezone` | `Intl.DateTimeFormat().resolvedOptions().timeZone` | `"Asia/Shanghai"` |
| `canvas_hash` | Canvas 2D API 渲染特征哈希（含服务端 Nonce） | SHA256(渲染数据 + nonce) |
| `webgl_renderer` | `WebGLRenderingContext.getParameter(UNMASKED_RENDERER_WEBGL)` | `"ANGLE (Intel UHD..."` |
| `platform` | `navigator.platform` | `"Win32"` |
| `touch_support` | `navigator.maxTouchPoints > 0` | `true/false` |

> **Canvas Hash 生成方式：** 在隐藏 Canvas 上绘制特定图形（字体+渐变+形状组合），提取 `toDataURL()` 后 SHA256 哈希。不同设备渲染存在细微差异，产生唯一特征。
>
> **⚠️ 防伪造机制（v1.1 新增）：** Canvas 渲染数据中混入服务端下发的随机 `nonce`，使得自动化工具无法在无服务端参与的情况下伪造有效指纹哈希。详见 2.1.1 节。

### 2.1.1 CanvasHash 服务端挑战-应答机制（v1.1 新增）

```
┌─────────┐  1. GET /api/v1/auth/canvas-challenge     ┌────────────┐
│  前端   │ ─────────────────────────────────────────→│   服务端   │
│  (JS)   │  ←── 200: { challenge_id, nonce } ───────│            │
└─────────┘                                           └────────────┘
       │
       │  2. 使用 nonce 混入 Canvas 渲染
       │     canvas_hash = SHA256(canvas_data + nonce)
       │     （nonce 明文附加到渲染数据末端）
       │
       ▼
  3. 提交登录请求（X-Device-Fingerprint 含 canvas_hash + challenge_id）

       ┌────────────┐  4. 验证：查 Redis 获取 nonce，比对 canvas_hash
       │   服务端   │     验证通过 → 记录指纹
       │            │     验证失败 → 拒绝（HTTP 400，reason: invalid_canvas_challenge）
       └────────────┘
```

**服务端挑战接口：**

```
GET /api/v1/auth/canvas-challenge

响应：
{
  "challenge_id": "uuid-v4",   -- 挑战ID，用于后续验证
  "nonce": "a1b2c3d4e5f6..."   -- 32字节随机十六进制字符串
}

Redis 存储：
Key: canvas_challenge:{challenge_id}
Value: JSON {nonce, created_at, user_id_hint, fp_hash}
TTL: 120秒（2分钟超时）
```

**前端 JS 伪代码：**

```javascript
async function fetchCanvasChallenge() {
  const res = await fetch('/api/v1/auth/canvas-challenge');
  const { challenge_id, nonce } = await res.json();
  return { challenge_id, nonce };
}

async function generateCanvasHash(challengeNonce) {
  const canvas = document.createElement('canvas');
  canvas.width = 200;
  canvas.height = 50;
  const ctx = canvas.getContext('2d');

  // 固定图形（字体+渐变+形状，不同设备渲染存在差异）
  ctx.fillStyle = 'gradient';
  const gradient = ctx.createLinearGradient(0, 0, 200, 0);
  gradient.addColorStop(0, '#ff6b6b');
  gradient.addColorStop(1, '#4ecdc4');
  ctx.fillStyle = gradient;
  ctx.fillRect(0, 0, 200, 50);

  ctx.font = '24px Arial';
  ctx.fillStyle = '#2c3e50';
  ctx.fillText('AuthMaster', 10, 35);

  const dataURL = canvas.toDataURL();
  // 将 nonce 混入哈希计算
  const combined = dataURL + challengeNonce;
  return SHA256(combined);
}
```

**验证流程（后端）：**

```python
async def verify_canvas_challenge(
    challenge_id: str,
    canvas_hash: str,
    received_data: str,  # canvas toDataURL 原始数据
) -> bool:
    """
    1. 从 Redis 获取 challenge_id 对应的 nonce
    2. 将 received_data + nonce 合并后计算 SHA256
    3. 与前端提交的 canvas_hash 做 constant-time 比较
    """
    nonce = await redis.get(f"canvas_challenge:{challenge_id}")
    if not nonce:
        return False  # challenge 不存在或已过期

    expected_hash = SHA256(received_data.encode() + nonce.encode())
    # 验证后立即删除（一次性）
    await redis.delete(f"canvas_challenge:{challenge_id}")
    return secrets.compare_digest(expected_hash, canvas_hash)
```

**安全设计说明：**
- `nonce` 由服务端生成（CSPRNG），自动化工具无法预测
- `canvas_hash = SHA256(canvas_render_data + nonce)`，前端需先请求 challenge 才能拿到 nonce
- `challenge_id` 带 TTL（120秒），超时后失效
- 每个 challenge 仅能使用一次（验证后立即从 Redis 删除）
- `challenge_id` 与 `nonce` 分离传输，即使请求被拦截也难以关联

### 2.2 指纹存储

**Redis（短期缓存，TTL 7天）：**
```
Key: device_fp:{tenant_id}:{user_id}:{fp_hash_prefix}
Value: JSON {fp_data, first_seen_at, last_seen_at, trust_score}
```

**PostgreSQL（长期记录）：**
```sql
CREATE TABLE device_fingerprints (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    user_id         UUID NOT NULL REFERENCES users(id),
    fp_hash         VARCHAR(64) NOT NULL,
    challenge_id    UUID REFERENCES canvas_challenges(id),  -- v1.1: 关联挑战
    ua              TEXT,
    accept_language VARCHAR(255),
    color_depth     INTEGER,
    screen_size     VARCHAR(16),
    timezone        VARCHAR(64),
    canvas_hash     VARCHAR(64),
    webgl_renderer  VARCHAR(255),
    platform        VARCHAR(32),
    touch_support   BOOLEAN,
    first_seen_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    trust_score     INTEGER DEFAULT 0,
    is_trusted      BOOLEAN DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, user_id, fp_hash)
);

CREATE INDEX idx_device_fp_lookup
    ON device_fingerprints(tenant_id, user_id, fp_hash);
CREATE INDEX idx_device_fp_user
    ON device_fingerprints(tenant_id, user_id);
```

### 2.3 指纹风险评分

| 情况 | 分数 |
|------|------|
| 从未见过的设备 | **+10**（需要额外验证） |
| 常用设备（过去30天登录≥3次）且指纹稳定 | **+20** |
| 异常设备（超过3个历史字段变化） | **-30** |
| 设备被用户标记为"记住"且在30天内 | **+15** |
| 新设备+异常时段（如凌晨3-6点） | **-20**（额外扣分） |

### 2.4 指纹变更检测

将当前指纹与该用户最近3个历史指纹逐一对比：
- 统计**字段差异数**（UA、语言、屏幕、时区、Canvas、WebGL等）
- 差异字段数 **> 3** → 标记为高风险（`is_compromised = TRUE`）
- 触发告警：`ALERT: Device fingerprint changed significantly for user {user_id}`

---

## 3. 防重放攻击

### 3.1 请求签名机制

客户端对每个敏感请求（登录、Token刷新、密码修改等）进行签名：

```
signature = HMAC-SHA256(
    key = client_secret,          -- 客户端持有密钥（与后端共享）
    data = request_method +
           request_path +
           timestamp +
           nonce +
           body_plaintext         -- 请求体原始 JSON 字符串
)
```

请求 Header：
```
X-Timestamp: 1743624000           -- Unix epoch 秒（10位）
X-Nonce:    8f14e45f-ceea-...     -- UUID v4，每请求唯一
X-Signature: hex(signature)       -- 小写十六进制
```

### 3.2 重放校验流程

```
1. Timestamp 校验：
   - 当前时间与 X-Timestamp 差值 > 5 分钟 → 拒绝（HTTP 400）
   - 防御：攻击者无法重放旧请求

2. Nonce 唯一性校验：
   - Redis SETNX "nonce:{nonce_value}" TTL 600秒（10分钟）
   - SETNX 返回 0（已存在）→ 请求已被使用，拒绝（HTTP 400）
   - 防御：同一请求无法被重放两次

3. Signature 校验：
   - 后端用相同算法重新计算 signature
   - constant-time 比较（防止时序攻击）
   - 不匹配 → 拒绝（HTTP 400）
```

### 3.3 签名白名单

以下请求路径不参与签名校验（配置化）：
- `GET /health`
- `GET /api/v1/public/*`（公开接口）
- `POST /api/v1/auth/send-code`（防撞库在限流层处理）

### 3.4 Client Secret 管理

#### 3.4.1 存储策略（v1.1 强化）

| 客户端类型 | 存储方式 | HttpOnly | Secure | SameSite |
|-----------|---------|----------|--------|----------|
| Web 浏览器 | httpOnly Cookie（自动） | ✅ | ✅ | Strict |
| 移动 App（原生） | 系统 KeyChain/Keystore | — | — | — |
| SPA（单页应用） | httpOnly Cookie（同 Web） | ✅ | ✅ | Strict |
| 服务端客户端 | 环境变量/密钥管理系统 | — | — | — |

**Web/SPA 场景：**
- `client_secret` 不再存储于 localStorage
- 改为自动通过 httpOnly Cookie 管理（`__client_secret`，Secure，SameSite=Strict）
- 首次登录成功后，服务端通过 Set-Cookie 设置该 Cookie
- 后续请求浏览器自动附加，JavaScript 无法读取（防止 XSS 窃取）

#### 3.4.2 自动密钥轮换（v1.1 新增）

```
轮换周期：每 30 天自动生成新 client_secret
旧 secret 宽限期：7 天（新旧 secret 均可验证）
宽限期结束后：旧 secret 自动失效
```

**轮换流程：**

```
1. 系统每日检查：当前时间 - secret_created_at > 30 天？
   → 是 → 触发轮换

2. 生成新 secret：
   new_secret = CSPRNG(32 bytes).hex()

3. 存储双 secret 状态（Redis + PostgreSQL）：
   active_secrets: {user_id} = [
     {secret: new_secret, issued_at: now, expires_at: now + 7d},
     {secret: old_secret, issued_at: old_issued_at, expires_at: now}
   ]
   -- 宽限期7天内两者均有效

4. 通知用户（可选，通过邮件/推送）：
   "您的认证密钥已更新，旧密钥将于7天后失效"

5. 7天宽限期结束后：
   -- 从 active_secrets 中移除旧 secret
   -- 旧 secret 验证请求返回 HTTP 401 + error: secret_expired
   -- 提示用户重新登录获取新 secret
```

**DDL 变更：**

```sql
ALTER TABLE users ADD COLUMN client_secret_hash VARCHAR(64);
ALTER TABLE users ADD COLUMN client_secret_rotated_at TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN previous_secret_hash VARCHAR(64);  -- 宽限期内的旧secret
ALTER TABLE users ADD COLUMN previous_secret_expires_at TIMESTAMPTZ;

-- 新增 secret 轮换历史表
CREATE TABLE client_secret_history (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id),
    secret_hash     VARCHAR(64) NOT NULL,
    issued_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expired_at      TIMESTAMPTZ,
    rotated_by      UUID REFERENCES users(id),    -- 谁触发了轮换（NULL=系统）
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_secret_history_user ON client_secret_history(user_id, issued_at DESC);
```

**用户主动撤销：**
- `POST /api/v1/auth/revoke-secret` → 立即失效，生成新 secret，重新设置 Cookie
- 用户可从管理界面查看活跃设备列表（基于指纹），手动撤销可疑设备

---

## 4. 风控决策引擎

### 4.1 风险因子体系

> **⚠️ v1.1 变更：** 各因子 `max_score` 明确为 100，权重通过 `risk_rules` 表可配置，默认权重标注为"基于经验值，建议根据实际业务调整"。

| 因子 | 默认权重 | max_score | 数据来源 | 说明 |
|------|---------|-----------|----------|------|
| 登录失败次数 | W=1.0 | 100 | Redis Counter | 越多越危险 |
| 设备指纹得分 | W=0.8 | 100 | 设备指纹服务 | 负分=异常 |
| IP 信誉得分 | W=1.0 | 100 | IP 信誉系统 | 黑名单直接满分 |
| 地理位置异常 | W=0.6 | 100 | IP 地理库 | 与常用位置偏差大 |
| 登录时间异常 | W=0.4 | 100 | 系统时间 | 非工作时段 |

> **权重配置说明：** 权重为相对权重，用于因子间重要性排序。建议值基于经验值，实际部署时需根据业务场景调整。

### 4.2 归一化评分公式（v1.1 明确）

```
各因子 raw_score ∈ [0, 100]（已标准化）

weighted_sum = Σ(factor_score × weight)
weight_sum   = Σ(weight × max_score)   -- 即 Σ(weight × 100)

risk_score = clamp(
    (weighted_sum / weight_sum) × 100,
    0, 100
)
```

**Python 实现：**

```python
def normalize_risk_score(factor_scores: dict[str, float], weights: dict[str, float]) -> int:
    """
    factor_scores: {"fingerprint": 20, "ip_reputation": 0, ...}
    weights:        {"fingerprint": 0.8, "ip_reputation": 1.0, ...}
    max_score_per_factor = 100（各因子统一）
    """
    weighted_sum = sum(factor_scores[k] * weights[k] for k in weights)
    weight_sum   = sum(weights[k] * 100 for k in weights)  # 100 为 max_score

    raw = (weighted_sum / weight_sum) * 100 if weight_sum > 0 else 0
    return clamp(int(raw), 0, 100)
```

### 4.3 风险等级与处置

| 风险分 | 等级 | 处置动作 |
|--------|------|----------|
| 0–30 | 低风险 | ✅ 直接通过，无感知 |
| 31–60 | 中风险 | ⚠️ 触发 MFA 验证（强制 TOTP/短信） |
| 61–100 | 高风险 | 🚫 拒绝登录 + 记录风控事件 + 告警 |

### 4.4 风控决策服务

```python
class RiskDecisionEngine:
    # 默认权重（基于经验值，建议根据实际业务调整）
    DEFAULT_WEIGHTS = {
        "failure_count":   1.0,  # 经验值：失败次数是最强信号
        "fingerprint":     0.8,  # 经验值
        "ip_reputation":   1.0,  # 经验值：IP黑名单直接满分
        "geo_location":    0.6,  # 经验值
        "login_time":      0.4,  # 经验值
    }

    async def evaluate(
        self,
        user_id: UUID | None,
        fp_data: FingerprintData,
        ip_address: str,
        login_failures: int,
        request_timestamp: datetime,
        tenant_id: UUID,
    ) -> RiskDecision:
        # 从 risk_rules 表热加载权重（带 Redis 缓存）
        weights = await self._load_weights(tenant_id)

        fp_score      = self._score_fingerprint(fp_data, user_id)
        ip_score      = self._score_ip_reputation(ip_address)
        geo_score     = self._score_geo_location(ip_address, user_id)
        time_score    = self._score_login_time(request_timestamp)
        failure_score = self._score_failure_count(login_failures)

        factor_scores = {
            "fingerprint":   fp_score,
            "ip_reputation": ip_score,
            "geo_location":  geo_score,
            "login_time":    time_score,
            "failure_count": failure_score,
        }

        risk_score = self.normalize_risk_score(factor_scores, weights)

        thresholds = await self._load_thresholds(tenant_id)
        if risk_score <= thresholds["low"]:
            action = RiskAction.ALLOW
        elif risk_score <= thresholds["medium"]:
            action = RiskAction.MFA_REQUIRED
        else:
            action = RiskAction.DENY

        return RiskDecision(
            risk_score=risk_score,
            action=action,
            factors=factor_scores,
            weights_used=weights,  # v1.1: 记录本次使用的权重
        )
```

### 4.5 阈值与权重可配置化（v1.1 强化）

所有阈值通过 `risk_rules` 配置表管理，运行时可热更新（Redis 缓存 + Postgres 持久化）：

```sql
CREATE TABLE risk_rules (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID REFERENCES tenants(id),     -- NULL = 全局规则
    rule_key    VARCHAR(64) NOT NULL UNIQUE,
    rule_value  JSONB NOT NULL,
    description TEXT,
    is_active   BOOLEAN DEFAULT TRUE,
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    updated_at  TIMESTAMPTZ DEFAULT NOW()
);

INSERT INTO risk_rules (rule_key, rule_value, description) VALUES
('risk_thresholds',        '{"low": 30, "medium": 60}',     '风险分阈值，基于经验值'),
('weight_failure',         '{"value": 1.0}',                '失败计数权重，基于经验值，建议范围 0.5-2.0'),
('weight_fingerprint',     '{"value": 0.8}',                '指纹权重，基于经验值，建议范围 0.5-1.5'),
('weight_ip_reputation',   '{"value": 1.0}',                'IP信誉权重，基于经验值，建议范围 0.5-2.0'),
('weight_geo',             '{"value": 0.6}',                '地理位置权重，基于经验值，建议范围 0.3-1.0'),
('weight_time',            '{"value": 0.4}',                '登录时间权重，基于经验值，建议范围 0.1-0.8'),
('ip_block_ttl_seconds',   3600,                             'IP封禁TTL（秒）'),
('failure_count_max',      5,                                '触发封禁的失败次数'),
('geo_distance_threshold_km', 500,                           '地理位置异常阈值（公里）'),
('unusual_hour_start',      23,                               '异常时段开始（小时）'),
('unusual_hour_end',        6,                                '异常时段结束（小时）'),
('max_score_per_factor',   100,                              '各因子标准化满分值（固定为100）');
```

**热更新机制：**

```
1. 管理员通过 API 修改 risk_rules 表
2. 触发器自动更新 updated_at
3. 后台同步任务（轮询/CDC）将更新推送到 Redis 缓存
4. 下次风控评估时自动加载新权重
5. 缓存 TTL：300秒（5分钟），无需主动失效
```

---

## 5. IP 信誉系统

### 5.1 IP 黑名单

**Redis（动态黑名单，TTL 可配置）：**

```
Key:   ip_blacklist:{ip_address}
Value: JSON {reason, added_at, expires_at, attack_type}
TTL:   可配置（默认 3600 秒）
```

**PostgreSQL（持久化记录）：**

```sql
CREATE TABLE ip_blacklist (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ip_address  INET NOT NULL,
    ip_version  SMALLINT NOT NULL CHECK (ip_version IN (4, 6)),
    reason      VARCHAR(64) NOT NULL,   -- 'bruteforce' | 'credential_stuffing' | 'anomaly' | 'manual'
    attack_type VARCHAR(32),
    added_by    UUID,
    expires_at  TIMESTAMPTZ,
    is_active   BOOLEAN DEFAULT TRUE,
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    updated_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_ip_blacklist_active  ON ip_blacklist(ip_address) WHERE is_active = TRUE;
CREATE INDEX idx_ip_blacklist_expires ON ip_blacklist(expires_at) WHERE expires_at IS NOT NULL;
```

### 5.2 IP 段封锁（/24）（v1.1 优化）

> **⚠️ v1.1 变更：** `/24` 段封锁**默认关闭**。段封锁可能影响同一 ISP 下的无辜用户，造成大范围误伤。仅在明确检测到大规模自动化攻击时由管理员手动启用。

```python
class IPSubnetBlocker:
    BLOCK_SUBNET_SIZE    = 24
    SUBNET_BLOCK_DEFAULT = False  # v1.1: 默认关闭
    SUBNET_BLOCK_TTL     = 900    # 15分钟
```

**配置项（risk_rules）：**

```sql
INSERT INTO risk_rules (rule_key, rule_value, description) VALUES
('subnet_block_enabled',  false,   '默认关闭 /24 段封锁，仅大规模攻击时启用'),
('subnet_block_size',      24,      '/24 段封锁掩码'),
('subnet_block_ttl',      900,     '段封锁 TTL（秒，15分钟）');
```

### 5.3 验证码阶梯（v1.1 新增）

> **设计思路：** 不是所有失败都是攻击，首次失败后出现验证码可在不阻断正常用户的前提下有效阻止暴力破解。

```
失败计数 → 验证码触发规则：
  第 1 次失败 → 显示 CAPTCHA（前端拦截，不请求后端）
  第 2 次失败 → 需通过 CAPTCHA 验证才能继续
  第 3 次失败 → 需通过 CAPTCHA + 限流
  第 5 次失败 / 15分钟 → 封禁 IP
```

**CAPTCHA 集成：**
- 支持多种 CAPTCHA 提供商（配置化）：Turnstile、reCAPTCHA、Geetest
- CAPTCHA token 随登录请求一起提交，后端验证 token 有效性
- 验证失败视为登录失败

### 5.4 IP 封禁渐进升级（v1.1 新增）

> **设计思路：** 短时封禁（5分钟）作为第一道防线，逐步升级，避免直接长时间封禁导致的用户体验问题。

| 阶段 | 触发条件 | 封禁时长 | 说明 |
|------|---------|---------|------|
| **Stage 1** | 5次失败/15分钟 | 5 分钟 | 短时冷却，防止自动化工具 |
| **Stage 2** | Stage 1 后再失败 3 次 | 30 分钟 | 中时封禁 |
| **Stage 3** | Stage 2 后再失败 3 次 | 2 小时 | 长时封禁 |
| **Stage 4** | Stage 3 后再失败 2 次 | 24 小时 | 整天封禁，触发告警 |
| **手动封禁** | 管理员操作 | 可配置 | 长期或永久 |

**Redis 存储：**

```
Key: ip_ban_stage:{ip_address}
Value: Integer (stage: 0-4)
TTL: 随封禁时长自动过期（封禁结束时 stage 重置为 0）
```

**成功登录后：**
- 立即清除该 IP 的失败计数（Redis Key 删除）
- 封禁 stage 重置为 0
- 防止正常用户因记错密码被长期封禁

### 5.5 IP 白名单

```sql
CREATE TABLE ip_allowlist (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID REFERENCES tenants(id),
    ip_pattern  INET NOT NULL,
    description VARCHAR(255),
    is_active   BOOLEAN DEFAULT TRUE,
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_ip_allowlist_active ON ip_allowlist(ip_pattern) WHERE is_active = TRUE;
```

白名单 IP 不参与任何风控检查。

### 5.6 自动封禁规则（v1.1 修订）

| 触发条件 | 动作 | TTL | 说明 |
|----------|------|-----|------|
| 登录失败 5 次 / 15 分钟 | 封禁 IP Stage 1 | 5分钟 | 渐进升级第一级 |
| 撞库检测（100次/小时） | 封禁 IP Stage 2 | 30分钟 | 确认攻击行为 |
| 风控决策 = DENY | 封禁 IP Stage 3 | 2小时 | 高风险拒绝 |
| 管理员手动封禁 | 封禁 IP | 手动解封 | 长期 |
| `/24` 段封锁（可选） | 封禁段 | 15分钟 | 默认关闭 |

---

## 6. 登录行为审计

### 6.1 登录日志扩展

```sql
ALTER TABLE login_attempts ADD COLUMN IF NOT EXISTS fp_hash              VARCHAR(64);
ALTER TABLE login_attempts ADD COLUMN IF NOT EXISTS fp_score             INTEGER;
ALTER TABLE login_attempts ADD COLUMN IF NOT EXISTS fp_is_new             BOOLEAN;
ALTER TABLE login_attempts ADD COLUMN IF NOT EXISTS risk_score           INTEGER;
ALTER TABLE login_attempts ADD COLUMN IF NOT EXISTS risk_action          VARCHAR(16);
ALTER TABLE login_attempts ADD COLUMN IF NOT EXISTS risk_factors         JSONB;
ALTER TABLE login_attempts ADD COLUMN IF NOT EXISTS risk_weights_used     JSONB;  -- v1.1: 记录风控评估使用的权重
ALTER TABLE login_attempts ADD COLUMN IF NOT EXISTS geo_country          VARCHAR(8);
ALTER TABLE login_attempts ADD COLUMN IF NOT EXISTS geo_city             VARCHAR(64);
ALTER TABLE login_attempts ADD COLUMN IF NOT EXISTS geo_latitude         DECIMAL(9,6);
ALTER TABLE login_attempts ADD COLUMN IF NOT EXISTS geo_longitude         DECIMAL(9,6);
ALTER TABLE login_attempts ADD COLUMN IF NOT EXISTS user_agent            TEXT;
ALTER TABLE login_attempts ADD COLUMN IF NOT EXISTS login_time_unusual   BOOLEAN;
ALTER TABLE login_attempts ADD COLUMN IF NOT EXISTS ip_unusual           BOOLEAN;
ALTER TABLE login_attempts ADD COLUMN IF NOT EXISTS mfa_used              BOOLEAN;
ALTER TABLE login_attempts ADD COLUMN IF NOT EXISTS mfa_method            VARCHAR(8);
ALTER TABLE login_attempts ADD COLUMN IF NOT EXISTS session_id           UUID;
ALTER TABLE login_attempts ADD COLUMN IF NOT EXISTS challenge_id          UUID;   -- v1.1: canvas challenge ID
```

### 6.2 风控事件表

```sql
CREATE TABLE risk_events (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    event_type      VARCHAR(32) NOT NULL,
    event_level     VARCHAR(8) NOT NULL,
    user_id         UUID REFERENCES users(id),
    ip_address      INET NOT NULL,
    fp_hash         VARCHAR(64),
    risk_score      INTEGER,
    risk_action     VARCHAR(16),
    details         JSONB,
    resolved        BOOLEAN DEFAULT FALSE,
    resolved_at     TIMESTAMPTZ,
    resolved_by     UUID,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_risk_events_tenant     ON risk_events(tenant_id, created_at DESC);
CREATE INDEX idx_risk_events_user       ON risk_events(tenant_id, user_id, created_at DESC);
CREATE INDEX idx_risk_events_type       ON risk_events(tenant_id, event_type, created_at DESC);
CREATE INDEX idx_risk_events_unresolved ON risk_events(tenant_id) WHERE resolved = FALSE;
```

### 6.3 异常登录告警

| 告警类型 | 触发条件 | 通知方式 |
|----------|----------|----------|
| **异地登录** | 当前登录城市与上次登录城市距离 > 500km 且时间 < 2小时 | Admin告警 + 用户通知 |
| **异常时间** | 本地时间 23:00–06:00 登录（可配置） | Admin告警 |
| **频繁失败** | 同一IP登录失败 ≥ 5次 / 15分钟 | Admin告警 |
| **新设备高风险** | 新设备 + 风险分 > 50 | Admin告警 |
| **账户接管嫌疑** | 1小时内登录失败10次后突然成功 | Admin告警 |
| **IP 封禁升级** | Stage ≥ 3 的封禁触发 | Admin告警 + 安全团队通知 |

---

## 7. API 限流增强

### 7.1 限流规则

| 接口 | 限流 | Key |
|------|------|-----|
| `POST /api/v1/auth/login` | 5次/分钟 | IP |
| `POST /api/v1/auth/login` | 10次/分钟 | User（失败计数） |
| `POST /api/v1/auth/refresh` | 10次/分钟 | User |
| `POST /api/v1/auth/register` | 3次/小时 | IP |
| `POST /api/v1/auth/send-code` | 5次/分钟 | IP |
| `POST /api/v1/auth/logout` | 30次/分钟 | User |
| `GET /api/v1/auth/canvas-challenge` | 10次/分钟 | IP |

### 7.2 限流实现

滑动窗口算法，Redis 存储：

```
Key:   ratelimit:{endpoint}:{key}:{window_id}
Value: 请求计数
TTL:   窗口大小（秒）
```

限流触发返回 HTTP 429，包含 `Retry-After` Header。

---

## 8. 完整 DDL

```sql
-- =============================================================
-- Canvas Challenge 表（v1.1 新增）
-- =============================================================
CREATE TABLE canvas_challenges (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    nonce           VARCHAR(64) NOT NULL,
    user_id_hint    UUID,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ NOT NULL,
    used            BOOLEAN DEFAULT FALSE,
    used_at         TIMESTAMPTZ,
    used_fp_hash    VARCHAR(64)
);

CREATE INDEX idx_canvas_challenge_expires ON canvas_challenges(expires_at) WHERE used = FALSE;

-- =============================================================
-- 设备指纹库
-- =============================================================
CREATE TABLE device_fingerprints (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    user_id         UUID NOT NULL REFERENCES users(id),
    fp_hash         VARCHAR(64) NOT NULL,
    challenge_id    UUID REFERENCES canvas_challenges(id),
    ua              TEXT,
    accept_language VARCHAR(255),
    color_depth     INTEGER,
    screen_size     VARCHAR(16),
    timezone        VARCHAR(64),
    canvas_hash     VARCHAR(64),
    webgl_renderer  VARCHAR(255),
    platform        VARCHAR(32),
    touch_support   BOOLEAN,
    first_seen_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    trust_score     INTEGER DEFAULT 0,
    is_trusted      BOOLEAN DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, user_id, fp_hash)
);

CREATE INDEX idx_device_fp_lookup ON device_fingerprints(tenant_id, user_id, fp_hash);
CREATE INDEX idx_device_fp_user   ON device_fingerprints(tenant_id, user_id);

-- =============================================================
-- Client Secret 轮换历史（v1.1 新增）
-- =============================================================
CREATE TABLE client_secret_history (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id),
    secret_hash     VARCHAR(64) NOT NULL,
    issued_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expired_at      TIMESTAMPTZ,
    rotated_by      UUID REFERENCES users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_secret_history_user ON client_secret_history(user_id, issued_at DESC);

-- =============================================================
-- IP 黑名单
-- =============================================================
CREATE TABLE ip_blacklist (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ip_address  INET NOT NULL,
    ip_version  SMALLINT NOT NULL CHECK (ip_version IN (4, 6)),
    reason      VARCHAR(64) NOT NULL,
    attack_type VARCHAR(32),
    added_by    UUID,
    expires_at  TIMESTAMPTZ,
    is_active   BOOLEAN DEFAULT TRUE,
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    updated_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_ip_blacklist_active  ON ip_blacklist(ip_address) WHERE is_active = TRUE;
CREATE INDEX idx_ip_blacklist_expires ON ip_blacklist(expires_at) WHERE expires_at IS NOT NULL;

-- =============================================================
-- IP 白名单
-- =============================================================
CREATE TABLE ip_allowlist (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID REFERENCES tenants(id),
    ip_pattern  INET NOT NULL,
    description VARCHAR(255),
    is_active   BOOLEAN DEFAULT TRUE,
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_ip_allowlist_active ON ip_allowlist(ip_pattern) WHERE is_active = TRUE;

-- =============================================================
-- 风控事件记录
-- =============================================================
CREATE TABLE risk_events (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    event_type      VARCHAR(32) NOT NULL,
    event_level     VARCHAR(8) NOT NULL,
    user_id         UUID REFERENCES users(id),
    ip_address      INET NOT NULL,
    fp_hash         VARCHAR(64),
    risk_score      INTEGER,
    risk_action     VARCHAR(16),
    details         JSONB,
    resolved        BOOLEAN DEFAULT FALSE,
    resolved_at     TIMESTAMPTZ,
    resolved_by     UUID,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_risk_events_tenant     ON risk_events(tenant_id, created_at DESC);
CREATE INDEX idx_risk_events_user       ON risk_events(tenant_id, user_id, created_at DESC);
CREATE INDEX idx_risk_events_type       ON risk_events(tenant_id, event_type, created_at DESC);
CREATE INDEX idx_risk_events_unresolved ON risk_events(tenant_id) WHERE resolved = FALSE;

-- =============================================================
-- 风控规则配置
-- =============================================================
CREATE TABLE risk_rules (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID REFERENCES tenants(id),
    rule_key    VARCHAR(64) NOT NULL,
    rule_value  JSONB NOT NULL,
    description TEXT,
    is_active   BOOLEAN DEFAULT TRUE,
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    updated_at  TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(tenant_id, rule_key)
);

-- =============================================================
-- Users 表字段变更（v1.1 新增）
-- =============================================================
ALTER TABLE users ADD COLUMN IF NOT EXISTS client_secret_hash         VARCHAR(64);
ALTER TABLE users ADD COLUMN IF NOT EXISTS client_secret_rotated_at   TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN IF NOT EXISTS previous_secret_hash       VARCHAR(64);
ALTER TABLE users ADD COLUMN IF NOT EXISTS previous_secret_expires_at TIMESTAMPTZ;
```

---

## 9. API 详细设计

### 9.1 Canvas Challenge 接口（v1.1 新增）

**`GET /api/v1/auth/canvas-challenge`**

响应：
```json
{
  "challenge_id": "550e8400-e29b-41d4-a716-446655440000",
  "nonce": "a1b2c3d4e5f67890...",
  "expires_in": 120
}
```

### 9.2 登录接口（扩展）

**`POST /api/v1/auth/login`**

新增请求头：
```
X-Device-Fingerprint: {"ua":"...","accept_language":"...","canvas_hash":"...","challenge_id":"..."}
X-Timestamp: 1743624000
X-Nonce: uuid-v4
X-Signature: hex-hmac-sha256
X-Captcha-Token: (可选，第2次失败后必传)
```

响应扩展：
```json
{
  "access_token": "...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "mfa_required": false,
  "risk": {
    "risk_score": 15,
    "risk_level": "low",
    "device_trusted": true,
    "weights_used": {"failure_count": 1.0, "fingerprint": 0.8, ...}
  }
}
```

当 `risk_level = "medium"` 时，`mfa_required = true`。

### 9.3 Secret 轮换接口（v1.1 新增）

**`POST /api/v1/auth/rotate-secret`** — 手动触发 secret 轮换（正常由系统自动执行）。

**`POST /api/v1/auth/revoke-secret`** — 主动撤销当前 secret，生成新 secret，踢出所有设备。

### 9.4 风控事件查询

**`GET /api/v1/admin/v1/risk/events`**

### 9.5 添加白名单

**`POST /api/v1/admin/v1/risk/allowlist`**

### 9.6 手动封禁 IP

**`POST /api/v1/admin/v1/risk/block`**

### 9.7 风控仪表盘

**`GET /api/v1/admin/v1/risk/overview`**

### 9.8 风控规则管理 API（v1.1 新增）

**`GET /api/v1/admin/v1/risk/rules`**
**`PUT /api/v1/admin/v1/risk/rules/{rule_key}`** — 热更新，无需重启

---

## 10. 风险分数与 ABAC 集成（v1.1 新增）

### 10.1 设计目标

将风控引擎产出的 `risk_score` 无缝传递到 ABAC 决策引擎，实现：
1. JWT 中携带本次登录的 `risk_score`
2. MFA 完成后将会话与初始风险事件绑定
3. ABAC 策略根据 `environment.risk_score` 动态调整权限

### 10.2 JWT 中增加 risk_score 声明

```json
{
  "sub": "user_uuid",
  "tenant_id": "tenant_uuid",
  "risk_score": 25,
  "risk_level": "low",
  "session_id": "session_uuid",
  "mfa_completed": true,
  "initial_risk_event_ids": ["event_uuid_1"],
  "iat": 1743624000,
  "exp": 1743627600
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `risk_score` | int | 本次登录的风险评分（0-100） |
| `risk_level` | str | low / medium / high |
| `initial_risk_event_ids` | list[UUID] | MFA 完成后绑定的初始风险事件 ID |
| `mfa_completed` | bool | 本次会话是否完成了 MFA 验证 |

### 10.3 MFA 完成时会话绑定初始风险事件

```python
async def mfa_verify_complete(
    session_id: UUID,
    user_id: UUID,
    risk_decision: RiskDecision,
    tenant_id: UUID,
) -> None:
    # 查找该用户在当前会话的未解决风险事件
    risk_events = await db.fetch(
        """
        SELECT id FROM risk_events
        WHERE user_id = $1 AND tenant_id = $2
          AND session_id IS NULL
          AND resolved = FALSE
          AND created_at > NOW() - INTERVAL '1 hour'
        ORDER BY created_at DESC
        """,
        user_id, tenant_id
    )

    if risk_events:
        event_ids = [e["id"] for e in risk_events]
        await db.execute(
            "UPDATE risk_events SET resolved = TRUE, resolved_at = NOW(), session_id = $1 WHERE id = ANY($2)",
            session_id, event_ids
        )

    await db.execute(
        "UPDATE sessions SET initial_risk_events = $1, initial_risk_score = $2 WHERE id = $3",
        event_ids, risk_decision.risk_score, session_id
    )
```

### 10.4 ABACContextBuilder 集成 risk_score

```python
class ABACContextBuilder:
    @classmethod
    async def from_jwt(cls, token_payload: dict) -> ABACContext:
        context = ABACContext()

        context.subject = Subject(
            id=token_payload["sub"],
            tenant_id=token_payload["tenant_id"],
            roles=token_payload.get("roles", []),
        )

        # Environment（含 risk_score，v1.1）
        context.environment = Environment(
            risk_score=token_payload.get("risk_score", 0),
            risk_level=token_payload.get("risk_level", "unknown"),
            mfa_completed=token_payload.get("mfa_completed", False),
            session_id=token_payload.get("session_id"),
            initial_risk_events=token_payload.get("initial_risk_event_ids", []),
            ip_address=token_payload.get("ip_address"),
            device_fp_hash=token_payload.get("fp_hash"),
        )

        return context
```

### 10.5 ABAC 策略示例（基于 risk_score）

```python
class HighRiskOperationPolicy(Policy):
    """
    规则：risk_score >= 60 时，禁止执行敏感操作
    规则：risk_score >= 30 时，敏感操作需要 Step-Up Auth
    """

    def evaluate(self, context: ABACContext, resource: Resource, action: Action) -> Decision:
        risk_score = context.environment.risk_score

        if action.is_sensitive:
            if risk_score >= 60:
                return Decision.DENY(reason=f"High risk login (score={risk_score}), action blocked")
            elif risk_score >= 30:
                return Decision.CONDITIONAL(require_step_up=True, message="Additional verification required")

        return Decision.ALLOW
```

### 10.6 Session 与 Risk Event 关联 DDL

```sql
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS initial_risk_events  UUID[];
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS initial_risk_score    INTEGER;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS initial_risk_action  VARCHAR(16);
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS mfa_completed_at      TIMESTAMPTZ;

ALTER TABLE risk_events ADD COLUMN IF NOT EXISTS session_id  UUID REFERENCES sessions(id);
```

---

## 11. 服务架构

```
backend/app/
├── api/
│   ├── admin/v1/risk.py              # 风控管理 API
│   └── auth/v1/
│       ├── login.py                  # 登录接口
│       └── canvas.py                 # Canvas challenge 接口（v1.1）
├── services/
│   ├── defense/
│   │   ├── device_fingerprint.py     # 设备指纹服务（含 challenge 验证）
│   │   ├── replay_protection.py      # 重放攻击防护
│   │   ├── risk_engine.py             # 风控决策引擎（含权重加载）
│   │   ├── ip_reputation.py          # IP 信誉服务（含渐进封禁）
│   │   ├── geo_locator.py            # IP 地理定位
│   │   └── alert_service.py          # 异常告警
│   ├── auth/
│   │   ├── login_flow.py             # 登录流程
│   │   ├── client_secret.py           # Secret 管理 + 轮换（v1.1）
│   │   └── mfa_flow.py               # MFA 流程（会话绑定 v1.1）
│   └── abac/
│       └── context_builder.py        # ABACContextBuilder（v1.1 集成 risk_score）
├── models/defense.py                 # SQLAlchemy 模型
├── schemas/defense.py                # Pydantic schemas
├── middleware/
│   ├── replay_signature.py           # 重放签名中间件
│   ├── rate_limit.py                # 限流中间件
│   └── risk_context.py              # 风控上下文注入
└── core/security/
    ├── hmac_signature.py             # HMAC 签名工具
    └── fp_hasher.py                  # 指纹哈希工具
```

### 11.1 防御链路集成点

```
登录请求
    │
    ▼
[限流中间件] ──── 超出限制 ──→ HTTP 429
    │
    ▼
[签名中间件] ──── 签名失败 ──→ HTTP 400 "Invalid signature"
    │
    ▼
[IP白名单检查] ── 白名单IP ──→ 跳过风控，直接认证
    │
    ▼
[IP黑名单检查] ── 在黑名单 ──→ HTTP 403 "IP blocked"
    │
    ▼
[设备指纹服务] ── 获取 canvas-challenge ──→ 服务端生成 nonce
    │
    ▼
[Canvas Challenge 验证] ── 验证失败 ──→ HTTP 400 "invalid_canvas_challenge"
    │
    ▼
[风控决策引擎]
    │         高风险 ──→ HTTP 403 + 记录 risk_event
    │         中风险 ──→ 触发 MFA → MFA通过 → 绑定 risk_event 到 session
    │         低风险 ──→ 直接认证
    │
    ▼
[Client Secret 轮换检查] ── 超期 ──→ 触发自动轮换
    │
    ▼
[认证服务] → 登录成功 → 清除该 IP 失败计数 → 颁发 JWT（含 risk_score 声明）
```

---

## 12. 与 Phase 1-2 的兼容性

| 已有功能 | 兼容策略 |
|----------|----------|
| 登录失败锁定 | 保留，数据打通；失败计数统一使用 Redis |
| TOTP MFA | 风控触发 MFA 时复用现有 TOTP 验证接口 |
| ABAC 策略 | 风控决策后可携带 `environment.risk_score` 进入 ABAC 决策（v1.1 强化） |
| 会话管理 | 登录成功后颁发 Session ID；Session 中增加 risk_score 字段（v1.1） |
| 审计日志 | `login_attempts` 扩展字段与审计日志系统共享 |
| 现有 JWT | 向后兼容；无 risk_score 声明的 JWT 等同于 risk_score=0 |

---

## 13. 安全注意事项

| 威胁 | 防御措施 |
|------|----------|
| HMAC 密钥泄漏 | 客户端密钥存 httpOnly Cookie（v1.1 强制），不可通过 JS 读取 |
| Canvas 指纹伪造 | 服务端挑战-应答机制（nonce 混哈希），自动化工具无法绕过（v1.1） |
| 时序攻击 | HMAC 比较使用 `secrets.compare_digest` |
| Redis 数据泄漏 | Redis 仅存短期数据，无敏感明文 |
| IP 伪造 | X-Forwarded-For 取最左侧非信任代理IP |
| 暴力破解 | 验证码阶梯 + 渐进封禁 + 限流三重防护（v1.1） |
| 撞库 | 请求签名 + 频率限制 + IP信誉联动 |
| 重放攻击 | nonce + timestamp + HMAC 三重校验 |
| Secret 长期持有泄漏 | 自动 30 天轮换 + 7 天宽限期（v1.1） |
| ABAC 绕过 | risk_score 注入 JWT 并由 ABACContextBuilder 读取，不可客户端伪造（v1.1） |

---

## 14. 性能考量

| 优化点 | 方案 |
|--------|------|
| Redis 热路径 | 指纹/限流/Nonce/Challenge 全部走 Redis，PG 仅持久化 |
| 批量写 | 风控事件异步写入（后台队列），不影响登录响应 |
| IP 地理库 | 轻量库（geoip2/ip2region），首次查询缓存 Redis 1天 |
| 签名验证 | HMAC-SHA256 极快，延迟 < 1ms |
| 并发 | async/await 全链路，Redis MGET 批量查询 |
| 权重热加载 | risk_rules 缓存 Redis 5分钟，减少 PG 查询 |
| Canvas Challenge | 每个 challenge 仅用一次，验证后立即删除，无累积压力 |

---

## 15. 事件类型定义

| event_type | event_level | 说明 |
|------------|-------------|------|
| `fp_changed` | high | 设备指纹显著变更（账户接管嫌疑） |
| `brute_force` | critical | 暴力破解检测到 |
| `credential_stuffing` | critical | 撞库攻击 |
| `replay_attack` | high | 重放攻击请求 |
| `geo_anomaly` | medium | 地理位置异常 |
| `time_anomaly` | low | 登录时间异常 |
| `ip_blocked` | medium | IP 被封禁 |
| `ip_block_escalated` | high | IP 封禁升级（Stage >= 2，v1.1 新增） |
| `high_risk_login` | high | 高风险登录（分数>60） |
| `mfa_bypass_attempt` | critical | MFA 绕过尝试 |
| `mfa_failed` | low | MFA 验证失败 |
| `canvas_challenge_failed` | medium | Canvas 挑战验证失败（v1.1 新增） |
| `secret_rotated` | low | Secret 轮换触发（v1.1 新增） |
| `subnet_blocked` | medium | /24 段封锁触发（v1.1 新增） |

---

## 16. 修订说明（v1.0 → v1.1）

| 问题 | 修订内容 |
|------|---------|
| CanvasHash 可伪造 | 新增服务端挑战-应答机制：GET /canvas-challenge 返回随机 nonce，前端将其混入 Canvas 渲染数据后 SHA256，验证时后端比对，防止自动化工具离线伪造 |
| client_secret 安全 | 强制 httpOnly Cookie 存储 secret（Web/SPA），新增 30 天自动密钥轮换 + 7 天旧 secret 宽限期；新增 revoke-secret 主动撤销接口 |
| 风控权重调优 | 各因子 max_score=100 明确标注；归一化公式完整给出 `weighted_sum / (Σweight×100) × 100`；默认权重标注"基于经验值"；权重在 risk_rules 表可热更新 |
| IP 封禁优化 | /24 封锁默认关闭；新增验证码阶梯（第1次失败→前端 CAPTCHA，2次+→后端验证）；成功登录后立即清除失败计数；封禁改为 Stage 1-4 渐进升级（5分钟→30分钟→2小时→24小时） |
| 风险分数与 ABAC 集成 | JWT 中增加 `risk_score`、`risk_level`、`initial_risk_event_ids` 声明；MFA 完成后将 risk_events 绑定到 session；ABACContextBuilder 从 JWT 提取 `environment.risk_score` 并传给策略引擎；新增高风险操作的 ABAC 策略示例 |
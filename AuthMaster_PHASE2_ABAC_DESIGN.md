# AuthMaster Phase 2-2: ABAC 动态策略引擎设计

## 1. 概述

### 1.1 设计目标

在现有 RBAC 基础上构建 ABAC（Attribute-Based Access Control）层，实现**细粒度、动态上下文感知的访问控制**。ABAC 策略基于用户、资源、环境的多维属性进行决策，支持比 RBAC 更复杂的业务规则。

### 1.2 技术栈

- **后端框架**: FastAPI + SQLAlchemy async
- **数据库**: PostgreSQL（策略存储）+ Redis（缓存层）
- **表达式引擎**: Python `eval` + 安全 AST 解析（禁止 `exec`/`__import__`）
- **策略编译器**: 热点策略预编译为可调用函数

---

## 2. ABAC 核心模型

### 2.1 属性类型体系

```
AttributeCategory
├── SUBJECT（主体属性 / 用户属性）
├── RESOURCE（资源属性）
└── ENVIRONMENT（环境属性）
```

| 属性名 | 类别 | 类型 | 示例值 | 说明 |
|--------|------|------|--------|------|
| `department` | SUBJECT | string | `"engineering"` | 用户所属部门 |
| `location` | SUBJECT | string | `"CN"` | 用户所在地区/国家 |
| `clearance_level` | SUBJECT | integer | `3` | 安全 clearance 等级（1-5） |
| `role` | SUBJECT | string | `"admin"` | 用户角色（RBAC 衔接） |
| `owner` | RESOURCE | string | `"user:42"` | 资源拥有者 ID |
| `owner.department` | RESOURCE | string | `"engineering"` | 资源拥有者部门 |
| `sensitivity` | RESOURCE | integer | `2` | 资源敏感等级（1-5） |
| `type` | RESOURCE | string | `"document"` | 资源类型 |
| `ip` | ENVIRONMENT | string | `"192.168.1.100"` | 请求来源 IP |
| `time.hour` | ENVIRONMENT | integer | `14` | 当前小时（0-23） |
| `time.weekday` | ENVIRONMENT | string | `"Monday"` | 当前星期几 |
| `device_type` | ENVIRONMENT | string | `"trusted_laptop"` | 设备类型 |
| `network_zone` | ENVIRONMENT | string | `"internal"` | 网络区域 |

### 2.2 策略结构（Policy）

```python
class Policy:
    id: UUID
    name: str                          # 策略唯一名称
    description: str | None
    version: int                        # 版本号（每次修改 +1）
    effect: Literal["allow", "deny"]   # 策略效果

    # 匹配范围（为空 = 匹配全部）
    subjects: list[SubjectPattern]      # 匹配哪些用户属性
    resources: list[ResourcePattern]   # 匹配哪些资源
    actions: list[str]                  # 匹配哪些操作（read/write/delete/...）

    # 条件表达式（核心）
    condition: ConditionExpression | None

    # 元数据
    priority: int                       # 优先级（数值越小越优先）
    enabled: bool
    created_at: datetime
    updated_at: datetime
    created_by: str
```

### 2.3 条件表达式（ConditionExpression）

支持三种表达式的自由组合：

#### 2.3.1 简单比较

```json
{
  "type": "simple",
  "attribute": "user.clearance_level",
  "operator": ">=",
  "value": 3
}
```

**支持的操作符：**

| 操作符 | 说明 | 示例 |
|--------|------|------|
| `==` | 等于 | `user.department == "engineering"` |
| `!=` | 不等于 | `user.role != "guest"` |
| `>` | 大于 | `user.clearance_level > 2` |
| `>=` | 大于等于 | `user.clearance_level >= 3` |
| `<` | 小于 | `resource.sensitivity < 4` |
| `<=` | 小于等于 | `resource.sensitivity <= 2` |
| `in` | 在集合中 | `user.location in ["CN", "US", "SG"]` |
| `not_in` | 不在集合中 | `user.role not_in ["banned"]` |
| `contains` | 字符串包含 | `user.email contains "@company.com"` |
| `starts_with` | 前缀匹配 | `resource.type starts_with "doc:"` |
| `regex` | 正则匹配（带超时保护） | `user.id regex "^emp_\\d+$"` |

#### 2.3.2 时间范围

```json
{
  "type": "time_range",
  "attribute": "env.time.hour",
  "start": 9,
  "end": 18,
  "days": ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]
}
```

#### 2.3.3 IP 网段

```json
{
  "type": "ip_range",
  "attribute": "env.ip",
  "cidr": "10.0.0.0/8"
}
```

#### 2.3.4 组合表达式

```json
{
  "type": "and",
  "conditions": [
    { "type": "simple", "attribute": "user.department", "operator": "==", "value": "engineering" },
    { "type": "simple", "attribute": "user.clearance_level", "operator": ">=", "value": 3 }
  ]
}
```

```json
{
  "type": "or",
  "conditions": [
    { "type": "simple", "attribute": "user.role", "operator": "==", "value": "admin" },
    { "type": "and", "conditions": [
      { "type": "simple", "attribute": "user.department", "operator": "==", "value": "engineering" },
      { "type": "simple", "attribute": "resource.owner", "operator": "==", "value": "user.id" }
    ]}
  ]
}
```

---

## 3. 数据库模型

### 3.1 ER 图

```
┌──────────────────────┐     ┌─────────────────────────┐
│   abac_policy_attrs  │     │      abac_policies       │
├──────────────────────┤     ├─────────────────────────┤
│ id (PK)              │     │ id (PK)                  │
│ name                 │◄────│ attribute_id (FK)        │
│ category             │     │ name                     │
│ data_type            │     │ description              │
│ description          │     │ version                  │
│ default_value        │     │ effect                   │
│ validation_rule      │     │ priority                 │
│ enabled              │     │ enabled                  │
└──────────────────────┘     │ created_at               │
                              │ updated_at               │
                              │ created_by               │
                              └───────────┬─────────────┘
                                          │
                              ┌───────────▼─────────────┐
                              │  abac_policy_conditions  │
                              ├─────────────────────────┤
                              │ id (PK)                  │
                              │ policy_id (FK)           │
                              │ condition_type           │
                              │ attribute_path           │
                              │ operator                 │
                              │ value (JSONB, max 4KB)   │
                              │ position (排序)           │
                              └─────────────────────────┘

┌──────────────────────┐
│  abac_user_attrs     │   （用户属性缓存表）
├──────────────────────┤
│ user_id (PK, FK)     │
│ attr_name (PK)       │
│ attr_value (JSONB)   │
│ cached_at            │
└──────────────────────┘

┌──────────────────────┐
│   abac_policy_versions│  （策略版本历史）
├──────────────────────┤
│ id (PK)              │
│ policy_id (FK)       │
│ version              │
│ snapshot (JSONB)      │
│ changed_by           │
│ changed_at           │
│ change_summary       │
└──────────────────────┘
```

### 3.2 表 DDL

#### `abac_policy_attributes` — 属性类型定义

```sql
CREATE TABLE abac_policy_attributes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(64) NOT NULL UNIQUE,
    category VARCHAR(32) NOT NULL CHECK (category IN ('SUBJECT', 'RESOURCE', 'ENVIRONMENT')),
    data_type VARCHAR(32) NOT NULL CHECK (data_type IN ('string', 'integer', 'boolean', 'list', 'ip', 'time')),
    description TEXT,
    default_value JSONB,
    validation_rule JSONB,
    allowed_values JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    enabled BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE INDEX idx_abac_policy_attrs_category ON abac_policy_attributes(category);
CREATE INDEX idx_abac_policy_attrs_enabled ON abac_policy_attributes(enabled);
```

#### `abac_policies` — 策略定义

```sql
CREATE TABLE abac_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(128) NOT NULL UNIQUE,
    description TEXT,
    version INT NOT NULL DEFAULT 1,
    effect VARCHAR(16) NOT NULL CHECK (effect IN ('allow', 'deny')),
    priority INT NOT NULL DEFAULT 100,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    subjects JSONB NOT NULL DEFAULT '[]',
    resources JSONB NOT NULL DEFAULT '[]',
    actions JSONB NOT NULL DEFAULT '[]',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by VARCHAR(128) NOT NULL,

    CONSTRAINT chk_actions_not_empty CHECK (jsonb_typeof(actions) = 'array')
);

CREATE INDEX idx_abac_policies_enabled ON abac_policies(enabled);
CREATE INDEX idx_abac_policies_effect ON abac_policies(effect);
CREATE INDEX idx_abac_policies_priority ON abac_policies(priority);
CREATE INDEX idx_abac_policies_actions ON abac_policies USING GIN(actions);
```

#### `abac_policy_conditions` — 策略条件

```sql
CREATE TABLE abac_policy_conditions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id UUID NOT NULL REFERENCES abac_policies(id) ON DELETE CASCADE,
    condition_type VARCHAR(32) NOT NULL CHECK (condition_type IN ('simple', 'time_range', 'ip_range', 'and', 'or', 'not')),
    attribute_path VARCHAR(128),
    operator VARCHAR(16),
    value JSONB NOT NULL CHECK (octet_length(value::text) <= 4096),  -- 【修复 v4】最大 4KB
    extra JSONB,
    position INT NOT NULL DEFAULT 0,

    CONSTRAINT chk_simple_condition CHECK (
        (condition_type = 'simple' AND attribute_path IS NOT NULL AND operator IS NOT NULL AND value IS NOT NULL) OR
        (condition_type != 'simple')
    )
);

CREATE INDEX idx_abac_policy_conditions_policy ON abac_policy_conditions(policy_id);
```

#### `abac_user_attributes` — 用户属性缓存

```sql
CREATE TABLE abac_user_attributes (
    user_id UUID NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
    attr_name VARCHAR(64) NOT NULL,
    attr_value JSONB NOT NULL,
    cached_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (user_id, attr_name)
);

CREATE INDEX idx_abac_user_attrs_cached_at ON abac_user_attributes(cached_at);
```

#### `abac_policy_versions` — 策略版本历史

```sql
CREATE TABLE abac_policy_versions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id UUID NOT NULL REFERENCES abac_policies(id) ON DELETE CASCADE,
    version INT NOT NULL,
    snapshot JSONB NOT NULL,
    changed_by VARCHAR(128) NOT NULL,
    changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    change_summary TEXT,

    UNIQUE(policy_id, version)
);

CREATE INDEX idx_abac_policy_versions_policy ON abac_policy_versions(policy_id);
CREATE INDEX idx_abac_policy_versions_changed_at ON abac_policy_versions(changed_at);
```

---

## 4. 策略评估引擎

### 4.1 评估流程

```
┌─────────────────────────────────────────────────────────────────┐
│                      Access Request                             │
│              { user_id, resource, action, context }              │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│  Step 1: RBAC 前置过滤                                           │
│  → require_permission(user, action, resource_type)              │
│  → 如果 RBAC deny，直接返回 Deny（不进入 ABAC）                    │
└────────────────────────┬────────────────────────────────────────┘
                         │ RBAC Allow
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│  Step 2: 收集属性（用户 + 资源 + 环境）                             │
│  → Redis 缓存优先 → DB 回源 → 写入 Redis                          │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│  Step 3: 策略匹配（Policy Matcher）                               │
│  → 按 priority 升序获取所有 enabled 策略                           │
│  → 【修复 v4】DB 层 JSON 过滤：actions @> :action OR actions = []│
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│  Step 4: 条件评估 + 决策收集                                      │
│  → 对所有匹配策略逐条评估条件                                      │
│  → 【修复 v2】收集所有 (policy_id, effect)，不 first-applicable    │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│  Step 5: 决策合成（deny-override）                               │
│  → 任一 deny → Deny；无 deny → Allow                            │
│  → 无匹配策略 → ABAC_DEFAULT_DECISION（deny）                    │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│  Step 6: 100ms 硬超时（asyncio.wait_for 最外层包装）               │
│  → 超时 → Deny（fail-safe）                                      │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
                   [ Allow / Deny ]
```

### 4.2 评估器核心代码

```python
# app/abac/engine.py

import asyncio
import re
import ipaddress
import time
import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID

import redis.asyncio as redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.abac import (
    ABACPolicy, ABACPolicyCondition, ABACUserAttribute,
    ABACPolicyAttribute
)
from app.core.errors import PermissionDeniedError


# ─── 配置 ───────────────────────────────────────────────────────────────────

class ABACConfig:
    """ABAC 全局配置（从 config.yaml 加载）"""
    EVALUATION_TIMEOUT_MS: int = 100          # 评估硬超时（毫秒）
    USER_ATTR_CACHE_TTL: int = 300             # 用户属性缓存 TTL（秒）
    POLICY_CACHE_TTL: int = 60                 # 策略列表缓存 TTL（秒）
    COMPILED_CACHE_TTL: int = 600              # 编译策略缓存 TTL（秒）
    DEFAULT_COMBINATION_ALGO: str = "deny-override"
    DEFAULT_DECISION: str = "deny"             # 无匹配策略时默认拒绝
    REGEX_TIMEOUT_SEC: float = 0.1            # 【修复 v4】正则超时（秒）


# ─── 数据模型 ───────────────────────────────────────────────────────────────

@dataclass
class AccessRequest:
    """访问请求"""
    user_id: UUID
    action: str                          # "read", "write", "delete"
    resource_type: str                   # "document", "project"
    resource_id: UUID | None = None
    resource_attrs: dict[str, Any] = field(default_factory=dict)
    context: dict[str, Any] = field(default_factory=dict)  # env attributes


@dataclass
class AttributeSet:
    """属性集合"""
    subject: dict[str, Any] = field(default_factory=dict)
    resource: dict[str, Any] = field(default_factory=dict)
    environment: dict[str, Any] = field(default_factory=dict)
    _eval_now: datetime | None = field(default=None)  # 评估开始时的统一时间戳

    def get(self, path: str) -> Any:
        """
        获取属性值，支持任意深度嵌套路径。

        支持示例：
        - "user.department"           → 两层
        - "resource.owner.department" → 三层（任意深度）
        - "env.time.hour"             → 三层

        实现：全分割后逐层迭代解析，不限制嵌套深度。
        """
        parts = path.split(".")
        if not parts:
            return None

        prefix = parts[0]
        if prefix == "user":
            d = self.subject
        elif prefix == "resource":
            d = self.resource
        elif prefix == "env":
            d = self.environment
        else:
            return None

        for part in parts[1:]:
            if isinstance(d, dict):
                d = d.get(part)
            else:
                return None
        return d


@dataclass
class EvaluationResult:
    """评估结果"""
    decision: str                        # "allow" | "deny"
    matched_policy: UUID | None
    reason: str
    evaluation_time_ms: float


class CombinationAlgorithm(Enum):
    DENY_OVERRIDE = "deny-override"       # 默认：任何 deny 优先
    PERMIT_OVERRIDE = "permit-override"  # 任何 permit 优先（需无 deny）
    FIRST_APPLICABLE = "first-applicable"  # 第一个匹配的策略决定
    ONLY_ONE_APPLICABLE = "only-one-applicable"  # 仅当恰好一个匹配时


def combine_decisions(
    algorithm: CombinationAlgorithm,
    decisions: list[tuple[UUID, str]],   # [(policy_id, effect), ...]
    default: str = "deny",
) -> str:
    """
    合成多个策略决策。

    deny-override 算法：
    1. 遍历所有决策，任一 deny → 最终 Deny
    2. 若无 deny 且至少一个 allow → 最终 Allow
    3. 无匹配策略 → ABAC_DEFAULT_DECISION（默认 deny）
    """
    if not decisions:
        return default

    if algorithm == CombinationAlgorithm.DENY_OVERRIDE:
        for _, effect in decisions:
            if effect == "deny":
                return "deny"
        for _, effect in decisions:
            if effect == "allow":
                return "allow"
        return default

    elif algorithm == CombinationAlgorithm.PERMIT_OVERRIDE:
        has_deny = any(e == "deny" for _, e in decisions)
        if has_deny:
            return "deny"
        has_permit = any(e == "allow" for _, e in decisions)
        return "allow" if has_permit else default

    elif algorithm == CombinationAlgorithm.FIRST_APPLICABLE:
        return decisions[0][1] if decisions else default

    elif algorithm == CombinationAlgorithm.ONLY_ONE_APPLICABLE:
        if len(decisions) == 1:
            return decisions[0][1]
        return default

    return default


# ─── 条件表达式求值器 ─────────────────────────────────────────────────────────

class ConditionEvaluator:
    """
    条件表达式求值器（安全，不使用 eval）。

    安全措施（v4 修复）：
    - 所有操作均为显式方法调用，无动态代码执行
    - regex 操作符使用 asyncio.wait_for + loop.run_in_executor 限制执行时间（0.1s），
      防止 ReDoS；异常时直接返回 False，不降级同步匹配
    - condition.value 经过类型校验，不匹配则跳过该条件（防止 TypeError）
    - 正则长度限制（<=500）在初始化阶段校验，运行时直接使用预编译对象
    - 【修复 v4】in/not_in 操作符增加 actual 类型检查（非 dict/list 等集合类型报错）
    """

    SCALAR_OPS = {"==", "!=", ">", ">=", "<", "<="}
    COLLECTION_OPS = {"in", "not_in"}
    STRING_OPS = {"contains", "starts_with", "regex"}

    def __init__(self, regex_timeout_sec: float = 0.1):
        self.REGEX_TIMEOUT_SEC = regex_timeout_sec

    def evaluate(self, condition: ABACPolicyCondition, attrs: AttributeSet) -> bool:
        ctype = condition.condition_type

        if ctype == "simple":
            return self._eval_simple(condition, attrs)
        elif ctype == "time_range":
            return self._eval_time_range(condition, attrs)
        elif ctype == "ip_range":
            return self._eval_ip_range(condition, attrs)
        elif ctype == "and":
            return self._eval_and(condition, attrs)
        elif ctype == "or":
            return self._eval_or(condition, attrs)
        elif ctype == "not":
            return self._eval_not(condition, attrs)
        else:
            return False

    def eval_condition(self, condition: ABACPolicyCondition, attrs: AttributeSet) -> bool:
        """与 evaluate 相同，供 PolicyCompiler 生成的闭包调用"""
        return self.evaluate(condition, attrs)

    def _validate_types(self, actual: Any, expected: Any, op: str) -> bool:
        """
        【修复 v4】类型校验：校验操作符与值类型是否匹配。
        不匹配时返回 False（跳过该条件，防止 TypeError）。
        """
        if op in ("in", "not_in"):
            # 【修复 v4】actual 必须是可迭代集合类型
            # dict/str/int/float/bool/None 均不是合法的集合类型
            if isinstance(actual, (dict, str, int, float, bool, type(None))):
                return False
            if not isinstance(expected, (list, tuple, set, frozenset)):
                return False
            return True

        if op in self.SCALAR_OPS:
            if actual is None:
                return False
            # 布尔值只支持 == / !=
            if isinstance(actual, bool) and op not in ("==", "!="):
                return False
            # 跨类型比较直接拒绝
            if type(actual) != type(expected):
                # 允许 int/float 互转
                if isinstance(actual, (int, float)) and isinstance(expected, (int, float)):
                    return True
                return False
            return True

        if op == "contains":
            return isinstance(actual, str) and isinstance(expected, str)
        if op == "starts_with":
            return isinstance(actual, str) and isinstance(expected, str)
        if op == "regex":
            # 正则长度限制（初始化阶段防止资源耗尽）
            return isinstance(expected, str) and len(expected) <= 500

        return True

    def _safe_regex(self, pattern: str, text: str) -> bool:
        """
        【修复 v4】带超时保护的正则匹配（ReDoS 防护，跨平台兼容）。

        使用 asyncio.wait_for + loop.run_in_executor 实现超时：
        - asyncio.wait_for 驱动超时控制，跨平台兼容
        - loop.run_in_executor 将同步正则匹配卸载到线程池，避免阻塞事件循环
        - 0.1 秒超时，超时直接返回 False，不降级同步匹配
        - 编译异常（re.error）也直接返回 False
        """
        try:
            compiled = re.compile(pattern)
        except re.error:
            return False

        def _sync_match() -> bool:
            return bool(compiled.match(text))

        async def _match_with_timeout() -> bool:
            loop = asyncio.get_running_loop()
            return await asyncio.wait_for(
                loop.run_in_executor(None, _sync_match),
                timeout=self.REGEX_TIMEOUT_SEC,
            )

        try:
            loop = asyncio.get_running_loop()
            try:
                return loop.run_until_complete(_match_with_timeout())
            except (asyncio.TimeoutError, OSError, RuntimeError):
                # 【修复 v4】异常时直接返回 False，不降级同步匹配
                return False
        except RuntimeError:
            # 无运行中事件循环（罕见），直接同步执行
            try:
                import signal
                with signal.timeout(self.REGEX_TIMEOUT_SEC):
                    return _sync_match()
            except (signal.TimeoutError, AttributeError):
                # signal.timeout 不可用（Windows），返回 False
                return False

    OPERATORS = {
        "==": lambda a, b: a == b,
        "!=": lambda a, b: a != b,
        ">": lambda a, b: a > b,
        ">=": lambda a, b: a >= b,
        "<": lambda a, b: a < b,
        "<=": lambda a, b: a <= b,
    }

    def _eval_simple(self, cond: ABACPolicyCondition, attrs: AttributeSet) -> bool:
        actual = attrs.get(cond.attribute_path)
        if actual is None:
            return False

        op = cond.operator
        expected = cond.value

        # 类型校验：不匹配则跳过（视为条件不成立）
        if not self._validate_types(actual, expected, op):
            return False

        try:
            if op in self.SCALAR_OPS:
                return self.OPERATORS[op](actual, expected)
            elif op == "in":
                return actual in expected
            elif op == "not_in":
                return actual not in expected
            elif op == "contains":
                return expected in str(actual)
            elif op == "starts_with":
                return str(actual).startswith(expected)
            elif op == "regex":
                # 【修复 v4】ReDoS 保护：正则匹配带超时，异常直接返回 False
                return self._safe_regex(expected, str(actual))
            else:
                return False
        except (TypeError, ValueError, OverflowError):
            return False

    def _eval_time_range(self, cond: ABACPolicyCondition, attrs: AttributeSet) -> bool:
        """
        时间范围评估。

        星期几评估优先使用 request.context.now（评估开始时统一时间戳），
        若 context 中无 now 则降级为 datetime.now()（保持向后兼容）。
        """
        extra = cond.extra or {}
        start = extra.get("start", 0)
        end = extra.get("end", 23)
        days = extra.get("days", [])

        actual = attrs.get(cond.attribute_path)
        if actual is None:
            return False

        if not isinstance(actual, (int, float)):
            return False
        if not (start <= actual <= end):
            return False

        if days:
            # 优先使用 AttributeSet._eval_now（评估开始时统一时间戳）
            now = attrs._eval_now if attrs._eval_now else datetime.now()
            weekday = now.strftime("%A")
            if weekday not in days:
                return False

        return True

    def _eval_ip_range(self, cond: ABACPolicyCondition, attrs: AttributeSet) -> bool:
        """
        IP 网段评估，带格式预校验。

        双重保护：
        1. 格式预校验：快速拒绝明显非 IP 格式的输入
        2. ipaddress 模块解析 + 比较（已有的 try/except）
        """
        extra = cond.extra or {}
        cidr = extra.get("cidr")
        if not cidr:
            return False

        actual = attrs.get(cond.attribute_path)
        if not actual:
            return False

        # 格式预校验：IPv4 点分十进制 / IPv6 冒号十六进制
        if isinstance(actual, str):
            # IPv4: 4段数字，段值 0-255
            if "." in actual and not ":" in actual:
                parts = actual.split(".")
                if len(parts) != 4:
                    return False
                try:
                    if not all(0 <= int(p) <= 255 for p in parts):
                        return False
                except ValueError:
                    return False
            # IPv6: 8段十六进制（简化检测）
            elif ":" in actual:
                parts = actual.split(":")
                if len(parts) > 8:
                    return False
                try:
                    if not all(len(p) <= 4 for p in parts if p):
                        return False
                except ValueError:
                    return False

        try:
            ip = ipaddress.ip_address(actual)
            network = ipaddress.ip_network(cidr, strict=False)
            return ip in network
        except (ValueError, TypeError):
            return False

    def _eval_and(self, cond: ABACPolicyCondition, attrs: AttributeSet) -> bool:
        for sub in (cond.value or []):
            if not self.evaluate(sub, attrs):
                return False
        return True

    def _eval_or(self, cond: ABACPolicyCondition, attrs: AttributeSet) -> bool:
        for sub in (cond.value or []):
            if self.evaluate(sub, attrs):
                return True
        return False

    def _eval_not(self, cond: ABACPolicyCondition, attrs: AttributeSet) -> bool:
        for sub in (cond.value or []):
            if self.evaluate(sub, attrs):
                return False
        return True


# ─── ABAC 评估引擎 ───────────────────────────────────────────────────────────

class ABACEngine:
    """
    ABAC 策略评估引擎。

    关键保障：
    1. deny-override 决策合成：先收集所有策略决策，再合并（不是 first-applicable）
    2. asyncio.wait_for 硬超时：100ms 内必须完成，超时 → Deny
    3. 缓存失效：策略 CRUD 时同步清理 abac:policies:all / abac:policy:{id} / abac:compiled:{id}
    4. 无匹配策略 → ABAC_DEFAULT_DECISION（deny）
    """

    CACHE_KEY_USER_ATTRS = "abac:user_attrs:{user_id}"
    CACHE_KEY_POLICIES_ALL = "abac:policies:all"
    CACHE_KEY_POLICY = "abac:policy:{policy_id}"
    CACHE_KEY_COMPILED = "abac:compiled:{policy_id}"

    def __init__(
        self,
        db: AsyncSession,
        redis_client: redis.Redis,
        evaluation_timeout_ms: int = 100,
    ):
        self.db = db
        self.redis = redis_client
        self.timeout_ms = evaluation_timeout_ms
        self.condition_evaluator = ConditionEvaluator(
            regex_timeout_sec=ABACConfig.REGEX_TIMEOUT_SEC
        )
        self.config = ABACConfig()

    async def evaluate(self, request: AccessRequest) -> EvaluationResult:
        """
        执行策略评估（deny-override + 100ms 硬超时）。

        评估流程：
        1. 收集属性（subject/resource/environment）
        2. 获取所有匹配的策略（按 priority 排序）
        3. 对每个匹配策略执行条件评估，收集 (policy_id, effect) 决策列表
        4. 调用 combine_decisions(deny-override) 合并决策
        5. 无匹配 → ABAC_DEFAULT_DECISION（deny）
        """
        start = time.monotonic()

        # 评估开始时获取统一 now，存入 request.context
        # 确保同一请求内所有时间相关评估（time.hour、time_range days 等）使用同一时间戳
        request.context["now"] = datetime.now()

        # 1. 收集属性
        attrs = await self._collect_attributes(request)

        # 2. 获取所有匹配策略
        policies = await self._get_matching_policies(request)

        # 3. 收集所有匹配策略的决策，不再 first-applicable
        decisions: list[tuple[UUID, str]] = []

        for policy in policies:
            elapsed_ms = (time.monotonic() - start) * 1000
            # 软超时检查（防止单次评估占用过多时间）
            if elapsed_ms > self.timeout_ms:
                return EvaluationResult(
                    decision="deny",
                    matched_policy=None,
                    reason=f"Evaluation soft-timeout after {elapsed_ms:.1f}ms (fail-safe)",
                    evaluation_time_ms=elapsed_ms,
                )

            matched = await self._evaluate_policy(policy, attrs, request)
            if matched:
                decisions.append((policy.id, policy.effect))

        elapsed_ms = (time.monotonic() - start) * 1000

        # 4. 决策合成：deny-override
        algo = CombinationAlgorithm(self.config.DEFAULT_COMBINATION_ALGO)
        final_decision = combine_decisions(
            algo,
            decisions,
            default=self.config.DEFAULT_DECISION,
        )

        if decisions:
            matched_id = decisions[0][0]
            deny_count = sum(1 for _, e in decisions if e == "deny")
            if final_decision == "deny":
                reason = f"Deny-override: {deny_count}/{len(decisions)} policies voted deny"
            else:
                reason = f"No deny found among {len(decisions)} matched policies → allow"
        else:
            matched_id = None
            reason = f"No matching policy, default={self.config.DEFAULT_DECISION}"

        return EvaluationResult(
            decision=final_decision,
            matched_policy=matched_id,
            reason=reason,
            evaluation_time_ms=elapsed_ms,
        )

    async def evaluate_with_timeout(self, request: AccessRequest) -> EvaluationResult:
        """
        带 100ms 硬超时的评估入口。

        使用 asyncio.wait_for 包装整个 evaluate() 调用。
        超时直接抛出 asyncio.TimeoutError，外部捕获后返回 Deny。
        这是 fail-safe 的最后兜底（比内部软超时更强）。
        """
        try:
            return await asyncio.wait_for(
                self.evaluate(request),
                timeout=self.timeout_ms / 1000.0,
            )
        except asyncio.TimeoutError:
            return EvaluationResult(
                decision="deny",
                matched_policy=None,
                reason=f"ABAC evaluation hard-timeout after {self.timeout_ms}ms (fail-safe)",
                evaluation_time_ms=float(self.timeout_ms),
            )

    async def _collect_attributes(self, request: AccessRequest) -> AttributeSet:
        """收集用户、资源、环境属性"""
        # 用户属性（Redis 缓存优先）
        subject_attrs = await self._get_user_attributes(request.user_id)

        # 资源属性
        resource_attrs = {
            **request.resource_attrs,
            "type": request.resource_type,
            "id": str(request.resource_id) if request.resource_id else None,
        }

        # 环境属性（时间使用评估开始时统一 now）
        now = request.context.get("now", datetime.now())
        env_attrs = {
            "ip": request.context.get("ip"),
            "time.hour": now.hour,
            "time.weekday": now.strftime("%A"),
            "device_type": request.context.get("device_type", "unknown"),
            "network_zone": request.context.get("network_zone", "external"),
        }

        return AttributeSet(
            subject=subject_attrs,
            resource=resource_attrs,
            environment=env_attrs,
            _eval_now=now,
        )

    async def _get_user_attributes(self, user_id: UUID) -> dict[str, Any]:
        """从 Redis 缓存获取用户属性，缓存未命中则查 DB"""
        cache_key = self.CACHE_KEY_USER_ATTRS.format(user_id=str(user_id))

        cached = await self.redis.get(cache_key)
        if cached:
            return json.loads(cached)

        from sqlalchemy import select
        from app.models.abac import ABACUserAttribute

        result = await self.db.execute(
            select(ABACUserAttribute).where(ABACUserAttribute.user_id == user_id)
        )
        rows = result.scalars().all()

        attrs = {}
        for row in rows:
            attrs[row.attr_name] = row.attr_value

        await self.redis.setex(cache_key, self.config.USER_ATTR_CACHE_TTL, json.dumps(attrs))

        return attrs

    async def _get_matching_policies(self, request: AccessRequest) -> list[ABACPolicy]:
        """
        【修复 v4】获取所有匹配的策略（按 priority 升序）。

        DB 层 JSON 过滤：
        - actions @> :action  → 匹配包含该 action 的策略（GIN 索引支持）
        - OR actions = '[]'  → 空 actions 列表匹配全部 action
        - subjects / resources 在应用层过滤（复杂度低）
        """
        from sqlalchemy import select, text
        from app.models.abac import ABACPolicy

        # 【修复 v4】DB 层 JSON 过滤，减少应用层过滤负担
        result = await self.db.execute(
            select(ABACPolicy)
            .where(
                ABACPolicy.enabled == True,
                # 【修复 v4】actions @> :action OR actions = '[]'（DB 层过滤）
                text("(actions @> :action OR actions = '[]'::jsonb)")
            )
            .params(action=json.dumps(request.action))
            .order_by(ABACPolicy.priority.asc())
        )
        all_policies = result.scalars().all()

        matched = []
        for p in all_policies:
            # subjects 在应用层过滤
            if not self._match_subject_pattern(p.subjects, request):
                continue
            if not self._match_resource_pattern(p.resources, request.resource_type, request.resource_attrs):
                continue
            matched.append(p)

        return matched

    def _match_action(self, policy_actions: list, request_action: str) -> bool:
        """检查请求 action 是否在策略 actions 中"""
        if not policy_actions:
            return True
        return request_action in policy_actions

    def _match_subject_pattern(self, patterns: list, request: AccessRequest) -> bool:
        """
        主体属性模式匹配。

        patterns 为空表示匹配全部；
        所有模式均需匹配（AND 逻辑）。
        """
        if not patterns:
            return True

        # 从 request.context 获取 subject attrs（由 RBAC 层提供）
        subject_attrs = request.context.get("subject_attrs", {})
        for pattern in patterns:
            pat_attr = pattern.get("attr")
            pat_op = pattern.get("op", "==")
            pat_value = pattern.get("value")
            actual = subject_attrs.get(pat_attr)
            if actual is None:
                return False
            try:
                matched = self._match_scalar(actual, pat_op, pat_value)
            except (TypeError, ValueError):
                return False
            if not matched:
                return False
        return True

    def _match_resource_pattern(self, patterns: list, resource_type: str, resource_attrs: dict) -> bool:
        """
        完整的资源匹配实现，支持任意属性模式。

        支持的属性：
        - type        : 资源类型（string）
        - sensitivity : 敏感等级（integer）
        - owner       : 资源拥有者（string）
        - id          : 资源 ID（string）
        - 自定义属性   : resource_attrs 中的任意键

        支持的操作符：==, !=, >, >=, <, <=, in, not_in
        所有模式均需匹配（AND 逻辑），空模式列表表示匹配全部。
        """
        if not patterns:
            return True

        for pattern in patterns:
            pat_attr = pattern.get("attr")
            pat_op = pattern.get("op", "==")
            pat_value = pattern.get("value")

            # 解析实际属性值
            if pat_attr == "type":
                actual = resource_type
            elif pat_attr in ("id", "sensitivity", "owner"):
                actual = resource_attrs.get(pat_attr)
            else:
                actual = resource_attrs.get(pat_attr)

            if actual is None:
                return False

            # 类型预校验（防止比较时 TypeError）
            try:
                matched = self._match_scalar(actual, pat_op, pat_value)
            except (TypeError, ValueError):
                return False

            if not matched:
                return False

        return True

    def _match_scalar(self, actual: Any, op: str, expected: Any) -> bool:
        """单值模式匹配，支持所有标准操作符"""
        if op == "==":
            return actual == expected
        elif op == "!=":
            return actual != expected
        elif op == ">":
            return actual > expected
        elif op == ">=":
            return actual >= expected
        elif op == "<":
            return actual < expected
        elif op == "<=":
            return actual <= expected
        elif op == "in":
            return actual in expected if isinstance(expected, (list, tuple, set, frozenset)) else False
        elif op == "not_in":
            return actual not in expected if isinstance(expected, (list, tuple, set, frozenset)) else False
        return False

    async def _evaluate_policy(
        self,
        policy: ABACPolicy,
        attrs: AttributeSet,
        request: AccessRequest,
    ) -> bool:
        """评估单个策略的条件是否满足"""
        conditions = policy.conditions

        if not conditions:
            return True

        for cond in sorted(conditions, key=lambda c: c.position):
            if not self.condition_evaluator.evaluate(cond, attrs):
                return False
        return True
```

---

## 5. 与 RBAC 集成

### 5.1 集成架构

```
┌─────────────────────────────────────────────────────────┐
│                  FastAPI Endpoint                        │
│  @require_permission("document:write", resource_type)   │
└────────────────────────┬────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│  RBAC Layer (第一道防线)                                  │
│  → 检查 user.role → permission 映射                      │
│  → 快速拒绝未授权操作（无属性依赖）                         │
└────────────────────────┬────────────────────────────────┘
                         │ RBAC Allow
                         ▼
┌─────────────────────────────────────────────────────────┐
│  ABAC Layer (第二道防线 / 细粒度控制)                      │
│  → 评估动态属性条件（deny-override）                      │
│  → 100ms 硬超时保护（asyncio.wait_for）                   │
└────────────────────────┬────────────────────────────────┘
                         │
                         ▼
                   [ 最终决策 ]
```

### 5.2 扩展 `require_permission` 装饰器

```python
# app/api/deps.py

from functools import wraps
from typing import Callable

from fastapi import Depends, HTTPException, status, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import get_current_user
from app.models.user import User
from app.api.v1 import rbac
from app.abac.engine import ABACEngine, AccessRequest, CombinationAlgorithm
from app.core import redis


async def get_abac_engine(
    db: AsyncSession = Depends(get_db),
) -> ABACEngine:
    """Dependency: 获取 ABAC 引擎实例"""
    redis_client = await redis.get_redis()
    return ABACEngine(db=db, redis_client=redis_client)


def require_permission(
    permission: str,
    resource_type: str,
    resource_id_param: str = "resource_id",
    abac_enabled: bool = True,
    combination_algo: CombinationAlgorithm = CombinationAlgorithm.DENY_OVERRIDE,
):
    """
    扩展的权限装饰器（RBAC + ABAC）。

    Args:
        permission: RBAC 权限字符串，如 "document:write"
        resource_type: 资源类型，如 "document"
        resource_id_param: FastAPI 路径参数中的资源 ID 字段名
        abac_enabled: 是否启用 ABAC 评估
        combination_algo: 决策合成算法
    """
    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            user = kwargs.get("current_user") or args[0] if args else None
            if not user:
                raise HTTPException(status_code=401, detail="Not authenticated")

            # RBAC 基础检查
            has_permission = await rbac.check_permission(user.id, permission)
            if not has_permission:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Permission denied: {permission}"
                )

            # 2. ABAC 细粒度检查（如果启用）
            if abac_enabled:
                resource_id = kwargs.get(resource_id_param)
                resource_attrs = kwargs.get("resource_attrs", {})

                request_obj: Request = kwargs.get("request")
                context = {}
                if request_obj:
                    context["ip"] = request_obj.client.host if request_obj.client else None

                abac_engine: ABACEngine = kwargs.get("abac_engine")
                if abac_engine:
                    access_request = AccessRequest(
                        user_id=user.id,
                        action=permission.split(":")[-1],
                        resource_type=resource_type,
                        resource_id=resource_id,
                        resource_attrs=resource_attrs,
                        context=context,
                    )
                    # 使用带超时的评估入口
                    result = await abac_engine.evaluate_with_timeout(access_request)
                    if result.decision == "deny":
                        raise HTTPException(
                            status_code=status.HTTP_403_FORBIDDEN,
                            detail=f"ABAC policy denied: {result.reason}",
                        )

            return await func(*args, **kwargs)

        return wrapper
    return decorator


### 5.3 API 端点使用示例

```python
# app/api/v1/endpoints/documents.py

from fastapi import APIRouter, Depends, Path, Body, Request
from uuid import UUID

from app.api.deps import (
    get_current_user,
    get_abac_engine,
    require_permission,
)
from app.models.user import User
from app.abac.engine import ABACEngine

router = APIRouter()


@router.post("/documents/{document_id}/share")
@require_permission("document:share", resource_type="document", resource_id_param="document_id")
async def share_document(
    document_id: UUID = Path(...),
    target_user_id: UUID = Body(...),
    current_user: User = Depends(get_current_user),
    abac_engine: ABACEngine = Depends(get_abac_engine),
    request: Request = None,
):
    """
    共享文档（RBAC 检查 + ABAC 条件检查）。

    ABAC 条件示例：
    - 用户必须与文档 owner 同部门
    - 或用户 clearance_level >= 文档 sensitivity
    """
    # ... 业务逻辑
    pass
```

---

## 6. 管理员 API

### 6.1 路由结构

```
/admin/v1/abac/
├── policies/
│   ├── GET    /                     → 列出策略（分页、过滤）
│   ├── POST   /                     → 创建策略
│   ├── GET    /{policy_id}           → 获取策略详情
│   ├── PUT    /{policy_id}           → 更新策略
│   ├── DELETE /{policy_id}           → 删除策略（同时清理缓存）
│   ├── GET    /{policy_id}/audit    → 策略变更审计日志
│   └── POST   /evaluate              → 手动测试策略评估
├── attributes/
│   ├── GET    /                     → 列出属性定义
│   └── POST   /                     → 创建属性定义
└── user-attributes/
    ├── GET    /{user_id}            → 获取用户属性
    ├── PUT    /{user_id}            → 更新用户属性
    └── DELETE /{user_id}/{attr_name} → 删除用户属性
```

### 6.2 策略 CRUD — 核心实现（含缓存失效）

```python
# app/api/v1/abac/policies.py

from fastapi import APIRouter, Depends, HTTPException, status, Body, Query
from pydantic import BaseModel, Field
from uuid import UUID
from typing import Literal, Any
from datetime import datetime

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, delete

from app.api.deps import get_db, get_current_admin_user
from app.models.abac import (
    ABACPolicy, ABACPolicyCondition, ABACPolicyVersion,
    ABACPolicyAttribute
)
from app.models.user import User

router = APIRouter(prefix="/admin/v1/abac/policies", tags=["ABAC Policies"])

# ─── Redis 缓存失效辅助 ────────────────────────────────────────────────────────

class PolicyCache:
    """策略缓存管理（完整失效）"""

    @staticmethod
    async def invalidate(redis_client: redis.Redis, policy_id: UUID):
        """
        策略变更时同步删除以下缓存：
        - abac:policies:all       （策略列表缓存）
        - abac:policy:{id}         （单策略缓存）
        - abac:compiled:{id}       （编译策略缓存）
        """
        keys = [
            "abac:policies:all",
            f"abac:policy:{policy_id}",
            f"abac:compiled:{policy_id}",
        ]
        for key in keys:
            await redis_client.delete(key)

    @staticmethod
    async def invalidate_all(redis_client: redis.Redis):
        """全局失效：所有策略相关缓存"""
        keys = [
            "abac:policies:all",
        ]
        # 清理所有 abac:policy:* 和 abac:compiled:* keys
        async for key in redis_client.scan_iter(match="abac:policy:*"):
            await redis_client.delete(key)

        async for key in redis_client.scan_iter(match="abac:compiled:*"):
            await redis_client.delete(key)
        for key in keys:
            await redis_client.delete(key)


# ─── Schemas ──────────────────────────────────────────────────────────────────

class ConditionExpression(BaseModel):
    type: Literal["simple", "time_range", "ip_range", "and", "or", "not"]
    attribute: str | None = None
    operator: str | None = None
    value: Any | None = None
    extra: dict | None = None
    conditions: list["ConditionExpression"] | None = None


class SubjectPattern(BaseModel):
    attr: str
    op: str = "=="
    value: str | list


class ResourcePattern(BaseModel):
    attr: str
    op: str = "=="
    value: str | list


class PolicyCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    description: str | None = None
    effect: Literal["allow", "deny"]
    priority: int = Field(default=100, ge=1, le=10000)
    subjects: list[SubjectPattern] = []
    resources: list[ResourcePattern] = []
    actions: list[str] = Field(..., min_length=1)
    conditions: list[ConditionExpression] = []


class PolicyUpdate(BaseModel):
    description: str | None = None
    effect: Literal["allow", "deny"] | None = None
    priority: int | None = None
    enabled: bool | None = None
    subjects: list[SubjectPattern] | None = None
    resources: list[ResourcePattern] | None = None
    actions: list[str] | None = None
    conditions: list[ConditionExpression] | None = None


class PolicyResponse(BaseModel):
    id: UUID
    name: str
    description: str | None
    version: int
    effect: str
    priority: int
    enabled: bool
    subjects: list
    resources: list
    actions: list
    conditions: list
    created_at: datetime
    updated_at: datetime
    created_by: str

    class Config:
        from_attributes = True


# ─── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/", response_model=list[PolicyResponse])
async def list_policies(
    enabled: bool | None = None,
    effect: str | None = None,
    action: str | None = None,
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
):
    """列出 ABAC 策略（分页、过滤）"""
    query = select(ABACPolicy)

    if enabled is not None:
        query = query.where(ABACPolicy.enabled == enabled)
    if effect:
        query = query.where(ABACPolicy.effect == effect)

    count_query = select(func.count()).select_from(ABACPolicy)
    total = await db.scalar(count_query)

    query = query.order_by(ABACPolicy.priority.asc()).offset(offset).limit(limit)
    result = await db.execute(query)
    policies = result.scalars().all()

    return [
        PolicyResponse(
            id=p.id,
            name=p.name,
            description=p.description,
            version=p.version,
            effect=p.effect,
            priority=p.priority,
            enabled=p.enabled,
            subjects=p.subjects or [],
            resources=p.resources or [],
            actions=p.actions or [],
            conditions=[],
            created_at=p.created_at,
            updated_at=p.updated_at,
            created_by=p.created_by,
        )
        for p in policies
    ]


@router.post("/", response_model=PolicyResponse, status_code=status.HTTP_201_CREATED)
async def create_policy(
    policy_in: PolicyCreate,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_current_admin_user),
    redis_client: redis.Redis = Depends(get_redis),
):
    """创建 ABAC 策略"""
    # 名称唯一检查
    existing = await db.execute(
        select(ABACPolicy).where(ABACPolicy.name == policy_in.name)
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Policy name already exists")

    # 创建策略
    policy = ABACPolicy(
        name=policy_in.name,
        description=policy_in.description,
        effect=policy_in.effect,
        priority=policy_in.priority,
        subjects=[s.model_dump() for s in policy_in.subjects],
        resources=[r.model_dump() for r in policy_in.resources],
        actions=policy_in.actions,
        created_by=admin.username,
    )
    db.add(policy)
    await db.flush()

    # 创建条件
    for idx, cond in enumerate(policy_in.conditions):
        _create_condition(db, policy.id, cond, idx)

    # 创建初始版本快照
    await _create_version_snapshot(db, policy, admin.username, "Initial creation")

    await db.commit()
    await db.refresh(policy)

    # 缓存失效
    await PolicyCache.invalidate(redis_client, policy.id)

    return PolicyResponse(
        id=policy.id, name=policy.name, description=policy.description,
        version=policy.version, effect=policy.effect, priority=policy.priority,
        enabled=policy.enabled, subjects=policy.subjects or [],
        resources=policy.resources or [], actions=policy.actions or [],
        conditions=[], created_at=policy.created_at,
        updated_at=policy.updated_at, created_by=policy.created_by,
    )


@router.get("/{policy_id}", response_model=PolicyResponse)
async def get_policy(
    policy_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """获取策略详情"""
    result = await db.execute(
        select(ABACPolicy).where(ABACPolicy.id == policy_id)
    )
    policy = result.scalar_one_or_none()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")

    return PolicyResponse(
        id=policy.id, name=policy.name, description=policy.description,
        version=policy.version, effect=policy.effect, priority=policy.priority,
        enabled=policy.enabled, subjects=policy.subjects or [],
        resources=policy.resources or [], actions=policy.actions or [],
        conditions=[], created_at=policy.created_at,
        updated_at=policy.updated_at, created_by=policy.created_by,
    )


@router.put("/{policy_id}", response_model=PolicyResponse)
async def update_policy(
    policy_id: UUID,
    policy_in: PolicyUpdate,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_current_admin_user),
    redis_client: redis.Redis = Depends(get_redis),
):
    """更新策略（自动版本 +1，同步清理缓存）"""
    result = await db.execute(
        select(ABACPolicy).where(ABACPolicy.id == policy_id)
    )
    policy = result.scalar_one_or_none()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")

    # 更新字段
    update_data = policy_in.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        if field == "subjects" and value is not None:
            setattr(policy, field, [v.model_dump() if hasattr(v, "model_dump") else v for v in value])
        elif field == "resources" and value is not None:
            setattr(policy, field, [v.model_dump() if hasattr(v, "model_dump") else v for v in value])
        elif field == "actions" and value is not None:
            setattr(policy, field, value)
        else:
            setattr(policy, field, value)

    policy.version += 1

    # 重建条件（删除旧 + 插入新）
    if policy_in.conditions is not None:
        await db.execute(
            delete(ABACPolicyCondition).where(ABACPolicyCondition.policy_id == policy_id)
        )
        for idx, cond in enumerate(policy_in.conditions):
            _create_condition(db, policy.id, cond, idx)

    # 版本快照
    await _create_version_snapshot(db, policy, admin.username, "Policy updated")

    await db.commit()
    await db.refresh(policy)

    # 缓存失效（三个 key）
    await PolicyCache.invalidate(redis_client, policy.id)

    return PolicyResponse(
        id=policy.id, name=policy.name, description=policy.description,
        version=policy.version, effect=policy.effect, priority=policy.priority,
        enabled=policy.enabled, subjects=policy.subjects or [],
        resources=policy.resources or [], actions=policy.actions or [],
        conditions=[], created_at=policy.created_at,
        updated_at=policy.updated_at, created_by=policy.created_by,
    )


@router.delete("/{policy_id}", status_code=204)
async def delete_policy(
    policy_id: UUID,
    db: AsyncSession = Depends(get_db),
    redis_client: redis.Redis = Depends(get_redis),
):
    """删除策略（同步清理缓存）"""
    result = await db.execute(
        select(ABACPolicy).where(ABACPolicy.id == policy_id)
    )
    policy = result.scalar_one_or_none()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")

    await db.delete(policy)
    await db.commit()

    # 缓存失效（三个 key）
    await PolicyCache.invalidate(redis_client, policy_id)


# ─── Helpers ───────────────────────────────────────────────────────────────────

def _create_condition(db: AsyncSession, policy_id: UUID, cond: ConditionExpression, position: int, max_depth: int = 50, _depth: int = 0):
    """
    递归创建条件，带深度限制防止栈溢出。

    Args:
        max_depth: 最大递归深度（默认 50），超出则抛出 ValueError
        _depth:   内部递归计数，无需外部传入
    """
    if _depth > max_depth:
        raise ValueError(f"Condition tree exceeds max_depth={max_depth} (possible circular reference or excessive nesting)")

    condition = ABACPolicyCondition(
        policy_id=policy_id,
        condition_type=cond.type,
        attribute_path=cond.attribute,
        operator=cond.operator,
        value=cond.value,
        extra=cond.extra,
        position=position,
    )
    db.add(condition)
    db.flush()

    if cond.type in ("and", "or", "not") and cond.conditions:
        for idx, sub in enumerate(cond.conditions):
            _create_condition(db, policy_id, sub, idx, max_depth=max_depth, _depth=_depth + 1)


async def _create_version_snapshot(db: AsyncSession, policy: ABACPolicy, changed_by: str, summary: str):
    """创建策略版本快照"""
    from sqlalchemy import select

    result = await db.execute(
        select(ABACPolicyCondition).where(ABACPolicyCondition.policy_id == policy.id)
    )
    conditions = result.scalars().all()

    snapshot = {
        "name": policy.name,
        "description": policy.description,
        "effect": policy.effect,
        "priority": policy.priority,
        "subjects": policy.subjects,
        "resources": policy.resources,
        "actions": policy.actions,
        "conditions": [
            {
                "type": c.condition_type,
                "attribute": c.attribute_path,
                "operator": c.operator,
                "value": c.value,
                "extra": c.extra,
            }
            for c in conditions
        ],
    }

    version = ABACPolicyVersion(
        policy_id=policy.id,
        version=policy.version,
        snapshot=snapshot,
        changed_by=changed_by,
        change_summary=summary,
    )
    db.add(version)


### 6.3 策略评估测试 API

```python
# POST /admin/v1/abac/policies/evaluate

class EvaluateRequest(BaseModel):
    user_id: UUID
    action: str = Field(..., example="write")
    resource_type: str = Field(..., example="document")
    resource_id: UUID | None = None
    resource_attrs: dict[str, Any] = Field(default_factory=dict)
    context: dict[str, Any] = Field(default_factory=dict)


class EvaluateResponse(BaseModel):
    decision: str          # "allow" | "deny"
    matched_policy: str | None
    reason: str
    evaluation_time_ms: float


@router.post("/evaluate", response_model=EvaluateResponse)
async def evaluate_policy(
    request: EvaluateRequest,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_current_admin_user),
):
    """
    手动测试策略评估（供管理员调试）。

    示例请求：
    ```json
    {
      "user_id": "550e8400-e29b-41d4-a716-446655440000",
      "action": "read",
      "resource_type": "document",
      "resource_attrs": {
        "owner": "user:42",
        "sensitivity": 3
      },
      "context": {
        "ip": "10.0.1.50",
        "device_type": "trusted_laptop"
      }
    }
    ```
    """
    from app.abac.engine import ABACEngine, AccessRequest
    import time

    redis_client = await redis.get_redis()
    engine = ABACEngine(db=db, redis_client=redis_client)

    access_req = AccessRequest(
        user_id=request.user_id,
        action=request.action,
        resource_type=request.resource_type,
        resource_id=request.resource_id,
        resource_attrs=request.resource_attrs,
        context=request.context,
    )

    # 使用带超时的评估入口
    result = await engine.evaluate_with_timeout(access_req)

    return EvaluateResponse(
        decision=result.decision,
        matched_policy=str(result.matched_policy) if result.matched_policy else None,
        reason=result.reason,
        evaluation_time_ms=result.evaluation_time_ms,
    )
```

### 6.4 审计日志 API

```python
# GET /admin/v1/abac/policies/{policy_id}/audit

class PolicyAuditEntry(BaseModel):
    version: int
    changed_by: str
    changed_at: str
    change_summary: str | None
    snapshot: dict


@router.get("/{policy_id}/audit", response_model=list[PolicyAuditEntry])
async def get_policy_audit(
    policy_id: UUID,
    limit: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    """获取策略变更审计日志"""
    result = await db.execute(
        select(ABACPolicyVersion)
        .where(ABACPolicyVersion.policy_id == policy_id)
        .order_by(ABACPolicyVersion.version.desc())
        .limit(limit)
    )
    versions = result.scalars().all()

    return [
        PolicyAuditEntry(
            version=v.version,
            changed_by=v.changed_by,
            changed_at=v.changed_at.isoformat(),
            change_summary=v.change_summary,
            snapshot=v.snapshot,
        )
        for v in versions
    ]
```

---

## 7. 属性定义 API

```python
# app/api/v1/abac/attributes.py

router = APIRouter(prefix="/admin/v1/abac/attributes", tags=["ABAC Attributes"])


class AttributeCreate(BaseModel):
    name: str = Field(..., max_length=64)
    category: Literal["SUBJECT", "RESOURCE", "ENVIRONMENT"]
    data_type: Literal["string", "integer", "boolean", "list", "ip", "time"]
    description: str | None = None
    default_value: Any | None = None
    validation_rule: dict | None = None
    allowed_values: list | None = None


class AttributeResponse(BaseModel):
    id: UUID
    name: str
    category: str
    data_type: str
    description: str | None
    default_value: Any | None
    validation_rule: dict | None
    allowed_values: list | None
    enabled: bool
    created_at: str
    updated_at: str

    class Config:
        from_attributes = True


@router.get("/", response_model=list[AttributeResponse])
async def list_attributes(
    category: str | None = None,
    enabled: bool | None = None,
    db: AsyncSession = Depends(get_db),
):
    """列出属性定义"""
    query = select(ABACPolicyAttribute)
    if category:
        query = query.where(ABACPolicyAttribute.category == category)
    if enabled is not None:
        query = query.where(ABACPolicyAttribute.enabled == enabled)

    result = await db.execute(query.order_by(ABACPolicyAttribute.name))
    attrs = result.scalars().all()

    return [
        AttributeResponse(
            id=a.id, name=a.name, category=a.category, data_type=a.data_type,
            description=a.description, default_value=a.default_value,
            validation_rule=a.validation_rule, allowed_values=a.allowed_values,
            enabled=a.enabled, created_at=a.created_at.isoformat(),
            updated_at=a.updated_at.isoformat(),
        )
        for a in attrs
    ]


@router.post("/", response_model=AttributeResponse, status_code=201)
async def create_attribute(
    attr_in: AttributeCreate,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_current_admin_user),
):
    """创建属性定义"""
    attr = ABACPolicyAttribute(
        name=attr_in.name,
        category=attr_in.category,
        data_type=attr_in.data_type,
        description=attr_in.description,
        default_value=attr_in.default_value,
        validation_rule=attr_in.validation_rule,
        allowed_values=attr_in.allowed_values,
    )
    db.add(attr)
    await db.commit()
    await db.refresh(attr)

    return AttributeResponse(
        id=attr.id, name=attr.name, category=attr.category, data_type=attr.data_type,
        description=attr.description, default_value=attr.default_value,
        validation_rule=attr.validation_rule, allowed_values=attr.allowed_values,
        enabled=attr.enabled, created_at=attr.created_at.isoformat(),
        updated_at=attr.updated_at.isoformat(),
    )
```

---

## 8. 用户属性 API

```python
# app/api/v1/abac/user_attributes.py

router = APIRouter(prefix="/admin/v1/abac/user-attributes", tags=["ABAC User Attributes"])


class UserAttributeUpdate(BaseModel):
    attributes: dict[str, Any]  # {"department": "engineering", "clearance_level": 3}


@router.get("/{user_id}", response_model=dict[str, Any])
async def get_user_attributes(
    user_id: UUID,
    db: AsyncSession = Depends(get_db),
    redis_client: redis.Redis = Depends(get_redis),
):
    """获取用户 ABAC 属性（优先 Redis 缓存）"""
    cache_key = f"abac:user_attrs:{user_id}"
    cached = await redis_client.get(cache_key)
    if cached:
        return json.loads(cached)

    result = await db.execute(
        select(ABACUserAttribute).where(ABACUserAttribute.user_id == user_id)
    )
    rows = result.scalars().all()

    attrs = {row.attr_name: row.attr_value for row in rows}

    await redis_client.setex(cache_key, 300, json.dumps(attrs))

    return attrs


@router.put("/{user_id}")
async def update_user_attributes(
    user_id: UUID,
    update: UserAttributeUpdate,
    db: AsyncSession = Depends(get_db),
    redis_client: redis.Redis = Depends(get_redis),
):
    """更新用户 ABAC 属性"""
    for attr_name, attr_value in update.attributes.items():
        result = await db.execute(
            select(ABACUserAttribute).where(
                and_(
                    ABACUserAttribute.user_id == user_id,
                    ABACUserAttribute.attr_name == attr_name,
                )
            )
        )
        existing = result.scalar_one_or_none()

        if existing:
            existing.attr_value = attr_value
            existing.cached_at = datetime.now()
        else:
            db.add(ABACUserAttribute(
                user_id=user_id,
                attr_name=attr_name,
                attr_value=attr_value,
            ))

    await db.commit()

    # 缓存失效
    cache_key = f"abac:user_attrs:{user_id}"
    await redis_client.delete(cache_key)

    return {"status": "ok"}


@router.delete("/{user_id}/{attr_name}", status_code=204)
async def delete_user_attribute(
    user_id: UUID,
    attr_name: str,
    db: AsyncSession = Depends(get_db),
    redis_client: redis.Redis = Depends(get_redis),
):
    """删除用户单个属性"""
    await db.execute(
        delete(ABACUserAttribute).where(
            and_(
                ABACUserAttribute.user_id == user_id,
                ABACUserAttribute.attr_name == attr_name,
            )
        )
    )
    await db.commit()

    cache_key = f"abac:user_attrs:{user_id}"
    await redis_client.delete(cache_key)
```

---

## 9. SQLAlchemy 模型

```python
# app/models/abac.py

from datetime import datetime
from uuid import UUID, uuid4
from sqlalchemy import (
    Column, String, Integer, Boolean, DateTime, ForeignKey,
    UniqueConstraint, JSON, Index
)
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import relationship, declarative_base

Base = declarative_base()


class ABACPolicyAttribute(Base):
    """ABAC 属性类型定义"""
    __tablename__ = "abac_policy_attributes"

    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    name = Column(String(64), nullable=False, unique=True)
    category = Column(String(32), nullable=False)  # SUBJECT, RESOURCE, ENVIRONMENT
    data_type = Column(String(32), nullable=False)
    description = Column(String, nullable=True)
    default_value = Column(JSON, nullable=True)
    validation_rule = Column(JSON, nullable=True)
    allowed_values = Column(JSON, nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    enabled = Column(Boolean, nullable=False, default=True)


class ABACPolicy(Base):
    """ABAC 策略定义"""
    __tablename__ = "abac_policies"

    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    name = Column(String(128), nullable=False, unique=True)
    description = Column(String, nullable=True)
    version = Column(Integer, nullable=False, default=1)
    effect = Column(String(16), nullable=False)  # allow, deny
    priority = Column(Integer, nullable=False, default=100)
    enabled = Column(Boolean, nullable=False, default=True)

    subjects = Column(JSON, nullable=False, default=list)
    resources = Column(JSON, nullable=False, default=list)
    actions = Column(JSON, nullable=False, default=list)

    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = Column(String(128), nullable=False)

    conditions = relationship(
        "ABACPolicyCondition",
        back_populates="policy",
        cascade="all, delete-orphan",
        order_by="ABACPolicyCondition.position",
    )
    versions = relationship(
        "ABACPolicyVersion",
        back_populates="policy",
        cascade="all, delete-orphan",
    )


class ABACPolicyCondition(Base):
    """ABAC 策略条件表达式"""
    __tablename__ = "abac_policy_conditions"

    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    policy_id = Column(PG_UUID(as_uuid=True), ForeignKey("abac_policies.id", ondelete="CASCADE"), nullable=False)
    condition_type = Column(String(32), nullable=False)
    attribute_path = Column(String(128), nullable=True)
    operator = Column(String(16), nullable=True)
    value = Column(JSON, nullable=True)
    extra = Column(JSON, nullable=True)
    position = Column(Integer, nullable=False, default=0)

    policy = relationship("ABACPolicy", back_populates="conditions")


class ABACUserAttribute(Base):
    """用户 ABAC 属性缓存"""
    __tablename__ = "abac_user_attributes"

    user_id = Column(PG_UUID(as_uuid=True), ForeignKey("auth_users.id", ondelete="CASCADE"), primary_key=True)
    attr_name = Column(String(64), primary_key=True)
    attr_value = Column(JSON, nullable=False)
    cached_at = Column(DateTime, nullable=False, default=datetime.utcnow)


class ABACPolicyVersion(Base):
    """策略版本历史记录"""
    __tablename__ = "abac_policy_versions"

    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    policy_id = Column(PG_UUID(as_uuid=True), ForeignKey("abac_policies.id", ondelete="CASCADE"), nullable=False)
    version = Column(Integer, nullable=False)
    snapshot = Column(JSON, nullable=False)
    changed_by = Column(String(128), nullable=False)
    changed_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    change_summary = Column(String, nullable=True)

    __table_args__ = (
        UniqueConstraint("policy_id", "version"),
    )

    policy = relationship("ABACPolicy", back_populates="versions")
```

---

## 10. 缓存优化

### 10.1 缓存策略

| 缓存项 | Key 格式 | TTL | 说明 |
|--------|----------|-----|------|
| 用户属性 | `abac:user_attrs:{user_id}` | 300s | 用户属性缓存层 |
| 策略列表 | `abac:policies:all` | 60s | 策略列表（按需加载） |
| 单策略缓存 | `abac:policy:{policy_id}` | 300s | 单策略详情缓存 |
| 编译策略 | `abac:compiled:{policy_id}` | 600s | 预编译策略函数 |

### 10.2 热点策略预编译

```python
# app/abac/compiler.py
# 【修复 v4】禁用 pickle/cloudpickle，改用 AST 编译（绝对安全）

import ast
import hashlib
import json
from types import FunctionType
from typing import Callable, Any
from uuid import UUID

from app.abac.engine import AttributeSet


class PolicyCompiler:
    """
    策略预编译器：将条件表达式预编译为可调用函数。

    【修复 v4】禁用 pickle/cloudpickle，改用 AST 编译：
    - pickle/cloudpickle 反序列化可执行任意代码（安全风险）
    - 新方案：Python 源码字符串 → ast.parse() → compile() → FunctionType
    - 生成的函数签名固定为 (attrs: AttributeSet, context: dict) -> bool
    - 所有操作均为白名单内的显式代码构造，无动态 eval/exec
    - 闭包变量通过 default_args 固化（避免构造闭包）
    - 【修复 v4】safe_globals 预注入 re / datetime / ipaddress 模块，禁止动态 __import__
    """

    CACHE_KEY_COMPILED = "abac:compiled:{policy_id}"
    MAX_PATTERN_LEN = 500  # 正则长度上限

    def __init__(self, redis_client):
        self.redis = redis_client

    async def get_compiled(self, policy_id: UUID, condition_tree: dict) -> Callable:
        """
        获取已编译的条件判断函数，优先从缓存加载。
        缓存命中时从 Redis 取回源码字符串，重新编译为函数（而非反序列化对象）。
        """
        cache_key = self.CACHE_KEY_COMPILED.format(policy_id=str(policy_id))
        cached_source = await self.redis.get(cache_key)

        if cached_source:
            source_code = cached_source.decode("utf-8") if isinstance(cached_source, bytes) else cached_source
            return self._compile_source(source_code)

        source_code = self._generate_source(condition_tree)
        await self.redis.setex(cache_key, 600, source_code.encode("utf-8"))

        return self._compile_source(source_code)

    def _compile_source(self, source_code: str) -> Callable:
        """
        【修复 v4】将源码字符串编译为可调用函数。
        safe_globals 预注入模块（禁止动态 __import__）：
        - re, datetime, ipaddress 作为白名单模块直接可用
        - __builtins__ = {} 完全禁用，无任何内建函数
        """
        try:
            tree = ast.parse(source_code, mode="eval")
        except (SyntaxError, ValueError):
            raise ValueError(f"Invalid AST source: {source_code!r}")

        if not isinstance(tree, ast.Expression):
            raise ValueError("Source must be a single ast.Expression")

        code = compile(tree, filename="<policy_compiler>", mode="eval")

        # 【修复 v4】预注入模块，禁止动态 __import__
        import re as _re_module
        import datetime as _datetime_module
        import ipaddress as _ipaddress_module

        safe_globals = {
            "__builtins__": {},  # 完全禁用内建函数
            "True": True,
            "False": False,
            "None": None,
            "str": str,
            "int": int,
            "float": float,
            "bool": bool,
            "list": list,
            "dict": dict,
            "tuple": tuple,
            "set": set,
            "frozenset": frozenset,
            # 【修复 v4】预注入模块，禁止动态 __import__
            "re": _re_module,
            "datetime": _datetime_module,
            "ipaddress": _ipaddress_module,
            "len": len,
            "isinstance": isinstance,
            "getattr": getattr,
        }

        return lambda attrs, context: eval(code, safe_globals, {"attrs": attrs, "context": context})

    def _generate_source(self, tree: dict) -> str:
        """【修复 v4】将条件树生成为 Python 源码字符串"""
        return self._gen_node(tree)

    def _gen_node(self, node: dict, depth: int = 0) -> str:
        """将条件树生成为 Python 源码字符串"""
        if depth > 200:
            return "False"
        ctype = node.get("type")

        if ctype == "simple":
            attr = node["attribute"]
            op = node["operator"]
            value = self._gen_literal(node["value"])

            if op in ("==", "!=", ">", ">=", "<", "<="):
                return f"(attrs.get({repr(attr)}) {op} {value})"
            elif op == "in":
                return f"(attrs.get({repr(attr)}) in {value})"
            elif op == "not_in":
                return f"(attrs.get({repr(attr)}) not in {value})"
            elif op == "contains":
                return f"(isinstance(attrs.get({repr(attr)}), str) and {value} in attrs.get({repr(attr)}))"
            elif op == "starts_with":
                return f"(isinstance(attrs.get({repr(attr)}), str) and attrs.get({repr(attr)}).startswith({value}))"
            elif op == "regex":
                pat = node["value"]
                if not isinstance(pat, str) or len(pat) > self.MAX_PATTERN_LEN:
                    return "False"
                # 【修复 v4】使用预注入的 re 模块，不使用 __import__
                return (
                    f"(isinstance(attrs.get({repr(attr)}), str) and "
                    f"re.match({repr(pat)}, attrs.get({repr(attr)})) is not None)"
                )

        elif ctype == "time_range":
            attr = node["attribute"]
            extra = node.get("extra", {})
            start = extra.get("start", 0)
            end = extra.get("end", 23)
            days = extra.get("days", [])

            hour_check = f"(({start} <= attrs.get({repr(attr)})) and (attrs.get({repr(attr)}) <= {end}))"
            if days:
                # 【修复 v4】使用预注入的 datetime 模块
                day_check = (
                    f"(context.get('now', datetime.datetime.now()).strftime('%A') in {repr(days)})"
                )
                return f"({hour_check} and {day_check})"
            return hour_check

        elif ctype == "ip_range":
            attr = node["attribute"]
            cidr = node.get("extra", {}).get("cidr", "")
            # 【修复 v4】使用预注入的 ipaddress 模块
            return (
                f"(ipaddress.ip_address(attrs.get({repr(attr)})) in "
                f"ipaddress.ip_network({repr(cidr)}, strict=False))"
            )

        elif ctype == "and":
            subs = " and ".join(f"({self._gen_node(sub, depth+1)})" for sub in node.get("conditions", []))
            return subs if subs else "True"

        elif ctype == "or":
            subs = " or ".join(f"({self._gen_node(sub, depth+1)})" for sub in node.get("conditions", []))
            return subs if subs else "False"

        elif ctype == "not":
            subs = node.get("conditions", [])
            if subs:
                return f"(not ({self._gen_node(subs[0], depth+1)}))"
            return "True"

        return "False"

    def _gen_literal(self, value: Any) -> str:
        """将 Python 值生成为字面量字符串"""
        if isinstance(value, str):
            return repr(value)
        elif isinstance(value, bool):
            return "True" if value else "False"
        elif isinstance(value, (int, float)):
            return str(value)
        elif isinstance(value, (list, tuple)):
            items = ", ".join(self._gen_literal(v) for v in value)
            bracket = "[" if isinstance(value, list) else "("
            close = "]" if isinstance(value, list) else ")"
            return f"{bracket}{items}{close}"
        elif isinstance(value, dict):
            items = ", ".join(f"{repr(k)}: {self._gen_literal(v)}" for k, v in value.items())
            return f"{{{items}}}"
        elif value is None:
            return "None"
        return repr(value)


def invalidate_policy_cache(policy_id: UUID):
    """策略变更后自动清理相关缓存的装饰器"""
    async def decorator(func):
        async def wrapper(*args, **kwargs):
            result = await func(*args, **kwargs)
            redis_client = kwargs.get("redis_client")
            if redis_client and policy_id:
                await PolicyCache.invalidate(redis_client, policy_id)
            return result
        return wrapper
    return decorator

---

## 11. 策略示例

### 11.1 示例1：部门敏感文档访问控制

> 只有同部门成员或高 clearance 用户才能访问敏感文档

```json
{
  "name": "department-sensitive-document-access",
  "effect": "allow",
  "priority": 10,
  "resources": [{"attr": "type", "op": "==", "value": "document"}],
  "actions": ["read"],
  "conditions": [
    {
      "type": "or",
      "conditions": [
        {
          "type": "and",
          "conditions": [
            {"type": "simple", "attribute": "user.department", "operator": "==", "value": "resource.owner.department"},
            {"type": "simple", "attribute": "user.clearance_level", "operator": ">=", "value": 2}
          ]
        },
        {
          "type": "simple",
          "attribute": "user.clearance_level",
          "operator": ">=",
          "value": 4
        }
      ]
    }
  ]
}
```

### 11.2 示例2：核心系统工作时间访问限制

> 核心系统只允许在工作时间（9-18点），工作日，办公网络访问

```json
{
  "name": "core-system-work-hours-access",
  "effect": "allow",
  "priority": 5,
  "resources": [{"attr": "type", "op": "==", "value": "core-system"}],
  "actions": ["read", "write"],
  "conditions": [
    {
      "type": "time_range",
      "attribute": "env.time.hour",
      "start": 9,
      "end": 18,
      "days": ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]
    },
    {
      "type": "ip_range",
      "attribute": "env.ip",
      "cidr": "10.0.0.0/8"
    }
  ]
}
```

### 11.3 示例3：高敏感数据防泄露

> 高敏感（sensitivity >= 5）数据禁止从外部网络或未知设备访问

```json
{
  "name": "executive-data-device-restriction",
  "effect": "deny",
  "priority": 1,
  "resources": [{"attr": "sensitivity", "op": ">=", "value": 5}],
  "actions": ["read", "write", "download"],
  "conditions": [
    {
      "type": "or",
      "conditions": [
        {"type": "simple", "attribute": "env.device_type", "operator": "==", "value": "unknown"},
        {"type": "simple", "attribute": "env.network_zone", "operator": "==", "value": "external"}
      ]
    }
  ]
}
```

---

## 12. 实现计划

### Phase 2-2A：核心引擎（预计 3 周）

- [ ] 数据库表设计和 migration
- [ ] SQLAlchemy 模型定义
- [ ] ABACEngine 核心评估逻辑（含 deny-override）
- [ ] 条件表达式求值器（含类型校验 + ReDoS 保护）
- [ ] Redis 用户属性缓存
- [ ] 单元测试

### Phase 2-2B：API 层（预计 2 周）

- [ ] 策略 CRUD API（含缓存失效）
- [ ] 属性定义 API
- [ ] 用户属性 API
- [ ] 策略评估测试 API
- [ ] 审计日志 API

### Phase 2-2C：RBAC 集成（预计 2 周）

- [ ] 扩展 `require_permission` 装饰器
- [ ] 集成测试
- [ ] 性能基准测试

### Phase 2-2D：缓存优化（预计 1 周）

- [ ] 热点策略预编译（AST 编译，禁用 pickle）
- [ ] 策略列表缓存
- [ ] 压测评估延迟

---

## 附录 A：配置项

```yaml
# config.yaml

abac:
  evaluation_timeout_ms: 100      # 评估超时（毫秒）
  user_attr_cache_ttl: 300         # 用户属性缓存 TTL（秒）
  policy_cache_ttl: 60             # 策略列表缓存 TTL（秒）
  compiled_cache_ttl: 600          # 编译策略缓存 TTL（秒）
  default_combination_algo: "deny-override"  # 默认决策合成算法
  default_decision: "deny"         # 无匹配策略时默认拒绝
  regex_timeout_sec: 0.1           # 【修复 v4】正则匹配超时（秒）
```

## 附录 B：错误码

| HTTP 状态码 | 错误码 | 说明 |
|------------|--------|------|
| 400 | `POLICY_NAME_EXISTS` | 策略名称已存在 |
| 400 | `INVALID_CONDITION` | 无效的条件表达式 |
| 400 | `INVALID_ATTRIBUTE` | 无效的属性路径或操作符 |
| 404 | `POLICY_NOT_FOUND` | 策略不存在 |
| 404 | `USER_NOT_FOUND` | 用户不存在 |
| 429 | `EVALUATION_TIMEOUT` | 评估超时（100ms 硬超时触发） |

## 附录 C：集成系统接入步骤

1. **User Model**：添加 `abac_attributes` 关系，关联 `ABACUserAttribute`
2. **Resource Model**：添加 `get_abac_attributes()` 方法，提取资源属性
3. **AuthMiddleware**：权限检查链路中注册 ABAC 引擎
4. **AuditLog**：ABAC 决策写入结构化审计日志
5. **Notification**：高频 deny 触发安全告警通知
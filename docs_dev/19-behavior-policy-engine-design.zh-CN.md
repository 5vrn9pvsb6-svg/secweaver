# behavior-policy 声明式引擎设计

**语言：** [English](19-behavior-policy-engine-design.md) | 简体中文（本文）

> 文档版本 v1.1 | 按当前代码核对：2026-09-21
> 目标：消除 risk-identification **策略层 CLI/Agent 双轨**，运营改 JSON + MD 即可，`assess.py` 不再依赖 `behavior_policy.py` 内手写 evaluator。

## 1. 改造前的问题

| 路径 | 策略来源 | 痛点 |
|------|----------|------|
| **Agent** | `behavior-policy.md` 自然语言 | 运营改 MD 即生效 |
| **CLI / CI** | `behavior_policy.py` ~865 行 Python 镜像 | 每增 `OPS-*` 规则需工程同步 regex/evaluator |

以上是改造前的状态。当前 CLI 已由 `policy_engine.py` 解释 JSON 策略；`behavior_policy.py` 保留裁决数据结构和应用编排，不再要求为每条 OPS 规则编写 Python evaluator。

## 2. 方案概览

```text
behavior-policy.md          ← 自然语言权威（Agent、审计、修订记录）
behavior-policy.rules.json  ← 机器可读规则（CLI/CI 单一事实来源）
policy_engine.py            ← 通用解释器（一次性平台代码）
behavior_policy.py          ← 谓词 helper + PolicyDecision + apply 编排（逐步瘦身）
```

**v1 已落地：**

- Schema：`src/skills/risk-identification/schema/behavior-policy-rules.schema.json`
- 规则包：`rules/behavior-policy.rules.json`（迁移现有 21 条 OPS/WEB/SYS + 5 条硬护栏）
- 引擎：`scripts/policy_engine.py`
- `evaluate_item()` 委托引擎；`test_policy_engine.py` + 扩展 `test_policy_sync.py`

## 3. 规则包结构

结构示例，仅展示一条规则；不含完整默认行为、硬护栏和其他策略，不能直接替换默认规则包。

```json
{
  "version": "1.0.0",
  "policy_id": "example-ssh-policy",
  "default_behavior": {
    "rules": []
  },
  "rules": [
    {
      "id": "SSH-BRUTE-001",
      "tier": "force_alert",
      "modules": [
        "ssh"
      ],
      "when": {
        "matched_rules_any": [
          "ssh_bruteforce"
        ]
      },
      "decision": {
        "severity": "P0",
        "alert_required": true,
        "alert_suppressed": false,
        "verdict": "confirmed_attack",
        "recommended_action": "block_src_ip_and_investigate",
        "reason": "SSH 认证短时间大量失败，符合暴力破解"
      }
    }
  ]
}
```

### 3.1 tier 与 precedence（与 MD 一致）

裁决顺序不变：

```text
hard_guardrail → force_alert → downgrade → default
```

`pick_best_decision()` 逻辑仍在 `behavior_policy.py`（force 优先于 downgrade；硬护栏阻止降级）。

### 3.2 when 条件类型（v1）

| 类型 | 示例 |
|------|------|
| `all` / `any` / `not` | 组合逻辑 |
| `risk_module` | `"exec"` / `["exec","connect"]` |
| `matched_rules_any` / `_all` | 检测层标签 |
| `command_regex` / `command_contains` | 命令文本 |
| `event_type` | syslog 事件类型 |
| `predicate` | 复用引擎内置谓词（见下） |
| `dst_port_in` / `dst_ip_in` | connect 模块 |
| `severity_in` | 默认行为分支 |
| `type: guardrail_matched` | 第二节 matched_rules 硬护栏 |

### 3.3 predicate 注册表（v2 — JSON 可编辑）

复合谓词已全部迁入 **`behavior-policy.rules.json` → `predicates`**，由 `shared_conditions.py` 求值；**不再**在 Python 内置注册表维护。

| predicate | 含义 |
|-----------|------|
| `is_web_entry` | Web 监听进程或 80/443/8080/8443 |
| `is_sshd_session` | sshd:22 |
| `is_shell_command` | exec shell / external_listener_shell_exec |
| `is_agent_sshd_monitor` | sshd -D 监控子进程 |
| `is_lab_setup` / `is_lab_setup_syslog` | 演练降噪 |
| `is_agent_uninstall` | agent systemd 卸载 |
| `is_sshd_webshell_abuse` | sshd + s.phtml curl |
| `is_trusted_deploy` / `is_cloud_ops` / `is_local_curl` | 部署/云 metadata/本地 curl |

新增 OPS 规则时：**优先改 predicates + regex**；全新条件**类型**（非组合）才扩 `shared_conditions.py`（一次性工程）。

connect / syslog 检测层 **`when_extensions`**：在 `connect-rules.json` / `syslog-rules.json` 注册自定义 `when` 键，插件化扩展，免改 `_when_matches` 分支。

### 3.4 decision 扩展

- `severity_when[]`：按条件动态 severity（如 RECON-HIGH-001 shadow→P0）
- `inherit_severity` / `inherit_verdict`：硬护栏保留检测层初判
- `id_template`：`HARD-GUARDRAIL-{matched_rule}`

## 4. 运营工作流（v1 之后）

### 4.1 新增降噪规则 OPS-FOO-001

1. 在 `behavior-policy.md` 第四节写自然语言（审计 / Agent）
2. 在 `rules/behavior-policy.rules.json` 追加同级 JSON 规则（CLI）
3. 跑测试：`.venv/bin/python -m unittest discover -s src/skills/risk-identification/tests -p 'test_policy*.py'`
4. **无需**改 `behavior_policy.py` 内 `_downgrade_*` 函数

### 4.2 临时关闭规则

```json
{ "id": "OPS-SSH-001", "enabled": false, ... }
```

### 4.3 环境专用策略包

已支持自定义策略包。离线输入使用以下 `behavior_policy` 字段，CLI 对应 `--behavior-policy` 与 `--behavior-policy-rules`：

```json
{
  "behavior_policy": {
    "path": "behavior-policy.lab.md",
    "rules_path": "rules/behavior-policy.lab.rules.json"
  }
}
```

## 5. 与 trace_profile 对比

| | trace_profile | policy_engine |
|--|---------------|---------------|
| 配置 | `dataasset/trace-profiles/*.json` | `rules/behavior-policy.rules.json` |
| 权威文档 | asset + 设计 doc | `behavior-policy.md` |
| 引擎 | `_shared/data-access/trace_profile.py` | `policy_engine.py` |
| 目标 | L0 日志语义 | L1 告警/降噪 |

## 6. 仍未配置化（边界）

| 项 | 说明 |
|----|------|
| 检测层引擎 | `exec_rules.py` 等（pattern 在 JSON，算法在 Python） |
| connect/syslog 计算型 when | `web_context` 等需引擎注入 ctx；其余 via `when_extensions` |
| 新 condition **类型** | 需扩 `shared_conditions.py` + schema |
| assess 编排 | 过滤、去重、top_incidents |
| `source_risk_map.py` | 数据源覆盖与缺口评估；场景→module 默认值由 `scenarios.json` 定义 |
| 独立纯提示词试验 | 可由智能体解释 MD，但须标注为独立试验；默认 Skill/CLI 调用 assess.py 使用 JSON |

**不是目标：** 把 `behavior-policy.md` 删掉。MD 保留自然语言、修订记录、复杂语义说明；JSON 服务确定性执行。

## 7. 工作量评估

| 阶段 | 内容 | 状态 | 估时 |
|------|------|------|------|
| **P0** | schema + 规则包 + engine + 委托 evaluate_item | ✅ | ~1–2 人日 |
| **P1** | `behavior_policy.rules_path` payload/CLI；文档更新；删除 Python 镜像死代码 | ✅ | ~1 人日 |
| **P2** | `validate_policy_sync.py` + CI/Makefile；JSON `predicates` 插件 | ✅ | ~1 人日 |
| **P3** | `md_to_policy_rules.py` MD→JSON 草稿生成 | ✅ | ~0.5 人日 |

现有条件能表达的新策略可通过 JSON + Markdown 维护；全新 condition 类型或计算上下文仍需修改引擎。这里不以未经持续统计的百分比描述覆盖程度。

## 8. 验证

```bash
make validate-policy
.venv/bin/python -m unittest discover -s src/skills/risk-identification/tests -p 'test_policy*.py' -v
.venv/bin/python src/skills/risk-identification/scripts/md_to_policy_rules.py --id OPS-SSH-001
```

## 9. 相关文档

- [OPS-HANDBOOK.zh-CN.md](../src/skills/risk-identification/OPS-HANDBOOK.zh-CN.md) CLI 与智能体执行路径（JSON 为 CLI 策略源）
- [DESIGN.zh-CN.md](../src/skills/risk-identification/DESIGN.zh-CN.md) §7 执行路径
- [trace-profile-design.zh-CN.md](21-trace-profile-design.zh-CN.md)


## 策略编写实例

策略回答：**检测已命中（或未命中）时，要不要告警、最终 severity 是多少。**

### 推荐四步流程

```text
1. behavior-policy.md     写自然语言（Agent 权威、审计）
2. behavior-policy.rules.json   写 when + decision（CLI 执行）
3. 如需复用条件 → predicates 块
4. make validate-policy   校验 MD ↔ JSON ID 一致
```

**策略规则最小结构：**

```json
{
  "id": "MY-RULE-001",
  "tier": "force_alert",
  "modules": ["exec"],
  "when": { "matched_rules_any": ["crypto_miner"] },
  "decision": {
    "severity": "P0",
    "alert_required": true,
    "alert_suppressed": false,
    "verdict": "confirmed_attack",
    "recommended_action": "isolate_host_and_investigate",
    "reason": "Web 入口挖矿，必须处置"
  }
}
```

| 字段 | 说明 |
|------|------|
| `id` | 全局唯一，= 输出 `policy_rule_id` |
| `tier` | `hard_guardrail` / `force_alert` / `downgrade` |
| `modules` | 限定 `exec` / `connect` / `dns` / `persistence` / `ssh` / `syslog` |
| `when` | 命中条件（DSL，与检测层共用 `shared_conditions`） |
| `unless` | 命中 when 但 **排除** 的子条件（数组） |
| `decision` | 最终 severity、告警开关、reason |

---

### predicates — 可复用复合条件

把多处用到的条件抽成谓词，**运营可直接编辑 JSON**，无需改 Python。

**示例：Web 入口判定**

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

**示例：引用检测产出 + 模块**

```json
"is_shell_command": {
  "all": [
    { "risk_module": "exec" },
    {
      "any": [
        { "matched_rules_any": ["external_listener_shell_exec"] },
        { "type": "shell_exe" }
      ]
    }
  ]
}
```

**在规则中引用：** `{ "predicate": "is_web_entry" }`

**新增谓词 checklist：**

1. 在 `predicates` 加块
2. 在 `rules[]` 用 `"predicate": "your_name"`
3. 同步在 `behavior-policy.md` 写一句说明
4. `make validate-policy`

---

### 三种 tier 写法对照

#### force_alert — 必须告警（覆盖 downgrade 之前的初判）

**引用检测标签** — `DOWNLOAD-MALICIOUS-001`（仓库真实片段）：

```json
{
  "id": "DOWNLOAD-MALICIOUS-001",
  "tier": "force_alert",
  "modules": ["exec"],
  "when": { "matched_rules_any": ["download_and_execute"] },
  "unless": [
    { "predicate": "is_trusted_deploy" },
    { "predicate": "is_cloud_ops" },
    { "predicate": "is_local_curl" }
  ],
  "decision": {
    "severity": "P0",
    "alert_required": true,
    "alert_suppressed": false,
    "verdict": "confirmed_attack",
    "recommended_action": "isolate_host_and_investigate",
    "reason": "从非可信来源下载并执行远程脚本"
  }
}
```

**引用谓词组合** — `WEB-SHELL-001`：

```json
{
  "id": "WEB-SHELL-001",
  "tier": "force_alert",
  "modules": ["exec"],
  "when": {
    "all": [
      { "predicate": "is_web_entry" },
      { "predicate": "is_shell_command" }
    ]
  },
  "decision": {
    "severity": "P0",
    "alert_required": true,
    "alert_suppressed": false,
    "verdict": "confirmed_attack",
    "recommended_action": "isolate_host_and_investigate",
    "reason": "Web 监听进程后代执行 shell/系统命令，视为 WebShell/RCE"
  }
}
```

#### downgrade — 降噪 / 留痕不告警

**可信部署路径** — `OPS-DEPLOY-001`：

```json
{
  "id": "OPS-DEPLOY-001",
  "tier": "downgrade",
  "modules": ["exec"],
  "when": { "predicate": "is_trusted_deploy" },
  "decision": {
    "severity": "P3",
    "alert_required": false,
    "alert_suppressed": true,
    "verdict": "benign",
    "recommended_action": "log_only",
    "reason": "平台 Agent 官方 portal 部署路径"
  }
}
```

**演练环境** — `OPS-LAB-SETUP-001`（即使检测命中 `persistence_modify` 也可降噪）：

```json
{
  "id": "OPS-LAB-SETUP-001",
  "tier": "downgrade",
  "modules": ["exec"],
  "when": { "predicate": "is_lab_setup" },
  "decision": {
    "severity": "P3",
    "alert_required": false,
    "alert_suppressed": true,
    "verdict": "benign",
    "recommended_action": "log_only",
    "reason": "演练环境预置 devops 账号与诱饵凭据"
  }
}
```

#### hard_guardrail — 禁止被任何降噪覆盖

```json
{
  "id": "HARD-GUARDRAIL-REVERSE-SHELL",
  "tier": "hard_guardrail",
  "when": {
    "command_regex": "/dev/tcp/|bash -i|sh -i|\\bnc -e\\b",
    "flags": "i"
  },
  "decision": {
    "severity": "P0",
    "alert_required": true,
    "alert_suppressed": false,
    "verdict": "confirmed_attack",
    "recommended_action": "isolate_host_and_investigate",
    "reason": "反弹 shell / Getshell 行为，禁止降噪"
  }
}
```

硬护栏可带 `unless`（如 `is_lab_setup`），仅 **明确豁免** 的场景才不强制 P0。

---

### when 条件常用写法

| 类型 | JSON 示例 | 典型用途 |
|------|-----------|---------|
| 检测标签 | `"matched_rules_any": ["download_and_execute"]` | 策略跟随检测 |
| 谓词 | `"predicate": "is_web_entry"` | 跨模块复用 |
| 命令正则 | `"command_regex": "curl.*\\|.*bash", "flags": "i"` | 策略直读 command |
| 端口 | `"dst_port_in": [4444, 1337]` | connect 模块 |
| 模块限定 | `"modules": ["connect"]` | 规则级（顶层字段） |
| 组合 | `"all": [ {...}, {...} ]` / `"any": [ ... ]` | 与/或 |
| 排除 | `"unless": [ { "predicate": "is_trusted_deploy" } ]` | 白名单例外 |

---

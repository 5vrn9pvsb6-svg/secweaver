# 风险识别告警策略 · 运营手册

**语言：** [English overview](DESIGN.md) | 简体中文（本文）

> 给安全运营同学：完整手册见 **[OPS-HANDBOOK.zh-CN.md](OPS-HANDBOOK.zh-CN.md)**。  
> 策略正文：[behavior-policy.md](behavior-policy.md) · 检测 JSON：[rules/](rules/)

---

## 1. 两层架构（必读本节）

```text
检测层（工程）     →  这条日志「像什么攻击」→ matched_rules[]、初判 severity
策略层（运营）     →  「要不要告警」      → behavior-policy.md
溯源层（另一 Skill）→  「攻击链怎么串」    → traceability-analysis
```

| 你想做的事 | 改哪个文件 |
|------------|------------|
| 某类 agent 安装不要告警 | `behavior-policy.md` 第四节 OPS-DEPLOY-001 |
| 演练环境 useradd devops 降噪 | `behavior-policy.md` OPS-LAB-SETUP-001 |
| sshd 里 ls/grep 默认不告警 | `behavior-policy.md` OPS-SSH-001 |
| WebShell 必须 P0 告警 | `behavior-policy.md` WEB-SHELL-001 |
| **新增**检测 pattern（regex/keyword） | **`rules/exec-rules.json`** 等 |
| **新增**全新 matched_rule 语义 | 改 JSON + detection-catalog + 可选 behavior-policy |
| 主机 A→B 横向链、多轮演练解读 | **traceability-analysis**，不在本 Skill |

---

## 2. 配置文件

| 文件 | 谁维护 | 作用 |
|------|--------|------|
| **`behavior-policy.md`** | **运营** | **自然语言权威**告警策略（Agent、审计） |
| **`rules/behavior-policy.rules.json`** | **运营** | **CLI/CI** 策略规则包（与 MD 同步） |
| `detection-catalog.zh-CN.md` | 工程 | 检测标签说明（只读） |
| `whitelist.json` | 环境白名单 | scope 例外（CIDR、exe 前缀）；assess 默认开启 |
| `behavior_policy.py` | 工程 | PolicyDecision 编排；策略逻辑在 JSON + `policy_engine.py` |

可选环境覆盖：从 Skill 目录复制 Markdown 和 JSON 策略，在输入中同时指定路径。仅设置 `path` 不会切换 CLI 执行的规则包。

```json
{
  "behavior_policy": {
    "path": "src/skills/risk-identification/behavior-policy.local.md",
    "rules_path": "src/skills/risk-identification/rules/behavior-policy.local.rules.json"
  }
}
```

---

## 3. 新增一条运营规则（标准流程）

### 3.1 选章节

| 章节 | 何时用 | 规则 ID 前缀示例 |
|------|--------|------------------|
| 二、硬护栏 | 任何情况都不允许降噪 | （内嵌于第二节，无独立 ID） |
| 三、必须告警 | 必须推送 P0/P1 | `WEB-SHELL-*`、`LATERAL-*`、`SSH-IMPACT-*` |
| 四、降噪 | 运维噪声、可信部署 | `OPS-*` |

### 3.2 写规则（模板）

在 `behavior-policy.md` 对应章节追加：

```markdown
### OPS-MY-RULE-001｜短标题（业务语言）

**何时命中**：
- listener 为 sshd:22；
- 命令包含 …（用业务描述，不要写正则）；
- matched_rules 含 xxx（可选，见 detection-catalog）；
- **且未**命中第二节硬护栏 / 第三节必须告警。

**决策**：P3，不告警，verdict=benign。

**反例**：（可选）真实攻击应走 SSH-IMPACT-001。

**示例**：（可选）一条真实 command 摘要。
```

### 3.3 命名规范

- 格式：`类别-描述-序号`，如 `OPS-SSH-001`、`WEB-SHELL-002`
- 必须全局唯一；输出会写入 `policy_rule_id`

### 3.4 提 PR 与验证

1. 同步更新 `behavior-policy.md` 的规则和修订记录，以及 `rules/behavior-policy.rules.json` 的对应规则。
2. PR 附应命中和不应命中的脱敏样例，验证最终等级、告警标记、命中策略 ID 与硬护栏。
3. 从仓库根目录运行 `python3 src/skills/risk-identification/scripts/validate_policy_sync.py --strict` 和相关策略回归测试。
4. 审核合并后，下一次 `assess.py` 调用读取更新的 JSON；只改 MD 不会使默认确定性规则生效。

### 3.5 不要做的事 ❌

- 自然语言理由写在 MD；可执行条件写在 JSON，字段和操作符以 [规则参考](rules/README.zh-CN.md) 为准
- 不要改 `exec_rules.py` 来「不告警某个命令」（应写 OPS 降噪）
- 全平台 OPS 降噪写 **behavior-policy**；按客户/集群的细 scope 例外写 **whitelist.json**

JSON 策略包 1.0.1 的 `HARD-GUARDRAIL-PERSISTENCE` 和 `SSH-IMPACT-001` 账户/持久化
命令分支使用 `type=persistence_write`，与检测层共享写入语义。只读检查、复制到备份
不因路径出现而触发；真实写入、建号、改密继续告警，其他敏感读取分支不变。
后续白名单不能覆盖硬护栏或 force_alert；普通降到 P2/P3 的项目不再告警。
- 不要在本 Skill 写跨主机攻击链叙事

---

## 4. 章节与优先级

| 章节 | 用途 |
|------|------|
| 一、默认 | 无专属规则：P0/P1 告警，P2 观察，P3 留痕 |
| 二、硬护栏 | 反弹 shell、Web 入口 shell、持久化等 **禁止降级** |
| 三、必须告警 | force alert |
| 四、降噪 | suppress / 降为 P3 |
| 五、冲突 | 裁决顺序 |
| 六、输出 | policy_rule_id、policy_reason 等 |
| 七、修订 | 审计 |

**优先级：二 > 三 > 四 > 一**

---

## 5. assess 流水线中的位置

```text
Step 1–4  检测层 → risk_items[]（matched_rules + 初判 severity）
Step 5    去重
Step 6    读取 behavior-policy.rules.json（与 MD 同步）→ alert_required / 最终 severity
Step 7    环境白名单 → MITRE 标注
Step 8    top_incidents 聚合
Step 9    输出结果；需跨主机调查时另行使用 traceability-analysis
```

---

## 6. CLI vs Agent

| 方式 | 策略怎么生效 |
|------|----------------|
| **Cursor Agent / Skill** | 按 Skill 调用 `assess.py` 时使用同一 JSON 引擎；MD 提供说明和审计 |
| **`assess.py` 脚本** | 读 `rules/behavior-policy.rules.json`，每次运行加载；修改须同步 MD 并通过正/负例验证 |

校验 MD↔JSON：`python3 scripts/validate_policy_sync.py --strict`  
草稿生成：`python3 scripts/md_to_policy_rules.py --id OPS-XXX-001`

禁用策略：`--no-behavior-policy` 或 payload `"behavior_policy": {"enabled": false}`

自定义规则包：`"behavior_policy": {"rules_path": "rules/behavior-policy.lab.rules.json"}`

---

## 7. 与检测层分工（FAQ）

| 问题 | 谁回答 |
|------|--------|
| 是不是 download_and_execute？ | 检测层 `exec_rules` |
| portal 装 agent 要不要告警？ | **OPS-DEPLOY-001**（本策略） |
| sshd 里 ls 要不要告警？ | **OPS-SSH-001** |
| sshd 里 useradd backdoor？ | **SSH-IMPACT-001**（必须告警） |
| sshd 里 useradd devops 演练预置？ | **OPS-LAB-SETUP-001**（降噪） |
| 跨主机攻击的完整时间线？ | **traceability-analysis** |

---

## 8. 修订与审计

- 每次改策略 = 改 `behavior-policy.md` + `rules/behavior-policy.rules.json` + 第七节一行记录
- 输出字段 `policy_rule_id` + `policy_reason` 便于复盘
- Code Review：运营可读 Markdown，无需懂 Python

---

## 9. 后续规划（非阻塞）

- `behavior-policy.prod.md` / `.lab.md` 环境分叉（已支持 `rules_path` payload）
- 策略条目过多时按章节拆文件，MD 主文件做索引

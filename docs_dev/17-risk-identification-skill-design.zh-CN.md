# 风险识别技能设计与实现

**语言：** [English](17-risk-identification-skill-design.md) | 简体中文（本文）

本文面向维护者，说明 `risk-identification` 当前的模块、输入输出和执行边界，按 2026-09-16 的代码核对。首次使用请读[风险识别用户指南](../docs_user/19-risk-identification.zh-CN.md)，智能体工作流见 [SKILL.md](../src/skills/risk-identification/SKILL.md)。

## 1. 定位与边界

风险识别回答“已观察到的日志或行为中，哪些需要优先处理，为什么”。它以确定性规则检测事件、SSH 失败波次和 DNS 查询画像，输出 P0–P3 风险项，再应用告警策略和环境白名单。

| Skill | 负责什么 |
|---|---|
| `data-source-completeness` | 判断指定调查范围的数据覆盖与缺口 |
| `risk-identification` | 风险项、证据引用、告警/抑制决策及同主机事件聚合 |
| `alert-confirmation` | 判断 WAF 等告警是否真实、攻击是否成功 |
| `traceability-analysis` | 跨源、跨主机证据关联与攻击链解释 |

同主机上下文可以参与规则判断，但事件聚合不等于跨主机攻击链。`assess.py` 当前输出 `top_incidents` 和 `ssh_brute_waves`，不输出旧设计中的 `attack_chains`，也没有 `chain_builder.py` 模块。需要解释入口、横向路径或多阶段攻击时，另行使用溯源分析。

## 2. 当前已实现的检测模块

以下六个模块均由 [assess.py](../src/skills/risk-identification/scripts/assess.py) 调度；是否运行还取决于场景选择、输入数据和完整性门禁。

| 模块 | 输入证据 | 已实现能力 | 实现与规则 |
|---|---|---|---|
| `exec` | `host_exec` | 命令执行、反弹 Shell、下载执行、WebShell 命令特征等 | [exec_rules.py](../src/skills/risk-identification/scripts/exec_rules.py)、[exec-rules.json](../src/skills/risk-identification/rules/exec-rules.json) |
| `connect` | `host_connect` | 可疑外连、端口和命令关联外连 | [connect_rules.py](../src/skills/risk-identification/scripts/connect_rules.py)、[connect-rules.json](../src/skills/risk-identification/rules/connect-rules.json) |
| `ssh` | `ssh_auth`，或可提取认证失败的 syslog 事件 | 按来源、目标主机和时间窗聚合 SSH 暴力破解波次 | [ssh_rules.py](../src/skills/risk-identification/scripts/ssh_rules.py)、[ssh-rules.json](../src/skills/risk-identification/rules/ssh-rules.json) |
| `dns` | `dns_log`；DoH/DoT 检查使用 `host_connect` | NXDOMAIN 突增、疑似 DGA、非常见 TLD、疑似 DNS 隧道及 DoH/DoT 外连特征 | [dns_rules.py](../src/skills/risk-identification/scripts/dns_rules.py)、[dns-rules.json](../src/skills/risk-identification/rules/dns-rules.json) |
| `persistence` | `host_persistence` | cron、systemd、SSH 公钥、profile、sudoers 等持久化位置变更 | [persistence_rules.py](../src/skills/risk-identification/scripts/persistence_rules.py)、[persistence-rules.json](../src/skills/risk-identification/rules/persistence-rules.json) |
| `syslog` | `syslog_risk_alert` | sudo、建号、防火墙等结构化风险事件；SSH 暴破原始事件交给 `ssh` | [syslog_rules.py](../src/skills/risk-identification/scripts/syslog_rules.py)、[syslog-rules.json](../src/skills/risk-identification/rules/syslog-rules.json) |

SSH 暴力破解已经实现，入口是 `scripts/ssh_rules.py`，不需要名为 `ssh-bruteforce-risk/` 的独立 Skill 目录。它检测失败波次，不代表覆盖所有 SSH 账号异常或证明登录成功后的主机失陷。

`host_file_op` 仍是 exec 的辅助上下文，**没有独立 file 检测模块**。主机进程、端口、身份、服务和内核快照可用于补充调查，但不能替代实时命令、连接或认证事件。DNS 检测结果是可疑特征，不能单凭命中就证明存在 C2 通信或数据外传。

规则 ID、阈值、匹配字段和等级以对应 JSON 规则包为准，本文不复制完整清单。`external-listener-cmd-risk` 和 `external-listener-connect-risk` 是已有的命令/外连子能力说明，不代表风险识别仅支持这两类证据。

## 3. 场景与模块选择

默认映射由 [scenarios.json](../src/skills/risk-identification/scenarios.json) 定义：

| 场景 | 默认 `risk_modules` |
|---|---|
| `S5`、`S5-HOST` | `exec`, `connect`, `persistence`, `ssh`, `syslog` |
| `S5-EXEC` | `exec` |
| `S5-CONNECT` | `connect` |
| `S5-PERSISTENCE` | `persistence` |
| `S5+WAF` | `exec`, `connect`, `persistence` |
| `S8` | `connect`, `dns`, `exec`, `syslog` |

离线输入可用顶层非空 `risk_modules` 数组覆盖场景默认值。模块被选择不等于它有数据可分析；以输出的 `risk_modules_run`、`data_source_status` 和 `user_reminders` 判断实际覆盖。

[默认资产包](../dataasset/bundles/bundle-host-risk-default.json)是样例资产的组合，不保证你的环境已经接入所有模块所需的数据。接入时默认修改 `dataasset/`；需要隔离时可复制为 `dataasset_my/` 并设置 `DATAASSET_ROOT`。完整步骤见[数据源配置指南](../docs_user/03-configure-data-sources.zh-CN.md)。

## 4. 完整性、缺失数据与降级

从 Bundle 构造输入时，运行时默认执行完整性预检；数据取回后，[source_risk_map.py](../src/skills/risk-identification/scripts/source_risk_map.py)再评估实际事件覆盖。元数据预检通过不保证时间窗内一定有事件。

| 情况 | 当前行为 |
|---|---|
| 对应主数据源缺失或过滤后为空 | 跳过无法运行的模块，在 `user_reminders` 和覆盖结果中说明 |
| 只有 `host_connect`，没有 `dns_log` | 选中 `dns` 时仍可做 DoH/DoT 外连检查；DNS 查询画像不可用 |
| 缺少 `host_file_op` 等辅助源 | 相关上下文判断降级，不把缺失当成无风险 |
| 预检为 `partial_traceable` | 检测置信度上限不超过 0.85，并受预检置信度约束 |
| 预检为 `not_traceable` 或 `next_skill_blocked=true` | 检测置信度上限不超过 0.5；还需判断硬阻断条件 |
| `next_skill_blocked=true` 且输入中既无 `host_exec` 也无 `host_persistence` 事件 | 返回 `insufficient_data`，不执行检测模块 |

最后一行是当前实现的具体门禁，不应改述成“缺 exec 一律阻断”或“只要有 SSH 就一定可运行”。没有预检的离线 JSON 不会自动证明数据完整；使用者仍应检查覆盖结果。

## 5. 输入与查询方式

### 5.1 离线输入

下面是结构示意，空事件数组不构成可用证据：

```json
{
  "scenario": "S5",
  "risk_modules": ["exec", "connect", "persistence", "ssh", "syslog"],
  "params": {
    "hosts": ["REPLACE_WITH_AUTHORIZED_HOST"],
    "time_start": "REPLACE_WITH_ISO8601_START_WITH_TIMEZONE",
    "time_end": "REPLACE_WITH_ISO8601_END_WITH_TIMEZONE",
    "severity_floor": "P2"
  },
  "evidence_bundles": {
    "host_exec": [],
    "host_connect": [],
    "host_persistence": [],
    "ssh_auth": [],
    "syslog_risk_alert": []
  }
}
```

`params` 限定目标、带时区的起止时间和输出等级；完整性结果可通过 `completeness_precheck` 传入。字段别名和归一化约束见[证据最小字段配置](../dataasset/configure/evidence-minimum-fields.json)，各模块的规则包及解析器决定具体匹配条件。

从仓库根目录运行已有合成样例，无需数据源或查询凭证：

```bash
python3 src/skills/risk-identification/scripts/assess.py \
  -i src/skills/risk-identification/scripts/input.example.json
```

### 5.2 已授权数据查询

先完成环境安装和[只读数据源接入验收](../docs_user/03-configure-data-sources.zh-CN.md)。将 `RISK_BUNDLE_ID` 设置为已接入的资产包 ID，`RISK_PARAMS_FILE` 设置为本地参数 JSON 文件路径，文件中填写明确的 `hosts`、`time_start`、`time_end`，不要放凭证。默认使用 `dataasset/`；使用隔离副本时先设置 `DATAASSET_ROOT=dataasset_my`。

```bash
export DATAASSET_ROOT="${DATAASSET_ROOT:-dataasset}"
python3 src/skills/risk-identification/scripts/assess.py \
  --from-bundle \
  --bundle "${RISK_BUNDLE_ID:?Set an authorized bundle ID}" \
  --params-file "${RISK_PARAMS_FILE:?Set a scoped query params JSON path}" \
  --fetch
```

该入口默认构造完整性预检再取数。常规使用不要加 `--skip-completeness`。预检不是权限检查，运行前必须已确定查询范围；未提供目标和时间窗时应先补齐。

## 6. 执行流程与规则维护

```text
读取场景与完整性结果，判断门禁和置信度上限
  → 按目标与时间窗过滤证据，评估数据覆盖
  → 调度选中的 exec / connect / dns / persistence / ssh / syslog 模块
  → 风险项去重
  → behavior-policy 告警/抑制策略
  → 环境白名单（默认启用，可显式关闭）
  → MITRE ATT&CK 标注、同主机事件聚合
  → JSON、Markdown 报告与下游建议
```

| 改动目标 | 维护入口 |
|---|---|
| 日常检测模式、阈值和输出语义 | `src/skills/risk-identification/rules/*.json`；见[规则配置说明](../src/skills/risk-identification/rules/README.zh-CN.md) |
| 告警、抑制和平台策略 | [behavior-policy.md](../src/skills/risk-identification/behavior-policy.md)；CLI 执行对应的 [behavior-policy.rules.json](../src/skills/risk-identification/rules/behavior-policy.rules.json)，修改时保持同步 |
| 现有环境白名单兼容配置 | `whitelist.json`；当前仍在策略层之后默认执行，`--no-whitelist` 可关闭，不应描述为已从运行时删除 |
| 新算法、输入字段语义或模块 | Python 检测引擎及相应测试、规则和文档 |

不要以为只改自然语言策略就会自动改变 CLI 的确定性执行；普通 JSON 规则调整也不需要一律修改 Python。团队 YAML 规则的自动加载不属于本文承诺的功能。

## 7. 输出与验收

| 字段 | 使用方式 |
|---|---|
| `overall_verdict` | `no_risk_detected` / `low_risk_only` / `high_risk_detected` / `insufficient_data`；汇总考虑告警抑制结果，不能只数原始 P0/P1 |
| `risk_items[]` | 每项包含检测依据、等级、证据引用和策略结果；不得脱离对应事件下结论 |
| `risk_modules_run` | 实际执行的模块，不能由场景名称推断全部已执行 |
| `coverage_level`、`data_source_status`、`risk_coverage` | 覆盖程度、各源状态与不可识别/降级的规则 |
| `user_reminders`、`data_gaps`、`warnings` | 必须向用户解释的数据缺口与运行限制 |
| `top_incidents`、`ssh_brute_waves` | 事件聚合与 SSH 波次，不是跨主机攻击链 |
| `policy_hits`、`whitelist_hits` | 解释告警、抑制及白名单影响 |
| `fetch_summary` | 取数时核对数量、资产、时间窗和截断信息 |
| `markdown_report` | 脚本生成的确定性报告；智能体仍需核对证据并解释业务含义 |
| `recommended_next_skills` | 当前脚本在存在需告警的 P0 且有 WAF 证据时可建议 `alert-confirmation`；不会自动运行下游 Skill |

是否进一步调用 `traceability-analysis` 由调查任务决定，不应承诺每个 P0 都会由脚本自动推荐溯源。`recommended_action` 只是建议，不代表获得隔离、封禁或其他处置授权。

本地验证从仓库根目录执行；测试使用本地固定输入，不需要真实数据源：

```bash
.venv/bin/python -m unittest discover \
  -s src/skills/risk-identification/scripts/tests -p 'test_*.py'
.venv/bin/python -m unittest discover \
  -s src/skills/risk-identification/tests -p 'test_*.py'
```

开发环境与依赖见[贡献者上手指南](01-new-contributor-quickstart.zh-CN.md)。分析器处理归一化 JSON，实际能采集哪些事件取决于对应平台、采集器和数据源；不要把模块存在等同于所有操作系统都有相同采集覆盖。

## 8. 维护时保持一致的文件

新增或调整模块时同步检查 `scenarios.json`、数据源能力元数据 `source-requirements.json`、运行时 `source_risk_map.py`、规则包、`SKILL.md` 和本篇中英文文档。实现状态以当前模块调度和回归结果核对，不能仅凭规划中的目录名判断是否支持。

更细的操作步骤见[运营手册](../src/skills/risk-identification/OPS-HANDBOOK.zh-CN.md)；首次运行和真实数据切换仍以[用户指南](../docs_user/19-risk-identification.zh-CN.md)为入口。

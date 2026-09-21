---
name: risk-identification
description: >-
  SecWeaver 风险识别：对主机事件、SSH 失败波次、DNS 查询画像、持久化变更和 syslog 风险
  做确定性 P0-P3 分级及 behavior-policy 告警/降噪。跨源、跨主机攻击链由 traceability-analysis 处理。
  适用于风险识别、S5 主机异常、S8 C2 通信、WebShell、SSH 暴力破解、audit-port-execmon 筛查。
---

# 风险识别

SecWeaver Skill：**识别有风险的事件与行为模式** — 对主机、认证、DNS、持久化和 syslog 证据做分级、策略裁决与告警。

**职责边界**：评估事件以及 SSH 波次、DNS 画像等源内聚合结果；跨源、跨主机的完整攻击过程使用[溯源分析](../traceability-analysis/SKILL.zh-CN.md)。

机器可读输出契约见 [`output-schema.json`](output-schema.json)。输出在风险字段旁
同时携带共享 envelope 和取数结论边界。

## 在流水线中的位置

| Skill | 回答的问题 |
|---|---|
| 数据源完整性 | 能不能查？ |
| **风险识别** | **哪些事件或行为模式有风险？** |
| 溯源分析 | 跨源、跨主机、跨时间窗如何关联成攻击链？ |
| 告警确认 | WAF 告警是否真实攻击/是否成功？ |

## 子模块

| 模块 | 实现 | 数据 |
|---|---|---|
| `exec` 高危命令 | `scripts/exec_rules.py` | host_exec |
| `connect` 主动外连 | `scripts/connect_rules.py` | host_connect |
| `ssh` 暴力破解波次 | `scripts/ssh_rules.py` | ssh_auth / syslog 中可提取的认证失败 |
| `dns` 查询画像与 DoH/DoT 外连 | `scripts/dns_rules.py` | dns_log / host_connect |
| `persistence` 持久化变更 | `scripts/persistence_rules.py` | host_persistence |
| `syslog` 结构化系统风险 | `scripts/syslog_rules.py` | syslog_risk_alert |

`host_file_op` 是 exec 的辅助上下文，没有独立文件检测模块。默认映射见 [scenarios.json](scenarios.json)：S5/S5-HOST 选择 exec、connect、persistence、ssh、syslog；S8 选择 connect、dns、exec、syslog。以 `risk_modules_run` 和覆盖结果确认实际运行范围。

## 适用时机

- 对已授权的主机、认证、DNS、持久化或 syslog 证据做 **异常筛查**
- 「这台机器有没有可疑 shell / curl / 外连 / sshpass？」
- audit-port-execmon 事件批量研判
- 完整性 S5 或 S8 通过后的主机异常/C2 筛查

## 前置条件

| completeness（S5/S8） | 能力 |
|---|---|
| `full_traceable` | 按可用证据运行选定模块，受预检置信度上限约束 |
| `partial_traceable` | 报告缺失数据源，检测置信度上限为 0.85 |
| `not_traceable` 或 `next_skill_blocked` | 检测置信度上限为 0.5；还需判断下一行的硬阻断 |
| `next_skill_blocked` 且既无 host_exec 也无 host_persistence 事件 | **阻断**，返回 insufficient_data |

元数据完整不保证指定时间窗内一定有事件。真实查询前必须指定已授权的资产包、目标主机或 IP，以及带时区的起止时间；缺少范围时先补齐，不以样例目标或日期作为默认值。

## 研判流程

```text
Step 0  读 completeness_precheck → confidence 上限
Step 1  过滤 evidence（hosts、时间窗、listener_ports）
Step 2  检测层：选中的 exec / connect / dns / persistence / ssh / syslog → risk_items[]
Step 3  去重
Step 4  策略层（运营）：behavior-policy → alert_required / 最终 severity
Step 5  环境白名单：whitelist.json → suppress / downgrade（默认开启）
Step 6  MITRE 标注 → 事件聚合 top_incidents[]
Step 7  汇总 + 输出 JSON + markdown_report
```

**三层模型**：检测标签 [`rules/*.json`](rules/)；**告警策略** [`behavior-policy.md`](behavior-policy.md) + [`rules/behavior-policy.rules.json`](rules/behavior-policy.rules.json)；**环境例外** [`whitelist.json`](whitelist.json)（`exe_prefixes`、`dst_cidrs` 等细粒度 scope，默认 assess 自动应用）。

## 运营：规则写在哪

| 层级 | 文件 | 维护方 | 改什么 |
|------|------|--------|--------|
| 检测层（标签） | `rules/*.json` | **运营** | 增删 pattern/keyword/端口 |
| **策略层（告警）** | **`behavior-policy.md`** + **`rules/behavior-policy.rules.json`** | **运营** | 硬护栏、必须告警、全平台 OPS 降噪 |
| **环境白名单** | **`whitelist.json`** | **运营** | 按环境 scope 例外（默认开启） |
| 运营手册 | [behavior-policy.zh-CN.md](behavior-policy.zh-CN.md) · [whitelist.zh-CN.md](whitelist.zh-CN.md) | — | 如何新增规则 |

禁用白名单：`--no-whitelist` 或 `"whitelist": {"enabled": false}`。

每条 `risk_item` 必须能追溯到 **具体事件**（`evidence_refs`、command、timestamp、host）。

## CLI

从仓库根目录运行固定离线样例：

```bash
python3 src/skills/risk-identification/scripts/assess.py \
  -i src/skills/risk-identification/scripts/input.example.json
```

真实查询前先完成[数据源接入](../../../docs_user/03-configure-data-sources.zh-CN.md)。将 `RISK_BUNDLE_ID` 设置为已授权且已接入的资产包，`RISK_PARAMS_FILE` 设置为包含明确 `hosts`、`time_start`、`time_end` 的本地 JSON 参数文件路径，凭证单独保存。默认使用 `dataasset/`；隔离副本可设置 `DATAASSET_ROOT=dataasset_my`。

```bash
export DATAASSET_ROOT="${DATAASSET_ROOT:-dataasset}"
python3 src/skills/risk-identification/scripts/assess.py \
  --from-bundle \
  --bundle "${RISK_BUNDLE_ID:?Set an authorized bundle ID}" \
  --params-file "${RISK_PARAMS_FILE:?Set a scoped query params JSON path}" \
  --fetch
```

该入口默认执行完整性预检，常规使用不要加 `--skip-completeness`；预检不代表查询授权。

离线 payload 的顶层非空 `risk_modules` 可覆盖场景默认值，例如 `["exec","ssh"]` 只运行这两个模块。

## 输出字段

| 字段 | 说明 |
|---|---|
| `risk_items[]` | **主输出** — 检出的事件或模式（severity、matched_rules、policy_rule_id、**mitre_attack**、evidence_refs） |
| `top_incidents[]` | 同主机/同签名聚合，便于值班展示（默认 Top 20） |
| `ssh_brute_waves[]` | 认证失败波次，不代表已经成功入侵 |
| `risk_modules_run` | 实际运行的模块；缺失与降级见覆盖提醒 |
| `overall_verdict` | no_risk_detected / low_risk_only / high_risk_detected / insufficient_data |
| `coverage_level` | full / partial / insufficient |
| `fetch_summary` | 取数时必需：数量、资产、时间窗与截断情况 |
| `markdown_report` | 确定性 Markdown 报告，取数时含取数统计 |
| `policy_hits[]` | behavior-policy 裁决记录 |
| `recommended_next_skills` | 可选（需告警的 P0 + WAF 时建议 **alert-confirmation**），不会自动运行下游 Skill |

运行时覆盖映射见 [scripts/source_risk_map.py](scripts/source_risk_map.py)。事件聚合不是 `attack_chains` 输出；需跨源、跨主机还原时另行调用溯源分析。

## 与其他 Skill

```text
证据取数 → 风险识别（异常点清单）
              → (可选) 告警确认
跨源攻击链 / 横向 / 多轮叙事 → 溯源分析（独立 Skill，不在此输出）
```

## 禁止事项

- 不要在本 Skill 内还原 **跨主机 / 跨源** 攻击链（→ 溯源分析）
- 不要仅凭时间戳推断跨主机攻击顺序或因果关系（→ 溯源分析）
- 不要判 WAF 误报（→ 告警确认）
- 不要虚构 evidence_bundles 中不存在的事件
- P0 必须可追溯到 `matched_rules[]` 或 behavior-policy 强制告警规则

## 附加资源

- **取数专用 Skill：[../evidence-fetch/SKILL.zh-CN.md](../evidence-fetch/SKILL.zh-CN.md)**（先拉 evidence，再研判）
- **运营手册：[OPS-HANDBOOK.zh-CN.md](OPS-HANDBOOK.zh-CN.md)**（推荐阅读）
- 架构设计：[DESIGN.zh-CN.md](DESIGN.zh-CN.md)
- 告警策略：[behavior-policy.md](behavior-policy.md) · [behavior-policy.zh-CN.md](behavior-policy.zh-CN.md)
- 检测层 JSON：[rules/README.zh-CN.md](rules/README.zh-CN.md) · [detection-catalog.zh-CN.md](detection-catalog.zh-CN.md)
- 完整规格：[docs_dev/17-risk-identification-skill-design.zh-CN.md](../../../docs_dev/17-risk-identification-skill-design.zh-CN.md)
- exec/connect 规则说明：[../external-listener-cmd-risk/rules.md](../external-listener-cmd-risk/rules.md)
- 样例：[examples.zh-CN.md](examples.zh-CN.md)

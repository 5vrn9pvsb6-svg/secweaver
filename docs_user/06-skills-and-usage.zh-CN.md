# 06. 项目技能与使用方式：让 AI 做安全运营任务

**语言：** [English](06-skills-and-usage.md) | 简体中文（本文）

> 本文是技能选择与能力参考；日常提问步骤和报告复核见[操作指南](07-how-to-use.zh-CN.md)，首次体验见[快速上手](00-security-operator-quickstart.zh-CN.md)。

SecWeaver 不只是登记数据源，还内置了一组安全运营 Skill。你可以把 Skill 理解成：

```text
把一类安全运营任务封装成可复用的 AI 工作流。
```

如果 `dataasset` 负责告诉 AI“有什么数据、怎么取数据、怎么关联数据”，那么 Skill 负责告诉 AI：

```text
拿到这些数据后，应该按什么步骤分析、输出什么结论、什么时候升级到下一个技能。
```

技能选择目录；确定要用哪个技能后，转到 [07 操作流程](07-how-to-use.zh-CN.md)。各技能的执行参数以其 SKILL 与专题指南为准。


## 1. 什么是 Skill？

Skill 是 SecWeaver 中的任务能力单元。

一个 Skill 通常包含：

- 适用场景。
- 输入要求。
- 分析步骤。
- 输出格式。
- 证据要求。
- 置信度规则。
- 下一步建议。

例如：

```text
告警确认 Skill：判断一条 WAF 告警是误报、真实攻击，还是攻击成功。
溯源分析 Skill：在多源证据基础上还原攻击链。
风险识别 Skill：识别主机上的高危命令、外连和文件行为。
```

## 2. Skill 和 dataasset 是什么关系？

二者分工不同。

| 对象 | 负责什么 |
|---|---|
| `dataasset` | 数据源是什么、怎么连接、怎么查询、怎么关联 |
| `Scenario Pattern` | 某类问题先查什么、按什么链路查 |
| `Correlation Matrix` | 证据之间怎么 Join |
| `Skill` | 拿到证据后如何研判、如何输出结论 |
| 大模型 | 理解用户问题、调用合适 Skill、解释证据和结果 |

简单说：

```text
dataasset 解决“数据从哪来”；
Skill 解决“拿到数据后怎么分析”。
```

## 3. 当前项目有哪些主要 Skill？

下表按离线体验、接入、体检、取数、研判和子模块区分技能职责。

### 3.1 技能总览表

| 技能 | 类型 | 主要解决什么问题 | 典型使用时机 | 关键输入 | 常见输出 / 下一步 |
|---|---|---|---|---|---|
| [log-format-discovery](../src/skills/log-format-discovery/SKILL.zh-CN.md) | 数据接入 | 新日志格式字段识别、字段映射、归一化建议 | 新增 `status=discovery` 的数据源时 | discovery asset、样例日志 | 字段映射建议、parser 建议、`discovery → draft` |
| [dataasset-validation-advisor](../src/skills/dataasset-validation-advisor/SKILL.zh-CN.md) | 数据体检 | 检查 `dataasset/` 静态配置是否正确，并解释错误怎么修 | 修改 assets/connectors/bundles/hosts/scenarios 后 | `dataasset/` 配置、`validate.py` 输出 | error/warning 分类、阻塞判断、最小修复建议 |
| [dataasset-connectivity-check](../src/skills/dataasset-connectivity-check/SKILL.zh-CN.md) | 数据体检 | 检查 active 数据资产是否真实可连接、可取数 | 发布资产前、排查“validate 过了但查不到数据” | active asset、connector、凭证、查询模板 | 连接状态、取数状态、失败归因 |
| [data-source-completeness](../src/skills/data-source-completeness/SKILL.zh-CN.md) | 数据体检 / 前置门禁 | 判断当前数据是否足够支撑告警确认、溯源、横向、外传分析 | 正式研判前，或用户问“缺什么数据” | scenarios、params、registered_assets | 完整性结论、数据缺口、建议下一步 Skill |
| [alert-confirmation](../src/skills/alert-confirmation/SKILL.zh-CN.md) | 安全研判 | 判断 WAF/WEB/IDS 告警是误报、真实攻击，还是攻击成功 | 用户有一条或一批告警需要二次确认 | primary_alerts、correlated_evidence、completeness_precheck | `alert_verdict`、`attack_outcome`、处置建议；成功后进入溯源 |
| [traceability-analysis](../src/skills/traceability-analysis/SKILL.zh-CN.md) | 安全研判 | 跨源还原攻击链、初始入口、横向路径和影响范围 | 已知攻击 IP、攻击成功后、需要查第一攻破点 | evidence_bundles、join_edges、params、completeness_precheck | attack_chain、timeline、impact_scope、data_gaps |
| [risk-identification](../src/skills/risk-identification/SKILL.zh-CN.md) | 安全研判 | 识别主机高危命令、可疑外连、WebShell/C2 风险 | 用户指定主机、监听进程、host_exec/host_connect 证据 | host_exec、host_connect、host_file_op、host/context | P0-P3 风险项、攻击链片段、处置建议 |
| [external-listener-cmd-risk](../src/skills/external-listener-cmd-risk/SKILL.zh-CN.md) | 底层子模块 | 识别对外监听进程触发的高危命令 | 通常由 `risk-identification` 调用 | host_exec | 命令风险项、规则命中、严重级别 |
| [external-listener-connect-risk](../src/skills/external-listener-connect-risk/SKILL.zh-CN.md) | 底层子模块 | 识别对外监听进程主动外连风险 | 通常由 `risk-identification` 调用 | host_connect | 外连风险项、C2/可疑端口判断 |
| [offline-showcase](../src/skills/offline-showcase/SKILL.md) | 离线体验 | 无凭证体验调查和报告复核 | 首次使用 | 公开合成案例 | 报告与证据核对 |
| [evidence-fetch](../src/skills/evidence-fetch/SKILL.zh-CN.md) | 证据获取 | 按授权资产及范围取数 | 已接通真实数据后 | 资产/Bundle、主机或 IP、时间窗 | evidence_bundles、取数摘要；交给研判技能 |
| [prompt-risk-analysis](../src/skills/prompt-risk-analysis/SKILL.zh-CN.md) | 纯提示词研判 | 按提示词解释证据、发现风险和缺口 | 离线证据或取数后 | evidence_bundles、调查问题 | 带证据引用的报告；不冒充确定性规则命中 |

### 3.2 怎么快速选择 Skill？

| 用户想做什么 | 优先使用哪个 Skill |
|---|---|
| 接入一种新日志，不知道字段怎么映射 | `log-format-discovery` |
| 改完 JSON，想知道配置有没有问题 | `dataasset-validation-advisor` |
| 想知道 active 资产是否真的能查到数据 | `dataasset-connectivity-check` |
| 想知道当前数据够不够做调查 | `data-source-completeness` |
| 想确认告警是不是误报/真实/成功 | `alert-confirmation` |
| 想查攻击链、第一攻破点、横向范围 | `traceability-analysis` |
| 想查某台主机有没有高危行为 | `risk-identification` |

> 建议顺序：先用体检类 Skill 确认“能不能查”，再用研判类 Skill 输出“查出了什么”。

### 3.3 取数与提示词研判

`evidence-fetch` 只负责按 DataAsset 和调查场景取回、归一化并汇总证据，不判断攻击是否成立。
`prompt-risk-analysis` 是完全由提示词编写的研判 Skill，接收已有 `evidence_bundles`，由智能体解释多源证据、引用 `evidence_id`、列出数据缺口并提出下一步调查建议。

推荐流程：

```text
evidence-fetch → data-source-completeness → prompt-risk-analysis → 人工复核
```

示例入口见 [evidence-fetch](../src/skills/evidence-fetch/SKILL.md)、[prompt-risk-analysis](../src/skills/prompt-risk-analysis/SKILL.md) 和[提示词研判样例](../examples/prompt-risk-analysis/README.zh-CN.md)。

## 4. 技能和 S1-S8 场景的关系

| 场景 | 常用 Skill |
|---|---|
| S1 外部 IP 溯源 | data-source-completeness、traceability-analysis |
| S2 WEB 入侵 | alert-confirmation、traceability-analysis |
| S3 横向移动 | data-source-completeness、traceability-analysis |
| S4 告警确认 | data-source-completeness、alert-confirmation |
| S5 主机风险 | data-source-completeness、risk-identification |
| S6 账号失陷 | data-source-completeness、traceability-analysis |
| S7 数据外传 | data-source-completeness、traceability-analysis |
| S8 C2 通信检测 | data-source-completeness、risk-identification；按需 traceability-analysis |
| 新日志接入 | log-format-discovery、dataasset-validation-advisor、dataasset-connectivity-check |

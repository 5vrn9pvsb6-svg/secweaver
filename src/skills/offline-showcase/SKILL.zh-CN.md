---
name: offline-showcase
description: >-
  读取仓库内置离线证据并调用对应分析 Skill（包括 traceability-analysis、
  risk-identification 等），无需 ES、SLS 或凭证即可生成有证据支撑的报告。
  适用于快速体验、产品演示、测试案例、样例事件，以及“运行离线案例”、
  “不接数据源看看效果”等请求。
---

# SecWeaver 离线案例体验

**语言：** [English](SKILL.md) | 简体中文（本文）

本 Skill 负责选择案例并准备离线输入。被选中的分析 Skill 负责解释证据并生成最终调查报告。

## 默认交付

“运行 SecWeaver 离线案例”表示：**运行目录中的全部案例，并交付可读报告**。
用户无需再补充“形成可读报告”或“生成报告”。默认交付包括全部案例的运行结果、
每例可读分析报告，以及带报告链接的汇总。不得停在 PASS 输出或 JSON；报告编写与
证据复核属于同一项任务。用户指定单个案例时，也默认交付其可读报告。

## 案例选择

读取 [`examples/ai-showcase/cases.json`](../../../examples/ai-showcase/cases.json)。

- 用户指定案例时，选择对应 `case_id`。
- 用户只要求列出或比较案例时，概述目录，不运行案例。
- 用户只要求运行离线案例时，按 `cases[]` 顺序运行全部条目，不选择单一默认案例，
  也不要求用户再次选择；以后新增的目录条目自动纳入默认运行。
- 目录覆盖所有可执行研判输入；数量必须从 `cases[]` 动态读取，不得写死。
  仅供提示词取数的 fixture 和原始格式发现样例属于其他流程，不得声称本次已研判。
- 用户未指定案例但要求主机风险分析时，选择 `reverse-shell-risk`；要求攻击链时，
  选择 `webshell-to-ssh-lateral`。

## 分析 Skill 路由

| 离线案例 | 调用的分析 Skill |
|---|---|
| `webshell-to-ssh-lateral` 及其他溯源案例 | [traceability-analysis](../traceability-analysis/SKILL.zh-CN.md) |
| `reverse-shell-risk` 及其他主机风险案例 | [risk-identification](../risk-identification/SKILL.zh-CN.md) |
| 告警案例 | [alert-confirmation](../alert-confirmation/SKILL.zh-CN.md) |
| 数据源完整性案例 | [data-source-completeness](../data-source-completeness/SKILL.zh-CN.md) |

实际路由以每个条目的 `skill_doc` 为准，表格只是指引，不是固定案例清单。

“调用”表示完整阅读并遵循该 Skill 的流程，通过 runner 执行其分析脚本，并完成报告
要求。runner 会执行确定性分析、校验预期字段，并在 JSON 旁生成可读的结构化结果
Markdown。自动报告只是基线，不能替代智能体的叙事分析，也不能替代被调用 Skill 的
报告合同。

## 运行流程

1. 对每个选中条目读取其 `input` JSON，包括证据与完整性预检。确认 `offline: true`。
   `_meta.expected_*` 和目录中的 `expected` 只用于回归断言，不能作为事件证据。
2. 完整阅读被委派的 `skill_doc`，并告诉用户正在调用哪个分析 Skill；其流程与报告合同优先。
3. 在 Linux、macOS 或 WSL2 的仓库根目录运行 `.venv/bin/python
   src/scripts/run_ai_showcase.py <case_id>`；Windows 用户必须在 WSL2 中运行，原生 Windows
   不是受支持的 Community 客户端运行环境。单例传入案例 ID；全量省略 `<case_id>` 或使用
   `--all`。runner 在个别失败后继续，
   写入 `outputs/ai-showcase/suite-summary.json` 和 `suite-summary.md`；成功案例写入
   `<case_id>.json` 与 `<case_id>.md`。报告写入失败也计为失败；非零退出表示至少一例失败，
   不代表其余案例未执行。
4. 不得增加 `--fetch`、解析凭证、访问实时端点或发送通知。runner 对溯源强制
   `--no-ip-intel --no-notify`，实施离线边界并校验稳定预期字段。
   WebShell-to-SSH 案例确认 SSH 横向证据，但初始失陷点仍未解决；报告该缺口，
   不得称完整入口链已经证实。
5. 对本次成功的每个条目，读取 runner 输出中 `Result` 指向的 JSON 及离线输入。
   `Report` 指向自动基线；完成被选分析 Skill 的证据复核与 Markdown 报告，将其保存为
   同目录 `<case_id>.md` 并替换基线。未复核的自动基线不得称为智能体调查报告。
   重跑会覆盖 JSON 和 Markdown，因此必须在最后一次运行后完成分析。预期不匹配是
   回归信号，应报告问题，不能篡改预期结果。
6. 批量运行时完善 `outputs/ai-showcase/suite-summary.md`：写明总数、成功、失败，
   每例裁决与限制，并链接 JSON 和经智能体复核的 Markdown。包含失败及错误；失败案例
   遗留的旧文件不是本次结果。成功案例仍需继续完成报告。
7. 结束前对比本次成功 ID 与报告路径，确认每个成功案例都有非空且已复核的 Markdown，
   汇总中的链接都可解析。最终回复先链接可读汇总，并写明总数、成功数、失败数。
   报告生成或复核未完成时应明确说明，不得声称离线体验已经完成。

输入是合成测试证据。运行案例只允许写入 Git 忽略的 `outputs/ai-showcase/`。

## 完成分析

遵循所选分析 Skill 的报告模板，不能用通用演示摘要替代。溯源报告应包含证据统计、
攻击路径、有引用的时间线、已确认/疑似横向移动、影响与缺口。风险识别报告应包含证据
统计、风险项、严重度、证据引用、规则/ATT&CK 映射及处置建议。

每个成功案例具备分析 Skill 报告、失败项已披露、批量汇总或单例报告已在对话中链接，
任务才算完成。runner 成功、预期裁决匹配或只给 JSON 链接，都不构成完整调查交付。

必须说明这是离线合成案例，未使用 ES、SLS、凭证或生产数据；不得暗示分析了实时环境。

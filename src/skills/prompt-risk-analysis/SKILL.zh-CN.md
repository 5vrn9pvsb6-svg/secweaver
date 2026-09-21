---
name: prompt-risk-analysis
description: >-
  SecWeaver 开源提示词研判 Skill：evidence-fetch 取数后，由 AI 扮演资深安全专家
  主动分析；优先读 correlation-cheatsheet，参考 matrix/anchor 做关联与场景编排。
  适用于提示词研判、LLM 专家复盘。
---

# 提示词风险研判（开源版）

英文 `SKILL.md` 是工作流规范源；本文件是其中文本地化镜像。修改必选工作流步骤时，必须同步更新两个文件。

SecWeaver Skill：**evidence-fetch 取数，资深专家研判** — 纯提示词，无 Python。  
AI 应扮演 **资深安全分析专家**，发挥能动性与行业经验；`policy-lite` 等文件仅为参考基线，**不得**机械照搬或仅复述文档内容。

**搭配：** 仅需 [evidence-fetch](../evidence-fetch/SKILL.zh-CN.md)。

## 流水线

```text
evidence-fetch  →  evidence_bundles + fetch_summary
        ↓
Agent 以资深专家身份读 PROMPT.zh-CN.md + correlation-cheatsheet（优先）
        + evidence + matrix/anchor（按需）
        ↓
研判报告（专家洞察 + 证据引用）
```

| 步骤 | 工具 | 是否确定性 |
|------|------|------------|
| 取数 | evidence-fetch | 是 |
| 研判 | PROMPT + 资深专家 AI（能动性、行业经验） | 否（需人工复核） |

## 适用场景

- 开源用户需要 **AI 专家级** 调查叙事，而非固定规则引擎。
- 单次调查、复盘、写事故报告。
- `policy-lite.zh-CN.md` 可作为团队默认口径，**专家可偏离并说明理由**。

## 能力边界

本 Skill **不提供**：

- 可版本化、可机器回归的确定性规则输出（无 `policy_rule_id` 契约）。
- 7×24 海量事件低成本全自动分级。
- 跨源拼链的专用关联引擎（可在报告中做叙事级关联，须标明置信度）。

## 工作流（仅 evidence-fetch CLI）

```bash
# 取数（本 Skill 无自有脚本）
python3 src/skills/evidence-fetch/scripts/fetch_evidence.py \
  --asset-id asset-secweaver-host-exec \
  --asset-id asset-secweaver-sys-risk-alert \
  --params '{"hosts":["192.0.2.91"],"time_start":"2026-06-20T00:00:00+08:00","time_end":"2026-07-03T23:59:59+08:00"}' \
  -o /tmp/fetch.json
```

可选：取数时加 `--format markdown` 便于人工浏览；研判仍以 JSON 中 `evidence_bundles` 为准。

## Agent 工作流

1. 按用户参数运行 **evidence-fetch**（或读取已有 fetch JSON / `examples/` 离线样例）。
2. 以 **资深安全分析专家** 身份阅读 **PROMPT.zh-CN.md**。
3. **先阅读** [analysis-contract.zh-CN.md](analysis-contract.zh-CN.md) 中的场景、计数、成功、WAF 覆盖和脱敏契约；再读 [correlation-cheatsheet.zh-CN.md](correlation-cheatsheet.zh-CN.md) 做关联与补数。
4. 深入分析 `evidence_bundles`；`policy-lite.zh-CN.md` **仅作参考**。
5. 在专家研判叙事之前，**先输出 `fetch_summary`**：已拉取资产、按类型的事件数、时间窗与截断情况。
6. 事件过多时抽样并声明范围；输出含 **chain_coverage**、**join_refs**、**fetch_next**（见 output-schema.json）。
7. 离线练习：`examples/prompt-risk-analysis/` 下的 exec/syslog 与 WAF 漏过样例。

## 文件说明

| 文件 | 作用 |
|------|------|
| [PROMPT.zh-CN.md](PROMPT.zh-CN.md) | Agent 主提示词：资深专家角色、能动性、证据边界 |
| [PROMPT.md](PROMPT.md) | 英文提示词 |
| [analysis-contract.md](analysis-contract.md) | **规范源**：场景、参数、证据、计数、WAF 与脱敏契约 |
| [analysis-contract.zh-CN.md](analysis-contract.zh-CN.md) | 研判契约中文镜像 |
| [correlation-cheatsheet.zh-CN.md](correlation-cheatsheet.zh-CN.md) | **优先阅读** — 时间窗、场景速选、常用 join、补数模板 |
| [correlation-cheatsheet.md](correlation-cheatsheet.md) | 英文速查表 |
| [correlation-matrix.json](../../../dataasset/assets/correlation-matrix.json) | **重要参考** — Join 键、时间窗、跨源/同主机关联规则 |
| [anchor-patterns.json](../../../dataasset/scenarios/anchor-patterns.json) | **重要参考** — S1–S8 场景、推荐关联链、调查窗、补数资产 |
| [policy-lite.zh-CN.md](policy-lite.zh-CN.md) | **可选参考** — 团队默认告警/降噪示例，非唯一依据 |
| [output-schema.json](output-schema.json) | 严格结构化输出契约 |
| [examples/prompt-risk-analysis/](../../../examples/prompt-risk-analysis/) | 离线 fetch + 黄金报告样例 |
| [examples.zh-CN.md](examples.zh-CN.md) | 端到端 CLI 样例 |

## 与 evidence-fetch 的分工

| Skill | 回答的问题 |
|-------|------------|
| evidence-fetch | 能拉到哪些日志？ |
| **prompt-risk-analysis** | 这些日志说明什么风险？如何被打穿？ |

## 相关文档

- [evidence-fetch/SKILL.zh-CN.md](../evidence-fetch/SKILL.zh-CN.md)

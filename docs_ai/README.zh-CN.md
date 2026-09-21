# AI 参考文档（docs_ai）

供 智能体在资产接入或解释源字段时按需加载的人类可读参考资料。本目录不是运行时依赖，也不复制 Skill 内容；**机器可读规格**仍以 `dataasset/` 为权威来源。

## 加载规则

- 只有当前资产的证据类型和数据形态匹配时才加载对应字段指南，不要把整个目录加入每次 Prompt。
- 工作流指令以 `src/skills/<skill>/SKILL.md` 为准；本目录只提供上下文，不提供可执行指令。
- Schema、查询模板、关联规则和场景编排从 `dataasset/` 读取；说明文字与 JSON 冲突时，以通过校验的 JSON 契约为准。
- 样例文件名中的 `prod` 只是示例资产命名，不代表能够访问生产系统。指南不包含凭证，也不授权真实查询。

## 本目录文档

| 文件 | 说明 |
|------|------|
| [asset-es-waf-prod-field-guide.zh-CN.md](asset-es-waf-prod-field-guide.zh-CN.md) | L1 逻辑资产字段说明样例（WAF / ES） |
| [asset-es-waf-prod-field-guide.md](asset-es-waf-prod-field-guide.md) | 英文版 |

## 关联研判必读（仍在 dataasset，运行时代码引用此处）

| 文件 | 说明 | 典型消费者 |
|------|------|------------|
| [correlation-matrix.json](../dataasset/assets/correlation-matrix.json) | 跨源 Join 键、时间窗、同主机/跨源关联规则 | prompt-risk-analysis、traceability-analysis |
| [anchor-patterns.json](../dataasset/scenarios/anchor-patterns.json) | S1–S8 场景、推荐关联链、调查窗、bundle | evidence-fetch、traceability-analysis |
| [evidence-minimum-fields.json](../dataasset/configure/evidence-minimum-fields.json) | 各 asset_type 最小字段与别名 |
| [text-log-parsers.json](../dataasset/configure/text-log-parsers.json) | 内置 text_parser 清单 |
| [query-templates/templates.json](../dataasset/query-templates/templates.json) | 查询模板与 param 约定 |

## 与 Skill 的关系

- **prompt-risk-analysis**：接入资产时按需加载匹配的字段指南，并根据当前任务读取关联与场景 JSON。
- **evidence-fetch / traceability-analysis**：运行时直接读取 `dataasset/` 下 JSON，不依赖本目录。

# AI reference docs (`docs_ai`)

Human-readable reference material that an AI host may load while onboarding an asset or interpreting source fields. This directory is not a runtime dependency and is not a copy of a Skill. **Machine-readable specs** under `dataasset/` remain authoritative.

## Loading policy

- Load a field guide only when the current asset matches its evidence type and source shape; do not add the whole directory to every prompt.
- Read `src/skills/<skill>/SKILL.md` for workflow instructions. Files in this directory provide context, not executable instructions.
- Read schemas, query templates, correlation rules, and scenario patterns from `dataasset/`; when prose conflicts with JSON, the validated JSON contract wins.
- The `prod` token in the sample filename is an example asset name, not access to a production system. The guide contains no credentials and does not authorize live queries.

## In this directory

| File | Description |
|------|-------------|
| [asset-es-waf-prod-field-guide.md](asset-es-waf-prod-field-guide.md) | L1 logical asset field guide sample (WAF / ES) |
| [asset-es-waf-prod-field-guide.zh-CN.md](asset-es-waf-prod-field-guide.zh-CN.md) | Chinese version |

## Correlation & scenarios (canonical paths in `dataasset`)

| File | Role | Typical consumers |
|------|------|-------------------|
| [correlation-matrix.json](../dataasset/assets/correlation-matrix.json) | Join keys, time windows, internal/cross-source rules | prompt-risk-analysis, traceability-analysis |
| [anchor-patterns.json](../dataasset/scenarios/anchor-patterns.json) | S1–S8 patterns, recommended chains, investigation windows | evidence-fetch, traceability-analysis |
| [evidence-minimum-fields.json](../dataasset/configure/evidence-minimum-fields.json) | Minimum fields and aliases per `asset_type` |
| [text-log-parsers.json](../dataasset/configure/text-log-parsers.json) | Built-in `text_parser` catalog |
| [query-templates/templates.json](../dataasset/query-templates/templates.json) | Query templates and param conventions |

## Skills

- **prompt-risk-analysis**: load the matching field guide while onboarding an asset; read the correlation and scenario JSON only as required by the task.
- **evidence-fetch / traceability-analysis**: runtime reads JSON from `dataasset/` directly and does not depend on this directory.

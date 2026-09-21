# Risk Identification Module Map

[English / 简体中文](DESIGN.zh-CN.md)

For code maintainers: entry points and dependencies. The [design entry](../../../docs_dev/17-risk-identification-skill-design.md) owns the architecture; detection and policy syntax have separate references below.

| Module | Responsibility |
|---|---|
| `scripts/assess.py` | Completeness, retrieval/offline input, orchestration, output |
| Detection engines and `rules/*-rules.json` | `matched_rules`, initial severity, context |
| `scripts/behavior_policy.py`, `policy_engine.py`, `rules/behavior-policy.rules.json` | Hard guards, force alert, suppression, default decisions |
| `behavior-policy.md` | Policy rationale and audit, synchronized with JSON; not the default execution engine |
| `whitelist.json` | Scoped environment exceptions, preserving safety guards |
| `rules/attck-map.json` | Detection/policy to ATT&CK mapping |
| `rules/chain-patterns.json` | Cross-stage patterns consumed by traceability |

AI-agent and CLI invocations use the same deterministic engine. `prompt-risk-analysis` is a separate prompt-only Skill; its conclusions are not JSON rule matches. Risk items are not cross-host attack chains, which belong to `traceability-analysis`. Reports must retain evidence references, data gaps, and policy rationale.

## Maintenance references

- [Detection engine](../../../docs_dev/18-risk-identification-engine-design.md)
- [Policy engine](../../../docs_dev/19-behavior-policy-engine-design.md)
- [Operations playbooks](OPS-HANDBOOK.md)
- [JSON reference](../../../docs_dev/18-risk-identification-engine-design.md)
- [Detection catalog](detection-catalog.md)

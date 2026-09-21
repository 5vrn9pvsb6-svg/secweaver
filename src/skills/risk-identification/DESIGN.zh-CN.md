# 风险识别模块地图

[English / 简体中文](DESIGN.md)

本文面向代码维护者，说明入口与依赖。完整架构由[设计入口](../../../docs_dev/17-risk-identification-skill-design.zh-CN.md)维护；检测语法与策略语法分别见下表。

| 模块 | 职责 |
|---|---|
| `scripts/assess.py` | 完整性预检、取数/离线输入、检测编排与输出 |
| 检测引擎与 `rules/*-rules.json` | 生成 `matched_rules`、初判等级和上下文 |
| `scripts/behavior_policy.py`、`policy_engine.py` 与 `rules/behavior-policy.rules.json` | 硬护栏、强制告警、降噪与默认裁决 |
| `behavior-policy.md` | 策略理由和审计；与 JSON 同步，不是默认执行引擎 |
| `whitelist.json` | 环境范围例外；保留安全护栏 |
| `rules/attck-map.json` | 标签/策略到 ATT&CK 的映射 |
| `rules/chain-patterns.json` | 供溯源复用的跨阶段剧本 |

智能体与 CLI 调用同一确定性引擎。`prompt-risk-analysis` 是独立纯提示词技能，不能把它的结论归为 JSON 规则命中。风险项不是跨主机攻击链；后者由 `traceability-analysis` 负责。最终报告必须保留证据引用、数据缺口与策略依据。

## 维护入口

- [Detection engine](../../../docs_dev/18-risk-identification-engine-design.zh-CN.md)
- [Policy engine](../../../docs_dev/19-behavior-policy-engine-design.zh-CN.md)
- [Operations playbooks](OPS-HANDBOOK.zh-CN.md)
- [JSON reference](rules/README.zh-CN.md)
- [Detection catalog](detection-catalog.zh-CN.md)

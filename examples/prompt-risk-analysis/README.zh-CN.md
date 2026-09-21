# 提示词研判 — 离线样例

无需 Vault / SLS，可直接用于 prompt-risk-analysis 练习或 CI 对照。
两份取证样例都包含 `evidence-fetch` v1 契约字段（`contract_version`、`skill`、
`data_access` 和 `fetch_summary`）；WAF 研判报告使用独立的严格提示词输出 Schema。

| 文件 | 说明 |
|------|------|
| [fetch-exec-syslog-mini.json](fetch-exec-syslog-mini.json) | 精简 fetch JSON（91 主机执行、尝试 SSH 到 92，另含 92 较早的上下文；14:00–18:30 共 8 条事件） |
| [report-exec-syslog-mini.zh-CN.md](report-exec-syslog-mini.zh-CN.md) | 黄金报告样例；区分 SSH 尝试与已证实的横向成功 |
| [fetch-waf-bypass-mini.json](fetch-waf-bypass-mini.json) | 脱敏 S4 样例：包含拦截、漏过、良性和去重流量 |
| [report-waf-bypass-mini.json](report-waf-bypass-mini.json) | 符合严格 Schema 的黄金 JSON 报告 |
| [report-waf-bypass-mini.zh-CN.md](report-waf-bypass-mini.zh-CN.md) | WAF 漏过人读黄金报告 |

## 用法

```text
1. 读取 fetch-exec-syslog-mini.json 中的 evidence_bundles
2. 加载 prompt-risk-analysis/PROMPT.zh-CN.md + correlation-cheatsheet.zh-CN.md
3. 输出研判报告，对照 report-exec-syslog-mini.zh-CN.md 检查结构与 chain_coverage
```

For a larger offline drill, extend [fetch-exec-syslog-mini.json](fetch-exec-syslog-mini.json) or add sanitized events under `examples/risk-identification/`.

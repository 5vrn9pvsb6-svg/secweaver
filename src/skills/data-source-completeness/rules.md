# Data Source Completeness — Rule Matrix

> Machine-readable scenario requirements: [scenarios.json](scenarios.json); deterministic assessment: [scripts/check.py](scripts/check.py)

## 1. Asset type to data domain mapping

| asset_type | Name | Domain | Default correlation keys |
|---|---|---|---|
| `waf_alert` | WAF/WEB security alerts | D1/D5 | src_ip, timestamp, url, payload, rule_id |
| `web_access_log` | WEB access logs | D1 | src_ip, timestamp, url, status, user_agent |
| `host_exec` | Host process command execution | D2 | host, timestamp, pid, ppid, command, user |
| `host_connect` | Host active outbound connections | D2 | host, timestamp, pid, dst_ip, dst_port |
| `host_file_op` | Host file operations | D2 | host, timestamp, path, action, pid |
| `host_persistence` | Host persistence changes | D2 | host, timestamp, path, action, persistence_type, pid |
| `windows_event_log` | Windows system/event logs | D2 | host, timestamp, event_id, channel, user |
| `linux_syslog` | Linux system/syslog logs | D2 | host, timestamp, message, program, severity |
| `ssh_auth` | SSH authentication logs | D3 | host, src_ip, user, timestamp, result |
| `vpn_auth` | VPN login | D3 | user, src_ip, timestamp, result |
| `firewall_log` | Firewall logs | D4 | src_ip, dst_ip, src_port, dst_port, timestamp |
| `network_traffic_audit` | Full traffic audit logs | D4 | src_ip, dst_ip, src_port, dst_port, protocol, timestamp |
| `dns_log` | DNS queries | D4 | client_ip, query, timestamp, response |
| `proxy_log` | Proxy logs | D4 | src_ip, dst_ip, url, timestamp |
| `ids_alert` | IDS/IPS alerts | D5 | src_ip, dst_ip, signature, timestamp |
| `edr_event` | EDR events | D2 | host, timestamp, process, action |
| `asset_inventory` | Asset inventory | D6 | hostname, ip, zone, owner, services |
| `vuln_scan` | Vulnerability scans | D6 | host, cve, component, scan_time |

### SecWeaver tool mapping

| Tool | Produces asset_type |
|---|---|
| audit-port-execmon (exec) | `host_exec` |
| audit-port-execmon (connect) | `host_connect` |
| audit-port-execmon (file_op) | `host_file_op` |
| Winlogbeat / WEF → SLS (Security/System/Application/Sysmon) | `windows_event_log` |
| Filebeat/Fluent Bit/rsyslog → SLS (syslog, journald) | `linux_syslog` |
| NDR/TAP/full-traffic platform → SLS/ES | `network_traffic_audit` |

---

## 2. Scenario requirement matrix

### S1 External attack IP traceability

| Priority | asset_type | Required fields | Coverage |
|---|---|---|---|
| P0 | `waf_alert` or `web_access_log` | src_ip, timestamp, url | All external WEB |
| P0 | `host_exec` | host, command, timestamp | **WEB servers** |
| P0 | `ssh_auth` | host, src_ip, user, result, timestamp | SSH hosts that may be laterally targeted |
| P1 | `host_connect` | dst_ip, dst_port, timestamp | WEB servers |
| P1 | `firewall_log` or `network_traffic_audit` | src_ip, dst_ip, port | WEB→internal segments |
| P1 | `dns_log` | client_ip, query | WEB servers or DNS servers |
| P2 | `host_file_op` | path, action | WEB servers |
| P2 | `asset_inventory` | hostname, ip, services | Full internal SSH asset set |
| P2 | `edr_event` | process, action | Critical hosts |

### S2 WEB intrusion traceability

| Priority | asset_type | Notes |
|---|---|---|
| P0 | `waf_alert` / `web_access_log` | Attack requests and payload |
| P0 | `host_exec` | WebShell commands, system commands |
| P0 | `host_file_op` | WebShell drops, anomalous files |
| P1 | `host_connect` | Reverse shell, downloads |
| P1 | `web_access_log` | Pre/post-alert access sequence |
| P2 | `vuln_scan` | Vulns in attacked components |

### S3 Lateral movement investigation

| Priority | asset_type | Notes |
|---|---|---|
| P0 | `ssh_auth` | Login success/failure, source IP |
| P0 | `firewall_log` or `network_traffic_audit` | Internal connection relationships |
| P1 | `host_exec` | ssh/scp/nc on jump hosts |
| P1 | `host_connect` | Internal scan, 445/3389 |
| P2 | `vpn_auth` | Lateral from VPN entry |
| P2 | `asset_inventory` | Internal asset boundaries |

### S4 WEB alert confirmation

| Priority | asset_type | Notes |
|---|---|---|
| P0 | `waf_alert` | **Must include payload or request_body** |
| P0 | `web_access_log` | 5–10 min context around alert |
| P1 | `host_exec` | Prove attack success (shell, whoami) |
| P1 | `host_connect` | Prove C2 or download success |
| P1 | `host_file_op` | WebShell drop |
| P2 | `vuln_scan` | Vuln on attacked path |

**Alert confirmation conclusion constraints:**

| Data state | Allowed conclusions |
|---|---|
| D1/D5 only | Attempt / suspected real attack / possible FP |
| D1 + D2 exec/connect | May judge real attack + success |
| No payload | No “SQLi/XSS success”; only “rule matched” |

### S5 Host anomalous behavior

| Priority | asset_type | Notes |
|---|---|---|
| P0 | `host_exec` | Commands from externally listening processes |
| P1 | `host_connect` | Active outbound targets |
| P1 | `host_file_op` | Anomalous file I/O |
| P1 | `host_persistence` | cron/systemd/authorized_keys persistence changes |
| P2 | `waf_alert` | Explain trigger source |

### S6 Account compromise

| Priority | asset_type | Notes |
|---|---|---|
| P0 | `ssh_auth` / `vpn_auth` / AD logs | Anomalous logins |
| P1 | `host_exec` | Post-login commands |
| P1 | `firewall_log` | Anomalous egress |
| P2 | `proxy_log` | Account abuse |

### S7 Data exfiltration

| Priority | asset_type | Notes |
|---|---|---|
| P0 | `host_connect` / `proxy_log` | Bulk outbound |
| P0 | `host_file_op` | Archive, compress, sensitive paths |
| P1 | `host_exec` | tar/zip/scp/rsync |
| P1 | `firewall_log` | Exfil traffic |
| P2 | `dlp` | Sensitive data identification |

### S8 C2 communication detection

| Priority | asset_type | Notes |
|---|---|---|
| P0 | `host_connect` | Host, destination IP/port, and callback time |
| P1 | `network_traffic_audit` / `proxy_log` | Beacon periodicity, session volume, proxy path |
| P1 | `dns_log` | C2 domain and DGA attribution |
| P1 | `host_exec` | Process/command attribution and reverse-shell context |
| P2 | `syslog_risk_alert` | Independent host-risk corroboration |

---

## 3. Per-item evaluation rules

### 3.1 status determination

```text
ready:
  - asset registered
  - coverage covers investigation hosts/segments
  - required fields complete
  - retention covers time_start ~ time_end

partial:
  - registered but coverage is partial hosts only
  - or missing non-critical field (e.g. no payload in S1)
  - or insufficient retention

missing:
  - not registered
  - or registered but coverage=none

optional:
  - P2 and scenario allows degraded analysis
```

### 3.2 Correlation key check

Cross-source correlation needs **≥3** ready keys:

| Key | Use |
|---|---|
| `src_ip` | Chain WAF→SSH attack source |
| `host` / `dst_ip` | Victim host location |
| `timestamp` | Timeline (timezone UTC+8 or labeled) |
| `user` | Account dimension |
| `pid` / `process` | Process chain |
| `session` / `flow_id` | Network session |

< 3 keys → `key_completeness = partial`, confidence cap 0.75

### 3.3 Time window

| Scenario | Default window |
|---|---|
| Known alert time T | [T-24h, T+6h] |
| Attack IP only | Last 7 days (configurable) |
| Lateral movement | Entry time -24h to last activity +12h |

retention < required window → source status = partial, gaps add `retention_insufficient`

### 3.4 Coverage

| coverage | Meaning |
|---|---|
| `full` | All investigation hosts/segments covered |
| `partial` | Partial only (e.g. web-01 but not web-02) |
| `none` | No coverage |

**S1 special rule:** WEB host exec must cover **the first WEB server that may be breached** — not internal SSH only without WEB-side behavior.

---

## 4. Overall verdict rules

```text
IF any P0 == missing:
  overall_verdict = not_traceable
  next_skill_blocked = true
  block_reason = "Missing P0 source: {list}"

ELSE IF scenario includes S4 AND no host_exec AND no host_connect:
  can_confirm_breach = false
  IF waf_alert only:
    overall_verdict = alert_triage_only

ELSE IF all P0 == ready AND P1 ready_rate >= 0.8:
  overall_verdict = full_traceable
  next_skill_blocked = false

ELSE IF all P0 == ready:
  overall_verdict = partial_traceable
  next_skill_blocked = false

ELSE:
  overall_verdict = not_traceable
```

### confidence calculation

```text
P0_ready_rate = ready P0 count / total P0
P1_ready_rate = ready P1 count / total P1
key_score = 1.0(≥4 keys) | 0.7(3 keys) | 0.4(<3 keys)
time_score = 1.0(all met) | 0.6(partial) | 0.3(insufficient)

confidence = 0.40*P0_ready_rate + 0.35*P1_ready_rate + 0.15*key_score + 0.10*time_score
```

---

## 5. Onboarding recommendation priority

When generating recommendations, sort:

```text
1. All P0 missing, by impact
2. P0 partial (coverage/field gaps) remediation
3. P1 missing and directly relevant to investigation
4. P2 optional
```

### collection_hint standard phrasing

| asset_type | collection_hint |
|---|---|
| `host_exec` | Deploy audit-port-execmon on Linux; whitelist_ports for external-port process exec |
| `host_connect` | Enable monitor_connect in audit-port-execmon |
| `host_file_op` | Enable monitor_file_ops in audit-port-execmon |
| `host_persistence` | Enable secweaver-agent host-persistence for cron/systemd/authorized_keys/sudoers/profile paths |
| `ssh_auth` | rsyslog /var/log/auth.log or journald; unify timestamp and host fields |
| `waf_alert` | WAF API/syslog; ensure payload/request included |
| `firewall_log` | Firewall syslog or SIEM forward; retain 5-tuple |
| `network_traffic_audit` | NDR/TAP full-traffic export; 5-tuple, protocol, bytes/session ID |
| `dns_log` | Internal DNS query logs or DNS security gateway |

---

## 6. SecWeaver scenario requirement checklist

### External IP traceability (S1)

User input: time A, hacker IP A, find breach point + lateral scope

AI agent must check:

- [ ] WAF/WEB has records for this IP
- [ ] WEB server has exec (curl/bash/webshell)
- [ ] WEB server has connect (download domains)
- [ ] SSH logs cover possible internal targets
- [ ] WEB→internal firewall records exist
- [ ] Asset inventory knows full SSH server set

Missing exec → output: “Cannot confirm SSH brute-force tool download; cannot prove breach”

### WEB alert confirmation (S4)

- [ ] WAF has payload
- [ ] WEB host exec proves success
- No D2 → “Cannot confirm attack success; can only classify alert type”

---

## 7. Downstream Skill handoff

| Condition | next_skill |
|---|---|
| S1/S2/S3 and P0 complete | `traceability_analysis` |
| S4 and P0 complete | `alert_confirmation` |
| S5 and host_exec ready | `risk-identification` |
| P0 missing | none; output recommendations |

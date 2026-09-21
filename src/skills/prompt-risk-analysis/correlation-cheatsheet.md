# Correlation cheatsheet (prompt-risk-analysis)

> **Read this first for chaining and follow-up fetches; authoritative specs:**  
> [correlation-matrix.json](../../../dataasset/assets/correlation-matrix.json) · [anchor-patterns.json](../../../dataasset/scenarios/anchor-patterns.json)

Use [analysis-contract.md](analysis-contract.md) to resolve overlapping scenarios and apply parameter, counting, success, WAF coverage, and redaction rules.

## 1. Time windows (cite window id in reports)

| window id | Range | Typical use |
|-----------|-------|-------------|
| `host_behavior_chain` | −5m / +5m | Same-host exec ↔ connect ↔ file_op |
| `attack_success` | −5m / +30m | host_exec after WAF/WEB alert |
| `alert_context` | −10m / +10m | WEB access around WAF alert |
| `alert_confirmation_fetch` | −10m / +30m | S4 default fetch window |
| `lateral_movement` | −30m / +120m | SSH lateral, syslog account + target exec |
| `trace_default` | −24h / +6h | S1/S2/S3 default investigation window |

## 2. Scenario quick pick

| Evidence / user question | Scenario | pattern id | bundle |
|--------------------------|----------|------------|--------|
| `waf_alert`, real attack? | S4 | `S4_alert_confirmation` | `bundle-alert-confirm-min` |
| WebShell / uploads script | S2 | `S2_web_breach` | `bundle-incident-trace-default` |
| External IP → which host | S1 | `S1_external_ip_trace` | `bundle-incident-trace-default` |
| `host_exec` + `syslog_risk_alert` | S5 | `S5_host_risk` | `bundle-host-risk-default` |
| Multi-host SSH / lateral | S3 | `S3_lateral_movement` | `bundle-incident-trace-default` |
| Account compromise / brute success | S6 | `S6_account_compromise` | `bundle-incident-trace-default` |
| Egress / DNS / exfil | S7 | `S7_data_exfiltration` | `bundle-data-exfiltration-default` |

**exec + syslog only (no WAF):** align **S5** first; add **S2 + S3** narrative if web-process shell + cross-host sshpass appear.

## 3. Common join ids

| join id | Left → right | Stage | Notes |
|---------|--------------|-------|-------|
| `waf_to_host_exec_via_web_access` | waf → web → exec | execution | Two-layer S4 confirmation |
| `host_connect_to_dns` | host_connect → dns_log | network_activity | Egress and DNS resolution |
| `web_access_to_host_exec` | web_access → host_exec | execution | WEB then shell on same host |
| `d2_exec_connect_same_listener` | host_exec → host_connect | execution | Exec then egress same listener |
| `d2_exec_file_same_host` | host_exec → host_file_op | execution | File ops after exec |
| `ssh_auth_to_host_exec_same_host` | ssh_auth → host_exec | execution | Commands after SSH login |
| `attacker_ip_to_ssh_auth` | src_ip → ssh_auth | lateral_movement | Attacker IP login attempts |
| `host_ip_to_ssh_auth_lateral` | host → ssh_auth | lateral_movement | SSH activity on victim |
| `lateral_from_exec` | host_exec(A) → host_exec(B) | lateral_movement | Weak cross-host exec link |
| `lateral_from_syslog` | syslog(A) → exec(B) | lateral_movement | Syslog + target exec |

`host_connect_to_dns` establishes network context between an outbound connection and DNS resolution; it does not by itself prove exfiltration. An exfiltration conclusion needs transfer direction, data content/volume, destination and supporting evidence. Otherwise retain an unknown outcome or an explicit hypothesis.

Without a matrix join, label cross-host links `confidence: low` and state hypotheses.

## 4. Chain coverage (`chain_coverage` in output)

- S5: `d2_exec_connect_same_listener` needs host_exec + host_connect; `d2_exec_file_same_host` needs host_exec + host_file_op. Missing connect/file data leaves egress or file-write claims unconfirmed.
- S2: `waf_to_web_access_by_ip` → `web_access_to_host_exec` → `d2_exec_file_same_host` → `d2_exec_connect_same_listener`.
- S3: `attacker_ip_to_ssh_auth` → `host_ip_to_ssh_auth_lateral` → `ssh_auth_to_host_exec_same_host`.

For each gap, record the missing stage, join ID, and suggested asset to fetch.

## 5. Follow-up retrieval

Use an authorized bundle and a local params file with explicit hosts or attacker IP and timezone-qualified `time_start` / `time_end`. The file must not contain credentials. This performs live read-only retrieval; verify scope first. The standard S5 bundle is `bundle-host-risk-default`; S2 uses `bundle-incident-trace-default`, subject to your active asset coverage.

```bash
python3 src/skills/evidence-fetch/scripts/fetch_evidence.py \
  --from-bundle --bundle "${EVIDENCE_BUNDLE_ID:?Set an authorized bundle ID}" \
  --params-file "${EVIDENCE_PARAMS_FILE:?Set a scoped params JSON file}" \
  -o /tmp/secweaver-followup-evidence.json
```

## 6. Field hints

[evidence-minimum-fields.json](../../../dataasset/configure/evidence-minimum-fields.json): `host_ip`/`host_name` → `host`; use both `command_line` and `command` for exec.

Use `listener_process` + `listener_port` to identify ingress context; `rule_name` and `event_type` help correlate syslog with exec.

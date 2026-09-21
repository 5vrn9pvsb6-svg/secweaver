# Data Source Completeness — Examples

## Example 1: SecWeaver scenario requirement — external IP traceability (insufficient data)

### User input

```text
Select all assets
Alert time 2026-06-21 10:00, hacker IP 203.0.113.10
Possibly breached; find first breach point and lateral scope
Tell me what data you lack
```

### Registered assets

```json
{
  "registered_assets": [
    {"asset_id": "waf_01", "type": "waf_alert", "domain": "D1", "fields": ["src_ip", "timestamp", "url", "payload"], "coverage": ["web_zone"]},
    {"asset_id": "ssh_logs", "type": "ssh_auth", "domain": "D3", "fields": ["host", "src_ip", "user", "result", "timestamp"], "coverage": ["partial_internal"]},
    {"asset_id": "cmdb", "type": "asset_inventory", "domain": "D6", "coverage": ["full"]}
  ]
}
```

### Expected output (summary)

```json
{
  "alert_type": "data_source_completeness",
  "scenario": ["S1", "S3"],
  "overall_verdict": "not_traceable",
  "confidence": 0.38,
  "can_trace": false,
  "can_confirm_breach": false,
  "summary": "WAF alerts and partial SSH logs exist, but WEB server host behavior (exec/connect) is missing — cannot confirm breach or SSH tool download; SSH coverage incomplete, lateral scope may be missed.",
  "missing_critical": [
    {
      "source_name": "WEB server process command execution",
      "domain": "D2",
      "priority": "P0",
      "impact_if_missing": "Cannot confirm WebShell or curl/wget SSH brute-force tool download; cannot prove attack success"
    },
    {
      "source_name": "WEB server active outbound connections",
      "domain": "D2",
      "priority": "P1",
      "impact_if_missing": "Cannot link download domains and C2; attack chain lacks egress evidence"
    }
  ],
  "recommendations": [
    {
      "rank": 1,
      "source_name": "WEB server process command execution",
      "priority": "P0",
      "collection_hint": "Deploy audit-port-execmon on WEB servers; monitor 80/443 process exec",
      "expected_gain": "Confirm breach, command chain, download behavior"
    },
    {
      "rank": 2,
      "source_name": "WEB server active outbound connections",
      "priority": "P1",
      "collection_hint": "Enable monitor_connect in audit-port-execmon",
      "expected_gain": "See download tool egress target IP/port"
    },
    {
      "rank": 3,
      "source_name": "Full internal SSH auth logs",
      "priority": "P0",
      "collection_hint": "Extend ssh_auth coverage to all internal Linux servers",
      "expected_gain": "Complete lateral scope, avoid missed hosts"
    },
    {
      "rank": 4,
      "source_name": "Internal firewall traffic",
      "priority": "P1",
      "collection_hint": "Ingest firewall syslog for WEB segment to internal SSH segment",
      "expected_gain": "Visualize WEB→internal SSH path and timing"
    }
  ],
  "next_skill": "traceability_analysis",
  "next_skill_blocked": true,
  "block_reason": "Missing P0 source: host_exec (WEB servers)"
}
```

### Claw should tell the user

> WAF shows attack requests from 203.0.113.10, but **there are no command execution logs on WEB servers**, so breach and curl SSH tool download cannot be confirmed.  
> SSH logs cover only part of internal hosts; lateral scope may be incomplete.  
> **Onboard first**: WEB server exec (audit-port-execmon) → WEB server connect → complete SSH log coverage.

---

## Example 2: External IP traceability (mostly complete data)

### Registered assets

```json
{
  "registered_assets": [
    {"asset_id": "waf_01", "type": "waf_alert", "coverage": ["web_zone"], "fields": ["src_ip", "timestamp", "url", "payload"]},
    {"asset_id": "web_exec", "type": "host_exec", "coverage": ["web-01"], "fields": ["host", "command", "timestamp", "pid"]},
    {"asset_id": "web_connect", "type": "host_connect", "coverage": ["web-01"], "fields": ["dst_ip", "dst_port", "timestamp"]},
    {"asset_id": "ssh_all", "type": "ssh_auth", "coverage": ["full"], "fields": ["host", "src_ip", "user", "result", "timestamp"]},
    {"asset_id": "fw_01", "type": "firewall_log", "coverage": ["dmz_to_internal"]}
  ]
}
```

### Expected output (summary)

```json
{
  "overall_verdict": "full_traceable",
  "confidence": 0.88,
  "can_trace": true,
  "can_confirm_breach": true,
  "summary": "WAF, WEB host exec/connect, full-network SSH, and DMZ firewall are onboarded — supports external IP traceability and lateral analysis.",
  "missing_critical": [],
  "recommendations": [
    {
      "rank": 1,
      "source_name": "WEB server file operations",
      "priority": "P2",
      "collection_hint": "audit-port-execmon monitor_file_ops",
      "expected_gain": "Add WebShell drop paths; improve persistence analysis confidence"
    }
  ],
  "next_skill_blocked": false
}
```

---

## Example 3: WEB alert confirmation — WAF only

### User input

```text
Is this WAF SQLi alert FP or real? Was the server breached?
Alert ID WAF-20260621-001
```

### Registered assets

```json
{
  "registered_assets": [
    {"asset_id": "waf_01", "type": "waf_alert", "fields": ["src_ip", "timestamp", "url", "rule_id"], "gaps": ["no_payload"]}
  ]
}
```

### Expected output (summary)

```json
{
  "scenario": ["S4"],
  "overall_verdict": "alert_triage_only",
  "confidence": 0.35,
  "can_trace": false,
  "can_confirm_breach": false,
  "summary": "WAF alerts only; missing payload and host behavior — alert classification only; cannot confirm attack success or breach.",
  "registered_sources": [
    {
      "asset_id": "waf_01",
      "status": "partial",
      "gaps": ["payload", "request_body"]
    }
  ],
  "recommendations": [
    {
      "rank": 1,
      "source_name": "WAF full request body",
      "priority": "P0",
      "collection_hint": "Enable request body logging on WAF or correlate WEB access logs",
      "expected_gain": "Judge whether SQLi payload is a real injection attempt"
    },
    {
      "rank": 2,
      "source_name": "WEB server process command execution",
      "priority": "P1",
      "collection_hint": "audit-port-execmon on WEB servers",
      "expected_gain": "Confirm whether SQLi led to RCE or follow-on commands"
    }
  ],
  "next_skill": "alert_confirmation",
  "next_skill_blocked": true,
  "block_reason": "WAF missing payload and no D2 host behavior"
}
```

### Allowed vs prohibited conclusions

| Conclusion | Allowed? |
|---|---|
| “Rule matched; suspected SQLi attempt” | ✅ |
| “Real SQL injection attack” | ⚠️ Low confidence; must label |
| “Successfully injected database” | ❌ |
| “Server breached” | ❌ |

---

## Example 4: Host anomalous behavior — audit-port-execmon integration

### User input

```text
nginx on external port 443 just ran bash -c — is data enough for risk analysis?
```

### Registered assets

```json
{
  "registered_assets": [
    {"asset_id": "web_exec", "type": "host_exec", "coverage": ["web-01"]},
    {"asset_id": "web_connect", "type": "host_connect", "coverage": ["web-01"]}
  ]
}
```

### Expected output (summary)

```json
{
  "scenario": ["S5"],
  "overall_verdict": "full_traceable",
  "confidence": 0.85,
  "can_trace": true,
  "summary": "exec and connect onboarded — may start risk identification Skill.",
  "next_skill": "risk-identification",
  "next_skill_blocked": false,
  "recommendations": [
    {
      "rank": 1,
      "source_name": "File operation logs",
      "priority": "P2",
      "collection_hint": "audit-port-execmon monitor_file_ops on 443 listener",
      "expected_gain": "Detect WebShell drops or anomalous files"
    }
  ]
}
```

---

## Example 5: Multiple scenarios combined

### User input

```text
WAF alert + suspected lateral to internal — trace full attack chain
```

### Scenario identification

`["S2", "S3", "S4"]` — WEB intrusion + lateral + alert confirmation

### Merged P0 needs (deduped)

- waf_alert (with payload)
- web_access_log
- host_exec (WEB + jump hosts)
- host_file_op (WEB)
- ssh_auth (full internal)
- firewall_log (WEB→internal)

### Output points

- List merged P0 checklist and each item’s status
- overall_verdict takes strictest scenario result
- recommendations merged by rank, avoid duplicates

---

## Example 6: Insufficient correlation keys

### Problem

WAF has src_ip + time; SSH has host + user + time, but **SSH logs lack src_ip** (local login only)

### Determination

- ssh_auth status = partial
- key_completeness = partial (cannot directly link WAF IP → SSH lateral)
- confidence cap 0.75
- recommendation: SSH logs must record source IP or bridge via firewall_log

```json
{
  "recommendations": [
    {
      "rank": 1,
      "source_name": "SSH auth source IP",
      "priority": "P0",
      "collection_hint": "Ensure auth.log records remote IP; or correlate via firewall WEB→SSH traffic",
      "expected_gain": "Chain WAF attack IP to internal SSH logins"
    }
  ]
}
```

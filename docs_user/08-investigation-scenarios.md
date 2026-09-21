# 08. Investigation Scenarios

**Languages:** English (this page) | [简体中文](08-investigation-scenarios.zh-CN.md)

SecWeaver uses Scenario Patterns to describe common security investigation scenarios. Think of them as “investigation playbooks” for the AI.

---

## Why Investigation Scenarios?

Different questions need different investigation paths.

For example:

- External attacker IP → start from the IP.
- WebShell → start from WAF / Web access / files and commands.
- Lateral movement → start from hosts, accounts, logins, and firewall logs.
- Data exfiltration → start from outbound connections, DNS, traffic, and database audit.

Without defined scenarios, the LLM may investigate differently each time, producing unstable results.

Scenario Patterns tell the system:

```text
What type of investigation is this?
Which field to start from?
What to query first?
What to query next?
Which Join rules to use?
What is the default time range?
```

---

## S1: External IP Traceability

### Good for questions like

```text
Did this attacker IP get in?
Which business did this IP reach first?
Did it cause host anomalies?
Was there subsequent lateral movement?
```

### Common inputs

- `attacker_ip`
- `alert_time`
- `time_start` / `time_end`

### Data commonly queried

- WAF alerts
- Web access logs
- Host command execution
- SSH login
- Firewall logs
- Asset inventory

### Typical chain

```text
Attacker IP
→ WAF alert
→ Web access log
→ Host command execution
→ SSH login / firewall access
→ Impact scope
```

### Output focus

- Whether attack requests occurred.
- Whether traffic reached the application.
- Whether host behavior appeared.
- Whether lateral movement occurred.
- Which host was compromised first.

---

## S2: WEB Intrusion / WebShell

### Good for questions like

```text
Did this Web alert indicate a breach?
Was a WebShell dropped?
Did the host execute commands after the attack request?
```

### Common inputs

- `src_ip`
- `url`
- `alert_time`
- `host`

### Data commonly queried

- WAF alerts
- Web access logs
- Host command execution
- File operations
- Host outbound connections

### Typical chain

```text
WAF alert
→ Web access hit
→ Host command execution
→ File write / outbound connection
```

### Output focus

- False positive or not.
- Whether the attack request reached the backend.
- Whether command execution occurred.
- Whether WebShell files appeared.
- Whether suspicious outbound connections appeared.

---

## S3: Lateral Movement Tracking

### Good for questions like

```text
Did this host access other internal hosts?
Did the attacker move from a Web server to a database?
Did a given IP participate in lateral movement?
```

### Common inputs

- `host`
- `host_ip`
- `user`
- `src_ip`
- `alert_time`

### Data commonly queried

- SSH login
- Firewall logs
- Host command execution
- Asset inventory
- Network / Host information

### Typical chain

```text
Victim host
→ SSH login / firewall access
→ Target host
→ Command execution on target host
→ Impact scope
```

### Output focus

- Whether access crossed hosts.
- Whether access crossed network segments.
- Whether movement went from low-trust to high-trust zones.
- Which accounts were involved.
- What the lateral path was.

---

## S4: Alert Confirmation

### Good for questions like

```text
Is this alert a real attack or a false positive?
Did the attack succeed?
Does this need escalation?
```

### Common inputs

- Alert content
- `src_ip`
- `url`
- `alert_time`
- `rule_id`

### Data commonly queried

- WAF alerts
- Web access logs
- Host command execution
- Host outbound connections
- File operations

### Typical chain

```text
WAF alert
→ Web access context
→ Host execution / files / outbound connections
→ Success determination
```

### Output focus

- False positive or not.
- Real attack or not.
- Attack success or not.
- What the evidence chain is.
- Whether to block, isolate, or continue monitoring.

---

## S5: Host Behavior Risk Identification

### Good for questions like

```text
Are there high-risk commands on this host?
Did externally listening processes run abnormal commands?
Are there suspicious outbound connections or file operations?
```

### Common inputs

- `host`
- `host_ip`
- `time_start` / `time_end`

### Data commonly queried

- Host command execution
- Host outbound connections
- File operations
- Host exposure information

### Typical chain

```text
Externally listening service
→ Command execution
→ Outbound connection / file operation
→ Risk level
```

### Output focus

- Whether high-risk commands exist.
- Whether behavior relates to externally exposed services.
- Whether download, reverse connection, or persistence behavior appeared.
- Risk level and response recommendations.

---

## S6: Account Compromise Tracking

### Good for questions like

```text
Was this account compromised?
Where did this account log in from?
What did it do after login?
```

### Common inputs

- `user`
- `src_ip`
- `host`
- `alert_time`

### Data commonly queried

- SSH login
- Host command execution
- Windows event logs
- Linux system logs
- Asset inventory

### Typical chain

```text
Account
→ Login source
→ Login host
→ Subsequent command execution
→ Lateral movement or impact scope
```

### Output focus

- Whether login was abnormal.
- Whether login source was abnormal.
- Whether the account logged into multiple hosts.
- Whether sensitive commands ran after login.
- Whether the account should be disabled or credentials reset.

---

## S7: Data Exfiltration Tracking

### Good for questions like

```text
Did this host exfiltrate data outward?
Was there abnormal high-volume outbound traffic?
Was database data accessed and then exfiltrated?
```

### Common inputs

- `host`
- `host_ip`
- `dst_ip`
- `domain`
- `time_start` / `time_end`

### Data commonly queried

- Host outbound connections
- DNS logs
- Network traffic audit
- Database audit
- File operations

### Typical chain

```text
Host
→ DNS resolution
→ Outbound session
→ Large-volume transfer
→ Database access / file access
```

### Output focus

- Whether suspicious external IPs or domains were accessed.
- Whether abnormal high-volume traffic appeared.
- Whether sensitive database access occurred.
- Whether compression, packaging, or upload behavior appeared.
- Whether evidence is sufficient to confirm exfiltration.

---

## S8: C2 Communication Detection

### Good for questions like

```text
Could this host's suspicious outbound connections be related to C2 communication?
Can a reverse-shell command be linked to its outbound destination?
Can these DNS queries explain a suspicious callback domain?
```

### Common inputs

- `host` / `host_ip`
- `dst_ip` / `domain`
- `time_start` / `time_end` (start and end times with a timezone)

### Data commonly queried

- P0: Host outbound connections (`host_connect`) with at least `host`, `dst_ip`, `dst_port`, and `timestamp`.
- P1: Network traffic audit or proxy logs, DNS logs, and host command execution for session, domain, and process context.
- P2: System risk alerts for additional host context.

P0/P1/P2 are data-completeness requirement priorities. See [Data Source Completeness Analysis](15-data-source-completeness.md) for the field requirements.

### Typical chain

```text
Host outbound connection
→ Destination IP / domain
→ DNS and traffic / proxy session context
→ Same-host command execution and system risk alerts
```

### Skill entry point and output focus

Run `data-source-completeness` for S8 first, then use
[`risk-identification`](19-risk-identification.md) when the assessment is not blocked.
Hand off to traceability analysis when a cross-host attack chain needs investigation.

- Cite suspicious connections and related commands, with severity and investigation recommendations.
- Distinguish observed risks from C2 suspicions requiring more evidence; a connection or domain alone does not prove host compromise.
- DNS adds resolution context; it cannot replace session direction, byte counts, or proxy actions.
- Onboard missing P0 data first; no detections do not establish that the host is safe.

---

## Scenarios and Data Sources

| Scenario | Most critical data sources |
|---|---|
| S1 External IP traceability | WAF, Web, host execution, SSH, firewall |
| S2 WEB intrusion | WAF, Web, host execution, files, outbound connections |
| S3 Lateral movement | SSH, firewall, host execution, asset inventory |
| S4 Alert confirmation | WAF, Web, host execution, files, outbound connections |
| S5 Host risk | Host execution, outbound connections, files, host exposure |
| S6 Account compromise | SSH, system logs, host execution |
| S7 Data exfiltration | Outbound connections, DNS, traffic, DB audit, files |
| S8 C2 communication detection | Host outbound connections, traffic or proxy logs, DNS, host execution, system risk alerts |

---

## How to Choose a Scenario

If you are unsure, use these cues:

| Clue in hand | Recommended scenario |
|---|---|
| An attacker IP | S1 |
| A WAF alert | S4 or S2 |
| A suspicious URL | S2 |
| An abnormal host | S5 or S3 |
| An account | S6 |
| An outbound IP / domain associated with suspected data uploads | S7 |
| Suspicious callbacks, reverse shells, or C2 IPs / domains | S8; add S7 when exfiltration is also suspected |
| Full attack-chain investigation | S1 + S2 + S3 |

The LLM can help choose a scenario, but what you can actually query depends on configured data assets.

---

## Next Steps

Continue reading: [09. Operations Checks and Troubleshooting](09-operations-troubleshooting.md)

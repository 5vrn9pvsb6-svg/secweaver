# Data Source Completeness Analysis

**Languages:** English (this page) | [简体中文](15-data-source-completeness.zh-CN.md)

> SecWeaver Skill documentation
> Purpose: Before incident traceability or deep alert confirmation, check whether onboarded data sources are sufficient and provide onboarding recommendations  
> Agent Skill: `src/skills/data-source-completeness/SKILL.md`  
> Assessment script: `src/skills/data-source-completeness/scripts/check.py`

---

## First Experience: What Happens When Evidence Is Missing?

After `make quickstart`, ask your intelligent agent:

```text
Run the SecWeaver offline case missing-host-exec-data.
Explain which evidence is missing, which conclusions are blocked, and what to onboard first.
```

The [fixed missing-exec fixture](../examples/data-source-completeness/s1-not-traceable-missing-exec.json)
expects `overall_verdict=not_traceable`, `can_trace=false`, and `can_confirm_breach=false`.
JSON is saved to `outputs/ai-showcase/missing-host-exec-data.json`, with the AI report beside it.
A gap report is the correct result here, not a product error; do not bypass the gate to force a chain.

Without a host, `make ai-showcase CASE=missing-host-exec-data` generates JSON and a readable structured-result Markdown report by default.
For live use, [onboard data](30-sls-proxy-onboarding.md), then specify real Asset/Bundle IDs and
a timezone-aware window. Fixture values do not identify your production assets.
The remaining sections explain the assessment rules.

### Exact host coverage

For `target_hosts` and `jump_hosts`, when both the asset and investigation enumerate hosts,
coverage uses set membership: all requested hosts → `full`, some → `partial`, none → `none`.
A matching `coverage.hosts` needs no extra zone label. Explicit host lists constrain broad
zone labels; they do not imply coverage of the whole network. Without explicit investigation
hosts, legacy zone-based checks remain available. A source's full host coverage does not make
the entire investigation complete: required fields, other sources and query integrity still apply.

## 1. Skill Scope

### 1.1 What Problem It Solves

Common traceability challenges:

| Symptom | Root cause |
|---|---|
| Known external attacker IP but cannot determine lateral scope | Missing SSH logs or WEB host exec |
| WAF alert but unknown whether breach occurred | Missing host behavior data (D2) |
| AI concludes "confirmed intrusion" without evidence | Drawing conclusions despite insufficient data |

Before investigation starts, this Skill answers three questions:

1. **How far can existing data take the investigation?**
2. **What data sources are missing? What cannot be found without them?**
3. **Which sources should be onboarded first? How?**

### 1.2 Position Among the Six Core Capabilities

```text
Asset/data management → [Data source completeness analysis] → Traceability / Alert confirmation / Risk identification
```

**Principle:** When P0 data sources are missing, **block** downstream traceability Skills to avoid overconfident wrong conclusions.

---

## 2. Dialog Usage

### 2.1 Basic Steps

1. Specify the registered assets or Bundle, target, and time window in your intelligent agent
2. Choose Skill: **Data source completeness analysis** (or describe intent in natural language)
3. Fill in investigation parameters, for example:

```text
Alert time 2026-06-21 10:00, attacker IP 203.0.113.10
Possible breach — find first compromise point and lateral scope
Tell me what data I'm missing
```

### 2.2 Output

The intelligent agent produces two parts:

- **Structured JSON**: for platform pipelines, reports, and downstream Skills
- **Markdown summary**: for security analysts to read directly

---

## 3. Investigation Scenarios

| ID | Scenario | Typical phrasing |
|---|---|---|
| S1 | External attacker IP traceability | Known attacker IP — find breach point and lateral movement |
| S2 | WEB intrusion traceability | WebShell, exploit, website compromise |
| S3 | Lateral movement investigation | SSH/RDP internal spread |
| S4 | WEB alert confirmation | WAF alert — false positive or real attack |
| S5 | Host anomalous behavior | External listener process exec/connect |
| S6 | Account compromise | Abnormal login, brute force |
| S7 | Data exfiltration | Bulk download, abnormal outbound connections |
| S8 | C2 communication detection | Suspicious callbacks, reverse shells, C2/DGA domains |

Scenarios can be combined; the agent merges P0 requirements and applies the strictest conclusion.

### S8 data requirements

These requirements match `src/skills/data-source-completeness/scenarios.json`:

| Priority | Asset type | Minimum fields |
|---|---|---|
| P0 | `host_connect` | `host`, `dst_ip`, `dst_port`, `timestamp` |
| P1 (either source) | `network_traffic_audit` or `proxy_log` | Traffic audit: `src_ip`, `dst_ip`, `dst_port`, `bytes`, `timestamp`; proxy: `src_ip`, `dst_ip`, `timestamp` |
| P1 | `dns_log` | `client_ip`, `query`, `timestamp` |
| P1 | `host_exec` | `host`, `command`, `timestamp` |
| P2 | `syslog_risk_alert` | `host_ip`, `event_type`, `timestamp` |

Missing P0 data blocks downstream analysis; missing P1 data must be reported as coverage limits. DNS cannot replace network session evidence.

---

## 4. Data Domains and Asset Types

### 4.1 Seven Data Domains

| Domain | Description | Typical sources |
|---|---|---|
| D1 | Perimeter and WEB | WAF, CDN, WEB access logs |
| D2 | Host behavior | exec, connect, file, EDR |
| D3 | Authentication access | SSH, VPN, AD, bastion |
| D4 | Network | Firewall, NetFlow, DNS, proxy |
| D5 | Security alerts | IDS, SOC platform |
| D6 | Asset configuration | CMDB, vulnerability scans |
| D7 | Application business | Application logs, DB audit |

### 4.2 SecWeaver Supported Asset Types

| asset_type | Name | Collection method |
|---|---|---|
| `waf_alert` | WAF/WEB security alerts | Product API/syslog |
| `web_access_log` | WEB access logs | Nginx/Apache/IIS |
| `host_exec` | Host command execution | **audit-port-execmon** |
| `host_connect` | Host active outbound connections | **audit-port-execmon** (connect) |
| `host_file_op` | Host file operations | **audit-port-execmon** (file_op) |
| `windows_event_log` | Windows system/security/application event logs | Winlogbeat, WEF, NXLog → SLS |
| `linux_syslog` | Linux system/syslog logs | rsyslog, journald, Filebeat → SLS |
| `ssh_auth` | SSH authentication logs | auth.log / journald |
| `firewall_log` | Firewall logs | syslog / NetFlow |
| `network_traffic_audit` | Full traffic audit (NDR/TAP sessions/flows) | NDR platform, TAP mirror analysis → SLS/ES |
| `dns_log` | DNS queries | DNS server / security gateway |
| `asset_inventory` | Asset inventory | CMDB |

---

## 5. Four Dimensions of Completeness Assessment

For each registered data source, evaluate:

| Dimension | Description |
|---|---|
| **Coverage** | Whether all hosts/network segments involved in the investigation have data |
| **Correlation keys** | Whether src_ip, host, timestamp, etc. can join across sources |
| **Time window** | Whether the investigation period is covered (default: 24h before ~ 6h after alert) |
| **Field granularity** | e.g. whether WAF includes payload, whether SSH includes src_ip |

Per-item verdict: `ready` / `partial` / `missing`

---

## 6. Walkthrough: External IP Traceability

### 6.1 Incident Background

- WEB server (with WEB security logs) + internal SSH servers
- Attack chain: WebShell → curl downloads SSH brute-force tool → SSH lateral movement
- Known: external attacker IP, event time A

### 6.2 P0 Minimum Requirements

| Data source | Purpose |
|---|---|
| WAF/WEB logs | Confirm attacker IP first appearance, hit URL |
| **WEB host exec** | Confirm WebShell, curl/bash download |
| SSH auth logs | Track lateral logins |

### 6.3 With Only WAF + Partial SSH

The intelligent agent should output:

```markdown
## Data Source Completeness Assessment

**Verdict**: Cannot fully trace (missing P0: WEB server process command execution)

### Critical Gaps
1. **WEB server process command execution** (P0)
   - Without it: cannot confirm WebShell, curl downloading SSH tools, cannot prove breach
   - Recommendation: deploy audit-port-execmon on the WEB server

### Next Steps
Onboard WEB host exec before starting traceability analysis.
```

---

## 7. Overall Verdict Reference

These verdicts assess registered metadata, not events returned for the current
investigation. After fetching, also inspect `fetch_summary.evidence_readiness`
and `query_integrity`: even `full_traceable` metadata can accompany `no_evidence`
or `partial` evidence. The attached precheck labels this distinction with
`assessment_basis=registry_metadata` and `metadata_readiness`; legacy fields stay
compatible. A successful empty query is not a failure, but cannot support a clean
security conclusion. Unqueried declared assets are marked `not_queried`.

| overall_verdict | Meaning | Action |
|---|---|---|
| `full_traceable` | Registry requirements met | Fetch and check actual evidence before traceability conclusions |
| `partial_traceable` | Partially traceable | Start traceability, note confidence ceiling |
| `not_traceable` | P0 missing | **Onboard data first** |
| `alert_triage_only` | WEB/WAF only | Alert classification only — cannot prove breach |

---

## 8. Deterministic Assessment Script

Platform or pipeline can call the Python script using the same `scenarios.json` as the intelligent agent:

```bash
.venv/bin/python src/skills/data-source-completeness/scripts/check.py \
  -i src/skills/data-source-completeness/scripts/input.example.json
```

See `src/skills/data-source-completeness/scripts/input.example.json` for input examples.

---

## 9. Downstream Skill Handoff

| Upstream conclusion | Downstream Skill |
|---|---|
| S1/S2/S3/S6/S7 and not blocked | Traceability analysis (`traceability-analysis`) |
| S4 and not blocked | Alert confirmation (`alert-confirmation`) |
| S5 and not blocked | Risk identification (`risk-identification`), for host anomalies |
| S8 and not blocked | Risk identification (`risk-identification`), for C2 communication risks |
| blocked | Onboarding recommendations only — do not start downstream |

The table uses Skill directory names; the script emits `traceability_analysis` and
`alert_confirmation` in `next_skill` for traceability and alert confirmation. For multiple
scenarios, it selects the first configured handoff in input order. Always check
`next_skill_blocked`, even when `next_skill` is populated; a suggested entry point is not permission to execute it.

---

## 10. Related Files

| File | Description |
|---|---|
| `src/skills/data-source-completeness/SKILL.md` | Intelligent-agent entry point |
| `src/skills/data-source-completeness/rules.md` | P0/P1/P2 rule matrix |
| `src/skills/data-source-completeness/scenarios.json` | Machine-readable scenario requirements |
| `src/skills/data-source-completeness/examples.md` | Input/output examples |
| [data-source-completeness-skill-design.md](../docs_dev/13-data-source-completeness-skill-design.md) | Detailed design document |
| `src/skills/data-source-completeness/scripts/check.py` | Deterministic assessment script |

---

*Document version: v1.1 | Updated: 2026-09-16*

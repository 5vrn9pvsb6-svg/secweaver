# Data Source Completeness Analysis Skill Design

> Public cases and inputs/outputs are in the [Skill examples](../src/skills/data-source-completeness/examples.md); no internal product-planning material is required.

**Languages:** English (this document) | [简体中文](13-data-source-completeness-skill-design.zh-CN.md)

> One of SecWeaver's six core capabilities  
> Purpose: Before **cyber incident traceability** or **deep alert confirmation**, check whether onboarded data sources are sufficient for analysis and recommend missing sources

---

## 1. Skill Positioning

### 1.1 Problem Solved

Security teams starting investigations often face:

- "Only WAF alerts — don't know if we were breached"
- "Know the external attacker IP but can't see lateral movement to which machines"
- "Have SSH failure logs but don't know which Web server was the initial entry"

Root cause is often not "AI can't analyze" but **incomplete data sources, missing correlation keys, or insufficient time windows**.

This Skill's job:

```text
Input: investigation scenario + registered data asset list + (optional) investigation params (attack IP, time, hosts)
Output: completeness assessment + whether trace/confirmation is feasible + missing source list + onboarding priority recommendations
```

### 1.2 Relation to Other Skills

| Order | Skill | Relation |
|---|---|---|
| 1 | **Data source completeness analysis** | First answer "can we investigate?" |
| 2 | Alert confirmation | False positive vs real attack only if data is sufficient |
| 3 | Traceability analysis | Reconstruct attack chain only if data is sufficient |
| 4 | Risk identification | Host-side exec/connect is part of completeness |

---

## 2. Investigation Scenario Model

Claw first identifies user intent (may be multiple):

| Scenario ID | Name | Typical user phrasing |
|---|---|---|
| `S1` | External attack IP trace | Known attacker IP; find breach point and lateral scope |
| `S2` | WEB intrusion trace | WebShell, exploit, site defacement |
| `S3` | Lateral movement investigation | SSH/RDP/SMB spread inside network |
| `S4` | WEB alert confirmation | WAF/WEB alert — real attack? successful? |
| `S5` | Host anomaly investigation | Commands from external listener processes, active outbound connections |
| `S6` | Account compromise investigation | Abnormal login, brute force, privileged accounts |
| `S7` | Data exfiltration investigation | Bulk download, abnormal egress, sensitive file archiving |
| `S8` | C2 communication detection | Suspicious callbacks, reverse shells, C2/DGA domains |

---

## 3. Data Source Taxonomy (Standard Inventory)

### 3.1 Seven Data Domains

| Domain | Description | Typical sources |
|---|---|---|
| **D1 Perimeter & WEB** | External attack entry | WAF, CDN, load balancer, WEB access/error logs |
| **D2 Host behavior** | What happened on servers | exec commands, active connections, file create/delete, EDR |
| **D3 Authentication & access** | Who logged into whom | SSH/auth.log, VPN, AD, bastion, RADIUS |
| **D4 Network traffic** | Who connected to whom | Firewall, NetFlow/sFlow, full packet capture, DNS, proxy |
| **D5 Security alerts** | Product conclusions | IDS/IPS, HIDS, AV, SOC platform alerts |
| **D6 Assets & configuration** | Context | CMDB, asset inventory, port/services, vulnerability scans |
| **D7 Application & business** | Business-side evidence | App logs, database audit, API gateway |

### 3.2 SecWeaver Deployed / Planned Sources

| Source | Domain | Collection | Correlation keys |
|---|---|---|---|
| WEB security alerts / WAF | D1/D5 | Product integration | src_ip, time, url, rule_id |
| Process command exec | D2 | audit-port-execmon | host, pid, time, command |
| Process active connect | D2 | audit-port-execmon | host, pid, dst_ip, dst_port, time |
| File create/delete file_op | D2 | audit-port-execmon | host, path, time, pid |
| SSH authentication logs | D3 | syslog/rsyslog | host, src_ip, user, time, result |
| Firewall / perimeter logs | D4 | syslog/API | src_ip, dst_ip, port, time |
| DNS logs | D4 | Dedicated collection | query, client_ip, time |
| Asset inventory | D6 | CMDB / manual registration | hostname, ip, owner, zone |

---

## 4. Completeness Assessment Dimensions

For each registered source, assess four dimensions:

| Dimension | Description | Levels |
|---|---|---|
| **Coverage** | Relevant hosts/segments/business covered | full / partial / missing |
| **Keys** | Can correlate with IP, time, host, user | complete / partial / missing |
| **Time** | Covers investigation period ± buffer | sufficient / insufficient / unknown |
| **Granularity** | Fields sufficient for analysis (e.g. WAF has payload) | sufficient / insufficient / unknown |

### 4.1 Minimum Correlation Key Requirements

Traceability needs at least **3 of**:

```text
src_ip (attack source)
dst_ip / host (victim target)
timestamp (unified timezone, second precision)
user / account (account dimension)
process / command (host behavior)
session / flow (network session)
```

---

## 5. Scenario × Data Source Requirement Matrix

### S1 External Attack IP Trace (public investigation example)

**Event**: Attacker IP A, time A, possibly breached — find first compromise point + lateral scope.

| Priority | Required source | Purpose | Impact if missing |
|---|---|---|---|
| P0 | WEB/WAF logs (D1) | Confirm Web hits, first seen time | Cannot locate entry |
| P0 | WEB server host exec (D2) | Confirm WebShell, curl/wget downloads | Cannot prove breach |
| P0 | SSH auth logs (D3) | Lateral login, brute force | Cannot track lateral movement |
| P1 | Host active connect (D2) | Tool download, C2 egress | Incomplete attack chain |
| P1 | Firewall / internal traffic (D4) | Web→internal SSH connections | Unclear lateral path |
| P1 | DNS logs (D4) | Download domains, C2 domains | Only see IPs |
| P2 | File operation file_op (D2) | WebShell drop path | Hard to prove persistence |
| P2 | EDR (D2) | Unified host behavior view | Depends on single tool |
| P2 | Asset inventory (D6) | Which SSH servers exist | Incomplete lateral scope |

**Minimum viable analysis (MVP)**:

> WAF/WEB logs + WEB host exec + at least one SSH auth log + unified time window

---

### S4 WEB Alert Confirmation

| Priority | Required source | Purpose |
|---|---|---|
| P0 | WEB/WAF alert with payload | Judge real attack payload |
| P0 | WEB access logs | Request context around alert |
| P1 | WEB host exec/connect | Confirm attack success (shell, egress) |
| P1 | File operations | WebShell landed |
| P2 | Vulnerability scan/assets | Component version for attacked URL |

---

### S5 Host Anomaly (audit-port-execmon integration)

| Priority | Required source | Purpose |
|---|---|---|
| P0 | Process command exec | Core analysis object |
| P1 | Active connect | Download, C2 |
| P1 | File operation file_op | WebShell, drops |
| P2 | WEB/WAF | Explain "what triggered abnormal command" |

---

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

When S8 is not blocked, `next_skill_map` points to `risk-identification`; consumers must
respect `next_skill_blocked`. See [S8 investigation scenarios](../docs_user/08-investigation-scenarios.md#s8-c2-communication-detection) for example questions and evidence chains.

---

## 6. Completeness Scoring Model

### 6.1 Per-Source Status

| Status | Meaning |
|---|---|
| `ready` | Onboarded and meets scenario needs |
| `partial` | Onboarded but coverage/fields/time window insufficient |
| `missing` | Scenario needs but not onboarded |
| `optional` | Nice to have; analysis can degrade without |

### 6.2 Overall Scenario Conclusion

This table follows [overall_verdict](../src/skills/data-source-completeness/scripts/check.py) in evaluation order. These are precheck enums, not attack verdicts.

| Order | Condition | Result and downstream behavior |
|---|---|---|
| 1 | Any P0 is `missing` | `not_traceable`; block downstream |
| 2 | S4 is selected, WAF/WEB assets exist, but no D2 assets exist | `alert_triage_only`; block automatic handoff; any separate alert triage must state its limitations |
| 3 | Every P0 is `ready` or `partial`, P1 count is greater than zero, and `(P1_ready + 0.5 × P1_partial) / P1_total ≥ 0.8` | `full_traceable`; allow scenario-specific handoff |
| 4 | Every P0 is `ready` or `partial`, but the previous condition is not met | `partial_traceable`; analyze with explicit gaps |
| 5 | Otherwise | `not_traceable`; block downstream |

A `partial` P0 is not `missing` and does not by itself block analysis. `full_traceable` does not guarantee that every field or coverage requirement is complete. Consumers must still show per-requirement gaps and check `next_skill_blocked`. Zero P1 requirements do not qualify for row 3.

### 6.3 Confidence

```text
P0_ready_rate = P0_ready / max(P0_total, 1)
P1_weighted_rate = (P1_ready + 0.5 × P1_partial) / max(P1_total, 1)
confidence = round(clamp(0.40 × P0_ready_rate + 0.35 × P1_weighted_rate
                        + 0.15 × key_score + 0.10 × time_score, 0, 1), 2)
if key_score < 0.7: confidence = min(confidence, 0.75)
```

A `partial` P0 passes the gate but does not count toward P0_ready in the score; a `partial` P1 counts as half a requirement. `key_score` measures registered correlation-field coverage. `time_score` is `0.6` when any requirement has `retention_insufficient`, otherwise `1.0`. This score is not an attack probability.

**Scoring example**: For S8, the single P0 is `partial`, all three P1 requirements are `ready`, `key_score=1`, `time_score=1`, and `host_connect` is registered. The result is `full_traceable`, `next_skill_blocked=false`, and confidence `0.60`. The P0 gap must still be shown; changing that requirement to `missing` takes the blocking branch first.

---

## 7. Claw Assessment Workflow

```text
1. Parse investigation intent → match scenarios S1–S8 (may be multiple)
2. Read user-selected "registered data assets" list
3. Extract params: attack IP, time range, hosts/business, alert ID, etc.
4. Compare scenario matrix item by item: ready / partial / missing
5. Check correlation keys: can src_ip, host, timestamp join across sources?
6. Check time window: covers [T-Δ, T+Δ] (default alert −24h ~ +6h)
7. Output overall verdict + missing list + prioritized onboarding recommendations
8. If user asks "what data is missing" → list explicitly with "what you cannot find without it"
```

---

## 8. Onboarding Recommendation Template

Each recommendation includes:

| Field | Description |
|---|---|
| `source_name` | Recommended source name |
| `domain` | D1–D7 |
| `priority` | P0/P1/P2 |
| `reason` | Why needed |
| `impact_if_missing` | What cannot be determined |
| `collection_hint` | How to onboard (product/API/auditd/syslog) |
| `correlation_keys` | Keys provided after onboarding |
| `tiger_brain_asset_type` | Suggested platform asset_type |

### Example Recommendation

```json
{
  "source_name": "WEB server process command execution",
  "domain": "D2",
  "priority": "P0",
  "reason": "S1 external IP trace needs to confirm curl/bash after Web breach",
  "impact_if_missing": "Cannot prove attack success — only WAF alerts, no attack chain",
  "collection_hint": "Deploy audit-port-execmon on Linux hosts with exec monitoring enabled",
  "correlation_keys": ["host", "timestamp", "pid", "command"],
  "tiger_brain_asset_type": "host_exec"
}
```

---

## 9. Claw Output JSON Template

The following is an actual output excerpt from the current assessment script using the [public synthetic sample missing P0 host execution data](../examples/data-source-completeness/s1-not-traceable-missing-exec.json). It retains the verdict, missing requirements, and downstream gate. The full output also contains per-requirement assessments, registered assets, onboarding recommendations, and other fields.

After `make quickstart`, run this from the repository root:

```bash
make ai-showcase CASE=missing-host-exec-data
```

Inspect `outputs/ai-showcase/missing-host-exec-data.json`. This command produces deterministic JSON; an agent must generate the investigation report separately according to the Skill. This example uses S1 only, and its numerical values apply only to this fixed sample. Chinese labels below are retained verbatim from the script output.

```json
{
  "alert_type": "data_source_completeness",
  "scenario": [
    "S1"
  ],
  "overall_verdict": "not_traceable",
  "confidence": 0.38,
  "can_trace": false,
  "can_confirm_breach": false,
  "missing_critical": [
    {
      "source_name": "WEB 服务器进程命令执行",
      "priority": "P0",
      "requirement_id": "S1-P0-exec",
      "impact_if_missing": "无法确认 WebShell、curl/wget 下载、命令执行链，不能证明攻击成功"
    },
    {
      "source_name": "WEB 服务器主动外连",
      "priority": "P1",
      "requirement_id": "S1-P1-connect",
      "impact_if_missing": "无法关联下载域名与 C2，攻击链缺少外连证据"
    },
    {
      "source_name": "防火墙/全流量内网连接",
      "priority": "P1",
      "requirement_id": "S1-P1-fw",
      "impact_if_missing": "无法可视化内网连接路径（如 WEB→SSH）"
    },
    {
      "source_name": "DNS 查询日志",
      "priority": "P1",
      "requirement_id": "S1-P1-dns",
      "impact_if_missing": "只能看到 IP 无法解析下载/C2 域名"
    }
  ],
  "next_skill": "traceability_analysis",
  "next_skill_blocked": true,
  "block_reason": "缺少 P0 数据源: WEB 服务器进程命令执行"
}
```

`next_skill` identifies the suggested follow-up Skill and can remain populated even when blocked; callers must check `next_skill_blocked` first. Missing P0 data makes `can_trace=false` and `can_confirm_breach=false`, with a `block_reason`. A Skill name or nonzero confidence does not authorize an automatic handoff. This result assesses data completeness, not whether an attack occurred.

---

## 10. Public Scenarios and Acceptance Examples

### Practical: External IP Trace (S1 + S3)

User actions:

```text
Select all assets
Alert time A, attacker IP A, possibly breached
Analyze first compromise point + lateral attack events
Tell me what data I'm missing
```

Claw should output:

1. Which current assets satisfy S1+S3
2. Explicitly: "Missing WEB host exec — cannot confirm curl download of SSH tools"
3. Explicitly: "Missing full internal SSH coverage — lateral conclusions may be incomplete"
4. Recommendations for audit-port-execmon, SSH syslog, firewall onboarding
5. If P0 missing → `next_skill_blocked: true`, suggest onboarding before traceability Skill

### Practical: WEB Alert Confirmation (S4)

Claw first checks:

- Does WAF have payload field?
- Is there WEB host exec proving attack success?
- Without D2 → conclusion can only be "suspected real attack, cannot confirm success"

---

## 11. One-Sentence Summary

**Data source completeness analysis Skill = pre-investigation "health check"**: tell security teams how far current data can take the investigation, what's missing, and what to onboard first — then decide whether to start traceability or alert confirmation, avoiding overconfident wrong conclusions when data is insufficient.

---

*Document version: v1.2 | Last updated: 2026-09-16*

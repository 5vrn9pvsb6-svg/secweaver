**Languages:** English (this page) | [简体中文](22-scenario-patterns.zh-CN.md)

# Scenario Patterns (Investigation Scenario Orchestration)

> Machine-readable config: [`dataasset/scenarios/anchor-patterns.json`](../dataasset/scenarios/anchor-patterns.json)  
> Join rule source: [`dataasset/assets/correlation-matrix.json`](../dataasset/assets/correlation-matrix.json)  
> Correlation engine: `src/skills/_shared/data-access/correlation_engine.py`  
> Related docs: [21-cross-source-field-correlation.md](21-cross-source-field-correlation.md), [historical correlation-matrix assessment](../docs_dev/history/22-correlation-matrix-design-evaluation.md), [data-asset-design.md](../docs_dev/09-data-asset-design.md)

> This page is a scenario configuration and implementation reference. Start with the [user quickstart](00-security-operator-quickstart.md); use the [Skills usage guide](06-skills-and-usage.md) for skill selection and invocation.

---

**Reading by task:** Jump to the relevant section; reading every section in order is optional.

- [5. Configuration Structure](#5-configuration-structure)
- [6. Field Semantics](#6-pattern-field-semantics)
- [7. Currently Defined Scenarios](#7-currently-defined-scenarios)
- [8. How Scenario Patterns Are Consumed at Runtime](#8-how-scenario-patterns-are-consumed-at-runtime)
- [11. Validation Rules](#11-validation-rules)

## 1. What It Is

`Scenario Patterns` is SecWeaver's **investigation scenario orchestration layer**.

It does not define fields directly, does not define Join rules directly, and does not connect to data sources directly. Instead it answers a higher-level question:

> When a user asks a certain class of security investigation question, which field should the system use as the investigation anchor, which assets should it pull, along which Join chain should it stitch evidence, and what is the default time window?

In other words:

```text
User question / Skill scenario
        ↓
Scenario Pattern (investigation playbook)
        ↓
Select asset bundle + default investigation window + recommended Join chain
        ↓
Join rules in correlation-matrix
        ↓
fetch evidence + correlate_bundles
        ↓
join_edges / data_gaps / attack_chain / alert verdict
```

If `correlation-matrix.json` is the **Join contract** for "how evidence connects," then `anchor-patterns.json` is the **investigation playbook** for "in what order to run these Joins for a given investigation task."

---

## 2. Why It Matters

Security investigation is not simply "query some logs." Different investigation scenarios have different starting points, evidence priorities, and stopping conditions.

For example:

- External IP traceability: start from `src_ip`, first WAF / WEB, then host execution, then SSH lateral movement and firewall.
- WEB alert confirmation: start from WAF alert, first judge payload, then confirm breach with WEB access and host behavior.
- Host risk identification: start from `host`, focus only on exec/connect/file behavior chains on that host.

Without `Scenario Patterns`, each Skill or Agent might decide investigation order on its own, causing several problems:

| Problem | Consequence |
|---|---|
| Investigation chains scattered across prompts / scripts | Same event yields different conclusions in different Skills |
| AI freely chooses Join order | Easy to miss key evidence or fabricate correlations |
| Asset bundles and investigation windows not fixed | Inconsistent fetch scope, hard to review |
| Scenarios coupled to Join rules | Adding scenarios or adjusting strategy requires changing underlying Join rules |
| No unified expression when evidence is missing | Cannot reliably produce `data_gaps`, hurting credibility |

Therefore the core value of `Scenario Patterns` is:

1. **Codify investigation experience as machine-readable configuration**.
2. **Let different Skills reuse the same investigation playbook**.
3. **Restrict AI to reasoning only along declared Join chains**.
4. **Turn "cannot find" explicitly into `data_gaps` instead of fabricating attack chains**.
5. **Chain completeness assessment, fetch, correlation, and report output into one pipeline**.

---

## 3. Position in the Data Source System

SecWeaver's current data source and investigation orchestration can be understood as five layers:

```text
L1 Asset / Connector / Host
  What each data source is, how to connect, which host it belongs to
        ↓
L2 Normalizer / Field Aliases
  Normalize source fields to canonical evidence
        ↓
L3 Correlation Matrix
  Which two evidence types can Join, with which fields and time window
        ↓
L4 Scenario Patterns
  Which Joins a scenario uses, in what chain, default time window
        ↓
L5 Skill / Report
  Alert confirmation, traceability analysis, risk identification, completeness recommendations
```

Corresponding files:

| Layer | File | Question answered |
|---|---|---|
| L1 asset layer | `dataasset/assets/asset-*.json` | What is the data, what are the fields, how to normalize |
| L1 connector layer | `dataasset/connectors/conn-*.json` | How to connect to backend data sources |
| L1 host layer | `dataasset/hosts/host-*.json` | Which host, IP/hostname/zone/role |
| L2 field normalization | `dataasset/configure/evidence-minimum-fields.json` + `asset.field_aliases` | How source fields become canonical fields |
| L3 correlation matrix | `dataasset/assets/correlation-matrix.json` | How evidence Joins |
| L4 scenario orchestration | `dataasset/scenarios/anchor-patterns.json` | Which chain to run for a given investigation class |
| L5 execution consumption | `correlation_engine.py`, alert confirmation / traceability / risk identification Skills | Produce join_edges, data_gaps, investigation conclusions |

---

## 4. Boundary with Correlation Matrix

`Scenario Patterns` and `Correlation Matrix` must have clear division of labor.

| Object | Responsible for | Not responsible for |
|---|---|---|
| `correlation-matrix.json` | Define Join rules, Join fields, time windows, fetch_plan | Decide complete investigation chain for a scenario |
| `anchor-patterns.json` | Define scenario, anchor, recommended Join chain, default investigation window, asset bundle | Define Join field details; do not duplicate field aliases |

Typical relationship:

```text
anchor-patterns.json
  patterns.S4_alert_confirmation.recommended_chain
    ├── waf_to_web_access_by_ip
    ├── waf_to_host_exec_via_web_access
    ├── d2_exec_connect_same_listener
    └── d2_exec_file_same_host

correlation-matrix.json
  cross_source_joins / internal_joins
    ├── waf_to_web_access_by_ip left/right asset_type, join_keys, time_window, fetch_plan
    ├── web_access_to_host_exec left/right asset_type, join_keys, time_window, fetch_plan
    └── d2_exec_connect_same_listener left/right asset_type, join_keys, time_window
```

That is, `Scenario Patterns` only references Join IDs; it does not copy Join rules.

This brings two benefits:

1. One Join can be reused by multiple scenarios.
2. Adjusting investigation order does not require changing underlying field correlation logic.

---

## 5. Configuration Structure

Current configuration structure:

```json
{
  "version": "1.0",
  "description": "SecWeaver investigation scenario orchestration...",
  "patterns": {
    "S1_external_ip_trace": {
      "label": "External IP traceability",
      "investigation_window": "trace_default",
      "anchor": {
        "field": "src_ip",
        "field_variants": ["ip", "client_ip"],
        "from": "params.attacker_ip",
        "fallback_asset_types": ["waf_alert", "web_access_log"]
      },
      "recommended_chain": [
        "waf_to_web_access_by_ip",
        "web_access_to_host_exec"
      ],
      "bundle_id": "bundle-incident-trace-default"
    }
  }
}
```

### 5.1 Top-Level Fields

| Field | Type | Description |
|---|---|---|
| `version` | string | Scenario orchestration config version |
| `description` | string | Config purpose description |
| `patterns` | object | All investigation scenario orchestrations; key is pattern ID |

### 5.2 Pattern ID Naming

Recommended format:

```text
S<scenario_number>_<english_semantics>
```

Examples:

| Pattern ID | Meaning |
|---|---|
| `S1_external_ip_trace` | External IP traceability |
| `S2_web_breach` | WEB intrusion / WebShell traceability |
| `S4_alert_confirmation` | WEB alert confirmation |
| `S5_host_risk` | Host behavior risk identification |

Naming principles:

- `S1` / `S2` / `S4` align with completeness scenario numbers.
- Suffix expresses investigation goal, not specific log product.
- Do not embed asset IDs in pattern ID to avoid deployment coupling.

---

## 6. Pattern Field Semantics

### 6.1 `label`

Human-readable name for UI, reports, and debug output.

Example:

```json
"label": "External IP traceability"
```

### 6.2 `investigation_window`

Default investigation fetch window; references `time_windows` in `correlation-matrix.json`.

Example:

```json
"investigation_window": "trace_default"
```

Current `trace_default` semantics are typically:

```text
Relative to alert_time: 24 hours before, 6 hours after
```

At runtime:

- If caller already passes `time_start` and `time_end`, do not override.
- If only `alert_time` is passed, `resolve_anchor_params()` auto-fills `time_start/time_end`.
- This is the "fetch window," not the Join matching window.

Distinguish two time window types:

| Type | Config location | Purpose |
|---|---|---|
| Investigation fetch window | `pattern.investigation_window` | Determines how large a time range fetch pulls |
| Join matching window | `join.time_window` | Determines whether two evidence records are temporally related |

### 6.3 `anchor`

Investigation anchor; describes which key field or parameter this scenario starts from.

Common fields:

| Field | Description |
|---|---|
| `field` | Canonical anchor field, e.g. `src_ip`, `url`, `host` |
| `field_variants` | Source field candidates, e.g. `ip`, `client_ip`, `host_name` |
| `from` | Anchor source, e.g. `params.attacker_ip`, `params.host`, `waf_alert` |
| `secondary` | Secondary anchor, e.g. in S2 URL plus `src_ip` |
| `fallback_asset_types` | Evidence types to fall back to for anchor extraction |

Example:

```json
"anchor": {
  "field": "src_ip",
  "field_variants": ["ip", "client_ip"],
  "from": "params.attacker_ip",
  "fallback_asset_types": ["waf_alert", "web_access_log"]
}
```

Meaning:

- This scenario anchors on attacker source IP.
- Prefer canonical field `src_ip`.
- Compatible with source fields `ip` / `client_ip`.
- User parameter is `params.attacker_ip`.
- If parameter is missing, try fallback extraction from `waf_alert` or `web_access_log`.

### 6.4 `recommended_chain`

List of recommended Join IDs for this scenario.

Example:

```json
"recommended_chain": [
  "waf_to_web_access_by_ip",
  "web_access_to_host_exec",
  "attacker_ip_to_ssh_auth",
  "host_ip_to_ssh_auth_lateral",
  "firewall_web_to_internal"
]
```

This is the most important field in `Scenario Patterns`.

At execution:

1. `correlation_engine.run_recommended_chain()` reads the chain in order.
2. Each Join ID looks up Join definition in `correlation-matrix.json`.
3. If Join is composite/path type, `expand_path()` expands into multiple real Joins.
4. Each Join runs `find_join_pairs()`.
5. Matches produce `join_edges`.
6. Non-matches produce `data_gaps`.

Notes:

- `recommended_chain` lists Join IDs only.
- Join IDs must exist in `internal_joins` or `cross_source_joins`.
- Do not put field names, time windows, or query templates here.

### 6.5 `bundle_id`

Default asset bundle for this scenario.

Example:

```json
"bundle_id": "bundle-incident-trace-default"
```

Purpose:

- Decide which assets to fetch by default.
- `plan_fetch()` loads asset set when `asset_ids` not explicitly passed.
- Links with completeness analysis to judge which data domains are missing for the scenario.

### 6.6 `layer1_assets` / `layer2_assets`

Currently mainly used for S4 alert confirmation.

Example:

```json
"layer1_assets": ["waf_alert"],
"layer2_assets": ["web_access_log", "host_exec", "host_connect", "host_file_op"]
```

Meaning:

- Layer 1: judge payload, rule, action from alert alone for preliminary classification.
- Layer 2: combine WEB access and host behavior to confirm actual breach.

This is the alert confirmation Skill's two-layer model:

```text
Layer 1: Alert semantic layer
  WAF payload / action / rule / status
        ↓
Layer 2: Success confirmation layer
  web_access_log + host_exec + host_connect + host_file_op
```

---

## 7. Currently Defined Scenarios

### 7.1 S1: External IP Traceability

Pattern ID: `S1_external_ip_trace`

Goal:

> Given an external attack IP, trace which WEB/WAF entry points it hit, whether it reached hosts, whether SSH lateral movement or internal access occurred.

Key configuration:

```json
{
  "label": "External IP traceability",
  "investigation_window": "trace_default",
  "anchor": {
    "field": "src_ip",
    "from": "params.attacker_ip"
  },
  "recommended_chain": [
    "waf_to_web_access_by_ip",
    "web_access_to_host_exec",
    "attacker_ip_to_ssh_auth",
    "host_ip_to_ssh_auth_lateral",
    "firewall_web_to_internal"
  ],
  "bundle_id": "bundle-incident-trace-default"
}
```

Recommended chain:

```text
attacker_ip
  ├─▶ waf_alert
  ├─▶ web_access_log
  ├─▶ host_exec
  ├─▶ ssh_auth
  └─▶ firewall_log / internal traffic
```

Typical questions:

- Is this external IP only scanning?
- Did it reach real WEB entry points?
- Did it trigger host command execution?
- Did it continue SSH lateral movement?
- Which internal hosts were affected?

### 7.2 S2: WEB Intrusion / WebShell

Pattern ID: `S2_web_breach`

Goal:

> From WEB alert, URL, or suspicious path, confirm WebShell, command execution, file write, or outbound connection.

Key anchor:

```json
"anchor": {
  "field": "url",
  "field_variants": ["request_uri", "path"],
  "from": "waf_alert",
  "secondary": "src_ip"
}
```

Recommended chain:

```text
waf_alert.url + src_ip
  └─▶ web_access_log
        └─▶ host_exec
              ├─▶ host_file_op
              └─▶ host_connect
```

Difference from S1:

| Scenario | Starting point | Focus |
|---|---|---|
| S1 | External IP | Trace full impact from attack source |
| S2 | WEB URL / WAF alert | Confirm breach and landing from WEB entry |

### 7.3 S4: Alert Confirmation (Two Layers)

Pattern ID: `S4_alert_confirmation`

Goal:

> Determine whether WAF/WEB alert is false positive, real attack but unsuccessful, or real attack with confirmed breach.

Configuration characteristics:

```json
"layer1_assets": ["waf_alert"],
"layer2_assets": [
  "web_access_log",
  "host_exec",
  "host_connect",
  "host_file_op"
]
```

Recommended chain:

```text
waf_alert
  ├─▶ web_access_log
  ├─▶ host_exec
  ├─▶ host_connect
  └─▶ host_file_op
```

Two-layer judgment:

| Layer | Input | Answers |
|---|---|---|
| Layer 1 | WAF alert itself | Is it an attack? Is payload effective? Possible false positive? |
| Layer 2 | WEB + D2 host behavior | Breached? Command execution, outbound connection, file write? |

Key principle:

```text
Without D2 host behavior evidence, do not easily output success_confirmed.
```

If WAF hit but no WEB/host correlation, output:

```text
alert_triage_only / insufficient_evidence / data_gap
```

Rather than directly asserting intrusion success.

### 7.4 S5: Host Behavior Risk Identification

Pattern ID: `S5_host_risk`

Goal:

> From a given host, identify high-risk commands, active outbound connections, file writes, and other behavior chains related to externally listening processes.

Anchor:

```json
"anchor": {
  "field": "host",
  "field_variants": ["host_name"],
  "from": "params.host"
}
```

Recommended chain:

```text
host_exec
  ├─▶ host_connect
  └─▶ host_file_op
```

Core Joins:

- `d2_exec_connect_same_listener`
- `d2_exec_file_same_host`

Typical questions:

- Did externally listening process execute high-risk commands?
- Active outbound connection after command execution?
- Download/write suspicious files?
- WebShell / C2 / persistence risk?

---

## 8. How Scenario Patterns Are Consumed at Runtime

### 8.1 Loading Configuration

In `correlation_engine.py`:

```text
load_anchor_patterns()
  Prefer dataasset/scenarios/anchor-patterns.json
  If file missing, compatibly read legacy anchor_patterns in correlation-matrix.json
```

Current authoritative path:

```text
dataasset/scenarios/anchor-patterns.json
```

Legacy path is compatibility only; do not use for new work.

### 8.2 Automatic Pattern Matching by Scenario

Function: `anchor_pattern_for_scenarios()`

Current priority:

```text
S4 → S1 → S2 → S5
```

Meaning:

- If input scenarios include `S4`, prefer `S4_alert_confirmation`.
- Otherwise match `S1_external_ip_trace`, `S2_web_breach`, `S5_host_risk`.

Note: if one request declares multiple scenarios, priority affects which Pattern is used.

### 8.3 Auto-Fill Investigation Time Window

Function: `resolve_anchor_params()`

Flow:

```text
Input params
  ├─ If time_start + time_end already present: return as-is
  ├─ If alert_time present: read pattern.investigation_window
  └─ Call fill_investigation_window() to generate time_start/time_end
```

Example:

```json
{
  "attacker_ip": "203.0.113.10",
  "alert_time": "2026-06-21T10:00:00+08:00"
}
```

If `investigation_window = trace_default`, derives to:

```json
{
  "time_start": "2026-06-20T10:00:00+08:00",
  "time_end": "2026-06-21T16:00:00+08:00"
}
```

### 8.4 Generate Fetch Plan

Function: `plan_fetch()`

Flow:

```text
pattern.bundle_id
  ↓
Load asset_ids in bundle
  ↓
Iterate Joins in recommended_chain
  ↓
Read each Join's fetch_plan.left/right
  ↓
Combine param_map to generate task queue
  ↓
Output correlation_fetch_plan
```

Output task example:

```json
{
  "join_id": "waf_to_web_access_by_ip",
  "side": "left",
  "asset_id": "asset-waf-prod-01",
  "asset_type": "waf_alert",
  "template_id": "waf_gateway_plugin_by_ip_time",
  "params": {
    "src_ip": "203.0.113.10",
    "time_start": "...",
    "time_end": "..."
  },
  "purpose": "..."
}
```

This reflects an important principle:

```text
Scenario Pattern decides which chain to query; Join.fetch_plan decides how to fetch each step.
```

At runtime `skill_input --fetch` uses `correlation_fetch_plan` as the primary path:

1. `fetch_scenario_evidence()` first calls `plan_fetch()` from `bundle_id + scenarios / anchor_pattern_id + params`.
2. If tasks are generated, `fetch_correlation_plan_evidence()` fetches evidence in task order; `template_id` and `params` in tasks take priority over traditional asset default template selection.
3. Before execution, checks whether tasks satisfy template required parameters; tasks missing bridge fields (e.g. `host_name` that must be derived from WEB access logs first) are recorded as `skipped_plan_task_count` so missing-parameter queries do not block the main path.
4. Each task still expands multiple connectors on the asset, so aggregated assets (e.g. multi-host SSH / multi-logstore) retain multi-connector capability.
5. Fetch results are aggregated and deduplicated per asset into `evidence_bundles`; payload retains `correlation_fetch_plan`, `correlation_anchor_pattern`, and `data_access.fetch_strategy=correlation_fetch_plan` for auditing "why these sources were queried."
6. If Pattern missing or `plan_fetch()` produces no tasks, fall back to `bundle_full_fallback` for traditional full-bundle fetch, preserving legacy flow compatibility.

### 8.5 Execute Recommended Chain and Output Correlation Results

Functions: `run_recommended_chain()` / `correlate_bundles()`

Flow:

```text
Input evidence_bundles + anchor_pattern_id
  ↓
Read pattern.recommended_chain
  ↓
expand_path() expand composite Joins
  ↓
find_join_pairs() find evidence pairs
  ↓
Match: add to join_edges
  ↓
No match: add to data_gaps
```

Output structure:

```json
{
  "anchor_pattern_id": "S4_alert_confirmation",
  "recommended_chain": [
    "waf_to_web_access_by_ip",
    "waf_to_host_exec_via_web_access",
    "d2_exec_connect_same_listener",
    "d2_exec_file_same_host"
  ],
  "join_edges": [
    {
      "join_id": "waf_to_web_access_by_ip",
      "left_ref": "waf-001",
      "right_ref": "web-001",
      "match_keys": { "src_ip": "203.0.113.10" },
      "time_window": "alert_context",
      "confidence": 0.9
    }
  ],
  "data_gaps": [
    "no_match:d2_exec_connect_same_listener (...)"
  ]
}
```

`join_edges` are the audit basis in reports for "why these two evidence records relate"; `data_gaps` explicitly state "which evidence segment is missing."

---

## 9. Relationship with Completeness Analysis

Completeness analysis answers:

> Which data domains does this scenario need? Are current assets sufficient? What gaps affect conclusions?

Scenario Patterns answer:

> If assets are sufficient, which chain should be queried?

Relationship:

```text
Completeness analysis
  ├─ S1 needs D1 + D2 + D3
  ├─ S4 needs D1; D2 preferred to prove breach
  └─ S5 needs D2
        ↓
Scenario Patterns
  ├─ S1_external_ip_trace uses bundle-incident-trace-default
  ├─ S4_alert_confirmation uses bundle-alert-confirm-min
  └─ S5_host_risk uses bundle-host-risk-default
        ↓
correlation_engine
  ├─ plan_fetch
  └─ correlate_bundles
```

Recommended conventions:

| Scenario | Completeness focus | Scenario Pattern focus |
|---|---|---|
| S1 External IP traceability | D1 + D2 + D3 coverage | Path from IP to WEB, host, SSH, internal |
| S2 WEB intrusion | D1 + D2 coverage | From URL/WAF to host exec, file, outbound |
| S4 Alert confirmation | D1 for verdict; D2 to prove breach | Two-layer confirmation chain |
| S5 Host risk | D2 exec/connect/file completeness | Same-host behavior chain |

If completeness finds P0 domain gaps, Scenario Pattern can still run, but conclusions must be downgraded and stated clearly in `data_gaps` or reports.

---

## 10. Maintenance and Adding Scenarios

### 10.1 Steps to Add a Pattern

1. Define scenario number and investigation goal.
2. Determine investigation anchor, e.g. `src_ip`, `host`, `url`, `user`.
3. Determine default investigation window, e.g. `trace_default`, `lateral_movement`.
4. Choose asset bundle `bundle_id`.
5. Select existing Joins from `correlation-matrix.json` for `recommended_chain`.
6. If Joins are missing, add to correlation-matrix first, then reference in Pattern.
7. Run `validate.py` to check:
   - `anchor-patterns.json` conforms to `anchor-patterns.schema.json`.
   - `investigation_window` exists.
   - All Join IDs in `recommended_chain` exist.
   - `bundle_id` exists.
   - `S1`–`S7` derived from Pattern ID are covered by bundle `investigation_scenarios`.
   - `asset_type` required by `recommended_chain` / `layer1_assets` / `layer2_assets` is covered by bundle `asset_ids`.
8. Validate `join_edges` and `data_gaps` with sample evidence.

### 10.2 New Pattern Template

```json
"S3_lateral_movement": {
  "label": "Lateral movement investigation",
  "investigation_window": "trace_default",
  "anchor": {
    "field": "host_ip",
    "field_variants": ["src_ip", "dst_ip"],
    "from": "params.host_ip",
    "secondary": "user"
  },
  "recommended_chain": [
    "host_ip_to_ssh_auth_lateral",
    "ssh_auth_to_host_exec_same_host",
    "firewall_web_to_internal"
  ],
  "bundle_id": "bundle-incident-trace-default"
}
```

Note: template only. Before production, confirm Join IDs exist in `correlation-matrix.json` and bundle contains required asset_type.

### 10.3 Recommended Chain Design Principles

| Principle | Description |
|---|---|
| Start from user's most certain anchor | e.g. attack IP, alert ID, host, user |
| Query high-confidence entry evidence first | WAF, WEB, SSH login, etc. |
| Then host behavior evidence | exec/connect/file to prove breach |
| Lateral and impact scope later | SSH, firewall, DNS, CMDB, etc. |
| Every step must have Join definition | Cannot invent Joins in Pattern |
| Missing evidence must form data_gap | Non-match is part of investigation result |

### 10.4 What Not to Do

| Do not | Reason |
|---|---|
| Write concrete field Join logic in Pattern | Field Joins belong in correlation-matrix |
| Write SLS/SQL queries in Pattern | Queries belong in Join.fetch_plan + query-templates |
| Embed asset IDs in Pattern ID | Scenarios should decouple from deployment |
| Let AI decide Join chain freely | Breaks auditability |
| Generate "speculative chains" on non-match | Output data_gap, do not fabricate |

---

## 11. Validation Rules

`validate.py` currently performs structural and cross-config contract validation on `anchor-patterns.json`:

| Check | Description |
|---|---|
| File existence | Warning if missing; skip anchor pattern validation |
| JSON format | Error on parse failure |
| JSON Schema | Uses `dataasset/schema/anchor-patterns.schema.json` for top-level structure, required Pattern fields, field types |
| `patterns` type | Must be object |
| pattern type | Each pattern must be object |
| `investigation_window` | If set, must exist in matrix `time_windows` |
| `recommended_chain` | Must be array; Join IDs must not duplicate |
| Join references | Each Join ID must exist in matrix `internal_joins` or `cross_source_joins` |
| `bundle_id` reference | Declared `bundle_id` must exist in `dataasset/bundles/` |
| Pattern ↔ Bundle scenario consistency | `S1`–`S7` derived from Pattern ID must be in bundle `investigation_scenarios` |
| Bundle covers Join requirements | `from_asset_type` / `to_asset_type` after expanding `recommended_chain` must be covered by bundle `asset_ids` |
| Layer asset coverage | `asset_type` in `layer1_assets` / `layer2_assets` must be covered by bundle |
| Composite Join expansion | If Join has `path`, validation recursively expands real Joins in path and includes required asset_type in bundle coverage check |
| Legacy config migration | If `correlation-matrix.json` still has `anchor_patterns`, prompt migration |

Extended validation also checks anchor fields, registered asset types, fallback asset
coverage, and scenario declarations. See [Scenario Pattern Runtime and Evolution](../docs_dev/29-scenario-pattern-runtime-and-evolution.md)
for the function-level implementation map and evolution constraints.

---

## 12. Runtime Boundaries

1. S3, S6, and S7 have Patterns. S7 production readiness still depends on live, accepted Connectors for DNS, full-traffic, and database-audit evidence.
2. When a Join lacks a complete `fetch_plan`, runtime may fall back to Bundle fetching. Check authorization scope, time range, and result limits before production use.
3. Completeness P0/P1/P2 requirements come from `data-source-completeness/scenarios.json`; they are not derived automatically from a Pattern's Join chain. Review both when changing a Pattern.
4. Key report conclusions should reference `join_edges` and retain `data_gaps` so unsupported hypotheses are not presented as facts.

## 13. Developer Implementation Notes

Pattern loading, anchor resolution, fetch planning, fallback behavior, validation, and
extension work are maintained in the [developer reference](../docs_dev/29-scenario-pattern-runtime-and-evolution.md).
Security operators can configure and verify Patterns using this guide alone.

---

## 14. End-to-End Example: S4 Alert Confirmation

User question:

```text
Did the WAF SQL injection alert from 203.0.113.10 lead to a breach?
```

Input parameters:

```json
{
  "scenario": "S4",
  "params": {
    "attacker_ip": "203.0.113.10",
    "alert_time": "2026-06-21T10:00:00+08:00"
  }
}
```

Execution flow:

```text
1. anchor_pattern_for_scenarios(["S4"])
   → S4_alert_confirmation

2. resolve_anchor_params("S4_alert_confirmation", params)
   → If time_start/time_end missing, fill per investigation_window

3. plan_fetch("S4_alert_confirmation", params)
   → Select assets per bundle-alert-confirm-min
   → Generate correlation_fetch_plan per recommended_chain

4. fetch evidence
   → waf_alert
   → web_access_log
   → host_exec
   → host_connect
   → host_file_op

5. correlate_bundles(..., anchor_pattern_id="S4_alert_confirmation")
   → Run recommended_chain
   → Output join_edges and data_gaps

6. confirm.py synthesizes judgment
   → false positive / attack unsuccessful / confirmed breach / insufficient evidence
```

Key judgments:

```text
WAF hit only: indicates attack attempt only.
WAF + WEB hit: request reached business entry.
WAF/WEB + host_exec: possible breach.
host_exec + connect/file: subsequent behavior; risk significantly elevated.
```

---

## 15. Summary

`Scenario Patterns` is a critical layer in the SecWeaver investigation system.

Its essence is not "configure a few scenario names," but codifying security experts' investigation paths into executable, validatable, reusable machine rules:

```text
Scenario → Anchor → Investigation window → Asset bundle → Recommended Join chain → join_edges/data_gaps → Trustworthy conclusion
```

The layering with `correlation-matrix.json` gives the system three core capabilities:

1. **Reusable**: one Join serves multiple investigation scenarios.
2. **Auditable**: every conclusion traces back to Join ID and evidence ID.
3. **Evolvable**: new scenarios orchestrate existing Joins first without breaking underlying assets and field model.

As SecWeaver automated investigation capability grows, `Scenario Patterns` should be treated as a core registration object on par with `Asset` and `Correlation Matrix`.

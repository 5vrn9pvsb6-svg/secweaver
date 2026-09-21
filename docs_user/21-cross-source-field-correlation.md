# Cross-Source Field Correlation Guide

**Languages:** English (this document) | [简体中文](21-cross-source-field-correlation.zh-CN.md)

> Machine-readable Join spec: [`dataasset/assets/correlation-matrix.json`](../dataasset/assets/correlation-matrix.json)  
> Scenario orchestration: [`dataasset/scenarios/anchor-patterns.json`](../dataasset/scenarios/anchor-patterns.json)  
> Historical design assessment: [correlation-matrix-design-evaluation.md](../docs_dev/history/22-correlation-matrix-design-evaluation.md)
> Field normalization: [`dataasset/configure/evidence-minimum-fields.json`](../dataasset/configure/evidence-minimum-fields.json)  
> Per-asset schema: [`dataasset/assets/`](../dataasset/assets/)

This document explains **which fields join across data source assets, what time windows apply, and which investigation chains each join supports**.  
When Skills (alert confirmation, traceability analysis, risk identification) build chains, they **must use only Joins defined in correlation-matrix**. If no rule exists, mark `data_gap` — do not invent correlations.

## Network context is not proof of exfiltration

`host_connect_to_dns`, `nta_session_correlation` and raw DNS timeline rows use the neutral
`network_activity` stage with an empty `mitre_id`. Their evidence references, timestamps,
graph edges and source coverage remain available. Selecting S7 or S8 alone does not prove
exfiltration or C2, and neutral network joins do not count as host-execution evidence.
Consumers should accept an empty ATT&CK ID for contextual rows. Preserve explicitly supported
attack stages separately; require transfer direction/content and corroborating evidence before
claiming data exfiltration. The default `webshell-to-ssh-lateral` case demonstrates download and
lateral activity, not proven exfiltration. Re-run saved reports to update historical labels.

Download-correlated and non-allowlisted egress retain their risk severity and review rules,
but carry `network_activity` tags without automatic T1048.003. An entry-point inference note
belongs to its selected candidate; a fallback note must not claim WEB/WAF is absent when the
selected entry cites those sources.


---

**Reading by task:** Jump to the relevant section; reading every section in order is optional.

- [2. Dual-Field Model (v1.1)](#2-dual-field-model-v11)
- [3. Canonical Field Semantics (Must-Know for Traceability)](#3-canonical-field-semantics-must-know-for-traceability)
- [6. Cross-Source Joins (D1 ↔ D2 ↔ Network)](#6-cross-source-joins-d1--d2--network)
- [8. S1 Full Example (External IP Trace)](#8-s1-full-example-external-ip-trace)

## 0. Design Intent

The core goal of `correlation-matrix.json` is to capture "how evidence is chained in security investigations" as a **machine-readable, validatable, reusable Join contract**. It is not a field dictionary or query template catalog; it answers:

- Which two evidence types can be correlated?
- Which keys join them?
- How much time skew is allowed?
- Which investigation scenario does this join support?
- After a successful join, how does it support alert confirmation, traceability, or risk identification?

### 0.1 Why correlation-matrix Is Centralized

If each Skill writes its own join logic:

| Problem | Consequence |
|---|---|
| Join rules scattered across scripts / prompts | Same attack chain yields inconsistent conclusions across Skills |
| Each place uses different field names | `ip`, `src_ip`, `host_name`, `host` get mixed up |
| Time windows hard-coded from experience | Events far apart get wrongly joined, or real delays are missed |
| Fetch logic mixed with join logic | Changing SLS/ES/DB query templates affects join semantics |
| AI improvises joins | Reports are hard to audit; "why these two events relate" is unexplained |

The matrix therefore uses **one rule set, many consumers**: alert confirmation, traceability, and risk identification use only declared Joins; on miss or no rule, output `data_gap` — never fabricate attack chains.

### 0.2 Why These Layers Exist

| Layer | Problem solved | Design rationale |
|---|---|---|
| `field_policy` | How join fields are read | Prefer canonical; still accept source fields to lower onboarding cost |
| `time_windows` | How large a time range counts as related | Different attack phases have different delays — must be explicit and auditable |
| `internal_joins` | How D2 behavior chains on one host | exec / connect / file are continuous behavior on one host — separate from cross-source bridges |
| `cross_source_joins` | How different data sources bridge | WAF, WEB, host, SSH, firewall, DNS have different semantics — explicit joins needed |
| `priority` / `confidence` | Why a Join is inspected first and why it is trustworthy | Gives UI, reports, and code review the same explanation instead of a black-box score |
| `scenario_patterns` | Which chain to investigate per scenario | S1/S2/S4/S5 have different anchors, bundles, and recommended chains — in `scenarios/anchor-patterns.json` |
| `fetch_plan` | How to fetch evidence for a join | Query params and index fields are fetch layer; joins that need fetch must declare `template_id` and `param_map` |
| `constraints` | What Skills must obey | Hard boundaries for AI and scripts so output is reviewable |

### 0.3 Why internal_joins vs cross_source_joins

Investigations usually have two phases:

```text
External entry chain: WAF / WEB / SSH / firewall / DNS cross-source evidence
        │
        ▼
Host-internal behavior: host_exec / host_connect / host_file_op D2 events
```

`cross_source_joins` answers: **Where did the attack come from, which host was hit, was there lateral movement or egress?**

`internal_joins` answers: **On the host, are command execution, active outbound connections, and file writes part of the same attack wave?**

Splitting this way lets entry traceability and host behavior chains be maintained independently and reused across S4 alert confirmation, S5 host risk, S2 web breach, etc.

### 0.4 Why Field Normalization Is Not in the Matrix

The matrix describes join semantics only; it does not maintain full field alias tables. Authoritative normalization:

1. Global aliases: `field_aliases` in `evidence-minimum-fields.json`
2. Asset aliases: `field_aliases` in `asset-*.json`
3. Join-local exceptions: `join_keys.*_variants`

This avoids three drifting mapping tables:

```text
schema.fields      — keep source fields
field_aliases      — source field → canonical
correlation-matrix — how canonical / source fields join
query-templates    — concrete query index fields
```

### 0.5 Why Join Windows vs Investigation Windows

- **Join time window**: Whether two evidence items are temporally related (e.g. `attack_success`, `host_behavior_chain`).
- **Investigation time window**: How much data to pull (e.g. `trace_default` derives `time_start/time_end` from `investigation_window` in `scenarios/anchor-patterns.json`).

You can pull 30 hours of logs via `trace_default`, then use smaller join windows to decide which events truly correlate — fewer missed events, less false joining.

---

## 1. Three-Layer Data Model

```text
┌─────────────────┐     field_aliases      ┌──────────────────┐
│  Source fields   │ ─────────────────────▶ │  canonical fields │
│  ip / host_name  │                        │  src_ip / host    │
└─────────────────┘                        └────────┬─────────┘
                                                    │
                                                    ▼
                                           ┌──────────────────┐
                                           │ correlation-matrix│
                                           │  Join rules + windows│
                                           └────────┬─────────┘
                                                    │
                                                    ▼
                                           evidence_bundles chaining
```

| Layer | File | Question answered |
|---|---|---|
| L1 Per-asset | `assets/asset-*.json` | What fields does this data have? |
| L2 Normalization | `evidence-minimum-fields.json` | How do source fields become canonical? |
| L3 Cross-source | `assets/correlation-matrix.json` | How do canonical fields join? Field normalization is not duplicated in matrix |

---

## 2. Dual-Field Model (v1.1)

Join rules **should use canonical names** but may use source fields in local cases; matching supports both normalized and alias fields:

```text
Read order (declared_first_then_alias):
  1. Field declared in the join (host or host_name)
  2. join_keys.*_variants                 ← per-join extra field names (few exceptions)
  3. Alias reverse: canonical → source (host → host_name)
  4. Alias forward: source → canonical (host_name → host)
```

| Use | Write | Read |
|---|---|---|
| Join rule definition | Prefer **canonical** (`host`, `src_ip`); source fields allowed (`host_name`) | Declared field + per-join variants + global/asset alias forward/reverse |
| SLS/ES query | `fetch_plan.param_map` + `query-templates` (e.g. `host_name: params.host`) | Template params set index keys |
| Evidence normalization | `evidence-minimum-fields.field_aliases` + `asset.field_aliases` | Fill canonical after fetch |

**Example**: `web_access_to_host_exec` may use `host` or `host_name` when the source field is known. The resolver reads the declared field first, then adds candidates via global/asset `field_aliases`. Default to canonical; use source fields only when a local data source requires it.

Implementation: `field_resolver.py` → `resolve_field_value()` / `match_join_key()`; **execution engine** → `correlation_engine.py` (join matching, time windows, `plan_fetch`, `join_edges` output contract).

---

## 2.1 Join Priority and Confidence

Every Join must declare:

```json
{
  "priority": 96,
  "confidence": {
    "base": 0.88,
    "max": 0.96,
    "optional_key_increment": 0.05,
    "reason": "WEB upstream/host aligns with host execution in the attack-success window; core chain for breach confirmation.",
    "signals": ["target_ip to host_ip exact", "host optional", "attack_success window"]
  }
}
```

How to read it:

| Field | Purpose |
|---|---|
| `priority` | Investigation ordering and UI display; 90+ is a strong main chain, 70-89 a regular investigation chain, 60-69 an auxiliary signal |
| `confidence.base` | Baseline confidence after required keys match |
| `confidence.max` | Confidence ceiling after optional / secondary keys match |
| `optional_key_increment` | Increment per optional / secondary key hit |
| `reason` | Operator-readable explanation of why this edge is trustworthy |
| `signals` | Audit signals such as exact key, short time window, 5-tuple, or CMDB enrichment |

Runtime `join_edges[]` includes `priority`, `confidence_base`, `confidence_ceiling`, and `confidence_reason`.  
`dataasset/schema/correlation-matrix.schema.json` handles structural validation; `validate.py` continues to handle cross-file references, field reachability, fetch_plan, and anchor/bundle semantic checks.

---

## 3. Canonical Field Semantics (Must-Know for Traceability)

| Canonical | Meaning | Common asset_type | Easy to confuse with |
|---|---|---|---|
| `src_ip` | **Attacker / client IP** | waf_alert, web_access_log, ssh_auth | ≠ victim machine IP |
| `host` | **Victim host hostname** | host_exec, ssh_auth, web_access_log | After normalization, always `host` |
| `host_ip` | **Victim host IP** | host_exec, firewall_log, CMDB | Used for lateral, firewall joins |
| `dst_ip` | Connection destination IP | host_connect, firewall_log | Egress / C2 / internal destination |
| `url` | HTTP path + query | waf_alert, web_access_log | Prefer path prefix match |
| `alert_id` | WAF alert unique key | waf_alert | Source field often `trace_id` |
| `listener_pid` | External listener process PID | host_exec, host_connect | D2 behavior chain anchor |
| `user` | Login / operation account | ssh_auth, host_exec | Key for SSH lateral movement |

### Production Alias Examples

**`asset-secweaver-host-exec`** (audit-port-execmon → SLS):

| Layer | Source field | Canonical | Notes |
|---|---|---|---|
| Evidence join | `host_name` | `host` | Unnormalized logs can join directly |
| Query param | `host_name` | — | Join-level `fetch_plan.param_map.host_name` ← `params.host` |
| Time | `time` | `timestamp` | Same pattern |

**`asset-waf-prod-01`** (generic WAF alert log):

| Layer | Source field | Canonical |
|---|---|---|
| Evidence join | `ip` | `src_ip` |
| Query param | `ip` | — | Template `waf_gateway_plugin_by_ip_time` uses `ip: {src_ip}` |
| Alert key | `trace_id` | `alert_id` |

Query param mapping is defined by join-level `fetch_plan.param_map` and `query-templates`; field normalization stays in global / asset `field_aliases`.

---

<a id="3-time-window-conventions"></a>

## 4. Time Window Conventions

| Name | Range | Use |
|---|---|---|
| `alert_context` | ±10 minutes | WEB access around WAF alert |
| `attack_success` | −5 / +30 minutes | Alert confirmation layer 2, WEB→exec |
| `host_behavior_chain` | ±5 minutes | Same-host exec/connect/file |
| `lateral_movement` | −30 / +120 minutes | SSH/firewall lateral |
| `trace_default` | −**24h** / +**6h** | Default trace **investigation fetch window** (relative to `alert_time`); referenced by `investigation_window` in `scenarios/anchor-patterns.json`; fills `time_start/time_end` |

**Two window types**:

| Type | Reference | Role |
|---|---|---|
| Join window | Join rule `time_window` | Whether two evidence items are temporally related |
| Investigation window | `investigation_window` in `scenarios/anchor-patterns.json` | Derives fetch `time_start/time_end` when only `alert_time` is known |

S1 / S2 trace scenarios use `"investigation_window": "trace_default"`. If caller passes explicit `time_start` + `time_end`, they are not overwritten.

**Clock skew**: Join windows use evidence `timestamp`. If a source clock is wrong or lacks timezone, declare correction on the **asset** via `schema.time_correction` (`normalizer` applies at fetch). See [time correction](../docs_dev/09-data-asset-design.md#asset-time-correction). Matrix windows themselves do not change.

---

<a id="4-d2-host-behavior-internal-joins-same-host"></a>

## 5. D2 Host Behavior Internal Joins (Same Host)

audit-port-execmon event types chain on the same `listener_pid` / `host`:

```text
host_exec ──(host + listener_pid, ±5min)──▶ host_connect
          ──(host + pid, ±5min)──────────▶ host_file_op
host_connect ──(host + pid, ±5min)───────▶ host_file_op
```

| Join ID | Left | Right | Keys |
|---|---|---|---|
| `d2_exec_connect_same_listener` | host_exec | host_connect | host, listener_pid, listener_port |
| `d2_exec_file_same_host` | host_exec | host_file_op | host, pid, listener_pid |
| `d2_connect_file_same_host` | host_connect | host_file_op | host, pid |

<a id="41-d2_exec_file_same_host-command-execution--file-write"></a>

### 5.1 `d2_exec_file_same_host`: Command Execution ↔ File Write

This rule joins **host command execution** (`host_exec`) with **host file operations** (`host_file_op`) to determine whether execution was accompanied by WebShell writes, script drops, tool downloads, or abnormal file creation.

```json
{
  "id": "d2_exec_file_same_host",
  "from_asset_type": "host_exec",
  "to_asset_type": "host_file_op",
  "join_keys": [
    {
      "left": "host",
      "left_variants": ["host_name"],
      "right": "host",
      "right_variants": ["host_name"],
      "match": "exact"
    },
    { "left": "pid", "right": "pid", "match": "exact", "optional": true },
    { "left": "listener_pid", "right": "listener_pid", "match": "exact", "optional": true }
  ],
  "time_window": "host_behavior_chain"
}
```

| Field | Meaning |
|---|---|
| `host` / `host_name` | Required. Both events on the same host; `host_name` is a source variant, compatible via dual-field model. |
| `pid` | Optional strengthener. If both sides have equal `pid`, file op more likely from that process. |
| `listener_pid` | Optional strengthener. Ties exec and file op to the same external listener chain (nginx, php-fpm, java, node, etc.). |
| `time_window: host_behavior_chain` | Time constraint within host behavior chain window — avoids joining unrelated events on same host far apart. |

**Scenarios**: `S2` web breach trace, `S4` web alert confirmation, `S5` host anomaly.  
**Consuming Skills**: `risk-identification`, `alert-confirmation`, `traceability-analysis`.

In short: on one host, if command execution and file operation occur within the allowed window and `pid` / `listener_pid` align, treat them as part of the same host attack behavior chain.

**Use**: Risk identification attack chains, alert confirmation "breach or not", traceability execution/persistence stages.

---

<a id="6-cross-source-joins-d1--d2--network"></a>

## 6. Cross-Source Joins (D1 ↔ D2 ↔ Network)

<a id="51-alert-confirmation--web-attack-s4"></a>

### 6.1 Alert Confirmation / WEB Attack (S4)

```text
waf_alert                    web_access_log              host_exec
(src_ip, url, timestamp) ──▶ (src_ip, url, host) ──▶ (host, command, listener_*)
     │                              │
     └──────── attack_success ±30min ─┘
```

| Join ID | Description |
|---|---|
| `waf_to_web_access_by_ip` | Same source IP + time window; optional url prefix |
| `web_access_to_host_exec` | **Victim host** alignment + time window |
| `waf_to_host_exec_via_web_access` | When WAF has no host, **must bridge via WEB access** |
| `d2_exec_*` | Layer-2 success evidence |

> Anti-pattern: join `waf.src_ip` to `host_exec.host` directly — **wrong** (different semantics).

<a id="52-external-ip-traceability-s1"></a>

### 6.2 External IP Traceability (S1)

Anchor: `params.attacker_ip` → canonical `src_ip`

```text
                    ┌──▶ web_access_log (same-source requests)
attacker_ip / src_ip ─┼──▶ waf_alert (rule hits)
                    ├──▶ ssh_auth (SSH ingress / port scan)
                    └──▶ firewall_log (hits on internal network)

web_access.host ──▶ host_exec (commands after WEB breach)
host_exec.host_ip ──▶ ssh_auth.src_ip (jump-box SSH lateral)
host / host_ip ──▶ asset_inventory (asset ownership)
```

Recommended chain: `scenarios/anchor-patterns.json` → `patterns.S1_external_ip_trace`.

<a id="53-lateral-movement-s3"></a>

### 6.3 Lateral Movement (S3)

| Join ID | Path |
|---|---|
| `host_ip_to_ssh_auth_lateral` | Victim IP → src_ip in SSH logs |
| `ssh_auth_to_host_exec_same_host` | SSH login host → exec on that host |
| `firewall_web_to_internal` | Firewall five-tuple ↔ SSH/internal host |

---

<a id="6-scenario--asset-bundle--correlation-chain"></a>

## 7. Scenario → Asset Bundle → Correlation Chain

| Scenario | Bundle | Main anchor fields | Recommended join chain |
|---|---|---|---|
| S1 External IP trace | `bundle-incident-trace-default` | `src_ip` | S1_external_ip_trace |
| S2 WEB intrusion | `bundle-incident-trace-default` | `url` + `src_ip` | S2_web_breach |
| S4 Alert confirmation | `bundle-alert-confirm-min` | `alert_id` / `src_ip` | S4_alert_confirmation |
| S5 Host risk | `bundle-host-risk-default` | `host` | S5_host_risk |

Full definitions: `dataasset/scenarios/anchor-patterns.json` → `patterns`.

---

<a id="7-s1-full-example-external-ip-trace"></a>

## 8. S1 Full Example (External IP Trace)

**Input**:

```json
{
  "params": {
    "attacker_ip": "203.0.113.10",
    "alert_time": "2026-06-21T10:00:00+08:00",
    "time_start": "2026-06-20T10:00:00+08:00",
    "time_end": "2026-06-21T16:00:00+08:00"
  }
}
```

**Step 1 — Anchor**: In `waf_alert` / `web_access_log`, fetch first/key events with `src_ip=203.0.113.10`.

**Step 2 — WEB context**: `waf_to_web_access_by_ip`, ±10min, restore requests around alert.

**Step 3 — WEB breach?**: `web_access_to_host_exec`, use `web_access.host` to query `host_exec` (±30min) for curl/bash/webshell commands.

**Step 4 — SSH lateral**: `attacker_ip_to_ssh_auth` + `host_ip_to_ssh_auth_lateral`, find SSH Accepted from same or jump IP.

**Step 5 — Asset enrichment**: `host_to_cmdb` for zone/owner and impact scope.

Each `attack_chain` entry must include: `evidence_refs`, `join_id` / `join_ids`, `timestamp`.  
Script output also includes **`join_edges`** array (see next section).

---

<a id="8-correlation-engine-correlation_engine"></a>

## 9. Correlation Engine (correlation_engine)

The matrix is executed by shared modules, not documentation-only:

| Module | Path |
|---|---|
| Field read | `src/skills/_shared/data-access/field_resolver.py` |
| **Correlation engine** | `src/skills/_shared/data-access/correlation_engine.py` |

<a id="81-main-apis"></a>

### 9.1 Main APIs

| Function | Purpose |
|---|---|
| `get_join(join_id)` | Read one join definition |
| `expand_path(join_id)` | Expand multi-hop joins (e.g. `waf_to_host_exec_via_web_access`) |
| `match_join_pair()` / `find_join_pairs()` | Dual-field match + matrix time window |
| `correlate_bundles()` | Run recommended chain per `scenarios/anchor-patterns.json` |
| `plan_fetch(anchor_pattern_id, params)` | Build `fetch_plan` fetch task queue |

<a id="82-join-output-contract-join_edges"></a>

### 9.2 Join Output Contract (`join_edges`)

`correlate.py`, `confirm.py` output:

```json
{
  "join_id": "web_access_to_host_exec",
  "left_ref": "web-001",
  "right_ref": "exec-001",
  "match_keys": { "host": "web-01" },
  "time_window": "attack_success",
  "confidence": 0.9,
  "from_asset_type": "web_access_log",
  "to_asset_type": "host_exec"
}
```

<a id="83-fetch-orchestration-fetch_plan--correlation_fetch_plan"></a>

### 9.3 Fetch Orchestration (`fetch_plan` / `correlation_fetch_plan`)

Joins in the matrix may declare `fetch_plan`; `skill_input.py` writes payload on `--fetch`:

```json
{
  "correlation_anchor_pattern": "S4_alert_confirmation",
  "correlation_fetch_plan": [
    {
      "join_id": "waf_to_web_access_by_ip",
      "side": "left",
      "asset_id": "asset-waf-prod-01",
      "template_id": "waf_gateway_plugin_by_ip_time",
      "params": { "src_ip": "203.0.113.10", "time_start": "...", "time_end": "..." }
    }
  ]
}
```

Join-level `fetch_plan.param_map` maps bridged `host` to template param `host_name` (`host_exec_by_host_name_time`).

<a id="84-extended-match-types"></a>

### 9.4 Extended match Types

| match | Implementation |
|---|---|
| `exact` | `correlation_engine.values_match` |
| `path_prefix` | URL path prefix |
| `hostname_to_ip_via_cmdb` | `build_host_ip_map` + CMDB |
| `dns_answer_ip` | Parse IP from DNS response |

---

<a id="9-skill-usage-constraints"></a>

## 10. Skill Usage Constraints

1. **Join keys: prefer canonical, allow source fields** — read via `field_resolver.py` declared-first + alias forward/reverse; match via **`correlation_engine.py`**
2. **Only matrix join_ids** — no hit → `data_gaps` / `data_gaps_impact` stating which join is missing
3. **success_confirmed** requires at least one D2 join (`web_access_to_host_exec` or `d2_*`)
4. **Query params**: live fetch consumes `correlation_fetch_plan` first; mapping in `fetch_plan.param_map` and query-templates
5. **Time windows**: per matrix `time_windows` (e.g. `attack_success` −5 / +30 minutes)
6. **Output**: must include `join_edges`; hits may note `matched_via: canonical|variant|alias`

---

<a id="10-maintenance"></a>

## 11. Maintenance

When adding or changing assets:

1. Maintain `schema.fields` and `field_aliases` in `asset-*.json`; common aliases in `evidence-minimum-fields.json`
2. For **new cross-source joins**, add to `cross_source_joins` or `internal_joins` in `assets/correlation-matrix.json`
3. Update the "Scenario → correlation chain" table in this document
4. Run `python3 src/dataasset/validate.py` to validate JSON

**Do not** duplicate cross-source join rules in each asset; **maintain one** correlation-matrix.

---

<a id="11-related-documents"></a>

## 12. Related Documents

- [data-asset-design.md](../docs_dev/09-data-asset-design.md)
- [agent-collection-and-evidence-spec.md](../docs_dev/12-agent-collection-and-evidence-spec.md)
- [traceability-analysis-skill-design.md](../docs_dev/15-traceability-analysis-skill-design.md)
- [alert-confirmation-skill-design.md](../docs_dev/14-alert-confirmation-skill-design.md)

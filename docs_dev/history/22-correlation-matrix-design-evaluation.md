**Languages:** English (this page) | [简体中文](22-correlation-matrix-design-evaluation.zh-CN.md)

# correlation-matrix.json Design Evaluation Report

> **Status: historical assessment (as of 2026-07-08).** Design proposals describe that evaluation period; TODOs do not imply missing functionality today. See [asset design](../09-data-asset-design.md) for current fields and [cross-source correlation](../../docs_user/21-cross-source-field-correlation.md) for current correlation behavior.

> **Implementation status (2026-07-08)**: Mid-term engineization **landed** — `correlation_engine.py`, `field_resolver.py`; `correlate.py` / `confirm.py` output `join_edges`; `skill_input` uses `correlation_fetch_plan` as primary fetch path; `fetch.py` supports ordered fetch by plan and falls back to full bundle when plan empty; `correlation-matrix.schema.json`, Join `priority/confidence`, and UI visual explanation have landed. TODO: Join mutex/conflict resolution and further matrixization of complex lateral BFS.

> **Evaluation target**: [`dataasset/assets/correlation-matrix.json`](../../dataasset/assets/correlation-matrix.json)
> **Related docs**: [21-cross-source-field-correlation.md](../../docs_user/21-cross-source-field-correlation.md) (correlation engine section) | [data-asset-design.md](../09-data-asset-design.md)
> **Evaluation date**: 2026-06-25
> **Summary**: **Design direction correct, semantic layering clear, and now viable as SecWeaver's cross-source correlation single source of truth**; engineization, Join output, ordered fetch via `correlation_fetch_plan`, `validate.py` semantic validation, dedicated JSON Schema, Join priority/confidence, and UI visual explanation have landed. Remaining work is mainly Join mutex/conflict resolution, full matrixization of complex lateral BFS, and more production sample regression.

---

## 0. Core Function and Architecture (Understanding the Correlation Matrix)

This chapter explains **what the correlation matrix is, what problem it solves, and how it runs in the platform**. Later sections "evaluation scope / issues / optimization" build on understanding this chapter.

### 0.1 One-line positioning

**correlation-matrix.json** is SecWeaver's **cross-source evidence correlation specification**: it defines "which fields, within what time window, can legally connect different logs into an investigation chain," executed by **`correlation_engine.py`**.

It is **not** a single-log schema (that is `asset-*.json`), **nor** the full normalization rule set (that is `evidence-minimum-fields.json` + `asset.field_aliases`), but **L3: cross-source Join contract**. Join keys recommend canonical names; source fields allowed locally.

### 0.2 Position in the platform

```text
┌──────────────────────────────────────────────────────────────────────────┐
│                    SecWeaver security investigation chain                 │
└──────────────────────────────────────────────────────────────────────────┘

  User intent / scenarios S1~S7
         │
         ▼
  data-source-completeness     "Is data sufficient to investigate?"
         │
         ▼
  skill_input + fetch          "Pull logs from asset bundle"
         │                        correlation_fetch_plan ← matrix.fetch_plan
         ▼
  normalizer + field_aliases     "Source fields → canonical (src_ip / host / …)"
         │
         ▼
  correlation_engine           "Join evidence per matrix rules" ★ core of this chapter
         │
         ├── alert-confirmation   Two-layer triage + join_edges
         ├── traceability         attack_chain + join_edges
         └── risk-identification  D2 internal chain (internal_joins)
```

**Single source of truth principle**: How cross-source correlation works is maintained **only in correlation-matrix**; Skill docs and AI must not invent Joins.

### 0.3 What's in the JSON file (structure map)

| Top-level block | Role | Analogy |
|---|---|---|
| `field_policy` | Join keys recommend canonical, allow source fields; read values via alias forward/reverse candidates | Field "read/write policy" |
| `time_windows` | `alert_context`, `attack_success`, etc. time windows | Correlation validity period |
| **`internal_joins`** | **Same host domain** D2 correlation (exec/connect/file) | Host behavior chain |
| **`cross_source_joins`** | **Cross data source** correlation (WAF↔WEB↔exec↔SSH…) | Main traceability chain |
| `scenario_patterns` | Scenario → recommended Join chain → `bundle_id`; now split to `dataasset/scenarios/anchor-patterns.json` | Investigation "playbook" |
| `fetch_plan` | Join-bound query templates and params; `fetch_plan_defaults` removed | Fetch orchestration |
| `constraints` | Hard rules AI/scripts must obey | Compliance boundary |

Current version: **v1.1**, path: [`dataasset/assets/correlation-matrix.json`](../../dataasset/assets/correlation-matrix.json).

### 0.4 Two Join types (most easily confused concept)

#### A. D2 internal correlation `internal_joins`

**Scope**: Same `asset_type` domain, behavior chain on same victim host (audit-port-execmon output).

```text
host_exec ──(host + listener_pid, ±5min)──▶ host_connect
          ──(host + pid, ±5min)──────────▶ host_file_op
```

| Join ID | Purpose |
|---|---|
| `d2_exec_connect_same_listener` | Command execution ↔ egress from same listener process |
| `d2_exec_file_same_host` | Command execution ↔ abnormal file write |
| `d2_connect_file_same_host` | Egress ↔ file operation |

**Serves**: S4 alert confirmation "did it breach", S5 risk identification attack chain, S2 traceability execution stage.

#### B. Cross-source correlation `cross_source_joins`

**Scope**: Between different `asset_type`; recommend canonical field alignment; local source fields OK, resolved by field_resolver alias forward/reverse.

```text
waf_alert                    web_access_log              host_exec
(src_ip, url)  ──same IP──▶  (src_ip, host)  ──host──▶  (host, command)
     │                              │
     └──────── attack_success time window ─┘
```

Typical Joins:

| Join ID | Left → Right | Key fields |
|---|---|---|
| `waf_to_web_access_by_ip` | WAF → WEB access | `src_ip` |
| `web_access_to_host_exec` | WEB → host commands | `host` |
| `waf_to_host_exec_via_web_access` | WAF → exec (**via WEB bridge**, multi-hop) | `path` expansion |
| `host_ip_to_ssh_auth_lateral` | Jump host → SSH lateral | `host_ip` ↔ `src_ip` |

**Anti-pattern (forbidden)**: Join `waf.src_ip` directly to `host_exec.host` — different semantics (attacker source IP ≠ victim hostname).

### 0.5 Dual-field model (v1.1)

Join rules **recommend canonical names** (e.g. `host`, `src_ip`); source fields (e.g. `host_name`) also allowed; matching reads declared fields and falls back to alias candidates:

```text
Read order (declared_first_then_alias):
  1. Field declared in Join (canonical or source)
  2. join_keys.*_variants (few exceptions per Join)
  3. Alias reverse: canonical → source field
  4. Alias forward: source field → canonical
```

| Layer | Module | Responsibility |
|---|---|---|
| Field read | `field_resolver.py` | `resolve_field_value()` |
| Join execution | `correlation_engine.py` | `match_join_pair()`, `find_join_pairs()` |

**Query vs correlation separation**: SLS query params defined by `fetch_plan.param_map` and `query-templates` (e.g. `host_name: params.host`); does not change Join semantics.

### 0.6 Scenario orchestration: `scenarios/anchor-patterns.json`

Completeness precheck answers "is data enough"; **scenario orchestration config answers "after enough, in what order to investigate and how to connect."** Not part of field correlation matrix body; split from `correlation-matrix.json`.

| anchor ID | Scenario | Recommended Join chain (excerpt) | Bundle |
|---|---|---|---|
| `S1_external_ip_trace` | External IP traceability | waf→web→exec→ssh→fw | `bundle-incident-trace-default` |
| `S4_alert_confirmation` | Alert confirmation | waf→web→exec + d2_* | `bundle-alert-confirm-min` |
| `S5_host_risk` | Host risk | d2_exec_* | `bundle-host-risk-default` |

Engine entry: `correlate_bundles(bundles, anchor_pattern_id="S4_alert_confirmation")`
Runs `recommended_chain` Join by Join, outputs **`join_edges`** and **`data_gaps`**.

### 0.7 Execution engine architecture

```text
correlation-matrix.json
        │
        ├─ load_matrix() / get_join(join_id)
        ├─ expand_path()          Multi-hop Join expansion
        ├─ in_time_window()      Read time_windows
        ├─ match_join_pair()      Single pair match (incl. path_prefix / cmdb / dns)
        ├─ find_join_pairs()      Batch match
        ├─ correlate_bundles()    Run full anchor chain
        └─ plan_fetch()           Generate correlation_fetch_plan
                │
                ▼
        correlate.py / confirm.py / skill_input.py
```

**Join output contract** (each `join_edges` entry):

```json
{
  "join_id": "web_access_to_host_exec",
  "left_ref": "web-001",
  "right_ref": "exec-001",
  "match_keys": { "host": "web-01" },
  "time_window": "attack_success",
  "confidence": 0.9
}
```

### 0.8 End-to-end example: S4 alert confirmation

```text
① User: "Did WAF SQLi alert for IP 203.0.113.10 breach?"

② fetch (skill_input --fetch)
   correlation_fetch_plan per matrix:
     - waf_gateway_plugin_by_ip_time(src_ip=203.0.113.10)
     - web_access_by_src_ip_time(...)
     - host_exec_by_host_name_time(host_name=web-01)  ← Join-level fetch_plan.param_map

③ normalizer: ip→src_ip, host_name→host, time→timestamp

④ confirm.py layer 1: WAF payload → alert_verdict

⑤ correlation_engine layer 2:
     - Join waf_to_web_access_by_ip (same source IP)
     - Join web_access_to_host_exec (host alignment)
     - Join d2_exec_connect_same_listener (exec+egress)
   → join_edges[]; if exec present → attack_success=true

⑥ If success → hand off traceability (anchor S1/S2 chain continues SSH lateral)
```

### 0.9 Core capability checklist (implemented vs pending)

| Capability | Status | Notes |
|---|---|---|
| Flexible Join field resolution | ✅ | field_resolver supports canonical or source + alias forward/reverse |
| D2 / cross-source Join spec | ✅ | internal + cross_source |
| Time-window-driven matching | ✅ | attack_success, etc. |
| Extended match (path_prefix / cmdb / dns) | ✅ | correlation_engine |
| join_edges output contract | ✅ | correlate / confirm |
| fetch_plan planning | ✅ | plan_fetch → payload |
| fetch.py ordered fetch by plan | ✅ | `correlation_fetch_plan` primary; empty plan falls back to full bundle |
| correlate lateral BFS full matrixization | ⏳ | Partially still hardcoded |
| validate.py matrix validation | ✅ | Join/time_window/Pattern/bundle contract; Pattern anchor/fallback/scenario declarations enhanced |
| S3/S6/S7 anchor_patterns | ✅ | Added `S3_lateral_movement` / `S6_account_compromise` / `S7_data_exfiltration` |

### 0.10 Relationship with related docs

| Document | What to read |
|---|---|
| [21-cross-source-field-correlation.md](../../docs_user/21-cross-source-field-correlation.md) | Join details, maintenance, dual-field model |
| [data-asset-design.md](../09-data-asset-design.md) | L1 assets, connectors, query-templates |
| `src/skills/_shared/data-access/README.md` | Engine API, fetch usage |
| [examples/traceability/](../../examples/traceability/) | Offline evidence + `_meta.correlation_joins` regression |

---

## 1. Evaluation Scope and Method

### 1.1 Evaluation scope

| Dimension | Content |
|---|---|
| Specification itself | Canonical fields, Join rules, time windows, anchor_patterns, constraints |
| L1/L2 consistency | `asset-*.json`, `evidence-minimum-fields.json`, `query-templates` |
| Skill implementation | `correlate.py`, `confirm.py`, `assess.py`, `fetch.py` / `normalizer.py` |
| Examples / production | `examples/traceability/`, `tmp-alert-confirm-asset-waf-prod-01.json` exposed issues |

### 1.2 Evaluation method

- Static review of JSON structure and field semantics
- Compare with `correlate.py` / `confirm.py` hardcoded logic
- Check production assets `asset-secweaver-host-exec`, `asset-waf-prod-01` and Join-level `fetch_plan`
- Check whether `validate.py` covers matrix
- Validate chain intent and script behavior with `examples/traceability/s1-web-shell-to-ssh-lateral.json`

### 1.3 Overall score (out of 5)

| Dimension | Score | Notes |
|---|---|---|
| Conceptual model | **4.5** | canonical + D2 internal + cross-source Join + anchor layering reasonable |
| Maintainability | **4.3** | `validate.py` covers Join/time_window/Pattern/bundle/field reachability; dedicated JSON Schema landed; more negative fixtures needed |
| Executability | **4.2** | Engine and `correlation_fetch_plan` primary path landed; complex lateral BFS still partially hardcoded |
| Production alignment | **4.0** | 12/13 cross-source Joins declare fetch_plan; `host_to_cmdb_inventory` is inventory enrichment and may remain deployment-specific |
| AI consumability | **4.5** | constraints + `join_edges` contract output |

**Overall: 4.2 / 5 — Architecture clear; core execution path usable; now in governance and UX refinement.** (Initial 3.4; see §0 implementation status comparison)

---

## 2. Design Strengths

### 2.1 Clear three-layer data model

```text
L1 asset-*.json          → Single-source fields and connectors
L2 evidence-minimum      → Normalization → canonical
L3 correlation-matrix    → How canonical fields Join
```

**Extracting cross-source correlation into a single matrix** avoids N×M duplicate maintenance; matches "define once, AI runs repeatedly" product philosophy.

### 2.2 Canonical field semantics well defined

`src_ip` / `host` / `host_ip` three-way split is the most confused point in traceability; matrix explicitly writes **semantics** and **common confusions** in `canonical_fields`, preventing typical errors (e.g. Join `waf.src_ip` directly to `host_exec.host`).

### 2.3 Solid D2 internal correlation (internal_joins)

`d2_exec_connect_same_listener`, `d2_exec_file_same_host` anchor on `listener_pid` / `listener_port`, consistent with audit-port-execmon collection model; serves:

- S5 risk identification attack chain
- S4 alert confirmation layer 2
- S2 traceability execution stage

Optional key design (listener_pid optional) balances degraded correlation when fields missing.

### 2.4 Bridge Join covers real data gaps

`waf_to_host_exec_via_web_access` uses `path` for **multi-hop bridge**, accurately reflecting production reality that "WAF logs often lack victim host; must bridge via WEB access logs." More practical than simple binary Join.

### 2.5 anchor_patterns provide scenario-level orchestration

`S1_external_ip_trace`, `S4_alert_confirmation` bind **investigation scenario → recommended Join chain → asset bundle**, reducing AI chain search space; upstream/downstream with `data-source-completeness/scenarios.json`.

### 2.6 Clear constraints

Constraints like "no join hit → no fabrication", "success_confirmed requires at least one D2 Join" give AI auditable boundaries; consistent with `_meta.correlation_joins` testing in examples.

---

## 3. Issues and Risks

### 3.1 【Mitigated】Spec–implementation gap — matrix now loaded by engine

**Before**: No script loaded matrix.
**Now** (2026-06-25):

| Capability | Module |
|---|---|
| Load matrix / Join match | `correlation_engine.py` |
| Dual-field read | `field_resolver.py` |
| Traceability `join_edges` | `correlate.py` → `correlate_bundles()` |
| Alert D2 time window + `join_edges` | `confirm.py` → `attack_success_window()` |
| Fetch orchestration plan | `scenario_fetch.fetch_scenario_evidence()` → `correlation_engine.plan_fetch()` → `fetch.fetch_correlation_plan_evidence()` |

**Still to align**: `correlate.py` `find_execution_chain` / `bfs_lateral` partially hardcoded; fetch primary path switched to `correlation_fetch_plan`; next focus more Join.fetch_plan and scenario Patterns.

### 3.2 【Mitigated】fetch_plan and query template production alignment

**Typical case: `asset-secweaver-host-exec`**

| Layer | Host-related keys |
|---|---|
| SLS raw field | `host_name` (indexed) |
| asset `field_aliases` | `host_name` → `host` |
| Join-level `fetch_plan.param_map` | `host_name` ← `bridge.host` / `params.host` |
| New template | `host_exec_by_host_name_time` ✅ (`plan_fetch` / `fetch_plan` referenced) |
| Legacy template | `host_exec_by_host_time` still uses `host:` (old index compatibility only) |

Query param mapping unified by Join-level `fetch_plan.param_map` and `query-templates`; matrix no longer maintains `query_field_resolution.index_fields` or global `fetch_plan_defaults`. Field normalization still via `evidence-minimum-fields.field_aliases` and `asset-*.json.field_aliases`.

### 3.3 【Mitigated】Some Join keys missing from evidence schema

This round filled key asset field declarations so these Join keys are statically reachable:

| Join | Handling |
|---|---|
| `firewall_web_to_internal` | `ssh_auth` asset added `host_ip` for login target host IP correlation |
| `host_connect_to_dns` | `host_connect` asset added `host_ip` |
| `nta_session_correlation` | `host_connect` asset added `host_ip` |
| `d2_exec_connect_same_listener` | `host_connect` asset added `listener_pid` / `listener_port` |
| `d2_exec_file_same_host` | `host_file_op` asset added `listener_pid` |

Remaining note: fields declared reachable at asset contract layer; production still must confirm collector outputs them or normalizer / field_aliases derives them.

### 3.4 【Mitigated】Incomplete anchor_patterns scenario coverage

`data-source-completeness/scenarios.json` defines S1–S7; `dataasset/scenarios/anchor-patterns.json` now has S3/S6/S7:

| Scenario | anchor pattern | Current status |
|---|---|---|
| S3 Lateral movement | `S3_lateral_movement` | Reuses `bundle-incident-trace-default`; chains SSH / firewall / host_exec / CMDB |
| S6 Account compromise | `S6_account_compromise` | Reuses `bundle-incident-trace-default`; chains `attacker_ip_to_ssh_auth` and `ssh_auth_to_host_exec_same_host` |
| S7 Data exfiltration | `S7_data_exfiltration` | New `bundle-data-exfiltration-default`; covers host_connect / DNS / NTA / DB audit |

Remaining risk: S7 assets mostly draft/example; production needs customer-specific connector, field aliases, query templates.

### 3.5 【Done / ongoing governance】validate.py + JSON Schema two-layer validation

`validate.py` now includes correlation-matrix in release-time semantic validation:

- Whether Join-referenced `time_window` exists
- Whether `from_asset_type` / `to_asset_type` have corresponding asset types
- Whether `join_keys.left/right` are reachable through asset fields, `field_aliases`, or evidence-minimum
- Whether anchor pattern / fallback / scenario / bundle references are closed
- Whether `path` referenced join ids exist
- Whether `fetch_plan.template_id` and `param_map` resolve to query templates

`dataasset/schema/correlation-matrix.schema.json` now covers structural types, required fields, match enums, `priority` / `confidence` ranges, and `fetch_plan` shape. Python semantic validation continues to cover cross-file references, field reachability, anchor/bundle closure, and `fetch_plan.template_id` resolution.

Remaining risk: add more negative fixtures for breaking changes, version compatibility, invalid priority/confidence ranges, and dangling path Joins.

### 3.6 【Mitigated / P2】fetch_plan is now the primary path; coverage governance remains

The main path is now closed:

```text
scenario_fetch.fetch_scenario_evidence -> correlation_engine.plan_fetch
  → payload.correlation_fetch_plan
  → fetch.py executes in plan order
  → empty plan falls back to full bundle fetch
```

Most cross-source Joins that need automatic evidence fetch now carry `fetch_plan`; `internal_joins` consume same-host-domain evidence already fetched and usually do not need their own fetch_plan. `host_to_cmdb_inventory` is inventory enrichment and can be deployment-specific.

Remaining risks:

- New Joins can still forget `fetch_plan`; validate should surface coverage summaries.
- Complex bridge and lateral BFS logic is still partly hardcoded and should continue moving into matrix + engine.
- The UI does not yet show `correlation_fetch_plan` as an operator-friendly preview.

### 3.7 【P2】Bundle and asset status drift

| bundle | Issue |
|---|---|
| `bundle-incident-trace-default` | Contains `asset-secweaver-host-file-op`, `asset-ssh-internal` etc. draft/placeholder |
| `bundle-alert-confirm-min` | `asset-web-access-prod` is **draft** |

anchor_patterns reference bundles inconsistent with production availability; completeness precheck vs live fetch diverge.

### 3.8 【P2】Missing reverse index and conflict-resolution model

- No reverse lookup of available Joins from `asset_type`
- Join `priority/confidence` now has a baseline model; mutex / conflict resolution remains (e.g. how to choose when `waf_to_host_exec_direct` and `via_web_access` both hit)
- Confidence is explainable, but cross-Join conflict down-weighting, alternative chains, and evidence-quality scoring still need work

---

## 4. Consistency with Examples and Production

### 4.1 examples/traceability aligns well

`s1-web-shell-to-ssh-lateral.json` `_meta.correlation_joins` highly consistent with matrix recommended chain; `correlate.py` produces `confirmed_intrusion_chain`.
Shows: **matrix effective as AI/test specification**; the bottleneck has shifted from "engine/fetch not landed" to complex path coverage, production samples, and visual explainability.

### 4.2 Historical production gap (alert confirmation live fetch)

Earlier, `asset-waf-prod-01` could fetch but `host_exec` failed because the query key was wrong, so the D2 Join could not run. The primary path is now closed via `host_exec_by_host_name_time` and Join-level `fetch_plan.param_map`.

Production acceptance should now focus on:

- Whether customer credentials, project/logstore, index, and SQL fields match templates.
- Whether large windows or high concurrency have fetch audit, rate limits, and timeout policies.
- Whether the UI can explain "why these sources were fetched and with which parameters."

---

## 5. Optimization Recommendations

### 5.1 Short term (1–2 weeks): Alignment and validation — low effort, high return

#### A. Unified field resolution single source

```text
Authoritative order (recommended):
asset.field_aliases  →  normalizer  →  canonical
fetch_plan.param_map  →  query-templates params
```

- Removed `query_field_resolution.index_fields` from matrix; query param mapping via `fetch_plan.param_map`
- `host_exec_by_host_name_time` aligns SLS index key via `param_map.host_name: params.host`

#### B. Maintain matrix JSON Schema; keep validate.py semantic checks

New `dataasset/schema/correlation-matrix.schema.json`, validate:

- join id unique
- time_window reference exists
- path join reachable
- bundle_id exists
- Join fields not in evidence-minimum → prompt confirm source field with alias/variants path

`validate.py` already performs cross-file semantic validation; JSON Schema now provides structure, enum, priority/confidence, and IDE/CI fast feedback. Next focus: negative fixtures and version compatibility policy.

#### C. Align time windows with scripts

| Name | Recommended unified value | Consumers |
|---|---|---|
| `attack_success` | before 5 / after 30 min | confirm.py, correlate.py |
| `host_behavior_chain` | ±5 min (300s) | correlate.py D2 |
| `alert_context` | ±10 min | confirm.py layer1 |

**Completed (verified 2026-09-16):** `attack_success_window()` in `alert_confirmation/common.py` reads the matrix, defaulting to 5 minutes before and 30 after. The earlier proposal to replace a fixed 15-minute window is no longer pending.

#### D. Explicit fetch_plan on Joins needing fetch

All Joins participating in automatic evidence supplement should declare `template_id` and `param_map` in `fetch_plan.left/right`; no global default fetch config.

The current cross-source main chain is mostly covered; next focus is coverage reporting for newly added Joins, documented exemptions for optional inventory Joins, and UI preview.

---

### 5.2 Mid term (3–6 weeks): Engineization — matrix truly drives execution

#### E. Extend shared module `correlation_engine.py`

```text
src/skills/_shared/data-access/correlation_engine.py
├── load_matrix()
├── resolve_field(event, asset_id)      # canonical
├── match_join(join_id, left, right)    # incl. match_type
├── expand_path("waf_to_host_exec_via_web_access")
├── apply_time_window(window_id, anchor_ts, event_ts)
└── plan_fetch(anchor_pattern, params)  # → template_id + params
```

The module already exists and is consumed by `correlate.py` / `confirm.py`; next, continue moving remaining hardcoded paths toward:

1. Select chain per `anchor_patterns`
2. Call `match_join` on evidence
3. Output `attack_chain[].join_id` and `data_gaps[]`

#### F. Join output contract

Each correlation edge must output:

```json
{
  "join_id": "web_access_to_host_exec",
  "left_ref": "web-001",
  "right_ref": "exec-001",
  "match_keys": { "host": "web-01" },
  "time_window": "attack_success",
  "confidence": 0.9
}
```

For audit, regression, AI report citation.

#### G. Fetch orchestration bound to Join

Extend each Join:

```json
{
  "fetch_plan": {
    "left": { "template_id": "waf_gateway_plugin_by_ip_time", "param_map": { "src_ip": "params.attacker_ip" } },
    "right": { "template_id": "host_exec_by_host_time", "param_map": { "host": "$left.bridge.host" } }
  }
}
```

`scenario_fetch.fetch_scenario_evidence` uses `correlation_engine.plan_fetch` to
generate `correlation_fetch_plan` per anchor_pattern, and `fetch.py` executes it
in order. Input adapters and workflow execution live in `skill_runtime`;
`prepare.py` remains a one-shot preparation and compatibility entry.

#### H. Implement extended match types

| match_type | Implementation notes |
|---|---|
| `path_prefix` | URL normalize then prefix compare |
| `hostname_to_ip_via_cmdb` | Reuse `build_host_ip_map` |
| `dns_answer_ip` | Parse DNS response A/AAAA records |

---

### 5.3 Long term (6–12 weeks): Scenario completion and evolution

#### I. Continue improving anchor_patterns

| anchor | Follow-up |
|---|---|
| `S3_lateral_movement` | More lateral path evidence (Windows login, VPN, bastion) and lateral BFS matrixization |
| `S6_account_compromise` | VPN / IAM / AD login Join; avoid SSH-only dependency |
| `S7_data_exfiltration` | Fuller exfil chain d2_exec_file → host_connect → DNS/NTA → db_audit |

#### J. Join priority and mutex

For `waf_to_host_exec_direct` vs `waf_to_host_exec_via_web_access` add:

```json
"preconditions": { "requires_field": { "waf_alert": "host" } },
"priority": 10,
"fallback_join": "waf_to_host_exec_via_web_access"
```

#### K. Versioning and changelog

- matrix upgrade `version: "1.1"` retains `deprecated_joins`
- `CHANGELOG-correlation-matrix.md` records breaking changes
- examples regression: `pytest` traverses `_meta.expected_*` + join_id

#### K. Optional: correlation graph visualization

Generate Mermaid/GraphML from matrix for security operations Join topology review.

---

## 6. Proposed v1.1 Structure Increment (Draft)

**Incremental extension** on existing structure, avoid large rewrite:

```json
{
  "version": "1.1",
  "cross_source_joins": [
    {
      "id": "web_access_to_host_exec",
      "fetch_plan": {
        "right": {
          "asset_types": ["host_exec"],
          "template_id": "host_exec_by_host_name_time",
          "param_map": {
            "host_name": "bridge.host",
            "time_start": "params.time_start",
            "time_end": "params.time_end"
          }
        }
      },
      "preconditions": { "requires": ["web_access_log.host"] },
      "output_confidence": 0.85
    }
  ],
  "join_registry_index": {
    "host_exec": ["d2_exec_connect_same_listener", "web_access_to_host_exec", "..."]
  }
}
```

---

## 7. Priority Roadmap

| Priority | Task | Expected effect |
|---|---|---|
| **P0** | Fix `host_exec` SLS query key (host_name) | ✅ Done; S4 D2 primary path unblocked |
| **P0** | Align confirm/correlate time windows with matrix | ✅ Main engine/time_window path aligned; keep regression coverage |
| **P1** | matrix semantic validation in validate.py | ✅ Done |
| **P1** | dedicated correlation-matrix JSON Schema | ✅ Done; add negative fixtures |
| **P1** | Explicit fetch_plan on Joins needing fetch | ✅ Main chain done; new Joins need coverage governance |
| **P1** | correlation_engine skeleton + join_id output | ✅ Done |
| **P2** | fetch_plan bound to query_templates | ✅ Main path done; add UI preview and audit |
| **P2** | Add S3/S6/S7 anchor_patterns | ✅ Added; extend more evidence sources |
| **P3** | Join mutex, alternative chains, and conflict down-weighting | Reduce false correlation |

---

## 8. Conclusion

`correlation-matrix.json` is **conceptually sound and important**: it correctly answers SecWeaver's core cross-source traceability question—**which fields, what time window, in what order to Join**. Three-layer model, D2 internal correlation, WAF bridge Join, constraints, etc. reach production-grade specification level.

The main weakness is no longer "Join rules are wrong" or "fetch path is not closed." It is now **governance and complex-scenario coverage**: Join mutex/conflict resolution, complex lateral BFS, production fetch audit, more real sample regression, and UI explainability details.

**Recommended positioning**: Treat correlation-matrix as a **platform core asset** alongside `scenarios.json` and `attack-patterns.json`. It has already moved from "important document" to **executable correlation kernel**; the next phase should improve explainability, visualization, and release governance.

---

## 9. Related Files

| File | Relationship |
|---|---|
| [correlation-matrix.json](../../dataasset/assets/correlation-matrix.json) | Evaluation target |
| [21-cross-source-field-correlation.md](../../docs_user/21-cross-source-field-correlation.md) | Human-readable specification |
| [evidence-minimum-fields.json](../../dataasset/configure/evidence-minimum-fields.json) | L2 normalization |
| [templates.json](../../dataasset/query-templates/templates.json) | Fetch layer, bound to Join-level `fetch_plan` on the primary path |
| [correlate.py](../../src/skills/traceability-analysis/scripts/correlate.py) | Consumes matrix/engine; complex lateral BFS continues to converge |
| [confirm.py](../../src/skills/alert-confirmation/scripts/confirm.py) | Consumes matrix/engine and `join_edges` |
| [examples/traceability/](../../examples/traceability/) | Regression test set |

---

*Report version: v1.0 | Reviewer: SecWeaver architecture review*

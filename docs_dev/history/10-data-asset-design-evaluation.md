**Languages:** English (this page) | [简体中文](10-data-asset-design-evaluation.zh-CN.md)

# Data Source Asset Design Evaluation

> **Document status: historical evaluation.** Dates through 2026-07-08, estimates, backlog items, and version scores are historical records rather than current release commitments. For current behavior, use [`dataasset/`](../../dataasset/), the [user onboarding guide](../../docs_user/03-configure-data-sources.md), and the root README.


> Detailed evaluation of SecWeaver **data source asset design** (documentation + `dataasset/` + data access layer)  
> Evaluation dates: 2026-06-21 (eighth) · **2026-06-25 (tenth, correlation engine and field governance)** · **2026-06-30 (object model consolidation and parser updates)** · **2026-07-08 (documentation status sync)**  
> Related: [data-asset-design.md](../09-data-asset-design.md) | [current onboarding workflow](../../docs_user/03-configure-data-sources.md) | [field discovery](../../docs_user/20-log-format-discovery.md) | [agent-collection-and-evidence-spec.md](../12-agent-collection-and-evidence-spec.md) | Implementation: [dataasset/](../../dataasset/)

---

## Overall Conclusions

| Dimension | v2.0 | v2.2 | v2.3 | v2.5 | v2.6 | **v3.0** |
|---|---|---|---|---|---|---|
| **Concept clarity** | ★★★★★ | ★★★★★ | ★★★★★ | ★★★★★ | ★★★★★ | **★★★★★** |
| **Implementability** | ★★★★☆ | ★★★★★ | ★★★★★ | ★★★★☆ | ★★★★☆ | **★★★★☆** |
| **Extensibility** | ★★★★☆ | ★★★★☆ | ★★★★☆ | ★★★★☆ | ★★★★☆ | **★★★★★** |
| **Doc vs implementation** | ★★★★☆ | ★★★★★ | ★★★★★ | ★★★★☆ | ★★★★☆ | **★★★★☆** |
| **Example catalog coherence** | — | — | — | ★★★☆☆ | ★★★☆☆ | **★★★★☆** |
| **New source onboarding ease** | — | — | — | — | ★★★★☆ | **★★★★☆** |
| **Format mapping ease** | — | — | — | — | ★★★★☆ | **★★★★★** |

**Current stage fits**: local editing + SOPS + validate/diagnose + **multi-source fetch** (built-in, plugin, external executor) + Normalizer + multi-connector aggregation + four investigation Skills + `--from-bundle` end-to-end demo.

**Onboarding new data (current conclusion)**: **Convenient for same medium and known asset_type** (edit JSON + connector + query template; usually no Python); **brand-new log formats** via `discovery` + log-format-discovery + `schema.fields` closure; host association on assets consolidated to `coverage.hosts` source IPs, avoiding `host_binding` / aliases / hostname mixing.

**Format mapping (current conclusion)**: **JSON/structured is easiest** (`json_lines` + `field_aliases`); nested JSON in field values uses `json_lines2`, expanding to `parent.child`; **built-in text** one-line config; **new text** via `parsers/*.json`. **Per-asset `field_aliases` supported**; `correlation_keys` auto-derived from matrix+fields — do not hand-write.

**Still short of product-grade**: deeper product UI, real vendor examples and screenshot tutorials, all-green example catalog, fetch audit, more connector integration samples, and stronger remote CI matrices.

**Tenth increment (2026-06-25)**: `correlation_engine` / `field_resolver` / `correlation_keys` auto-derivation, `time_correction`, platform-wide field reference `examples/reference-assets.json`; hand-written `schema.correlation_keys` deprecated.

**2026-06-30 increment**: `host_binding` removed from asset model; `coverage.hosts` defined as log source IP array; Host `aliases` / `interfaces` retained with scoped use; Network `zone` / `network_type` / `trust_level` roles clarified; new `asset_type: syslog_risk_alert`, `asset-secweaver-sys-risk-alert` consolidated to `asset-secweaver-sys-risk-alert`; new `json_lines2` parser for nested JSON field expansion.

**Implementation completeness estimate**: core code ~**92–95%**; **demo-ready loop** ~**75–80%** (data asset model, UI, config diagnostics, and connector extension mechanisms have consolidated; example catalog and real vendor integration still need work).

---

## 1. Issues Resolved Since v1.0

| v1.0 issue | Current status | Evidence |
|---|---|---|
| No `validate.py` | ✅ | `src/dataasset/validate.py` + JSON Schema |
| Hard-coded template selection | ✅ | `template_select.py` + `FALLBACK_BY_ASSET_TYPE` |
| Agent vs SLS path confusion | ✅ | Design §3.8, `agent-collection-and-evidence-spec.md` |
| No evidence spec | ✅ | `evidence-minimum-fields.json` + Normalizer |
| SSH fetch not implemented | ✅ | `ssh_fetch.py` |
| DB / HTTP / ES fetch | ✅ | `db_fetch.py` / `http_fetch.py` / `es_fetch.py` |
| Cloud vendor / SIEM / warehouse fetch | ✅ | AWS/Azure/GCP/Tencent/Huawei/Splunk/ClickHouse/Hive independent fetch files or external executors |
| Normalizer not implemented | ✅ | `normalizer.py` |
| Multi-connector aggregation | ✅ | `connector_ids` + `aggregate.py` |
| Format discovery Skill | ✅ | `log-format-discovery` |
| PostgreSQL database_ro | ✅ | `db_fetch.py` + psycopg3 (v2.3) |
| Field normalization ops guide | ✅ | [Log Format Discovery](../../docs_user/20-log-format-discovery.md) |
| `status=active` vs bundle reference semantics unclear | ✅ | `registry.asset_to_registered` + `validate.check_bundle` + `--from-bundle` + `promote-after-connectivity.py` |
| coverage hint soft match | ✅ | `check.py` `match_coverage_hint` (option B) |
| **correlation_engine + join_edges** | ✅ | `correlation_engine.py`; trace/alert output join contract |
| **correlation_keys auto-derivation** | ✅ | `correlation_keys.py`; hand-written in assets deprecated |
| **time_correction** | ✅ | `schema.time_correction` + `normalizer.py` |
| **Shared field completeness check** | ✅ | `field_inventory.py`; `data-source-completeness` uses `effective_fields` |
| **Field reference examples** | ✅ | `examples/reference-assets.json` + `build-field-reference.py` |
| **Asset-side host association consolidation** | ✅ | Removed `host_binding`; `coverage.hosts` source IP + `connector.config.host_id` |
| **Network field definitions** | ✅ | `zone` / `network_type` / `trust_level` for grouping, purpose, trust |
| **syslog-risk-json typing** | ✅ | `asset_type: syslog_risk_alert`, asset ID `asset-secweaver-sys-risk-alert` |
| **Nested JSON line parsing** | ✅ | `json_lines2`: expand JSON object in field values to dot fields |

### 1.1 v2.3 New Capabilities (vs v2.2)

| Item | Description |
|---|---|
| **asset_type extensions** | `windows_event_log`, `linux_syslog`, `network_traffic_audit` |
| **database_ro dual engine** | MySQL (pymysql) + PostgreSQL (psycopg3), shared `:param` SQL templates |
| **ES example assets** | `asset-es-waf-prod`, `asset-es-web-access-prod` |
| **MySQL example assets** | `asset-mysql-ssh-auth`, `asset-mysql-db-audit`, `asset-cmdb-hosts` |
| **PostgreSQL examples** | `conn-db-pg-sec-audit`, `asset-pg-cmdb-hosts` |
| **Onboarding FAQ** | Q1 onboarding flow, Q2 text_parser, Q3 source vs normalized fields |
| **Risk identification Skill** | Depends on D2 exec/connect, decoupled from dataasset via `asset_type` |

### 1.2 Typical validate.py Output (2026-07-08)

Early `text_parser` oneOf ambiguity schema errors are gone; unreferenced connectors are no longer warnings. Target: **0 error / 0 warning / 0 blocking issue**.

Current `validate.py --json` smoke test is **0 error / 0 warning / 0 blocking issue**; use `--diagnose` when operators need root causes and fix steps.

Acceptable warnings mainly from incomplete draft asset fields, doc notes, or onboarding status; unreferenced connectors may be spare, jump, or in-progress — not warned.

| Type | Example | Nature |
|---|---|---|
| catalog stale reference | Deleted example network path | Catalog cleanup; does not affect object model |

Current validation focus: `coverage.hosts` is IP, asset connector exists, `connector.config.host_id` exists, host/network membership reasonable, active assets have owner/description/retention/evidence fields.

### 1.3 Three Default Bundle Completeness (`--from-bundle`, 2026-06-21)

| Bundle | Scenario | active/total | `overall_verdict` | Blocking P0 |
|---|---|---|---|---|
| `bundle-incident-trace-default` | S1+S3 | 3/8 | **not_traceable** | WEB process exec (`host_exec` draft) |
| `bundle-alert-confirm-min` | S4 | 1/4 | **not_traceable** | WEB access log (`web_access_log` draft) |
| `bundle-host-risk-default` | S5 | 0/3 | **not_traceable** | Host exec (all D2 draft) |

Conclusion: **design and Skill chain ready**; example catalog D2/WEB promotion and bundle coherence remain ops P0 (§3.7).

### 1.4 Tenth Evaluation Increment (2026-06-25)

| Item | Description |
|---|---|
| **Correlation engine** | `correlation-matrix` v1.1 + `correlation_engine.py`: `match_join_pair`, `plan_fetch`, `join_edges` |
| **Dual-field read** | `field_resolver.py`; matrix `field_policy` + `fetch_plan.param_map` |
| **Correlation key governance** | Removed hand-written `correlation_keys` in assets; registry / completeness Skill use derived keys |
| **Time correction** | `schema.time_correction` (`assume_timezone` / `offset_minutes`) |
| **Field reference** | Merged asset `asset-example-all-fields` (128 fields, 17-type union) |
| **Unit tests** | data-access **68+** (correlation_engine, correlation_keys, field_resolver) |

**Done**: `fetch.py` consumes `correlation_fetch_plan` in order; `validate.py` validates matrix/anchor/bundle field contracts.

**Still pending**: trace `correlate.py` full matrix lateral BFS; more negative fixtures for correlation-matrix Schema / priority / confidence; more tests for fetch_plan coverage, complex vendor connectors, and UI diagnostics.

---

## 2. What the Design Does Well (Continued + v2.3)

### 1. Clear layering: L1 assets vs L2 connectors

Decoupling from Skills (bundles use `investigation_scenarios` S1–S7, not Skill names) is well executed.

### 2. Unified multi-source fetch entry

```text
fetch.py → sls | ssh_file | ssh_command | local_file | database_ro
         → http_api | es | agent_stream | syslog_ingest | object_storage
         → AWS/Azure/GCP/Tencent/Huawei/Splunk/ClickHouse/Hive
         → plugin_executor / external executor
         → normalizer → evidence_bundles
```

Query templates pick fields by `connector_type` (`sls_query` / `sql` / `es_query` / `cloudwatch_query`, etc.). For new sources, prefer config-only external executors or plugins first; only first-class in-core connectors require platform fetch code.

### 3. Credentials and AI boundary

SOPS + `vault://` ref; Skills/Claw see ref and normalized evidence only, not secrets.

### 4. Two-layer field model (FAQ Q3)

```text
Query layer: logstore/ES/SQL use source field names
Evidence layer: normalizer + field_aliases → canonical (src_ip, timestamp…)
```

Reduces "data fetched but Skill fields empty" onboarding failures.

### 5. Documentation system

| Document | Role |
|---|---|
| data-asset-design.md | Main design (**v3.1**) |
| 16-data-source-onboarding-faq.md | Then-current combined FAQ; current procedures are split across docs 03, 20, and 09 |
| agent-collection-and-evidence-spec.md | Collection chain + evidence |
| log-format-discovery*.md | New log types |
| dataasset/README.md | Directory editing |
| This evaluation | Gaps and priorities |

---

## 3. Still Unclear or Easy to Confuse

### 1. `status=active` vs bundle reference (implemented)

**Former confusion**: completeness Skill only counts `active`; bundles could list draft members → validate errors vs `--from-bundle` results seemed contradictory.

**Current contract** ([Data Asset Design §8, §10](../09-data-asset-design.md)):

| Layer | Rule | Implementation |
|---|---|---|
| Asset JSON | `status=active` = usable | `registry.asset_to_registered` → `registered` / `not_registered` |
| Bundle JSON | `status=active` requires all members `active` | `validate.check_bundle` errors |
| Skill input | draft assets after bundle expand count as `missing` | `bundle_to_registered_assets` + `skill_input --from-bundle` |
| Promotion | connectivity test then status change | `promote-after-connectivity.py` |

Assembly/onboarding: bundle stays **`draft`**, may reference draft assets; before production each asset **`active`**, then bundle **`active`** and validate passes.

**Status**: ✅ contract aligned in registry / validate / Skill chain; current validate errors are **example assets not promoted**, not missing rules.

### 2. `coverage` semantics (option B implemented)

`check.py` matches scenario `coverage` hints to asset `zones`/`hosts` **item by item** (including `params.hosts` host-level); no longer defaults to `full`. Dictionary and rules: [Data Asset Design §2.3.11](../09-data-asset-design.md).

**Status**: ✅ (`match_coverage_hint` + `registry.coverage_detail` + unit tests).

### 2.1 Field completeness check (shared)

Former `data-source-completeness` only checked `registered_assets[].fields`, mis-flagging `asset-secweaver-host-exec` missing `host` / `timestamp` when source fields were `host_name` / `time` but `asset.field_aliases` already mapped to canonical.

**Current contract**: field completeness via `src/skills/_shared/data-access/field_inventory.py`:

```text
raw_fields       = schema.fields
canonical_fields = global field_aliases / asset.field_aliases / time_field reachable fields
effective_fields = raw_fields ∪ canonical_fields
```

`registry.asset_to_registered()` outputs `field_aliases`, `canonical_fields`, `effective_fields`; `data-source-completeness` calls `check_required_fields()` on `effective_fields`. `correlation-matrix.json` no longer maintains a second `canonical_fields.variants`. Retest S1/S3: `asset-secweaver-host-exec` `S1-P0-exec` went from `partial` to `ready`, confidence 0.59 → 0.68.

**Status**: ✅; other Skills should reuse `field_inventory.py`, not `set(asset.fields)`.

### 3. JSON Schema and object model consolidation

Early `text_parser` oneOf ambiguity fixed via `not: { enum: [...] }`; `validate.py` can reach **0 error / 0 blocking**. Schema focus shifts from "pass validation" to "reduce ops and AI misunderstanding".

#### 3.1 `text_parser` built-in enum (consolidated)

| Item | Current state |
|---|---|
| **Built-in parsers** | `syslog_auth`, `nginx_combined`, `json_lines`, `json_lines2`, `raw_only` |
| **Custom parser** | Second string branch uses `not enum` to avoid overlap with built-in IDs |
| **`json_lines`** | Per-line JSON object; mapping via `field_aliases` |
| **`json_lines2`** | Per-line JSON; nested JSON in values expands to `parent.child` |
| **Example** | `fields: "{\"user\":\"root(uid=0\"}"` → `fields.user` |

Acceptance: new built-in parser must sync `text-log-parsers.json` and `data-asset.schema.json` enum.

#### 3.2 `masking` / `pii_fields` alignment (P2 · done)

| Field | Schema | Runtime | Notes |
|---|---|---|---|
| **`masking`** | ✅ `redact` or `truncate_<N>` | ✅ `normalizer.apply_masking` | Runtime masking; keys field name or dot path |
| **`pii_fields`** | ✅ `array<string>` | **Not read** at runtime | PII annotation for governance, UI, audit only |

Design choice: `pii_fields` does not auto-`redact` to avoid harming trace fields. Explicit `masking` required for redaction.  
**Gap**: `masking` keys not validated against `schema.fields` (P3 quality).

#### 3.3 connector `config` / `constraints` branches (P2 · partial)

[`data-connector.schema.json`](../../dataasset/schema/data-connector.schema.json) has per-type required fields for **sls / ssh_file / database_ro (MySQL, PostgreSQL, Oracle/PLSQL, SQL Server, SQLite) / http_api / es / local_file / agent_stream / AWS / Azure / GCP / Tencent / Huawei / Splunk / ClickHouse / Hive / MongoDB / Redis**; **active** connectors need `credentials_ref` (`local_file` excepted).

| Remaining gap | Notes |
|---|---|
| `ssh_command`, `syslog_ingest`, `object_storage` | Templates and fetch paths exist, but schema constraints can be tightened further |
| `constraints` | Can carry generic limits, but not fully typed per connector for `max_rows` / `max_time_span_hours` |
| `bastion_id` reference | No schema check that jump connector exists |

#### 3.4 Other loose items (P2–P3)

| Item | Example | Suggestion |
|---|---|---|
| **`environment` enum** | `asset-local-lab-auth` uses `lab` → 1 error | Add `lab` or use `development` |
| **`additionalProperties: true`** | asset / connector allow undefined fields | Tighten to `false` + explicit `properties`, or `unevaluatedProperties` |
| **`coverage.hosts` IP-only** | `coverage.zones` removed | Schema/validate prevent hostname, aliases, text aliases |
| **`field_aliases` per-asset** | ✅ | `asset.field_aliases` overrides global; `discover --apply` writes per-asset by default |

**Summary**: Schema moved from blocking validation to governance enhancement; prioritize `coverage.hosts` IP-only, `text_parser` enum sync, connector `constraints` per type, catalog cleanup.

### 4. Firewall template granularity

`firewall_by_src_dst_time` for exact src/dst IP correlation; when only attacker IP known use **`firewall_by_src_ip_time`** (`src_ip` + time window). `template_select` prefers latter when `dst_ip` missing.

**Status**: ✅ (`templates.json` + `asset-fw-dmz-internal`).

### 5. Live data and Skill stability

Normalizer exists, but some logstores (gateway `ip` vs `src_ip`) depend on **field_aliases maintenance**; new sources still need format discovery loop. `asset-waf-api-prod` still in **discovery** queue.

### 6. Taxonomy "semi-registered": `dns_log`, etc. (P1)

| asset_type | schema enum | completeness scenarios | template | example asset | evidence spec |
|---|---|---|---|---|---|
| **`dns_log`** | ✅ | S1/S2 **P1** | ✅ | ✅ `asset-dns-internal-prod` | ✅ |
| `ids_alert` / `edr_event` / `vuln_scan` / `app_api_log` | ✅ | not in scenarios | ❌ | ❌ | partial/none |

**Impact**: `dns_log` has draft example and template; `ids_alert` etc. lack end-to-end samples. Confirm `template_select.FALLBACK_BY_ASSET_TYPE` for `dns_log`.

**Fix**: complete ids/edr P2 types; or mark scenarios "optional" until templates ready.

### 7. Example catalog and validate coherence (P0 · repo hygiene)

| Issue | Status | Suggestion |
|---|---|---|
| **bundle still `active`** | 3 bundles active but 11 draft member refs → 10 validate errors | Set bundle **`draft`** until onboarding done; or promote members per §3.1 |
| **SLS placeholders** | 7 connectors still `YOUR_SLS_PROJECT` | Real project/logstore in private deployments only |
| **ES/DB/HTTP placeholders** | `es.example.com`, `db-audit.internal.example.com`, etc. | Replace after integration or mark `status: draft` |
| **`promote-after-connectivity.py`** | Default tests `host_*` / `web_access_log` only | Extend `--types` for CMDB, NTA, Win/Linux syslog |

### 8. SLS vs ES dual path (P2 · ops confusion)

Same `asset_type` (e.g. `waf_alert`, `web_access_log`) may have SLS and ES draft assets. **Design allows** but lacks decision table → duplicate registration or wrong connector.

**Suggestion**: add **onboarding path decision** in design doc or FAQ (SLS first if available; ES-only if indexed there; if dual-write pick by latency/cost).

### 9. Testing and CI gaps (P1–P2)

| Item | Status |
|---|---|
| Unit tests | data-access **68+**, completeness **14+**, passing |
| **Existing** | `release_scan`, docs link scan, SecWeaver CLI/dataasset UI tests cover validate and release-gate primary paths |
| **Missing** | targeted `http_fetch` tests are still sparse; matrix negative fixtures, complex vendor connector smoke tests, and remote CI matrix need more coverage |
| validate sample params | `check_template_fetch_samples` only **warns**, fixed IP/time, not ES/SQL/firewall single-IP branches |

**Suggestion**: keep local `release_scan` + docs-check + unittest; add matrix negative fixtures, targeted `http_fetch` tests, per-asset-type validate sample params, and remote CI.

### 10. Platform capabilities not landed (P2 · within design boundary)

| Capability | Notes |
|---|---|
| **fetch audit** | Design requires answering "who had AI query which machine"; no query audit store |
| **AccessPolicy / RBAC** | Removed from asset JSON, separate doc; not implemented on platform |
| **Product UI** | Asset registration, bundle selection, connectivity still JSON + CLI |

---

## 4. Extensibility Analysis

| Extension | Where to change | Difficulty | Ops changes Python? |
|---|---|---|---|
| New **SLS/ES** asset (known asset_type) | connector + asset + template | **Low** | ❌ |
| New **query template** | `templates.json` + asset `query_template_ids` | **Low** | ❌ |
| New **asset_type** | schema + evidence-minimum-fields + scenarios + `FALLBACK` | **Low–medium** | ❌ |
| **JSON new field names** | `field_aliases` + maybe template query fields | **Low** | ❌ |
| **Built-in text** (auth/nginx) | asset `text_parser` enum | **Low** | ❌ |
| **Custom text** | `parsers/<id>.json` + asset `text_parser` | **Medium** | ❌ |
| New **DB engine** | MySQL/PostgreSQL/Oracle/SQL Server/SQLite exist; other engines via independent fetch file | **Medium** | ✅ platform or plugin |
| New **connector type** | config-only external executor / plugin / in-core connector | **Low–high** | ❌ (external/plugin) or ✅ (in-core) |
| Credential backend | `vault.py` | Medium | ✅ platform |

**Current bottlenecks**:

1. **Ops data**: 20% active, D2/WEB placeholder connectors block promotion  
2. **Taxonomy half-done**: `dns_log` etc. enum open but no template/asset  
3. **Mapping scale**: per-asset aliases supported; global table large — split by asset_type (P3)  
4. **Engineering hygiene**: more negative fixtures, real vendor smoke tests, remote CI matrix, and fetch audit  

---

## 4 (supplement). New Source Onboarding Ease (v3.0)

### 4.1 Overall: ★★★★☆ (convenient, with "last mile" friction)

Goal "ops edits JSON, not Python" is largely met across **common built-in connectors + external executors + plugins**. Current onboarding entry: [complete workflow](../../docs_user/03-configure-data-sources.md); field details: [Log Format Discovery](../../docs_user/20-log-format-discovery.md) and the [field guide sample](../../docs_ai/asset-es-waf-prod-field-guide.md).

| Stage | Ease | Notes |
|---|---|---|
| Register connector + asset | ★★★★★ | JSON templates + Schema; `credentials_ref` separate from config |
| Format discovery (new log) | ★★★★☆ | `discover.py` + log-format-discovery Skill; **LLM review required** |
| Write mapping/templates | ★★★★☆ | `discover.py --apply` writes aliases/parser/schema; **not correlation_keys** |
| Validate and promote | ★★★★☆ | `validate.py` + `test-connector.py` + `promote-after-connectivity.py` |
| Post-onboarding Skill use | ★★★★☆ | `--from-bundle` auto-expand; needs `active` + scenario asset_types |

### 4.2 Scores by Onboarding Scenario

| Scenario | Difficulty | Typical steps | Example asset |
|---|---|---|---|
| **SLS/ES structured fields** (new logstore, known `waf_alert`, etc.) | ⭐ Low | connector → asset → `schema.fields` + aliases → template → validate; omit `text_parser` | `asset-waf-prod-01`, `asset-es-waf-prod` |
| **Change project/logstore** (same format) | ⭐ Very low | connector `config` + aliases if needed | Copy active asset, new ID |
| **SSH/local built-in text** | ⭐ Low | `text_parser: syslog_auth` / `nginx_combined` | `asset-ssh-web-01-file` |
| **MySQL/PG structured table** | ⭐ Low | `database_ro` + SQL template `:param` | `asset-cmdb-hosts`, `asset-pg-cmdb-hosts` |
| **Brand-new text line format** | ⭐⭐ Medium | `parsers/*.json` (`line_regex`) + format discovery | `parsers/iso_syslog_auth.json` |
| **Brand-new asset_type** | ⭐⭐ Medium | schema enum + evidence-minimum-fields + scenarios + template fallback | NTA/Win/Linux demonstrated |
| **Brand-new connector type** | ⭐ Low (external/plugin) to ⭐⭐⭐ High (in-core) | External executor only adds config; plugin adds an isolated package; in-core connector changes platform fetch | `external_generic`, connector plugins, built-in cloud vendor examples |
| **HTTP API WAF** | ⭐⭐ Medium | `http_api` + `waf_api_search` template; `asset-waf-api-prod` still in discovery | pending format discovery |

### 4.3 Remaining Onboarding Friction

| Issue | Impact |
|---|---|
| **Product UI still needs polish** | Onboarding/credentials/validation pages exist, but explanation, previews, error guidance, and screenshot tutorials need more work |
| **Taxonomy semi-registered** | `ids_alert` / `edr_event` no templates to copy |
| **SLS/ES dual path** | Same asset_type two assets — which to copy? |
| **Placeholder connectors** | Copy example, forget `YOUR_SLS_PROJECT`, promote fails |
| **bundle vs status** | Bundle `active` during onboarding → persistent validate errors |

### 4.4 Suggested Improvements

| Priority | Item |
|---|---|
| P1 | `discover.py --apply` | ✅ see the current field-discovery guide |
| P1 | per-asset `field_aliases` | ✅ |
| P1 | complete `dns_log` + onboarding three-file kit | ✅ `dataasset/onboarding/` |
| P2 | FAQ **SLS vs ES path decision table**; bundle default `draft` during onboarding |
| P2 | Product UI: wizard connector → discovery → promote |

---

## 4 (supplement 2). Format Mapping Ease (v3.0)

### 5.1 Overall: ★★★★☆ (clear model; JSON smoothest, text next)

Platform uses a **two-layer field model**; see the current [field discovery and normalization guide](../../docs_user/20-log-format-discovery.md):

```text
Query layer (template)  → source field names (ip, @timestamp, client_ip)
Evidence layer (Skill)    → canonical (src_ip, timestamp, url…)
```

Split **reduces** "fetched but Skill fields empty"; cost is **multiple alias paths per canonical** — needs discipline.

### 5.2 Mapping Path by Format

| Log format | Config entry | Change Python? | Ease | Notes |
|---|---|---|---|---|
| **JSON fields already expanded by the SLS/ES SDK** | Omit `text_parser` + **`field_aliases`** | ❌ | ★★★★★ | Most common; gateway `ip`→`src_ip` |
| **JSON + nested object in field value** | `text_parser: json_lines2` + **dot fields** + `field_aliases` | ❌ | ★★★★★ | `fields: "{...}"` → `fields.user`, `fields.session.tty` |
| **syslog auth** | `text_parser: syslog_auth` | ❌ | ★★★★★ | Built-in, zero regex |
| **nginx combined** | `text_parser: nginx_combined` | ❌ | ★★★★★ | Built-in |
| **Custom text** | `dataasset/parsers/<id>.json` + `line_regex` | ❌ | ★★★★☆ | Named groups → keys; aliases → canonical |
| **Inline regex** | `text_parser: { line_regex, ... }` | ❌ | ★★★☆☆ | PoC only |
| **DB column names** | SQL template `AS` alias or aliases | ❌ | ★★★★☆ | `:param` binding |
| **ES nested fields** | Template DSL source path; aliases flatten | ❌ | ★★★☆☆ | Deep nesting needs format discovery + careful DSL |
| **New binary/EVTX** | Must land in SLS/ES as JSON or text first | — | ★★☆☆☆ | No direct `.evtx` grep (design explicit) |

Only **4** built-in parsers ([`text-log-parsers.json`](../../dataasset/configure/text-log-parsers.json)); custom parser repo has **1** example (`iso_syslog_auth.json`) — docs OK, **samples sparse**.

### 5.3 Mapping Mechanism Pros and Cons

| Strengths | Pain points |
|---|---|
| Query vs evidence split, clear failure localization | Template query fields often hard-coded source names — sync with aliases |
| `discover.py --apply` writes per-asset aliases | Complex multiline / nested JSON still LLM + manual regex |
| **correlation_keys auto-derived**, matrix single source of truth | New Joins still need fetch_plan coverage governance and UI preview |
| `normalizer` unified evidence_id, ISO time, **time_correction**, masking | Large clock skew needs source NTP + manual wider fetch window |

### 5.4 Typical Mapping Workflow (Ops View)

```text
Sample logs
  → discover.py (structure probe + alias suggestions)
  → LLM review (log-format-discovery)
  → ① evidence-minimum-fields.json  field_aliases
  → ② asset.json  text_parser + schema.fields
  → ③ templates.json  query fields (source names!)
  → ④ parsers/*.json (only non-JSON/non-built-in text)
  → validate + test-connector + --preview-normalize
  → discovery → draft → active
```

**Minimum touch** (JSON new source, rename only): **② aliases + ③ template**.  
**Maximum touch** (brand-new text): **①–④** all.

### 5.5 Suggested Mapping Improvements

| Priority | Item |
|---|---|
| P1 | **per-asset `field_aliases` override** | ✅ |
| P1 | discover **`--apply`** | ✅ |
| P1 | **correlation_keys auto-derivation** (no hand-write) | ✅ 2026-06-25 |
| P2 | Template **field indirection** (`connector.field_map` not hard-coded `src_ip`) |
| P2 | More **built-in parsers** or grok library (Windows Event, CEF, common WAF vendors) |
| P3 | Split alias tables **by domain/asset_type** to avoid global JSON bloat |

---

## 5. Design vs Implementation Table

| Design capability | v2.2 | v2.3 | v2.5 | **v2.8** |
|---|---|---|---|---|
| Six-source live fetch | ✅ | ✅ | ✅ | ✅ |
| MySQL database_ro | ✅ | ✅ | ✅ | ✅ |
| PostgreSQL database_ro | ❌ | ✅ | ✅ | ✅ |
| ES fetch + es_query template | ✅ | ✅ | ✅ | ✅ |
| evidence Normalizer | ✅ | ✅ | ✅ | ✅ |
| Multi-connector aggregation | ✅ | ✅ | ✅ | ✅ |
| catalog auto-scan | ✅ | ✅ | ✅ | ✅ |
| Log format discovery | ✅ | ✅ | ✅ | ✅ |
| Data source onboarding FAQ | ❌ | ✅ | ✅ | ✅ |
| asset_type: NTA / Win / Linux syslog | ❌ | ✅ | ✅ | ✅ |
| coverage hint deterministic match | ❌ | ✅ | ✅ | ✅ |
| status/bundle contract | — | ✅ | ✅ | ✅ |
| **`dns_log` end-to-end** | ❌ | ❌ | ✅ | ✅ |
| **correlation_engine + join_edges** | ❌ | ❌ | ❌ | **✅** |
| **correlation_keys derivation** | ❌ | ❌ | ❌ | **✅** |
| **time_correction** | ❌ | ❌ | ❌ | **✅** |
| **examples/reference-assets** | ❌ | ❌ | ❌ | **✅** |
| validate 0 error | ❌ | ❌ | ❌ | **✅** |
| fetch by correlation_fetch_plan | ❌ | ❌ | ❌ | **✅** |
| fetch audit | ❌ | ❌ | ❌ | ❌ |
| CI / release gate (validate + test + docs) | ❌ | ❌ | ❌ | **✅ local gate; remote matrix pending** |
| Product UI | ❌ | ❌ | ❌ | **✅ basic usable; UX polishing continues** |

### Catalog Scale and Placeholders (2026-06-21)

| Type | Count | Notes |
|---|---|---|
| assets | 24 | active **6** · draft 17 · discovery 1 |
| connectors | 21 | active **12** · draft 9; example placeholders remain for private deployment replacement |
| bundles | 4 | active 3 · draft 1; active bundles still need draft-member conflict attention |
| test entry files | 5 test files | docs links, release_scan, SecWeaver CLI, dataasset UI, report markdown |

---

## 6. Optimization Recommendations (by Priority)

### P0 — Ops readiness (non-code)

| # | Item | Notes |
|---|---|---|
| 1 | **Real SLS project/logstore** | Priority D2/WEB: `conn-sls-secweaver-host-events`, `web-access`, `host-connect`, etc. Use private config outside the public tree |
| 2 | **Promote + bundle publish** | Connectivity → `promote-after-connectivity.py` → all members active → bundle `active` (or bundle `draft` during onboarding) |
| 3 | **dns_log or adjust scenarios** | S1 P1 needs DNS; add template+asset or downgrade scenario |
| 4 | **discovery dequeue** | `asset-waf-api-prod` format discovery → draft |

### P1 — Engineering

| # | Item | Status |
|---|---|---|
| 5 | evidence Normalizer | ✅ |
| 6 | DB / HTTP / ES fetch | ✅ |
| 7 | PostgreSQL database_ro | ✅ |
| 8 | Firewall src_ip-only template | ✅ |
| 9 | coverage hint match | ✅ |
| 10 | status / bundle contract | ✅ |
| 11 | Tighten text_parser JSON Schema | ✅ `not enum` fixed oneOf ambiguity |
| 12 | **`dns_log` template + evidence + example** | ✅ |
| 13 | masking / pii_fields alignment | ✅ done (§3.3.2) |
| 14 | validate sample params per asset_type | Pending |
| 15 | **Release gate: validate + unittest + docs** | ✅ local release_scan/docs-check exists; remote CI matrix pending |
| 16 | targeted `http_fetch` tests | Pending |
| 17 | discover **`--apply`** | ✅ `discover_apply.py` + CLI |
| 18 | **per-asset `field_aliases`** | ✅ schema + `normalizer` |
| 19 | **dns_log template + example + onboarding kit** | ✅ `asset-dns-internal-prod` + `dataasset/onboarding/` |
| 20 | validate sample params per asset_type | Pending |

### P2 — Product and UX

| # | Item |
|---|---|
| 19 | Product UI: continue productizing asset registration, credential ref, bundle selection, connectivity |
| 20 | SOPS multi-recipient / CI decrypt docs |
| 21 | SLS vs ES onboarding path decision table (FAQ) |
| 22 | Per-connector **minimum three-file copy template** |
| 23 | coverage.hosts IP-only validation and UI hints |
| 24 | asset/connector version fields |
| 25 | connector `constraints` per-type schema |
| 26 | fetch query audit |
| 27 | Built-in parser / grok library expansion |
| 28 | `json_lines2` guidance for syslog-risk-json nested JSON logs |

---

## 7. Architecture Diagram (v2.5)

```text
dataasset JSON ──► validate.py (+ JSON Schema, catalog sync)
                      │
                      ├──► template_select (query fields by connector_type)
                      ├──► vault (SOPS)
                      ├──► fetch
                      │      ├── sls
                      │      ├── ssh_file / local_file
                      │      ├── database_ro (mysql │ postgresql)
                      │      ├── http_api
                      │      └── es (Elasticsearch _search)
                      ├──► aggregate (multi-connector dedupe)
                      ├──► normalizer (evidence_id, timestamp, alias, masking)
                      └──► Skill (completeness / trace / alert / risk --from-bundle)
```

---

## 8. Summary

### Is it clear?

**Yes.** Two-layer model, multi-source fetch, credential separation, templated queries, D1–D7 vs S1–S7 decoupling, FAQ for field normalization — security ops and onboarding can execute independently.

### Is it extensible?

**Taxonomy and template paths extend easily** (PG/ES/NTA verified). **New JSON sources low cost**; **new text formats** via parsers without Python, but regex quality depends on people/models.

### Is onboarding new data easy? (v3.0)

**Same-class multi-source, known asset_type: convenient (★★★★☆)** — copy three-file kit + aliases/field_aliases + validate.  
**Brand-new format/type: medium (★★★☆☆)** — discovery + `--apply` loop exists; `correlation_keys` auto-derived.  
**Brand-new connector type: easy through external/plugin paths, medium-high as in-core support** — external executors are config-only, plugins do not change core, and only in-core maintenance needs a platform-owned fetch implementation.

### Is format mapping easy? (v3.0)

**JSON: easiest (★★★★★)** — `json_lines` / `json_lines2` + global / per-asset `field_aliases`.  
**Built-in text: easy (★★★★★)** — change `text_parser` enum.  
**Custom text: fairly easy (★★★★☆)** — `parsers/*.json`, no Python.  
**Cross-source correlation: fairly easy (★★★★☆)** — matrix single source + engine; assets only `fields` + aliases.  
**Complex nesting / clock skew: awkward (★★★☆☆)** — `time_correction` and manual wider windows as bridge.

### Top 5 optimization points (v3.0)

1. **Ops loop** — real SLS project → promote D2/WEB → bundle and validate coherent.  
2. **Fetch chain governance** — `fetch.py` already consumes `correlation_fetch_plan`; continue coverage summary, UI preview, and audit.  
3. **Schema quick wins** — `text_parser` oneOf fixed; continue catalog, connector constraints, example status.  
4. **Field reference maintenance** — run `build-field-reference.py` after evidence/matrix changes.  
5. **Product UI** — wizard connector → discovery → promote.

### Worth doing but not blocking integration

- SLS vs ES dual-path FAQ (§3.8)  
- `pii_fields` vs `masking` role merge (§3.3.2)  
- `promote-after-connectivity` extend asset_types  
- connector `bastion_id` reference validation  

---

## 9. Cross-References to Main Design Doc

Main design [data-asset-design.md](../09-data-asset-design.md) uses new definitions: asset-side host binding removed; host coverage via `coverage.hosts` source IPs; `syslog_risk_alert` and `json_lines2` documented; fetch by plan is now the primary path, with coverage governance and UI explanation as next work.

Correlation matrix evaluation: [correlation-matrix-design-evaluation.md](22-correlation-matrix-design-evaluation.md).

---

## 10. Issue Checklist (Quick Reference, v3.0)

| Category | Issue | Priority |
|---|---|---|
| Ops | 7× SLS `YOUR_SLS_PROJECT`, bundle active vs draft conflict | P0 |
| Ops | Three default bundles completeness `not_traceable` | P0 |
| **Onboarding** | discover output needs manual 3–4 file edits, no `--apply` | ✅ done |
| **Mapping** | `field_aliases` global only | ✅ per-asset supported |
| **Correlation keys** | hand-written `correlation_keys` duplicates matrix | ✅ auto-derived |
| Schema | `text_parser` oneOf 9 errors, `environment: lab` 1 error | ✅ `text_parser` fixed; enum/catalog cleanup ongoing |
| Taxonomy | `dns_log` no template/asset/evidence | ✅ |
| Engineering | remote CI matrix, targeted http_fetch tests, matrix negative fixtures | P1–P2 |
| Correlation | fetch_plan coverage summary and full matrix lateral BFS | P1–P2 |
| Doc/ops | SLS vs ES dual path confusion | P2 |
| Platform | UI needs more product polish; no fetch audit | P2 |
| Resolved | status/bundle, coverage hint, multi-source fetch, FAQ Q3, config-driven parser, correlation_engine, correlation_keys derivation | ✅ |

---

## 11. Onboarding vs Mapping — One-Line Comparison

| Question | Conclusion |
|---|---|
| **Is onboarding new data easy?** | **Easy** (existing connector + known type); **medium** (new format/type); **easy through external/plugin paths and medium-high for in-core support** (new connector type) |
| **Is format mapping easy?** | **JSON/built-in text easiest**; **custom text** still zero Python; **complex nesting/cross-source** main friction |
| **Who changes Python?** | Ops **does not**; external/plugin connectors do not change core; only new in-core connectors or DB engines need platform fetch changes |
| **Must-read docs** | [complete onboarding](../../docs_user/03-configure-data-sources.md), [field discovery and normalization](../../docs_user/20-log-format-discovery.md), [field guide sample](../../docs_ai/asset-es-waf-prod-field-guide.md), [field reference](../../dataasset/examples/reference-assets.json) |

---

*Document version: v2.8 | Tenth evaluation: 2026-06-25 | Increments: correlation_engine, correlation_keys derivation, time_correction, reference-assets*

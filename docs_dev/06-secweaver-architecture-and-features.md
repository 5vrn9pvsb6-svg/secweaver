**Languages:** English (this page) | [简体中文](06-secweaver-architecture-and-features.zh-CN.md)

# SecWeaver Architecture and Features

> SecWeaver is an AI-native security analysis and traceability investigation platform for security operations.  
> Architecture overview, module responsibilities, skill chain, and documentation index

**One-line positioning**: SecWeaver is an AI-native security analysis and traceability investigation platform for security operations.

---

## 1. Scope

This page owns module dependencies, data flow, and implementation boundaries. Read [concepts](../docs_user/01-getting-started.md) and the [skill directory](../docs_user/06-skills-and-usage.md) for product and task selection. Local Community workflows do not require private server code; managed integrations use the public client contract.

## 2. Overall Architecture

### 2.1 Layered Architecture

```text
┌─────────────────────────────────────────────────────────────────────────┐
│  Interaction layer: AI Agent chat (Cursor / CC / Codex / OpenClaw …) / CLI / run_pipeline.py │
│  Natural-language tasks · select asset bundles · --from-bundle --fetch                       │
└───────────────────────────────┬─────────────────────────────────────────┘
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  Skill layer (src/skills/)                                               │
│  Completeness │ Alert confirmation │ Traceability │ Risk identification │ Format discovery                    │
└───────────────────────────────┬─────────────────────────────────────────┘
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  Data access layer (src/skills/_shared/data-access/)                        │
│  registry → template_select → vault → fetch → aggregate → normalizer    │
└───────────────────────────────┬─────────────────────────────────────────┘
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  Asset layer (dataasset/)                                                    │
│  assets · connectors · bundles · query-templates · schema · credentials │
└───────────────────────────────┬─────────────────────────────────────────┘
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  Data sources (production systems)                                                        │
│  Alibaba Cloud SLS · SSH logs · MySQL · HTTP API · Elasticsearch · Agent→SLS    │
└─────────────────────────────────────────────────────────────────────────┘
```

### 2.2 Investigation Pipeline (Typical)

```text
                    ┌──────────────────────┐
  New log type ──────▶│ Format discovery (discovery)│──▶ draft/active asset
                    └──────────────────────┘
                                │
  User initiates investigation ◀────────────────┘
        │
        ▼
  Select bundle + fill params (IP, time, host, alert)
        │
        ▼
  ┌─────────────────┐
  │ Data source completeness analysis │── P0 missing → block, output onboarding recommendations
  └────────┬────────┘
           │ ready / partial
           ▼
  ┌─────────────────┐     ┌─────────────────┐
  │ fetch + normalize│────▶│ evidence_bundles │
  └────────┬────────┘     └────────┬────────┘
           │                       │
     ┌─────┴─────┐                 │
     ▼           ▼                 ▼
  Alert confirmation    Traceability analysis         Risk identification (exec/connect)
     │           │
     └───── success / needs deeper dive ────▶ Traceability analysis
```

### 2.3 Evidence Data Flow

```text
params + asset_id + template_id
        │
        ▼
template_select (select sls_query / ssh_command / local_file_command / sql / http / es_query by connector_type)
        │
        ▼
vault.resolve(credentials_ref)  ← AI / Skill only see ref
        │
        ▼
fetch (sls │ ssh_file │ local_file │ database_ro │ http_api │ es)
        │
        ▼
text_log_parser (SSH text, configured via asset.text_parser)
        │
        ▼
normalizer (evidence_id · ISO time · field_aliases · masking)
        │
        ▼
aggregate (multi-connector dedup merge, optional)
        │
        ▼
evidence_bundles.{asset_type}[]
        │
        ▼
Skill scripts + LLM triage
```

---

## 3. Repository Structure

```text
secweaver/
├── README.md                          # Product overview
├── docs_dev/                          # Developer, architecture, and design documentation
│   ├── secweaver-architecture-and-features.md    # This document
│   ├── data-asset-design.md           # dataasset main design
├── docs_user/                         # Operator and SOC usage documentation
│   ├── 13-SecWeaver-CLI.md               # Local CLI usage guide
│   ├── agent-collection-and-evidence-spec.md     # Collection chain + evidence fields
│   ├── 16-data-source-onboarding-faq.md  # Short onboarding answers and guide routing
│   └── … (per-Skill guides and design docs; Chinese: *.zh-CN.md)
├── dataasset/                         # Editable asset directory (L1/L2)
│   ├── assets/                        # Logical data assets
│   ├── connectors/                    # Connectors
│   ├── bundles/                       # Investigation asset bundles
│   ├── query-templates/               # Parameterized query templates
│   ├── schema/                        # JSON Schema + evidence spec
│   ├── parsers/                       # Custom text log regex (optional)
│   ├── credentials/                   # SOPS Vault
│   └── scripts/                       # validate · test-connector · catalog
├── src/skills/                    # Agent Skills (shared across Cursor / CC / Codex / OpenClaw)
│   ├── _shared/data-access/           # Data access layer implementation
│   ├── data-source-completeness/
│   ├── alert-confirmation/
│   ├── traceability-analysis/
│   ├── external-listener-cmd-risk/
│   └── log-format-discovery/
├── src/tools/
│   └── secweaver-agent/               # Unified host-side collection client (Go)
└── requirements-data-access.txt       # fetch layer Python dependencies
```

---

## 4. Data Asset Layer (dataasset)

### 4.1 Two-Layer Model

| Layer | Object | Responsibility |
|---|---|---|
| **L1** | `DataAsset` | Investigation-visible "what data exists": asset_type, schema, coverage |
| **L2** | `DataConnector` | "How to connect": endpoint, host, index; **no secrets** |

Logical assets bind one or more connectors via `connector_id` / `connector_ids[]`; the same `asset_type` can aggregate multiple sources (e.g., SLS aggregation + multi-host SSH).

### 4.2 Asset Status

| status | Meaning | Selectable in dialog |
|---|---|---|
| `discovery` | Format discovery queue, pending field mapping | No |
| `draft` | Under editing | No |
| `active` | Published | Yes |
| `disabled` | Disabled | No |

### 4.3 Supported Connector Types

| connector_type | Purpose | Template field | fetch module |
|---|---|---|---|
| `sls` | Alibaba Cloud Log Service | `sls_query` | `fetch.py` |
| `ssh_file` | SSH read auth/nginx, etc. | `ssh_command` | `ssh_fetch.py` |
| `local_file` | Logs local to the intelligent agent runtime | `local_file_command` | `local_file_fetch.py` |
| `database_ro` | MySQL / PostgreSQL read-only | `sql` | `db_fetch.py` |
| `http_api` | REST API | `http` | `http_fetch.py` |
| `es` | Elasticsearch `_search` | `es_query` | `es_fetch.py` |
| `agent_stream` | Collection topology documentation | — | Queries go through sink SLS |

Text log parsing is configured via **`asset.text_parser`** (built-in `syslog_auth` / `nginx_combined` / `json_lines`, or `dataasset/parsers/*.json`); **operators do not modify Python**.

### 4.4 Credentials and Security

```text
connectors/*.json  →  credentials_ref: vault://sls/security-readonly
                              ↓
credentials/secrets/*.enc.yaml  (SOPS encrypted, committable to Git)
                              ↓
vault.py / fetch.py decrypt and inject (Skills and LLM never see plaintext)
```

### 4.5 Toolchain

| Command | Purpose |
|---|---|
| `python3 src/dataasset/validate.py` | JSON Schema, references, template matching gate |
| `python3 src/dataasset/validate.py --sync-catalog` | Sync catalog.json |
| `python3 src/dataasset/test_connector.py` | Single-asset/aggregate dry-run or live fetch |

See [dataasset/README.md](../dataasset/README.md) and [data-asset-design.md](09-data-asset-design.md).

---

## 5. Data Access Layer

Path: `src/skills/_shared/data-access/`

| Module | Responsibility |
|---|---|
| `registry.py` | Load assets / connectors / bundles / templates |
| `vault.py` | SOPS decrypt `credentials_ref` |
| `template_select.py` | Select template by asset + connector + params |
| `fetch.py` | Unified fetch entry, dispatches by connector_type |
| `aggregate.py` | Multi-connector merge, host filter, dedup |
| `normalizer.py` | evidence_id, ISO time, field_aliases, masking |
| `text_log_parser.py` | Configurable text log parsing (shared by SSH / local_file) |
| `scenario_fetch.py` | Scenario fetch plans, investigation windows and bounded evidence expansion; no concrete Skill Python invocation |
| `skill_input.py` | Compatibility alias of `../skill_runtime/inputs.py` |
| `prepare.py` | Compatibility entry; `--bundle ID` prepares metadata, `--run-skill` also assesses |
| `run_pipeline.py` | Compatibility entry of `../skill_runtime/pipeline.py` |

Shared Skill input/precheck adaptation, assessment invocation and workflow order
belong to [`src/skills/_shared/skill_runtime/`](../src/skills/_shared/skill_runtime/README.md).
Concrete Skills own their rules and verdicts; the evidence layer never imports
their Python implementations. Plugin discovery/validation/execution reuse
`src/dataasset/plugin_contract.py` with a 30-second default and whole-response
validation. See [Connector Plugins](04-connector-plugins.md) for migration details.

Minimum evidence fields: `dataasset/configure/evidence-minimum-fields.json` and [agent-collection-and-evidence-spec.md](12-agent-collection-and-evidence-spec.md).

---

## 6. Skill System

All Skills live under `src/skills/` (repository convention path, **not Cursor-specific**). **SKILL.md** guides each intelligent agent; core Skills include **deterministic Python scripts** for repeatability and testing.

### 6.1 Skill and scenario index

The [skill directory](../docs_user/06-skills-and-usage.md) owns the skill list and S1–S8 mapping. This section describes invocation and blocking rules.

### 6.3 Skill Chain and Blocking Rules

```text
Data source completeness analysis
  ├── overall_verdict = insufficient → next_skill_blocked = true
  └── P0 ready → allow Alert confirmation / Traceability analysis

Alert confirmation
  ├── attack_outcome = success → recommend starting traceability
  └── WAF only, no D2 → cannot confirm "success"; confidence ceiling limited

Traceability analysis
  └── Built-in completeness pre-check (--from-bundle can skip with --skip-completeness)
```

### 6.4 CLI Pipeline

```bash
# Completeness + traceability (live fetch)
python3 src/skills/_shared/data-access/run_pipeline.py trace-chain \
  --params '{"attacker_ip":"203.0.113.10","time_start":"...","time_end":"...","host":"web-01"}' \
  --fetch --pretty

# Completeness + alert confirmation
python3 src/skills/_shared/data-access/run_pipeline.py alert-chain \
  --bundle bundle-alert-confirm-min \
  --params '{...}' --fetch
```

Individual Skills also support `--from-bundle --fetch`; see [_shared/data-access/README.md](../src/skills/_shared/data-access/README.md).

---

## 7. Host Collection and Agent Chain

### 7.1 audit-port-execmon

Path: `src/tools/secweaver-agent/pkg/auditportexecmon/` (Go + auditd module)

- Monitors `execve`, optional `connect`, and file operations of processes bound to **externally listening ports**
- Outputs JSON Lines → ingested into SLS → registered as `host_exec` / `host_connect` / `host_file_op` assets
- Skill: **external-listener-cmd-risk**

### 7.2 Agent → SLS

exec/connect and other host behavior data are written to SLS by the Agent; **fetch always uses the `sls` connector**, not direct queries via `agent_stream`. See [agent-collection-and-evidence-spec.md](12-agent-collection-and-evidence-spec.md) §1.2.

---

## 8. New Data Source Onboarding

```text
1. connectors/ + credentials (SOPS)
2. assets/ registration; set status=discovery for new formats
3. log-format-discovery: discover.py + LLM mapping
4. Configure text_parser / field_aliases / query-template
5. status: discovery → draft → active
6. validate.py + test_connector.py
```

Short FAQ: [16-data-source-onboarding-faq.md](../docs_user/16-data-source-onboarding-faq.md)

---

## 9. Seven Data Domains (D1–D7)

| Domain | Meaning | Typical asset_type |
|---|---|---|
| D1 | Perimeter and WEB | waf_alert, web_access_log |
| D2 | Host behavior | host_exec, host_connect, host_file_op, windows_event_log, linux_syslog |
| D3 | Authentication access | ssh_auth |
| D4 | Network | firewall_log, dns_log, network_traffic_audit |
| D5 | Application and API | app_api_log |
| D6 | Assets and vulnerabilities | asset_inventory, vuln_scan |
| D7 | Audit and DB | db_audit |

The completeness analysis Skill checks P0/P1/P2 coverage per domain for scenarios S1–S8.

---

## 10. Current Public Implementation Summary

This table helps contributors locate the main public capabilities; it is not a standalone version manifest. Current behavior is defined by repository code, DataAsset Schemas, automated tests, and module READMEs. See the root [`CHANGELOG.md`](../CHANGELOG.md) for version changes and migrations.

| Capability | Status |
|---|---|
| dataasset directory + JSON Schema + validate | ✅ |
| SOPS Vault + credentials_ref | ✅ |
| Multi-source fetch (SLS / SSH / local file / DB / HTTP / ES / cloud vendors / SIEM / warehouse / plugins / external executors) | ✅ |
| normalizer + multi-connector aggregation | ✅ |
| Configurable text_parser | ✅ |
| Format discovery Skill (discovery queue) | ✅ |
| Four core triage Skills + run_pipeline | ✅ |
| audit-port-execmon collection tool | ✅ |
| DataAsset Studio | ✅ Local configuration, diagnostics, onboarding, and sample-report viewing |
| Multi-user RBAC / approval workflow | Outside the Community local Studio; managed capabilities are not promised as open-source features |
| Multi-database drivers | ✅ MySQL / PostgreSQL / Oracle / SQL Server / SQLite split by independent fetch files |

See the [historical DataAsset design assessment](history/10-data-asset-design-evaluation.md) for past gaps and design decisions. Dates, scores, and TODOs in that assessment describe its evaluation period only.

---

## 11. Documentation Index

### 11.1 Platform and Architecture

| Document | Description |
|---|---|
| [README.md](../README.md) | Product positioning and quick start |
| **This document** | Architecture and feature overview |
| [13-SecWeaver-CLI.md](../docs_user/13-SecWeaver-CLI.md) | Local CLI commands, demos, and Skill wrapping |
| [data-asset-design.md](09-data-asset-design.md) | dataasset detailed design |
| [Historical DataAsset design assessment](history/10-data-asset-design-evaluation.md) | Dated implementation review; not a current backlog |
| [agent-collection-and-evidence-spec.md](12-agent-collection-and-evidence-spec.md) | Collection and evidence |
| [03-configure-data-sources.md](../docs_user/03-configure-data-sources.md) | Complete onboarding lifecycle |
| [16-data-source-onboarding-faq.md](../docs_user/16-data-source-onboarding-faq.md) | Short onboarding answers and guide routing |

### 11.2 Skill Usage Guides

| Document | Skill |
|---|---|
| [15-data-source-completeness.md](../docs_user/15-data-source-completeness.md) | data-source-completeness |
| [17-alert-confirmation.md](../docs_user/17-alert-confirmation.md) | alert-confirmation |
| [18-traceability-analysis.md](../docs_user/18-traceability-analysis.md) | traceability-analysis |
| [19-risk-identification.md](../docs_user/19-risk-identification.md) | risk-identification |
| [23-external-listener-command-risk.md](../docs_user/23-external-listener-command-risk.md) | external-listener-cmd-risk (exec sub-module) |
| [20-log-format-discovery.md](../docs_user/20-log-format-discovery.md) | log-format-discovery |

### 11.3 Skill Design Documents

| Document | Description |
|---|---|
| [data-source-completeness-skill-design.md](13-data-source-completeness-skill-design.md) | |
| [alert-confirmation-skill-design.md](14-alert-confirmation-skill-design.md) | |
| [risk-identification-skill-design.md](17-risk-identification-skill-design.md) | |
| [traceability-analysis-skill-design.md](15-traceability-analysis-skill-design.md) | |
| [log-format-discovery-design.md](20-log-format-discovery-design.md) | |

### 11.4 Implementation and Operations

| Path | Description |
|---|---|
| [dataasset/README.md](../dataasset/README.md) | Asset directory editing |
| [src/skills/README.md](../src/skills/README.md) | Skill directory and commands |
| [_shared/data-access/README.md](../src/skills/_shared/data-access/README.md) | fetch / Vault CLI |
| [src/tools/secweaver-agent/README.md](../src/tools/secweaver-agent/README.md) | Unified host collection client |

---

## 12. Quick Command Reference

```bash
# Dependencies
pip install -r requirements-data-access.txt

# Validate asset directory
python3 src/dataasset/validate.py --sync-catalog

# Format discovery queue
python3 src/skills/log-format-discovery/scripts/discover.py --list-discovery

# Completeness analysis
python3 src/skills/data-source-completeness/scripts/check.py \
  --from-bundle --params '{"attacker_ip":"203.0.113.10"}'

# Investigation pipeline
python3 src/skills/_shared/data-access/run_pipeline.py trace-chain \
  --params '{"attacker_ip":"203.0.113.10","time_start":"2026-06-21T08:00:00+08:00","time_end":"2026-06-21T20:00:00+08:00"}' \
  --fetch --pretty
```

---

## 13. Relationship to Traditional SOC Tools

SecWeaver **does not replace** WAF, SIEM, or EDR. Instead it:

1. **Registers** data from these systems uniformly as dataassets  
2. **Fetches and normalizes** into evidence for cross-source Skill correlation  
3. Uses **AI agent** within skill boundaries for completeness checks, alert confirmation, traceability, and reporting

Security teams control secrets and query templates; AI handles repetitive work and structured output, while key conclusions remain subject to human review.

---

*Maintenance note: When architecture changes (new connector, new Skill, pipeline adjustments), update this document and [data-asset-design.md](09-data-asset-design.md) together.*

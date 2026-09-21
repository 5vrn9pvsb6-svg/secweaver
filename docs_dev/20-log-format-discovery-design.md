# Log Format Discovery Design

**Languages:** English (this document) | [简体中文](20-log-format-discovery-design.zh-CN.md)

> SecWeaver **LLM-driven** Skill: **format analysis and field mapping before onboarding new log types**  
> Implementation: [`src/skills/log-format-discovery/`](../src/skills/log-format-discovery/)  
> Version: 1.1

**Scope of this document**: goals, architecture, human–machine division, report schema, and integration with dataasset / normalizer for the format discovery Skill.  
**Out of scope**: runtime fetch, multi-connector aggregation, Skill assessment logic (see [data-asset-design.md](09-data-asset-design.md), [agent-collection-and-evidence-spec.md](12-agent-collection-and-evidence-spec.md)).

**Related documents**:

| Document | Description |
|---|---|
| [20-log-format-discovery.md](../docs_user/20-log-format-discovery.md) | Skill usage (chat / workflow) |
| [SKILL.md](../src/skills/log-format-discovery/SKILL.md) | Agent playbook (when to use, commands, landing checklist) |
| [reference.md](../src/skills/log-format-discovery/reference.md) | Spec cross-reference, alias rules, file paths |
| [examples.md](../src/skills/log-format-discovery/examples.md) | auth / WAF / unknown format end-to-end examples |
| [output-schema.json](../src/skills/log-format-discovery/output-schema.json) | Agent mapping output JSON Schema |
| [Data Asset Design §Normalizer](09-data-asset-design.md) | Runtime normalization responsibilities |
| [Agent Collection and Evidence Spec §1.9](12-agent-collection-and-evidence-spec.md) | Position in platform onboarding flow |

---

## 1. Design Goals

### 1.1 Problems to Solve

| Gap | Consequence |
|---|---|
| New log formats use different field names (`client_ip` vs `remote_addr`) | Skills cannot correlate across sources; completeness analysis misjudges |
| No unified pre-onboarding flow | Everyone hand-writes parsers, repeats mistakes, skips validate |
| Debate "LLM reads raw" vs "normalize first" with no basis | Architecture drifts; audit and masking fail |
| Text logs (auth/nginx/custom) need regex | No sample-driven gap analysis and mapping draft |

### 1.2 Design Principles

```text
1. LLM required: field semantic mapping, unknown-format parsers — done by Cursor Agent (LLM)
2. Script assists: discover.py does format detection / key stats / gap analysis for LLM context (no production access, does not replace LLM)
3. Normalize first: mapping results go to evidence-minimum-fields + normalizer; runtime does not LLM-parse each line
4. Align with existing dataasset model: outputs map directly to asset / connector / template / schema files
5. Auditable: report JSON + output-schema trail; user confirms before repo changes
6. Security: do not commit samples/reports with sensitive data; template drafts must not contain secrets
```

### 1.2.1 Why "LLM-dependent" but `discover.py` does not call an LLM API?

| Question | Answer |
|---|---|
| Does this Skill depend on an LLM? | **Yes.** Running the script alone is incomplete; Step 3 must produce mapping JSON via Agent |
| Where does the LLM run? | Cursor chat Agent (the LLM), consuming `llm_prompt` + report + samples |
| Why no API in the script? | Agent is already the LLM runtime; script does deterministic preprocessing — avoids duplicate keys, enables CI regression on format detection |
| vs runtime LLM raw parsing? | Format discovery is **one-time onboarding** design; fetch uses deterministic normalizer, not per-log LLM |

### 1.3 Position in the Platform

```text
┌─────────────────────────────────────────────────────────────┐
│  Ops / dev: sample logs (file, paste, exported JSONL)         │
└────────────────────────────┬────────────────────────────────┘
                             ▼
┌─────────────────────────────────────────────────────────────┐
│  log-format-discovery (this Skill)                            │
│  discover.py → format detection / gap / llm_prompt (preprocess)│
│  Cursor Agent (LLM) → field mapping / parser / template design │
│  Agent + user confirm → evidence / normalizer / asset landing │
└────────────────────────────┬────────────────────────────────┘
                             ▼
┌─────────────────────────────────────────────────────────────┐
│  dataasset/ (registration) + validate.py + test_connector.py │
└────────────────────────────┬────────────────────────────────┘
                             ▼
┌─────────────────────────────────────────────────────────────┐
│  Data access layer fetch → normalizer → evidence_bundles → Skill│
└─────────────────────────────────────────────────────────────┘
```

**Relation to normalize vs LLM**:

| Phase | Executor | Input | Output |
|---|---|---|---|
| Format discovery (pre-onboarding) | discover.py + **LLM (Agent)** | Sample raw | Mapping draft, parser design, landable config |
| Runtime normalize | `normalizer.py` | Fetched raw event | canonical + evidence_id + masking |
| Assessment semantics | Downstream Skill + LLM | Normalized events | False positive / trace conclusions |

Keep `raw_line` only as **optional** semantic supplement, not primary Skill input.

---

## 2. Architecture

### 2.1 Components

```text
src/skills/log-format-discovery/
├── SKILL.md                 # Agent trigger and workflow
├── reference.md             # Spec cross-reference
├── examples.md              # Use cases
├── output-schema.json       # Agent output contract
├── scripts/discover.py      # Preprocessing engine (report + llm_prompt for LLM)
├── scripts/discover_apply.py # Validated, locked registry apply boundary
└── samples/                 # Committable redacted samples

docs_dev/20-log-format-discovery-design.md   # This document
```

| Component | Responsibility |
|---|---|
| `discover.py` | Read samples; read **dataasset/** (evidence spec, peer assets, templates); gap; `llm_prompt` |
| `discover_apply.py` | Require the same discovery Asset, stage all changes, validate available Schemas, then write under the shared registry lock |
| **Cursor Agent (LLM)** | **Required**: map against registered dataasset + samples; produce mapping and landing diff |
| `SKILL.md` | Teach Agent when to run script, **how to invoke LLM for mapping**, which files to land |
| `output-schema.json` | JSON structure constraints for Agent mapping plan |
| `evidence-minimum-fields.json` | Spec source: required fields, existing `field_aliases` |
| `normalizer.py` / `ssh_fetch.py` | Runtime mapping and text parsing |

### 2.2 Human–Machine Division

```text
┌──────────────┐     ┌──────────────────┐     ┌──────────────┐
│ discover.py  │ ──▶ │ Cursor Agent     │ ──▶ │ Repo changes │
│ (preprocess) │     │ (LLM · required) │     │ (user confirm)│
└──────────────┘     └──────────────────┘     └──────────────┘
       │                     │                     │
       ▼                     ▼                     ▼
  detected_format      semantic field map      field_aliases
  key_counts           regex / parser design   ssh_fetch extension
  gap_analysis         correlation_keys        asset/connector
  llm_prompt           confidence / open Qs    templates.json
```

**Preprocessing does not**: replace LLM semantic mapping, decrypt Vault, fetch
production, or write configuration. The explicit `--apply` path writes only a
reviewed mapping through `discover_apply.py`; it rejects non-discovery targets
and validates every staged object before the first replacement.

Apply uses atomic replacement per JSON file and restores earlier replacements if
a later write raises. This is exception-safe under the shared lock; it is not a
filesystem transaction across files and cannot roll back a forced process or
machine termination between replacements.

**LLM must**: complete mapping against samples and evidence spec; mark confidence; list open_questions; Agent edits repo only after user confirmation.

### 2.3 Format Detection (discover.py)

| `detected_format` | Criteria | Preview parsing |
|---|---|---|
| `json_lines` | Most lines `json.loads` to object | Key frequency + alias inference |
| `syslog_auth` | Matches sshd auth line head | Configure `text_parser: syslog_auth` |
| `nginx_combined` | Matches combined log | Configure `text_parser: nginx_combined` |
| `text_unknown` | None of above | `raw_line` + simple `key=value` extraction |
| `empty` | No valid samples | Exit with error |

Detection uses **first N lines** (default ≤50); samples should be ≥3 lines covering variants (success/fail, different key names).

---

## 3. Data Flow and Report Schema

### 3.1 Input

| Parameter | Required | Description |
|---|---|---|
| `--asset-id` | yes* | dataasset asset ID, **must** be `status=discovery` |
| `--list-discovery` | no | List discovery queue and exit |
| `-i` / stdin / `--text` | one of three | Sample logs |

\* Mutually exclusive with `--list-discovery`.

`asset_type`, `connector_type` inferred from discovery asset and its connector — no CLI override.

### 3.1.1 dataasset Read Scope

| Scope | Loaded? |
|---|---|
| `assets/{asset_id}.json` with `status=discovery` | **Yes** (only object processed) |
| draft/active assets of same asset_type | **No** |
| Bound connector | Yes (connector_type read-only) |
| `configure/evidence-minimum-fields.json` | Yes |
| `query-templates/templates.json` | Yes (match asset_type + connector_type) |

### 3.2 Core Report Fields

| Field | Meaning |
|---|---|
| `detected_format` | Format classification |
| `dataasset_context.discovery_asset` | Current discovery-queue asset |
| `discovery_asset_hints` | Existing fields / template_ids on asset |
| `requirements` | required / recommended from `evidence-minimum-fields.json` |
| `observed_json_keys` | Keys and counts in JSON samples |
| `applicable_existing_aliases` | Sample keys already covered by global `field_aliases` |
| `proposed_field_aliases` | Script-suggested **new** aliases (source → canonical) |
| `gap_analysis` | Canonical fields still missing after mapping preview |
| `preview_events` | Up to 5 parsed preview events (not written to repo) |
| `proposed_template_hint` | Template suggestion by connector_type |
| `llm_prompt` | Structured task text for Agent |
| `implementation_checklist` | Default landing steps |
| `llm_review_required` | true when gap misses required fields |

Optional: `--preview-normalize` calls `normalizer.py` on preview for runtime preview.

### 3.3 Agent / LLM Output (output-schema.json)

**Core Skill output** — cannot skip. After review, Agent produces one JSON including at least:

- `proposed_field_aliases`
- `proposed_asset_schema` (fields, correlation_keys, time_field)
- `proposed_normalizer` (`aliases_only` | `extend_parser` | `new_parser`)
- `proposed_query_template`
- `implementation_checklist`
- `confidence` (high / medium / low)

See [output-schema.json](../src/skills/log-format-discovery/output-schema.json).
`proposed_template_hint.existing_templates_in_dataasset` is a candidate list for
review. Only one reviewed object under `proposed_query_template` crosses the
apply boundary; the candidate list is never merged into the catalog.

---

## 4. Landing Mapping

### 4.1 Change Path by Format

| detected_format | Ops config | Notes |
|---|---|---|
| `json_lines` | `text_parser: json_lines` + `field_aliases` | No code change |
| `syslog_auth` | `text_parser: syslog_auth` | Built-in |
| `nginx_combined` | `text_parser: nginx_combined` | Built-in |
| `text_unknown` | `dataasset/parsers/*.json` | Custom regex JSON |

### 4.2 field_aliases Strategy

- **Global aliases**: write to `dataasset/configure/evidence-minimum-fields.json` → shared by all assets
- **canonical naming**: match `by_asset_type.*.required` (e.g. `src_ip` not `client_ip`)
- **Runtime**: `normalizer.py` applies aliases after fetch; `evidence_id` from normalizer — may ignore in gap

### 4.3 Validation Loop

```bash
python3 src/dataasset/validate.py --sync-catalog
python3 src/dataasset/test_connector.py <asset_id> --by-asset --plan --dry-run
python3 src/dataasset/test_connector.py <asset_id> --by-asset --params '{...}'
```

---

## 5. CLI Reference

Open-source recommended entry (wraps `discover.py`, default `--pretty --preview-normalize`):

```bash
python3 src/secweaver.py asset discover-format asset-waf-api-prod \
  -i examples/log-format-discovery/waf-jsonl.sample
```

Underlying script (queue list, report export, full LLM prompt params):

```bash
python3 src/skills/log-format-discovery/scripts/discover.py --list-discovery

python3 src/skills/log-format-discovery/scripts/discover.py \
  --asset-id asset-waf-api-prod \
  [-i sample.log | --text "..." | stdin] \
  [-o report.json] [--prompt prompt.md] [--preview-normalize] [--pretty]
```

---

## 6. Security and Compliance

| Item | Requirement |
|---|---|
| Samples | Redact when possible; do not commit production IPs/accounts |
| Reports / prompts | Local use; `-o` output not in Git |
| Template drafts | No password, access_key, private keys |
| masking | Agent output should suggest truncate/redact for `payload`/`command`, etc. |

---

## 7. Non-Goals and Future Extensions

**Current non-goals**:

- Embed OpenAI/Anthropic API in `discover.py` (LLM via Cursor Agent; optional future `--llm-api`)
- Auto PR / auto repo edit (requires LLM + user confirmation)
- Production log auto-sampling (use `test_connector.py`)
- Runtime LLM per-line raw parsing at fetch (opposite of normalize architecture)

**Possible extensions** (not implemented):

- Multi-sample batch compare, key drift detection
- `validate.py` integration `--discover` subcommand
- Report diff: format change alert for same asset
- Unit tests: `tests/test_discover.py` for format detection and gap

---

## 8. Document Map

| Reader need | Read |
|---|---|
| Why, architecture, human–machine split | **This document** |
| Chat usage, step overview | [20-log-format-discovery.md](../docs_user/20-log-format-discovery.md) |
| How Agent runs, commands, checklist | [SKILL.md](../src/skills/log-format-discovery/SKILL.md) |
| File paths, alias rules | [reference.md](../src/skills/log-format-discovery/reference.md) |
| Copy-paste examples | [examples.md](../src/skills/log-format-discovery/examples.md) |
| Complete new-source onboarding lifecycle | [How to Configure Data Sources](../docs_user/03-configure-data-sources.md) |
| Field discovery and normalization procedure | [Log Format Discovery](../docs_user/20-log-format-discovery.md) |

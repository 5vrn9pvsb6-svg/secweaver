# Log Format Discovery

**Languages:** English (this page) | [简体中文](20-log-format-discovery.zh-CN.md)

> SecWeaver Skill documentation
> Purpose: Process data sources with **`status: discovery`** in dataasset, complete field mapping, then hand a draft Asset back to the onboarding acceptance flow
> Agent Skill: `src/skills/log-format-discovery/SKILL.md`  
> Script: `src/skills/log-format-discovery/scripts/discover.py`

---

## First Run: Preview Without Changing Assets

Run `make quickstart` and use the public default `dataasset` root. The repository already
contains `asset-waf-api-prod` with `status=discovery`; no new handwritten Asset is needed:

```bash
.venv/bin/python src/secweaver.py asset discover-format asset-waf-api-prod \
  -i examples/log-format-discovery/waf-jsonl.sample
```

This fixture expects `detected_format=json_lines` and `sample_count=2`.
Inspect `proposed_field_aliases`, `gap_analysis`, and `normalized_preview`, especially
different source timestamps. Format detection alone does not justify activation.
The command prints JSON, makes no live query, and does not write configuration.

In your agent, ask:

```text
Use log-format-discovery on asset-waf-api-prod with the offline sample
examples/log-format-discovery/waf-jsonl.sample. Explain mappings, timestamps,
and evidence gaps. Propose changes only; do not modify the asset.
```

For real logs, redact samples, confirm discovery status, and obtain user approval before
writing changes. Keep incomplete assets draft/discovery until sample and query acceptance;
never invent fields or production credentials. The JSON below is a field-structure excerpt,
not a complete replacement Asset; use the onboarding wizard or full Schema for new assets.

## 1. Skill Scope

This Skill **only processes** data sources in the dataasset discovery queue (`status: discovery`).  
Assets already in `draft` / `active` / `disabled` **do not** and **should not** go through format discovery.

### 1.1 Status Flow

```text
New asset (status=discovery)
        ↓
log-format-discovery (discover.py + LLM)
        ↓
Update schema / aliases / parser, status=draft
        ↓
return to onboarding: validate + live query acceptance
        ↓
status=active only after acceptance
```

### 1.2 LLM Role

| Step | Executor |
|---|---|
| Load discovery assets, sample analysis, gap | `discover.py` |
| Field mapping, parser design | **Agent (LLM)** |
| Write back to dataasset, change status | Agent + user confirmation |

---

## 2. Usage

### 2.1 Register a Discovery Asset

Create or edit an asset under `dataasset/assets/`:

```json
{
  "asset_id": "asset-waf-api-prod",
  "status": "discovery",
  "connector_id": "conn-http-waf-api",
  "asset_type": "waf_alert",
  "schema": {
    "fields": ["src_ip", "timestamp", "url"],
    "correlation_keys": [],
    "time_field": "timestamp",
    "retention_days": 30
  }
}
```

`schema.fields` may be placeholders; the LLM completes them after format discovery.

### 2.2 View the Queue

```bash
.venv/bin/python src/skills/log-format-discovery/scripts/discover.py --list-discovery
```

### 2.3 Run Format Discovery

Recommended via CLI (offline samples need no credentials):

```bash
.venv/bin/python src/secweaver.py asset discover-format asset-waf-api-prod \
  -i examples/log-format-discovery/waf-jsonl.sample
```

For `--prompt`, `-o`, and other flags, use the underlying script:

```bash
.venv/bin/python src/skills/log-format-discovery/scripts/discover.py \
  --asset-id asset-waf-api-prod \
  -i samples.jsonl \
  --pretty --prompt /tmp/prompt.md
```

### 2.4 Hand Off After Discovery

1. LLM confirms mapping and updates `dataasset/assets/{asset_id}.json`
2. Set `"status": "draft"` and run `validate.py`
3. Return to [source onboarding](03-configure-data-sources.md#6-validate-query-and-activate) for live-query acceptance
4. Set `"status": "active"` only after acceptance; then add it to a verified Bundle

---

<a id="field-discovery-and-normalization-model"></a>

## 3. Field discovery and normalization model

Field discovery answers three separate questions: what fields exist in the source,
which fields can be queried upstream, and how returned events become canonical evidence.
Do not collapse these layers into one field list.

### 3.1 Separate query fields from canonical evidence

| Layer | Used by | Field names | Configuration |
|---|---|---|---|
| Query | SLS, ES, database, or file fetch | Actual source/index column names | Query template `sls_query`, `es_query`, `sql`, or file parameters |
| Parsing | Raw text or embedded JSON extraction | Parser output keys | Asset `text_parser` and `dataasset/parsers/*.json` |
| Evidence | Completeness and investigation Skills | Canonical fields such as `src_ip`, `timestamp`, `host`, `command` | Asset `field_aliases`, with global aliases reserved for universal mappings |

```text
canonical investigation parameter: src_ip
    -> query template uses source field: client_ip:{src_ip}
    -> fetch returns client_ip
    -> parser runs when input is raw text
    -> field_aliases copies client_ip to src_ip
    -> normalized evidence enters Skills
```

Query templates must use fields that are searchable in the backend. Aliases run after
fetch and cannot make a nonexistent upstream field queryable.

### 3.2 Inspect representative samples and choose a parser

Use at least three sanitized rows when possible, including time variants and optional
fields. First inspect whether the fetch result is already structured:

| Sample shape | Configuration |
|---|---|
| SLS/ES/SDK returns business fields as top-level keys | Omit `text_parser`; configure aliases only |
| One field contains a complete JSON object as text | Use `json_lines` or `json_lines2`, then aliases |
| Linux auth.log or secure line | Use `syslog_auth` |
| Nginx combined access line | Use `nginx_combined` |
| Unrecognized text format | Add reviewed `dataasset/parsers/<id>.json` and reference that ID |
| No structure should be inferred | Use `raw_only`; the Asset remains incomplete for field-based investigations |

Whether the original producer emitted JSON is not enough to choose `text_parser`; decide
from the rows returned by the Connector. Parser selection does not disable aliases,
timestamp normalization, masking, or trace profiles.

### 3.3 Declare raw fields and reviewed aliases

`schema.fields` describes keys directly visible in the fetched row or parser output.
`field_aliases` maps those source keys to canonical evidence fields:

```json
{
  "schema": {
    "fields": ["remote_addr", "request_uri", "status", "time_iso8601"],
    "time_field": "timestamp",
    "retention_days": 30
  },
  "field_aliases": {
    "remote_addr": "src_ip",
    "request_uri": "url",
    "time_iso8601": "timestamp"
  }
}
```

Prefer per-Asset aliases because the same source name may mean different things in
different products. Add an alias to `configure/evidence-minimum-fields.json` only when
its meaning is universal and low ambiguity. Aliases copy a source value only when the
canonical target is absent; source fields remain available for diagnostics.

Common mismatch symptoms:

| Symptom | Likely layer | Fix |
|---|---|---|
| Backend reports “column not found” or returns nothing | Query template uses a canonical name that the source does not index | Change the query to the actual source field; keep parameters canonical |
| Data is returned but `src_ip` or another canonical field is empty | Alias missing or points in the wrong direction | Add source-to-canonical `field_aliases` |
| Plain lines have no usable keys | Parsing | Select a built-in parser or add a reviewed custom parser |
| Completeness reports a required field unreachable | Schema/alias chain | Declare the raw field and add the alias that derives the canonical field |
| Time is wrong or inconsistent | Time field/parser/alias | Identify the real source time, map it to `timestamp`, and verify timezone conversion |

Do not treat client IP, proxy IP, host IP, and destination IP as interchangeable merely
because their values look alike. Ambiguous mappings require domain review.

### 3.4 Preview and apply discovery output

The discovery report proposes `field_aliases`, Asset schema, parser strategy, query
template, and masking. Running the script is not completion: review the proposal and
verify it against source documentation and samples before writing.

```bash
# Preview heuristic changes without writing
.venv/bin/python src/skills/log-format-discovery/scripts/discover.py \
  --asset-id asset-my-new-log -i samples.jsonl --apply --apply-dry-run

# Preview a mapping reviewed by the agent and operator
.venv/bin/python src/skills/log-format-discovery/scripts/discover.py \
  --asset-id asset-my-new-log -i samples.jsonl \
  --apply /path/to/mapping.json --apply-dry-run

# Apply that reviewed mapping; discovery becomes draft by default
.venv/bin/python src/skills/log-format-discovery/scripts/discover.py \
  --asset-id asset-my-new-log -i samples.jsonl \
  --apply /path/to/mapping.json
```

The mapping file must contain the same `asset_id`. `--apply` may update Asset schema,
`query_template_ids`, `text_parser`, masking, and per-Asset aliases, and may merge a
proposed query template. Use `--no-promote-draft` when review is not complete. Use
`--global-aliases` only after deciding that a mapping is safe for every Asset.
Existing templates listed under `proposed_template_hint` are review candidates;
apply never treats that list as a new template. A reviewed mapping can provide one
object in `proposed_query_template` when a template must be added or updated.

Apply accepts only the same `status=discovery` Asset. It stages the Asset and
template changes, validates every available JSON Schema, and only then replaces
files under the shared DataAsset write lock. Invalid mappings, active/draft
targets, and Schema failures leave registry objects unchanged. `jsonschema` is a
required runtime dependency when the selected registry provides these schemas.
Each file uses atomic replacement; if a later replacement raises an ordinary
write error, already replaced objects are restored before the command fails.

### 3.5 Verify fields before activation

Preview normalized events, validate the registry, then query a known event:

```bash
.venv/bin/python src/skills/log-format-discovery/scripts/discover.py \
  --asset-id asset-my-new-log -i samples.jsonl --preview-normalize --pretty
.venv/bin/python src/dataasset/validate.py --sync-catalog
.venv/bin/python src/dataasset/test_connector.py asset-my-new-log --by-asset \
  --params '{"src_ip":"203.0.113.10","time_start":"2026-09-08T00:00:00Z","time_end":"2026-09-08T00:05:00Z"}'
```

Confirm raw source fields have values, normalized required fields exist, query filters use
source names, the time is correct, masking is appropriate, and cross-source keys retain
their intended meaning. Return to the [complete onboarding workflow](03-configure-data-sources.md#end-to-end-onboarding-workflow)
for activation. Use [operations troubleshooting](09-operations-troubleshooting.md) when
validation or live-query acceptance fails.

### 3.6 Runtime behavior

After configuration, runtime normalization is automatic and deterministic:

```text
registry -> query template -> credential -> fetch -> text parser
    -> time normalization -> field aliases -> masking -> evidence_id -> Skill
```

The runtime does not call an LLM for every raw event. The agent participates during the
reviewable discovery phase; downstream Skills reason over normalized evidence.

---

## 4. Relationship to dataasset

| dataasset path | How this Skill uses it |
|---|---|
| `assets/*.json` (`status=discovery`) | **Only objects processed** |
| `connectors/*.json` | Read `connector_type`; do not modify other connectors |
| `configure/evidence-minimum-fields.json` | Gap comparison, alias suggestions |
| `query-templates/templates.json` | List reusable templates |

**Does not read** draft/active/disabled assets as references.

---

## 5. Related Files

| File | Description |
|---|---|
| [03-configure-data-sources.md](03-configure-data-sources.md) | Complete source onboarding and activation workflow |
| [09-operations-troubleshooting.md](09-operations-troubleshooting.md) | Validation and live-query troubleshooting |
| [16-data-source-onboarding-faq.md](16-data-source-onboarding-faq.md) | Short answers and pointers |
| [log-format-discovery-design.md](../docs_dev/20-log-format-discovery-design.md) | Architecture and design |
| `src/skills/log-format-discovery/SKILL.md` | Agent entry point |
| `dataasset/schema/data-asset.schema.json` | `status` includes `discovery` |
| `dataasset/assets/asset-waf-api-prod.json` | Example discovery asset |

---

*Document version: v1.1 | Updated: 2026-06-21*

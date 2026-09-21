---
name: log-format-discovery
description: >-
  LLM-powered log format discovery for dataasset assets with status=discovery.
  Run discover.py with --asset-id on the discovery queue, then use Agent/LLM
  to map fields and update that asset before promoting to draft/active.
  Use for 新日志格式, 字段映射, format discovery, discovery 状态数据源,
  or when a dataasset asset is in discovery status.
---

# Log Format Discovery

**LLM-driven** onboarding workflow: processes only dataasset assets with **`status: discovery`**; `discover.py` loads asset + sample analysis, then **AI Agent (LLM)** completes field mapping, updates the asset, and promotes `discovery → draft → active`.

**Role:** Dedicated Skill for the format discovery queue. **Does not process draft / active / disabled assets.**

> Architecture and design: [docs_dev/20-log-format-discovery-design.md](../../../docs_dev/20-log-format-discovery-design.md); usage: [docs_user/20-log-format-discovery.md](../../../docs_user/20-log-format-discovery.md).

## dataasset `discovery` status (required reading)

| status | This Skill | Dialog selectable | Notes |
|---|---|---|---|
| `discovery` | **Process** | No | Format discovery queue; pending mapping |
| `draft` | Do not process | No | Mapping done; editing |
| `active` | Do not process | Yes | Published |
| `disabled` | Do not process | No | Disabled |

When onboarding new log types: **register asset in `dataasset/assets/` with `status: discovery`**, then run this Skill.

## Workflow

```text
1. Register asset + connector in dataasset, status=discovery
2. discover.py --asset-id <id> + sample → report + llm_prompt
3. [Required·LLM] Agent produces mapping JSON; update discovery asset
4. User confirms → status draft → validate → active
```

### Step 0 — View discovery queue

```bash
python3 src/skills/log-format-discovery/scripts/discover.py --list-discovery
```

### Step 1 — Preprocess discovery asset

```bash
python3 src/skills/log-format-discovery/scripts/discover.py \
  --asset-id asset-waf-api-prod \
  -i samples.jsonl \
  --pretty -o /tmp/discovery.json \
  --prompt /tmp/discovery-prompt.md \
  --preview-normalize
```

`asset_type`, `connector_type` read from dataasset automatically — **no** `--asset-type` needed.

### Step 2 — [Required·LLM] Review report

Key report fields:

| Field | Purpose |
|---|---|
| `dataasset_context.discovery_asset` | Current discovery asset registration |
| `discovery_asset_hints` | Existing fields / template_ids |
| `detected_format` / `gap_analysis` | Format and gaps |
| `llm_prompt` | LLM task description |

### Step 3 — Land changes (dataasset config only, no Python)

1. `asset.field_aliases` by default; use global aliases only for reviewed universal mappings
2. **`text_parser`** — built-in id (`syslog_auth` / `nginx_combined` / `json_lines`) or `dataasset/parsers/*.json`
3. **`dataasset/assets/{asset_id}.json`** — update schema, template_ids, masking
4. `status`: `discovery` → `draft` → `active`
5. `validate.py` + `test_connector.py`

See the [field discovery and normalization model](../../../docs_user/20-log-format-discovery.md#field-discovery-and-normalization-model).

## Not applicable

An ineligible asset (for example, an already active asset) is rejected by the CLI
with an actionable argument error and exit code 2, without a Python traceback.
This does not bypass the discovery-status gate or change the asset status.

- Assets with `status` draft / active / disabled (edit normalizer or templates directly)
- Raw samples not registered in dataasset without discovery status (create discovery asset first)
- Expecting text log onboarding via `ssh_fetch.py` changes (use `text_parser` config)

## References

- [docs_user/03-configure-data-sources.md](../../../docs_user/03-configure-data-sources.md) — complete onboarding lifecycle
- [docs_user/20-log-format-discovery.md](../../../docs_user/20-log-format-discovery.md) — field discovery and normalization
- [docs_user/16-data-source-onboarding-faq.md](../../../docs_user/16-data-source-onboarding-faq.md) — short answers
- [docs_dev/20-log-format-discovery-design.md](../../../docs_dev/20-log-format-discovery-design.md)
- [reference.md](reference.md) | [examples.md](examples.md) | Samples: [examples/log-format-discovery/](../../../examples/log-format-discovery/)
- `dataasset/README.md` — status field description

# Log Format Discovery — Reproducible Example

Run from the repository root. `asset-waf-api-prod` is a public `status=discovery` example. Preprocessing and the apply preview below neither query live data nor write configuration.

## 1. Read offline samples and generate suggestions

```bash
python3 src/skills/log-format-discovery/scripts/discover.py \
  --asset-id asset-waf-api-prod \
  -i src/skills/log-format-discovery/samples/waf-jsonl.example \
  --pretty -o /tmp/discovery-waf.json --prompt /tmp/discovery-waf-prompt.md
```

## 2. Review the mapping

`derived_correlation_keys` in preprocessing output is derived from the matrix and fields. Treat it as read-only; do not copy it into `proposed_asset_schema` or asset JSON. Maintain actual fields and mappings rather than hand-writing the legacy `correlation_keys`.

The minimal mapping below satisfies [output-schema.json](output-schema.json). Review aliases and fields against actual samples, then save it as `/tmp/discovery-waf-mapping.json`. Its `asset_id` must match the command target. Optional suggestions are omitted; this does not establish activation readiness:

```json
{
  "asset_id": "asset-waf-api-prod",
  "asset_type": "waf_alert",
  "proposed_field_aliases": {
    "rule_action": "action",
    "hostname": "host"
  },
  "proposed_asset_schema": {
    "fields": [
      "src_ip",
      "timestamp",
      "url",
      "action",
      "host",
      "payload"
    ],
    "time_field": "timestamp"
  },
  "implementation_checklist": [
    "Review aliases against actual samples",
    "Preview changes before applying",
    "Validate and test connectivity before activation"
  ],
  "confidence": "medium"
}
```

## 3. Preview, apply and promote

```bash
python3 src/skills/log-format-discovery/scripts/discover.py \
  --asset-id asset-waf-api-prod \
  -i src/skills/log-format-discovery/samples/waf-jsonl.example \
  --apply /tmp/discovery-waf-mapping.json --apply-dry-run
```

After reviewing the preview, omit `--apply-dry-run` to write to the current `DATAASSET_ROOT` (default `dataasset/`) and promote discovery to draft by default. For isolation, prepare `dataasset_my/` using the [configuration guide](../../../docs_user/03-configure-data-sources.md). Static validation must be followed by authorized source configuration and live connectivity/fetch acceptance before activation; offline samples do not prove live readiness.

```bash
python3 src/secweaver.py validate --json
python3 src/dataasset/test_connector.py asset-waf-api-prod --by-asset --dry-run \
  --params '{"src_ip":"203.0.113.10","time_start":"2026-06-21T09:00:00+08:00","time_end":"2026-06-21T10:00:00+08:00"}'
```

## 4. Updating fields for an active asset

Normally maintain asset `field_aliases`, parser JSON referenced by `text_parser`, or query templates; Python normalizer changes are unnecessary. Discovery targets discovery assets by default. Do not change live status merely to bypass that check. Review edits in an isolated catalog, run static validation and query-plan previews above, then omit connectivity testing's `--dry-run` within the authorized scope to verify live data. Use the developer extension workflow only when configuration cannot express the needed parsing capability.

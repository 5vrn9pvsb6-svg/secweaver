# Log Format Discovery — Reference

> [日志格式发现设计.md](../../../docs_dev/20-log-format-discovery-design.md) | [日志格式发现.md](../../../docs_user/20-log-format-discovery.md)

## dataasset `discovery` status

| Question | Answer |
|---|---|
| Which data sources? | **Only** `status: discovery` in `dataasset/assets/*.json` |
| Other assets? | draft/active/disabled **not processed** |
| How to enqueue? | Create or edit asset with `"status": "discovery"` |
| How to dequeue? | After mapping: `discovery` → `draft` → `active` |
| CLI | `--asset-id` (required) or `--list-discovery` |

## Spec mapping

| Spec file | How this Skill writes |
|---|---|
| `dataasset/assets/{asset_id}.json` | Update discovery asset schema, template_ids, status |
| `configure/text-log-parsers.json` | Built-in text_parser list |
| `parsers/*.json` | Custom line_regex (ops-editable) |
| `configure/evidence-minimum-fields.json` | Global `field_aliases` |
| `query-templates/templates.json` | New templates (if needed) |

## discover.py report fields

```json
{
  "asset_id": "asset-waf-api-prod",
  "dataasset_context": {
    "discovery_asset": { "status": "discovery", "fields": [] },
    "matching_templates": []
  },
  "discovery_asset_hints": {
    "current_fields": [],
    "current_template_ids": []
  }
}
```

## Validation

```bash
python3 src/dataasset/validate.py --sync-catalog
python3 src/dataasset/test_connector.py <asset_id> --by-asset --dry-run
```

discovery assets have relaxed validation (template match not mandatory); full rules apply after promoting to draft/active.

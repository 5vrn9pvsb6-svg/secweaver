# Community Guide: Add an Asset and Its Connector

**Languages:** English (this page) | [简体中文](03-community-add-asset-connector.zh-CN.md)

This guide is for contributors who want to add a new data-source example, asset template, or connector path. The default goal is: **do not change core Python code**. Start with configuration, templates, synthetic samples, and an optional external executor.

Run `make quickstart` once from the repository root before using this guide. The commands
below invoke `.venv/bin/python` directly so they use the repository's pinned environment.

## What to contribute

| File | Purpose | Recommended location |
|---|---|---|
| connector | Non-secret source connection descriptor with `credentials_ref` | `dataasset/examples/connectors/conn-<vendor>-<purpose>-example.json` |
| asset | Logical meaning, parsing, fields, and coverage | Generated from onboarding config first |
| query template | Parameterized query by investigation params | `dataasset/query-templates/templates.json` or onboarding template |
| onboarding config | Copyable config for operators | `dataasset/onboarding/examples/*.json` |
| local sample | Synthetic data for format discovery and dry-runs | `examples/` or PR notes |
| docs | Scenario, validation, and usage notes | `docs_dev/` or `docs_user/` |

By default, do not put new objects directly into the formal registry under `dataasset/assets/` or `dataasset/connectors/`. Start under `dataasset/examples/` or onboarding examples; maintainers can promote vetted examples later.

## Choose the connector path

The full built-in connector list is in the "Built-in connector list" section of [`../dataasset/onboarding/README.md`](../dataasset/onboarding/README.md). The built-in connector metadata source of truth is [`../dataasset/configure/connector-catalog.json`](../dataasset/configure/connector-catalog.json): query key, runtime, dependency strategy, template selection, and Studio profile live in the same entry. Python no longer keeps duplicate fallback constants.

| Situation | Recommended action |
|---|---|
| Existing type such as `sls`, `es`, `http_api`, `database_ro`, `aws_cloudwatch` | Write onboarding config directly |
| New type can run via local samples or an external HTTP program | Register it in `dataasset/configure/external-connectors.json` |
| New type needs local code, SDKs, or custom parsing but should stay outside core | Add a plugin under `src/dataasset/plugins/connectors/<plugin_name>/` |
| New type requires a built-in SDK integration | Open an Issue/RFC first |

Config-only connector example:

```json
{
  "connectors": {
    "vendor_logs": {
      "query_key": "vendor_query",
      "runtime": "local_or_external_executor",
      "description": "External executor example for Vendor Logs.",
      "onboarding_template": "external_generic",
      "onboarding_profile": {
        "label": "Vendor Logs",
        "fields": ["endpoint", "sample_file"],
        "required": [],
        "defaults": {"sample_file": "examples/log-format-discovery/waf-jsonl.sample"},
        "default_asset_type": "waf_alert",
        "template_params": ["src_ip", "time_start", "time_end", "limit"],
        "template_defaults": {"limit": 1000},
        "default_query": "src_ip:{src_ip} limit {limit}",
        "hint": "Use a local sample or external executor."
      }
    }
  }
}
```

## Recommended path

Copy the sample config:

```bash
cp dataasset/onboarding/examples/data-sources.sample.json /tmp/my-source.json
```

Preview generated files:

```bash
.venv/bin/python src/secweaver.py asset apply -f /tmp/my-source.json --dry-run
```

Compare what would change in the current tree:

```bash
.venv/bin/python src/secweaver.py asset diff -f /tmp/my-source.json
```

Write the connector, asset, and query template:

```bash
.venv/bin/python src/secweaver.py asset apply -f /tmp/my-source.json
```

If the generated config is wrong, use the same onboarding config for controlled rollback:

```bash
.venv/bin/python src/secweaver.py asset rollback -f /tmp/my-source.json --dry-run
.venv/bin/python src/secweaver.py asset rollback -f /tmp/my-source.json --confirm-delete
```

Minimal source shape:

```json
{
  "name": "demo-vendor-waf",
  "connector_type": "vendor_logs",
  "asset_type": "waf_alert",
  "credentials_ref": "vault://vendor/security-readonly",
  "status": "discovery",
  "endpoint": "http://127.0.0.1:8788/fetch",
  "sample_file": "examples/log-format-discovery/waf-jsonl.sample",
  "asset": {
    "text_parser": "json_lines",
    "schema": {
      "fields": ["timestamp", "src_ip", "url", "action"],
      "time_field": "timestamp"
    },
    "field_aliases": {
      "client_ip": "src_ip"
    },
    "coverage": {
      "zones": ["edge"],
      "apps": ["demo-gateway"],
      "hosts": []
    }
  },
  "template": {
    "params": ["src_ip", "time_start", "time_end", "limit"],
    "defaults": {
      "limit": 1000
    },
    "vendor_query": "source:security src_ip:{src_ip} limit {limit}"
  }
}
```

## UI path

Run the local DataAsset UI:

```bash
DATAASSET_UI_PORT=8765 .venv/bin/python dataasset-ui/server.py
```

Open:

```text
http://127.0.0.1:8765/onboarding.html
```

Choose a connector type, fill in source, parsing, coverage, and query fields, then generate config, preview the kit, and write DataAsset files.

## External executors

For SDK-heavy or vendor-specific integrations, prefer an external executor. SecWeaver POSTs `query`, `params`, and sanitized connector `config` to `connector.config.endpoint`. Return an object with an `events`, `data`, `results`, `records`, `items`, or `alerts` array.

See [External Connector Executors](05-external-connector-executors.md) for details and the AWS CloudWatch example.

## Connector plugins

For local integrations that should not run as an HTTP service, add a plugin directory:

```text
src/dataasset/plugins/connectors/vendor_logs/
  plugin.json
  fetch.py
  requirements.txt
  README.md
```

`plugin.json` registers the type:

```json
{
  "api_version": "1.0",
  "connector_type": "vendor_logs",
  "query_key": "vendor_query",
  "runtime": "plugin",
  "protocol": "stdio-json",
  "entrypoint": "fetch.py"
}
```

Then use `connector_type: "vendor_logs"` in onboarding config. See [Connector Plugins](04-connector-plugins.md) and the demo plugin under `src/dataasset/plugins/connectors/demo_plugin_logs/`.

Validate the plugin contract before submitting:

```bash
.venv/bin/python src/secweaver.py connector plugin validate src/dataasset/plugins/connectors/vendor_logs
```

## Fields and parsing rules

| Field | Purpose |
|---|---|
| `asset_type` | Logical type such as `waf_alert`, `web_access_log`, `ssh_auth`, or `db_audit` |
| `text_parser` | Text parser such as `json_lines`, `syslog_auth`, or `nginx_combined` |
| `schema.fields` | Fields the contribution promises to expose for analysis |
| `schema.time_field` | Event-time field |
| `field_aliases` | Source-to-standard mappings such as `client_ip -> src_ip` |
| `coverage` | Zones, applications, or hosts covered by this source |
| `query_template_ids` | Query templates available to the Asset |

Keep a new log format in `status: "discovery"` while deriving and reviewing its mappings:

```bash
.venv/bin/python src/skills/log-format-discovery/scripts/discover.py \
  --asset-id YOUR_ASSET_ID \
  -i examples/your-sample.jsonl \
  --apply --apply-dry-run
```

## Checks before PR

```bash
.venv/bin/python src/secweaver.py validate --json --only-active
.venv/bin/python tests/run_tests.py
.venv/bin/python src/scripts/release_scan.py
.venv/bin/python src/scripts/check_docs_links.py
```

If you changed onboarding, connector registry, or CLI:

```bash
.venv/bin/python -m unittest tests.test_secweaver_cli tests.test_dataasset_ui -v
```

## PR checklist

- [ ] No real credentials, tokens, private keys, customer logs, production hostnames, or bulk internal inventories
- [ ] Unique `connector_id` / `asset_id`, with `example` or `demo` suffix
- [ ] Credentials use `vault://...` references only
- [ ] Query templates use standard params such as `src_ip`, `time_start`, `time_end`, `limit`
- [ ] New connector type is registered in `dataasset/configure/external-connectors.json` or a plugin `plugin.json`
- [ ] Local samples are synthetic; IPs use documentation ranges
- [ ] Docs explain the scenario or Skill this asset helps
- [ ] Local checks pass and are listed in the PR description

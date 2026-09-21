# Elasticsearch WAF Asset Field Guide

**Languages:** English (this page) | [简体中文](asset-es-waf-prod-field-guide.zh-CN.md)

This guide explains the public examples [asset-es-waf-prod.json](../dataasset/assets/asset-es-waf-prod.json)
and [conn-es-waf-prod.json](../dataasset/connectors/conn-es-waf-prod.json). It covers field onboarding
for existing ES WAF logs. It does not install ES or assume the example can query production.
For your first connection, follow [data source configuration](../docs_user/03-configure-data-sources.md).

## 1. Configuration Directory and Boundaries

Edit `dataasset/` directly by default. For isolation, optionally copy it once from the repository root:

```bash
if [ ! -e dataasset_my ]; then
  cp -R dataasset dataasset_my
fi
export DATAASSET_ROOT=dataasset_my
```

Preserve an existing directory. With isolation enabled, replace `dataasset/` configuration paths below
with `dataasset_my/`, but leave the program path `src/dataasset/` unchanged. CLI, UI, and AI agent
must use the same `DATAASSET_ROOT`. Use `export DATAASSET_ROOT=dataasset` to return to the default.

Store real credentials in the selected directory's SOPS Vault; Connectors store only `credentials_ref`.
For either directory, do not commit real keys, private keys, encrypted credentials, or customer
configuration. The filename token `prod` and `environment: production` are example names and
classifications, not proof of a production connection.

## 2. Asset Fields

| Field | Example value | Meaning |
|---|---|---|
| `asset_id` | `asset-es-waf-prod` | Unique ID matching `^asset-[a-z0-9-]+$` |
| `name` | Elasticsearch WAF 安全告警 | Human-readable name |
| `asset_type` / `domain` | `waf_alert` / `D1` | WAF/gateway security alerts and their domain |
| `owner_team` | `security-ops` | Responsible team |
| `environment` | `production` | One of `production`, `staging`, `development` |
| `status` | `draft` | Onboarding; activate only after validation and real-query acceptance |
| `connector_id` | `conn-es-waf-prod` | Reference to the ES Connector |
| `coverage.hosts` | `[]` | Log-source IP array; empty means no specific host coverage is declared |
| `query_template_ids` | `waf_es_by_src_ip_time` | Template compatible with `waf_alert` and `es` |
| `sensitivity` | `internal` | Governance classification; does not automatically mask data |
| `masking` | `payload: truncate_500` | Truncates this field after normalization; does not cover every sensitive field |
| `field_aliases` | Not set in this example | Optional source-to-canonical mapping, overriding the same global alias |
| `tags` / `description` | See JSON | Classification and onboarding notes |

`coverage.hosts` accepts source IPs such as `192.0.2.10`, not `web-01`, FQDNs, or aliases.
Register hostnames and aliases in `hosts/` objects. This example has no `coverage.zones` or
`coverage.apps`; do not copy those fields from an old guide as requirements for this example.

The [DataAsset Schema](../dataasset/schema/data-asset.schema.json) defines all fields, the current
`asset_type` enum, and extensions. Multi-connector aggregation uses `connector_ids`,
`aggregate.max_events`, and `aggregate.dedupe_by`; configure these only when merging multiple
sources. See [asset design](../docs_dev/09-data-asset-design.md).

## 3. Field Contract and Normalization

| Field | Example value | Meaning |
|---|---|---|
| `schema.fields` | See asset JSON | Declared fields; verify against real samples |
| `schema.time_field` | `timestamp` | Normalized time field, distinct from ES source field `@timestamp` |
| `schema.retention_days` | `30` | Backend retention declaration; does not change ES retention policy |
| `schema.correlation_keys` | Not set | Deprecated; derived from the correlation matrix and `schema.fields`, not entered manually |

Minimum WAF fields are `src_ip`, `timestamp`, `url`, and `action`; `payload` is strongly recommended.
Common required fields also include `evidence_id`, handled by normalization. See
[evidence-minimum-fields.json](../dataasset/configure/evidence-minimum-fields.json) for the complete contract.

When source names differ, configure mappings on the current asset, for example:

```json
{
  "field_aliases": {
    "client_ip": "src_ip",
    "request_uri": "url"
  }
}
```

Mappings rename existing information; they cannot invent fields absent from source logs. Prefer
asset-level aliases. Change global `evidence-minimum-fields.json` only when a shared mapping applies
to all affected assets. ES queries use source-index fields, while evidence analysis uses normalized
fields; aliases do not automatically rewrite query templates.

## 4. Connector and Query Template

| Connector field | Example value | Requirement |
|---|---|---|
| `connector_type` | `es` | Compatible with the asset and template |
| `status` | `draft` | Managed separately from asset status |
| `credentials_ref` | `vault://es/security-readonly` | Read-only account reference in SOPS Vault |
| `config.url` | `https://es.example.com:9200` | Replace with the authorized HTTPS endpoint |
| `config.index` | `logs-waf-*` | Replace with authorized indices or pattern |
| `config.time_field` | `@timestamp` | ES source time field |
| `constraints.max_records_per_request` | `2000` | Per-request record limit |
| `constraints.request_timeout_sec` | `30` | Request timeout in seconds |

TLS verifies certificates by default. Use `config.ca_file` for a private CA; do not disable
verification to bypass certificate failures. Connector types are not a fixed enum maintained here:
see the [Connector Catalog](../dataasset/configure/connector-catalog.json) for built-ins, dependencies,
and execution modes, and the [extension guide](../docs_dev/04-connector-plugins.md) for external types.

Templates come from [templates.json](../dataasset/query-templates/templates.json). This example uses
`waf_es_by_src_ip_time` with `src_ip`, `time_start`, `time_end`, and optional `limit`. Times include
a timezone; use the IP and window from the actual authorized task. This example shows request
structure and does not supply production query parameters:

```json
{
  "asset_id": "asset-es-waf-prod",
  "template_id": "waf_es_by_src_ip_time",
  "params": {
    "src_ip": "203.0.113.10",
    "time_start": "2026-06-21T08:00:00+08:00",
    "time_end": "2026-06-21T20:00:00+08:00",
    "limit": 500
  }
}
```

## 5. Masking and Lifecycle

`masking` accepts field names or dotted paths. Rules include `redact`, `truncate_<N>`, `phone`,
`id_card`, and the object forms defined in the Schema. Missing or empty rules preserve original
values; `pii_fields` is annotation only. Inspect source fields, aliases, and nested copies;
see [real-data guidance](../docs_user/community-release-and-data-safety.md).

New formats enter discovery with `status: discovery`, then move to `draft`. This known-format example
starts as `draft`. Activate both Connector and Asset after validation, query preview, and acceptance
against a real event. Setting `active` or receiving empty results does not establish successful onboarding.

## 6. Onboarding Checklist

1. Prepare Python, SOPS/age, and the selected asset directory using the onboarding guide; the default is `dataasset/`.
2. Edit its `connectors/conn-es-waf-prod.json`: set the endpoint, index, time field, and any required CA.
3. Save `vault://es/security-readonly` in that directory's credential store; do not put passwords in JSON or prompts.
4. Check asset fields, source IPs, and asset-level aliases against real samples; inspect ES source fields in the template.
5. Run `.venv/bin/python src/secweaver.py validate` from the repository root, preserving your selected `DATAASSET_ROOT`.
6. Follow [query acceptance and activation](../docs_user/03-configure-data-sources.md#query-acceptance-and-activation): preview first, confirm a known event and its fields, then activate.

## 7. Adapting This Guide

Keep the asset purpose, configuration directory, key fields, query parameters, failure boundaries,
and acceptance steps. Link complete enums and runtime contracts to the Schema, Catalog, and query
templates instead of duplicating an exhaustive list that can become stale.

Updated: 2026-09-16. Machine-readable contracts take precedence over this guide.

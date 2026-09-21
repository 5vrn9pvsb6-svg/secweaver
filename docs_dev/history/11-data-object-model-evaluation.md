# Data Asset Object Model Design Evaluation: Assets / Connectors / Hosts / Networks

> **Status: historical assessment (as of 2026-06-30).** Design proposals describe that evaluation period; TODOs do not imply missing functionality today. See [asset design](../09-data-asset-design.md) for current fields and [cross-source correlation](../../docs_user/21-cross-source-field-correlation.md) for current correlation behavior.

**Languages:** English (this document) | [简体中文](11-data-object-model-evaluation.zh-CN.md)

Last updated: 2026-06-30

> Example data: hostnames, asset identifiers, and network groups in this document are synthetic. IP addresses use documentation ranges. Configure real values in `dataasset/` by default, or optionally copy it to `dataasset_my/` for isolation. Do not commit customer configuration to the public repository.

## 1. Latest Conclusions

The current object model continues to use a four-layer division of responsibility:

- `assets`: Describes data source semantics, fields, query templates, text parsers, and coverage sources.
- `connectors`: Describes fetch paths, connection configuration, and credential references.
- `hosts`: Describes host identity, primary address, aliases, network membership, and exposure surface.
- `networks`: Describes network segments, logical zones, network types, and trust levels.

To avoid confusion around host association semantics, `host_binding` has been temporarily removed from the asset model. Host relationships are now expressed through only two clear paths:

```text
asset.coverage.hosts: Array of log source IPs — only actual source IPs.
connector.config.host_id: Optional; used only for single-host connectors to label the physical collection target.
```

Unified definitions:

```text
host.host_ip: Primary host address; should be an IP whenever possible.
host.aliases: Host aliases, historical names, FQDNs, and host_name values that may appear in logs.
host.interfaces: Optional; fill in only for multi-NIC / multi-address scenarios.
asset.coverage.hosts: Log source IPs only — not aliases or hostnames.
host_binding: Temporarily removed to avoid confusion with coverage.hosts, aliases, and host_field.
```

Recent format and type extensions have also been consolidated:

```text
asset_type: syslog_risk_alert — for structured risk alert logs in syslog-risk-json format.
asset-secweaver-sys-risk-alert: Replaces the old asset-secweaver-sys-risk-alert naming.
text_parser: json_lines2 — for per-line JSON where field values embed JSON objects; expands to xxx.xx dot-path fields.
```

## 2. Why host_binding Was Removed First

Previously, `host_binding` served two roles at once:

- `single`: The asset is bound to a specific `host_id`.
- `aggregated`: The asset declares a row-level host field `host_field`.

This was easy to confuse with:

- `coverage.hosts`: Is this a hostname, an IP, or a coverage scope?
- `host.aliases`: Can these be used to match coverage?
- `schema.fields`: Does field presence imply the field can be used for host association?
- SLS `__source__` / `__tag__:__client_ip__`: Log source, client IP, or event host?

Removing `host_binding` for now makes the model easier to explain:

```text
Whether an asset covers a log-source host depends only on source IPs in asset.coverage.hosts.
For single-host collection targets, express them only in connector.config.host_id.
Row-level event host fields are not declared separately in the asset model; schema.fields, field_aliases, log discovery, and correlation-matrix handle them together.
```

This reduces misunderstanding of "host association" by both AI and operators.

## 3. Redefined Object Responsibilities

### 3.1 Asset

`Asset` describes data semantics and no longer declares host binding relationships directly.

Core fields retained:

- `asset_id`
- `name`
- `asset_type`
- `domain`
- `owner_team`
- `environment`
- `status`
- `connector_id` / `connector_ids`
- `coverage.hosts`
- `schema.fields`
- `schema.time_field`
- `schema.retention_days`
- `field_aliases`
- `text_parser`
- `query_template_ids`
- `sensitivity`
- `masking`
- `tags`
- `description`

Key semantics:

```text
coverage.hosts = Array of log source IPs.
```

Do not put hostnames, business names, FQDNs, or aliases in `coverage.hosts`.

`text_parser` declares row-level text/JSON parsers. Built-in parsers:

| parser | Purpose |
|---|---|
| `syslog_auth` | Linux SSH/PAM authentication logs |
| `nginx_combined` | Nginx combined access logs |
| `json_lines` | Per-line JSON object; parses top-level fields |
| `json_lines2` | Per-line JSON object; expands JSON objects inside field values as `parent.child` |
| `raw_only` | No parsing; raw line only |

`json_lines2` is AI-friendly because semi-structured fields like `fields: "{...}"` are no longer a single string — they appear in the evidence layer as searchable fields such as `fields.user`, `fields.session.tty`, etc.

### 3.2 Connector

`Connector` describes the fetch path.

Core fields retained:

- `connector_id`
- `name`
- `connector_type`
- `credentials_ref`
- `status`
- `config`
- `constraints`

For single-host connectors (e.g. SSH direct read, single-host agent, local file), you may label the physical target in `config.host_id`:

```json
"config": {
  "host_id": "host-web-01"
}
```

Aggregated SLS / platform-level connectors should not set `config.host_id`, to avoid implying a single-host data source.

### 3.3 Host

`Host` describes the host entity.

Unified definitions:

```text
host.host_ip: Primary host address; should be an IP whenever possible.
host.aliases: Host aliases, historical names, FQDNs, and host_name values that may appear in logs.
host.interfaces: Optional; fill in only for multi-NIC / multi-address scenarios.
```

Example:

```json
{
  "host_id": "host-example-web-01",
  "hostname": "example-web-01",
  "host_ip": "192.0.2.10",
  "aliases": ["web-01", "web-01.example.invalid"],
  "network_id": "net-example-web"
}
```

Here `aliases` identify hostnames in logs; they are not used for `asset.coverage.hosts`.

### 3.4 Network

`Network` continues to provide network context:

- `network_id`
- `name`
- `cidr`
- `zone`
- `network_type`
- `gateway_ip`
- `trust_level`
- `status`

Division of `zone`, `network_type`, and `trust_level`:

| Field | Definition | Primary use |
|---|---|---|
| `zone` | Logical zone / topology grouping token | UI grouping, topology display, filter by business/zone |
| `network_type` | Network purpose / form classification | Whether the segment is production, DMZ, office, management, lab, cloud VPC, or external |
| `trust_level` | Security trust level / access sensitivity | Lateral movement, impact scope, risk prioritization |

Key principles:

```text
zone ≠ network_type.
network_type ≠ trust_level.
zone answers "where to group it"; network_type answers "what it is for"; trust_level answers "how trusted/sensitive it is from a security perspective".
```

Example for a production database segment:

```json
{
  "zone": "production_network",
  "network_type": "production",
  "trust_level": "restricted"
}
```

`zone` is for logical grouping and topology display only; it no longer needs to align with host or asset coverage fields.

## 4. Latest Relationship Model

Recommended relationships:

```text
Asset.connector_id / connector_ids -> Connector.connector_id
Asset.coverage.hosts               -> Host.host_ip / Host.interfaces[].ip (log source IP match)
Connector.config.host_id           -> Host.host_id (optional; single-host connector only)
Host.network_id                    -> Network.network_id
Host.interfaces[].network_id       -> Network.network_id
```

No longer used:

```text
Asset.host_binding.host_id
Asset.host_binding.host_field
```

## 5. AI Understandability Evaluation

After removing `host_binding`, the AI explanation path is clearer:

1. Read `asset_type` to determine data type.
2. Read `schema.fields` and `field_aliases` for field capabilities.
3. Read `text_parser` to see how raw text/JSON lines become fields.
4. Read `connector_id` to find the fetch path.
5. Read `coverage.hosts` for log source IP coverage.
6. Read `hosts` / `networks` to explain which hosts and segments those source IPs belong to.
7. For single-host collection, read `connector.config.host_id` when needed.

AI should no longer infer host association from `host_binding.host_field`.

## 6. Field Optimization Recommendations

### 6.1 Asset

Continue to strengthen:

- Schema-constrain `coverage.hosts` to IP strings.
- Have `validate.py` warn on non-IP coverage values.
- In the new-asset UI, clearly state: coverage is log source IPs only.
- Built-in `text_parser` IDs must stay in sync with `text-log-parsers.json`, `data-asset.schema.json`, parser implementation, and unit tests.
- Distinguish `syslog_risk_alert` from `linux_syslog`: the former is structured risk alerts; the latter is ordinary system logs.

Optional new field:

```json
"source_field_hint": "__source__"
```

Explains which field `coverage.hosts` comes from. This is a hint only, not a host association model.

### 6.2 Connector

Consider adding query capability description:

```json
"constraints": {
  "search_mode": "full_text",
  "indexed_fields": [],
  "source_field_candidates": ["__source__", "__tag__:__client_ip__"]
}
```

When SLS fields are not indexed, AI can more accurately suggest indexing the actual source field.

### 6.3 Host

Recommendations:

- Omit empty `aliases: []`.
- Omit empty `interfaces: []`.
- Fill `interfaces` only for multi-NIC, multi-address, or cross-segment cases.
- Do not put IPs in `aliases` unless that IP actually appears as a hostname string in logs.

### 6.4 Network

Recommendations:

- Keep `trust_level` for security risk judgment and impact ordering.
- Clarify that `zone` is logical grouping and topology only — not security level.
- Clarify that `network_type` describes network purpose/form only — not trustworthiness.
- Do not restore network-level `internet_exposed`.
- Keep `internet_exposed` on `host.exposure`.

Reference values:

| Scenario | `zone` example | `network_type` | `trust_level` |
|---|---|---|---|
| Internet or external address range | `internet` / `external_edge` | `external` | `external` |
| DMZ / edge | `dmz_edge` | `dmz` | `dmz` |
| Production WEB | `production_network` | `production` | `internal` |
| Production database | `production_network` | `production` | `restricted` |
| Management / bastion | `management_network` | `management` | `management` |
| Office | `office_network` | `office` | `internal` |
| Lab/test | `lab_network` | `lab` | `internal` |
| Cloud VPC block | `example_vpc` | `cloud_vpc` | `internal` / `restricted` / `management` per workload |

### 6.5 Text Parser

Treat parsers as declarations from "raw log → fields", not as host association fields:

- `json_lines`: Top-level JSON object only.
- `json_lines2`: Top-level JSON object; expands nested JSON in field values to dot paths.
- `raw_only`: Suitable when format discovery is incomplete or SLS/ES already returns structured data.

`json_lines2` does not replace `schema.fields` and `field_aliases`: it flattens nested content into candidate source fields; whether fields enter asset capability is still filled by the log discovery Skill into `schema.fields`, then aligned to canonical fields via `field_aliases`.

## 7. Implementation Priority

### P0

- Remove `host_binding` from all asset JSON files.
- Remove `host_binding` from `data-asset.schema.json`.
- `validate.py` no longer requires `host_binding` on active host-related assets.
- UI no longer shows or writes `host_binding`.

### P1

- Document `coverage.hosts` as IP-only everywhere.
- Topology uses `coverage.hosts` to match host IPs.
- Single-host connector physical targets only via `connector.config.host_id`.

### P2

- Add `source_field_hint` or connector constraints to explain log source fields.
- If host association needs arise later, design new explicit fields rather than restoring old `host_binding`.

## 8. Final Assessment

After removing `host_binding` and adding `syslog_risk_alert` / `json_lines2`, the current model is simpler and better fits the current operations stage:

```text
Asset = data semantics + field capability + parser + coverage source IPs
Connector = fetch path + optional single-host target
Host = host entity
Network = network context
```

This is easier for both AI and humans than having `coverage.hosts + host_binding + aliases + host_field` coexist.

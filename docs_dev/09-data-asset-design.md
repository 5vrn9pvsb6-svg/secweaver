**Languages:** English (this page) | [简体中文](09-data-asset-design.zh-CN.md)

# Data Asset Design

Last updated: 2026-09-16

> Example data: hostnames, asset identifiers, and network groups in this document are synthetic. IP addresses use documentation ranges. Configure real values in `dataasset/` by default, or optionally copy it to `dataasset_my/` for isolation. Do not commit customer configuration to the public repository.

## 1. Current Core Model

The SecWeaver data asset model consists of four object types:

```text
Asset ──connector_id / connector_ids──→ Connector ──credentials_ref──→ Credentials
  │
  ├── coverage.hosts(log source IPs) ──→ Host ──network_id / interfaces[].network_id──→ Network
  │
  ├── query_template_ids ──→ Query Template
  │
  └── asset_type ──→ Evidence Spec / Scenario / Correlation Matrix
```

To avoid host-association semantic confusion, assets no longer use host-binding fields. The unified model is:

```text
host.host_ip: primary host address; should be an IP whenever possible.
host.aliases: host aliases, historical names, FQDNs, host_name values that may appear in logs.
host.interfaces: optional; fill only for multi-NIC / multi-address scenarios.
asset.coverage.hosts: log source IPs only; do not put aliases/hostname here.
```

## 2. Object Responsibilities

### 2.1 Asset

An Asset describes data semantics and availability.

Core fields:

| Field | Description |
|---|---|
| `asset_id` | Globally unique ID, e.g. `asset-xxx` |
| `name` | Display name |
| `asset_type` | Data type, e.g. `waf_alert`, `host_exec`, `syslog_risk_alert` |
| `domain` | D1–D7 data domain |
| `owner_team` | Owning team |
| `environment` | `production` / `staging` / `development` |
| `status` | `discovery` / `draft` / `active` / `disabled` |
| `connector_id` | Primary connector |
| `connector_ids` | Multi-connector aggregation, optional |
| `coverage.hosts` | Log source IP array; IPs only |
| `schema.fields` | Log field list, maintained by format discovery or manual confirmation |
| `schema.time_field` | Time field |
| `schema.retention_days` | Backend log retention in days |
| `field_aliases` | Source field to canonical field mapping |
| `query_template_ids` | Available query templates |
| `text_parser` | Text or JSON parser |
| `sensitivity` / `masking` | Data governance and masking |
| `tags` | Tags |

Example:

```json
{
  "asset_id": "asset-secweaver-sys-risk-alert",
  "name": "Example syslog-risk-json alert log",
  "asset_type": "syslog_risk_alert",
  "domain": "D2",
  "owner_team": "security-ops",
  "environment": "production",
  "status": "active",
  "connector_id": "conn-sls-secweaver-sys-risk-alert",
  "text_parser": "raw_only",
  "coverage": {
    "hosts": ["192.0.2.10", "192.0.2.20"]
  },
  "schema": {
    "fields": ["timestamp", "host_name", "event_type", "risk_level", "src_ip"],
    "time_field": "timestamp",
    "retention_days": 30
  },
  "query_template_ids": ["syslog_risk_by_time"],
  "tags": ["example", "syslog-risk-json", "alert"]
}
```

<a id="asset-retention"></a>

#### Log retention: `schema.retention_days`

Declare the backend's actual log retention in days so completeness checks can assess potential investigation-window coverage. This is governance metadata; it does not change ES/SLS retention policies. Verify that the required logs actually exist by querying them.

<a id="asset-time-correction"></a>

#### Time correction: `schema.time_correction`

During fetch normalization, `normalizer` can correct evidence `timestamp` values using asset settings. `assume_timezone` interprets timestamps without a timezone (for example `Asia/Shanghai` or `+08:00`); `offset_minutes` adds or subtracts minutes, positive for a slow source clock and negative for a fast one. Record the verified reason in `reason` and avoid correcting already accurate timestamps twice. Correction changes neither source logs nor the correlation matrix's Join window.

<a id="asset-correlation-keys"></a>

#### Correlation keys: `schema.correlation_keys`

This field is deprecated and should not be maintained manually. Runtime derives available keys from the correlation matrix, `schema.fields`, and `field_aliases`; maintain source fields and aliases instead. Legacy hand-written values may produce validation warnings and cannot replace actual fields or guarantee a successful join. See the [Asset Schema](../dataasset/schema/data-asset.schema.json) for constraints.

### 2.2 Connector

A Connector describes how to fetch data.

Core fields:

| Field | Description |
|---|---|
| `connector_id` | Globally unique ID, e.g. `conn-xxx` |
| `name` | Display name |
| `connector_type` | `sls` / `ssh_file` / `database_ro` / `http_api` / `es`, etc. |
| `credentials_ref` | `vault://...` credential reference |
| `status` | `draft` / `active` / `disabled` |
| `config` | Connection target configuration |
| `constraints` | Query limits, capability description |

Single-host connectors may use `config.host_id` to mark the actual collection target:

```json
{
  "connector_id": "conn-ssh-web-01-auth",
  "connector_type": "ssh_file",
  "credentials_ref": "vault://ssh/web-01-readonly",
  "status": "active",
  "config": {
    "host": "192.0.2.30",
    "host_id": "host-web-01",
    "log_paths": {
      "auth": "/var/log/auth.log"
    }
  }
}
```

Aggregated SLS / platform-level connectors should not set `config.host_id`.

### 2.3 Host

A Host describes a host entity.

Core fields:

| Field | Description |
|---|---|
| `host_id` | Globally unique ID, e.g. `host-xxx` |
| `name` | Display name |
| `hostname` | Short hostname; used for display and matching log `host` / `host_name` fields |
| `host_type` | `server` / `network_device` / `endpoint` / `gateway` |
| `host_os` | `linux` / `windows` / `macos` / `network_os` / `other` |
| `host_ip` | Primary host address; should be an IP whenever possible |
| `network_id` | Network segment of the primary address |
| `aliases` | Host aliases, historical names, FQDNs, host_name values that may appear in logs |
| `interfaces` | Optional; fill only for multi-NIC / multi-address scenarios |
| `nat` | Optional; NAT/EIP mapping |
| `exposure` | Optional; host-level internet exposure |
| `roles` | Business or security roles |
| `status` | `draft` / `active` / `retired` |

Example:

```json
{
  "host_id": "host-example-web-01",
  "name": "Example Web host",
  "hostname": "example-web-01",
  "host_type": "server",
  "host_os": "linux",
  "host_ip": "192.0.2.10",
  "network_id": "net-example-web",
  "aliases": ["web-01", "web-01.example.invalid"],
  "roles": ["syslog-source"],
  "environment": "production",
  "status": "active"
}
```

### 2.4 Network

A Network describes network context, answering: which segment does this IP belong to, what is the segment used for, and how should it be viewed from a security perspective.

Core fields:

| Field | Description |
|---|---|
| `network_id` | Globally unique ID, e.g. `net-xxx` |
| `name` | Display name |
| `cidr` | IPv4/IPv6 CIDR |
| `zone` | Logical zone / topology grouping token for display, grouping, and operational filtering |
| `network_type` | Network purpose/form classification: `dmz` / `production` / `office` / `management` / `lab` / `cloud_vpc` / `external` / `other` |
| `gateway_ip` | Gateway IP |
| `trust_level` | Security trust level: `external` / `dmz` / `internal` / `restricted` / `management` |
| `status` | `draft` / `active` / `retired` |

The three fields must have clear division of labor:

| Field | Question answered | Usage | Do not use to express |
|---|---|---|---|
| `zone` | "Which topology/operations group?" | UI grouping, topology display, business/region filtering, e.g. `production_network`, `example_vpc`, `example_site` | Purpose type or security level |
| `network_type` | "What is this segment's purpose/form?" | Describe network purpose, e.g. production, office, management, lab, DMZ, cloud VPC | Trustworthiness or sensitivity |
| `trust_level` | "How trustworthy/sensitive from a security view?" | Risk judgment, lateral movement paths, impact scope priority | Topology grouping or business purpose |

Recommended example:

```json
{
  "network_id": "net-prod-db",
  "name": "生产数据库网段",
  "cidr": "198.51.100.0/24",
  "zone": "production_network",
  "network_type": "production",
  "trust_level": "restricted",
  "status": "active"
}
```

Common value recommendations:

| Scenario | `zone` example | `network_type` | `trust_level` |
|---|---|---|---|
| Internet or external address range | `internet` / `external_edge` | `external` | `external` |
| DMZ / perimeter zone | `dmz_edge` | `dmz` | `dmz` |
| Production WEB network | `production_network` | `production` | `internal` |
| Production database network | `production_network` | `production` | `restricted` |
| Management / bastion network | `management_network` | `management` | `management` |
| Office network | `office_network` | `office` | `internal` |
| Lab/test network | `lab_network` | `lab` | `internal` |
| Cloud VPC large block | `example_vpc` | `cloud_vpc` | Set `internal` / `restricted` / `management` based on workload |

`internet_exposed` is no longer maintained at the network level; internet exposure belongs on `host.exposure`.

## 3. Relationships

| From | To | Mechanism | Description |
|---|---|---|---|
| Asset | Connector | `connector_id` / `connector_ids` | One asset can bind one or more connectors |
| Connector | Credentials | `credentials_ref` | Connector stores credential reference only, not plaintext |
| Asset | Host | `coverage.hosts` | Log source IPs match `host.host_ip` / `interfaces[].ip` |
| Connector | Host | `config.host_id` | Optional; single-host connectors only |
| Host | Network | `network_id` / `interfaces[].network_id` | Host addresses belong to networks |
| Asset | Query Template | `query_template_ids` | Controls query entry points available to AI / Skills |

## 4. coverage.hosts Rules

`coverage.hosts` is a log source IP array; only actual source IPs.

Correct:

```json
"coverage": {
  "hosts": ["192.0.2.10", "192.0.2.80"]
}
```

Incorrect:

```json
"coverage": {
  "hosts": ["web-01", "web-02", "gateway-example"]
}
```

If logs contain `host_name=web-01`, write it to the corresponding host's `aliases`, not to asset coverage.

## 5. Field Discovery and Field Aliases

`schema.fields` lists fields already discovered or confirmed in logs. The field discovery Skill can augment it.

`field_aliases` maps source fields to canonical fields, for example:

```json
"field_aliases": {
  "host_name": "host",
  "time": "timestamp"
}
```

Note: a field being present does not mean SLS has a key-value index. If you see:

```text
key (...) is not config as key value config
```

Prompt the user to verify the actual source field and add that field index in the corresponding SLS logstore index configuration. The field may not be `src_ip`; use the real log field.

## 6. Text Parser text_parser

`text_parser` is only for **raw text or JSON strings** returned by a connector. It mainly serves `ssh_file` / `local_file`, plus SLS sources that return only raw payload fields such as `__line__` or `content`. When SLS, ES, or a cloud SDK already returns structured fields, omit `text_parser` and use only `schema.fields` plus `field_aliases`; do not retain a parser as descriptive metadata.

| Actual SDK result shape | `text_parser` | Configuration |
|---|---|---|
| Top-level business fields such as `event_type`, `src_ip`, or `request_uri` | **Omit** | `schema.fields` + `field_aliases` |
| Only SLS metadata and one raw JSON string field | **Required** | `json_lines` / `json_lines2` |
| Only raw syslog/nginx text in `__line__`, `content`, etc. | **Required** | `syslog_auth`, `nginx_combined`, or a custom parser |
| Parsing is not ready but raw evidence must be retained | **Required** | `raw_only` |

Current built-in parsers:

| parser | Applicable scenario | Behavior |
|---|---|---|
| `syslog_auth` | Linux `auth.log` / `secure` | Parse sshd login, failed login, and other auth logs |
| `nginx_combined` | Nginx combined access log | Parse common access log fields |
| `json_lines` | One JSON object per line | Parse top-level JSON fields; field mapping via `field_aliases` |
| `json_lines2` | One JSON object per line with nested JSON objects in field values | Extends `json_lines`; expands JSON object strings/objects into dot-notation fields |
| `raw_only` | No parsing yet or raw text only | Output `raw_line` + `host`; suitable for logs pending format discovery |

`json_lines2` example:

```json
{
  "event_type": "ssh_login",
  "fields": "{\"user\":\"root(uid=0\",\"session\":{\"tty\":\"pts/0\"}}"
}
```

After parsing, original fields are retained and supplemented with:

```json
{
  "fields.user": "root(uid=0",
  "fields.session.tty": "pts/0"
}
```

When adding a built-in parser, sync:

1. `dataasset/configure/text-log-parsers.json`
2. `dataasset/schema/data-asset.schema.json` `text_parser` enum / `not enum`
3. `src/skills/_shared/data-access/text_log_parser.py`
4. Corresponding unit tests

## 7. New asset_type Onboarding Flow

When adding a new `asset_type`, update:

1. `dataasset/schema/data-asset.schema.json`
2. `dataasset/configure/evidence-minimum-fields.json`
3. `dataasset/query-templates/templates.json`
4. `dataasset-ui/module-page.js`
5. Type-specific logic in `src/dataasset/validate.py`; reusable diagnostics and report helpers in `src/dataasset/validate_lib/`
6. Related Skill documentation or rules

`syslog_risk_alert` is a current new type for `syslog-risk-json` structured alert logs, distinct from ordinary `linux_syslog`.

## 8. Validation Focus

`validate.py` remains the CLI-compatible validation entry. Shared validation support lives in `src/dataasset/validate_lib/`; `diagnostics.py` owns report formatting, `connector_contracts.py` owns cross-file onboarding invariants, `inventory_contracts.py` owns Host/Network semantic checks, and `runtime_readiness.py` derives static Bundle execution readiness.

`validate.py` currently checks:

- JSON schema compliance;
- ID matches filename;
- connector exists;
- query template exists and matches connector / asset_type;
- active assets have owner, description, retention, required evidence fields;
- `coverage.hosts` are IPs;
- `connector.config.host_id` references an existing host;
- host `network_id` / `interfaces[].network_id` exist;
- host IPs fall within the corresponding CIDR;
- bundles do not reference missing or non-active assets.

Asset, Bundle, Host, and Network schemas close their top-level object. Host
`interfaces`, `nat`, `exposure`, and object-form `exposed_ports` also reject
unknown fields. Existing
metadata such as `quality`, `tenant_scope`, Bundle `notes`, and Host
`source_host_description` is modeled explicitly. Vendor or deployment metadata
must use `extensions`; a field needed across environments belongs in the
canonical schema. This catches misspellings without forcing private metadata
into an unstructured top level.

### Runtime lifecycle gate

Validation and execution have separate responsibilities. Production Skill
`fetch()` requires both Asset and Connector to be `active`. Onboarding tools use
the explicit `onboarding_test` execution mode to test `draft/discovery` before
promotion. `disabled` is always rejected, including connectivity tests. This
check runs before template rendering and credential resolution.

`validate --runtime-ready` adds a static deployment gate over Bundle -> Asset ->
Connector -> credential ciphertext, including `agent_stream` sink traversal,
placeholder detection, and bounded cycle detection. It folds base validation
errors from dependency objects into the corresponding Bundle blockers and does
not decrypt secrets or call a backend. In JSON, `registry_valid` describes the
whole registry, Bundle `status` describes the local graph, and
`ready_for_execution` is true only when both pass. Live reachability
and data presence remain the responsibility of `dataasset-connectivity-check`.

### Catalog and multi-root contracts

`connector-catalog.json` and `external-connectors.json` declare
`format_version: "2.0"`; `version` remains their content release version. Runtime
fails closed on an unsupported format. Migrate old catalogs with
`secweaver dataasset migrate --root <root>` for preview and add `--write` after
review. The migration retains the legacy profile file for rollback.

Connector Schema is the single validation contract for built-in Connector
structure, required fields, and conditional combinations; the catalog owns
runtime, dependency, and onboarding UI metadata. It rejects unknown top-level
fields and unknown `config` fields for built-in types. Config-only external connectors and plugins keep open config
objects for vendor extensions. When a repository contains local overlays, run
`make validate-all-roots`. The canonical
`dataasset/configure/shared-contracts.json` assigns every governed JSON file to
exactly one class: `shared` files are byte-identical, `override` files may differ
for a recorded reason, and `root_owned` inventory belongs to its environment.
CI rejects unclassified files, overlapping classes, stale shared patterns, and
shared content drift without opening credential files.

Shared-contract repair is preview-first: `sync_shared_contracts.py --check`
reports differences, and `--write` copies only `shared` files from the public
root after review. It never copies credentials or changes `root_owned` inventory.
The shared `credential-status.schema.json` accepts only `active` and `disabled`;
validation, Studio, and runtime fail closed on unknown states. ES Connectors must
verify certificates and use `ca_file` for private CAs; `tls_verify: false` is rejected.

## 9. AI Usage Recommendations

When using assets, AI should follow:

```text
First check asset_type to determine data type.
Then check schema.fields / field_aliases for field capabilities.
Then check text_parser for how raw text/JSON lines are parsed.
Then check connector_id / query_template_ids to choose fetch path.
Then check coverage.hosts for log source IP coverage.
For single-host collection targets, also check connector.config.host_id.
```

Do not rely on asset-side host-binding fields to infer host associations.

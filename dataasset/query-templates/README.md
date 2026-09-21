# Query Templates

**Languages:** English (this page) | [简体中文](README.zh-CN.md)

AI / Claw **must not** construct SLS SQL or SSH commands manually. Use `template_id` + `params` instead.

Template definitions: [templates.json](templates.json); structural contract:
[`../schema/query-templates.schema.json`](../schema/query-templates.schema.json).
The platform selects render fields by `connector_type`: `sls_query` / `ssh_command` / `local_file_command` / `sql` / `http` / **`es_query`**.

## How templates are selected

Single-connector asset: `template_select` walks `asset.query_template_ids` in order and picks the first template that matches `params` and `connector_type`.

**Multi-connector aggregation** (asset has `connector_ids`): each connector selects a template **independently**, forming a fetch plan:

```text
asset-ssh-internal
  ├── conn-sls-ssh-auth-web-01 (sls)     → ssh_auth_by_src_ip_time
  ├── conn-ssh-web-01-auth (ssh_file)    → ssh_file_grep_auth
  └── conn-sls-ssh-auth-internal (sls)    → ssh_auth_by_src_ip_time
         ↓ merge + dedupe_by
  evidence_bundles.ssh_auth[]
```

Rules:

1. Iterate `connector_ids` (including `connector_id`); when `params.host` is present, filter by `config.hostname`
2. For each connector, find the **first** entry in `query_template_ids` where `connector_types` matches and required `params` are present
3. If none match, fall back to the default template for that `asset_type` (must still be compatible with the connector type)
4. After merge, deduplicate using `asset.aggregate.dedupe_by`

Inspect the plan:

```bash
python3 src/dataasset/test_connector.py asset-ssh-internal --by-asset --plan \
  --params '{"attacker_ip":"203.0.113.10","host":"web-01","time_start":"2026-06-21T08:00:00+08:00","time_end":"2026-06-21T20:00:00+08:00"}'
```

### Writing `query_template_ids` for aggregated assets

| connector_type | Example template | Typical params |
|---|---|---|
| `sls` | `ssh_auth_by_src_ip_time` | `src_ip`, `time_start`, `time_end` |
| `ssh_file` | `ssh_file_grep_auth` | `grep_pattern` (can be mapped from `attacker_ip`) |
| `local_file` | `local_file_grep_auth` | Same as `ssh_file` (local grep/tail, no SSH) |
| `database_ro` | `cmdb_all_hosts` | `limit` |
| `http_api` | `waf_api_search` | `src_ip`, `time_start`, `time_end` |
| `es` | `waf_es_by_src_ip_time` | `src_ip`, `time_start`, `time_end`, `limit` |

**The list for one asset should include at least one template per connector type in the aggregation.** Not every template needs to work with every connector. `validate.py` checks that each connector has at least one usable template.
When adding a field or query payload type, update the Schema and run `.venv/bin/python src/secweaver.py validate --strict`.

## DataRequest example (SLS)

```json
{
  "asset_id": "asset-waf-prod-01",
  "template_id": "waf_by_src_ip_time",
  "params": {
    "src_ip": "203.0.113.10",
    "time_start": "2026-06-21T08:00:00+08:00",
    "time_end": "2026-06-21T20:00:00+08:00",
    "limit": 2000
  }
}
```

## DataRequest example (SSH log read)

For `connector_type: ssh_file`, template `ssh_file_grep_auth`:

```json
{
  "asset_id": "asset-ssh-web-01-file",
  "template_id": "ssh_file_grep_auth",
  "params": {
    "attacker_ip": "203.0.113.10",
    "grep_pattern": "203.0.113.10",
    "log_path": "/var/log/auth.log",
    "max_lines": 5000
  }
}
```

The platform renders a remote read-only command (**the AI does not construct it**):

```text
grep -E '203.0.113.10' /var/log/auth.log | tail -n 5000
```

| Param | Description |
|---|---|
| `grep_pattern` | Optional; `attacker_ip` / `src_ip` are mapped automatically |
| `log_path` | Optional; filled from connector `log_paths[asset_type]` |
| `max_lines` | Default 5000; capped by connector `max_lines_per_query` |

Test:

```bash
python3 src/dataasset/test_connector.py asset-ssh-web-01-file --by-asset \
  --params '{"attacker_ip":"203.0.113.10"}' --dry-run
```

## DataRequest example (local file)

For `connector_type: local_file`, template `local_file_grep_auth` (same params as SSH log read):

```json
{
  "asset_id": "asset-local-lab-auth",
  "template_id": "local_file_grep_auth",
  "params": {
    "attacker_ip": "203.0.113.10",
    "grep_pattern": "203.0.113.10",
    "log_path": "auth.log",
    "max_lines": 5000
  }
}
```

The platform runs the equivalent `grep -E | tail` locally on the Claw host (**no shell invocation**). Relative paths under `base_path` are resolved by the connector. Sample logs: `dataasset/samples/local-logs/`.

Test:

```bash
python3 src/dataasset/test_connector.py asset-local-lab-auth --by-asset \
  --params '{"attacker_ip":"203.0.113.10","host":"web-01"}' --fetch
```

## DataRequest examples (DB / HTTP / ES)

| connector_type | Template | Render field |
|---|---|---|
| `database_ro` | `cmdb_all_hosts` | `sql` (`:param` binding) |
| `http_api` | `waf_api_search` | `http.method/path/body` |
| `es` | `waf_es_by_src_ip_time` | `es_query` (Query DSL JSON; supports `{src_ip}` placeholders) |

### ES template example

```json
"es_query": {
  "query": {
    "bool": {
      "must": [
        { "term": { "src_ip": "{src_ip}" } },
        { "range": { "@timestamp": { "gte": "{time_start}", "lte": "{time_end}" } } }
      ]
    }
  },
  "size": "{limit}"
}
```

Connector `config` needs `url` + `index`; credentials `vault://es/security-readonly` (`type: es`).

## Credential rules

`credentials_ref` is injected automatically by the platform **per connector**. LLMs pass **only the ref or omit it** (plaintext secrets are forbidden). During aggregated fetch, each connector is decrypted independently; Skills see only merged evidence.

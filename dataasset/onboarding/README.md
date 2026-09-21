# New Data Source Onboarding — Ops Config First

**Languages:** English (this page) | [简体中文](README.zh-CN.md)

Recommended path: edit one JSON config file, review generated files with `--dry-run`, then let the CLI write the connector, asset, and query template files.

```bash
python3 src/secweaver.py asset apply \
  -f dataasset/onboarding/examples/data-sources.sample.json \
  --dry-run

python3 src/secweaver.py asset apply \
  -f dataasset/onboarding/examples/data-sources.sample.json
```

Suggested ops lifecycle:

```bash
# Compare what the config would create or replace.
python3 src/secweaver.py asset diff \
  -f dataasset/onboarding/examples/data-sources.sample.json

# After writing, run connectivity and promote draft -> active on success.
python3 src/secweaver.py asset promote \
  --asset asset-demo-waf-sls \
  --params '{"src_ip":"203.0.113.10"}' \
  --dry-run

# Roll back generated files from the same config. Preview first, then confirm.
python3 src/secweaver.py asset rollback \
  -f dataasset/onboarding/examples/data-sources.sample.json \
  --dry-run
python3 src/secweaver.py asset rollback \
  -f dataasset/onboarding/examples/data-sources.sample.json \
  --confirm-delete
```

Config schema: [`data-sources.schema.json`](data-sources.schema.json). Example config: [`examples/data-sources.sample.json`](examples/data-sources.sample.json).

## Vendor quickstarts

| Example | Scenario | Runtime |
|---|---|---|
| [`examples/data-sources.sample.json`](examples/data-sources.sample.json) | SLS, ES, and SSH file basics | built-in fetch / file read |
| [`examples/secweaver-saas-sls-proxy-assets.json`](examples/secweaver-saas-sls-proxy-assets.json) | SecWeaver SaaS SLS Proxy: 8 public Logstores and 13 host/DNS/WEB/WAF logical assets | built-in SLS Proxy fetch |
| [`examples/vendor-quickstart-cloudwatch.json`](examples/vendor-quickstart-cloudwatch.json) | AWS CloudWatch Logs / CloudTrail | optional external executor |
| [`examples/vendor-quickstart-cloud-vendors.json`](examples/vendor-quickstart-cloud-vendors.json) | Azure Monitor, GCP Logging, Tencent CLS, Huawei LTS | local sample / REST / external executor |
| [`examples/vendor-quickstart-cloud-audit-siem.json`](examples/vendor-quickstart-cloud-audit-siem.json) | AWS CloudTrail, Azure Activity / Entra, GCP Audit, Splunk ES notable events | local sample / REST / external executor |
| [`examples/vendor-quickstart-siem-warehouse.json`](examples/vendor-quickstart-siem-warehouse.json) | Splunk + ClickHouse | live fetch |
| [`examples/vendor-quickstart-external-connector.json`](examples/vendor-quickstart-external-connector.json) | config-only connector type, such as Datadog | local sample / external executor |
| [`examples/vendor-quickstart-databases.json`](examples/vendor-quickstart-databases.json) | MySQL, SQL Server, and SQLite read-only audit | live fetch / local SQLite |
| [`examples/vendor-quickstart-document-cache.json`](examples/vendor-quickstart-document-cache.json) | MongoDB document logs + Redis asset cache | live fetch |
| [`examples/vendor-quickstart-identity-edge-edr.json`](examples/vendor-quickstart-identity-edge-edr.json) | Okta, Cloudflare, and CrowdStrike external connectors | local sample / external executor |
| [`examples/vendor-quickstart-edr-identity-vendors.json`](examples/vendor-quickstart-edr-identity-vendors.json) | Microsoft Defender XDR, SentinelOne, CrowdStrike, Okta, Google Workspace, Entra ID | local sample / external executor |
| [`examples/vendor-quickstart-plugin-connector.json`](examples/vendor-quickstart-plugin-connector.json) | Local connector plugin example | plugin subprocess |

These files are also available from the DataAsset UI Quickstart dropdown. Preview any quickstart with:

```bash
python3 src/secweaver.py asset apply \
  -f dataasset/onboarding/examples/vendor-quickstart-cloudwatch.json \
  --dry-run
```

For the hosted SLS Proxy, preview the complete asset template first:

```bash
python3 src/secweaver.py asset apply \
  -f dataasset/onboarding/examples/secweaver-saas-sls-proxy-assets.json \
  --dry-run
```

The template contains no credentials, and generated Connectors/Assets remain `draft/discovery`. Remove unneeded or unauthorized sources before writing. DNS, TS access, and WAF routes also require server-side `enterprise_id` integration and field indexes, followed by a successful live query.

List the full capability catalog, including source, runtime, query key, and dependency hints:

```bash
python3 src/secweaver.py connector catalog
python3 src/secweaver.py connector catalog --json
```

## Built-in connector list

Operators can use this page as the user-facing built-in connector list. The DataAsset UI `Connector Type` dropdown reads the same registry.

| connector_type | Runtime | Query key |
|---|---|---|
| `sls` | built-in fetch | `sls_query` |
| `sls_proxy` | built-in fetch | `sls_query` |
| `ssh_file` | built-in fetch | `ssh_command` |
| `ssh_command` | built-in fetch | `ssh_command` |
| `database_ro` | built-in fetch | `sql` |
| `http_api` | built-in fetch | `http` |
| `es` | built-in fetch | `es_query` |
| `local_file` | built-in fetch | `local_file_command` |
| `splunk` | built-in fetch | `splunk_search` |
| `clickhouse` | built-in fetch | `sql` |
| `hive` | built-in fetch | `sql` |
| `mongodb` | built-in fetch | `mongo_query` |
| `redis` | built-in fetch | `redis_query` |
| `agent_stream` | local sample / external executor | `stream_query` |
| `syslog_ingest` | local sample / external executor | `syslog_query` |
| `object_storage` | local sample / external executor | `object_query` |
| `aws_cloudwatch` | built-in fetch / external executor | `cloudwatch_query` |
| `aws_s3_logs` | built-in fetch / external executor | `object_query` |
| `azure_monitor` | built-in fetch / external executor | `kql` |
| `gcp_logging` | built-in fetch / external executor | `gcp_logging_filter` |
| `tencent_cls` | built-in fetch / external executor | `cls_query` |
| `huawei_lts` | built-in fetch / external executor | `lts_query` |

The authoritative built-in connector metadata lives in [`../configure/connector-catalog.json`](../configure/connector-catalog.json), including query key, runtime, dependency strategy, `onboarding_template`, and `onboarding_profile`. The Python registry [`../../src/skills/_shared/data-access/connector_registry.py`](../../src/skills/_shared/data-access/connector_registry.py) loads that contract directly. A private asset root that omits it uses the packaged public catalog; no parallel Python fallback constants are maintained. Fetch dispatch lives in [`../../src/skills/_shared/data-access/extended_fetch.py`](../../src/skills/_shared/data-access/extended_fetch.py).

## Connector SDK Strategy Matrix

"Built-in support" means SecWeaver ships the `connector_type`, query key, onboarding templates, and fetch routing. It **does not** mean every vendor SDK is installed by default. Default dependencies stay small; heavier SDKs and drivers use lazy import, REST fallback, plugins, or external executors.

| connector | Default / optional dependency strategy | Current live fetch path | If SDK/driver is missing |
|---|---|---|---|
| `sls` | Default `aliyun-log-python-sdk` | Official SLS SDK | Clear install error |
| `ssh_file` / `ssh_command` | Default `paramiko` | Paramiko read-only command/file fetch | Clear install error |
| `database_ro` MySQL/PostgreSQL | Default `pymysql`, `psycopg[binary]` | DB driver with select-only guard | Clear install error |
| `database_ro` Oracle/SQL Server | Optional `oracledb`, `pyodbc` lazy import | DB driver with select-only guard | Clear install error |
| `database_ro` SQLite | Python stdlib `sqlite3` | Read-only SQLite URI | No extra SDK needed |
| `http_api` / `es` / `splunk` | No vendor SDK by default | HTTP/REST API | No SDK needed; configured endpoint is used |
| `local_file` | Python stdlib | Local file read and parsing | No SDK needed |
| `clickhouse` / `hive` | Optional `clickhouse-connect`, `PyHive` lazy import | Official/community driver | Clear install error |
| `mongodb` / `redis` | Optional `pymongo`, `redis` lazy import | Official driver | Clear install error |
| `aws_cloudwatch` / `aws_s3_logs` | Optional `boto3` lazy import, not a default dependency | local sample → external executor → `boto3` → SigV4 REST fallback | Automatically falls back to REST when `boto3` is absent |
| `azure_monitor` | Azure SDK is not installed by default | local sample → external executor → OAuth + Log Analytics REST | No Azure SDK needed; SDK wrappers can live in an external executor |
| `gcp_logging` | Optional `google-auth` lazy import | local sample → external executor → `google-auth` token → Cloud Logging REST | Pre-issued token needs no SDK; service-account flow reports missing dependency |
| `tencent_cls` | Tencent Cloud SDK is not installed by default | local sample → external executor → TC3-signed REST | No SDK needed; SDK wrappers can live in an external executor |
| `huawei_lts` | Huawei Cloud SDK is not installed by default | local sample → external executor → token/AKSK-signed REST | No SDK needed; SDK wrappers can live in an external executor |
| `agent_stream` / `syslog_ingest` / `object_storage` | No vendor SDK binding | local sample / external executor / lightweight dedicated fetcher | Returns planned metadata when no endpoint is configured |

Recommended rule of thumb:

- For the smallest open-source core, use default dependencies, REST fallback, and local samples.
- To use an official SDK without polluting core dependencies, write a connector plugin or external executor.
- To make an SDK a built-in experience, add optional lazy import in the relevant `*_fetch.py` and keep a no-SDK fallback.

## Add a connector type without Python changes

You have two no-core-code paths:

- Register a config-only connector in `dataasset/configure/external-connectors.json` for local samples or external HTTP executors.
- Add a connector plugin under `src/dataasset/plugins/connectors/<plugin_name>/` when you need local code or SDKs without adding core dependencies.

Register the type in [`../configure/external-connectors.json`](../configure/external-connectors.json):

```json
{
  "connectors": {
    "datadog_logs": {
      "query_key": "datadog_query",
      "runtime": "local_or_external_executor",
      "description": "Datadog external executor",
      "onboarding_template": "external_generic",
      "onboarding_profile": {
        "label": "Datadog Logs",
        "fields": ["endpoint", "sample_file"],
        "required": [],
        "defaults": {"sample_file": "examples/log-format-discovery/waf-jsonl.sample"},
        "default_asset_type": "waf_alert",
        "template_params": ["src_ip", "time_start", "time_end", "limit"],
        "template_defaults": {"limit": 1000},
        "default_query": "source:security @network.client.ip:{src_ip} limit {limit}",
        "hint": "Use a local sample or external executor."
      }
    }
  }
}
```

Copyable config-only vendor examples already registered there include `datadog_logs`,
`okta_system_log`, `cloudflare_logs`, `crowdstrike_fdr`,
`microsoft_entra_signin`, `google_workspace_audit`,
`microsoft_defender_xdr`, and `sentinelone_events`.

Then use that `connector_type` in an onboarding config. `asset apply` uses the manifest's `onboarding_template` and injects the `query_key` from the same manifest; Studio builds its form from `onboarding_profile`.

```json
{
  "name": "demo-datadog",
  "connector_type": "datadog_logs",
  "asset_type": "waf_alert",
  "connector": {
    "config": {
      "endpoint": "https://executor.example.com/datadog",
      "sample_file": "examples/log-format-discovery/waf-jsonl.sample"
    }
  },
  "template": {
    "datadog_query": "source:security src_ip:{src_ip}"
  }
}
```

Runtime behavior:

- `sample_file`, `sample_dir`, `base_path`, or local `bucket/prefix` runs through the built-in local sample executor.
- `endpoint` or `base_url` receives a POST payload with `query`, `params`, and sanitized connector `config`.
- If neither local samples nor endpoint are configured, fetch returns planned metadata rather than failing as an unknown type.

External executor protocol and the optional AWS CloudWatch example are documented in
[`../../docs_dev/05-external-connector-executors.md`](../../docs_dev/05-external-connector-executors.md).
For CloudWatch, run:

```bash
python3 -m pip install boto3
python3 examples/executors/aws_cloudwatch_executor.py --port 8788
```

Then set `connector.config.endpoint` to `http://127.0.0.1:8788/fetch`.

For plugin connectors, add `plugin.json` and `fetch.py` under `src/dataasset/plugins/connectors/`, or set `SECWEAVER_PLUGIN_ROOT` to an external code directory. The demo type `demo_plugin_logs` is discovered from [`../../src/dataasset/plugins/connectors/demo_plugin_logs/plugin.json`](../../src/dataasset/plugins/connectors/demo_plugin_logs/plugin.json) and can be previewed with:

You can also scaffold a plugin first:

```bash
python3 src/secweaver.py connector plugin init vendor_logs \
  --query-key vendor_query
```

```bash
python3 src/secweaver.py asset apply \
  -f dataasset/onboarding/examples/vendor-quickstart-plugin-connector.json \
  --dry-run
```

Protocol details are documented in [`../../docs_dev/04-connector-plugins.md`](../../docs_dev/04-connector-plugins.md).

Each `data_sources[]` item supports three deep-merged override sections:

| Section | Use it for |
|---|---|
| `connector` | Source connection details beyond the common flags, such as nested `config`, fetch constraints, TLS settings, or source-specific options |
| `asset` | Runtime interpretation: `text_parser`, `schema.fields`, `schema.time_field`, `field_aliases`, `coverage.zones/apps/hosts`, tags, and status metadata |
| `template` | Query template behavior: `params`, `defaults`, `sls_query`, `es_query`, SQL text, descriptions, and custom `template_id` |

These sections are merged into the generated connector, asset, and query template JSON after placeholders are filled. Keep private deployment values in a private config file; committed examples should use `YOUR_*` or `vault://...` placeholders.

For a single source, the equivalent command form is:

```bash
python3 src/secweaver.py asset init \
  --connector-type sls \
  --asset-type waf_alert \
  --name demo-waf \
  --project YOUR_SLS_PROJECT \
  --logstore YOUR_LOGSTORE
```

Manual fallback: copy the three files from the directory for your `connector_type`, replace placeholders globally, then write them into `dataasset/`:

| Placeholder | Description |
|---|---|
| `YOUR_CONN_ID` | Connector ID, e.g. `conn-sls-my-log` |
| `YOUR_ASSET_ID` | Asset ID, e.g. `asset-my-log-prod` |
| `YOUR_SLS_PROJECT` / `YOUR_INDEX` | Real project, logstore, or ES index |
| `YOUR_HOST` | SSH/DB hostname |
| `YOUR_HOST_ID` | Host registry ID, e.g. `host-web-01` (see [hosts/](../hosts/)) |

## Directories

| Directory | connector_type | Files |
|---|---|---|
| [sls/](sls/) | `sls` | connector.json · asset.json · template.snippet.json |
| [es/](es/) | `es` | same |
| [ssh_file/](ssh_file/) | `ssh_file` | same |
| [database_ro/](database_ro/) | `database_ro` | same |
| [http_api/](http_api/) | `http_api` | same |
| [local_file/](local_file/) | `local_file` | same |
| [mongodb/](mongodb/) | `mongodb` | same |
| [redis/](redis/) | `redis` | same |
| [clickhouse/](clickhouse/) | `clickhouse` | same |
| [hive/](hive/) | `hive` | same |
| [splunk/](splunk/) | `splunk` | same |
| [aws_cloudwatch/](aws_cloudwatch/) | `aws_cloudwatch` | same |
| [aws_s3_logs/](aws_s3_logs/) | `aws_s3_logs` | same |
| [azure_monitor/](azure_monitor/) | `azure_monitor` | same |
| [gcp_logging/](gcp_logging/) | `gcp_logging` | same |
| [tencent_cls/](tencent_cls/) | `tencent_cls` | same |
| [huawei_lts/](huawei_lts/) | `huawei_lts` | same |

## Onboarding workflow (short)

```text
1. Edit dataasset/onboarding/examples/data-sources.sample.json (or your private copy)
2. Run secweaver asset apply --dry-run and review generated connector / asset / template content
3. Run secweaver asset apply to write dataasset/connectors/ + assets/ + query-templates/templates.json
4. Run secweaver validate --json --only-active
5. New format: asset status=discovery → discover.py + log-format-discovery Skill
6. discover.py ... --apply (or --apply mapping.json) writes field_aliases / schema / templates
7. validate.py → test_connector.py → status active
```

Connectivity checks can use either the asset command or the connector helper:

```bash
python3 src/secweaver.py connector test YOUR_ASSET_ID --by-asset --dry-run
python3 src/secweaver.py connector test YOUR_ASSET_ID --by-asset --plan
```

One-shot format discovery write:

```bash
python3 src/skills/log-format-discovery/scripts/discover.py \
  --asset-id YOUR_ASSET_ID -i samples.json --apply --apply-dry-run

# Review, then write for real
python3 src/skills/log-format-discovery/scripts/discover.py \
  --asset-id YOUR_ASSET_ID -i samples.json --apply
```

For a new text log format, generate a custom parser draft before review:

```bash
python3 src/secweaver.py asset discover-format YOUR_ASSET_ID \
  -i samples.log \
  --parser-id vendor-kv-log \
  --emit-parser dataasset/parsers/vendor-kv-log.json
```

**Field aliases are written to `asset.field_aliases` by default** (per-asset override of global aliases). Add `--global-aliases` to merge into `evidence-minimum-fields.json`.

See also [complete source onboarding](../../docs_user/03-configure-data-sources.md) · [field discovery and normalization](../../docs_user/20-log-format-discovery.md) · [field guide example](../../docs_ai/asset-es-waf-prod-field-guide.md)

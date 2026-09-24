# 03. How to Configure Data Sources

**Languages:** English (this page) | [简体中文](03-configure-data-sources.zh-CN.md)

This guide configures read-only queries for existing logs. It does not install ES, SLS,
or host collectors. Start with the [offline quickstart](00-security-operator-quickstart.md);
this guide is not a prerequisite for the first experience.

## Choose an onboarding path

| Your situation | Action |
|---|---|
| Community local client using SaaS (recommended) | Follow [SLS Proxy onboarding](30-sls-proxy-onboarding.md) for issued query credentials and assets |
| An administrator already prepared your analysis environment | Use the [Data Cloud quickstart](29-secweaver-data-system-quickstart.md); do not recreate credentials |
| Logs already in Elasticsearch/OpenSearch | Prepare the local directory below, then configure ES read-only access |
| You manage Alibaba Cloud SLS | Prepare the directory, then use the SLS example below |
| Logs are in MySQL, PostgreSQL, Oracle, SQL Server, or SQLite | Use the `database_ro` Connector with a read-only account and an engine-specific query template; follow the common workflow below |
| Logs are files reachable over SSH or on the local machine | Use the SSH/local templates and acceptance procedure below |
| Logs come from a cloud service, SIEM, EDR, or HTTP API | Start from `dataasset/onboarding/examples/`; use an external Connector or plugin only when the runtime is explicitly supported |
| Host logs are not collected yet | SaaS users follow Data Cloud; self-managed ES users follow [standalone Agent onboarding](../src/tools/secweaver-agent/elasticsearch/README.md) |

Identify the log type, storage location, real time field, and fields needed for investigation.
Register Networks and Hosts when you need their coverage metadata; they are not mandatory
prerequisites for platform-level WAF logs.

## Prepare the Asset Directory

Use a Linux/macOS POSIX terminal or WSL2 with Python 3.10+ and Make. Windows users must
first complete the [WSL2 quickstart](00-security-operator-quickstart.md); native Windows
is not a supported Community query-client environment. Saving query credentials requires
SOPS and age; see the [credential guide](../dataasset/credentials/README.md). Run from the repository root:

```bash
make quickstart
source .venv/bin/activate
export DATAASSET_ROOT=dataasset
```

Edit `dataasset/` directly by default. To isolate local configuration from the repository examples, optionally run the following before saving configuration or credentials:

```bash
if [ ! -e dataasset_my ]; then
  cp -R dataasset dataasset_my
fi
export DATAASSET_ROOT=dataasset_my
```

Preserve an existing `dataasset_my/`. When using isolation, replace configuration paths beginning with `dataasset/` below with `dataasset_my/`; do not replace the program directory `src/dataasset/`.
CLI, UI, and the AI agent must use the same asset root. In new terminals, set the selected `DATAASSET_ROOT` and activate the virtual environment again; specify the root in tasks if a desktop agent does not inherit it.
For either directory, Connector JSON stores credential references only. Do not commit real keys, private keys, encrypted credentials, or customer configuration to the public repository.

Start the configuration UI:

```bash
make ui
```

Open `http://127.0.0.1:8765/`. This UI manages configuration; it is not an AI chat interface. It occupies the terminal, so use a separate terminal or stop it with Ctrl+C before later commands. Initialize the credential environment and create a read-only credential on the Credentials page.

## End-to-end onboarding workflow

Use this lifecycle for every source. The ES, SLS, SSH, and local-file sections below
provide source-specific values, but they share the same status and acceptance rules.

```text
Choose asset root and collect source facts
    -> create read-only credential reference and Connector
    -> create Asset as discovery (unknown format) or draft (known format)
    -> discover and review fields when needed
    -> validate and preview the query
    -> run an authorized live query and verify one known event
    -> promote Connector and Asset to active, then add them to a Bundle
```

### 1. Collect the source contract

Record the log type, endpoint or file path, authorized scope, actual time field,
retention, sample event, expected canonical fields, and the exact test time window.
Do not infer these values from a similarly named sample Asset.

### 2. Register the Connector and credential reference

Create the credential in the local Vault or on the Studio Credentials page. Connector
JSON contains only a `vault://...` reference and non-secret connection settings:

For CLI-only setup, follow the [credential guide](../dataasset/credentials/README.md).
Initialize only a Vault that does not exist, then edit the required read-only reference;
never regenerate an existing age key or overwrite an existing SOPS policy:

```bash
bash src/dataasset/credentials/sops-vault.sh init
bash src/dataasset/credentials/sops-vault.sh edit vault://sls/your-readonly
```

| `connector_type` | Typical non-secret settings |
|---|---|
| `sls` | endpoint, region, project, logstore |
| `es` | HTTPS URL, index, time field, CA path when needed |
| `ssh_file` | host, port, allowed log paths |
| `local_file` | base path, log paths, hostname; no Vault required |
| `database_ro` | engine, host, database, read-only query scope |
| `http_api` | HTTPS base URL, endpoint allowlist, CA path when needed |
| `aws_s3_logs` | bucket, optional prefix and region |
| `azure_monitor` | workspace ID and optional tenant ID |
| `gcp_logging` | project ID |
| `tencent_cls` | endpoint, topic ID, region |
| `huawei_lts` | HTTPS endpoint, log group ID, log stream ID, project ID |
| `splunk` | HTTPS base URL, index, CA path when needed |

Keep a new Connector in `draft`. Never put passwords, access keys, private keys, or
tokens in Connector JSON, onboarding files, or agent conversations.

Configure the final HTTPS URL for remote ES, HTTP API, Splunk, and external executor
connections; runtime requests do not follow redirects. Plain HTTP is limited to explicit
`localhost`, `127.0.0.1`, or `::1` loopback development endpoints. Use `ca_file` for a
private CA, resolved relative to `DATAASSET_ROOT`; `tls_verify: false` and
`verify_tls: false` cannot bypass verification. A `credentials_ref` must use
`vault://namespace/name` without empty, `.` or `..` path segments.
After resolution, a relative `ca_file` and any symlink must remain inside
`DATAASSET_ROOT`; an administrator-managed system CA may use an absolute path.

### 3. Register the logical Asset

Create `assets/{asset_id}.json` under the selected asset root and bind it to the
Connector. Use `status: discovery` when the raw format or field mapping is unknown;
use `draft` only when the format, parser, fields, and query template are already known.

```jsonc
{
  "asset_id": "asset-my-new-log",
  "name": "My new log",
  "asset_type": "waf_alert",
  "domain": "D1",
  "status": "discovery",
  "connector_id": "conn-my-new-log",
  "schema": {
    "fields": ["timestamp", "src_ip", "url"],
    "time_field": "timestamp",
    "retention_days": 30
  },
  "query_template_ids": [],
  "coverage": {"zones": [], "apps": [], "hosts": []}
}
```

The initial fields may be incomplete while the Asset is in `discovery`. Do not add it
to a production Bundle or mark it active at this point.

### 4. Discover fields and write reviewed mappings

For an unknown format, prepare sanitized representative samples and follow
[Log Format Discovery](20-log-format-discovery.md). That guide owns source-field
inspection, `text_parser` selection, `field_aliases`, query-field mapping, preview,
and reviewed write-back. When complete, move the Asset from `discovery` to `draft`.

Known formats may skip discovery, but still require a source-field review. Runtime
normalization is deterministic after configuration; it does not invoke an LLM for every
event.

### 5. Preview, apply, and review generated configuration

When using a bundled onboarding file, preview before writing and inspect the diff:

```bash
.venv/bin/python src/secweaver.py asset apply --output-dir "$DATAASSET_ROOT" \
  -f /tmp/my-source.json --dry-run
.venv/bin/python src/secweaver.py asset diff --output-dir "$DATAASSET_ROOT" \
  -f /tmp/my-source.json
.venv/bin/python src/secweaver.py asset apply --output-dir "$DATAASSET_ROOT" \
  -f /tmp/my-source.json
```

If an applied onboarding package is wrong, preview its controlled rollback first:

```bash
.venv/bin/python src/secweaver.py asset rollback --output-dir "$DATAASSET_ROOT" \
  -f /tmp/my-source.json --dry-run
```

Rollback targets only the Connector, Asset, and query template generated by that file.
Do not manually delete active production objects; use `--confirm-delete` only after the
preview identifies the intended generated objects.

### 6. Validate, query, and activate

Run Schema/catalog validation, then a query-plan dry-run. Replace the sample values with
an authorized known event before the live query:

```bash
.venv/bin/python src/dataasset/validate.py --sync-catalog
.venv/bin/python src/dataasset/test_connector.py asset-my-new-log --by-asset \
  --plan --dry-run
.venv/bin/python src/dataasset/test_connector.py asset-my-new-log --by-asset \
  --params '{"src_ip":"203.0.113.10","time_start":"2026-09-08T00:00:00Z","time_end":"2026-09-08T00:05:00Z","limit":10}'
```

Acceptance requires a successful command, the expected backend and time window, one
known event, correct canonical fields after normalization, and usable evidence references.
An empty result is not acceptance. Resolve validation errors with
[Operations Checks and Troubleshooting](09-operations-troubleshooting.md).

Only after those checks pass should both Connector and Asset become `active`. Add only
verified Assets to a Bundle, rerun validation, and run a completeness check before an
investigation. At runtime, fetch, parsing, aliases, time normalization, masking, and
`evidence_id` generation run automatically from the reviewed configuration.

## Existing Elasticsearch: one-click onboarding

The browser wizard verifies HTTPS certificates during discovery and activation. Generated
Connectors use `tls_verify: true`. For a private CA, supply `ca_file`; relative paths
resolve from `DATAASSET_ROOT`. Unknown CAs, expired certificates and hostname mismatches
fail without an insecure retry. Schema validation, the go-live gate, and the ES runtime
also reject a manually written `tls_verify: false`. Obtain a read-only account and CA
from your ES administrator.

Open Customer-managed Elasticsearch at `http://127.0.0.1:8765/onboarding.html`,
probe the cluster, select an index, inspect its fields, and activate. A successful query
does not verify field correlation, event coverage or production capacity. Complete the
checks below before investigation. See [query integrity and masking](community-release-and-data-safety.md).

### Production ES: configure read-only queries explicitly

1. Obtain the HTTPS endpoint, authorized indices, real time field, read-only account, and any CA file from your ES administrator.
2. Create `vault://es/security-readonly` with type `es` on the local UI Credentials page.
3. Edit `connectors/conn-es-waf-prod.json` in the selected asset directory. This is a complete Connector example;
   replace the endpoint and indices. Add `ca_file` for a private CA; relative paths resolve from `DATAASSET_ROOT`.

```json
{
  "connector_id": "conn-es-waf-prod",
  "name": "Customer WAF Elasticsearch",
  "connector_type": "es",
  "status": "draft",
  "credentials_ref": "vault://es/security-readonly",
  "config": {
    "url": "https://es.example.com:9200",
    "index": "logs-waf-*",
    "time_field": "@timestamp",
    "tls_verify": true
  }
}
```

Omit `ca_file` when using the system trust store; a private CA example path is
`credentials/ca/customer-es.pem`. Relative paths and symlinks cannot escape
`DATAASSET_ROOT`; system CA files may use absolute paths. Do not disable verification to troubleshoot.
Do not query with the setup administrator or Filebeat writer account.

4. Edit the existing `assets/asset-es-waf-prod.json`; check fields, aliases, retention,
   and the `waf_es_by_src_ip_time` template. Its source fields must match your index;
   do not reuse a WAF asset for other log types.
5. Complete Query acceptance and activation below. Verify OpenSearch query compatibility
   on the target version; query support does not imply Agent shipper support for OpenSearch.

## Direct Alibaba Cloud SLS

Use this section only when you manage the SLS Project and RAM read permissions.
Proxy Keys are not RAM Keys; SaaS users should follow [SLS Proxy onboarding](30-sls-proxy-onboarding.md).

Create `vault://sls/security-readonly` with type `aliyun_ram` on the Credentials page.
Edit `connectors/conn-sls-waf-prod.json` in the selected asset directory, replacing the regional endpoint,
Project, and Logstore:

```json
{
  "connector_id": "conn-sls-waf-prod",
  "name": "Customer WAF SLS",
  "connector_type": "sls",
  "credentials_ref": "vault://sls/security-readonly",
  "config": {
    "endpoint": "cn-hangzhou.log.aliyuncs.com",
    "region": "cn-hangzhou",
    "project": "YOUR_SLS_PROJECT",
    "logstore": "YOUR_WAF_LOGSTORE"
  },
  "status": "draft"
}
```

Confirm logs already exist and query fields have SLS indexes. SecWeaver does not create
Projects, Logstores, or RAM permissions.

## Configure the Asset

An Asset identifies the logical log, its fields, and its query templates. This complete SLS
WAF structure corresponds to `assets/asset-waf-prod-01.json` in the selected asset directory;
it is not a universal template for every log type:

```json
{
  "asset_id": "asset-waf-prod-01",
  "name": "Customer WAF alerts",
  "asset_type": "waf_alert",
  "domain": "D1",
  "connector_id": "conn-sls-waf-prod",
  "coverage": {"hosts": []},
  "schema": {
    "fields": ["timestamp", "src_ip", "url", "action", "rule_id", "payload"],
    "time_field": "timestamp",
    "retention_days": 30
  },
  "field_aliases": {
    "client_ip": "src_ip",
    "remote_addr": "src_ip",
    "request_uri": "url",
    "path": "url"
  },
  "query_template_ids": ["waf_gateway_plugin_by_ip_time"],
  "status": "draft"
}
```

Use D1 through D7 for `domain`; `schema.time_field` is required.
Record actual upstream retention. Changing this metadata does not change ES/SLS deletion policies.

`field_aliases` maps source fields to canonical fields after retrieval; query templates
must still use fields searchable in the upstream system. The complete source-field,
parser, alias, and query-layer model is maintained in
[Log Format Discovery](20-log-format-discovery.md#field-discovery-and-normalization-model).

For an unknown format, start with `discovery`, inspect sanitized samples with
[log format discovery](20-log-format-discovery.md), then move to `draft` after review.
See [DataAsset Schemas](../dataasset/schema/) for Host, Network, and field constraints.

<a id="ssh-and-local-files"></a>

## SSH and local log files: minimal onboarding

Complete the local directory preparation above and keep your selected `DATAASSET_ROOT`. These steps cover `syslog_auth` text authentication logs from a Linux/macOS/WSL2 query client. JSON, Windows events, and other formats need a matching parser. SSH also requires network access, permission to read the target logs, and a read-only account stored as `type: ssh` in the Vault; see the [credential guide](../dataasset/credentials/README.md).

Start with the [SSH file templates](../dataasset/onboarding/ssh_file/) or [local file templates](../dataasset/onboarding/local_file/). The commands below copy only to new files, preserving existing configuration. Run the group you need:

```bash
# SSH files
cp -n dataasset/onboarding/ssh_file/connector.json "${DATAASSET_ROOT}/connectors/conn-my-ssh-auth.json"
cp -n dataasset/onboarding/ssh_file/asset.json "${DATAASSET_ROOT}/assets/asset-my-ssh-auth.json"

# Local files
cp -n dataasset/onboarding/local_file/connector.json "${DATAASSET_ROOT}/connectors/conn-my-local-auth.json"
cp -n dataasset/onboarding/local_file/asset.json "${DATAASSET_ROOT}/assets/asset-my-local-auth.json"
```

Edit the copied JSON files and replace the placeholders:

| Field | SSH files | Local files |
|---|---|---|
| Connector `connector_id` | `conn-my-ssh-auth` | `conn-my-local-auth` |
| Asset `asset_id` | `asset-my-ssh-auth` | `asset-my-local-auth` |
| Asset `connector_id` | `conn-my-ssh-auth` | `conn-my-local-auth` |
| Connection and path | Set `config.host`, SSH `config.port`, and the readable absolute path in `config.log_paths.ssh_auth` | Set `config.base_path` to the absolute local log directory and `config.log_paths.ssh_auth` to the filename within it |
| Query template | Change `query_template_ids` to `["ssh_file_grep_auth"]` | Set `query_template_ids` to `["local_file_grep_auth"]` |
| Credentials | Use the existing `vault://ssh/readonly` reference; keep passwords/private keys in the Vault | No SSH credentials; the local user running the query reads the file |

Keep `text_parser: "syslog_auth"`. Set the real retention and coverage metadata, and `config.hostname` for local logs. Set SSH Asset `coverage.hosts` to actual log source IPs matching Host `host_ip` or `interfaces[].ip`, not Host IDs or hostnames. Use an empty array until the source is confirmed; completeness checks will reflect the coverage gap. Keep both Connector and Asset in `draft`, and promote them only after query verification below. Do not use `ssh_auth_by_src_ip_time` from the SSH asset template: that template targets SLS/databases. File queries need `ssh_file_grep_auth` instead.

Preview without decrypting credentials or contacting the remote host. Paths must match the files permitted by the Connector:

```bash
.venv/bin/python src/dataasset/test_connector.py asset-my-ssh-auth --by-asset --dry-run \
  --params '{"grep_pattern":"203.0.113.10","log_path":"/var/log/auth.log","max_lines":100}'

.venv/bin/python src/dataasset/test_connector.py asset-my-local-auth --by-asset --dry-run \
  --params '{"grep_pattern":"203.0.113.10","log_path":"auth.log","max_lines":100}'
```

Replace the sample IP and filename with an authorized, known test event, then remove `--dry-run` from the applicable command to read it. Confirm the event is returned and `host`, `timestamp`, `src_ip`, `user`, and `result` match the source. Empty results do not pass verification.

These templates match a constrained regular expression and retain the last `max_lines` lines (dots in an IP remain regex wildcards, so verify the returned `src_ip`); they **do not automatically filter by `time_start/time_end`**. Use a bounded log excerpt and verify timestamps, timezone, year, and rotated files. This read cannot establish that no other events exist in the investigation window. Local file queries run on the SecWeaver machine and cannot read remote paths.

## Query acceptance and activation

This example uses SLS WAF; ES users substitute `asset-es-waf-prod`.
Replace the parameters with the real target and exact time window before a live query.
The reserved IP and fixed dates below are for offline preview only:

```bash
.venv/bin/python src/dataasset/validate.py --sync-catalog
.venv/bin/python src/dataasset/test_connector.py asset-waf-prod-01 --by-asset \
  --dry-run --params '{"src_ip":"203.0.113.10","time_start":"2026-09-08T00:00:00Z","time_end":"2026-09-08T00:05:00Z","limit":10}'
```

Check the actual index/Logstore, template, and filter fields. Replace the IP and times with
an authorized test event, then remove `--dry-run` for a live query.
Do not use the fixed sample dates for production acceptance.

Acceptance requires no command errors, the known test event, the correct target/time,
and usable canonical fields and evidence references. Empty results prove neither successful
onboarding nor absence of attack; check time, permissions, fields, indices, and ingestion delay.

Only after live queries and field checks pass, set both Connector and Asset to `active`.
Add only verified assets to an investigation Bundle, then run:

```bash
.venv/bin/python src/dataasset/validate.py --sync-catalog
make validate
```

Unconfigured copied examples are not production assets; do not bulk-enable them or add them
to production Bundles. Configuration existence, Schema validity, successful queries, and
complete evidence are four different checks.

Finally give the AI the selected `DATAASSET_ROOT`, actual Asset/Bundle IDs, target,
and timezone-aware start/end times. Run [completeness checks](15-data-source-completeness.md)
before alert confirmation, risk identification, or traceability. Keep credentials out of
the conversation and report missing evidence explicitly.

## Collection and further reading

- New host logs: [SaaS Agent installation](29-secweaver-data-system-quickstart.md) or
  [Agent to your ES](../src/tools/secweaver-agent/elasticsearch/README.md).
  Deployment, upgrades, and rollback belong to those guides; installation commands are not repeated here.
- Cross-source joins: [Correlation Matrix](04-correlation-matrix.md).
- Validation and troubleshooting: [Operations Checks and Troubleshooting](09-operations-troubleshooting.md).
- Short onboarding answers: [Data Source Onboarding FAQ](16-data-source-onboarding-faq.md).

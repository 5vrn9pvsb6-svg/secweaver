# SLS Proxy User Onboarding

After onboarding, use [Enterprise Workspace → Query logs](https://sc.id-net.cn:30443/#/query-logs) to inspect query text, status, source IP and API Key ownership. Shared enterprise keys do not identify an individual user; old records may lack these fields.

**Languages:** English (this page) | [简体中文](30-sls-proxy-onboarding.zh-CN.md)

This guide connects the Community client to SaaS: save one query credential, retrieve a
real event, then make the asset available to AI. No SLS Proxy, Docker, or ES deployment is needed.

If an administrator has already configured your DataAsset environment, use the
[Data Cloud customer quickstart](29-secweaver-data-system-quickstart.md).
Use that guide for a platform-issued Agent install command when new host logs are needed.
The steps below configure **queries, not uploads**. Proxy keys are not Logtail write credentials.

## 1. Obtain Connection Settings

Register at the [enterprise workspace](https://sc.id-net.cn:30443/) and complete the first SSO login to automatically create an enterprise and one Proxy AK/SK pair. Under **Agent Configuration (`智能体配置`)**, Owner/Admin members can see AK and explicitly reveal or copy SK. Older enterprises missing a mapped key backfill on their next login. Repeated login does not rotate keys; expired/revoked keys need operator action. Store credentials in the local encrypted Vault, never in an intelligent-agent conversation.

Check the settings below. An unbound Logstore or missing logs still requires administrator SLS resource configuration:

| Setting | Value |
|---|---|
| Query endpoint | `https://sls-proxy.id-net.cn:30443` (the Connector `endpoint`) |
| Enterprise Workspace | `https://sc.id-net.cn:30443/` (login, **Agent Configuration (`智能体配置`)**, and **Query Logs (`查询日志`)**) |
| Fallback query endpoint | No distinct default; the compatibility `fallback_endpoint` repeats the primary origin |
| Project | The public Project displayed in Enterprise Workspace, currently `secweaver`; omit or leave empty only to use the Proxy default |
| Logstore | A user-facing logical Logstore displayed by Enterprise Workspace; see the table below |
| Query credentials | Proxy `access_key_id` and `access_key_secret`, not Alibaba Cloud RAM keys |

The platform owns tenant identity, upstream SLS resources, collection fields, and indexing.
Do not add `enterprise_id` or `region` to the Connector or construct tenant
predicates yourself. If service or credentials are unavailable, contact the platform
administrator; public source does not automatically provision SaaS.
`config.project` and `config.logstore` select an authorized resource together. Explicit Project selection requires Go Proxy 0.6.0-rc.14/schema 10 or later with that Project configured and bound to your enterprise. An older service may reject the request; do not remove Project to bypass a failure or accidentally query the default. Use the Project/Logstore displayed in Enterprise Workspace → Agent Configuration. With resource mapping enabled, one public Project (for example `secweaver`) can represent multiple physical resources; do not substitute real SLS Project names. Physical names in older examples apply only to services without mapping. The Proxy hostname stays unchanged.
Obtain service activation confirmation and the platform login URL from your organization's
Data Cloud administrator. The endpoints above are for queries, not registration, platform login,
or Agent uploads. Continue with offline cases while an administrator handoff is unavailable.

### 1.1 User-facing Project and Logstore catalog

The following catalog is what Enterprise Workspace exposes to users. Every row uses the public
Project `secweaver`; the Proxy maps these logical names to physical SLS resources on the server.
Do not put physical Project/Logstore names, including `wis-log/gateway_plugin_log`, into a
Connector. Availability still depends on administrator publication, enabled Agent modules, and
whether the selected time window contains data.

| User-facing Project | User-facing Logstore | Main purpose and data scope |
|---|---|---|
| `secweaver` | `host-persistence` | Changes under persistence locations such as cron, systemd, `authorized_keys`, sudoers, and profile files; useful for backdoor, auto-start, and privilege-escalation investigation. |
| `secweaver` | `host-process` | Process baselines, starts, exits, and key attribute changes for anomalous-process investigation; periodic snapshots do not replace real-time auditing of short-lived commands. |
| `secweaver` | `host-state` | Baselines and changes for accounts/sessions, services/tasks, listening ports, kernel, and container context; supports exposure and state checks, not an audit of every operation. |
| `secweaver` | `host-exec` | Command execution, active outbound connections, and file operations separated by `event_type`, for WebShell, reverse-shell, and dangerous-command investigation. |
| `secweaver` | `host-sys-messages` | Structured SSH, PAM, root-session, and system-risk events parsed from Linux messages/secure logs; it is not the complete raw system log. |
| `secweaver` | `dns` | Internal DNS queries for suspicious-domain, suspected-C2, and host-network correlation; only queries passing through the designated platform resolver are covered. |
| `secweaver` | `wis-waf-access` | TS gateway requests and upstream-access evidence for Web analysis, alert validation, and tracing; an access record alone is not an attack alert. |
| `secweaver` | `wis-waf-log` | WAF gateway-plugin alerts with rule, source-IP, and request clues; an administrator must activate the enterprise `tenant_id` mapping, and a rule hit does not prove a successful attack. |

DNS, TS access, and WAF assets may be generated from the template, but keep them in
`discovery`/`draft` until server-side `enterprise_id`/tenant isolation, field indexing, and a
real event query have all succeeded.

This example uses existing host-execution logs. For other log types, use the platform's
Asset/query templates or [configure the source](03-configure-data-sources.md);
do not label all logs as `host_exec`.

### Project and TLS validation

`project` is optional; an empty value keeps the server default. A nonempty name must be
1–128 ASCII letters, digits, `_` or `-`, beginning with a letter or digit. The public
schema and query runtime enforce the same rule; `region` remains server-managed.

Probes and signed queries verify TLS certificates by default (`tls_verify: true`).
For a private CA, set `config.ca_file` to a PEM CA bundle; relative paths resolve under
`DATAASSET_ROOT`, and absolute paths are accepted. Missing/invalid CA files and certificate
failures stop the request without switching to a fallback endpoint or disabling validation.
`tls_verify` accepts booleans only. Explicit `false` is retained for diagnostic compatibility,
not recommended for production, and cannot be combined with `ca_file`. Existing configurations
that omitted the flag now require a trusted certificate; fix the trust chain or supply the CA.
After configuration, run the dry-run and live checks in §5, followed by `catalog sync` and
`validate`; a dry-run alone does not test the certificate or credentials.

## 2. Prepare the Local Query Environment

Use a Linux/macOS POSIX terminal or WSL2 with Python 3.10+, Make, SOPS, and age. Windows
users must install WSL2 first; native Windows is not a supported Community query-client
environment. In WSL2, keep the checkout and virtual environment inside the WSL filesystem.
See the [quickstart](00-security-operator-quickstart.md) for installation and environment
limits. Run from the repository root:

```bash
make quickstart
source .venv/bin/activate
export DATAASSET_ROOT=dataasset
```

WSL2 can run the Python query client and SLS Proxy workflow, but it does not provide
Windows Event Log, Security 4688, Sysmon, or Windows service collection. Install the
Windows Agent on the native Windows host when those Windows sources are required.

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

## 3. Save the Query Credential

Start the UI and use **Credentials** to create `vault://sls/sls-proxy-query` with type
`aliyun_ram` and the platform-issued Proxy AK/SK. Both UI and CLI require local SOPS/age.

```bash
make ui
```

Open `http://127.0.0.1:8765/`, initialize the credential environment, and create the credential.
Keep the UI running in a separate terminal, or stop it with Ctrl+C before the CLI steps.
In a new terminal, repeat the selected `DATAASSET_ROOT` and `source .venv/bin/activate`.
Alternatively, use **Bash 4+**, `sops`, `age`, and `age-keygen` for the commands below.
macOS's default Bash 3.2 does not satisfy the script's requirement; select an installed newer
Bash. See the [credential guide](../dataasset/credentials/README.md) for dependencies.

Run the first command only for an uninitialized local Vault; preserve existing keys/configuration:

```bash
bash src/dataasset/credentials/sops-vault.sh init
bash src/dataasset/credentials/sops-vault.sh edit vault://sls/sls-proxy-query
bash src/dataasset/credentials/sops-vault.sh get vault://sls/sls-proxy-query
```

The editor uses the fields below and encrypts on save. The last command prints masked values:

```yaml
type: aliyun_ram
access_key_id: "SWAK_REPLACE_ME"
access_key_secret: "REPLACE_ME"
```

Never put real keys into AI prompts, CLI arguments, or Connector JSON. Do not commit private
keys or ciphertext. No full `bootstrap` is required; `edit` creates this credential from
its public placeholder template.

## 4. Configure the Connector and Asset

Edit `dataasset/connectors/conn-sls-proxy-demo.json` in your selected asset directory.
Preserve its ID and credential reference; set `config.project` and `config.logstore` to the authorized pair shown in Enterprise Workspace. The host-execution example below uses the current public names. Omit or leave `project` empty only for the default Project. Confirm both HTTPS endpoints:

```json
{
  "endpoint": "https://sls-proxy.id-net.cn:30443",
  "fallback_endpoint": "https://sls-proxy.id-net.cn:30443",
  "project": "secweaver",
  "logstore": "host-exec"
}
```

This is the Connector's `config` object, not a complete Connector.
See the full [public connector](../dataasset/connectors/conn-sls-proxy-demo.json).

Use the accompanying [host-execution Asset](../dataasset/assets/asset-sls-proxy-host-exec-demo.json).
In the selected asset directory, check `schema.time_field`, real fields, and aliases. Example host coverage
and retention are not production guarantees. Keep the Connector `draft` and Asset `discovery`
until verification succeeds.

To configure the complete SecWeaver SaaS asset set, select
[`secweaver-saas-sls-proxy-assets.json`](../dataasset/onboarding/examples/secweaver-saas-sls-proxy-assets.json)
from the DataAsset UI Quickstart dropdown, or preview the 13 generated Connector, Asset, and query-template sets from the repository root:

```bash
.venv/bin/python src/secweaver.py asset apply \
  -f dataasset/onboarding/examples/secweaver-saas-sls-proxy-assets.json \
  --dry-run
```

The template uses the public logical Project `secweaver` and covers 8 public Logstores. Its Connectors contain no physical upstream Project, `enterprise_id` value or filter, or credentials. The enterprise field in an Asset schema is the target data contract that the server will populate and use for isolation. Remove unneeded or unauthorized sources before writing. Generated Connectors/Assets remain `draft/discovery`; run a live query for each retained asset before enabling it. DNS, TS access, and WAF templates may be generated in advance, but they are usable only after server-side `enterprise_id` integration, field indexing, and a successful query.

## 5. Verify a Real Event

Generate a recent five-minute UTC window in the same terminal. This only computes time;
it does not access credentials or the network:

```bash
SLS_CHECK_PARAMS="$(.venv/bin/python -c 'import datetime,json; end=datetime.datetime.now(datetime.timezone.utc); print(json.dumps({"time_start":(end-datetime.timedelta(minutes=5)).isoformat(),"time_end":end.isoformat(),"limit":10}))')"
.venv/bin/python src/dataasset/test_connector.py conn-sls-proxy-demo \
  --params "$SLS_CHECK_PARAMS" --dry-run
```

Inspect the rendered query/window, then remove `--dry-run` for a live platform request:

```bash
.venv/bin/python src/dataasset/test_connector.py conn-sls-proxy-demo \
  --params "$SLS_CHECK_PARAMS"
```

Results may contain real logs. Inspect them in an authorized local terminal, not a public
issue or an unredacted intelligent-agent prompt. Confirm:

- The command exits successfully without a `status: error` result, and `events` contains a
  test event previously confirmed by the platform; empty results
  do not prove successful ingestion.
- Host, command, and event time match expectations; internal tenant fields are absent.
- `query_meta.endpoint_used` and `query_meta.fallback_used` match the actual endpoint.
- Asset time fields and aliases match the returned records.

Then test `asset-sls-proxy-host-exec-demo` in the UI with the same window and a real host,
checking its query template. After success, set both local Connector and Asset to `active`:

```bash
.venv/bin/python src/secweaver.py catalog sync
.venv/bin/python src/secweaver.py validate
```

Add only accepted assets to investigation bundles. Tell the intelligent agent which Bundle, host, and
window to use. Host execution alone cannot establish a full attack chain; run completeness
before risk identification or traceability.

### 5.1 Counts and Categories (COUNT / GROUP BY)

The Proxy already supports SLS aggregation. **Omit `FROM`, including `FROM log`.**
Put search filters before `|` and analytics after it. The Connector still selects
Project/Logstore; do not select resources in SQL. This follows the
[official SLS query syntax](https://www.alibabacloud.com/help/en/sls/query-syntax/).
These are query strings, not terminal commands: use them in a tool/template that
accepts raw SLS queries, and supply start/end times separately. Replace the example
IP with an authorized real host:

```sql
host_ip:"192.0.2.10" | SELECT count(*) AS n
host_ip:"192.0.2.10" | SELECT event_type, count(*) AS n GROUP BY event_type ORDER BY n DESC LIMIT 100
host_ip:"192.0.2.10" | SELECT asset_type, count(*) AS n GROUP BY asset_type ORDER BY n DESC LIMIT 100
```

Choose fields present in the actual Asset; some system logs use `__source__` for
host filtering. Grouping fields require an SLS SQL analysis index. Ask the
administrator about missing fields/indexes; a failed query does not mean zero
records. Aggregate rows are not raw events and must not be passed directly to
risk-analysis or traceability skills that require raw evidence.

- The Proxy injects tenant filtering before aggregation. Signing, resource authorization,
  time-window, retention, concurrency, and result-row limits still apply.
- `FROM`, `JOIN`, `UNION`, and other cross-resource SQL remain unsupported; reserved
  tenant fields cannot be selected or grouped.
- `LIMIT 100` bounds returned groups, not scanned data. Grouping high-cardinality
  fields still increases latency and resource use. For a total, omit `GROUP BY`;
  for categories, choose a few low-cardinality fields and the shortest useful window.
- A complete count requires `progress=Complete` (SDK `is_completed()` is true).
  When the number of groups reaches `LIMIT`, additional groups may be omitted;
  their returned sum is not necessarily the total. API `count`/`X-Log-Count` reports
  aggregate rows returned; read each row's `n` for log counts.
- `COUNT(*)` counts stored records in the SLS query time window without deduplication;
  it does not automatically count by the original event timestamp field. Specify
  timezone, start/end times, and time basis when counting “today.”

## 6. Troubleshooting and Rotation

| Symptom | User action |
|---|---|
| `Unauthorized` | Check Proxy key, expiry, and system time; do not substitute Alibaba RAM keys |
| `Forbidden` | Ask the platform to check tenant/key state and scope |
| `ProjectNotExist` / `LogStoreNotExist` | Check the authorized Project/Logstore pair; ask the platform about upstream resources |
| Query succeeds without the test event | Check window, timezone, host fields, and delay; ask the platform to inspect ingestion |
| `QueryPolicyDenied` | Remove `FROM log` from aggregate queries; avoid reserved tenant fields, cross-resource SQL, and unsupported scans |
| TLS, 404, or both endpoints fail | Check local connectivity and send a redacted error to the platform; keep TLS verification enabled |
| CLI works but AI does not | Check the host's asset root, credential access, and Bundle |

The client probes primary `/livez` first. Connectivity failures, missing routes, timeouts,
and temporary `502/503/504` failures may select fallback. Authentication, authorization,
policy, and normal query errors do not. Fix certificate trust rather than disabling TLS checks.

For rotation, obtain a new query key, update the local credential, verify it, then revoke the
old key according to platform instructions. Do not change Agent enrollment tokens or SLS
collector write credentials as part of query-key rotation.

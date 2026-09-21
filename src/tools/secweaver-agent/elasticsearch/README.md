# Agent Ingestion Into Your Elasticsearch

**Language:** English (this page) | [简体中文](README.zh-CN.md)

Use [SaaS SLS Proxy](../../../../docs_user/30-sls-proxy-onboarding.md) by default. When you need
host telemetry, obtain the platform-issued installation command using the
[Data Cloud quickstart](../../../../docs_user/29-secweaver-data-system-quickstart.md). The platform
operates SLS storage, field governance, and upgrade delivery.

Use this alternative when you already operate ES or require customer-managed storage:

```text
Linux Agent -> local JSONL -> Filebeat -> customer Elasticsearch
                                     <- DataAsset read-only queries <- AI Skills
```

Everything in this directory is public. No `secweaver-es-operator`, private asset registry,
or server source is required. This is not an ES installer, managed-service replacement,
or capacity guarantee. It does not create ES users, SaaS tenants, or backups. Never run the
standalone installer on a host already enrolled in SaaS.

## Scope and Prerequisites

- This configuration targets Linux with systemd, Elasticsearch 8.x and Filebeat 8.19.x.
  Select maintained patch releases according to Elastic's support policy. Do not apply it
  unchanged to OpenSearch, ES 9, or Windows.
- See the [Agent manual](../README.md) for supported kernels,
  platforms, and audit prerequisites. Building needs Go 1.22+ and Make; initialization needs
  Python 3.10+. Install Filebeat separately from Elastic; no Filebeat binary is bundled here
  or in the public Agent. Existing host audit policy must remain compatible.
- ES must have HTTPS, authentication, a trusted certificate matching its hostname, and
  synchronized clocks. Prepare separate setup, ingestion, and read-only accounts. Restrict
  ES network access to the hosts that need it.
- Repository tests cover template and configuration contracts, script requests, and safety
  checks. Complete the live acceptance steps on your target Linux/ES environment before
  production. Unit tests are not throughput, compatibility, or lossless-delivery guarantees.

## 1. Initialize ES

From the repository root, preview the template offline without modifying anything:

```bash
python3 src/tools/secweaver-agent/elasticsearch/init_es.py
```

The setup account needs cluster `manage_index_templates` and version discovery access.
Online commands prompt for a hidden password, never saving it. Automation may inject
`SECWEAVER_ES_PASSWORD`; clear it after use rather than putting secrets on command lines.

```bash
python3 src/tools/secweaver-agent/elasticsearch/init_es.py --apply \
  --endpoint https://es.example.com:9200 \
  --ca-file /absolute/path/es-ca.crt --username setup_admin
```

Only the `secweaver-public-agent-v1` template matching `secweaver-public-agent-*` is created.
An identical template is skipped; a differing template is refused. `create=true` prevents
concurrent replacement. Failure never triggers deletion. Existing indices, other templates,
and retention policies are untouched. Have an administrator review any higher-priority
templates that also match this prefix.

Defaults are one primary and one replica. For a **single-node test cluster**, add
`--replicas 0`; that provides no replica redundancy. Changing this option on a later run
refuses the differing template; an administrator must review and change it explicitly.
The cluster must permit daily index auto-creation for this prefix. The script does not
change global auto-creation policy.

Create roles and separate users through your existing IAM process. This role API body is
for the Filebeat writer, not a DataAsset configuration:

```json
{
  "cluster": ["monitor"],
  "indices": [{
    "names": ["secweaver-public-agent-*"],
    "privileges": ["auto_configure", "create_doc"]
  }]
}
```

Use this separate role for DataAsset and verification queries. `monitor` is cluster-wide
and enables version/health probes; administrators should evaluate tighter privileges for
strict isolation. Never give Filebeat the setup administrator's credentials.

```json
{
  "cluster": ["monitor"],
  "indices": [{
    "names": ["secweaver-public-agent-*"],
    "privileges": ["read", "view_index_metadata"]
  }]
}
```

## 2. Install a Standalone Agent

On the target Linux host, prepare the public source and audit dependencies, then review and
build the source. These commands do not create a release package:

```bash
make -C src/tools/secweaver-agent build
sudo bash src/tools/secweaver-agent/elasticsearch/install-agent.sh \
  "$PWD/src/tools/secweaver-agent/secweaver-agent" SECWEAVERLOCAL01
```

Replace `SECWEAVERLOCAL01` with your local 16-character uppercase ASCII alphanumeric group
ID. It is **not a SaaS tenant identity or an ES tenant-isolation boundary**. Separate tenants
require independently scoped index permissions and deployment boundaries.

The installer refuses an existing `/opt/secweaver-agent` or service. It creates configuration
and a systemd unit but **does not start it**. Licensing, remote policy, and automatic updates
are disabled in this fresh standalone configuration; no managed control plane is contacted.
Installation failures preserve partial files for inspection. Do not delete an existing
host's identity, logs, or state simply to retry installation.

Review all three JSON files under `/opt/secweaver-agent/etc/`, including audit collection
scope and disk budgets. Then run each step only after the previous step succeeds:

```bash
sudo /opt/secweaver-agent/bin/secweaver-agent preflight \
  -config /opt/secweaver-agent/etc/config.json -strict
sudo systemctl enable --now secweaver-agent
sudo systemctl status secweaver-agent --no-pager
sudo journalctl -u secweaver-agent -n 50 --no-pager
sudo ls -l /opt/secweaver-agent/logs/
```

Resolve failed preflight checks before starting. Install `auditd`/net-tools as required by
the Agent platform guide. A container without host privileges is not full host collection.

## 3. Install and Configure Filebeat

Follow [Elastic's installation instructions](https://www.elastic.co/guide/en/beats/filebeat/8.19/filebeat-installation-configuration.html).
The commands below use deb/rpm defaults and assume a dedicated Filebeat service. If Filebeat
already collects other business logs, have its administrator merge inputs and routing;
do not overwrite that configuration or run duplicate collectors for the same files.

[filebeat.yml](filebeat.yml) is JSON-form YAML, allowing direct installation and deterministic
validation. It covers six default log paths and their rotated files. Preserve input IDs,
Filebeat's registry, and its `path.data` across restarts.

```bash
sudo install -m 0644 /absolute/path/es-ca.crt /etc/filebeat/secweaver-es-ca.crt
sudo install -m 0600 src/tools/secweaver-agent/elasticsearch/filebeat.yml /etc/filebeat/secweaver-agent.yml
sudo filebeat keystore create
sudo filebeat keystore add SECWEAVER_ES_URL
sudo filebeat keystore add SECWEAVER_ES_CA
sudo filebeat keystore add SECWEAVER_ES_WRITER_USER
sudo filebeat keystore add SECWEAVER_ES_WRITER_PASSWORD
```

Enter the HTTPS ES URL, `/etc/filebeat/secweaver-es-ca.crt`, writer username, and password.
Skip `keystore create` if a keystore exists; never replace the entire keystore with `--force`.
Follow Elastic's instructions to rotate individual values. Commands and the service must
use the same `path.data`, or credentials may be missing and events may be replayed.

Validate the candidate before replacing the service configuration:

```bash
sudo filebeat test config -c /etc/filebeat/secweaver-agent.yml -e
sudo filebeat test output -c /etc/filebeat/secweaver-agent.yml -e
```

After success, have the administrator back up `/etc/filebeat/filebeat.yml`, then enable this
configuration on the dedicated Filebeat service:

```bash
sudo install -m 0600 /etc/filebeat/secweaver-agent.yml /etc/filebeat/filebeat.yml
sudo systemctl enable --now filebeat
sudo systemctl restart filebeat
sudo journalctl -u filebeat -n 50 --no-pager
```

The default root service can read restricted Agent logs. Do not make security logs world-readable.
The processors remove Filebeat ECS host metadata before decoding Agent JSON at the root,
preserving the Agent's string `host` without an ECS `host.name` type conflict. Event `time` or
`timestamp` becomes `@timestamp`. Missing/invalid times fall back to collection time: check
timestamps and parsing errors during acceptance, not only document counts.

## 4. Verify and Register DataAsset

Keep the Agent running and wait for initial process/state snapshots. On an authorized test
host, run a harmless command such as `/usr/bin/id`. Check Filebeat and ES logs for authentication,
JSON decoding, mapping, disk-watermark, and Bulk errors. Query recent ingestion with a read-only
account; this check does not print raw commands or sensitive log documents:

```bash
python3 src/tools/secweaver-agent/elasticsearch/init_es.py --check \
  --endpoint https://es.example.com:9200 \
  --ca-file /absolute/path/es-ca.crt --username secweaver_reader
```

Any dataset in the last 30 minutes passes this connectivity check, **not full module acceptance**.
No recent data, a timed-out search, or failed shards returns nonzero. Risk and persistence
logs may legitimately be empty without events. Verify every enabled module with authorized
test events and expected records.

Next prepare configuration on the analysis computer running your intelligent agent, not on every collector.
Follow [asset directory preparation](../../../../docs_user/03-configure-data-sources.md#prepare-the-asset-directory): use `dataasset/` by default, or copy to `dataasset_my/` for isolation. CLI, UI, and AI agent must use the same root. After copying, use `export DATAASSET_ROOT=dataasset_my`; for the default, use `export DATAASSET_ROOT=dataasset`.
Save ES read-only credentials on the UI Credentials page as `vault://es/security-readonly`.
The ES wizard verifies certificates by default; configure `ca_file` for a private CA.
Do not give AI queries Filebeat writer/setup credentials.

The public [DataAsset source configuration](dataasset-source.example.json) generates the
host-execution Connector, Asset, and Template as `draft`, explicitly using `tls_verify: true`.
From the repository root:

```bash
export DATAASSET_ROOT="${DATAASSET_ROOT:-dataasset}"
cp -n src/tools/secweaver-agent/elasticsearch/dataasset-source.example.json "${DATAASSET_ROOT}/agent-es-source.json"
.venv/bin/python src/secweaver.py asset apply -f "${DATAASSET_ROOT}/agent-es-source.json" --output-dir "$DATAASSET_ROOT" --dry-run
```

Edit the local `agent-es-source.json` endpoint, actual retention, and fields first.
For a private CA, add `ca_file` under `connector.config`, relative to the selected root.
The explicit `--output-dir` overrides the example's output directory to keep writes in that root. `cp -n` preserves existing configuration.
Review the preview, then remove `--dry-run` to generate files; do not use `--force` to overwrite
existing assets. Generation does not query ES, verify credentials, or activate assets.
The query override replaces the generated `bool.must` list with a time range, removing the
generic WAF IP filter. Keep that structure when adapting the example; adding a separate
top-level query clause would be deep-merged with the old filter, not replace it.

Accept the first log using `asset-local-agent-exec`. For other types, copy a data source entry
in your local config and use distinct Asset, Connector, and Template IDs with the patterns below;
check actual fields and type filters. Choose `@timestamp` as the time field, and never register
the mixed global pattern as one asset type.

| Index pattern | Suggested asset type |
|---|---|
| `secweaver-public-agent-exec-*` | `host_exec` |
| `secweaver-public-agent-connect-*` | `host_connect` |
| `secweaver-public-agent-file-op-*` | `host_file_op` |
| `secweaver-public-agent-host-persistence-*` | `host_persistence` |
| `secweaver-public-agent-syslog-risk-json-*` | `syslog_risk_alert` |
| `secweaver-public-agent-host-process-snapshot-*` | `host_process` |
| `secweaver-public-agent-host-state-snapshot-*` | Separate assets and query filters for each `asset_type` |

Unrecognized audit events remain in `secweaver-public-agent-audit-port-execmon-*` for review.
With `dynamic: false`, unknown fields remain in `_source` but cannot be searched or aggregated.
To expand coverage, define their contracts, update mappings, and migrate/rebuild affected
indices. Adding a field name in the UI does not make an unmapped ES field searchable.

Verify field aliases, test each asset, and add validated assets to investigation bundles:

For outbound connections, set `field_aliases` from `connect_address` to `dst_ip` and
`connect_port` to `dst_port`; for system-risk events, map `host_name` to `host`. Aliases run
from source field to canonical field. Custom ES IP/port query filters must still use actual
indexed source fields; aliases do not create ES fields. Host-state asset queries also need
a `term` filter for their specific `asset_type`, such as `host_socket`, `host_identity`,
`host_service`, or `host_kernel_context`.

```bash
.venv/bin/python src/secweaver.py asset test <asset_id>
make validate
```

Use the generated ID for `<asset_id>` (`asset-local-agent-exec` for the first source), and
pass `--params` with the known test event's exact `time_start`, `time_end`, and `limit`.
Only after retrieving that event, set both Connector and Asset to `active`, add them to
the actual investigation Bundle, then run
`.venv/bin/python src/dataasset/validate.py --sync-catalog` and `make validate`.

Ask the AI to run risk identification or traceability for the test host and exact time window.
Confirm that the report cites the new records and identifies evidence gaps such as missing
WAF or Web access logs.

## Operations Boundary

- Indices use UTC event dates. Filebeat-managed templates and ILM are disabled; **ES data is
  never deleted automatically** by this integration. Configure retention, capacity alerts,
  snapshots, and restore tests before production. Sample shard counts are not capacity sizing.
- Filebeat's disk queue is bounded at 1 GB; provision additional space at its `path.data`.
  The Agent has its own disk budget. Extended outages, full queues, and rotation can still
  lose records. Retries give at-least-once delivery and may duplicate events, not exactly-once.
- Preserve the registry, Agent data, and logs on restart. For TLS/401/403 inspect CA and
  permissions; for 400 inspect mappings/raw types; for 429 inspect cluster load. Do not
  disable certificate verification to hide a problem.
- Your team owns upgrades: back up binaries/configs, stop the service, install a reviewed
  new binary while preserving identity/data, then repeat preflight and acceptance. Restore
  the previous binary on failure. This profile has no automatic upgrade or SaaS rollout service.
- Upstream references: [filestream](https://www.elastic.co/guide/en/beats/filebeat/8.19/filebeat-input-filestream.html),
  [ES output](https://www.elastic.co/guide/en/beats/filebeat/8.19/elasticsearch-output.html), and
  [index templates](https://www.elastic.co/docs/manage-data/data-store/templates).

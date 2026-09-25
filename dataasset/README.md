# SecWeaver Data Source Asset Catalog (dataasset)

**Languages:** English (this page) | [简体中文](README.zh-CN.md)

This directory holds **logical data assets** and **connector configurations** for security operations teams to edit directly.

Windows Agent 0.3.51 risk parser 0.3.1 retains complete PowerShell 4104 fragments in
`command`, makes `message` a summary and adds `script_sha256`/`script_bytes`. Read
command for script analysis rather than the former duplicate fields.ScriptBlockText.
Generic queries select all fields and required fields are unchanged. See the
[Windows record contract](../src/tools/secweaver-agent/docs/windows-installation.md).

Executable runtime and management programs live in
[`../src/dataasset/`](../src/dataasset/). Do not copy Python, shell, plugin, or
compiled program files into an asset root.

## Connect Your Data

Choose a path to query logs already stored in your ES cluster or SecWeaver SLS SaaS.
Both paths include configuration examples and a live-query acceptance procedure.

| Your data source | Start here | Configuration examples |
|---|---|---|
| Your own Elasticsearch | [ES setup and query verification](../docs_user/03-configure-data-sources.md) | [Connector](onboarding/es/connector.json), [Asset](onboarding/es/asset.json), [query template](onboarding/es/template.snippet.json) |
| SecWeaver SLS SaaS (recommended) | [SLS Proxy onboarding](../docs_user/30-sls-proxy-onboarding.md) | [Host-exec Connector](connectors/conn-sls-proxy-demo.json), [matching Asset](assets/asset-sls-proxy-host-exec-demo.json), [generic onboarding kit](onboarding/sls_proxy/) |

- **ES:** prepare the HTTPS endpoint, authorized indexes, actual time field,
  read-only credentials, and any private CA. Manual configuration and the UI wizard
  verify certificates by default; configure `ca_file` for a private CA. Adapt WAF templates to
  your actual log fields and type.
- **SLS SaaS:** obtain Proxy query AK/SK from the enterprise workspace, then
  configure the authorized Project/Logstore with `connector_type: sls_proxy`.
  The guide covers encrypted credential storage, query verification, and troubleshooting.

Follow the selected guide to edit `dataasset/` by default, or optionally use an isolated `dataasset_my/` copy, save credentials
through a [credential reference](credentials/README.md), and query a known test
event. Keep Connector/Asset status at `draft/discovery` until verified, then activate
them and add them to an investigation Bundle. CLI, UI, and AI agents must use the same selected `DATAASSET_ROOT`.

These steps configure queries. For new host-log collection, use the
[SaaS Agent guide](../docs_user/29-secweaver-data-system-quickstart.md) or the
[Agent-to-Elasticsearch guide](../src/tools/secweaver-agent/elasticsearch/README.md).

## Public-release boundary

The repository ships `dataasset/` as a sanitized example catalog; edit it directly for local use by default. Its examples use the
documentation-only address ranges `192.0.2.0/24`, `198.51.100.0/24`, and
`203.0.113.0/24`. SLS Proxy templates use only the explicitly public user-facing Project
`secweaver` and logical Logstore names such as `host-exec`, `host-sys-messages`, and
`wis-waf-access`; physical resource names are excluded. These names grant no access;
the scanner permits exact names only and still rejects prefixed or suffixed variants. Do not commit or export local customer configuration or SOPS material. Optionally copy to Git-ignored `dataasset_my/` and select it with `DATAASSET_ROOT` for isolation. Whichever directory you use, remove real environment values before publishing.
`make release-scan` rejects RFC1918 addresses and known private environment
markers in the public catalog.
Any public Connector whose `config.project` is still `YOUR_SLS_PROJECT` must
remain `draft`. Promote it to `active` only after replacing Project/Logstore,
configuring read-only credentials, and completing a live-query acceptance check.

**Platform architecture:** [docs_dev/06-secweaver-architecture-and-features.md](../docs_dev/06-secweaver-architecture-and-features.md)
Design reference: [docs_dev/09-data-asset-design.md](../docs_dev/09-data-asset-design.md)
Historical design assessment: [docs_dev/history/10-data-asset-design-evaluation.md](../docs_dev/history/10-data-asset-design-evaluation.md)
**Minimal onboarding kit for new sources:** [onboarding/](onboarding/)
**Community guide to add an asset + connector:** [docs_dev/03-community-add-asset-connector.md](../docs_dev/03-community-add-asset-connector.md)
Agent collection and Evidence spec: [docs_dev/12-agent-collection-and-evidence-spec.md](../docs_dev/12-agent-collection-and-evidence-spec.md)
**New log type onboarding:** [complete workflow](../docs_user/03-configure-data-sources.md) | [field discovery and normalization](../docs_user/20-log-format-discovery.md)
**Cross-source field correlation:** [docs_user/21-cross-source-field-correlation.md](../docs_user/21-cross-source-field-correlation.md) | [assets/correlation-matrix.json](assets/correlation-matrix.json) | [historical design assessment](../docs_dev/history/22-correlation-matrix-design-evaluation.md)
**Correlation engine:** `src/skills/_shared/data-access/correlation_engine.py` (Join matching, `join_edges`, `plan_fetch`)
**Cross-source test data:** [examples/traceability/](../examples/traceability/) (offline `evidence_bundles` at project root)
**Field reference example:** [examples/reference-assets.json](examples/reference-assets.json) (merged asset `asset-example-all-fields` with the full-platform `schema.fields` union)
**Example connectors:** [examples/connectors/](examples/connectors/) (non-production connector templates; not included in the production catalog)

**Built-in SLS Proxy catalog example:**
[`connectors/conn-sls-proxy-demo.json`](connectors/conn-sls-proxy-demo.json) +
[`assets/asset-sls-proxy-host-exec-demo.json`](assets/asset-sls-proxy-host-exec-demo.json).
Both appear in the Catalog but remain `draft/discovery` until endpoint, logstore,
and Proxy credentials are replaced and a live query succeeds.

To generate the complete hosted SLS Proxy asset set, use
[`onboarding/examples/secweaver-saas-sls-proxy-assets.json`](onboarding/examples/secweaver-saas-sls-proxy-assets.json).
It covers the current 8 public Logstores and 13 host, DNS, WEB, and WAF logical assets.
It contains no credentials, and generated entries remain `draft/discovery`. Preview it first:

```bash
python3 src/secweaver.py asset apply \
  -f dataasset/onboarding/examples/secweaver-saas-sls-proxy-assets.json \
  --dry-run
```

Remove unneeded or unauthorized sources before writing, then verify every retained asset with a live query.

Public asset IDs use the `asset-secweaver-*` namespace. A private `dataasset_my/`
overlay may keep older private filenames: the runtime resolves the public ID to
that private file for compatibility. New tests, bundles, and configuration should
always use the public ID so they also work in a clean Community checkout.

## Use SLS Proxy from dataasset

The open-source repository contains the `sls_proxy` connector, sanitized templates,
and the public asset-generation manifest. It does **not** contain the hosted SLS
Proxy server, customer catalogs, or query credentials. Obtain a Proxy endpoint,
authorized logical Logstores, and a query-only credential from your platform
administrator, or deploy a service compatible with the public client contract.

Configure actual values in local `dataasset/` by default, or optionally isolate them in `dataasset_my/`; do not commit customer configuration.
The connector only needs the following fields:

```json
{
  "connector_id": "conn-sls-proxy-example",
  "connector_type": "sls_proxy",
  "status": "draft",
  "credentials_ref": "vault://sls/sls-proxy-query",
  "config": {
    "endpoint": "https://sls-proxy.id-net.cn:30443",
    "fallback_endpoint": "https://sls-proxy.id-net.cn:30443",
    "project": "secweaver",
    "logstore": "host-exec"
  }
}
```

### User-facing endpoints and Logstores

For the hosted SLS Proxy, use these two addresses:

| Item | User-facing value |
|---|---|
| Query endpoint | `https://sls-proxy.id-net.cn:30443` |
| Enterprise Workspace | `https://sc.id-net.cn:30443/` (login, Agent Configuration, and Query logs) |
| Fallback query endpoint | No distinct default; `fallback_endpoint` is a compatibility field that repeats the primary origin |
| User-facing Project | `secweaver` |

Project and Logstore values must come from the public names shown in Enterprise Workspace. The
Proxy maps them to physical resources on the server, so a Connector must not contain physical
Project/Logstore names:

| User-facing Logstore | Purpose |
|---|---|
| `host-persistence` | Changes under cron, systemd, `authorized_keys`, sudoers, and other persistence locations for backdoor, auto-start, and privilege-escalation investigation. |
| `host-process` | Process baselines, starts, exits, and key attribute changes for anomalous-process investigation. |
| `host-state` | Baselines and changes for accounts/sessions, services/tasks, listening ports, kernel, and container context for exposure and state checks. |
| `host-exec` | Command execution, active outbound connections, and file operations separated by `event_type`, for WebShell, reverse-shell, and dangerous-command investigation. |
| `host-sys-messages` | Structured SSH, PAM, root-session, and system-risk events parsed from Linux messages/secure logs; not the complete raw system log. |
| `dns` | Internal DNS queries for suspicious-domain, suspected-C2, and host-network correlation. |
| `wis-waf-access` | TS gateway requests and upstream-access clues for Web analysis, alert validation, and tracing; an access record alone is not an attack alert. |
| `wis-waf-log` | WAF gateway-plugin alerts with rule, source-IP, and request clues; requires administrator activation of the enterprise `tenant_id` mapping, and a rule hit does not prove a successful attack. |

DNS, TS access, and WAF are usable only after server-side tenant isolation, field indexing, and
a real event query succeed. The final selectable list is the catalog shown in Enterprise
Workspace → Agent Configuration.

The default is HTTPS 30443, not 443. In these examples `fallback_endpoint` repeats
the primary origin for compatibility; this is not independent failover. Use a
separate fallback only when supplied by the operator.

`endpoint`, `fallback_endpoint`, and `logstore` are supplied by the Proxy
operator. `project` is optional for default-Project compatibility; specify it with
`logstore` to select a separately authorized resource on Go Proxy 0.6.0-rc.14/schema 10+.
Do not add `region` or `enterprise_id`: those remain server-managed for
`sls_proxy`. Store the Proxy AK/SK in the local SOPS/Vault credential referenced by
`credentials_ref`; never put credentials in connector JSON.

Validate the configuration before enabling it:

```bash
python3 src/dataasset/validate.py

# Render the fetch plan without contacting the Proxy or decrypting credentials.
python3 src/dataasset/test_connector.py \
  asset-sls-proxy-host-exec-demo --by-asset --plan \
  --params '{"host":"web-01","time_start":"2026-06-21T08:00:00+08:00","time_end":"2026-06-21T08:05:00+08:00"}'

# Run a live check only after the Proxy credential and endpoint are configured.
python3 src/dataasset/test_connector.py \
  asset-sls-proxy-host-exec-demo --by-asset \
  --params '{"host":"web-01","time_start":"2026-06-21T08:00:00+08:00","time_end":"2026-06-21T08:05:00+08:00"}'
```

The connector reuses normal SLS query templates. It probes the primary endpoint
and uses the fallback only for connectivity or temporary gateway failures;
authentication, authorization, and query-policy errors are returned directly.
Production connectors must use HTTPS. For the complete platform-side onboarding
and Proxy key lifecycle, see [SLS Proxy User Onboarding](../docs_user/30-sls-proxy-onboarding.md).

## Directory layout

```text
dataasset/
├── README.md                 # This file
├── connectors/               # L2 production connectors (config + credentials_ref; validated via catalog)
├── hosts/                    # Key host registry (host_id, hostname, zone)
├── assets/                   # L1 logical data assets + correlation-matrix.json (cross-source Join)
├── bundles/                  # Asset bundles (one-click selection)
├── credentials/              # Public credential docs/templates; generated secret files are ignored
├── query-templates/          # Parameterized query templates
├── examples/                 # Field reference and non-production example connectors (not in production catalog)
├── onboarding/               # Quickstarts that generate Connectors, Assets, and query templates
├── configure/                # Runtime config plus the canonical multi-root ownership policy
└── schema/                   # JSON Schema validation
```

## Editing workflow

**For a brand-new log format**, register the asset under `dataasset/assets/` with **`status: discovery`**, then follow [log format discovery](../docs_user/20-log-format-discovery.md).

1. In `connectors/`, fill in **non-sensitive** `config` and **only** `credentials_ref`
2. In `credentials/` under the selected asset root, maintain real AK/passwords/private keys with SOPS (see [credentials/README.md](credentials/README.md))
3. In `assets/`, register the logical asset, bind `connector_id`, and use **`status: discovery`** for new types
4. After format discovery: `discovery` → `draft` → `active`

**Validation** (recommended after editing JSON):

```bash
python3 src/dataasset/validate.py

# Static Bundle -> Asset -> Connector -> credential-file readiness; no network or decryption.
python3 src/secweaver.py validate --runtime-ready \
  --bundle bundle-incident-trace-default --json

# Rewrite catalog when it is out of sync with the directory
python3 src/dataasset/validate.py --sync-catalog

# In a development checkout, validate every local root and its ownership policy.
make validate-all-roots

# Single-connector dry-run
python3 src/dataasset/test_connector.py asset-cmdb-hosts --by-asset \
  --params '{"limit":10}' --dry-run

# Multi-connector aggregation: inspect fetch plan (Vault not decrypted)
python3 src/dataasset/test_connector.py asset-ssh-internal --by-asset --plan \
  --params '{"attacker_ip":"203.0.113.10","host":"web-01","time_start":"2026-06-21T08:00:00+08:00","time_end":"2026-06-21T20:00:00+08:00"}'

# Test only one connector inside an aggregated asset
python3 src/dataasset/test_connector.py asset-ssh-internal --by-asset \
  --connector conn-ssh-web-01-auth \
  --params '{"attacker_ip":"203.0.113.10"}' --dry-run
```

`--runtime-ready` derives execution readiness from local configuration only. A
successful result does not prove that an endpoint is reachable or contains data.
It folds base validation errors from dependency objects into Bundle blockers and
reports `registry_valid`, per-Bundle `status`, and final `ready_for_execution`;
run the `dataasset-connectivity-check` Skill after this gate. Multi-root ownership
is declared in `configure/shared-contracts.json`: `shared` files must be
byte-identical, `override` files may differ for a documented reason, and
`root_owned` files belong to one environment.

Preview shared drift with `python3 src/dataasset/sync_shared_contracts.py --check`
and use `--write` only after review. The command does not process credentials or
environment-owned inventory.

Asset, Bundle, Host, and Network schemas reject unknown top-level fields. Host
`interfaces`, `nat`, `exposure`, and object-form `exposed_ports` also reject
unknown fields. Put a
deployment- or vendor-specific value under `extensions`; add commonly useful
fields to the canonical schema instead.

`schema/data-connector.schema.json` is the single contract for Connector required
fields and conditional combinations; the catalog owns runtime, dependency, and
onboarding UI metadata. Validation rejects catalog profiles that omit schema-required
fields or declare fields unsupported by onboarding or Connector Schema; CLI also validates
the final merged Connector before writing. ES, HTTP API, Splunk, and remote
external executors require their final HTTPS URL and reject redirects; loopback
development may use HTTP. Private CAs use `ca_file`.
`credentials/credential-status.json` accepts only `active` and `disabled`.

Production Skills fetch only when both Asset and Connector are `active`.
Onboarding test/discovery/promotion commands may query `draft/discovery`; a
`disabled` Asset or Connector is never queried. Connector catalogs require
`format_version: "2.0"`; see [runtime configuration](configure/README.md) for the
preview-first migration command.

## Multi-connector aggregation (`connector_ids`)

A single logical asset can pull data from **multiple hosts / logstores / mixed SLS+SSH** sources and merge them into one `asset_type` evidence stream.

| Field | Description |
|---|---|
| `connector_id` | Primary connector (required; backward compatible; shown by completeness Skill) |
| `connector_ids` | Additional data sources; merged and deduplicated with `connector_id`, then fetched in order |
| `aggregate.max_events` | Upper bound on events after merge and deduplication |
| `aggregate.dedupe_by` | Deduplication keys, e.g. `timestamp,host,src_ip,user,result` |

**Per-logstore host labeling:** set `config.hostname` on the connector (e.g. `web-01`). When investigation params include `host`, only matching connectors plus global SLS sources without a hostname label are fetched.

Example: [`assets/asset-ssh-internal.json`](assets/asset-ssh-internal.json):

```json
{
  "connector_id": "conn-sls-ssh-auth-internal",
  "connector_ids": [
    "conn-sls-ssh-auth-internal",
    "conn-sls-ssh-auth-web-01",
    "conn-sls-ssh-auth-db-01",
    "conn-ssh-web-01-auth"
  ],
  "aggregate": {
    "max_events": 5000,
    "dedupe_by": ["timestamp", "host", "src_ip", "user", "result"]
  },
  "query_template_ids": [
    "ssh_auth_by_src_ip_time",
    "ssh_auth_by_host_time",
    "ssh_file_grep_auth"
  ]
}
```

`query_template_ids` must include **at least one template per `connector_type`** in the aggregation (e.g. SLS uses `ssh_auth_by_src_ip_time`, `ssh_file` uses `ssh_file_grep_auth`, `local_file` uses `local_file_grep_auth`). `validate.py` checks that every connector matches at least one template.

**Host coverage:** assets no longer use host-binding fields. `coverage.hosts` contains only log-source IPs. For single-host collection targets, use `config.host_id` on the corresponding connector.

Detailed design: [docs_dev/09-data-asset-design.md](../docs_dev/09-data-asset-design.md) · [historical object-model assessment](../docs_dev/history/11-data-object-model-evaluation.md)
Template selection rules: [query-templates/README.md](query-templates/README.md)

## Credential rules (important)

| Allowed | Forbidden |
|---|---|
| `"credentials_ref": "vault://sls/security-readonly"` and similar refs | Plaintext AccessKey, password, or private key |
| `endpoint`, `project`, `host` in `connectors` | Secrets in connector JSON |
| Placeholder templates in `credentials/examples/` | `credentials/secrets/` (local SOPS; not in Git) |
| Platform runtime decrypts from local Vault and injects | Writing secrets into AI chats or Skill files |

First choose a root using [source configuration](../docs_user/03-configure-data-sources.md): use `export DATAASSET_ROOT=dataasset` by default, or `export DATAASSET_ROOT=dataasset_my` for isolation. Keep UI, CLI, and AI agent consistent.
Prefer the local UI for credential initialization/editing. The command-line alternative
requires Bash 4+, SOPS, and age:

```bash
source .venv/bin/activate
# Only initialize a new local Vault; preserve existing keys and policy.
bash src/dataasset/credentials/sops-vault.sh init
bash src/dataasset/credentials/sops-vault.sh edit vault://sls/security-readonly
```

Configure only the credentials you use; do not `bootstrap` all public placeholder templates.

## How LLMs / Agents use this

1. The user selects assets from `assets/` or bundles from `bundles/`
2. The AI passes only: `asset_id`, `template_id`, `params` (and optionally `credentials_ref`)
3. The platform resolves `credentials_ref` from SOPS; **the AI never sees** secrets
4. Query results go through fetch → normalizer; multi-connector assets are deduplicated and merged into `evidence_bundles`

## Assets and Skills (decoupled)

- **DataAsset** describes data only: `asset_type`, schema, coverage
- **Skills** declare required data via `asset_type` + scenarios S1–S8
- **Do not bind Skill names inside asset JSON**

| asset_type | Typical file | Common investigation scenarios |
|---|---|---|
| waf_alert | assets/asset-waf-prod-01.json | S1/S2/S4 |
| web_access_log | assets/asset-web-access-prod.json | S1/S2/S4 |
| host_exec / connect / file_op / persistence | assets/asset-secweaver-host-exec.json, etc. | S2/S5 |
| windows_event_log | assets/asset-windows-event-prod.json | S3/S5/S6 (Windows hosts) |
| linux_syslog | assets/asset-linux-syslog-prod.json | S3/S5/S6 (Linux hosts) |
| ssh_auth | assets/asset-ssh-internal.json (**multi-source** SLS+logstore+SSH) / asset-ssh-web-01-file.json (single SSH, draft) | S1/S3/S6 |
| asset_inventory | assets/asset-cmdb-hosts.json (MySQL) / asset-pg-cmdb-hosts.json (PostgreSQL) | S1/S3 |
| db_audit | assets/asset-mysql-db-audit.json (MySQL example) | D7 database audit |
| ssh_auth (MySQL) | assets/asset-mysql-ssh-auth.json | S1/S3/S6 example |
| waf_alert (ES) | assets/asset-es-waf-prod.json | S1/S2/S4 example |
| web_access_log (ES) | assets/asset-es-web-access-prod.json | S1/S2/S4 example |
| firewall_log | assets/asset-fw-dmz-internal.json | S1/S3 |
| network_traffic_audit | assets/asset-network-nta-prod.json | S1/S3/S7 |

## Asset bundles

| Bundle ID | Scenarios | Description |
|---|---|---|
| bundle-alert-confirm-min | S4 | WEB alert confirmation |
| bundle-incident-trace-default | S1, S3 | External IP traceability |

## Status field

| status | Meaning |
|---|---|
| `discovery` | **Format discovery queue**; handled only by log-format-discovery Skill; not selectable |
| `draft` | Mapping complete, still being edited; not selectable |
| `active` | Published; selectable |
| `disabled` | Disabled |

Text log parsing: configure **`text_parser`** on the asset (built-ins in `configure/text-log-parsers.json`; custom parsers in `parsers/`). **Operators do not edit Python.**

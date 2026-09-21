# SecWeaver Data Foundation Deployment Modes

**Languages:** English (this page) | [简体中文](36-data-foundation-deployment-modes.zh-CN.md)

Choose one primary governed data foundation before onboarding Connectors, DataAssets, and Skills.

SaaS SLS Proxy is the recommended Community path. Existing ES users can use the
public integration below. The first two modes use an operator-managed data
foundation. Community provides the data integration contract but does not include
installation or operations tooling for those foundations; users can connect
SecWeaver to a compatible ES/OpenSearch service they prepare.

| Mode | Data location | Operator | Customer installation | Use case | Included in Community |
|---|---|---|---|---|---|
| Portable laptop ES-compatible | Operator laptop | Deployment operator | Agent + Filebeat on hosts | Response, exercises, isolated networks | Client integration included; foundation installation and operations are operator-managed |
| Linux server ES-compatible | Customer Linux server | Customer operations/deployment operator | Compatible foundation plus host collectors | Long-running private deployment | Client integration included; foundation installation and operations are operator-managed |
| Customer-managed ES/OpenSearch | Existing customer cluster | Customer platform team | No new ES; read-only SecWeaver access | Reuse existing logs | Client integration included; bring your own ES/OpenSearch |
| Data Cloud managed SLS | SecWeaver Data Cloud | SecWeaver platform team | Agent/Logtail only when needed | Fast onboarding and ongoing governance | Proxy client and Agent included; managed service/account provisioned separately |

Choose the portable mode for short-lived field work or isolated networks, the Linux server mode for a long-running private foundation, customer-managed ES/OpenSearch when a mature cluster already exists, and managed SLS when minimizing setup and ongoing data governance work is the main requirement. Mixed deployments are possible, but each project should name one primary query foundation.

## Portable laptop

This mode places the governed foundation, UI, and investigation Skills on an
operator laptop while business hosts run only the Agent and an approved shipper.
Community can connect to a compatible query service that has already been
prepared. The operator owns foundation installation, offline buffering,
capacity, and recovery procedures and must validate them before use.

## Linux server

This mode runs a compatible ES/OpenSearch service and authenticated HTTPS Query
Gateway on a customer Linux server. Community connects through public Connectors.
Customer operations or its deployment operator owns server installation, TLS,
capacity, backup, rollback, and upgrades.

Capacity planning, disk protection thresholds, JVM/shard tuning, load testing,
backup, and rollback depend on the environment. Community documentation defines
the integration and acceptance boundary rather than a universal foundation
installer. The operator must design and exercise these controls for the actual
volume, retention period, and availability requirements.

## Customer-managed ES/OpenSearch

Do not deploy another ES. First follow [data source configuration](03-configure-data-sources.md) to initialize Python and prepare query credentials. Edit `dataasset/` by default, or optionally copy it to `dataasset_my/` and set `DATAASSET_ROOT` for isolation. Then start the UI from the repository root and use **Connect customer-managed Elasticsearch** to probe the HTTPS cluster, discover an index, inspect fields, and generate the DataAsset configuration.

```bash
DATAASSET_UI_PORT=8765 make ui
```

The UI occupies the terminal. Stop it with Ctrl+C before running acceptance commands, or open another terminal and set the selected `DATAASSET_ROOT` again. CLI, UI, and agent queries must use the same selected asset directory. Follow [query acceptance and activation](03-configure-data-sources.md#query-acceptance-and-activation) with the actual asset, target, and time window. Confirm a known event and its fields; generated configuration or empty results do not pass acceptance.

This onboards existing data; the wizard does not modify the cluster or deploy collectors.
For new events, use the public initialization script, Agent installer, Filebeat configuration,
and acceptance steps in [Agent ingestion into your ES](../src/tools/secweaver-agent/elasticsearch/README.md).
That example targets Linux + ES 8.x without Operator; OpenSearch needs a compatible shipper selected separately.

## Data Cloud managed SLS

SLS storage, field governance, and SLS Proxy are managed by Data Cloud. Users do not receive
production SLS RAM keys. Install Agent/Logtail only when host data is required; Web/gateway alerts
and gateway access logs can be onboarded directly.

Distinguish managed and self-hosted operation. In managed Data Cloud mode, the
SecWeaver platform team owns the control plane, upstream SLS permissions,
Projects/Logstores, tenant-isolation indexes, collection rules, machine groups,
DNS, TLS, and service releases. A customer host only runs the Agent command
generated in Enterprise Workspace. An enterprise that operates a compatible
Proxy itself assigns those server-side configuration and operations duties to
its platform administrator; it is not a zero-configuration deployment.

Data Cloud issues the tenant-specific Agent command after the managed service is
ready and controls the endpoint, credentials, TLS, and release metadata.
Community covers the public Agent, Proxy client contract, and onboarding
templates. It does not include server installation or managed operations; a
self-hosting platform administrator must define deployment, certificate, and
operations procedures for the compatible service.

## Acceptance

Every mode must prove a real event, a read-only time-window query, correct fields and aliases,
retention/credential/backup ownership, and one successful Skill investigation.

```bash
.venv/bin/python src/secweaver.py validate
```

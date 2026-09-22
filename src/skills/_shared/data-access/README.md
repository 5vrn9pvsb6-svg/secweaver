# Data Access Layer (dataasset + SOPS Vault)

**Languages:** English (this page) | [简体中文](README.zh-CN.md)

Skill scripts support built-in `--from-bundle` to auto-load assets, decrypt Vault, and fetch evidence.

This directory owns registry reads, evidence fetching and normalization, not
Skill assessment. Scenario planning and bounded evidence expansion live in
`scenario_fetch.py`. Input adaptation and cross-Skill execution live in
[`../skill_runtime/`](../skill_runtime/README.md). The old `skill_input.py`,
`prepare.py` and `run_pipeline.py` paths remain compatibility entries, so the
commands below do not change. `--from-bundle` is a Skill-script flag; the
preparation wrapper uses `--bundle ID` instead.

SLS and SLS Proxy HTTPS queries now verify certificates by default. `tls_verify`
must be a boolean; live Connectors require `true`, while dedicated probe APIs retain
an explicit `false` diagnostic parameter. Use `ca_file` for a private PEM CA (absolute path or relative to `DATAASSET_ROOT`); it cannot be
combined with verification disabled. Proxy probes and SDK queries share this policy,
and certificate failures do not trigger endpoint fallback. See the
[SLS Proxy onboarding guide](../../../../docs_user/30-sls-proxy-onboarding.md).
The shared TLS helper defers annotation evaluation so direct compatibility imports do
not fail during module loading; the repository's supported runtime remains Python 3.10+.

ES, HTTP API, Splunk, and external HTTP executors share a strict transport policy:
remote endpoints require HTTPS, plain HTTP is limited to explicit loopback addresses,
and requests never follow redirects that could forward an authentication header or
downgrade transport. HTTPS uses the system trust store by default and accepts `ca_file`
for a private CA. Live fetch requires ES/HTTP API `tls_verify` and Splunk `verify_tls`
to remain `true`.
Resolved relative CA paths and symlinks must remain inside `DATAASSET_ROOT`;
administrator-managed system CA files may use absolute paths.

## One-shot commands

```bash
# Completeness analysis (from default bundle)
python3 src/skills/data-source-completeness/scripts/check.py \
  --from-bundle \
  --params '{"attacker_ip":"203.0.113.10","time_start":"2026-06-21T08:00:00+08:00","time_end":"2026-06-21T20:00:00+08:00","host":"web-01"}'

# Traceability (built-in completeness precheck + Vault live fetch: SLS / SSH)
python3 src/skills/traceability-analysis/scripts/correlate.py \
  --from-bundle --bundle bundle-incident-trace-default \
  --params '{"attacker_ip":"203.0.113.10","time_start":"...","time_end":"...","host":"web-01"}' \
  --fetch

# Alert confirmation
python3 src/skills/alert-confirmation/scripts/confirm.py \
  --from-bundle --bundle bundle-alert-confirm-min \
  --params '{"attacker_ip":"203.0.113.10","time_start":"...","time_end":"...","host":"web-01","primary_alerts":[...]}' \
  --fetch

# Pipeline (completeness → traceability / alert)
python3 src/skills/_shared/data-access/run_pipeline.py trace-chain \
  --params '{"attacker_ip":"203.0.113.10","time_start":"...","time_end":"...","host":"web-01"}' \
  --fetch --pretty
```

## Shared parameters

| Parameter | Description |
|---|---|
| `--from-bundle` | Load from `dataasset/bundles` (replaces `-i` / stdin) |
| `--bundle ID` | Bundle ID (each Skill has a default if omitted) |
| `--params JSON` | Investigation params (`attacker_ip` auto-maps to `src_ip`) |
| `--params-file` | Params JSON file |
| `--fetch` | SOPS decrypt and live fetch (SLS / SSH / local file / DB / HTTP / ES, via normalizer) |
| `--dry-run` | Build requests without decrypting Vault |
| `--skip-completeness` | Skip built-in completeness precheck for traceability / alert |

`-i input.json` or piped JSON still supported (offline / sample mode).

## Execution lifecycle boundary

`fetch()` defaults to production Skill mode. Both the Asset and Connector must
be `active`; `draft` and `discovery` are rejected before template rendering or
credential resolution. Connector tests, format discovery, connectivity checks,
and draft promotion explicitly use `onboarding_test`, which permits
`draft/discovery` while proving a source. `disabled` is an unconditional kill
switch in every mode.

## Field inventory and completeness

Fetch reports separate registry metadata from observed evidence. In an attached
`completeness_precheck`, `assessment_basis=registry_metadata` and `metadata_readiness`
describe the existing static assessment; legacy verdict/confidence/block fields are
preserved for compatibility. They do not establish that today's evidence exists.
`fetch_summary.evidence_readiness` (also attached to the precheck) reports
`no_evidence`, `partial`, `evidence_observed`, or `not_evaluated` for an empty dry run/plan.
It lists missing P0 evidence types from evaluated requirements. `evidence_observed`
only means events were returned without an observed requirement/query gap, not
complete detector coverage. During live fetch, declared assets with no recorded
attempt become `query_integrity` gaps with reason `not_queried`; successful empty
queries remain distinct from failures. Validate with the data-access test suite.

`fetch_summary.analysis_constraints` converts these observations into one common
consumer boundary. Positive findings may use returned events, while a negative
conclusion is allowed only for live evidence with observed events and no known
query gap. Plan/dry-run, failed, partial, truncated, unqueried, and successful
empty-query states set `absence_is_not_evidence=true`. The reported confidence
ceiling is advisory; each Skill remains responsible for domain-specific scoring.

`schema.fields` keeps source-side field names; global `evidence-minimum-fields.field_aliases` and `asset.field_aliases` map source fields to canonical fields; query param mapping is handled by join-level `fetch_plan.param_map` and `query-templates`. Shared `field_inventory.py` provides:

| API | Description |
|---|---|
| `raw_fields(asset)` | Source field set from `schema.fields` or registered asset `fields` |
| `canonical_fields(asset)` | Standard fields reachable via global/asset aliases and `time_field` |
| `effective_fields(asset)` | `raw_fields ∪ canonical_fields` for Skill semantic checks |
| `check_required_fields(asset, required)` | Field completeness check; returns satisfaction and missing fields |

Completeness Skill, registry, and any Skill that must judge whether an asset supports an investigation field should reuse this module — checking only `fields` alone causes false negatives.

## Modules

| File | Role |
|---|---|
| `scenario_fetch.py` | Scenario fetch plans and bounded evidence expansion; never imports or invokes concrete Skill Python code |
| `trace_time_window.py` | Trace timestamp parsing, attacker-window narrowing, and evidence-window filtering with bounded fallback behavior |
| `skill_input.py` | Compatibility alias of `skill_runtime.inputs`; no duplicated input logic |
| `prepare.py` | Compatibility CLI entry of `skill_runtime.prepare`; `--bundle ID`, optional `--run-skill` |
| `registry.py` | Read dataasset |
| `vault.py` | SOPS decrypt `credentials_ref` |
| `fetch.py` | Live evidence fetch orchestration and post-fetch normalization; no connector-specific branch growth |
| `connector_fetch_dispatch.py` | Unified connector fetch strategy registry; built-in connector strategies are registered here |
| `aggregate.py` | Multi-connector aggregation, host filter, dedup |
| `normalizer.py` | evidence_id, timestamp, **time_correction**, aliases, masking |
| `field_inventory.py` | Shared field inventory and completeness: raw / canonical / effective |
| `field_resolver.py` | correlation-matrix field reads (join fields + variants + alias candidates) |
| `correlation_keys.py` | Derive correlation keys from matrix + effective fields; consumed by `asset_to_registered` / completeness Skill |
| `correlation_engine.py` | Matrix-driven join matching, time windows, fetch orchestration; `fill_investigation_window` / `resolve_anchor_params` fill investigation windows by anchor |
| `sls_fetch.py` | Aliyun SLS live fetch |
| `db_fetch.py` | Dispatcher for `database_ro`; engine validation and row filtering |
| `db_common.py` | Shared SQL safety, bind params, default ports, credential matching |
| `mysql_fetch.py` | MySQL / MariaDB database_ro |
| `postgresql_fetch.py` | PostgreSQL database_ro |
| `oracle_fetch.py` | Oracle / PLSQL database_ro |
| `sqlserver_fetch.py` | SQL Server / MSSQL database_ro |
| `sqlite_fetch.py` | SQLite database_ro |
| `mongodb_fetch.py` | MongoDB document query connector |
| `redis_fetch.py` | Redis read-only command connector |
| `http_fetch.py` | http_api REST |
| `es_fetch.py` | Elasticsearch `_search` |
| `ssh_fetch.py` | SSH log read |
| `local_file_fetch.py` | Local file log read (no shell / no Vault) |
| `connector_registry.py` | Merges built-in, external-config, and plugin connector types; supports cache refresh |
| `connector_catalog.py` | Product-facing connector capability/source/dependency catalog for CLI/UI |
| `extended_fetch.py` | Dispatcher for extension connector types; no vendor-specific fetch logic |
| `connector_fetch_common.py` | Shared HTTP, local sample, time range, and external-executor helpers |
| `*_fetch.py` | One connector per file, for example `aws_cloudwatch_fetch.py`, `azure_monitor_fetch.py`, `splunk_fetch.py` |
| `template_select.py` | Select templates by asset.query_template_ids |
| `run_pipeline.py` | Compatibility CLI entry of `skill_runtime.pipeline` |
| `tests/test_ssh_fetch.py` | SSH command validation and log parse unit tests |
| `tests/test_local_file_fetch.py` | Local file grep/tail unit tests |

Connector extension rules:

- `fetch.py` only orchestrates: load asset/connector, render templates, resolve credentials, call the dispatcher, and normalize events.
- For a new built-in live connector, add a dedicated `*_fetch.py`, then register it in `connector_fetch_dispatch.py` or `extended_fetch.py`.
- Do not keep adding `if/elif connector_type` branches to `fetch.py`; keep the pipeline stable so contributors only need to read their fetch file and the registry.
- Config-only external connectors and plugin connectors are still discovered through `connector_registry.py`; the UI can refresh runtime metadata with `/api/onboarding/meta?refresh=1` or `/api/connectors/reload`.
- Template compatibility reads the current connector registry on every selection, so a successful cache refresh updates query-key selection without a process restart.
- Plugin contract rules belong to `src/dataasset/plugin_contract.py`, not CLI or executor copies. See [Connector Plugins](../../../../docs_dev/04-connector-plugins.md).
- Do not import Skill assessment code or `skill_runtime` here. New input/precheck adapters and multi-Skill workflows belong to `../skill_runtime/`; only the three historical compatibility entries may forward to it.

This keeps vendor SDKs, auth signing, and response parsing isolated for community contributors.

## Local file (local_file)

When an asset binds `connector_type: local_file`, `--fetch` reads local logs on the Claw host (Python regex filter, **no shell**, **no Vault**):

```bash
python3 src/dataasset/test_connector.py asset-local-lab-auth --by-asset \
  --params '{"attacker_ip":"203.0.113.10","host":"web-01"}' --fetch
```

`base_path` may be relative (to repo root); `log_path` and `grep_pattern` completion rules match `ssh_file`. Samples: `dataasset/samples/local-logs/`.

## SSH log read (ssh_file)

When an asset binds `connector_type: ssh_file`, `--fetch` runs template-rendered `grep | tail` via paramiko:

```bash
# dry-run: show rendered command only, no Vault decrypt
python3 src/dataasset/test_connector.py asset-ssh-web-01-file --by-asset \
  --params '{"attacker_ip":"203.0.113.10"}' --dry-run

# live (requires vault://ssh/readonly-web-01 and reachable host)
python3 src/dataasset/test_connector.py asset-ssh-web-01-file --by-asset \
  --params '{"attacker_ip":"203.0.113.10"}'
```

`attacker_ip` auto-maps to `grep_pattern`; `log_path` filled from connector `log_paths`. Supports `bastion_id` jump host.

## Dependencies

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-data-access.txt
DATAASSET_ROOT=dataasset src/dataasset/credentials/sops-vault.sh edit vault://sls/security-readonly

# Test SSH connector (requires real host and Vault credentials)
python3 src/dataasset/test_connector.py asset-ssh-web-01-file --by-asset \
  --params '{"attacker_ip":"203.0.113.10"}'
```

Credential rule: Skill output and LLM never contain plaintext secrets; decrypt only inside `vault.py` / `fetch.py` / `ssh_fetch.py`.
On plugin failure, runtime discards stdout and includes only a bounded stderr
excerpt after recursively redacting credential values. If a credential value is
too short to redact safely, stderr is omitted.

## New log type onboarding

Before registering a new asset, if fields are unmapped or format unknown, run [日志格式发现](../../../../docs_user/20-log-format-discovery.md) first: `discover.py` preprocess + **LLM** field mapping → then update `evidence-minimum-fields.json` / `normalizer.py` / dataasset. See [日志格式发现设计.md](../../../../docs_dev/20-log-format-discovery-design.md).

## Real data and release boundaries

ES verifies certificates by default and supports private CAs. Incomplete queries appear
in fetch summaries and reports. Native audit/event identities now use v3; other generated IDs retain v2. Sensitive source-log
fields still require explicit masking. See [release, compatibility, migration and masking guidance](../../../../docs_user/community-release-and-data-safety.md).

SLS and SLS Proxy retain SDK time as `_sls_timestamp`; valid `schema.time_field`
takes priority for `timestamp`, followed by timestamp/time aliases and transport
fallbacks. Upload time must not move historical events into the analysis window.
`truncated_asset_types` uses explicit per-query flags when available; merged
window/page totals are not compared against one page's limit. Legacy payloads
without flags retain the limit heuristic. Successful observed queries clear only
the derived `query_results_incomplete` precheck gap; unknown/failed/partial or
unqueried data never becomes a completeness guarantee.

---
name: dataasset-connectivity-check
description: >-
  Checks SecWeaver active data assets for real connectivity and usability. Use
  when the user asks to 探测/检查 active 资产连接性, test connectors, check whether
  dataasset assets can fetch data, verify SLS/SSH/ES/database/API connectors,
  or distinguish config validation from live fetch availability.
---

# Active Data Asset Connectivity Check

Answers: are current `active` data assets really connectable, fetchable, and usable by Skills?

This Skill supplements `src/dataasset/validate.py`:

- `validate.py`: static config, schema, references, matrix field contracts.
- This Skill: real credential resolution, connector connectivity, query template rendering, live fetch, usable evidence.

## Required prerequisite

From repo root, prefer the virtual environment:

```bash
.venv/bin/python src/dataasset/validate.py --json --strict --only-active
```

If the user only wants a quick connectivity check, you may still run the patrol even when validate has existing warnings; note those as static gate issues in the report.

## Patrol script

Main script:

```bash
.venv/bin/python src/skills/dataasset-connectivity-check/scripts/check.py
```

Common modes:

```bash
# Quick patrol: active assets, last 5 minutes, limit=1
.venv/bin/python src/skills/dataasset-connectivity-check/scripts/check.py --format markdown

# Standard patrol: last 24 hours — better for data volume
.venv/bin/python src/skills/dataasset-connectivity-check/scripts/check.py --window-minutes 1440 --limit 10 --format markdown

# Single-asset patrol
.venv/bin/python src/skills/dataasset-connectivity-check/scripts/check.py --asset-id asset-waf-prod-01 --window-minutes 60

# Config/credential/template only, no live fetch
.venv/bin/python src/skills/dataasset-connectivity-check/scripts/check.py --dry-run

# When active asset references draft connector, skipped by default; force probe:
.venv/bin/python src/skills/dataasset-connectivity-check/scripts/check.py --include-draft-connectors
```

For host-oriented templates, the patrol automatically uses the first valid
`asset.coverage.hosts` entry. Pass `--host` or `--host-name` to override it.
Each result exposes `probe_host` and `probe_host_source`; assets without declared
host coverage no longer receive a synthetic `web-01` filter.

## Status semantics

| Status | Meaning | Usable by Skills? |
|---|---|---|
| `OK_CONNECTED_WITH_DATA` | Connected and data returned | Candidate evidence; scenario coverage is not assessed |
| `OK_CONNECTED_NO_DATA` | Connect and template OK; no data in probe window | No evidence in this window; widen or correct scope |
| `FAILED_CONFIG` | Config error: placeholder, missing connector | No |
| `FAILED_CREDENTIAL` | Vault/SOPS/credential format/key parse failure | No |
| `FAILED_CONNECTOR` | Connector unreachable: ProjectNotExist, SSH banner, etc. | No |
| `FAILED_TEMPLATE` | Connector OK but template syntax or query execution failed | No |
| `FAILED_SCHEMA` | Returned data cannot normalize or fails schema | No |
| `FAILED_TEMPLATE_NO_MATCH` | No matching template | No |
| `SKIPPED_DRAFT_CONNECTOR` | Active asset references draft connector; not probed by default | No |

## Report requirements

Read connectivity, data presence, and scenario readiness separately. Live success sets
`connectable=true` and `has_data` from the returned events. `usable_for_requested_skill`
is `false` for an empty response and `null` when evidence exists but scenario coverage
has not been assessed. Dry runs leave all three as `null`. A failure leaves connectivity
unproven. The legacy `usable_for_skill` now means only that candidate events were
returned, not that a Skill has sufficient evidence. Summary fields
`connected_assets_total` and `assets_with_data_total` separate connection from data;
`skill_readiness=not_evaluated`. Empty successful queries are not failed connections.

Deliver an operations-ready report:

1. Overview: active asset count, connector paths, connected assets, assets with data, failed assets, and unassessed scenario coverage.
2. Detail: per asset/connector status, target, failure reason.
3. Layered attribution:
   - Config: placeholder, draft connector, missing connector.
   - Credentials: Vault parse failure, private key parse failure, type mismatch.
   - Connectivity: SLS ProjectNotExist, LogStoreNotExist, SSH banner, timeout.
   - Template: ParameterInvalid, parse_datetime, syntax errors.
   - Data: connected but no data in window.
4. Minimal fix suggestions; do not auto-edit files unless the user explicitly asks.

## Security requirements

- Never print decrypted secrets to the user.
- May output `credentials_ref`; do not output `access_key_secret`, SSH private key, password, token.
- Default small window and low limit for SLS/ES/DB/API to avoid heavy queries.
- SSH only via existing connector constraints — safe grep/tail.

## Recommended judgments

- `OK_CONNECTED_NO_DATA` is not failure; widen window if user asks “is there data?”
- Active asset referencing draft connector is an operational risk — report it.
- Live fetch fails but connector ping succeeds → attribute to template first.
- Connector config with `YOUR_*` or `REPLACE_ME` → `FAILED_CONFIG` without live fetch.

## Typical next steps

- `FAILED_CONFIG`: fix connector JSON; replace placeholders with real project/logstore/host.
- `FAILED_TEMPLATE`: fix `dataasset/query-templates/templates.json`.
- `FAILED_CREDENTIAL`: `src/dataasset/credentials/sops-vault.sh get <ref>` redacted verify, then edit Vault.
- `FAILED_CONNECTOR`: check cloud service, network, security group, SSH service, endpoint.
- `OK_CONNECTED_NO_DATA`: rerun with `--window-minutes 1440` or business params.

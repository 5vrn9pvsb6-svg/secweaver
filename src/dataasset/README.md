# DataAsset Runtime Tooling

This directory owns executable code for DataAsset registries. Asset roots such
as `dataasset/` and an operator-owned `dataasset_my/` contain configuration,
schemas, documentation, and sample data only.

| Program | Responsibility |
|---|---|
| `validate.py` | Validate registry structure, schemas, references, and the config-only boundary |
| `validate_roots.py` | Validate every checked-in DataAsset root and detect shared contract drift |
| `sync_shared_contracts.py` | Preview or synchronize public-root shared contracts without touching credentials or environment inventory |
| `config_migration.py` | Preview or atomically write connector catalog format migrations |
| `catalog_sync.py` | Build and compare `catalog.json` |
| `test_connector.py` | Render plans and test connector fetches |
| `promote_after_connectivity.py` | Promote validated draft assets |
| `build_field_reference.py` | Generate the field-reference example |
| `credentials/` | Resolve and manage SOPS-backed `vault://` credentials |
| `plugins/connectors/` | Bundled connector plugin code and contract examples |
| `plugin_contract.py` | Shared manifest, path, timeout and stdio-json response contract for plugin discovery, CLI checks and runtime execution; no Skill/vendor dependencies |
| `validate_lib/connector_contracts.py` | Cross-file connector ownership, onboarding skeleton, and UI profile invariants |
| `validate_lib/inventory_contracts.py` | Host/network CIDR, reference, and exposure semantics |
| `validate_lib/runtime_readiness.py` | Static Bundle-to-credential execution readiness without secret decryption or network access |

Select a registry without copying code into it:

```bash
DATAASSET_ROOT=dataasset_my python3 src/secweaver.py validate --json
DATAASSET_ROOT=dataasset_my python3 src/secweaver.py validate --runtime-ready --bundle <bundle_id> --json
DATAASSET_ROOT=dataasset_my python3 src/dataasset/test_connector.py <asset_id> --by-asset --plan
DATAASSET_ROOT=dataasset_my src/dataasset/credentials/sops-vault.sh list

# Validate public and local overlay roots together.
.venv/bin/python src/dataasset/validate_roots.py --strict

# Check shared drift first; use --write only after reviewing the plan.
.venv/bin/python src/dataasset/sync_shared_contracts.py --check
.venv/bin/python src/dataasset/sync_shared_contracts.py --write

# Preview first; add --write only after reviewing the JSON plan.
python3 src/secweaver.py dataasset migrate --root dataasset_my --json
```

Connector plugin code has a separate root. The bundled examples live here; an
operator-owned plugin directory can be selected independently:

```bash
SECWEAVER_PLUGIN_ROOT=/opt/secweaver/connectors python3 src/secweaver.py connector catalog --json
```

`src/dataasset/validate.py` rejects Python, shell, JavaScript, compiled programs,
and executable files found under the selected DataAsset root.
`validate(dataasset_root)` derives Schema and credential paths from that call and
does not rewrite the module-level `DATAASSET_ROOT`; runtime modules in the same
process keep the root resolved at startup.
Connector catalogs use format version `2.0`; unsupported formats fail closed and
must be migrated before runtime loading. `validate_roots.py` enforces the
`dataasset/configure/shared-contracts.json` ownership classes and byte-compares
only `shared` files. `override` and `root_owned` files require explicit policy
classification; credential files are outside the comparison scope.
Connector structure and required combinations have one validation contract in
the shared `schema/data-connector.schema.json`; the catalog owns runtime,
dependency, and onboarding UI metadata. Credential status accepts only `active`
or `disabled`; validation, Studio, and runtime reject unknown states.

## Real data and release boundaries

ES verifies certificates by default and supports private CAs. Incomplete queries appear
in fetch summaries and reports. Generated evidence IDs now use v2; sensitive source-log
fields still require explicit masking. See [release, compatibility, migration and masking guidance](../../docs_user/community-release-and-data-safety.md).

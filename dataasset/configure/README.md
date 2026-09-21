# Platform runtime configuration (`configure`)

JSON configs that **operators may edit** and that **runtime code loads directly** (not JSON Schema validation files).

| File | Role |
|------|------|
| [evidence-minimum-fields.json](evidence-minimum-fields.json) | Minimum evidence fields per `asset_type`, global `field_aliases` |
| [connector-catalog.json](connector-catalog.json) | Single source for built-ins: query key, runtime, dependency strategy, onboarding template, and UI profile |
| [external-connectors.json](external-connectors.json) | Single source for config-only external connector types |
| [ip-intel.json](ip-intel.json) | Attacker IP online enrichment providers; `auto` tries VirusTotal when configured, then ipwho.is, then legacy ip-api.com |
| [text-log-parsers.json](text-log-parsers.json) | Built-in `text_parser` catalog (assets select via `text_parser`) |
| [shared-contracts.json](shared-contracts.json) | Canonical ownership classes for JSON files shared across DataAsset roots |

Connector UI profiles no longer live in a parallel file. Each entry's
`onboarding_template` selects a kit under `dataasset/onboarding/<name>/`, while
`onboarding_profile` is consumed by both Studio and CLI. Plugins declare the same
fields in their own `plugin.json`. A private registry without the built-in catalog
uses the packaged public catalog; there is no drifting Python constant copy.

**JSON Schema** files live under [`../schema/`](../schema/). `validate.py` checks the
connector catalogs, onboarding profiles, and query templates. After changes, run
`.venv/bin/python src/secweaver.py validate --strict`.

Connector catalogs declare `format_version: "2.0"`. Runtime rejects missing or
unsupported format versions instead of loading a partial registry. Preview and
apply an older catalog migration with:

```bash
ASSET_ROOT="${DATAASSET_ROOT:-dataasset}"
python3 src/secweaver.py dataasset migrate --root "$ASSET_ROOT" --json
python3 src/secweaver.py dataasset migrate --root "$ASSET_ROOT" --write
DATAASSET_ROOT="$ASSET_ROOT" python3 src/secweaver.py validate --strict
```

The migration inlines legacy profiles and selects onboarding skeletons. It keeps
`onboarding-connector-profiles.json` for rollback; remove that legacy file only
after strict validation succeeds. Connector top-level fields and built-in
`config` keys are closed by Schema. Registered config-only external types and
plugins retain an open `config` object for vendor-specific fields.

`shared-contracts.json` is enforced by `src/dataasset/validate_roots.py` and CI.
Every governed JSON file must match exactly one class: `shared` files are
byte-identical across roots, `override` files carry a reason for intentional
differences, and `root_owned` files remain environment inventory. Credentials
are deliberately outside this policy and are never compared.

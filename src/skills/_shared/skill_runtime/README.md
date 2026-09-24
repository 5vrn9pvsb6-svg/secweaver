# Shared Skill Runtime

**Languages:** English (this page) | [简体中文](README.zh-CN.md)

This package owns input adaptation and cross-Skill execution, above the evidence
access layer. It is repository-local Python code, not a separate service or an
agent adapter. Source checkouts and Community archives use the same implementation.

## Ownership

| Location | Owns | Must not own |
|---|---|---|
| `src/dataasset/plugin_contract.py` | Plugin manifest, paths, timeout and response format | Vendor SDKs or Skill invocation |
| `../data-access/` | Registry/Vault, connector fetching, normalization; `scenario_fetch.py` handles plans and bounded expansion | Concrete Skill Python imports or assessment calls |
| `inputs.py` | Bundle parameters, Skill payloads and completeness prechecks | Vendor fetching or verdict rules |
| `contracts.py`, `schemas/` | Versioned Skill envelope and shared structural checks | Domain verdict schemas or connector configuration |
| `execution.py` | Invocation of the assessment entries declared in the catalog, without CLI report/webhook output | Evidence fetching or duplicate assessment rules |
| `pipeline.py`, `prepare.py` | Explicit workflow order and CLI payload/result output | Connector-specific transport |
| Individual Skill `scripts/` packages | Rules, verdicts and optional enrichment | Plugin contract copies |

The complete catalog is [`../../manifest.json`](../../manifest.json). The runtime loads
its assessment entrypoints from this file, while CLI visibility and documentation
checks use the same entries. Each deterministic
Skill keeps its domain output schema beside its `SKILL.md`; those schemas compose the
shared envelope and are checked against committed offline reports. A new deterministic
Skill therefore needs one catalog entry, one output schema, and one representative
contract test before it is considered runnable.

Dependency direction is CLI/Skill entry -> runtime -> data access -> DataAsset
configuration/contracts. Runtime execution also invokes canonical Skill engines;
the lower data-access layer must never call upward. Declarative correlation/trace
profile data remains shared; it does not import the concrete Skill implementation.

## Commands and defaults

Use the existing wrappers from the repository root with Python 3.10+ on Linux,
macOS, or WSL2. Windows users run the wrappers inside WSL2; native Windows is not
a supported Community Skill runtime:

```bash
# Registry metadata only; no assessment, Vault decrypt or evidence fetching.
python3 src/skills/_shared/data-access/prepare.py \
  --bundle bundle-incident-trace-default --pretty

# Metadata assessment, included as skill_result in the prepared payload.
python3 src/skills/_shared/data-access/prepare.py \
  --bundle bundle-incident-trace-default --run-skill completeness --pretty

# Defaults to the committed bundle-incident-trace-default.
python3 src/skills/_shared/data-access/run_pipeline.py completeness --pretty
```

`prepare.py` requires `--bundle ID`, not `--from-bundle`. With no `--run-skill`,
it emits completeness input metadata only. With `--run-skill
completeness|traceability|alert|risk`, it builds that input and runs the canonical
assessment, adding `skill_result`. Traceability/alert now assess as well, instead
of merely preparing payloads. There is no implicit notification or report write.

Pipeline defaults are `bundle-incident-trace-default` for completeness/trace,
`bundle-alert-confirm-min` for alert and `bundle-host-risk-default` for risk.
The historical `bundle-trace-oss-demo` is not shipped. Bundles contain source
configuration, not offline attack logs; use the [offline examples](../../../../examples/README.md)
to evaluate verdicts without external data sources.

Live evidence fetching requires explicit `--fetch`, configured assets and the
relevant dependencies from `requirements-data-access.txt`; Vault-backed sources
also require SOPS and a decryption identity. `--dry-run` previews fetch requests
without Vault decryption. Optional Skill enrichment keeps its existing behavior;
set `resolve_attacker_ip_profile: false` in `--params` to disable trace IP-profile
lookup. Metadata-only commands above need no live credentials. No Agent client,
Go service, database schema or package-version change is required by this split.

## Versioned Skill envelope

Shared builders and `assess_payload()` emit `contract_version: "1.0"` and the
canonical public `skill` id. Existing version-less v1 inputs remain accepted and
are stamped at the boundary. An explicit unknown version, a conflicting Skill id,
or malformed `params`, `evidence_bundles`, `fetch_summary`, or
`completeness_precheck` fails before fetch or assessment. When no precheck ran,
`completeness_precheck` may be absent or `null`; a supplied result must be an object.
The machine-readable
common shape is [`schemas/skill-envelope.schema.json`](schemas/skill-envelope.schema.json).
Individual Skills continue to own their domain fields and verdict semantics.

## Compatibility and verification

Skill CLI flags and pipeline modes/output keys remain available at their old
paths. `skill_input` is an alias of `skill_runtime.inputs`, rather than a copied
module, so adapter imports share state. New code imports `skill_runtime.inputs`;
canonical script entries bootstrap its source path independently of cwd and
`DATAASSET_ROOT`. This does not promise standalone wheel installation.

Patch `fetch.fetch_bundle_evidence` or `fetch.fetch_correlation_plan_evidence`
when intercepting evidence transport in tests; those functions no longer reside
in `skill_input`. Loader failures restore prior `sys.modules` registration.
Entrypoints/catalogs reload per assessment; regular imported dependencies retain
Python's normal cache. Workflows use synchronous execution, not concurrent loads.

After installing the repository development requirements, verify with:

```bash
.venv/bin/python -m unittest tests.test_skill_runtime tests.test_plugin_contract -v
.venv/bin/python -m unittest src/skills/_shared/data-access/tests/test_traceability_asset_cli.py -v
make test
make docs-check
```

These tests check dependency direction, envelope compatibility, catalog coverage,
domain output schemas, four-Skill offline verdict parity, historical commands, loader
rollback and plugin CLI/runtime contract parity.

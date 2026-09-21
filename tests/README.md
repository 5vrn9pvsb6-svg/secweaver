# SecWeaver Tests

**Languages:** English (this page) | [简体中文](README.zh-CN.md)

Unified test entry for the open-source edition. From the repository root, run `make setup` first; direct commands use `.venv/bin/python` without activation. See [development prerequisites](../docs_dev/01-new-contributor-quickstart.md#environment-and-command-conventions) for the additional tools required by full CI.

For just the existing UI regression suite, use `.venv/bin/python -m unittest tests.test_dataasset_ui`; pytest is not required.

```bash
make test
# or
.venv/bin/python tests/run_tests.py -v
```

## Coverage

| Directory | Focus |
|---|---|
| `tests/` | CLI and offline demo regression |
| `src/skills/_shared/data-access/tests/` | Data access, parsers, normalization |
| `src/skills/data-source-completeness/scripts/tests/` | Completeness skill |
| `src/skills/risk-identification/**/tests/` | Risk identification skill |
| `src/skills/log-format-discovery/scripts/tests/` | Format discovery apply logic |
| `src/skills/traceability-analysis/scripts/tests/` | Traceability correlation and reports |
| `src/skills/alert-confirmation/scripts/tests/` | Alert confirmation verdict logic |
| `src/skills/evidence-fetch/tests/` | Evidence fetch skill |

## Regression suites

- `tests/test_public_onboarding_docs.py` checks the first-run guide, case routing,
  read-only discovery and SaaS/SLS/ES query previews, current Agent log paths in Attack Lab docs,
  bilingual fenced JSON against the actual Schemas, private asset-root guidance,
  client platform/output limits, and generated Agent ES templates with verified TLS.
- `tests/test_agent_elasticsearch.py` covers public ES initialization, idempotency,
  overwrite/redirect/TLS protection, ingestion checks, log routing, and export boundaries.
- `tests/test_secweaver_cli.py` — `validate`, `list`, `discover-format`, `demo`, `skill`
- `tests/test_skill_catalog_and_output_contracts.py` — unified Skill catalog, domain output Schemas, all 27 catalog-backed offline assessment inputs checked against `_meta` verdicts/rules/Joins, batch query-gap behavior, a 9-vs-10 SSH failure threshold pair, alert and traceability evidence perturbations, six raw format samples plus WAF and host-exec normalization previews, committed Demos, both prompt-analysis fetch fixtures, and the strict prompt-analysis golden report
- `tests/test_report_markdown.py` — JSON → Markdown rendering and `report markdown` CLI
- `tests/test_ai_host_setup.py` — single/all-host adapter generation, idempotency, all-host preflight, and overwrite protection
- `tests/test_ai_showcase.py` — offline case catalog integrity, enforced online-IP-intelligence/notification opt-outs, and end-to-end expected verdicts

Expected demo verdict fields live in `tests/fixtures/demo_expectations.json`.
The assessment expectations live alongside their inputs under `examples/*/*.json`;
the regression requires every JSON input in the four assessment directories to
be registered in `examples/ai-showcase/cases.json`. The catalog is the public
case inventory; adding an unregistered file fails the test. The
traceability runner disables IP enrichment and notifications in this suite.

## CI

GitHub Actions covers the root `make ci` checks across separate jobs in [ci.yml](../.github/workflows/ci.yml). It additionally runs Linux systemd and Windows SCM service-upgrade jobs; those are not invoked by local `make ci`. Missing Docker locally skips Compose validation with a notice; record that omission rather than treating it as a pass.
`tests/run_tests.py` discovers the public Python suites listed above; it does not
automatically discover private SLS Proxy tests. Private service tests are maintained
and run in the server checkout. The runner pins the repository root on Python's import
path, so public tests may use absolute imports such as `src.dataasset` regardless of
which suite directory `unittest` is currently discovering.

The public workflow validates release hygiene, documentation links, supply-chain
metadata, the open-source Agent, Attack Lab scripts, DataAsset configuration,
behavior-policy synchronization, unit tests, and offline demos. It runs release
scanning again after demo generation so rewritten public reports cannot introduce
local paths or secrets after the first scan. Private Portable
build and package gates run only in the internal checkout that contains that source.
PostgreSQL migration and SLS Proxy service integration tests belong to the
internal server checkout and are not referenced by the public workflow.

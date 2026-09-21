# Developer Guide

**Languages:** English (this page) | [简体中文](02-developer-guide.zh-CN.md)

This guide is for contributors who want to change SecWeaver without first reading the whole repository.

## Contribution map

| Goal | Start here | Also update | Required checks |
|---|---|---|---|
| Add a sanitized data source example | `dataasset/examples/` | `CONTRIBUTING.md` checklist when needed | `.venv/bin/python src/secweaver.py validate` |
| Generate local connector + asset config | `.venv/bin/python src/secweaver.py asset apply -f dataasset/onboarding/examples/data-sources.sample.json --dry-run` | `dataasset/onboarding/` if a template is missing | `.venv/bin/python src/secweaver.py validate --only-active` |
| Add or expose a deterministic Skill | `src/skills/<skill>/` | `src/skills/manifest.json`, examples, tests | `.venv/bin/python src/secweaver.py list`, `.venv/bin/python tests/run_tests.py` |
| Add or modify a prompt-only Skill | `src/skills/<skill>/` | `src/skills/manifest.json`, bilingual workflow, skill index, offline evidence and output acceptance | `.venv/bin/python src/secweaver.py list` and the prompt-only workflow below |
| Change demo behavior | `examples/<skill>/`, `examples/reports/`, `tests/fixtures/` | `src/skills/manifest.json` if paths change | `.venv/bin/python src/secweaver.py demo all` |
| Modify or rewrite UI | `dataasset-ui/`, or a new frontend directory | [25-ui-contribution-guide.md](25-ui-contribution-guide.md), `dataasset-ui/README.md` | `.venv/bin/python -m unittest tests.test_dataasset_ui`, manual UI smoke |
| Change DataAsset schema or validation | `dataasset/schema/`, `src/dataasset/validate.py`, `src/dataasset/validate_lib/` | `docs_dev/09-data-asset-design.md`, tests | `.venv/bin/python src/secweaver.py validate --json` |
| Change the host agent or add a collector module | `src/tools/secweaver-agent/` | `src/tools/secweaver-agent/README.md`, `docs_dev/12-agent-collection-and-evidence-spec.md` | `make agent-check` |
| Change report rendering | `src/report_markdown.py` | `examples/reports/`, report tests | `.venv/bin/python src/secweaver.py report markdown --demo all` |

## Local setup

See the [new contributor quickstart](01-new-contributor-quickstart.md#environment-and-command-conventions) for tools, supported platforms and full-CI prerequisites. Commands below run from the repository root using the virtual-environment interpreter explicitly; no activation is required.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-data-access.txt
.venv/bin/python src/secweaver.py list
```

Common checks:

```bash
make validate
make test
make demo
make release-scan
make docs-check
```

`make ci` runs the normal local gate. `make release-scan` is the open-source hygiene gate for secrets, private markers, and files that should not enter the public tree.
`make docs-check` checks public documentation links and private-delivery command references. Running only the link checker covers one part, not the whole target. Focused checks support development iterations; see the [contributor entrypoint](01-new-contributor-quickstart.md) for full gates and unrun-check reporting.

## Adding a CLI-visible Skill

Use this path when the Skill has a deterministic script and should be runnable through `secweaver skill` or `secweaver demo`.

1. Create `src/skills/<skill>/SKILL.md` and the deterministic script under `src/skills/<skill>/scripts/`.
2. Add a synthetic offline input under `examples/<skill>/`.
3. Add the Skill to `src/skills/manifest.json`.
4. Add a CLI/demo regression in `tests/test_secweaver_cli.py` or a narrower unit test near the Skill.
5. Run:

```bash
.venv/bin/python src/secweaver.py list
.venv/bin/python src/secweaver.py skill <skill-name> -i examples/<skill>/<case>.json
.venv/bin/python tests/run_tests.py
```

Manifest fields:

| Field | Purpose |
|---|---|
| `key` | Short internal CLI key, such as `risk` |
| `name` | Public Skill name, such as `risk-identification` |
| `kind` | Skill type, such as `assessment`, `prompt`, or `router` |
| `cli_visible` | Whether `secweaver skill` may execute it; prompt-only and routing Skills use `false` |
| `aliases` | Extra names accepted by `secweaver skill` and `secweaver demo` |
| `script` | Optional deterministic Python entry point; workflow-only Skills omit it |
| `docs` | `SKILL.md` path |
| `output_schema` | Optional Schema for a stable public JSON contract |
| `demo.input` / `demo.output` | Optional built-in offline demo paths |

## Adding or Modifying a Prompt-only Skill

A prompt-only Skill is read and executed by an AI agent; its analysis does not require a Python entrypoint. Use [prompt-risk-analysis](../src/skills/prompt-risk-analysis/SKILL.md) as an existing reference. Retrieval can reuse `evidence-fetch`; use synthetic evidence for offline development.

1. Define the name, triggers, inputs, required workflow, outputs and evidence boundaries in `src/skills/<skill>/SKILL.md`, with a synchronized Chinese sibling. Split substantial prompts, contracts or references only when useful and link them from the entrypoint.
2. Add the Skill to the single catalog in `src/skills/manifest.json`: set `kind` to `prompt`, set `cli_visible` to `false`, provide the canonical `docs` path, and omit `script`. Also add a discoverable entry to `src/skills/README.md` / `README.zh-CN.md` and update the user skill directory. Thin adapters read this index before choosing a skill; do not duplicate implementations per agent. Load it through the [agent setup guide](../docs_user/38-ai-agent-host-setup.md), then explicitly request the new skill and verify the agent reads its entrypoint.
3. Provide fixed synthetic inputs and acceptance notes in `examples/<skill>/`, covering behavior that should be detected, benign counterexamples and insufficient evidence. State supported conclusions, prohibited inferences, evidence references and gaps. Golden reports define quality expectations, not wording the model must repeat verbatim.
4. Define an output Schema when structured results are needed and validate examples. Add relevant checks for bilingual contracts and critical decision boundaries; wording-only changes do not need tests that copy prose. For the existing `prompt-risk-analysis`, run:

```bash
.venv/bin/python -m unittest tests.test_prompt_risk_analysis_contract tests.test_prompt_risk_analysis_skill_parity
make docs-check
```

These tests cover the existing skill's contract, fixtures and bilingual conventions. They neither discover new skills nor run a model. Give a new skill its own verification entrypoint and document the command in its acceptance notes.

5. Review positive, negative and missing-evidence cases in the chosen AI agent using the same fixed inputs. Record the skill version/commit, agent and model, input files, request, outputs and pass/fail reasons. Check that evidence references exist, benign behavior is not falsely flagged, missing evidence stays unknown, network activity is not automatically called exfiltration, and model judgments do not impersonate deterministic `policy_rule_id` matches. Select checks relevant to the actual skill contract.
6. Include a sanitized review summary and known limitations in the PR. Automated tests do not establish model analysis quality; explicitly identify any model review not yet performed.

`src/skills/manifest.json` is the single catalog for every top-level Skill. Prompt-only Skills appear in `secweaver list` so agents and users can discover their `SKILL.md`; because they have no script and set `cli_visible` to `false`, `secweaver skill <name>` cannot execute them. Add `script`, set `cli_visible` to `true`, and complete the CLI/demo checks in the previous section only after the Skill gains a stable deterministic entrypoint.

## Adding data source configuration

Operators should be able to start from configuration, not code. Prefer the no-code path first:

```bash
.venv/bin/python src/secweaver.py asset apply \
  -f dataasset/onboarding/examples/data-sources.sample.json \
  --dry-run
```

`asset apply` reads a JSON config with a `data_sources` array and writes `dataasset/connectors/`, `dataasset/assets/`, and `dataasset/query-templates/templates.json`. Operators can set common fields directly, then use `connector`, `asset`, and `template` sections for deep overrides such as nested connector config, `text_parser`, `schema.fields`, `field_aliases`, `coverage`, query `params`, and template `defaults`. For one-off sources, `asset init` still accepts command-line arguments.

Ops config lifecycle commands:

```bash
.venv/bin/python src/secweaver.py asset diff -f dataasset/onboarding/examples/data-sources.sample.json
.venv/bin/python src/secweaver.py asset promote --asset asset-demo-waf-sls --params '{"src_ip":"203.0.113.10"}' --dry-run
.venv/bin/python src/secweaver.py asset rollback -f dataasset/onboarding/examples/data-sources.sample.json --dry-run
```

If a connector type or asset shape cannot be generated this way, improve the directory selected by its manifest's `onboarding_template` before adding bespoke instructions. Built-in query keys, runtime modes, dependency strategy, template selection, and Studio profile live together in `dataasset/configure/connector-catalog.json`; config-only external connectors keep the same fields in `dataasset/configure/external-connectors.json`; plugins own them in `plugin.json`. Do not add parallel Python constants or UI profile files. Validate plugins with `.venv/bin/python src/secweaver.py connector plugin validate src/dataasset/plugins/connectors/<name>`. Keep examples synthetic, use `vault://...` references, and run `.venv/bin/python src/secweaver.py validate --strict` plus `make release-scan` before opening a PR.

For a true in-core connector contribution, keep the "one connector, one `*_fetch.py`" boundary: add the dedicated fetch file, then register it in `src/skills/_shared/data-access/connector_fetch_dispatch.py` or `extended_fetch.py`. Do not add another `if/elif connector_type` branch to `fetch.py`; `fetch.py` only loads config, renders templates, resolves credentials, calls the dispatcher, and normalizes events.

The CLI entry `src/secweaver.py` should stay focused on command registration and top-level dispatch. Asset onboarding lifecycle commands (`asset init/apply/diff/rollback/promote`) live in `src/secweaver_cli/asset_commands.py`. When adding onboarding generation behavior, update that module and `dataasset/onboarding/` instead of putting generation logic back into the CLI entry file.

Plugin discovery, CLI validation and execution share `src/dataasset/plugin_contract.py`;
do not duplicate manifest/path/response rules in the CLI or executor. Keep evidence
transport and scenario fetch expansion under `src/skills/_shared/data-access/`.
Skill input adaptation, completeness prechecks and cross-Skill workflows belong to
[`src/skills/_shared/skill_runtime/`](../src/skills/_shared/skill_runtime/README.md),
not the lower fetch layer. The old `skill_input.py`, `prepare.py` and `run_pipeline.py`
paths only preserve compatibility. Run `tests.test_plugin_contract` and
`tests.test_skill_runtime` when changing these boundaries.

DataAsset validation follows the same split. Keep `src/dataasset/validate.py` as the CLI-compatible orchestration entry; put reusable validator helpers, structured reports, and operator-facing diagnostics under `src/dataasset/validate_lib/`. For example, edit `validate_lib/diagnostics.py` when changing `--diagnose` categories, priorities, owners, or fix steps.

Deterministic Skills should follow the same pattern: keep the historical script as a thin CLI-compatible entrypoint and move business logic into a package under `scripts/`. For example, `src/skills/alert-confirmation/scripts/confirm.py` only preserves command/import compatibility; payload verdict logic lives in `alert_confirmation/layer1.py`, D2 success logic in `alert_confirmation/success.py`, gateway miss logic in `alert_confirmation/gateway.py`, orchestration in `alert_confirmation/engine.py`, and Markdown/batch output in `alert_confirmation/report.py`. Traceability follows the same split: `src/skills/traceability-analysis/scripts/correlate.py` is the compatibility entry, while initial access, execution, lateral movement, verdict/report helpers, and orchestration live in `traceability_analysis/`.

For host-side collection, keep `src/tools/secweaver-agent/main.go` as the unified client supervisor and add module logic under `src/tools/secweaver-agent/pkg/<module>/`. Existing `audit-port-execmon` internals are split into config, listener/procfs discovery, process-tree monitoring, audit rule management, audit log parsing, and output helpers; follow that layout instead of adding new collector behavior to a single large file.

For the end-to-end community path to add one asset and its connector, see [community-add-asset-connector.md](03-community-add-asset-connector.md).

## Modifying or Rewriting UI

UI is an open contribution surface, not limited to small fixes. Contributors can:

- Improve existing `dataasset-ui/` pages, layout, forms, error hints, and i18n.
- Add connector, bundle, network, correlation, scenario, or fetch-plan pages.
- Extend the local `dataasset-ui/server.py` API; put non-trivial logic in the matching `dataasset-ui/dataasset_ui_services/` service module.
- Rewrite the whole UI with React/Vue/Svelte/desktop shells or another frontend stack.

Rewritten UIs should keep these platform contracts:

- Select the active asset directory through `DATAASSET_ROOT`.
- Read and write the standard DataAsset directory layout.
- Reuse `src/secweaver.py asset apply/diff/promote/rollback` for onboarding.
- Reuse `src/dataasset/validate.py --json/--diagnose` for validation.
- Write only `credentials_ref`, never plaintext secrets.
- Keep user-visible copy bilingual where applicable, or document the i18n scope.

See [UI Contribution and Rewrite Guide](25-ui-contribution-guide.md) for details.

## Pull request checklist

- The change has one obvious owner area: DataAsset, Skill, CLI, docs, examples, or tests.
- Code and comments are submitted together. New or materially changed non-obvious logic documents its design intent, constraints, and failure semantics; missing or misleading comments block merge.
- New contributor-facing behavior is reachable from `README.md`, `CONTRIBUTING.md`, `docs_dev/README.md`, or this guide.
- Every new top-level Skill is declared in `src/skills/manifest.json`; only Skills with a stable script entrypoint set `cli_visible: true`.
- New examples are synthetic and do not include credentials, internal hostnames, customer logs, or private IP inventories.
- `.venv/bin/python src/scripts/release_scan.py`, `.venv/bin/python src/secweaver.py validate`, and `.venv/bin/python tests/run_tests.py` pass locally. `make ci` runs the release gate before validation, tests, and demos.

## Review expectations

Small PRs are easier to review. Keep unrelated formatting, generated outputs, and example data changes separate unless the test fixture requires them together.

Comments must explain why the code exists rather than narrating each statement. Concurrency and lock ownership, lifecycle transitions, ordering assumptions, resource bounds, performance tradeoffs, compatibility handling, security boundaries, retries, rollback, and degraded-mode behavior require explicit comments. Update or remove stale comments in the same change that modifies behavior; tests do not replace documentation of design invariants and operational assumptions. Trivial accessors and direct assignments do not need narration, and syntax-repeating comments do not satisfy the rule. See the repository-wide mandatory rule in [`AGENTS.md`](../AGENTS.md).

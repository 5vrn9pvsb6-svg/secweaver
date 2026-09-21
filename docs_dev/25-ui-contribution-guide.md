# UI Contribution and Rewrite Guide

**Languages:** English (this page) | [简体中文](25-ui-contribution-guide.zh-CN.md)

The SecWeaver UI is not a closed module. Contributors can work on UI in addition to connector plugins, external connectors, Skills, and docs: improve existing pages, add pages, enhance interactions, or rewrite the UI on top of the same backend contracts.

The current open-source UI lives in [`dataasset-ui/`](../dataasset-ui/README.md). It is a lightweight local DataAsset Studio for operator-owned data source onboarding, asset editing, validation, and demo viewing.

## Contribution Modes

| Mode | Best for | Start here |
|---|---|---|
| Modify existing pages | Layout, copy, forms, validation hints, i18n | `dataasset-ui/*.html`, `dataasset-ui/*.js`, `dataasset-ui/style.css`, `dataasset-ui/styles/*.css` |
| Add pages | Connector management, bundle selection, network management, fetch-plan preview | Follow existing module pages and wire `shared-nav.js` |
| Extend the local API | New read/write actions or diagnostics | `dataasset-ui/server.py`; prefer reusing `src/secweaver.py` and `src/dataasset/validate.py` |
| Rewrite the UI | React/Vue/Svelte, desktop shell, or enterprise web console | Keep the DataAsset file contract and local API contract; frontend stack is replaceable |

## What Can Be Replaced?

The UI layer may replace:

- Framework and component library.
- Routing, state management, forms, and visual design.
- Graphical capabilities such as topology, correlation matrix, scenarios, and fetch-plan explanation.
- Local desktop shell or browser implementation.

Do not replace these platform contracts:

| Contract | Why it matters |
|---|---|
| `DATAASSET_ROOT` | Edits `dataasset/` by default, with optional isolation in `dataasset_my/` |
| DataAsset file layout | `assets/`, `connectors/`, `query-templates/`, `hosts/`, and `networks/` are shared by CLI, Skills, and validation |
| `asset apply` generation | Core no-code onboarding path; UI should call the same logic instead of inventing a second format |
| `validate.py --json/--diagnose` | UI errors should match CLI/CI gates |
| `credentials_ref` | UI writes `vault://...` references, never plaintext secrets |
| Bilingual docs and copy | User-visible copy should stay English/Chinese where applicable |

## Recommended Architecture

```text
UI / new frontend
  ├─ read/write DataAsset objects
  ├─ call onboarding preview/apply
  ├─ call validate / diagnose
  ├─ call demo / report / connectivity check
  └─ explain correlation / scenario / fetch plan

Backend contracts
  ├─ dataasset-ui/server.py (local API)
  ├─ src/secweaver.py asset apply/diff/promote/rollback
  ├─ src/dataasset/validate.py
  ├─ src/dataasset/validate_lib/diagnostics.py
  └─ dataasset/ directory layout
```

If you rewrite the UI, treat `dataasset-ui/server.py` as the local API adapter first. The new frontend should call it over HTTP rather than duplicating Python logic. If the API later becomes a formal service, keep response shapes compatible where possible.

## Adding a Page

Recommended steps:

1. Add `dataasset-ui/<page>.html`.
2. Add or reuse `<page>.js`.
3. Add navigation in `dataasset-ui/shared-nav.js`.
4. Add English and Chinese strings in `dataasset-ui/i18n.js`.
5. If backend data is needed, add a small stable API in `server.py`.
6. Add a smoke or API test in `tests/test_dataasset_ui.py`.

Do not hardcode real environment details, private endpoints, AK/SK, customer fields, or internal screenshots.

## API Extension Principles

When extending `dataasset-ui/server.py`:

- Return JSON with `ok`, `data`, or `error`.
- Restrict writes to the active `DATAASSET_ROOT`.
- Route JSON object saves through `dataasset_ui_services.objects.save_object`, including legacy API routes. It validates the canonical Schema and active references before an atomic replace. Use `src/dataasset/registry_write.py` for the same root lock as CLI asset writes; avoid bypasses through direct `Path.write_text`.
- Call `src/secweaver.py` for complex generation instead of reimplementing it.
- Use `validate.py --json` or `--diagnose` for validation results.
- Whitelist command arguments; do not pass arbitrary shell from the page.

Backend boundaries:

- `dataasset-ui/server.py`: HTTP routes, static files, and JSON responses.
- `dataasset-ui/dataasset_ui_services/onboarding.py`: onboarding metadata, preview/apply, and config diagnostics.
- `dataasset-ui/dataasset_ui_services/credentials.py`: credential references, sample YAML, and encrypted writes.
- `dataasset-ui/dataasset_ui_services/registry.py` / `topology.py`: asset inventory and topology.
- `dataasset-ui/dataasset_ui_services/validation.py`: validation execution and diagnosis cards.
- `src/dataasset/validate_lib/diagnostics.py`: CLI/UI shared validation categories, priorities, owners, and fix steps.

Frontend module-page boundaries:

- `dataasset-ui/module-page-config.js`: shared module definitions, default templates, and enum values.
- `dataasset-ui/module-page-utils.js`: DOM helpers, API wrapper, detail summary, modal helpers, JSON/YAML sync helpers.
- `dataasset-ui/module-page-list.js`: searchable registry lists, counters, pagination, and row actions.
- `dataasset-ui/module-page-editors.js`: asset, host, credential, correlation, and scenario structured editors.
- `dataasset-ui/module-page.js`: page state, detail load/save/delete, asset actions, and initialization.

Frontend style boundaries:

- `dataasset-ui/style.css`: stable stylesheet entrypoint; keep only ordered imports.
- `dataasset-ui/styles/00-base.css`: design tokens, reset, typography, topbar, title bar, and shared shell.
- `dataasset-ui/styles/01-layout-nav.css`: workbench grid, sidebar, panels, and resource navigation.
- `dataasset-ui/styles/02-dashboard-topology.css`: dashboard cards and topology visualization.
- `dataasset-ui/styles/03-forms-lists.css`: status cards, forms, tables, registry lists, and pagination.
- `dataasset-ui/styles/04-detail-editor.css`: detail modal, buttons, pills, summaries, and structured editors.
- `dataasset-ui/styles/05-correlation-validation.css`: correlation explanation, advice/report cards, and validation output.
- `dataasset-ui/styles/06-onboarding.css`: onboarding flow, vendor catalog, connector catalog, and preview panels.
- `dataasset-ui/styles/07-utilities-responsive.css`: empty states, utilities, and responsive overrides kept last.

## Minimum Acceptance for a Rewritten UI

A new UI should at least:

- Read the active `DATAASSET_ROOT`.
- View assets / connectors / hosts / networks.
- Preview generated `connector + asset + query template`.
- Dry-run before apply.
- Run validation and display error/warning/blocking issues.
- Avoid plaintext credentials.
- Include a local smoke test, or at least screenshots/recording notes.

## Suggested Checks

Prepare tools using the [development setup](01-new-contributor-quickstart.md#environment-and-command-conventions) and run `make setup`. Execute from the repository root with `.venv/bin/python`. Existing UI regressions use standard-library `unittest`; no additional pytest installation is needed.

```bash
.venv/bin/python tests/run_tests.py
.venv/bin/python -m unittest tests.test_dataasset_ui
.venv/bin/python src/scripts/check_docs_links.py
```

For static UI edits, at least run:

```bash
.venv/bin/python dataasset-ui/server.py
```

Open `http://127.0.0.1:8765/` and check loading, edit previews and error messages using synthetic assets. Do not commit live configuration. The server occupies the terminal; stop it with `Ctrl-C` when finished. This manual page check does not replace full CI.

## Review Focus

Maintainers will check:

- Whether the change lowers operator configuration cost.
- Whether it reuses existing CLI/validate/onboarding logic.
- Whether it preserves `DATAASSET_ROOT` and private-directory isolation.
- Whether errors are understandable.
- Whether it avoids unnecessary heavy dependencies or build chains.
- Whether docs, screenshots, or tests were updated.

The UI can be rewritten, but the data asset contract should stay stable. That lets the community freely improve the experience while keeping the platform core and operator configuration consistent.

# New Contributor Quickstart

**Languages:** English (this page) | [简体中文](01-new-contributor-quickstart.zh-CN.md)

This page is the shortest path for developers who want to contribute to SecWeaver without reading the whole repository first.

## Environment and Command Conventions

Run from the repository root containing `Makefile`. Python development and offline use require a Linux/macOS POSIX terminal, Python 3.10+, venv/pip and Make. Forks, branches and commits require Git; initial dependency installation needs package-download access. Native Windows PowerShell does not support this guide's `.venv/bin/python` and Make commands. Windows Agent support is separate; the WSL development path has not completed end-to-end acceptance.

Use `.venv/bin/python` for project Python commands throughout; **activation is unnecessary**. Running system `python3` after creating `.venv` can miss dependencies installed in the virtual environment.

| Goal | Additional prerequisites |
|---|---|
| Local Python, documentation, DataAsset or existing lightweight UI checks | No Go, Node.js, SaaS account or production credentials; document dependencies separately if adding a frontend build system |
| `make agent-check` / full `make ci` | Go matching [go.mod](../src/tools/secweaver-agent/go.mod) (currently 1.22), gofmt, Bash, a host supported by Go race and a C compiler toolchain; Go module download access |
| Attack Lab Compose validation | Docker with the Compose plugin; missing Docker prints a skip notice and must not be recorded as a local pass |
| Real-service upgrades or attack exercises | A separate authorized test environment; ordinary documentation work does not require installing host collectors or running attacks on a developer machine |

Initially check `python3 --version`, `make --version` and `git --version`. Before the full gate, also check `go version`, `gofmt -h`, `cc --version`, `bash --version` and `docker compose version`. Tool availability is not environment acceptance. Ubuntu is the public CI baseline for the main development checks; service upgrades have separate Linux/Windows jobs.

## First 15 Minutes

Run the local checks once before changing code:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-data-access.txt
.venv/bin/python src/secweaver.py list
.venv/bin/python src/secweaver.py validate
```

If you prefer the project Makefile:

```bash
make quickstart
```

Before opening a PR, run:

```bash
make ci
```

`make ci` runs dependency setup, release scans, documentation and SBOM checks,
Agent and Attack Lab checks, DataAsset validation, behavior-policy synchronization,
tests, and offline demos. Selected manual checks are not equivalent to this full gate.

Run the focused checks below while iterating, then record the full `make ci` result in the PR. If tools or platform support are unavailable, list each unrun check and reason for maintainers to verify against CI; do not present partial checks as a full pass. Real systemd/Windows SCM upgrade tests are separate CI jobs, not part of local `make ci`.

## Choose Your Contribution Path

| I want to... | Start here | Main docs | Expected check |
|---|---|---|---|
| Fix docs or examples | `docs_dev/`, `docs_user/`, `examples/` | [CONTRIBUTING.md](../CONTRIBUTING.md) | `make docs-check`, `make release-scan` |
| Add a sanitized connector or asset example | `dataasset/examples/` | [community-add-asset-connector.md](03-community-add-asset-connector.md) | `.venv/bin/python src/secweaver.py validate` |
| Let operators generate connector + asset + query template from config | `dataasset/onboarding/` | [developer-guide.md](02-developer-guide.md) | `.venv/bin/python src/secweaver.py asset apply -f dataasset/onboarding/examples/data-sources.sample.json --dry-run` |
| Add a connector that should not be in core | `src/dataasset/plugins/connectors/` | [connector-plugins.md](04-connector-plugins.md) | `.venv/bin/python src/secweaver.py connector plugin validate src/dataasset/plugins/connectors/<name>` |
| Add an external executor example | `examples/`, `docs_dev/`, optional local script | [external-connector-executors.md](05-external-connector-executors.md) | `.venv/bin/python src/dataasset/test_connector.py <asset_id> --by-asset --plan --dry-run` |
| Modify, add, or rewrite UI | `dataasset-ui/` or a new frontend directory | [ui-contribution-guide.md](25-ui-contribution-guide.md) | `.venv/bin/python -m unittest tests.test_dataasset_ui`, manual UI smoke |
| Add or modify a deterministic Skill | `src/skills/<skill>/` | [Deterministic CLI contribution](02-developer-guide.md#adding-a-cli-visible-skill) | `.venv/bin/python src/secweaver.py list` and `.venv/bin/python tests/run_tests.py` |
| Add or modify a prompt-only Skill | `src/skills/<skill>/`, `examples/<skill>/` | [Prompt-only contribution](02-developer-guide.md#adding-or-modifying-a-prompt-only-skill) | Documentation, output-contract and bilingual checks; then agent review on fixed positive/negative evidence |
| Add functionality to secweaver-agent | `src/tools/secweaver-agent/` | [Agent engineering manual](../src/tools/secweaver-agent/README.md) | `make agent-check` |
| Change schema or validation behavior | `dataasset/schema/`, `src/dataasset/validate.py`, `src/dataasset/validate_lib/` | [data-asset-design.md](09-data-asset-design.md) | `.venv/bin/python src/secweaver.py validate --json` |

## Recommended First PRs

- Add a sanitized connector example under `dataasset/examples/connectors/`.
- Add a new onboarding quickstart under `dataasset/onboarding/examples/`.
- Improve `dataasset-ui/onboarding.html` form UX, error hints, or i18n copy.
- Improve one troubleshooting entry in `docs_user/09-operations-troubleshooting.md` or one short answer in `docs_user/16-data-source-onboarding-faq.md`.
- Add tests around an existing CLI behavior in `tests/test_secweaver_cli.py`.
- Improve English or Chinese docs while keeping sibling files in sync.
- Run `make docs-check` after documentation edits to catch broken local Markdown links.

## First Documentation PR: A Small Complete Workflow

1. Fork and clone the repository, then create a working branch, for example `git switch -c docs/first-contribution`. Inspect your branch/worktree first if local edits already exist; preserve existing work.
2. Choose one specific issue, such as correcting a data-source FAQ entry, and update both `.md` and `.zh-CN.md`. This does not require runtime code or live asset changes.
3. Check from the repository root:

```bash
make docs-check
make release-scan
git diff --check
git diff --stat
```

4. Success means 0 documentation issues, 0 release-scan errors and only intended changes in the diff; explain any warnings. Verify changed commands with public synthetic inputs rather than checking wording alone.
5. Run `make ci` with the prerequisites above. Describe the problem, change, verification and unrun gates in the PR. Review `git diff`, stage explicit files, push to your Fork and open the PR. Exclude generated reports, live configuration and credentials.

## Data Safety Rules

- Never commit real credentials, tokens, private keys, decrypted vault files, customer logs, or private investigation reports.
- Use placeholders like `REPLACE_ME`, `YOUR_SLS_PROJECT`, and `vault://namespace/name`.
- Use synthetic addresses and hostnames. Prefer RFC 5737 public documentation ranges such as `203.0.113.0/24`.
- Put new examples under `dataasset/examples/` first unless a maintainer agrees to promote them into the active demo registry.
- Run `make release-scan` before PRs that touch data, examples, docs, or scripts.

## Useful Entrypoints

- [CONTRIBUTING.md](../CONTRIBUTING.md): contribution process, PR expectations, and data hygiene.
- [developer-guide.md](02-developer-guide.md): change map for DataAsset, Skills, demos, schema, reports, and tests.
- [community-add-asset-connector.md](03-community-add-asset-connector.md): end-to-end guide for adding one asset and its connector.
- [connector-plugins.md](04-connector-plugins.md): plugin mode for SDK-backed or custom local integrations.
- [external-connector-executors.md](05-external-connector-executors.md): external executor protocol for integrations that run outside core.
- [ui-contribution-guide.md](25-ui-contribution-guide.md): UI page extension, API contracts, and full UI rewrite guidance.
- [tests/README.md](../tests/README.md): test layout and regression expectations.

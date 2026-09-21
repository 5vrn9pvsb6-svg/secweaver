# Contributing to SecWeaver

**Languages:** English (this page) | [简体中文](CONTRIBUTING.zh-CN.md)

Thanks for helping improve SecWeaver.

## How to contribute

```text
Idea or bug
  → Search existing Issues / Discussions
  → Open an Issue (use a template) or start a Discussion
  → Fork → branch → change → make ci → Pull Request
  → Maintainer review → merge → CHANGELOG / Release
```

| Channel | Use for |
|---|---|
| Repository Issues | Bugs, features, doc gaps, example DataAsset requests |
| Repository Discussions (when enabled) | How-to questions, scenario design, RFC before coding |
| Pull requests | All merged code, examples, docs, and tests |
| [SECURITY.md](SECURITY.md) ([简体中文](SECURITY.zh-CN.md)) | Vulnerabilities — **private** report, not a public issue |

Issue and PR templates live under [`.github/`](.github/).

Suggested labels for maintainers: `bug`, `enhancement`, `documentation`, `dataasset`, `good first issue`.

If you are new to the repository, start with the short contributor path:
[`docs_dev/01-new-contributor-quickstart.md`](docs_dev/01-new-contributor-quickstart.md) /
[`docs_dev/01-new-contributor-quickstart.zh-CN.md`](docs_dev/01-new-contributor-quickstart.zh-CN.md).

## Contribution Scope

Good open-source contributions include:

- DataAsset schema improvements.
- Sanitized example assets, connectors, hosts, networks, bundles, and query templates.
- Basic Skills and deterministic helper scripts.
- Offline demo inputs and expected outputs.
- Documentation, onboarding guides, and troubleshooting notes.
- Tests for CLI, validation, data access, parsers, and Skills.

Please avoid submitting:

- Real credentials, tokens, private keys, production vault files, or API secrets.
- Customer logs, production investigation reports, or internal IP inventories that are not explicitly sanitized.
- Proprietary enterprise connector implementations.
- Customer-specific detection rules, allowlists, or response playbooks.
- Code that performs destructive SOAR actions against production systems without an explicit safe/dry-run boundary.

## Before Opening a Pull Request

### Code and comment standard

Code comments are a merge requirement, not optional cleanup. Every code change must add or update comments together with the implementation when behavior is not obvious.

- Comment the design intent and why the implementation is necessary; do not translate each statement into prose.
- Explicitly document concurrency and lock ownership, lifecycle and ordering assumptions, bounded-resource behavior, performance tradeoffs, compatibility handling, security boundaries, retries, rollback, and degraded-mode behavior.
- Document exported APIs according to the language's standard conventions.
- Update or remove stale comments whenever behavior changes. Tests do not replace comments for invariants and operational assumptions.
- Trivial accessors and direct assignments do not require narration, and syntax-repeating comments do not satisfy this rule.

A pull request with undocumented or misleading non-obvious logic is not ready to merge. The repository-wide rule is also recorded in [`AGENTS.md`](AGENTS.md) so automated coding tasks apply it before editing.

See [development prerequisites](docs_dev/01-new-contributor-quickstart.md#environment-and-command-conventions). Python setup alone is insufficient for the full gate; Go and its race compiler toolchain are also required. Record focused checks and skipped items accurately rather than claiming full CI success.

Run the same checks as CI:

```bash
make ci
```

Selected local checks (not equivalent to the complete CI gate):

```bash
.venv/bin/python src/secweaver.py validate
.venv/bin/python tests/run_tests.py
.venv/bin/python src/secweaver.py demo all
make docs-check
make sbom-check
```

Run `make ci` for the full gate, including dependency setup, release scanning,
documentation, SBOM, Agent checks, Attack Lab checks, DataAsset validation,
behavior-policy synchronization, tests, and demos. The commands above assume
`make setup` has already created `.venv`; they do not replace the full gate.

Test layout and CLI/demo regression expectations: [`tests/README.md`](tests/README.md).

Contributor change map and test matrix: [`docs_dev/02-developer-guide.md`](docs_dev/02-developer-guide.md) / [`docs_dev/02-developer-guide.zh-CN.md`](docs_dev/02-developer-guide.zh-CN.md).

First-day contributor guide: [`docs_dev/01-new-contributor-quickstart.md`](docs_dev/01-new-contributor-quickstart.md) / [`docs_dev/01-new-contributor-quickstart.zh-CN.md`](docs_dev/01-new-contributor-quickstart.zh-CN.md).

End-to-end guide for adding one asset and its connector: [`docs_dev/03-community-add-asset-connector.md`](docs_dev/03-community-add-asset-connector.md) / [`docs_dev/03-community-add-asset-connector.zh-CN.md`](docs_dev/03-community-add-asset-connector.zh-CN.md).

## Data and Credential Hygiene

Use placeholders such as `REPLACE_ME`, `YOUR_SLS_PROJECT`, or `vault://...` for sensitive values. If an example needs realistic data, use synthetic RFC 5737 / RFC 3849 addresses, synthetic hostnames, and fake event IDs. The release scan rejects known internal acceptance ranges and common local checkout paths throughout the public candidate; never copy real test-host addresses or contributor workspace paths into docs, Skills, examples, source, or test fixtures.

Do not include `.DS_Store`, local spreadsheets, temporary exports, decrypted vault files, or generated private reports.

## Contributing example DataAssets

Community PRs for **sanitized templates** are one of the highest-value contributions. They help others connect SLS, ES, SSH, Splunk, databases, and file sources without exposing real environments.

### Where files go

| You are adding… | Put it here | Enters `catalog.json`? |
|---|---|---|
| Connector template | `dataasset/examples/connectors/conn-<vendor>-<purpose>-example.json` | No — reference only |
| Field reference / copy-paste asset | `dataasset/examples/reference-assets.json` or a new file under `examples/` | No |
| Part of the **offline demo registry** | `dataasset/assets/`, `dataasset/connectors/`, `dataasset/hosts/`, `dataasset/networks/` | Yes — must pass full `validate` and stay synthetic |
| Query template | `dataasset/query-templates/` | Yes if referenced by active assets |
| Bundle wiring | `dataasset/bundles/` | Yes — only demo asset IDs |

**Default for new contributors:** add under `dataasset/examples/` first. Maintainers may promote vetted examples into the demo registry in a follow-up PR.

Naming patterns:

- Connectors: `conn-sls-example.json`, `conn-splunk-example.json`, `conn-ssh-file-example.json`
- Assets: `asset-<source>-<purpose>-demo.json`
- Hosts: `host-<role>-demo.json` with synthetic `host_ip`
- Networks: `net-demo-<zone>.json` with RFC 5737 documentation ranges in public examples

See existing files in [`dataasset/examples/connectors/`](dataasset/examples/connectors/).

### Required content rules

1. **Credentials** — `"credentials_ref": "vault://sls/security-readonly"` or similar; never plaintext secrets. Do not commit `dataasset/credentials/secrets/` (local SOPS only).
2. **Endpoints** — placeholder projects/index names: `YOUR_SLS_PROJECT`, `YOUR_ES_INDEX`, `example.log.aliyuncs.com`.
3. **IPs and hostnames** — use RFC 5737 IPv4 documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), RFC 3849 `2001:db8::/32` for IPv6, and clearly synthetic hostnames. Do not use RFC1918 addresses in public `dataasset/`, customer public IPs, or bulk internal inventories.
4. **Status** — new Connectors use `"status": "draft"`; new Assets use `"status": "discovery"` or `"draft"`. Use `"disabled"` for an explicitly disabled object. `inactive` is not valid in the current Schemas. Only maintainer-reviewed offline demos covered by `make ci` may use `active`.
5. **Descriptions** — English-first in committed JSON `description` fields when adding new objects.

### Workflow

```bash
# 1. Copy the closest existing example
cp dataasset/examples/connectors/conn-sls-example.json \
   dataasset/examples/connectors/conn-vendor-foo-example.json

# 2. Edit IDs, connector_type, config, credentials_ref

# 3. Validate (examples dir is not always in catalog — validate when touching registry assets)
.venv/bin/python src/secweaver.py validate

# 4. Full CI gate before PR
make ci
```

If you add or change registry assets (`dataasset/assets/`, etc.):

```bash
.venv/bin/python src/secweaver.py catalog sync
.venv/bin/python src/secweaver.py validate
```

Before publishing a community archive, commit the intended changes so the Git
worktree is clean, then run `make open-source-export OUTPUT=/tmp/secweaver-community.tar.gz`.
The exporter packages `HEAD` and re-runs the public gates from the extracted archive.

### PR checklist (example DataAssets)

- [ ] File path under `dataasset/examples/` (unless agreed demo registry change)
- [ ] `connector_id` / `asset_id` unique and suffixed with `-example` or `-demo`
- [ ] No `secrets/`, `.env`, or production hostnames (e.g. real cloud instance names)
- [ ] `make ci` green
- [ ] Short PR note: which Scenario Pattern (S1–S8) or Skill this helps

### Good first issues (ideas)

- Add `conn-<vendor>-example.json` for a log platform not yet in `examples/connectors/`
- Add synthetic host + network for a new demo zone
- Extend `examples/` offline input + expected `join_edges` for alert-confirmation or traceability
- Document one connector type in `docs_user/03-configure-data-sources.md` (and `03-configure-data-sources.zh-CN.md` if you update Chinese)

Open an Issue with the **Example DataAsset** template if you want maintainer feedback before coding.

## Licensing

Unless explicitly stated otherwise, contributions are accepted under the Apache License, Version 2.0, as included in `LICENSE`.

## Internationalization

- User-facing open-source entry points should be **English-first**.
- Keep Chinese copies as `*.zh-CN.md` in the **same directory** as the English file (`docs_dev/`, `docs_user/`, dataasset, skills, etc.).
- Developer, design, architecture, contribution, plugin, and integration docs live under **`docs_dev/`**.
- Security operator, SOC analyst, platform administrator, onboarding, and day-to-day usage docs live under **`docs_user/`**.
- DataAsset directory READMEs, Skills (`SKILL.md`, `rules.md`, etc.), examples, and tools docs follow the same pattern: English `*.md` + `*.zh-CN.md` sibling.
- DataAsset Studio strings belong in `dataasset-ui/i18n.js` (`en` and `zh` dictionaries).
- UI contributions are welcome: contributors may improve `dataasset-ui/`, add pages, or rewrite the UI, as long as the DataAsset file layout, `DATAASSET_ROOT`, `asset apply`, `validate.py --json/--diagnose`, and `credentials_ref` contracts remain intact. See [`docs_dev/25-ui-contribution-guide.md`](docs_dev/25-ui-contribution-guide.md).
- Markdown report templates live in `src/report_markdown.py` and should stay in English unless locale support is added explicitly.

## Documentation and release requirements

Follow [AGENTS.md](AGENTS.md): every code change must update its behavior documentation and English/Chinese siblings, document non-obvious implementation intent, and run the relevant gates. Agent packaged content changes require a new canonical `VERSION` before a new package is built. Record unavailable checks; a partial test run is not `make ci`.

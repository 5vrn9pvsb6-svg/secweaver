# SecWeaver CLI

`secweaver` is the local lightweight CLI for validating data assets, running offline demos, wrapping basic Skills, and generating Markdown reports.

**Languages:** English (primary) | [简体中文](13-SecWeaver-CLI.zh-CN.md)

---

## Quick start

```bash
make quickstart
```

After success, inspect:

```text
examples/reports/README.md
examples/reports/demo-*-output.json
```

Common commands:

```bash
make help
make validate
make validate-all-roots
make demo
make reports
make test
make ci
make ui
```

---

## Environment setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-data-access.txt
python3 src/secweaver.py --help
python3 src/secweaver.py list
```

---

## Validate data assets

```bash
python3 src/secweaver.py validate
python3 src/secweaver.py validate --strict
python3 src/secweaver.py validate --json
python3 src/secweaver.py validate --runtime-ready \
  --bundle bundle-incident-trace-default --json
python3 src/secweaver.py catalog sync
```

`make validate-all-roots` validates every checked-in `dataasset*` registry and
enforces `dataasset/configure/shared-contracts.json`. Files classified as
`shared` must be byte-identical, documented `override` files may differ, and
`root_owned` inventory stays local to one environment.

Check shared-contract drift before copying canonical `shared` files. This command
does not read credentials or replace `root_owned` environment inventory:

```bash
python3 src/dataasset/sync_shared_contracts.py --check
python3 src/dataasset/sync_shared_contracts.py --write
```

`--runtime-ready` statically traverses Bundle, Asset, Connector, agent-stream
sink, placeholder, and credential-ciphertext references, and folds in base
Schema/configuration errors from objects in the dependency graph. It never decrypts a
credential or contacts a backend. In JSON, `registry_valid` describes the whole
registry, each Bundle `status` describes that Bundle graph, and
`ready_for_execution` is true only when both pass. A zero exit status means the local execution
graph is ready for a live check; use `dataasset-connectivity-check` next to prove
reachability and data presence. Repeat `--bundle` to check selected Bundles, or
omit it to check every active Bundle.

Catalog format migration is preview-only unless `--write` is supplied:

```bash
python3 src/secweaver.py dataasset migrate --root dataasset_my --json
python3 src/secweaver.py dataasset migrate --root dataasset_my --write
DATAASSET_ROOT=dataasset_my python3 src/secweaver.py validate --strict
```

---

## Run offline demos

```bash
python3 src/secweaver.py demo all
python3 src/secweaver.py demo completeness
python3 src/secweaver.py demo alert
python3 src/secweaver.py demo traceability
python3 src/secweaver.py demo risk
```

Demo inputs:

| Demo | Input |
|---|---|
| `completeness` | `examples/data-source-completeness/s1-full-traceable.json` |
| `alert` | `examples/alert-confirmation/s4-webshell-attack-success.json` |
| `traceability` | `examples/traceability/s1-web-shell-to-ssh-lateral.json` |
| `risk` | `examples/risk-identification/s5-curl-download-exec-p0.json` |

---

## Generate Markdown reports

```bash
python3 src/secweaver.py report markdown \
  -i examples/reports/demo-alert-output.json \
  -o /tmp/alert-report.md

python3 src/secweaver.py report markdown --demo all --bundle
make reports
```

Outputs default to `examples/reports/`:

- `demo-*-output.md`
- `investigation-report.md`

---

## Data asset operations

```bash
python3 src/secweaver.py asset apply \
  -f dataasset/onboarding/examples/data-sources.sample.json \
  --dry-run
python3 src/secweaver.py asset init --connector-type sls --asset-type waf_alert --name demo-waf
python3 src/secweaver.py asset test <asset_id>
python3 src/secweaver.py asset test <asset_id> --plan
python3 src/secweaver.py asset test <asset_id> --dry-run
python3 src/secweaver.py asset discover-format asset-waf-api-prod \
  -i examples/log-format-discovery/waf-jsonl.sample
```

Use `asset apply` when operators should maintain data source onboarding through a JSON config file. Use `asset init` for one-off command-line generation.

Live production Skills query only `active` Assets through `active` Connectors.
The test, discovery, connectivity, and promotion commands may exercise
`draft/discovery` during onboarding; `disabled` is never queried.

When no sample file is supplied, `asset discover-format <discovery-asset-id>` first fetches a live sample. For advanced format-discovery flags (`--prompt`, `-o`, queue listing), use the underlying script:

```bash
python3 src/skills/log-format-discovery/scripts/discover.py --list-discovery
python3 src/skills/log-format-discovery/scripts/discover.py \
  --asset-id asset-waf-api-prod \
  -i examples/log-format-discovery/waf-jsonl.sample \
  --pretty -o /tmp/discovery-report.json --prompt /tmp/prompt.md
```

See [log-format-discovery](../src/skills/log-format-discovery/SKILL.md) and its [sample inputs](../examples/log-format-discovery/).

---

## Run a Skill directly

```bash
python3 src/secweaver.py skill alert-confirmation \
  -i examples/alert-confirmation/s4-webshell-attack-success.json

python3 src/secweaver.py skill traceability-analysis \
  -i examples/traceability/s1-web-shell-to-ssh-lateral.json

python3 src/secweaver.py skill data-source-completeness \
  -i examples/data-source-completeness/s1-full-traceable.json

python3 src/secweaver.py skill risk-identification \
  -i examples/risk-identification/s5-curl-download-exec-p0.json
```

Runnable with `secweaver skill` (the first four also have offline demos):

- `data-source-completeness` (`completeness`)
- `alert-confirmation` (`alert`)
- `traceability-analysis` (`traceability`)
- `risk-identification` (`risk`)
- `evidence-fetch` (`fetch`)
- `log-format-discovery` (`format-discovery`)
- `dataasset-connectivity-check` (`connectivity`)

`secweaver list` also shows workflow-only Skills. Use their linked `SKILL.md`
instead of `secweaver skill`: `prompt-risk-analysis` (prompts only),
`dataasset-validation-advisor`, `offline-showcase`,
`external-listener-cmd-risk`, and `external-listener-connect-risk`.

## Pass arguments to the underlying Skill

Pass extra script arguments after `--`:

```bash
python3 src/secweaver.py skill traceability-analysis \
  -i examples/traceability/s1-web-shell-to-ssh-lateral.json \
  -- --patterns dataasset/scenarios/anchor-patterns.json
```

The wrapper removes the separator before invoking the Skill. Input/output flags
may precede it as shown; flags after it are passed to the Skill script unchanged.

---

## CI boundary

GitHub Actions and local `make ci` run:

```text
setup → release scan → docs → SBOM → Agent → Attack Lab → all DataAsset roots → policy sync → tests → demos → final release scan
```

The final scan checks the reports regenerated by the demo step, including portable metadata paths.

See [`tests/README.md`](../tests/README.md).

Recommended usage:

```text
Automation / quick start: python3 src/secweaver.py
Daily analysis: request Skills in your AI agent (Cursor, Codex, Claude Code, OpenClaw, WorkBuddy, …) or use CLI only
Live data: configured SaaS SLS Proxy or customer-managed data sources with read-only credentials
```

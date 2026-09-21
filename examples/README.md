# SecWeaver Examples

Official offline sample library for SecWeaver Skills.

**Languages:** English (primary) | [简体中文](README.zh-CN.md)

## Layout

| Directory | Purpose |
|---|---|
| [`dataasset/`](../dataasset/) | Public configuration contracts and synthetic examples; configure real local assets using the onboarding guides |
| [`examples/`](.) | Offline payloads, investigation params, log samples |
| [`src/skills/`](../src/skills/) | Skill implementations and CLI wrappers |

```text
examples/
├── ai-showcase/
├── alert-confirmation/
├── data-source-completeness/
├── log-format-discovery/
├── prompt-risk-analysis/
├── risk-identification/
├── reports/
└── traceability/
```

## Skill chain

```text
data-source-completeness
        │
        ├──▶ alert-confirmation ──(success)──▶ traceability
        ├──▶ traceability
        └──▶ risk-identification ──(P0)──▶ traceability

log-format-discovery ──▶ dataasset (discovery → draft → active)
```

## Quick run

For a credential-free agent experience, run `make quickstart`, open this repository
in Codex or another supported agent, and ask `Run the SecWeaver offline showcase.` See
the [agent Showcase catalog](ai-showcase/README.md).

```bash
python3 src/secweaver.py demo all
python3 src/secweaver.py demo completeness
python3 src/secweaver.py demo alert
python3 src/secweaver.py demo risk
python3 src/secweaver.py demo traceability

# Save all four demo JSON reports to a directory, including names with dots.
python3 src/secweaver.py demo all -o /tmp/secweaver-offline.v1
```

For `demo all`, `-o` is always a directory (created if needed); an existing
regular file is rejected. For one demo, `-o` accepts a JSON filename or an
existing directory, including a directory whose name contains dots.

Log format discovery via CLI:

```bash
python3 src/secweaver.py asset discover-format asset-waf-api-prod \
  -i examples/log-format-discovery/waf-jsonl.sample
```

## Sample inventory

For each sample's situation, expected outcome and evidence limits, read the
[offline case catalog](CASE-CATALOG.md).

There are **27 distinct executable assessment inputs** across four Skills. The
27 Showcase routes cover these inputs once each; the four committed demo reports are
outputs, not additional cases. Prompt analysis has two fetch inputs and one
schema-checked golden report, but its human reasoning is not executable as a
deterministic Python Skill. Format discovery has six raw log samples, all
covered by the format-detection regression below.

| Skill | Directory | Scenarios |
|---|---|---|
| Agent showcase | [ai-showcase/](ai-showcase/) | 27 routed cases (all by default) |
| Data source completeness | [data-source-completeness/](data-source-completeness/) | 8 executable inputs |
| Alert confirmation | [alert-confirmation/](alert-confirmation/) | 5 executable inputs |
| Risk identification | [risk-identification/](risk-identification/) | 11 executable inputs (exec, connect, account, transfer, whitelist, SSH threshold pair, persistence, DNS) |
| Traceability | [traceability/](traceability/) | 3 executable inputs |
| Sample reports | [reports/](reports/) | 4 demo outputs |
| Prompt risk analysis | [prompt-risk-analysis/](prompt-risk-analysis/) | 2 fetch inputs + 1 JSON golden report |
| Format discovery | [log-format-discovery/](log-format-discovery/) | 6 raw samples |

Run all assessment inputs against the CLI, their `_meta` expectations and output
Schemas, plus all raw format samples against the detector and WAF/host-exec normalized previews, without credentials
or network calls:

```bash
.venv/bin/python -m unittest discover -s tests -p test_skill_catalog_and_output_contracts.py -v
```

The prompt-only Skill's golden report verifies structure, not the quality or
repeatability of a model's reasoning. Connector/live-fetch behavior and external
notification delivery require separate integration testing.
Offline regressions also perturb alert and traceability evidence to verify that
the conclusions weaken when corroboration or correlation keys disappear. This
does not measure precision or recall in a real environment.

## Maintenance rules

1. Sample JSON uses canonical fields aligned with fetch normalization.
2. Each JSON should include `_meta` with `scenario_label` and `expected_*` fields.
3. Re-run the corresponding Skill script and the offline example regression after adding scenarios.
4. Do not store credentials or production connector configs here.

## Related docs

- [Cross-source field correlation](../docs_user/21-cross-source-field-correlation.md) (Chinese)
- [Skills overview](../src/skills/README.md)
- [DataAsset design](../docs_dev/09-data-asset-design.md) (Chinese)

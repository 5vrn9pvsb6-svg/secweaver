# SecWeaver Project Skills

**Languages:** English (this page) | [简体中文](README.zh-CN.md)

This directory holds shared **Agent Skills**. Each defines its workflow in `SKILL.md`; deterministic skills provide `scripts/`, while prompt-only skills may contain just prompts and references. See the separate contribution paths in the [developer guide](../../docs_dev/02-developer-guide.md).

**Agent-neutral:** The same Skills work with **Cursor, Codex, Claude Code (CC), OpenClaw, WorkBuddy**, and other intelligent agents that support Skill / rule loading. The `src/skills/` path is the canonical implementation; thin adapters point here instead of copying it.

**Platform architecture:** [docs_dev/06-secweaver-architecture-and-features.md](../../docs_dev/06-secweaver-architecture-and-features.md)

## Intelligent agent integration and loading

| Intelligent agent | Typical loading |
|------|-----------------|
| **Cursor** | Skills 在 `src/skills/`；对话中 `@src/skills/<name>/SKILL.md` 引用，或在项目 Rules 中说明路径（不再使用 `.cursor/skills` 符号链接） |
| **Claude Code (CC)** | Project `CLAUDE.md` / skills config points here, or `@` reference `SKILL.md` in chat |
| **Codex** | Workspace rules or skill manifest includes `src/skills` |
| **OpenClaw** | Claw / skill registry mounts this repo skills path |
| **WorkBuddy** | Local-project Skill adapter points to this repository path; it is not a standalone Marketplace package |
| **No agent** | Run `scripts/*.py` or `src/secweaver.py skill …` directly (agent-independent) |

Generate a repository-local adapter with `make ai-setup HOST=<host>`. Copyable
configuration, screen-by-screen setup, expected results, and troubleshooting are
documented in [Intelligent Agent Setup](../../docs_user/38-ai-agent-host-setup.md).

**Roles:**

```text
Skill (SKILL.md + scripts)  →  capability contract, agent-neutral
Agent (Cursor / CC / Codex / OpenClaw / WorkBuddy …)  →  read SKILL.md, call scripts, optional LLM narrative
CLI (secweaver.py)          →  deterministic entry when no agent
```

When adding or changing Skills, maintain **one** `SKILL.md` only; do not duplicate logic per agent.

If a Skill should be runnable from the local CLI (`secweaver skill ...` or `secweaver demo ...`), register it in [`manifest.json`](manifest.json). See the contributor workflow in [`docs_dev/02-developer-guide.md`](../../docs_dev/02-developer-guide.md).

`manifest.json` is the single Skill catalog. Every top-level Skill appears there
with a `kind` (`assessment`, `fetch`, `operation`, `prompt`, `router`, or
`subskill`), its canonical documentation path, and whether it has a CLI entrypoint.
Machine-executable Skills with a stable JSON contract declare `output_schema`;
prompt-only and routing Skills intentionally have no script. Add a catalog entry before
adding a new Skill
directory so `secweaver list`, documentation checks, and contract tests see the same
surface.

Shared Python code has two layers: [_shared/data-access/](_shared/data-access/README.md)
owns evidence transport/normalization and scenario fetch expansion;
[_shared/skill_runtime/](_shared/skill_runtime/README.md) owns Skill input adapters,
completeness prechecks and cross-Skill invocation. Individual Skills retain their
rules. Historical `skill_input`, preparation and pipeline entries remain compatible.

## Report fetch statistics (all analysis Skills)

Any Skill that pulls or consumes `evidence_bundles` must surface **`fetch_summary`** in JSON output and lead Markdown reports with **数据取数统计** (assets, event counts by type, time window, truncation). Shared helper: `_shared/data-access/fetch_summary.py`.

| Skill | Directory | Description |
|---|---|---|
| Data asset connectivity | [dataasset-connectivity-check/](dataasset-connectivity-check/SKILL.md) | Probe active assets; distinguish connection, returned data and unassessed scenario coverage |
| Data source completeness | [data-source-completeness/](data-source-completeness/SKILL.md) | Assess data sufficiency before traceability / alert confirmation |
| Traceability analysis | [traceability-analysis/](traceability-analysis/SKILL.md) | Reconstruct cross-source attack chains and lateral paths |
| **Alert confirmation** | [alert-confirmation/](alert-confirmation/SKILL.md) | WAF/WEB alert FP vs real vs success triage |
| **Risk identification** | [risk-identification/](risk-identification/SKILL.md) | Host exec/connect P0–P3 triage |
| **Evidence fetch** | [evidence-fetch/](evidence-fetch/SKILL.md) | Fetch evidence_bundles only — for LLM or downstream Skills |
| **Prompt risk analysis (OSS)** | [prompt-risk-analysis/](prompt-risk-analysis/SKILL.md) | Prompt-only triage after evidence-fetch — no scripts |
| **Offline showcase** | [offline-showcase/](offline-showcase/SKILL.md) | Run bundled synthetic cases without ES, SLS, or credentials |
| External listener command risk | [external-listener-cmd-risk/](external-listener-cmd-risk/SKILL.md) | exec sub-module rules |
| External listener connect risk | [external-listener-connect-risk/](external-listener-connect-risk/SKILL.md) | connect sub-module rules |
| **Data access layer** | [_shared/data-access/](_shared/data-access/README.md) | dataasset + SOPS Vault → normalized evidence; includes **correlation_engine** |
| **Data asset validation advisor** | [dataasset-validation-advisor/](dataasset-validation-advisor/SKILL.md) | Run validate.py, categorize errors, suggest fixes |
| **Cross-source correlation** | [docs_user/21-cross-source-field-correlation.md](../../docs_user/21-cross-source-field-correlation.md) | Field join rules and traceability chaining |
| **Example data** | [examples/](../../examples/) | Offline test payloads at repo root (per Skill) |
| **Format discovery** | [log-format-discovery/](log-format-discovery/SKILL.md) | Only `status=discovery` queue in dataasset ([design](../../docs_dev/20-log-format-discovery-design.md)) |

## Skill chain

```text
[new log] register discovery asset → log-format-discovery (--asset-id)
                                   ↓
dataasset/bundles + SOPS Vault
        ↓
_shared/data-access/  or  evidence-fetch (--from-bundle)
        ↓
evidence_bundles ──┬──▶ prompt-risk-analysis (OSS prompt triage)
                   ├──▶ risk-identification / assess.py (deterministic rules; included in Community)
                   ├──▶ data-source-completeness
                   ├──▶ alert-confirmation ──(success)──▶ traceability-analysis
                   └──▶ traceability-analysis
```

## Credential rules

- Asset definitions: [`dataasset/`](../../dataasset/)
- Local Vault: [`dataasset/credentials/`](../../dataasset/credentials/)
- Skills / LLM: see only `credentials_ref`, never plaintext secrets
- Decrypt and fetch: `_shared/data-access/vault.py` + `fetch.py` (platform side)

## Directory layout

```text
src/skills/
├── README.md
├── _shared/data-access/     # registry / vault / fetch / scenario planning
├── _shared/skill_runtime/   # input adapters / assessment invocation / pipelines
├── evidence-fetch/          # multi-source fetch (no triage)
├── prompt-risk-analysis/    # OSS prompt triage (PROMPT.md only, no scripts)
├── data-source-completeness/
├── dataasset-validation-advisor/
├── traceability-analysis/
├── alert-confirmation/
├── risk-identification/
├── external-listener-cmd-risk/
├── external-listener-connect-risk/
└── log-format-discovery/   # new log format onboarding (discover.py + LLM mapping)
```

## New data source onboarding

```text
sample logs → log-format-discovery (discover.py preprocess + LLM mapping)
            → evidence-minimum-fields / normalizer / templates / assets
            → validate.py → test_connector.py
```

Docs: [complete onboarding](../../docs_user/03-configure-data-sources.md) | [field discovery and normalization](../../docs_user/20-log-format-discovery.md) | [short FAQ](../../docs_user/16-data-source-onboarding-faq.md)

## Quick examples

Offline test data: [examples/](../../examples/). Run from repo root:

For the fastest intelligent-agent experience, run `make quickstart`, open the repository in
Codex or another supported intelligent agent, and ask `Run the SecWeaver offline showcase.` The
case catalog and expected product value are documented in
[`examples/ai-showcase/`](../../examples/ai-showcase/README.md).

```bash
# Completeness precheck
.venv/bin/python src/skills/data-source-completeness/scripts/check.py \
  -i examples/data-source-completeness/s1-full-traceable.json

# Alert confirmation
.venv/bin/python src/skills/alert-confirmation/scripts/confirm.py \
  -i examples/alert-confirmation/s4-webshell-attack-success.json

# Risk identification
.venv/bin/python src/skills/risk-identification/scripts/assess.py \
  -i examples/risk-identification/s5-curl-download-exec-p0.json

# Traceability correlation
.venv/bin/python src/skills/traceability-analysis/scripts/correlate.py \
  -i examples/traceability/s1-web-shell-to-ssh-lateral.json

# Format discovery Step 1: requires discovery-status asset
.venv/bin/python src/skills/log-format-discovery/scripts/discover.py --list-discovery
.venv/bin/python src/skills/log-format-discovery/scripts/discover.py \
  --asset-id asset-waf-api-prod \
  -i src/skills/log-format-discovery/samples/waf-jsonl.example --pretty

# Single Skill (built-in dataasset + Vault)
.venv/bin/python src/skills/data-source-completeness/scripts/check.py --from-bundle \
  --params '{"attacker_ip":"203.0.113.10"}'

# Pipeline
.venv/bin/python src/skills/_shared/data-access/run_pipeline.py risk-chain \
  --bundle bundle-host-risk-default \
  --params '{"host":"web-01","time_start":"...","time_end":"..."}' \
  --pretty

.venv/bin/python src/skills/_shared/data-access/run_pipeline.py trace-chain \
  --params '{"attacker_ip":"203.0.113.10","time_start":"...","time_end":"...","host":"web-01"}' \
  --fetch --pretty
```

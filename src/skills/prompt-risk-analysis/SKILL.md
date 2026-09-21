---
name: prompt-risk-analysis
description: >-
  SecWeaver OSS prompt investigation: after evidence-fetch, senior-expert AI
  triage; read correlation-cheatsheet first, then matrix/anchor for joins.
  For 提示词研判, expert LLM narrative after fetch.
---

# Prompt Risk Analysis (Open Source)

This `SKILL.md` is the normative workflow source. `SKILL.zh-CN.md` is its localized mirror; update both files when changing required workflow steps.

SecWeaver Skill: **fetch with evidence-fetch, judge as a senior expert** — prompts only, no Python.  
The AI must act as a **senior security analyst**, exercising initiative and industry experience. Files like `policy-lite` are **reference baselines**, not exhaustive checklists to parrot.

**Pair with:** [evidence-fetch](../evidence-fetch/SKILL.md) only.

## Pipeline

```text
evidence-fetch  →  evidence_bundles + fetch_summary
        ↓
Agent reads PROMPT.md + correlation-cheatsheet (first)
        + evidence + matrix/anchor (as needed)
        ↓
Investigation report (expert insight + evidence citations)
```

| Step | Tool | Deterministic? |
|------|------|----------------|
| Fetch | `evidence-fetch` | Yes |
| Verdict / narrative | PROMPT + expert AI (initiative, experience) | No (human reviews) |

## When to use

- OSS users need **expert-grade** investigation narrative, not fixed rule engines.
- One-off investigations, breach narrative, “what happened on host X”.
- `policy-lite.md` as team defaults; experts may deviate with stated rationale.

## Capability boundaries

This skill does **not** provide:

- Versioned, machine-regression rule output (no `policy_rule_id` contract).
- Low-cost 24/7 auto-triage at very high event volume.
- Dedicated cross-source correlation engine (narrative chaining in reports only, with stated confidence).

## Workflow (evidence-fetch CLI only)

```bash
python3 src/skills/evidence-fetch/scripts/fetch_evidence.py \
  --asset-id asset-secweaver-host-exec \
  --asset-id asset-secweaver-sys-risk-alert \
  --params '{"hosts":["192.0.2.91"],"time_start":"2026-06-20T00:00:00+08:00","time_end":"2026-07-03T23:59:59+08:00"}' \
  -o /tmp/fetch.json
```

Optional: `--format markdown` for human browsing; triage still uses `evidence_bundles` in JSON.

## Agent workflow

1. Run **evidence-fetch** (or load existing fetch JSON / offline `examples/prompt-risk-analysis/`).
2. Adopt the **senior security analyst** role per **PROMPT.md** / **PROMPT.zh-CN.md**.
3. **Read first** [analysis-contract.md](analysis-contract.md) for scenario, counting, success, WAF coverage, and redaction; then read [correlation-cheatsheet.md](correlation-cheatsheet.md) for joins and fetches.
4. Analyze `evidence_bundles`; `policy-lite` is optional reference only.
5. **Report `fetch_summary` first** (assets pulled, event counts by type, time window, truncation) before expert narrative.
6. When volume is high, sample and document scope; output **chain_coverage**, **join_refs**, **fetch_next** (see output-schema.json).
7. Offline practice: exec/syslog and WAF-bypass fixtures under `examples/prompt-risk-analysis/`.

## Files

| File | Role |
|------|------|
| [PROMPT.zh-CN.md](PROMPT.zh-CN.md) | Main instructions (Chinese) |
| [PROMPT.md](PROMPT.md) | English prompt |
| [analysis-contract.md](analysis-contract.md) | **Normative** scenario, parameter, evidence, counting, WAF, and redaction contract |
| [analysis-contract.zh-CN.md](analysis-contract.zh-CN.md) | Chinese mirror of the analysis contract |
| [correlation-cheatsheet.zh-CN.md](correlation-cheatsheet.zh-CN.md) | **Read first** — windows, scenarios, joins, fetch templates |
| [correlation-cheatsheet.md](correlation-cheatsheet.md) | English cheatsheet |
| [correlation-matrix.json](../../../dataasset/assets/correlation-matrix.json) | Full join spec |
| [anchor-patterns.json](../../../dataasset/scenarios/anchor-patterns.json) | S1–S8 patterns and bundles |
| [policy-lite.md](policy-lite.md) | Optional alert/suppress baseline |
| [output-schema.json](output-schema.json) | Strict structured-output contract |
| [examples/prompt-risk-analysis/](../../../examples/prompt-risk-analysis/) | Offline fetch + golden report |
| [examples.md](examples.md) | End-to-end CLI samples |

## Related

- [evidence-fetch/SKILL.md](../evidence-fetch/SKILL.md)

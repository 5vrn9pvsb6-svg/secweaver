# Traceability Analysis

**Languages:** English (this page) | [简体中文](18-traceability-analysis.zh-CN.md)

Where did an intrusion start, how did it spread, and what scope can be proven?

## 1. Run a Fixed Offline Sample

Run `make quickstart` from the repository root, then ask your intelligent agent:

```text
Run the SecWeaver offline case webshell-to-ssh-lateral.
Reconstruct initial entry, host execution, SSH lateral movement, and scope. Cite the timeline and join edges, separating facts from hypotheses.
```

The case uses [examples/traceability/s1-web-shell-to-ssh-lateral.json](../examples/traceability/s1-web-shell-to-ssh-lateral.json) and the `traceability-analysis` Skill.
Inputs are synthetic; no production query occurs. The AI must follow the Skill,
not merely repeat script output.

Without an intelligent agent, run deterministic analysis first:

```bash
make ai-showcase CASE=webshell-to-ssh-lateral
```

## 2. Read the Result

JSON appears at `outputs/ai-showcase/webshell-to-ssh-lateral.json`; the AI-authored Skill report
is saved beside it. The CLI command also produces a readable structured-result Markdown report;
the agent completes the evidence review and full Skill report by default.

This fixed fixture expects `overall_verdict=confirmed_intrusion_chain`, `blocked=false`; do not impose that answer on other data.

| Check | Acceptance |
|---|---|
| Verdict | Explain what happened, not only its severity |
| Evidence | Cite the events supporting key judgments and verify host/time |
| Correlation | Explain why events connect; temporal proximity alone is not causality |
| Gaps | State what cannot be confirmed; no logs does not mean no attack |
| Actions | Separate further collection from responses requiring authorization |

## 3. Use Real Data

First complete [SaaS SLS Proxy onboarding](30-sls-proxy-onboarding.md) or
[existing-source onboarding](03-configure-data-sources.md) and a read-only query check.
Specify actual Asset/Bundle IDs, asset root, host or IP, and a timezone-aware start/end.
Do not reuse fixture dates and IDs blindly against production.

Ask the AI:

```text
Use traceability-analysis for my specified authorized assets and time window.
Check completeness, retrieve evidence using the Skill, and cite key judgments and gaps.
Do not execute blocking, deletion, or isolation actions.
```

Supply missing targets/windows first; do not default to an unrestricted scan.
Credentials come from the local store, never from the prompt.

## 4. When Evidence Is Insufficient

Run completeness first for a live investigation. If the precheck blocks traceability, report missing evidence and onboarding actions instead of forcing a chain. A partial chain is not proof that unobserved hosts are safe.

If fixture results differ, check the selected case/input, CLI errors, and dependencies.
For empty live results, inspect time fields, aliases, permissions, and ingestion delay
before changing detection rules.

## 5. Further Reading

- [traceability-analysis contract](../src/skills/traceability-analysis/SKILL.md)
- [Design and implementation](../docs_dev/15-traceability-analysis-skill-design.md)
- [Data completeness](15-data-source-completeness.md)
- [Offline case catalog](../examples/ai-showcase/README.md)

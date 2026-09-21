# Risk Identification

**Languages:** English (this page) | [简体中文](19-risk-identification.zh-CN.md)

Which observed host behaviors need attention, and why?

## 1. Run a Fixed Offline Sample

Run `make quickstart` from the repository root, then ask your intelligent agent:

```text
Run the SecWeaver offline case reverse-shell-risk.
Explain the reverse-shell behavior, severity, evidence, MITRE mapping, and response priority. Do not execute response actions.
```

The case uses [examples/risk-identification/s5-reverse-shell-p0.json](../examples/risk-identification/s5-reverse-shell-p0.json) and the `risk-identification` Skill.
Inputs are synthetic; no production query occurs. The AI must follow the Skill,
not merely repeat script output.

Without an intelligent agent, run deterministic analysis first:

```bash
make ai-showcase CASE=reverse-shell-risk
```

## 2. Read the Result

JSON appears at `outputs/ai-showcase/reverse-shell-risk.json`; the AI-authored Skill report
is saved beside it. The CLI command also produces a readable structured-result Markdown report;
the agent completes the evidence review and full Skill report by default.

This fixed fixture expects `overall_verdict=high_risk_detected`, `summary.p0=1`; do not impose that answer on other data.

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
Use risk-identification for my specified authorized assets and time window.
Check completeness, retrieve evidence using the Skill, and cite key judgments and gaps.
Do not execute blocking, deletion, or isolation actions.
```

Supply missing targets/windows first; do not default to an unrestricted scan.
Credentials come from the local store, never from the prompt.

## 4. When Evidence Is Insufficient

This Skill evaluates observed events and same-host context, not a complete cross-host intrusion chain. Missing host logs must appear in coverage reminders/data gaps. A P0 item warrants investigation; destructive containment still requires explicit authorization.

If fixture results differ, check the selected case/input, CLI errors, and dependencies.
For empty live results, inspect time fields, aliases, permissions, and ingestion delay
before changing detection rules.

## 5. Further Reading

- [risk-identification contract](../src/skills/risk-identification/SKILL.md)
- [Design and implementation](../docs_dev/17-risk-identification-skill-design.md)
- [Data completeness](15-data-source-completeness.md)
- [Offline case catalog](../examples/ai-showcase/README.md)

## Operations Rule Ownership

Maintain routine detection patterns in `src/skills/risk-identification/rules/*.json`;
maintain alert/suppression/exception policy in `behavior-policy.md`.
Follow the [detection catalog](../src/skills/risk-identification/detection-catalog.md) and
[policy reference](../src/skills/risk-identification/behavior-policy.md).
Routine rule changes do not require Python edits. Keep platform alert/suppression policy
synchronized in `behavior-policy.md` and `rules/behavior-policy.rules.json`. Environment-scoped
exceptions use the still-enabled `whitelist.json`; follow the
[whitelist guide](../src/skills/risk-identification/whitelist.zh-CN.md) (Chinese). Use [traceability](18-traceability-analysis.md) for cross-host investigation.

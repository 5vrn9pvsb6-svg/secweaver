# Alert Confirmation

**Languages:** English (this page) | [简体中文](17-alert-confirmation.zh-CN.md)

Is the WAF alert real, and is there evidence that the attack succeeded?

## 1. Run a Fixed Offline Sample

Run `make quickstart` from the repository root, then ask your intelligent agent:

```text
Run the SecWeaver offline case webshell-attack-confirmation.
Explain the suspicious request, correlated host behavior, evidence IDs, and uncertainty. Distinguish attack intent from confirmed outcome.
```

The case uses [examples/alert-confirmation/s4-webshell-attack-success.json](../examples/alert-confirmation/s4-webshell-attack-success.json) and the `alert-confirmation` Skill.
Inputs are synthetic; no production query occurs. The AI must follow the Skill,
not merely repeat script output.

Without an intelligent agent, run deterministic analysis first:

```bash
make ai-showcase CASE=webshell-attack-confirmation
```

## 2. Read the Result

JSON appears at `outputs/ai-showcase/webshell-attack-confirmation.json`; the AI-authored Skill report
is saved beside it. The CLI command also produces a readable structured-result Markdown report;
the agent completes the evidence review and full Skill report by default.

This fixed fixture expects `alert_verdict=confirmed_attack`, `attack_outcome=success_confirmed`, `attack_success=true`; do not impose that answer on other data.

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
Use alert-confirmation for my specified authorized assets and time window.
Check completeness, retrieve evidence using the Skill, and cite key judgments and gaps.
Do not execute blocking, deletion, or isolation actions.
```

Supply missing targets/windows first; do not default to an unrestricted scan.
Credentials come from the local store, never from the prompt.

## 4. When Evidence Is Insufficient

Do not infer success from a WAF hit or an arbitrary command occurring afterward. Correlation must connect the same target, time window, and relevant behavior. Without supporting host or response evidence, retain an unknown outcome or the applicable confidence ceiling.

If fixture results differ, check the selected case/input, CLI errors, and dependencies.
For empty live results, inspect time fields, aliases, permissions, and ingestion delay
before changing detection rules.

## 5. Further Reading

- [alert-confirmation contract](../src/skills/alert-confirmation/SKILL.md)
- [Design and implementation](../docs_dev/14-alert-confirmation-skill-design.md)
- [Data completeness](15-data-source-completeness.md)
- [Offline case catalog](../examples/ai-showcase/README.md)

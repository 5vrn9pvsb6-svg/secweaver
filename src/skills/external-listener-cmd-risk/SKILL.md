---
name: external-listener-cmd-risk
description: >-
  Exec sub-module of risk-identification for commands run by externally
  listening processes. Use the parent deterministic engine for host_exec
  evidence, Web/API process abuse, WebShell and reverse-shell triage.
---

# External Listener Command Risk

This is the exec sub-module of `risk-identification`. Normalize raw exec events through DataAsset, then put them in the parent payload's `evidence_bundles.host_exec`; raw JSON Lines are not the `assess.py` input contract.

## Execution and output

Run the public offline fixture from the repository root:

```bash
python3 src/skills/risk-identification/scripts/assess.py \
  -i examples/risk-identification/s5-curl-download-exec-p0.json \
  -o /tmp/secweaver-exec-risk.json
```

The fixture also includes connect evidence. To analyze exec alone, set `"risk_modules": ["exec"]` at the top level of a custom payload; put host and time bounds in `params`. See [examples.md](examples.md) for complete inputs and output excerpts.

The parent applies **JSON detection → behavior-policy decisions → environment whitelist**. Detection severity is not final severity. Report the final `risk_items[]` fields, including `severity`, `policy_rule_id`, `recommended_action` and evidence references. Do not recompute alerts by manually matching Markdown, adding fixed confidence increments or skipping policy.

For example, an nginx child running ordinary `ls` can receive P1 from the default policy even without a detection-rule match. Do not automatically label ordinary commands P2/observe. Current rules and authorized environment configuration determine the result.

## References on demand

- [Rule ownership and configuration](rules.md): detection, policy and whitelist responsibilities.
- [Parent skill](../risk-identification/SKILL.md): completeness, retrieval, reporting and downstream work.
- [Operations handbook](../risk-identification/OPS-HANDBOOK.md): rule changes and validation.

This skill evaluates command risk. Alert confirmation and traceability use correlated evidence to determine per-alert attack success and lateral chains respectively.

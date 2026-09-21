# Command Risk Rule Reference

This page describes ownership; it is not loaded at runtime. Use the parent [risk-identification](../risk-identification/SKILL.md) execution path.

| Layer | Authoritative configuration | Responsibility |
|---|---|---|
| Detection | [exec-rules.json](../risk-identification/rules/exec-rules.json) | Pipeline matches, initial severity and tags |
| Behavior policy | [behavior-policy.rules.json](../risk-identification/rules/behavior-policy.rules.json) | Guardrails, mandatory alerts, operations noise reduction and default decisions |
| Environment whitelist | [whitelist.json](../risk-identification/whitelist.json) | Scoped suppression/downgrades after policy, preserving evidence and guardrails |

## Reading results

- Shells, reverse shells, download-and-execute, persistence changes and sensitive reads are distinct signals. A tool name alone does not determine final severity or attack outcome.
- `matched_rules` identifies detection matches; `policy_rule_id` identifies policy decisions. Do not interchange them.
- An ordinary command without detection matches can still receive P1 from `DEFAULT-ALERT`, as the nginx → ls example demonstrates.
- `scp`, DNS and outbound connections are transfer/network signals, not standalone exfiltration proof.
- Nearby connect/file_op events can add context; do not manually raise severity/confidence in the model. The parent engine produces the final result.

## Changes and verification

See the [detection catalog](../risk-identification/detection-catalog.md) for IDs, patterns and current detection grades, and the [rule pack reference](../risk-identification/rules/README.md) for JSON syntax. Keep policy rationale synchronized with JSON. See the [whitelist reference](../risk-identification/whitelist.md) for environment exceptions.

Verify final decisions with the [reproducible examples](examples.md), including positive and negative cases for each change. Do not treat pattern explanations in this page as importable rules.

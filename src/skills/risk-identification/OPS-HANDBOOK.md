# Risk Identification Operations Handbook

**Languages:** English | [简体中文](OPS-HANDBOOK.zh-CN.md). Updated: 2026-09-18.

For operators changing detection patterns, alert decisions, and environment exceptions. Start with the [user guide](../../../docs_user/19-risk-identification.md) for setup and first analysis, or [DESIGN](DESIGN.md) for module responsibilities. This page owns operational playbooks; the [rule reference](../../../docs_dev/18-risk-identification-engine-design.md) owns JSON syntax.

## 1. Locate the layer

| Symptom | Maintenance entry | Verify |
|---|---|---|
| Missing or incorrect detection label | `rules/exec-rules.json`, `connect-rules.json`, `dns-rules.json`, `persistence-rules.json`, `ssh-rules.json`, `syslog-rules.json` | `matched_rules` and initial severity |
| Detection exists but alert/severity is wrong | `behavior-policy.md` **and** `rules/behavior-policy.rules.json` | `policy_rule_id`, `alert_required`, final severity, hard guards |
| Behavior allowed only in one environment | `whitelist.json` | Scope, expiry, and out-of-scope counterexamples; see [whitelist guide](whitelist.md) |
| Cross-stage pattern needs adjustment | `rules/chain-patterns.json` | Traceability pattern matches; changing patterns does not itself change single-event decisions |
| Cross-host links are missing | `traceability-analysis` and correlation matrix | Completeness, join fields, time window |

An AI agent invoking `assess.py` through this Skill uses the same JSON engine as the CLI. Markdown records rationale and audit history; editing it alone does not change default execution. Label standalone prompt-based experiments explicitly; they do not mean the executable rules have changed.

## 2. Replay before editing

From the repository root, after installing Python dependencies, run the synthetic input:

```bash
python3 src/skills/risk-identification/scripts/assess.py \
  -i src/skills/risk-identification/scripts/input.example.json \
  -o /tmp/secweaver-risk-review.json
```

This is offline analysis, without live retrieval or notification. For live queries, first verify read-only onboarding. The default root is `dataasset/`; optionally isolate with `DATAASSET_ROOT=dataasset_my`. Set an authorized Bundle and a params file containing explicit hosts and a timezone-qualified window:

```bash
python3 src/skills/risk-identification/scripts/assess.py \
  --from-bundle --bundle "${RISK_BUNDLE_ID:?Set an authorized bundle ID}" \
  --params-file "${RISK_PARAMS_FILE:?Set a scoped params JSON file}" --fetch
```

Keep completeness prechecks enabled. Review individual evidence in `risk_items`, aggregate displays in `top_incidents`, detection labels in `matched_rules`, and the decision basis in `policy_rule_id`. `alert_required` is a decision flag, not proof that any notification was sent.

## 3. Playbook: false positives and suppression

1. Save sanitized input and baseline output; locate the detection, policy, or whitelist layer responsible.
2. Change both Markdown and JSON with the same rule ID for platform-wide policy. Restrict local exceptions to a specific whitelist scope; a command name alone is not a sufficient exception.
3. Keep a positive suppression sample and counterexamples for Web-origin command execution, reverse shells, and persistence that must remain alertable.
4. Compare `original_risk`, final `severity`, `alert_required`, `policy_rule_id`, and `alert_suppressed`. Hard guards and force-alert rules take precedence over suppression.
5. Update the Markdown revision history and pass section 5 before submitting. Do not remove a general detection pattern to hide a false positive.

## 4. Playbook: missed detection and aggregation

- No label on a new command: inspect field normalization, then extend detection JSON using the rule reference. If the label exists but no alert is required, inspect JSON policy and whitelist.
- SSH bursts: `assess.py` uses `params.ssh_brute_threshold` and `params.ssh_brute_window_sec` for burst admission and window size. Rule-pack `thresholds` set detection severity; policy may override it. Review all `ssh_brute_waves`.
- Syslog: the SSH module aggregates raw authentication failures. The syslog module handles account, sudo, and firewall events; avoid duplicate classification merely to increase counts.
- No TTY: `has_tty=false` is context; cron and MOTD can also lack a TTY. Combine listener, command, and evidence before concluding WebShell execution.
- Patterns: after editing `chain-patterns.json`, replay a public traceability sample. Successful retrieval alone does not validate analysis. Traceability owns cross-host narratives; the rule reference owns pattern syntax.

## 5. Acceptance and rollback

```bash
python3 src/skills/risk-identification/scripts/validate_policy_sync.py --strict
python3 -m unittest discover -s src/skills/risk-identification/tests -p 'test_*.py'
```

Synchronization checks catch issues such as missing IDs, not semantic equivalence between Markdown and JSON. Replay both positive and negative examples. Record rationale, expected and actual outcomes, and revision history in the PR. Engineering changes also need full CI.

Custom policy uses paired files supplied through `--behavior-policy` and `--behavior-policy-rules`; see the [Skill](SKILL.md) for policy/whitelist switches. For `detection_rules.rules_dir`, copy the complete rule pack before editing it. Fix invalid configuration rather than disabling policy or whitelist to conceal a load error.

If results regress, restore the matching Markdown/JSON versions from before this change and replay the same samples. Preserve other contributors' uncommitted work.

## 6. References

- [Detection catalog](detection-catalog.md): labels and severity.
- [Policy text](behavior-policy.md) and [maintenance notes](behavior-policy.zh-CN.md): Chinese natural-language rules and audit history; the executable JSON contract is language-independent.
- [Policy engine design](../../../docs_dev/19-behavior-policy-engine-design.md): conditions, precedence, and extension boundaries.
- [Rule reference](../../../docs_dev/18-risk-identification-engine-design.md): detection, policy JSON, and pattern fields.

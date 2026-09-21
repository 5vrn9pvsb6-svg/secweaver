# behavior-policy Declarative Engine Design

**Languages:** English (this document) | [Simplified Chinese](19-behavior-policy-engine-design.zh-CN.md)

**Document version:** v1.1
**Checked against current code:** 2026-09-21

This document describes the declarative `behavior-policy` engine. Its goal is to remove the old dual-track model where the Agent read markdown policy while CLI/CI behavior depended on handwritten Python logic in `behavior_policy.py`.

## 1. Problem

Before this design, the policy layer had two maintenance paths:

- The Agent followed `behavior-policy.md`.
- The CLI/CI path mirrored policy behavior in roughly 865 lines of Python.

Detection rules were already mostly configurable, but policy behavior changed frequently during operations. That made the Python mirror the largest remaining configuration gap.

## 2. Solution Overview

The v1 design introduces:

- `behavior-policy.md`: human-readable operating policy.
- `behavior-policy.rules.json`: machine-readable policy rules.
- `policy_engine.py`: declarative policy evaluator.
- `behavior_policy.py`: compatibility wrapper for existing callers.

v1 implemented the schema, rule pack, engine, delegation path, and tests. New CLI policy rules should normally be added through JSON rather than Python.

## 3. Rule Pack Structure

A policy pack contains:

Structural example with one rule only. It omits the full defaults, guardrails, and other policies; do not replace the default policy pack with it.

```json
{
  "version": "1.0.0",
  "policy_id": "example-ssh-policy",
  "default_behavior": {
    "rules": []
  },
  "rules": [
    {
      "id": "SSH-BRUTE-001",
      "tier": "force_alert",
      "modules": [
        "ssh"
      ],
      "when": {
        "matched_rules_any": [
          "ssh_bruteforce"
        ]
      },
      "decision": {
        "severity": "P0",
        "alert_required": true,
        "alert_suppressed": false,
        "verdict": "confirmed_attack",
        "recommended_action": "block_src_ip_and_investigate",
        "reason": "Many SSH authentication failures occurred in a short window"
      }
    }
  ]
}
```

Each rule declares a stable ID, tier, conditions, output behavior, and optional severity/verdict handling.

### 3.1 Tiers and Precedence

Rules are evaluated in this precedence order:

1. `hard_guardrail`
2. `force_alert`
3. `downgrade`
4. `default`

Higher-precedence tiers win. A downgrade cannot override a hard guardrail.

### 3.2 Conditions

The `when` block supports:

- boolean composition: `all`, `any`, `not`
- risk metadata: `risk_module`, `matched_rules_any`, `matched_rules_all`, `severity_in`
- command matching: `command_regex`, `command_contains`
- event fields: `event_type`, `dst_port_in`, `dst_ip_in`
- named logic: `predicate`
- guardrail state: `guardrail_matched`

This gives operators enough structure for most policy changes without requiring a new evaluator.

### 3.3 Predicate Registry

Reusable predicates now live in `behavior-policy.rules.json` and are built from shared conditions in `shared_conditions.py`. There is no separate hardcoded Python predicate registry for ordinary policy work.

Examples include:

- `is_web_entry`
- `is_sshd_session`
- `is_shell_command`
- `is_agent_sshd_monitor`
- `is_lab_setup`
- `is_agent_uninstall`
- `is_sshd_webshell_abuse`
- `is_trusted_deploy`
- `is_cloud_ops`
- `is_local_curl`

Connect and syslog-specific conditions can be shared through `when_extensions`.

### 3.4 Decision Extensions

Rules can use decision helpers such as:

- `severity_when`
- `inherit_severity`
- `inherit_verdict`
- `id_template`

These options keep common policy output patterns declarative.

## 4. Operations Workflow

To add an operational downgrade:

1. Add a rule such as `OPS-FOO-001` to both `behavior-policy.md` and `rules/behavior-policy.rules.json`.
2. Reference existing detection fields or predicates in `when`.
3. Set the desired behavior and severity handling.
4. Run policy validation.

To disable a rule temporarily, set `enabled: false` rather than deleting it.

Environment-specific policy packs are implemented. Set these fields in an offline payload:

```json
{
  "behavior_policy": {
    "path": "behavior-policy.lab.md",
    "rules_path": "rules/behavior-policy.lab.rules.json"
  }
}
```

The corresponding CLI flags are `--behavior-policy` and `--behavior-policy-rules`. The Markdown path supplies policy documentation; `rules_path` selects the rules executed by the CLI. Changing only the Markdown path does not select a different JSON policy.

## 5. Trace Profile vs. Policy Engine

| Area | Trace Profile | Policy Engine |
| --- | --- | --- |
| Purpose | Normalize and repair source evidence | Decide final alert behavior |
| Input | raw or normalized events | risk items from detection |
| Output | enriched normalized events | policy-adjusted risk items |
| Main operator change | log-shape adaptation | alerting behavior |
| Typical file | `trace-profiles/*.json` | `behavior-policy.rules.json` |

Trace profiles make evidence usable. Policy rules decide how to treat detected behavior.

## 6. Remaining Boundaries

The declarative engine does not remove every Python boundary. Python is still expected for:

- detection engines,
- new computed `when` fields,
- new condition types,
- assessment orchestration,
- `source_risk_map`.

Independent prompt-only experiments may interpret Markdown, but must be labeled separately. Default Skill/CLI calls to `assess.py` use JSON policy.

The goal is not to delete `behavior-policy.md`. The markdown file remains the operator-facing policy source.

## 7. Workload Status

The v1 work completed:

- schema definition,
- default policy pack,
- policy engine,
- delegation from compatibility wrapper,
- validation and tests.

The practical result is that almost all new CLI policy behavior can be added without editing Python.

## 8. Validation

Run:

```bash
make validate-policy
make test
```

For release cleanup, also run:

```bash
make docs-check
.venv/bin/python src/scripts/release_scan.py --json
```

## 9. Related Docs

- [Operations Handbook](../src/skills/risk-identification/OPS-HANDBOOK.md)
- [Design Notes](../src/skills/risk-identification/DESIGN.md)
- [Trace Profile Design](21-trace-profile-design.md)


## Policy Authoring Examples

Policy answers: **after detection has matched, should this item alert, and what is its
final severity?**

### Recommended Four-Step Workflow

```text
1. behavior-policy.md           Write the human-readable policy for operators and audit
2. behavior-policy.rules.json   Write the executable when + decision rule
3. predicates                   Extract conditions that multiple rules reuse
4. make validate-policy         Check Markdown and JSON rule IDs stay aligned
```

A minimal policy rule looks like this:

```json
{
  "id": "MY-RULE-001",
  "tier": "force_alert",
  "modules": ["exec"],
  "when": { "matched_rules_any": ["crypto_miner"] },
  "decision": {
    "severity": "P0",
    "alert_required": true,
    "alert_suppressed": false,
    "verdict": "confirmed_attack",
    "recommended_action": "isolate_host_and_investigate",
    "reason": "Mining activity from a web entry point requires investigation"
  }
}
```

| Field | Meaning |
| --- | --- |
| `id` | Globally unique ID, emitted as `policy_rule_id` |
| `tier` | `hard_guardrail`, `force_alert`, or `downgrade` |
| `modules` | Optional scope: `exec`, `connect`, `dns`, `persistence`, `ssh`, or `syslog` |
| `when` | Match expression evaluated by the shared condition DSL |
| `unless` | Optional array of explicit exceptions after `when` matches |
| `decision` | Final severity, alert behavior, verdict, action, and reason |

### Predicates: Reusable Composite Conditions

Move repeated conditions into the rule pack's `predicates` object. Operators can edit
these JSON definitions without adding a Python predicate.

This predicate recognizes a web entry point:

```json
"predicates": {
  "is_web_entry": {
    "any": [
      { "web_listener_process": true },
      { "listener_port_in": [80, 443, 8080, 8443] }
    ]
  }
}
```

A predicate can also combine a detection result with its module:

```json
"is_shell_command": {
  "all": [
    { "risk_module": "exec" },
    {
      "any": [
        { "matched_rules_any": ["external_listener_shell_exec"] },
        { "type": "shell_exe" }
      ]
    }
  ]
}
```

Reference it in a rule with `{ "predicate": "is_web_entry" }`. When adding a
predicate:

1. Add it under `predicates`.
2. Reference it from one or more `rules[]` entries.
3. Describe the business/security meaning in `behavior-policy.md`.
4. Run `make validate-policy` and positive and negative replays.

### Tier Examples

#### `force_alert`: Preserve a High-Confidence Alert

`DOWNLOAD-MALICIOUS-001` follows a detection label while keeping narrowly defined
operational exceptions:

```json
{
  "id": "DOWNLOAD-MALICIOUS-001",
  "tier": "force_alert",
  "modules": ["exec"],
  "when": { "matched_rules_any": ["download_and_execute"] },
  "unless": [
    { "predicate": "is_trusted_deploy" },
    { "predicate": "is_cloud_ops" },
    { "predicate": "is_local_curl" }
  ],
  "decision": {
    "severity": "P0",
    "alert_required": true,
    "alert_suppressed": false,
    "verdict": "confirmed_attack",
    "recommended_action": "isolate_host_and_investigate",
    "reason": "A remote script was downloaded and executed from an untrusted source"
  }
}
```

`WEB-SHELL-001` composes two reusable predicates:

```json
{
  "id": "WEB-SHELL-001",
  "tier": "force_alert",
  "modules": ["exec"],
  "when": {
    "all": [
      { "predicate": "is_web_entry" },
      { "predicate": "is_shell_command" }
    ]
  },
  "decision": {
    "severity": "P0",
    "alert_required": true,
    "alert_suppressed": false,
    "verdict": "confirmed_attack",
    "recommended_action": "isolate_host_and_investigate",
    "reason": "A descendant of a web listener executed a shell or system command"
  }
}
```

#### `downgrade`: Keep Evidence Without Alerting

Use a downgrade for a tightly scoped approved deployment path:

```json
{
  "id": "OPS-DEPLOY-001",
  "tier": "downgrade",
  "modules": ["exec"],
  "when": { "predicate": "is_trusted_deploy" },
  "decision": {
    "severity": "P3",
    "alert_required": false,
    "alert_suppressed": true,
    "verdict": "benign",
    "recommended_action": "log_only",
    "reason": "Approved platform agent deployment path"
  }
}
```

A lab setup rule can preserve the detection while suppressing the operational alert:

```json
{
  "id": "OPS-LAB-SETUP-001",
  "tier": "downgrade",
  "modules": ["exec"],
  "when": { "predicate": "is_lab_setup" },
  "decision": {
    "severity": "P3",
    "alert_required": false,
    "alert_suppressed": true,
    "verdict": "benign",
    "recommended_action": "log_only",
    "reason": "Lab setup creates the approved account and decoy credentials"
  }
}
```

#### `hard_guardrail`: Prevent Policy Downgrade

```json
{
  "id": "HARD-GUARDRAIL-REVERSE-SHELL",
  "tier": "hard_guardrail",
  "when": {
    "command_regex": "/dev/tcp/|bash -i|sh -i|\\bnc -e\\b",
    "flags": "i"
  },
  "decision": {
    "severity": "P0",
    "alert_required": true,
    "alert_suppressed": false,
    "verdict": "confirmed_attack",
    "recommended_action": "isolate_host_and_investigate",
    "reason": "Reverse-shell behavior cannot be downgraded"
  }
}
```

A hard guardrail may still contain a deliberately reviewed `unless` clause, such as a
dedicated lab predicate. Without that explicit exception, lower tiers cannot suppress it.

### Common `when` Forms

| Type | JSON example | Typical use |
| --- | --- | --- |
| Detection label | `"matched_rules_any": ["download_and_execute"]` | Follow a detection output |
| Predicate | `"predicate": "is_web_entry"` | Reuse composite logic |
| Command regex | `"command_regex": "curl.*\\|.*bash", "flags": "i"` | Inspect command evidence |
| Destination port | `"dst_port_in": [4444, 1337]` | Scope connect behavior |
| Module scope | `"modules": ["connect"]` | Limit a rule at its top level |
| Composition | `"all": [{...}, {...}]` or `"any": [...]` | Express AND/OR conditions |
| Exclusion | `"unless": [{ "predicate": "is_trusted_deploy" }]` | Declare a narrow exception |

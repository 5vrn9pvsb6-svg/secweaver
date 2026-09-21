# Detection Rule Configuration (Operations-Editable, v1.1)

**Languages:** English (this document) | [Simplified Chinese](README.zh-CN.md)

This directory contains **detection-layer** JSON rule packs. Changes take
effect the next time `assess.py` runs and normally require no Python change.
The loader performs lightweight structural validation, including required
fields and regular-expression syntax.

| File | Module | Purpose |
|---|---|---|
| **exec-rules.json** | host_exec | Command-execution patterns: regex, keyword, and structural rules |
| **connect-rules.json** | host_connect | Ordered `rules[]` plus port and CIDR lists |
| **ssh-rules.json** | ssh_auth | Brute-force thresholds, message parsing, and `brute_force_rule` output semantics |
| **dns-rules.json** | dns_log / host_connect | DNS query profiling and DoH/DoT connection characteristics |
| **persistence-rules.json** | host_persistence | Persistence-location changes |
| **syslog-rules.json** | syslog_risk_alert | Ordered `rules[]` and `message_rules[]` for sudo, account creation, firewall events, and similar signals; excludes raw SSH brute-force events |
| **attck-map.json** | Output enrichment | Maps `matched_rule` and `policy_rule_id` to MITRE ATT&CK techniques |
| **chain-patterns.json** | Cross-stage narrative | Attack playbooks with `id` and per-stage `stage_rules`; traceability reuses these as `matched_pattern` |
| **behavior-policy.rules.json** | Policy-layer CLI | Alert/noise-reduction `when` and `decision` rules; synchronized with [`behavior-policy.md`](../behavior-policy.md) |

For natural-language alert and suppression policy, read
[`behavior-policy.md`](../behavior-policy.md). The CLI executes
**`behavior-policy.rules.json`**, whose schema is
`../schema/behavior-policy-rules.schema.json`. The operational entry point is
the [Operations Handbook](../OPS-HANDBOOK.md).

> Top-level `_doc` entries explain configuration. Detection `verdicts`,
> `actions`, and `confidence` affect detection output but do **not** decide
> whether an alert is sent.

## Detection engine profiles (`engine`)

Each of the six detection `*-rules.json` files declares an **`engine`** type.
`rule_loader.validate_rule_pack` checks that the filename and engine agree.
Different Python modules interpret the profiles at runtime:

| `engine` | Rule packs | Runtime | Matching model |
|---|---|---|---|
| **`pipeline`** | `exec-rules.json` | `exec_rules.ExecRulesEngine` | Multi-stage structural -> P0/P1 regex -> keyword -> fallback -> `context_boost` |
| **`chain`** | `connect-rules.json`, `syslog-rules.json`, `persistence-rules.json` | `detection_rule_chain.RuleChainEngine` | Ordered `rules[]` plus `when`; connect uses computed context and handlers, while syslog also uses `message_rules[]` |
| **`aggregate`** | `ssh-rules.json`, `dns-rules.json` | `ssh_rules.SshRulesEngine`, `dns_rules.DnsRulesEngine` | SSH failure bursts, DNS query profiles, and DoH/DoT checks |

All modules use `detection_output.DetectionOutput` for common output semantics:
`risk_tags`, `verdicts`, `actions`, and `confidence_base`.

```json
{
  "version": "1.1",
  "engine": "chain",
  "rules": [],
  "verdicts": { "P0": "confirmed_attack" },
  "actions": { "P0": "isolate_host_and_investigate" },
  "confidence_base": { "P0": 0.85 }
}
```

Do not convert exec's readable regex sections into `rules[]`. Do not convert
SSH to `chain`; its algorithm is stateful aggregation.

## `exec-rules.json`

Every **pattern or keyword** must declare **`field`**, explicitly identifying
which `host_exec` field to match. The engine no longer builds an implicit
combined `cmd_text`.

### `match_fields` values

| `field` | Meaning |
|---|---|
| `command` | Space-joined command argv; falls back to `comm` when empty |
| `command_line` | Original one-line command string |
| `exe` | Executable path |
| `comm` | Short process name |
| `cwd` | Working directory |
| `listener_process` | Listening process name |

### Add a P1 regular expression

```json
{
  "id": "internal_recon",
  "field": "command",
  "pattern": "your-command-here",
  "flags": "i",
  "enabled": true,
  "note": "optional explanation"
}
```

Example matching an executable path:

```json
{
  "id": "suspicious_binary",
  "field": "exe",
  "pattern": "/tmp/\\.|[\\\\/]dev/shm/",
  "flags": "i",
  "enabled": true
}
```

Append the rule to `p1_regex`. Its `id` becomes a `matched_rule`; keep it aligned
with the [Detection Catalog](../detection-catalog.md).

### Temporarily disable a rule

Set the matching entry's `"enabled"` field to `false`; do not delete the pattern.

### `p3_keywords` for noisy commands

```json
{ "id": "noise_command", "field": "command", "keyword": "hostname", "enabled": true }
```

### `listener_context`

```json
"listener_context": {
  "empty_process_is_web": false
}
```

This controls whether an empty `listener_process` counts as web context. The
default comes from `exec-rules.json`.

The top-level **`"engine": "pipeline"`** field is required and must not change.

## `connect-rules.json`

In addition to list parameters, ordered **`rules[]`** define decisions:

| `when` condition | Meaning |
|---|---|
| `web_context` | Whether the event has web-listener context |
| `dst_private` | Whether the destination is a private IP |
| `dst_port_in` | A port is in `suspicious_ports` or `common_service_ports` |
| `exec_download_nearby` | A nearby exec contains curl or wget |
| `no_matched_rules` | No earlier rule matched |
| `severity_worse_than` | Current severity is lower than the named level |

Optional **`when_extensions`** map custom `when` keys to declarative condition
trees evaluated by `shared_conditions.eval_condition`, without Python changes:

```json
"when_extensions": {
  "high_risk_egress": {
    "all": [
      { "field_equals": { "field": "web_context", "value": true } },
      { "field_equals": { "field": "dst_private", "value": false } }
    ]
  }
}
```

Reference it as `"when": { "high_risk_egress": true }`. Computed fields such
as `web_context` and `exec_download_nearby` are still injected by the connect
engine. Adding a new computed semantic requires a one-time engine handler.

The top-level **`"engine": "chain"`** field is required.

## `ssh-rules.json`

```json
"thresholds": [
  { "min_count": 10, "severity": "P0", "enabled": true },
  { "min_count": 5, "severity": "P2", "enabled": true }
],
"brute_force_rule": {
  "matched_rule": "ssh_bruteforce",
  "policy_rule_id": "SSH-BRUTE-001",
  "risk_tags": ["credential_access", "brute_force"]
}
```

`thresholds` are matched from highest to lowest `min_count`.

`assess.py` explicitly supplies `params.ssh_brute_window_sec` (default 300) and
`params.ssh_brute_threshold` (default 10), so use those parameters when tuning
through that entry point. Direct engine calls without overrides use
`brute_force.window_sec` and `threshold` from the rule pack. `thresholds[]`
select detection severity only after the burst threshold is met. Policy rule
`SSH-BRUTE-001` may then raise the result to P0.

The top-level **`"engine": "aggregate"`** field is required. Along with
`brute_force_rule`, configure `risk_tags`, `verdicts`, `actions`, and
`confidence_base` using the common structure.

## `dns-rules.json` and `persistence-rules.json`

- `dns-rules.json` uses `engine: aggregate` and defines `nxdomain_burst`,
  `domain_profile`, `doh_dot`, and output semantics. Its runtime entry point is
  `scripts/dns_rules.py`.
- `persistence-rules.json` uses `engine: chain` and evaluates `rules[]` against
  persistence-event fields. Its runtime entry point is
  `scripts/persistence_rules.py`.
- `scenarios.json` or input `risk_modules` selects enabled modules. When a data
  source is absent, use `risk_modules_run` and coverage warnings to determine
  what actually ran.

## `syslog-rules.json`

The source is `asset-secweaver-sys-risk-alert` (`syslog-risk-json`). Raw SSH
brute-force events are excluded by **`exclude_event_types`**.

### Ordered `rules[]` by event type

```json
{
  "id": "firewall_event",
  "severity": "P1",
  "enabled": true,
  "when": { "event_type": "firewall_event" }
}
```

Supported conditions also include `event_type_in`, `rule_id_in`,
`risk_level_in`, `program_in`, `tags_contains`, and `user`.

Optional **`when_extensions`** work like connect extensions. Register custom
keys in the top-level object and reuse `shared_conditions` operators such as
`command_regex` and `matched_rules_any` without changing `syslog_rules.py`.

The top-level **`"engine": "chain"`** field is required.

### `message_rules[]` command/message regular expressions

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

## `behavior-policy.rules.json`

This is the policy-layer CLI rule pack. In addition to `rules[]`, **`predicates`**
defines reusable predicates such as `is_web_entry` and `is_sshd_session`.
Operators can edit predicates directly without Python changes.

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

Keep the Markdown and JSON policy synchronized with `make validate-policy`,
which runs `validate_policy_sync.py --strict`.

## `attck-map.json`

This file maps `matched_rule` and `policy_rule_id` to **MITRE ATT&CK Enterprise**:

```json
{
  "matched_rules": {
    "webshell_write": {
      "techniques": [
        { "id": "T1505.003", "name": "Web Shell", "tactic": "persistence", "tactic_id": "TA0003" }
      ]
    }
  },
  "policy_rules": {
    "WEB-SHELL-001": {
      "techniques": [
        { "id": "T1505.003", "name": "Web Shell", "tactic": "persistence", "tactic_id": "TA0003" }
      ]
    }
  }
}
```

The engine writes `risk_items[].mitre_attack` and aggregates
`summary.top_mitre_techniques`.

## `chain-patterns.json`

This v1.0 file describes cross-stage attack narratives. Continue to edit
exec/connect/SSH rule packs for single-event detection; this file names a
playbook only after multiple stages are present.

```json
{
  "stage_mitre_defaults": {
    "initial_access": "T1190",
    "execution": "T1059",
    "lateral_movement": "T1021.004"
  },
  "chain_patterns": [
    {
      "id": "web_shell_to_ssh_lateral",
      "name": "WebShell -> tool download -> SSH lateral movement",
      "stages": ["initial_access", "execution", "lateral_movement"],
      "stage_rules": {
        "initial_access": ["webshell_write", "WEB-SHELL-001"],
        "execution": ["download_and_execute", "LATERAL-SSH-001"],
        "lateral_movement": ["root_ssh_login", "LATERAL-SSH-001"]
      },
      "policy_rules": ["WEB-SHELL-001", "LATERAL-SSH-001"]
    }
  ]
}
```

| Field | Meaning |
|---|---|
| `chain_patterns[].id` | Playbook ID, also emitted as traceability `matched_pattern` |
| `stages` | Kill-chain stages that must all have a match |
| `stage_rules` | At least one `matched_rule` or `policy_rule_id` that must match per stage |
| `policy_rules` | MITRE policy keys added after a playbook matches; see `attck-map.json` |

`traceability-analysis` consumes this through
`risk_rules_bridge.load_trace_patterns()`. Do not maintain a parallel copy under
traceability. See the [Operations Handbook playbook](../OPS-HANDBOOK.md).

## Custom paths (optional)

`assess.py` payload:

```json
{
  "detection_rules": {
    "rules_dir": "/path/to/custom/rules",
    "exec": "/path/to/exec-rules.json"
  }
}
```

Specify only `rules_dir` to load the standard filenames from that directory.

## Validation

```bash
python3 -m unittest discover -s src/skills/risk-identification/tests -p "test_*.py"
python3 -m unittest discover -s src/skills/risk-identification/scripts/tests -p "test_*.py"
```

## Notes

- Escape regular-expression backslashes twice in JSON, for example `\\b` and `\\.`.
- Replay positive and negative cases in an isolated exercise environment after changing detection rules.
- When policy refers to a new `matched_rule` type, update `behavior-policy.md` and its executable JSON together.

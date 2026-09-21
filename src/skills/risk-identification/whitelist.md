# Risk Identification Whitelist Guide

The risk identification whitelist applies unified noise reduction before various risk identification Skill outputs. It does not delete matched risk evidence; it keeps original hits in `risk_items[]` and marks whether the risk still requires an alert.

## 1. When to use whitelist

Good candidates for whitelist rules:

- Confirmed fixed behavior from business, ops, collectors, or cloud platform initialization.
- Commands, destinations, listener entry, and host scope are relatively stable.
- Risk rules fire but manual review confirmed no alert needed.

Poor candidates:

- One-off “looked fine this time” behavior that cannot be stably reproduced.
- Clear attack signatures: reverse shell, WebShell, arbitrary public download-and-execute.
- Overly broad rules — e.g. allowlisting only on `curl`, `bash`, or `sshd`.

## 2. Single config file

**Maintain only one file:**

`src/skills/risk-identification/whitelist.json`

Serves:

- `risk-identification` orchestration layer
- `external-listener-cmd-risk` exec sub-module
- `external-listener-connect-risk` connect sub-module

`whitelist.example.json` is template reference only; runtime reads `whitelist.json` first.

First-time setup:

```bash
cp src/skills/risk-identification/whitelist.example.json \
  src/skills/risk-identification/whitelist.json
```

**Deprecated:** `user_rules.whitelist_ports`, `user_rules.whitelist_exe_prefixes`, `user_rules.dst_cidrs` in payload. If still passed, a warning is emitted but they do not apply.

## 3. Execution flow

Risk identification flow:

```text
source-unique evidence → detection → behavior policy → whitelist → final output
```

Whitelist is **post-detection**:

- Run risk rules first; keep `matched_rules[]`, `summary`, evidence refs complete.
- Then check whitelist match on risk items.
- On hit: downgrade or suppress alert — do not delete the risk item.

Policy `hard_guardrail`/`force_alert` decisions and `policy_forced_alert` cannot be
overridden by whitelist rules and do not generate whitelist hits. A downgrade to
P2/P3 sets `alert_required=false`; absent `target_action`, the action becomes
`observe`/`log_only`. Downgrading never reactivates an already suppressed alert.

## 4. Output fields after whitelist hit

Hit whitelist adds these fields on each `risk_item`:

| Field | Description |
|---|---|
| `whitelisted` | Whether whitelist matched |
| `whitelist_rule_id` | Matched whitelist rule ID |
| `whitelist_action` | e.g. `suppress` / `downgrade` |
| `whitelist_reason` | Whitelist reason |
| `original_risk` | Original detection decision retained from policy, or pre-whitelist values when absent |
| `pre_whitelist_risk` | Severity, verdict, action and confidence immediately before whitelist |
| `alert_required` | Whether alert still required |
| `alert_suppressed` | Whether alert was suppressed |

`summary` also includes:

| Field | Description |
|---|---|
| `alert_required` | Count still requiring alert |
| `alert_suppressed` | Count suppressed by whitelist |

## 5. Rule structure

Basic whitelist file structure:

```json
{
  "version": "1.0",
  "defaults": {
    "enabled": true,
    "mode": "post_detection",
    "keep_evidence": true
  },
  "rules": [
    {
      "id": "wl-example-rule",
      "enabled": true,
      "description": "Rule description",
      "scope": {
        "risk_modules": ["exec"],
        "matched_rules_any": ["download_and_execute"],
        "listener_process": ["sshd"],
        "listener_ports": [22],
        "command_regex": "fixed-safe-command-pattern"
      },
      "action": "suppress",
      "target_severity": "P3",
      "target_verdict": "benign",
      "target_action": "log_only",
      "reason": "Manually confirmed whitelist reason"
    }
  ]
}
```

## 6. scope fields

`scope` match conditions are **AND** — all must match.

| Field | Type | Description |
|---|---|---|
| `risk_modules` | array | e.g. `exec`, `connect`, `file` |
| `hosts` | array | Hostname allowlist scope |
| `listener_process` | array | Entry listener process e.g. `sshd`, `nginx`, `java` |
| `listener_ports` | array | Entry ports e.g. `[22]`, `[80, 443]` |
| `dst_cidrs` | array | Egress destination CIDRs e.g. `10.0.0.0/8` |
| `dst_ports` | array | Egress destination ports |
| `matched_rules_any` | array | Match any one risk rule |
| `matched_rules_all` | array | Must match all listed risk rules |
| `severity_at_or_above` | string | Process risks at or above level e.g. `P1` = P0/P1 |
| `command_regex` | string | Command-line regex |
| `exe_regex` | string | Executable path regex |
| `exe_prefixes` | array | Executable path prefixes e.g. `["/opt/ops/"]` |
| `summary_regex` | string | Risk summary regex |

Recommend combining ≥3 conditions, e.g.:

- `risk_modules + matched_rules_any + command_regex`
- `listener_process + listener_ports + exe_regex + command_regex`
- `hosts + dst_cidrs + dst_ports + matched_rules_any`

## 7. action modes

### suppress: suppress alert

For events confirmed benign but evidence should be kept.

Effect:

```json
{
  "severity": "P3",
  "verdict": "benign",
  "recommended_action": "log_only",
  "alert_required": false,
  "alert_suppressed": true
}
```

### downgrade: reduce risk level

For not fully benign but should not alert at P0/P1.

Example:

```json
{
  "action": "downgrade",
  "target_severity": "P2",
  "target_verdict": "suspicious",
  "target_action": "observe",
  "target_confidence": 0.4
}
```

## 8. Built-in default rules

`whitelist.json` includes these defaults; adjust `enabled` or remove per environment:

| Rule ID | Module | Description |
|---|---|---|
| `wl-aliyun-metadata-region-curl` | exec | Aliyun metadata region-id query |
| `wl-ilogtail-loongcollector-grep` | exec | LoongCollector path grep patrol |
| `wl-nginx-config-test` | exec | `nginx -t` config test |
| `wl-ops-exe-prefix` | exec | `/opt/ops/` ops script directory |
| `wl-sshd-interactive-noise` | exec | SSH port 22 login session default noise reduction |
| `wl-listener-port-shell-exec` | exec | Port 22 shell exec default downgrade |
| `wl-connect-trusted-public-api` | connect | Business public API egress (default disabled) |

## 9. Example 1: Aliyun metadata query

Historical example: an older/custom detector labeled a metadata-only curl as
`download_and_execute`. Exec pack 1.3 no longer assigns that label to a plain fetch;
this example illustrates scoped legacy handling, not an exception to mandatory policy.

```json
{
  "id": "wl-aliyun-metadata-region-curl",
  "enabled": true,
  "description": "Aliyun metadata region-id query — common in cloud assistant/collector init; not an attack alert.",
  "scope": {
    "risk_modules": ["exec"],
    "matched_rules_any": ["download_and_execute"],
    "listener_process": ["sshd"],
    "listener_ports": [22],
    "command_regex": "100\\.100\\.100\\.200/latest/meta-data/region-id"
  },
  "action": "suppress",
  "target_severity": "P3",
  "target_verdict": "benign",
  "target_action": "log_only",
  "reason": "Aliyun metadata region-id query whitelist"
}
```

## 10. Example 2: LoongCollector patrol grep

Scenario: ops or collector checks `/usr/local/ilogtail/loongcollector` path; flagged as suspicious grep.

```json
{
  "id": "wl-ilogtail-loongcollector-grep",
  "enabled": true,
  "description": "LoongCollector/ilogtail install or patrol — grep on fixed path is low-risk noise.",
  "scope": {
    "risk_modules": ["exec"],
    "listener_process": ["sshd"],
    "listener_ports": [22],
    "exe_regex": "/usr/bin/grep$",
    "command_regex": "/usr/local/ilogtail/loongcollector"
  },
  "action": "suppress",
  "target_severity": "P3",
  "target_verdict": "benign",
  "target_action": "log_only",
  "reason": "LoongCollector path patrol whitelist"
}
```

## 11. Temporary whitelist in payload

Besides default `whitelist.json`, pass temporary whitelist in input payload:

```json
{
  "scenario": "S5-EXEC",
  "risk_modules": ["exec"],
  "risk_whitelist": {
    "version": "1.0",
    "defaults": {"enabled": true},
    "rules": []
  },
  "evidence_bundles": {
    "host_exec": []
  }
}
```

Supported field names:

- `risk_whitelist`
- `whitelist`

Payload whitelist takes priority when provided.

## 12. Verifying whitelist effect

After risk identification, check three places:

1. `summary.alert_suppressed` > 0
2. `whitelist_hits[]` contains target rule ID
3. Corresponding `risk_items[]` shows:

```json
{
  "whitelisted": true,
  "whitelist_rule_id": "wl-aliyun-metadata-region-curl",
  "alert_required": false,
  "alert_suppressed": true,
  "original_risk": {
    "severity": "P0"
  }
}
```

## 13. Maintenance guidelines

Whitelist rules should:

- Use stable, readable `id` — suggest `wl-business-object-behavior` naming.
- Write clear manual confirmation in `reason` for audit.
- Prefer precise match conditions; do not allowlist on a single command name.
- After adding whitelist, rerun risk identification on a recent real sample.
- Whitelist controls alerting only; if rules chronically false-positive, improve risk rules.

## 14. FAQ

### Does whitelist delete evidence?

No. Risk items remain in `risk_items[]`; only `alert_required=false` is set.

### Do whitelisted items still enter local correlation?

Risk items are kept; whitelist downgrades or suppresses first. Cross-source chains → traceability-analysis Skill.

### Why not only command_regex?

Single-command match easily allows attacks. e.g. allowlisting only `curl` also allows real remote downloads. Also constrain `matched_rules_any`, `listener_process`, `listener_ports`, target URL or path.

### Can example file go straight to production?

Not recommended. Copy to `whitelist.json` and tune for actual hosts, business paths, and collector behavior.

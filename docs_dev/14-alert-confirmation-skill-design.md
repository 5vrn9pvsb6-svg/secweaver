**Languages:** English (this page) | [简体中文](14-alert-confirmation-skill-design.zh-CN.md)

# Alert Confirmation Skill Design

> Public cases and inputs/outputs are in the [Skill examples](../src/skills/alert-confirmation/examples.md); no internal product-planning material is required.

> SecWeaver sixth core capability  
> Purpose: **Secondary triage** of WAF/WEB/IDS security alerts—false positive, real attack, attack success  
> **Current implementation reference (2026-09-16)**: [entry point](../src/skills/alert-confirmation/scripts/confirm.py), [outcome and confidence logic](../src/skills/alert-confirmation/scripts/alert_confirmation/success.py), and [user guide](../docs_user/17-alert-confirmation.md).

---

## 1. Skill Positioning

### 1.1 What problem it solves

Front-line SOC faces large volumes of WEB security alerts daily. Core questions:

| Question | Alert confirmation Skill should answer |
|---|---|
| Should we handle this alert? | Disposition priority (close / observe / escalate / block) |
| Scan or real attack? | **Attempt / real attack / false positive** |
| Is the payload effective? | Attack type and validity from payload analysis |
| Did it breach? | **Attack success** (requires correlated host behavior D2) |
| Need deeper investigation? | Whether to recommend **traceability analysis** Skill |

### 1.2 Boundaries with other Skills

```text
Data source completeness ──▶ Alert confirmation ──(real + success)──▶ Traceability analysis
                           │
                           └── D1 only: alert classification, does not prove breach
```

| Skill | Responsibility | Does not |
|---|---|---|
| Data source completeness | S4 scenario data sufficiency | Triage single alerts |
| **Alert confirmation** | Single/batch alerts: FP · real · success | Full lateral BFS, complete attack chain |
| Traceability analysis | Multi-source attack chain reconstruction | FP/real binary (unless user forces) |
| Risk identification | exec high-risk triage | Explain why WAF rule matched |

### 1.3 Two-layer triage model

Alert confirmation is **two progressive layers**—do not skip:

```text
Layer 1: Alert authenticity (Alert Verdict)
  ├── false_positive      False positive
  ├── scanning_or_probe   Scan/probe (attempt)
  ├── suspicious          Suspicious; needs more context
  └── confirmed_attack    Real attack (valid payload)

Layer 2: Attack outcome — evaluated only when layer 1 ≥ suspicious
  ├── not_applicable      Layer 1 was false positive
  ├── blocked             WAF/gateway blocked; did not reach application
  ├── attempt_failed      Reached application but no success indicators
  ├── success_confirmed   D2 evidence confirms success (breach/RCE/WebShell)
  └── success_unknown     No D2 data; cannot judge success
```

**Key principle**: Layer 1 can use D1/D5 only; layer 2 **requires** D2 (host_exec/connect/file_op) for `success_confirmed`.

---

## 2. Applicable Scenarios

Main scenario reuses completeness **S4 WEB alert confirmation**; extensions:

| Scenario ID | Name | Alert source | Notes |
|---|---|---|---|
| **S4** | WEB/WAF alert confirmation | waf_alert, web_access_log | S4 main scenario |
| **S4-IDS** | IDS/IPS alert confirmation | ids_alert | Rule hit + traffic context |
| **S4-batch** | Batch alert noise reduction | Multiple waf_alert | Aggregate by same IP/rule then triage |
| **S4-success-chain** | Alert + breach check | waf + D2 | User explicitly asks "did it breach" |

**Not main scenarios**: Full lateral investigation (→ traceability), account compromise (→ S6 dedicated flow).

---

## 3. Prerequisites

### 3.1 Relationship with completeness Skill

| completeness verdict | Alert confirmation capability |
|---|---|
| `full_traceable` / `partial_traceable` | Layer 1 + layer 2 (layer 2 affected by D2 coverage) |
| `alert_triage_only` | **Layer 1 only**; layer 2 at most `success_unknown` |
| `not_traceable` | Weak triage on single alert (very low confidence), or recommend data first |

### 3.2 Start gate (soft gate)

Unlike traceability, alert confirmation can run with **WAF only**, but must:

- Set `confirmation_mode`: `triage_only` or `full`
- Without D2, `attack_outcome` cannot be `success_confirmed`
- Markdown must state "**cannot confirm attack success**; recommend host_exec onboarding"

---

## 4. Input Design

### 4.1 Single alert confirmation

```json
{
  "investigation_intent": "Analyze today's WEB security alerts for IP 203.0.113.10—FP vs real attack, success or not",
  "scenario": "S4",
  "params": {
    "attacker_ip": "203.0.113.10",
    "alert_time": "2026-06-21T14:30:00+08:00",
    "time_window_minutes": 10,
    "alert_ids": ["WAF-20260621-001"],
    "target_url": "/api/user?id=1"
  },
  "completeness_precheck": {
    "overall_verdict": "partial_traceable",
    "confidence": 0.75,
    "next_skill_blocked": false,
    "data_gaps": ["host_connect not registered"]
  },
  "primary_alerts": [
    {
      "alert_id": "WAF-20260621-001",
      "source": "waf",
      "timestamp": "2026-06-21T14:30:05+08:00",
      "src_ip": "203.0.113.10",
      "url": "/api/user?id=1' OR 1=1--",
      "method": "GET",
      "rule_id": "942100",
      "rule_name": "SQL Injection",
      "payload": "id=1' OR 1=1--",
      "action": "blocked",
      "host": "web-01"
    }
  ],
  "correlated_evidence": {
    "web_access_log": [],
    "host_exec": [],
    "host_connect": [],
    "host_file_op": [],
    "waf_alert_context": []
  }
}
```

### 4.2 Batch alert confirmation

```json
{
  "batch_mode": true,
  "primary_alerts": [ "... multiple ..." ],
  "group_by": ["src_ip", "rule_id"],
  "params": { "time_start": "...", "time_end": "..." }
}
```

Batch output: per-alert JSON + trailing `batch_summary` (similar to external-listener-cmd-risk).

### 4.3 Field descriptions

| Field | Description |
|---|---|
| `primary_alerts` | **Alerts to confirm**, at least 1 |
| `correlated_evidence` | Context around alert + D2 host behavior (platform retrieves by IP/URL/host/time window) |
| `completeness_precheck` | Optional; caps confidence and outcome capability |
| `params.time_window_minutes` | Default ±10min for WEB access log correlation |

---

## 5. Output Design

### 5.1 Dual channel

1. **Structured JSON** (one object per alert)
2. **Markdown triage card** (for analysts)

### 5.2 Single-alert JSON structure

This is an actual output excerpt from the [public synthetic input](../examples/alert-confirmation/s4-webshell-attack-success.json), checked against current code. It is a different case from the input-shape illustration above. Evidence, context, and report fields omitted here remain in the full output.

After `make quickstart`, reproduce it from the repository root:

```bash
make ai-showcase CASE=webshell-attack-confirmation
```

```json
{
  "alert_type": "alert_confirmation",
  "alert_id": "WAF-20260621-002",
  "scenario": "S4",
  "confirmation_mode": "full",
  "alert_verdict": "confirmed_attack",
  "attack_outcome": "success_confirmed",
  "attack_success": true,
  "confidence": 0.88,
  "confidence_ceiling": 0.88,
  "next_skill": "traceability_analysis"
}
```

The full JSON is `outputs/ai-showcase/webshell-attack-confirmation.json`; the agent-generated Markdown report is a separate output. These values apply only to this fixed synthetic case.

### 5.3 alert_verdict enum

| alert_verdict | Meaning | Typical conditions |
|---|---|---|
| `false_positive` | False positive | Normal business params, overly broad rule, scanner mis-match |
| `scanning_or_probe` | Scan/probe | Many 404s, no valid payload, low-frequency fingerprint |
| `suspicious` | Suspicious | Hit but incomplete payload or insufficient context |
| `confirmed_attack` | Real attack | Valid attack payload, not business mis-match |

### 5.4 attack_outcome enum

The current `layer2_outcome` returns in this order. Missing logs alone cannot establish attack failure:

| Order | Condition | attack_outcome |
|---|---|---|
| 1 | `alert_verdict=false_positive` | `not_applicable` |
| 2 | Verdict is not suspicious/scanning_or_probe/confirmed_attack | `success_unknown` |
| 3 | `confirmation_mode=triage_only` | `success_unknown`, even if WAF reports a block |
| 4 | Matched success evidence exists in `success_refs` | `success_confirmed` |
| 5 | A configured block action matches and verdict is confirmed_attack | `blocked` |
| 6 | No D2 data | `success_unknown` |
| 7 | D2 exists but no success evidence, and no earlier branch applies | `attempt_failed` |

`attempt_failed` means the available evidence did not confirm success; it does not prove the environment is safe. D2 success evidence still requires matching target, time window, and behavior. See [success.py](../src/skills/alert-confirmation/scripts/alert_confirmation/success.py) for the full logic.

### 5.5 recommended_action enum

| Value | Meaning |
|---|---|
| `close_as_fp` | Close alert (false positive) |
| `log_only` | Log only |
| `log_and_monitor` | Log and observe |
| `manual_review_30m` | Manual review within 30 minutes |
| `escalate_investigate` | Escalate investigation |
| `block_ip` | Recommend blocking source IP |
| `isolate_host` | Recommend isolating victim host (when success_confirmed) |

### 5.6 Downstream Skill triggers

| Condition | next_skill |
|---|---|
| `alert_verdict=confirmed_attack` and `attack_outcome=success_confirmed` | `traceability_analysis` |
| User explicitly requests "trace lateral / attack chain" | `traceability_analysis` |
| attempt / blocked only | null |
| Need D2 supplement | Recommend `data-source-completeness` first |

---

## 6. Triage Workflow (Skill core algorithm)

### 6.1 Seven-step pipeline

```text
Step 0  Read completeness_precheck; set triage_only / full mode
Step 1  Parse primary_alert: rule, payload, action, URL, IP, time
Step 2  Layer 1: payload analysis → alert_verdict (FP/scan/suspicious/real)
Step 3  Context: correlate web_access_log same-window (same IP, same URL prefix)
Step 4  Layer 2: if ≥ suspicious, correlate host_exec/connect/file_op (matrix `attack_success`, same host)
Step 5  Success determination: D2 shell/download/WebShell success indicators
Step 6  Confidence + recommended_action + next_skill
Step 7  Output JSON + Markdown triage card
```

### 6.2 Layer 1: payload and false positive rules

#### Attack type identification (attack_type)

| attack_type | Recognition features |
|---|---|
| `sqli` | `' OR`, `UNION SELECT`, `--`, `#`, `sleep(`, `benchmark(` |
| `xss` | `<script`, `onerror=`, `javascript:`, `<svg/onload` |
| `rce` | `;`, `|`, `` ` ``, `$()`, `system(`, `exec(`, `cmd=` |
| `path_traversal` | `../`, `..\\`, `/etc/passwd`, `file://` |
| `webshell` | `eval(`, `base64_decode`, `assert(`, `shell.php` |
| `ssrf` | `url=`, `http://127.`, `http://169.254`, `file://` |
| `scanner_fingerprint` | Many different URLs, no body, known scanner UA |
| `unknown` | Rule hit but unclassified |

#### False positive downgrade (→ false_positive / suspicious)

| Condition | Handling |
|---|---|
| Empty payload, rule based on URL path only | suspicious; not confirmed_attack |
| Params match known business whitelist (order ID, UUID format) | Tend false_positive |
| Single alert from IP, action=blocked, no repeats | scanning_or_probe or suspicious |
| Matches historical FP pattern library | false_positive |
| Only URL-encoded normal Chinese/business characters | false_positive |

#### Real attack upgrade (→ confirmed_attack)

| Condition | Handling |
|---|---|
| Decoded content has clear exploit syntax | confirmed_attack |
| Same IP many different exploits in short time | confirmed_attack; raise recommended_action |
| Payload consistent with rule_name (SQLi rule + SQLi syntax) | confirmed_attack |

### 6.3 Layer 2: attack success correlation

| Correlation | Rule |
|---|---|
| Time window | matrix `time_windows.attack_success`, currently -5/+30 minutes; matching WEB requests become correlation anchors when present |
| Host | `correlated.host = primary_alert.host` |
| IP | When exec lacks host, use victim host from alert |

#### Candidate success indicators (require target, time, and behavior correlation)

| Indicator | Evidence source | Example |
|---|---|---|
| Shell execution | host_exec | bash/sh/cmd launched by web process child |
| Download and execute | host_exec + connect | curl/wget + egress 80/443 |
| WebShell drop | host_file_op | `.php`/`.jsp` write to upload/www |
| Echo exploit | web_access_log | 500 error + abnormal response body (if available) |
| Reverse connection | host_connect | Web process egress to unexpected IP |

These are candidate signals, not universal success conditions for every attack type. D2 contains only `host_exec`, `host_connect`, `host_file_op` and `host_persistence`; HTTP 500 or an unusual response alone is WEB context. Success evidence must match the target, time window and attack type: SQLi accepts only the `database` exec category, while a curl download may support compatible RCE/WebShell/SSRF types. See `_indicator_compatible()` and `find_d2_success()` in `success.py` for compatibility and request attribution. Campaign-level success does not establish success for each alert.

#### Failure/block indicators

Follow the order in §5.4: triage_only remains unknown. In full mode, matched success evidence takes precedence, followed by a configured WAF block action. With neither a block nor D2 data, return success_unknown; attempt_failed requires D2 without success evidence. HTTP 200 or WAF action alone does not prove the attack outcome.

### 6.4 Confidence

The implementation calculates an effective ceiling, then scores the verdict. See `layer1_upgrade` in `attack-types.json` and [success.py](../src/skills/alert-confirmation/scripts/alert_confirmation/success.py):

```text
base_ceiling = float((completeness_precheck or {}).get("confidence") or 1.0)
if success_confirmed and success_refs: ceiling = max(base_ceiling, d2_success_confidence_floor)
elif confirmed_attack: ceiling = max(base_ceiling, confirmed_attack_confidence_floor)
else: ceiling = base_ceiling
```

The current default floors are `0.88` and `0.75`. They may raise the effective ceiling; they do not assign the score directly. Missing or numeric-zero upstream confidence currently falls back to 1.0; do not use zero instead of explicit gate fields.

| Layer 1 result | Base score |
|---|---|
| confirmed_attack, payload validity=valid | 0.88 |
| confirmed_attack, other validity | 0.72 |
| false_positive | 0.82 |
| suspicious | 0.58 |
| scanning_or_probe | 0.70 |
| Other | 0.60 |

Layer 2 adjustments: success_confirmed uses `min(0.95, base+0.08)`; success_unknown uses `min(base, 0.68)`; blocked uses `min(0.88, base+0.02)`; other outcomes keep the base. Finally, `confidence=round(min(ceiling, base), 2)`. The output `confidence_ceiling` is the effective ceiling and always bounds confidence. This is a rule score, not a statistically calibrated attack probability.

---

## 7. WEB Alert Confirmation Example (S4)

### 7.1 User actions

```text
Select WEB security alert asset
Analyze today's security alerts for IP XX
Confirm: attempt / real attack (with payload) / false positive
If real attack, confirm success (correlate other data)
```

### 7.2 Output by case

#### Case A: WAF only, no D2

```markdown
## Alert Triage

**Alert**: WAF-001 | SQL Injection | 203.0.113.10
**Layer 1**: confirmed_attack (real SQLi attempt, payload: `id=1' OR 1=1--`)
**Layer 2**: success_unknown — no WEB host exec/connect data, **cannot confirm breach**
**Recommendation**: log_and_monitor; for success confirmation, onboard audit-port-execmon
**Next step**: Do not jump to traceability; run data source completeness first
```

#### Case B: Full mode, WAF blocked, no success evidence

- alert_verdict: confirmed_attack
- attack_outcome: blocked
- attack_success: false
- recommended_action: log_and_monitor or block_ip (by repeat count)

#### Case C: RCE/WebShell alert + exec matching the target and time window (curl/bash)

- alert_verdict: confirmed_attack
- attack_outcome: success_confirmed
- attack_success: true
- recommended_action: escalate_investigate
- next_skill: traceability_analysis

### 7.3 Prohibited output

| Scenario | Prohibited |
|---|---|
| No payload | "Confirmed SQL injection success" |
| No D2 | "Server has been breached" |
| Single scan only | "Organization-wide APT attack" |

---

## 8. Batch Alert Noise Reduction

### 8.1 Aggregation dimensions

- Same `src_ip` + same `rule_id` → merge into one triage
- Same `src_ip` multiple rules → take highest alert_verdict

### 8.2 batch_summary

```json
{
  "alert_type": "alert_confirmation_batch_summary",
  "total": 50,
  "false_positive": 20,
  "scanning_or_probe": 15,
  "confirmed_attack": 10,
  "success_confirmed": 2,
  "escalate_count": 2,
  "top_attack_types": ["sqli", "xss"],
  "top_ips": ["203.0.113.10"]
}
```

---

## 9. Collaboration with WAF / Risk Identification Skills

```text
WAF alert ──▶ Alert confirmation
                │
                ├─ Need payload detail → layer 1
                │
                └─ Post-alert exec exists ──▶ Can call external-listener-cmd-risk
                    for exec P0–P3 triage; result in evidence.supporting
```

---

## 10. Skill File Layout

```text
src/skills/alert-confirmation/
├── SKILL.md                 # AI agent entry
├── rules.md                 # FP/real/success rules, attack type features
├── fp-patterns.json         # Common FP and whitelist patterns
├── attack-types.json        # SQLi/XSS/RCE payload feature library
├── examples.md              # S4 confirmation and batch examples
└── scripts/
    ├── confirm.py           # Thin CLI entrypoint and compatibility exports
    ├── alert_confirmation/
    │   ├── paths.py         # Catalog and shared data-access paths
    │   ├── common.py        # JSON/time/host/pattern helpers
    │   ├── url_match.py     # URL, HTTP method, and WAF-request matching
    │   ├── layer1.py        # Payload validity and attack-type classification
    │   ├── success.py       # D2 success, confidence, action, analyst prompts
    │   ├── gateway.py       # Gateway miss scan and gateway success hints
    │   ├── engine.py        # confirm_alert/analyze orchestration
    │   ├── report.py        # Batch summary and Markdown rendering
    │   └── cli.py           # argparse and command output
    └── input.example.json
```

### 10.1 SKILL.md should include

1. Frontmatter triggers: alert confirmation, false positive, WAF, real attack, success
2. Two-layer model and no-skip rule
3. Input/output schema
4. Seven-step flow
5. triage_only vs full mode
6. Markdown triage card template
7. traceability / completeness handoff

### 10.2 rules.md should include

1. alert_verdict decision tree
2. attack_outcome decision tree
3. Attack type regex/keyword table
4. FP downgrade checklist
5. D2 success indicator table
6. recommended_action mapping
7. Confidence formula

### 10.3 Implementation Boundaries

| Module | Does | Does not |
|---|---|
| `confirm.py` | Preserve `python confirm.py -i ...` and old `import confirm` compatibility | Hold new business logic |
| `layer1.py` | Payload pattern match → `attack_type` / `alert_verdict` | Success confirmation |
| `success.py` | D2 evidence → `attack_outcome`, confidence, action | Gateway log miss scanning |
| `gateway.py` | WAF bypass/miss scan, gateway success hints | Host behavior success proof |
| `engine.py` | Orchestrate one alert or batch and output JSON skeleton | Full traceability chain |
| `report.py` | Batch summary and Markdown report sections | Detection rules |

---

## 11. Markdown Triage Card Template

```markdown
## Alert Triage Report

**Alert ID**: {alert_id}
**Time**: {timestamp} | **Source IP**: {src_ip} | **URL**: {url}
**Rule**: {rule_name} ({rule_id}) | **WAF action**: {action}

### Layer 1: Alert authenticity
| Item | Conclusion |
|------|------------|
| Verdict | {alert_verdict} |
| Attack type | {attack_type_label} |
| Payload analysis | {payload_analysis.notes} |
| Confidence | {confidence} |

### Layer 2: Attack outcome
| Item | Conclusion |
|------|------------|
| Success? | {attack_success yes/no/unknown} |
| Outcome | {attack_outcome} |
| Success evidence | {success_proof refs or "none"} |

### Evidence references
- Alert: {alert refs}
- Correlated: {supporting refs}

### Remediation
**{recommended_action_label}**

### Data gaps
{data_gaps_impact}

### Next step
{next_skill or data supplement recommendation}
```

---

## 12. Prohibitions (hard constraints)

1. **No payload → no confirmed_attack** (max suspicious), unless multiple correlated evidence
2. **No D2 → no attack_outcome=success_confirmed**
3. **Do not fabricate** events not in correlated_evidence
4. **Do not give success_confirmed after layer 1 false_positive**
5. **Do not replace traceability** with lateral list or full attack chain
6. **Batch mode**: per-alert verdict; summary aggregates statistics only
7. WAF action=blocked → default attack_success=false unless D2 proves bypass

---

## 13. Acceptance Criteria (S4)

| # | Case | Expected |
|---|---|---|
| 1 | Valid SQLi payload + blocked + no D2 | confirmed_attack; blocked in full mode, success_unknown in triage_only |
| 2 | Normal business param false hit | false_positive |
| 3 | Alert and command match target, time window, and success-evidence rules | confirmed_attack + success_confirmed + next_skill=traceability_analysis |
| 4 | No payload, rule ID only | suspicious + success_unknown |
| 5 | Same IP 50 scan alerts | batch_summary + mostly scanning_or_probe |
| 6 | completeness=alert_triage_only | Layer 1 normal; layer 2 at most success_unknown |

---

## 14. Skill Chain Overview

```text
                    ┌─────────────────────┐
                    │ Data source         │
                    │ completeness        │
                    └──────────┬──────────┘
                               │
              ┌────────────────┼────────────────┐
              ▼                ▼                ▼
       alert_triage_only   success capable   not_traceable
              │                │                │
              ▼                ▼                ▼
       ┌──────────────┐  ┌──────────────┐  Recommend data
       │ Alert        │  │ Alert        │
       │ confirmation │  │ confirmation │
       │ (layer 1)    │  │ (layer 1+2)  │
       └──────┬───────┘  └──────┬───────┘
              │                 │
              │    success_confirmed
              │                 ▼
              │          ┌──────────────┐
              └─────────▶│ Traceability │
                         └──────────────┘
```

---

## 15. One-Line Summary

**Alert confirmation Skill = two-layer health check on security product alerts: first FP/real and payload type, then attack success with D2 evidence support; conservative conclusions, traceable evidence; hand off to traceability after success confirmation.**

---

*Document version: v1.2 | Updated: 2026-09-16 | Status: Skill implemented and split by responsibility → `src/skills/alert-confirmation/`*

# Alert Confirmation — Examples

## Example 1: public S4 alert-confirmation scenario — SQLi blocked, no D2

### User input

```text
Select WEB security alert assets
Analyze today's security alerts for IP 203.0.113.10
Confirm attempt/real/FP; if real, check success
```

### Run

```bash
python3 src/skills/alert-confirmation/scripts/confirm.py \
  -i src/skills/alert-confirmation/scripts/input.example.json
```

### Expected

```json
{
  "alert_verdict": "confirmed_attack",
  "attack_type": "sqli",
  "attack_outcome": "blocked",
  "attack_success": false,
  "next_skill": null,
  "data_gaps_impact": ["No host_exec/connect/file_op; cannot confirm breach"]
}
```

Claw must state: **cannot confirm attack success**; recommend deploying audit-port-execmon.

---

## Example 2: Real attack + success (hand off to traceability)

### Input

`scripts/input.example.success.json`

### Expected

```json
{
  "alert_verdict": "confirmed_attack",
  "attack_outcome": "success_confirmed",
  "attack_success": true,
  "recommended_action": "escalate_investigate",
  "next_skill": "traceability_analysis",
  "evidence": {
    "success_proof": ["exec-101", "connect-101"]
  }
}
```

---

## Example 3: False positive — business UUID

### primary_alert

```json
{
  "alert_id": "WAF-FP-001",
  "rule_name": "Generic Attack",
  "payload": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "url": "/order/detail",
  "action": "logged"
}
```

### Expected

- alert_verdict: `false_positive`
- attack_outcome: `not_applicable`
- recommended_action: `close_as_fp`

---

## Example 4: No payload — suspicious

### primary_alert

```json
{
  "alert_id": "WAF-NP-001",
  "rule_id": "990001",
  "rule_name": "Generic Anomaly",
  "url": "/admin",
  "payload": "",
  "action": "logged"
}
```

### Expected

- alert_verdict: `suspicious` or `scanning_or_probe`
- attack_outcome: `success_unknown`
- Must not be confirmed_attack

---

## Example 5: Batch noise reduction

### Input

```json
{
  "batch_mode": true,
  "primary_alerts": [ "...50 items..." ],
  "correlated_evidence": {}
}
```

### Output structure

```json
{
  "results": [ "...per alert_confirmation..." ],
  "batch_summary": {
    "alert_type": "alert_confirmation_batch_summary",
    "total": 50,
    "false_positive": 20,
    "confirmed_attack": 10,
    "success_confirmed": 2
  }
}
```

---

## Example 6: alert_triage_only precheck

### completeness_precheck

```json
{
  "overall_verdict": "alert_triage_only",
  "confidence": 0.55
}
```

### Constraints

- confirmation_mode: `triage_only`
- Even with exec, triage_only mode must not output success_confirmed (script enforced)
- Layer 2 capped at success_unknown

---

## Example 7: Collaboration with risk identification

When exec events exist after an alert, Claw may:

1. This Skill judges success_confirmed
2. Call **external-listener-cmd-risk** for P0–P3 grading on exec-101
3. Write risk results to `evidence.supporting`

---

## Prohibited output examples

| Scenario | Wrong | Correct |
|---|---|---|
| No D2 | “Server breached” | success_unknown |
| No payload | “Confirmed SQLi success” | suspicious + rule hit |
| false_positive | success_confirmed | not_applicable |

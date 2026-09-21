# Traceability Analysis — Examples

**Cross-source test data:** [examples/traceability/](../../../examples/traceability/) (repo root — S1 full chain / scan negative / breach without lateral)

## Example 1: public S1/S3 traceability scenarios — WebShell → curl → SSH lateral (full chain)

### User input

```text
Select all assets
Alert time 2026-06-21 10:00, hacker IP 203.0.113.10
Possibly breached — find first breach point and lateral events
```

### Prerequisite: completeness precheck passed

```json
{
  "overall_verdict": "full_traceable",
  "confidence": 0.88,
  "next_skill_blocked": false
}
```

### Input

See [examples/traceability/s1-web-shell-to-ssh-lateral.json](../../../examples/traceability/s1-web-shell-to-ssh-lateral.json) (full cross-source test data) or [scripts/input.example.json](scripts/input.example.json) (compact)

### Run correlation script

```bash
python3 src/skills/traceability-analysis/scripts/correlate.py \
  -i examples/traceability/s1-web-shell-to-ssh-lateral.json
```

### Expected JSON summary

```json
{
  "overall_verdict": "confirmed_intrusion_chain",
  "confidence": 0.88,
  "initial_access": {
    "host": "web-01",
    "vector": "webshell",
    "url": "/upload/shell.php",
    "attacker_ip": "203.0.113.10",
    "evidence_refs": ["waf-001"]
  },
  "attack_chain": [
    {"stage": "initial_access", "host": "web-01", "evidence_refs": ["waf-001"]},
    {"stage": "execution", "host": "web-01", "evidence_refs": ["exec-001", "connect-001"]},
    {"stage": "lateral_movement", "host": "db-01", "evidence_refs": ["ssh-001", "fw-001"]},
    {"stage": "lateral_movement", "host": "app-02", "evidence_refs": ["ssh-002"]}
  ],
  "impacted_assets": [
    {"host": "web-01", "role": "initial_compromise", "priority": "P0"},
    {"host": "db-01", "role": "lateral_target", "priority": "P0"},
    {"host": "app-02", "role": "lateral_target", "priority": "P0"}
  ]
}
```

### Expected Markdown excerpt

```markdown
## Traceability Analysis Report

**Verdict**: Confirmed full attack chain (confidence 0.88)

### Executive summary
Attacker 203.0.113.10 hit web-01 via WebShell at 09:10; at 09:15 nginx child curl downloaded sshscan tool; from 09:22 SSH lateral from web-01 (10.0.1.5) to db-01 and app-02.

### Initial entry (first breach point)
- **Host**: web-01
- **Time**: 2026-06-21 09:10:05
- **URL**: /upload/shell.php
- **Vector**: webshell
- **Evidence**: waf-001

### Lateral movement
- confirmed: web-01 → db-01 (root, ssh-001, fw-001)
- confirmed: web-01 → app-02 (deploy, ssh-002)
```

---

## Example 2: Precheck blocked — no confirmed output

### completeness_precheck

```json
{
  "overall_verdict": "not_traceable",
  "next_skill_blocked": true,
  "block_reason": "Missing P0 source: host_exec"
}
```

### Expected

```json
{
  "overall_verdict": "insufficient_evidence",
  "blocked": true,
  "attack_chain": [],
  "summary": "Data source precheck failed; reliable traceability not possible"
}
```

Claw must not output “confirmed breach” or lateral conclusions.

---

## Example 3: WAF only — scanning_or_attempt_only

Test data: [examples/traceability/s1-scan-only-no-host-exec.json](../../../examples/traceability/s1-scan-only-no-host-exec.json)

### evidence_bundles

Only `waf_alert`; no `host_exec`.

### Expected

```json
{
  "overall_verdict": "scanning_or_attempt_only",
  "initial_access": {"host": "web-01", "vector": "webshell"},
  "attack_chain": [{"stage": "initial_access"}],
  "hypotheses": [
    {"text": "WEB entry indicators present but no host command execution — breach not confirmed"}
  ]
}
```

---

## Example 4: Breach without lateral — initial_access_only

Test data: [examples/traceability/s2-initial-access-no-lateral.json](../../../examples/traceability/s2-initial-access-no-lateral.json)

### evidence

- waf + exec + connect; no ssh Accepted

### Expected

```json
{
  "overall_verdict": "initial_access_only",
  "hypotheses": [
    {"text": "Host execution/download observed but no SSH Accepted lateral success"}
  ],
  "recommended_actions": [
    "Isolate initial victim host immediately: web-01",
    "Preserve WEB and SSH related logs"
  ]
}
```

---

## Example 5: Incomplete SSH coverage — partial

### completeness_precheck

```json
{
  "overall_verdict": "partial_traceable",
  "confidence": 0.72,
  "data_gaps": ["ssh_auth coverage partial"]
}
```

### Output requirements

- `summary` uses “**at least** lateral to db-01”
- `impacted_assets[].note`: “SSH log coverage incomplete; may be missed”
- `confidence` ≤ 0.72

---

## Example 6: Entering traceability from alert confirmation

### Upstream alert confirmation conclusion

```json
{
  "verdict": "confirmed_attack",
  "attack_success": true,
  "alert_id": "WAF-001"
}
```

### User

“This alert is confirmed real and successful — trace full attack chain and lateral scope”

### Claw behavior

1. Fill `evidence_bundles` with WAF alert and correlated exec/connect
2. Run traceability six-step workflow
3. Do not repeat FP triage here

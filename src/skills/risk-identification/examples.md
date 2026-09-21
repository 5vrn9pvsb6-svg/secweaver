# Risk Identification Examples

## Run offline sample

```bash
python3 src/skills/risk-identification/scripts/assess.py \
  -i src/skills/risk-identification/scripts/input.example.json
```

Expected: `overall_verdict=high_risk_detected`, P0/P1 **risk_items** (per-event anomalies).

## Sample output excerpt

```json
{
  "overall_verdict": "high_risk_detected",
  "summary": {
    "p0": 2,
    "alert_required": 2,
    "top_incidents": 2
  },
  "recommended_next_skills": []
}
```

Cross-source chains → **traceability-analysis** Skill (not in this output).

## exec + ssh only (no connect)

```json
{
  "risk_modules": ["exec", "ssh"],
  "params": {
    "hosts": ["192.0.2.91", "192.0.2.92"],
    "time_start": "2026-06-01T00:00:00+08:00",
    "time_end": "2026-07-02T23:59:59+08:00",
    "severity_floor": "P2"
  }
}
```

## Dialog phrasing

> Use **risk identification** to list anomalous exec/ssh events on web-01 (WebShell, sshpass, brute-force bursts).  
> Use **traceability-analysis** to link source-to-target lateral movement and a multi-round drill narrative.

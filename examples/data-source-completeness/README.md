# Data Source Completeness — Test Data

Offline `registered_assets` lists that simulate registered data assets and evaluate whether investigation scenarios (S1, S4, etc.) meet traceability or alert-confirmation prerequisites.

## Scenarios

| File | Scenario | Expected overall_verdict | Notes |
|---|---|---|---|
| [s1-full-traceable.json](s1-full-traceable.json) | S1 external IP traceability | `full_traceable` | All 9 asset types present |
| [s1-not-traceable-missing-exec.json](s1-not-traceable-missing-exec.json) | S1 missing host_exec | `not_traceable` | `next_skill_blocked: true` |
| [s4-alert-triage-only.json](s4-alert-triage-only.json) | S4 WAF/WEB only | `alert_triage_only` | Cannot confirm breach |
| [s4-partial-missing-connect.json](s4-partial-missing-connect.json) | S4 missing connect | `partial_traceable` | P0 complete, P1 gaps |
| [s6-full-traceable.json](s6-full-traceable.json) | S6 account-compromise sources complete | `full_traceable` | Readiness only; no compromise claim |
| [s6-not-traceable-missing-auth.json](s6-not-traceable-missing-auth.json) | S6 missing authentication | `not_traceable` | P0 gap blocks downstream analysis |
| [s7-full-traceable.json](s7-full-traceable.json) | S7 exfiltration sources complete | `full_traceable` | Actual events are still required |
| [s7-partial-missing-traffic-volume.json](s7-partial-missing-traffic-volume.json) | S7 missing traffic volume | `partial_traceable` | Transfer volume remains unknown |

## Run

```bash
python3 src/skills/data-source-completeness/scripts/check.py \
  -i examples/data-source-completeness/s1-full-traceable.json
```

## Skill chain

```text
data-source-completeness (this directory)
    ├── full/partial → alert-confirmation / traceability / risk-identification
    └── not_traceable → add missing assets, then run downstream Skills
```

## Related

- Skill: `src/skills/data-source-completeness/SKILL.md`
- Scenario definitions: `src/skills/data-source-completeness/scenarios.json`

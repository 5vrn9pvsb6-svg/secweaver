# Alert Confirmation — Test Data

Offline `primary_alerts` + `correlated_evidence` for validating the two-layer triage model: authenticity (`alert_verdict`) and success (`attack_outcome`).

## Scenarios

| File | Scenario | Expected alert_verdict | Expected attack_success |
|---|---|---|---|
| [s4-sqli-blocked-no-breach.json](s4-sqli-blocked-no-breach.json) | SQLi blocked by WAF | `confirmed_attack` | `false` |
| [s4-webshell-attack-success.json](s4-webshell-attack-success.json) | WebShell + D2 exec/connect | `confirmed_attack` | `true` |
| [s4-false-positive-uuid-param.json](s4-false-positive-uuid-param.json) | UUID business-parameter false positive | `false_positive` | `false` |
| [s4-scanner-generic-no-payload.json](s4-scanner-generic-no-payload.json) | Scanner/generic with no payload | `scanning_or_probe` | `false` |
| [s4-batch-mixed-with-query-gap.json](s4-batch-mixed-with-query-gap.json) | Mixed batch plus failed host query | 1 FP, 1 scan, 1 confirmed attack | all `false`; query remains incomplete |

## Run

```bash
python3 src/skills/alert-confirmation/scripts/confirm.py \
  -i examples/alert-confirmation/s4-webshell-attack-success.json
```

## Skill chain

- Success confirmed (`attack_success: true`) → continue to [examples/traceability/](../traceability/)
- Completeness precheck → [examples/data-source-completeness/](../data-source-completeness/)

## Related

- Skill: `src/skills/alert-confirmation/SKILL.md`
- False-positive patterns: `fp-patterns.json` | Attack types: `attack-types.json`

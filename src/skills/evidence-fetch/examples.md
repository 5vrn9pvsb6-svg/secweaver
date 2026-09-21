# Evidence Fetch Examples

**Languages:** English (this document) | [Simplified Chinese](examples.zh-CN.md)

## 1. Fetch evidence for a host-risk investigation

```bash
python3 src/skills/evidence-fetch/scripts/fetch_evidence.py \
  --from-bundle --bundle bundle-host-risk-default \
  --params '{
    "hosts": ["192.0.2.91", "192.0.2.92"],
    "time_start": "2026-06-21T08:00:00+08:00",
    "time_end": "2026-06-21T20:00:00+08:00"
  }' \
  --pretty
```

The output contains `evidence_bundles.host_exec`, `host_connect`, `ssh_auth`,
and other available evidence for an LLM or `assess.py` to analyze.

## 2. Fetch evidence for external-IP traceability

```bash
python3 src/skills/evidence-fetch/scripts/fetch_evidence.py \
  --from-bundle --bundle bundle-incident-trace-default \
  --params '{
    "attacker_ip": "203.0.113.10",
    "time_start": "2026-06-21T08:00:00+08:00",
    "time_end": "2026-06-21T20:00:00+08:00",
    "host": "web-01"
  }' \
  --format markdown
```

## 3. Fetch selected assets only

```bash
python3 src/skills/evidence-fetch/scripts/fetch_evidence.py \
  --from-bundle \
  --asset-id asset-waf-prod-01 \
  --params '{
    "attacker_ip": "203.0.113.10",
    "time_start": "2026-06-21T14:00:00+08:00",
    "time_end": "2026-06-21T15:00:00+08:00"
  }'
```

## 4. Review a plan before live fetch

```bash
# Step 1: render the plan
python3 src/skills/evidence-fetch/scripts/fetch_evidence.py \
  --from-bundle --plan-only \
  --params '{"attacker_ip":"203.0.113.10","time_start":"...","time_end":"..."}' \
  --pretty

# Step 2: run the live fetch after review
python3 src/skills/evidence-fetch/scripts/fetch_evidence.py \
  --from-bundle \
  --params '{"attacker_ip":"203.0.113.10","time_start":"...","time_end":"..."}' \
  --pretty
```

## 5. Open-source prompt analysis (recommended)

```text
1. evidence-fetch -> evidence_bundles
2. Read prompt-risk-analysis/PROMPT.md and policy-lite.md
3. Analyze evidence_bundles -> investigation report
```

See [prompt-risk-analysis/examples.md](../prompt-risk-analysis/examples.md).

## 6. Deterministic rule engine (included in Community; optional comparison)

```text
1. evidence-fetch -> evidence_bundles
2. risk-identification/assess.py -> risk_items + policy_rule_id
```

## 7. Offline JSON pipeline

```bash
python3 src/skills/evidence-fetch/scripts/fetch_evidence.py \
  --from-bundle --params '{"hosts":["192.0.2.91"],"time_start":"...","time_end":"..."}' \
  -o /tmp/fetch-out.json

python3 src/skills/risk-identification/scripts/assess.py -i /tmp/fetch-out.json
```

When the input already contains `evidence_bundles` and no repeated fetch is
requested, `assess.py` can consume it directly. The payload must still contain
the required scenario and parameters.

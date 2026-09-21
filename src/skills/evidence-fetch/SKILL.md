---
name: evidence-fetch
description: >-
  SecWeaver multi-source evidence collection only — fetch normalized
  evidence_bundles from dataasset bundles/assets via SOPS Vault (SLS, SSH, ES,
  DB, HTTP, local_file). No risk triage, alert verdict, or attack-chain
  analysis. Use when the user asks to 取数, 拉日志, 拉证据, fetch evidence,
  get logs, prepare payload for LLM analysis, or separate fetch from judgment.
---

# Evidence Fetch

SecWeaver Skill: **collect evidence only** — output `evidence_bundles` for downstream Skills or LLM triage.

**Does not**: P0-P3 risk scoring, alert confirmation, traceability chains, or policy verdicts.

Machine-readable output contract: [`output-schema.json`](output-schema.json). The fetch
result must retain `evidence_bundles`, `fetch_summary`, and `data_access` together.

## Position in pipeline

```text
evidence-fetch  →  evidence_bundles + fetch_summary
        ↓
   Prompt-based triage (Community): prompt-risk-analysis (PROMPT + policy-lite)
   Deterministic rules (Community): risk-identification (assess.py + JSON rules)
        ↓
optional: alert-confirmation | traceability-analysis
```

| Skill | Question |
|-------|----------|
| **evidence-fetch** | **What raw logs exist for this investigation?** |
| **prompt-risk-analysis** | **Prompt-based triage (Community): how should an LLM triage these logs?** |
| data-source-completeness | Can we query at all? |
| risk-identification | Is this single event risky? |
| alert-confirmation | Is this WAF alert real / successful? |
| traceability-analysis | How do events form a cross-host chain? |

## When to use

- Operator: "pull host_exec + ssh_auth for 192.0.2.91 last 24h"
- Agent workflow: fetch first, then let LLM apply `behavior-policy.md`
- Debugging connectors/templates before running triage Skills
- Building offline `-i` payloads for examples or CI

## CLI

```bash
# Explicit asset list (--asset-id alone is enough; no --from-bundle needed)
python3 src/skills/evidence-fetch/scripts/fetch_evidence.py \
  --asset-id asset-secweaver-host-exec \
  --asset-id asset-secweaver-sys-risk-alert \
  --params '{"hosts":["192.0.2.91"],"time_start":"2026-07-01T17:00:00+08:00","time_end":"2026-07-01T18:00:00+08:00"}' \
  --pretty

# Bundle + scenario-driven fetch (use --from-bundle for whole bundle)
python3 src/skills/evidence-fetch/scripts/fetch_evidence.py \
  --from-bundle --bundle bundle-host-risk-default \
  --params '{"hosts":["192.0.2.91","192.0.2.92"],"time_start":"2026-06-21T08:00:00+08:00","time_end":"2026-06-21T20:00:00+08:00"}' \
  --pretty

# Plan only (no Vault / no live query)
python3 src/skills/evidence-fetch/scripts/fetch_evidence.py \
  --from-bundle --plan-only \
  --params '{"attacker_ip":"203.0.113.10","time_start":"...","time_end":"..."}' \
  --pretty

# Dry-run (render queries, no secrets)
python3 src/skills/evidence-fetch/scripts/fetch_evidence.py \
  --from-bundle --dry-run \
  --params '{"host":"web-01","time_start":"...","time_end":"..."}'

# Markdown summary for operators
python3 src/skills/evidence-fetch/scripts/fetch_evidence.py \
  --from-bundle --format markdown \
  --params '{"hosts":["192.0.2.91"],"time_start":"...","time_end":"..."}'

# Optional completeness metadata (does not block fetch)
python3 src/skills/evidence-fetch/scripts/fetch_evidence.py \
  --from-bundle --include-completeness \
  --params '{"attacker_ip":"203.0.113.10","time_start":"...","time_end":"..."}'

# Replay existing offline evidence without a connector query
python3 src/skills/evidence-fetch/scripts/fetch_evidence.py \
  -i examples/prompt-risk-analysis/fetch-exec-syslog-mini.json \
  -o /tmp/fetch-offline-replay.json
```

`-i` with a completed `data_access.fetch_mode=offline` result keeps its evidence
and original fetch counts. Add `--fetch` only to refresh against configured active
connectors; `--plan-only` and `--dry-run` replace the saved evidence with a new
preview. A saved preview with no asset or bundle scope cannot be executed.

## Output (JSON)

For a bundle scoped only to S5/S5-HOST with the `S5_host_risk` pattern,
`fetch_strategy=host_risk_bundle` queries all declared bundle assets directly.
D1/WAF reverse lookup is not a prerequisite for host screening. Trace and mixed
scenarios retain correlation planning; an empty D1 bootstrap alone must not
suppress the full-bundle fallback when no usable plan exists.

| Field | Meaning |
|-------|---------|
| `evidence_bundles` | Events grouped by `asset_type` (host_exec, ssh_auth, waf_alert, …) |
| `fetch_summary` | Counts, strategy, fetch_mode |
| `data_access` | bundle_id, fetch_strategy, correlation plan meta |
| `correlation_fetch_plan` | Matrix-driven task list when applicable |
| `completeness_precheck` | Only if `--include-completeness` |

**Never** includes decrypted credentials. `credentials_ref` only in fetch meta.

## Agent workflow (fetch + LLM judge)

1. Run this Skill with `--from-bundle` + `--params`.
2. Read `evidence_bundles` and investigation context.
3. Apply judgment docs (`behavior-policy.md`, alert rules, etc.) — **LLM owns verdict**.
4. Optionally call deterministic Skills for regression/compare (`assess.py`, `confirm.py`).

## Security

- Do not print Vault secrets, SSH keys, or API tokens.
- Prefer narrow time windows and small limits in params.
- For connectivity health checks use [dataasset-connectivity-check](../dataasset-connectivity-check/SKILL.md).

## Related

- Data access layer: [_shared/data-access/README.md](../_shared/data-access/README.md)
- Examples: [examples.md](examples.md)
- Chinese doc: [SKILL.zh-CN.md](SKILL.zh-CN.md)

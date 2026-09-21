---
name: data-source-completeness
description: >-
  Assesses whether registered security data sources are sufficient for incident
  traceability and alert confirmation. Maps investigation scenarios to required
  data domains, evaluates coverage/keys/time/granularity, and outputs missing
  source recommendations with collection hints. Use when investigating whether
  data is complete for溯源, traceability, lateral movement, WEB breach analysis,
  数据源完整性, missing logs, C2 communication, beacon, DGA, 你缺少什么数据,
  or before starting SecWeaver
  traceability or alert confirmation skills.
---

# Data Source Completeness Analysis

SecWeaver Skill: before **traceability / deep alert confirmation**, assess whether registered data assets are sufficient and recommend onboarding.

**Role:** Pre-investigation “data health check” — tell analysts how far they can investigate, what’s missing, and what to onboard first, before starting traceability or alert confirmation.

Machine-readable output contract: [`output-schema.json`](output-schema.json). Outputs
also carry the shared `contract_version` and canonical `skill` fields.

## When to use

- Before traceability: “Is data enough?” “What’s missing?” “Tell me what data you lack”
- Known attack IP/time — find breach point and lateral scope
- Before WEB alert confirmation — can we prove “attack succeeded / breached”?
- After assets are selected in the dialog, **before** running traceability / alert confirmation Skills

## Input

```json
{
  "investigation_intent": "Trace external attack IP; find first breach point and lateral scope",
  "scenarios": ["S1", "S3"],
  "params": {
    "attacker_ip": "203.0.113.10",
    "time_start": "2026-06-21T08:00:00+08:00",
    "time_end": "2026-06-21T20:00:00+08:00",
    "hosts": ["web-01"],
    "alert_id": "optional"
  },
  "registered_assets": [
    {
      "asset_id": "web_waf",
      "name": "WEB WAF alerts",
      "type": "waf_alert",
      "domain": "D1",
      "fields": ["src_ip", "timestamp", "url", "payload", "action"],
      "coverage": ["web_zone"],
      "retention_days": 30
    }
  ]
}
```

- `registered_assets`: assets **selected in the dialog**; unregistered or `status=not_registered` treated as `missing`
- `scenarios` optional — inferred from `investigation_intent` (see table)
- `fields` are source-side; `field_aliases`, `canonical_fields`, `effective_fields` may be auto-filled by `registry.asset_to_registered()`
- Platform may call `src/skills/data-source-completeness/scripts/check.py` for deterministic assessment; Claw adds natural-language explanation

## Scenario identification

| ID | Scenario | Typical keywords |
|---|---|---|
| S1 | External attack IP traceability | external, attack IP, hacker IP, trace, breach, entry point |
| S2 | WEB intrusion traceability | WebShell, WEB intrusion, site compromise, exploit |
| S3 | Lateral movement investigation | lateral, internal spread, jump host, brute-force lateral |
| S4 | WEB alert confirmation | alert confirmation, FP, WAF alert, real attack, breached |
| S5 | Host anomalous behavior | listening process, command execution, exec, connect, external port |
| S6 | Account compromise | account, login anomaly, VPN, brute force |
| S7 | Data exfiltration | exfiltration, leak, bulk download |
| S8 | C2 communication detection | C2, C&C, callback, reverse shell, beacon, DGA |

Multiple may apply. Example: “WAF alert + suspected lateral” → `["S2","S3","S4"]`, merge P0 needs, take strictest conclusion.

Full matrix: [scenarios.json](scenarios.json) and [rules.md](rules.md).

## Assessment workflow

Execute in order; do not skip steps:

```text
1. Identify scenarios S1–S8 (explicit scenarios or infer from investigation_intent)
2. Read registered_assets and params (IP, time, host, alert_id)
3. Merge multi-scenario P0/P1/P2 needs (dedupe; see scenarios.json)
4. Evaluate each requirement:
   - ready: registered + required fields complete + full coverage + retention covers window
   - partial: registered but coverage/fields/retention insufficient
   - missing: not registered or no coverage
   - Field completeness must call shared field_inventory.check_required_fields(); judge by effective_fields = raw + canonical; do not check asset.fields alone
5. Evaluate correlation keys: src_ip, host, timestamp, user, pid — ≥3 cross-source ready
6. Evaluate time window: default [alert_time-24h, +6h]; insufficient retention → partial
7. Compute overall_verdict, confidence, can_trace, can_confirm_breach
8. Generate missing_critical + recommendations (rank sorted, with collection_hint)
9. Decide next_skill and next_skill_blocked (any P0 missing → blocked)
10. Output JSON + user-readable Markdown summary
```

## Data domains D1–D7

| Domain | Meaning |
|---|---|
| D1 | Perimeter and WEB (WAF, CDN, WEB logs) |
| D2 | Host behavior (exec, connect, file, EDR) |
| D3 | Auth access (SSH, VPN, AD, bastion) |
| D4 | Network (firewall, NetFlow, DNS, proxy) |
| D5 | Security alerts (IDS, SOC) |
| D6 | Asset config (CMDB, vulns) |
| D7 | Application business logs |

## Overall verdict

| overall_verdict | Meaning | next_skill |
|---|---|---|
| `full_traceable` | P0 complete, P1≥80% ready | May start traceability |
| `partial_traceable` | P0 complete, P1 partially missing | Traceable with confidence cap |
| `not_traceable` | P0 missing | **blocked** — onboard data first |
| `alert_triage_only` | D1/D5 only, no D2 | Alert classification only; cannot prove breach |

### confidence calculation

```text
confidence = 0.40×P0_ready_rate + 0.35×P1_ready_rate + 0.15×key_score + 0.10×time_score
< 3 correlation keys → confidence cap 0.75
```

## Output format

### 1. Structured JSON (required)

```json
{
  "alert_type": "data_source_completeness",
  "scenario": ["S1", "S3"],
  "scenario_summary": "External attack IP trace + lateral movement",
  "overall_verdict": "not_traceable",
  "confidence": 0.38,
  "can_trace": false,
  "can_confirm_breach": false,
  "summary": "One-line: what can/cannot be investigated",
  "requirements_evaluated": [],
  "registered_sources": [],
  "missing_critical": [],
  "recommendations": [],
  "next_skill": "traceability_analysis",
  "next_skill_blocked": true,
  "block_reason": "Missing P0 source: WEB server process command execution"
}
```

### Field constraints

| Field | Requirement |
|---|---|
| `can_confirm_breach` | Only applies to S1/S2/S4 and requires at least D1 + D2 (exec or connect) |
| `missing_critical` | All P0/P1 with status=missing |
| `recommendations` | Each with rank, priority, reason, impact_if_missing, collection_hint, expected_gain |
| `next_skill_blocked` | Must be true if any P0 missing |
| `block_reason` | Required when blocked; list missing P0 |

### recommendations collection hints (SecWeaver tools)

| asset_type | collection_hint |
|---|---|
| `host_exec` | Deploy audit-port-execmon on Linux; whitelist_ports for external-port process exec |
| `host_connect` | Enable monitor_connect in audit-port-execmon |
| `host_file_op` | Enable monitor_file_ops in audit-port-execmon |
| `ssh_auth` | rsyslog auth.log; retain src_ip, user, result |
| `waf_alert` | WAF API/syslog; **must include payload** |

### 2. User-readable Markdown (required)

In the dialog, besides JSON, reply with:

```markdown
## Data Source Completeness Assessment

**Scenario**: {scenario_summary}
**Verdict**: {overall_verdict} (confidence {confidence})
**Can trace**: {yes/no/partial} | **Can confirm breach**: {yes/no}

### Ready
- {asset_name}: {one-line what it supports}

### Critical gaps
1. **{source_name}** ({priority})
   - Impact if missing: {impact_if_missing}
   - Recommended onboarding: {collection_hint}

### Next steps
{if blocked: onboard P0 sources above before traceability}
{if not blocked: may start **{next_skill}** Skill}
```

## Key rules (SecWeaver scenario alignment)

### S1 external IP traceability P0

- WAF/WEB logs + **WEB host exec** + SSH auth

**When exec is missing, must state clearly:**

> Cannot confirm WebShell or curl/wget SSH tool download; **cannot prove breach**

### S4 WEB alert confirmation

- P0: WAF with payload + WEB access logs
- No D2 → `can_confirm_breach=false`; do not output “breached”

### Prohibited conclusions

| Data state | Prohibited |
|---|---|
| No host_exec/connect | “Confirmed breach” / “Confirmed successful injection” |
| No full ssh_auth | “Confirmed lateral to X hosts” (say “may be incomplete”) |
| WAF only, no payload | “Real SQLi success” |

## Downstream Skill handoff

| Scenario | next_skill | Pass condition |
|---|---|---|
| S1/S2/S3 | `traceability_analysis` | P0 complete |
| S4 | `alert_confirmation` | P0 complete |
| S5 | `risk-identification` | host_exec ready |
| S8 | `risk-identification` | host_connect ready |
| P0 missing | none | blocked=true |

## Prohibited

- Do not conclude “confirmed breach / confirmed lateral to X” when data is insufficient
- Do not omit `impact_if_missing` and `collection_hint`
- Do not treat unregistered assets as ready
- P0 missing → `next_skill_blocked` must be true
- Do not skip “critical gaps” and start traceability directly

## dataasset / SOPS Vault

This Skill **does not touch plaintext secrets**. Assets from [`dataasset/`](../../../dataasset/); credentials are `credentials_ref` only (SOPS Vault decrypt locally).

**Recommended flow:**

```bash
# Built-in --from-bundle: read dataasset + optional Vault fetch
python3 src/skills/data-source-completeness/scripts/check.py \
  --from-bundle \
  --params '{"attacker_ip":"203.0.113.10"}'

# Or prepare input JSON only
python3 src/skills/_shared/data-access/prepare.py \
  --bundle bundle-incident-trace-default \
  --params '{"attacker_ip":"203.0.113.10"}' --run-skill completeness --pretty
```

- Bundles: `dataasset/bundles/bundle-incident-trace-default.json`, `bundle-alert-confirm-min.json`
- Vault config: `dataasset/credentials/README.md`
- Data access layer: [`_shared/data-access/README.md`](../_shared/data-access/README.md)

Claw in dialog references only `asset_id` / `credentials_ref`; decrypt and fetch by `fetch.py` on platform side.

## Additional resources

- Platform docs: [docs_user/15-data-source-completeness.md](../../../docs_user/15-data-source-completeness.md)
- Design: [docs_dev/13-data-source-completeness-skill-design.md](../../../docs_dev/13-data-source-completeness-skill-design.md)
- Requirement matrix: [rules.md](rules.md)
- Scenario JSON: [scenarios.json](scenarios.json)
- Assessment script: [scripts/check.py](scripts/check.py)
- Data access layer: [../_shared/data-access/prepare.py](../_shared/data-access/prepare.py)
- Examples: [examples.md](examples.md) | Test data: [examples/data-source-completeness/](../../../examples/data-source-completeness/)

---
name: risk-identification
description: >-
  SecWeaver risk identification: deterministic P0-P3 triage of host events,
  SSH failure bursts, DNS query profiles, persistence changes, and syslog risk
  events, with behavior-policy alert/suppress decisions. Use for 风险识别,
  S5 host anomalies, S8 suspicious egress, high-risk commands, and SSH brute force.
  Cross-source or cross-host attack reconstruction belongs to traceability-analysis.
---

# Risk Identification

SecWeaver Skill: **identify risky events and behavior patterns** — P0–P3 grading, behavior-policy, and alerting for host, authentication, DNS, persistence, and syslog evidence.

**Scope:** assess events and per-source aggregates such as SSH bursts and DNS profiles. Use [traceability-analysis](../traceability-analysis/SKILL.md) to explain how an attack unfolded across sources and hosts.

Machine-readable output contract: [`output-schema.json`](output-schema.json). The shared
envelope and fetch conclusion boundary are included alongside risk-specific fields.

## Role in the pipeline

| Skill | Question |
|---|---|
| data-source-completeness | Can we investigate? |
| **risk-identification** | **Which events or behavior patterns are risky?** |
| traceability-analysis | How do events link across sources/hosts/time (attack chain)? |
| alert-confirmation | Is this WAF alert a real attack / success? |

## Sub-modules

| Module | Implementation | Data |
|---|---|---|
| `exec`: high-risk commands | `scripts/exec_rules.py` | host_exec |
| `connect`: active outbound risk | `scripts/connect_rules.py` | host_connect |
| `ssh`: brute-force bursts | `scripts/ssh_rules.py` | ssh_auth / authentication failures extracted from syslog |
| `dns`: query profiles and DoH/DoT egress | `scripts/dns_rules.py` | dns_log / host_connect |
| `persistence`: persistence changes | `scripts/persistence_rules.py` | host_persistence |
| `syslog`: structured system risk events | `scripts/syslog_rules.py` | syslog_risk_alert |

`host_file_op` supplies exec context; there is no standalone file detector. Defaults come from [scenarios.json](scenarios.json): S5/S5-HOST select exec, connect, persistence, ssh, syslog; S8 selects connect, dns, exec, syslog. Check `risk_modules_run` and coverage before claiming a module ran.

## When to use

- Screen authorized host, authentication, DNS, persistence, or syslog evidence for **anomalies**
- “Any suspicious shell / curl / egress / sshpass on this host?”
- Batch triage of audit-port-execmon events
- After completeness S5 or S8 passes

## Preconditions

| completeness (S5/S8) | Capability |
|---|---|
| `full_traceable` | Run selected modules with usable evidence, bounded by precheck confidence |
| `partial_traceable` | Report missing sources; detection confidence capped at 0.85 |
| `not_traceable` or `next_skill_blocked` | Detection confidence capped at 0.5; also evaluate the hard block below |
| `next_skill_blocked` + neither host_exec nor host_persistence events | **Blocked** — return insufficient_data |

Metadata completeness does not guarantee events exist in the requested window. Require an explicit authorized asset/bundle, target hosts or IPs, and start/end times with time zones before live retrieval. Obtain missing scope first; do not use sample targets or dates as defaults.

## Assessment workflow

```text
Step 0  Read completeness_precheck → confidence ceiling
Step 1  Filter evidence (hosts, time window, listener_ports)
Step 2  Detection: selected exec / connect / dns / persistence / ssh / syslog → risk_items[]
Step 3  Dedupe
Step 4  Policy layer (ops): behavior-policy.md → alert_required / final severity
Step 5  Environment whitelist → MITRE annotations → incident aggregation → top_incidents[]
Step 6  Output JSON + markdown_report
```

**Detection and policy:** detection engines interpret [JSON rule packs](rules/README.md); [behavior-policy.md](behavior-policy.md) describes alert/suppress policy, with [behavior-policy.rules.json](rules/behavior-policy.rules.json) used by the CLI. Keep both policy representations synchronized. Routine supported rule changes do not require Python edits.

## Ops: where rules live

| Layer | File | Owner | Changes |
|---|---|---|---|
| **Policy (alerting)** | **`behavior-policy.md`** | **Security ops** | Alert, suppress, exceptions, hard guardrails |
| Detection patterns | `rules/*.json` | Security ops / Engineering | Supported patterns, thresholds, and output semantics |
| Detection algorithms | `scripts/*_rules.py` | Engineering | New algorithms or input semantics |
| Ops playbook | [behavior-policy.zh-CN.md](behavior-policy.zh-CN.md) | — | How to add OPS-* rules |

Existing `whitelist.json` configuration is still applied after behavior-policy by default; `--no-whitelist` disables that layer. Do not assume it has been removed. Keep new platform alert/suppress rules in the synchronized behavior-policy files.

Each `risk_item` MUST be traceable to **one or more concrete events** (`evidence_refs`, command, timestamp, host).

## CLI (deterministic script)

```bash
# Offline sample
python3 src/skills/risk-identification/scripts/assess.py \
  -i src/skills/risk-identification/scripts/input.example.json
```

For live queries, first complete [data source onboarding](../../../docs_user/03-configure-data-sources.md). Set `RISK_BUNDLE_ID` to an authorized, onboarded bundle and `RISK_PARAMS_FILE` to a local JSON file with explicit `hosts`, `time_start`, and `time_end`. Store credentials separately. Use `dataasset/` by default, or set `DATAASSET_ROOT=dataasset_my` for an isolated copy.

```bash
export DATAASSET_ROOT="${DATAASSET_ROOT:-dataasset}"
python3 src/skills/risk-identification/scripts/assess.py \
  --from-bundle \
  --bundle "${RISK_BUNDLE_ID:?Set an authorized bundle ID}" \
  --params-file "${RISK_PARAMS_FILE:?Set a scoped query params JSON path}" \
  --fetch
```

This entry point runs the built-in completeness precheck by default. Do not add `--skip-completeness` for routine use. The precheck does not authorize a query.

Pass a nonempty top-level `risk_modules` in offline payload JSON, e.g. `["exec","ssh"]`, to override scenario defaults.

## Output fields

| Field | Description |
|---|---|
| `fetch_summary` | **Required when fetched** — total_events, by_asset_type, asset_ids, time_window, truncated_asset_types |
| `markdown_report` | Includes **数据取数统计** section before verdict/risk items |
| `overall_verdict` | no_risk_detected / low_risk_only / high_risk_detected / insufficient_data |
| `coverage_level` | full / partial / insufficient |
| `risk_items[]` | **Primary output** — detected event or pattern (severity, matched_rules, policy_rule_id, evidence_refs) |
| `top_incidents[]` | Same-host/same-signature roll-up for alerting UI (default top 20) |
| `ssh_brute_waves[]` | Authentication failure bursts; not proof of a successful compromise |
| `risk_modules_run` | Modules actually executed; report unavailable sources and degraded coverage |
| `policy_hits[]` | behavior-policy.md decisions |
| `recommended_next_skills` | Optional (alerting P0 + WAF → alert-confirmation); does not execute downstream Skills |

Runtime coverage mapping: [scripts/source_risk_map.py](scripts/source_risk_map.py). Incident aggregation is not an `attack_chains` output. Choose traceability-analysis separately when the investigation needs cross-source or cross-host reconstruction.

## Other Skills

```text
evidence-fetch → risk identification (anomaly list)
                    → (optional) alert confirmation
Cross-source chains / lateral / multi-round narrative → traceability-analysis (separate Skill)
```

## Prohibited

- Do not reconstruct **cross-host** or **cross-source** attack chains (→ traceability-analysis)
- Do not infer host-to-host attack order or causality from timestamps alone (→ traceability-analysis)
- Do not use for WAF false-positive triage (→ alert confirmation)
- Do not fabricate events not in evidence_bundles
- P0 must trace to `matched_rules[]` or named behavior-policy force-alert rule

## Additional resources

- Design: [DESIGN.zh-CN.md](DESIGN.zh-CN.md) (architecture) · [docs_dev/17-risk-identification-skill-design.md](../../../docs_dev/17-risk-identification-skill-design.md) (full spec)
- exec rules: [../external-listener-cmd-risk/rules.md](../external-listener-cmd-risk/rules.md)
- connect rules: [../external-listener-connect-risk/rules.md](../external-listener-connect-risk/rules.md)
- Behavior policy (ops): [behavior-policy.md](behavior-policy.md) · [运营手册 behavior-policy.zh-CN.md](behavior-policy.zh-CN.md)
- Detection catalog (engineering, read-only): [detection-catalog.md](detection-catalog.md)
- Examples: [examples.md](examples.md)

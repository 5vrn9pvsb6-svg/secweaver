# Risk Identification Skill: Design and Implementation

**Language:** English (this file) | [简体中文](17-risk-identification-skill-design.zh-CN.md)

This maintainer guide describes the current modules, input/output, and execution boundaries of `risk-identification`, checked against the code on 2026-09-16. For first use, read the [risk identification user guide](../docs_user/19-risk-identification.md); AI agent workflow instructions live in [SKILL.md](../src/skills/risk-identification/SKILL.md).

## 1. Purpose and boundaries

Risk identification answers “which observed logs or behaviors need attention, and why?” Deterministic rules assess events, SSH failure bursts, and DNS query profiles, produce P0–P3 risk items, then apply alert policy and the environment whitelist.

| Skill | Responsibility |
|---|---|
| `data-source-completeness` | Evaluate coverage and gaps for the specified investigation scope |
| `risk-identification` | Risk items, evidence references, alert/suppress decisions, and same-host incident aggregation |
| `alert-confirmation` | Determine whether WAF and other alerts are real and whether an attack succeeded |
| `traceability-analysis` | Correlate evidence across sources and hosts and explain attack chains |

Same-host context can influence rules, but incident aggregation is not a cross-host attack chain. `assess.py` currently returns `top_incidents` and `ssh_brute_waves`, not the old design's `attack_chains`; there is no `chain_builder.py` module. Use traceability analysis separately for entry points, lateral movement paths, or multi-stage attack explanations.

## 2. Implemented detection modules

[assess.py](../src/skills/risk-identification/scripts/assess.py) dispatches all six modules below. Actual execution also depends on scenario selection, input evidence, and the completeness gate.

| Module | Input evidence | Implemented capability | Implementation and rules |
|---|---|---|---|
| `exec` | `host_exec` | Command execution, reverse shells, download-and-execute, WebShell command signatures, and related patterns | [exec_rules.py](../src/skills/risk-identification/scripts/exec_rules.py), [exec-rules.json](../src/skills/risk-identification/rules/exec-rules.json) |
| `connect` | `host_connect` | Suspicious outbound connections, ports, and exec-correlated egress | [connect_rules.py](../src/skills/risk-identification/scripts/connect_rules.py), [connect-rules.json](../src/skills/risk-identification/rules/connect-rules.json) |
| `ssh` | `ssh_auth`, or syslog events from which authentication failures can be extracted | SSH brute-force bursts grouped by source, target host, and time window | [ssh_rules.py](../src/skills/risk-identification/scripts/ssh_rules.py), [ssh-rules.json](../src/skills/risk-identification/rules/ssh-rules.json) |
| `dns` | `dns_log`; DoH/DoT checks use `host_connect` | NXDOMAIN bursts, suspected DGA, uncommon TLDs, suspected DNS tunneling, and DoH/DoT egress indicators | [dns_rules.py](../src/skills/risk-identification/scripts/dns_rules.py), [dns-rules.json](../src/skills/risk-identification/rules/dns-rules.json) |
| `persistence` | `host_persistence` | Changes to cron, systemd, SSH keys, profiles, sudoers, and other persistence locations | [persistence_rules.py](../src/skills/risk-identification/scripts/persistence_rules.py), [persistence-rules.json](../src/skills/risk-identification/rules/persistence-rules.json) |
| `syslog` | `syslog_risk_alert` | Structured sudo, account-creation, firewall, and related risk events; raw SSH brute-force events go to `ssh` | [syslog_rules.py](../src/skills/risk-identification/scripts/syslog_rules.py), [syslog-rules.json](../src/skills/risk-identification/rules/syslog-rules.json) |

SSH brute-force detection is implemented in `scripts/ssh_rules.py`; it does not require a separate Skill directory named `ssh-bruteforce-risk/`. It detects failure bursts, not every SSH account anomaly, and does not prove compromise after a successful login.

`host_file_op` remains auxiliary exec context, with **no standalone file detection module**. Process, socket, identity, service, and kernel snapshots can support investigation but cannot replace real-time command, connection, or authentication events. DNS matches are suspicious indicators; a match alone does not prove C2 communication or exfiltration.

The JSON rule packs define rule IDs, thresholds, match fields, and severity. This guide does not duplicate their full catalog. `external-listener-cmd-risk` and `external-listener-connect-risk` document the existing exec/connect sub-capabilities; they do not limit risk identification to those two evidence types.

## 3. Scenarios and module selection

[scenarios.json](../src/skills/risk-identification/scenarios.json) defines the defaults:

| Scenario | Default `risk_modules` |
|---|---|
| `S5`, `S5-HOST` | `exec`, `connect`, `persistence`, `ssh`, `syslog` |
| `S5-EXEC` | `exec` |
| `S5-CONNECT` | `connect` |
| `S5-PERSISTENCE` | `persistence` |
| `S5+WAF` | `exec`, `connect`, `persistence` |
| `S8` | `connect`, `dns`, `exec`, `syslog` |

A nonempty top-level `risk_modules` array in offline input overrides the scenario defaults. Selecting a module does not ensure evidence is available; inspect `risk_modules_run`, `data_source_status`, and `user_reminders` for actual coverage.

The [default bundle](../dataasset/bundles/bundle-host-risk-default.json) groups sample assets; it does not guarantee that your environment supplies every module's required evidence. Edit `dataasset/` by default. For isolation, copy it to `dataasset_my/` and set `DATAASSET_ROOT`. See the [data source configuration guide](../docs_user/03-configure-data-sources.md).

## 4. Completeness, missing data, and degradation

Bundle input construction runs a completeness precheck by default. After fetching evidence, [source_risk_map.py](../src/skills/risk-identification/scripts/source_risk_map.py) evaluates actual event coverage. Passing the metadata precheck does not guarantee events exist in the requested window.

| Condition | Current behavior |
|---|---|
| A module's primary source is missing or empty after filtering | Skip unavailable detection and report the gap in `user_reminders` and coverage results |
| `host_connect` exists but `dns_log` does not | A selected `dns` module can still check DoH/DoT egress; DNS query profiles are unavailable |
| Auxiliary sources such as `host_file_op` are missing | Degrade the relevant contextual assessment; missing data is not evidence of safety |
| Precheck returns `partial_traceable` | Detection confidence is capped at 0.85 and constrained by precheck confidence |
| Precheck returns `not_traceable` or `next_skill_blocked=true` | Detection confidence is capped at 0.5; also evaluate the hard-block condition |
| `next_skill_blocked=true` and the input contains neither `host_exec` nor `host_persistence` events | Return `insufficient_data` without executing detection modules |

The final row is the implementation's specific gate. Do not generalize it to “missing exec always blocks” or “SSH evidence always permits execution.” Offline JSON without a precheck does not establish completeness; callers must still examine coverage.

## 5. Input and query entry points

### 5.1 Offline input

This illustrates the structure; empty event arrays are not usable evidence:

```json
{
  "scenario": "S5",
  "risk_modules": ["exec", "connect", "persistence", "ssh", "syslog"],
  "params": {
    "hosts": ["REPLACE_WITH_AUTHORIZED_HOST"],
    "time_start": "REPLACE_WITH_ISO8601_START_WITH_TIMEZONE",
    "time_end": "REPLACE_WITH_ISO8601_END_WITH_TIMEZONE",
    "severity_floor": "P2"
  },
  "evidence_bundles": {
    "host_exec": [],
    "host_connect": [],
    "host_persistence": [],
    "ssh_auth": [],
    "syslog_risk_alert": []
  }
}
```

`params` scopes the targets, start/end times with time zones, and output severity. Pass completeness results through `completeness_precheck`. See the [minimum evidence fields](../dataasset/configure/evidence-minimum-fields.json) for aliases and normalization constraints; each module's rule pack and parser determine specific matching conditions.

Run the existing synthetic sample from the repository root without a data source or query credentials:

```bash
python3 src/skills/risk-identification/scripts/assess.py \
  -i src/skills/risk-identification/scripts/input.example.json
```

### 5.2 Authorized data queries

First install the environment and complete [read-only data source acceptance](../docs_user/03-configure-data-sources.md). Set `RISK_BUNDLE_ID` to an onboarded bundle ID and `RISK_PARAMS_FILE` to a local parameters JSON file containing explicit `hosts`, `time_start`, and `time_end`, without credentials. The default asset root is `dataasset/`; set `DATAASSET_ROOT=dataasset_my` first when using an isolated copy.

```bash
export DATAASSET_ROOT="${DATAASSET_ROOT:-dataasset}"
python3 src/skills/risk-identification/scripts/assess.py \
  --from-bundle \
  --bundle "${RISK_BUNDLE_ID:?Set an authorized bundle ID}" \
  --params-file "${RISK_PARAMS_FILE:?Set a scoped query params JSON path}" \
  --fetch
```

This entry point constructs the completeness precheck before fetching. Omit `--skip-completeness` in normal usage. The precheck is not an authorization check: establish the query scope before running, and obtain missing targets or time bounds first.

## 6. Execution flow and rule maintenance

```text
Read scenario and completeness results; determine gate and confidence ceiling
  → Filter evidence by target and time window; evaluate source coverage
  → Dispatch selected exec / connect / dns / persistence / ssh / syslog modules
  → Deduplicate risk items
  → Apply behavior-policy alert/suppress decisions
  → Apply environment whitelist (enabled by default; can be explicitly disabled)
  → Add MITRE ATT&CK annotations and aggregate same-host incidents
  → Emit JSON, Markdown report, and downstream suggestions
```

| Change | Maintenance entry point |
|---|---|
| Routine detection patterns, thresholds, and output semantics | `src/skills/risk-identification/rules/*.json`; see the [rule configuration guide](../src/skills/risk-identification/rules/README.md) |
| Alert, suppression, and platform policy | [behavior-policy.md](../src/skills/risk-identification/behavior-policy.md); CLI executes the corresponding [behavior-policy.rules.json](../src/skills/risk-identification/rules/behavior-policy.rules.json), which must stay synchronized |
| Existing environment whitelist compatibility settings | `whitelist.json`; still runs after policy by default, with `--no-whitelist` to disable it; it has not been removed from runtime |
| New algorithms, input semantics, or modules | Python detection engines and corresponding tests, rules, and documentation |

Editing natural-language policy alone does not automatically change deterministic CLI execution. Ordinary JSON rule updates do not always require Python changes either. This guide does not promise automatic loading of team YAML rules.

## 7. Output and verification

| Field | How to use it |
|---|---|
| `overall_verdict` | `no_risk_detected` / `low_risk_only` / `high_risk_detected` / `insufficient_data`; aggregation considers suppression, not just raw P0/P1 counts |
| `risk_items[]` | Detection basis, severity, evidence references, and policy results; ground conclusions in the corresponding events |
| `risk_modules_run` | Modules actually executed; a scenario name does not prove all modules ran |
| `coverage_level`, `data_source_status`, `risk_coverage` | Coverage, source states, and unavailable/degraded rules |
| `user_reminders`, `data_gaps`, `warnings` | Explain these gaps and execution limits to the user |
| `top_incidents`, `ssh_brute_waves` | Incident aggregation and SSH bursts, not cross-host attack chains |
| `policy_hits`, `whitelist_hits` | Explain alert, suppression, and whitelist effects |
| `fetch_summary` | For fetched evidence, check counts, assets, time bounds, and truncation |
| `markdown_report` | Deterministic script report; an AI agent must still verify evidence and explain its meaning |
| `recommended_next_skills` | The script can suggest `alert-confirmation` when an alerting P0 and WAF evidence are present; it does not run downstream Skills |

The investigation task determines whether to use `traceability-analysis`; do not promise that the script recommends it for every P0. `recommended_action` is advice, not authorization for isolation, blocking, or other response actions.

Run local verification from the repository root. These tests use local fixed inputs without a real data source:

```bash
.venv/bin/python -m unittest discover \
  -s src/skills/risk-identification/scripts/tests -p 'test_*.py'
.venv/bin/python -m unittest discover \
  -s src/skills/risk-identification/tests -p 'test_*.py'
```

See the [contributor quickstart](01-new-contributor-quickstart.md) for environment setup and dependencies. The analyzer consumes normalized JSON; available collection depends on the platform, collector, and data source. An implemented module does not imply identical collection coverage on every operating system.

## 8. Files to keep synchronized

When adding or changing a module, check `scenarios.json`, the source capability metadata in `source-requirements.json`, runtime `source_risk_map.py`, rule packs, `SKILL.md`, and both language versions of this guide. Verify implementation status against current dispatch and regression results, rather than a planned directory name.

For detailed operations, see the [operations handbook](../src/skills/risk-identification/OPS-HANDBOOK.zh-CN.md) (Chinese). Continue using the [user guide](../docs_user/19-risk-identification.md) as the entry point for first use and switching to real data.

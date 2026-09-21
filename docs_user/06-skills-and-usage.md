# 06. Project Skills and Usage: Let AI Run Security Operations Tasks

**Languages:** English (this page) | [简体中文](06-skills-and-usage.zh-CN.md)

> This is the skill selection and capability reference. See the [operations guide](07-how-to-use.md) for daily prompts and report review, or the [quickstart](00-security-operator-quickstart.md) for a first run.

SecWeaver is not just about registering data sources—it includes a set of security operations Skills. You can think of a Skill as:

```text
Packaging a class of security operations tasks into a reusable AI workflow.
```

If `dataasset` tells AI "what data exists, how to fetch it, how to link it," then Skills tell AI:

```text
After getting this data, what steps to analyze, what conclusions to output, and when to escalate to the next skill.
```

Skill selection directory. After choosing a skill, follow [07: operating workflow](07-how-to-use.md). Its SKILL and dedicated guide own execution parameters.


## 1. What Is a Skill?

A Skill is a task capability unit in SecWeaver.

A Skill typically includes:

- Applicable scenarios.
- Input requirements.
- Analysis steps.
- Output format.
- Evidence requirements.
- Confidence rules.
- Next-step recommendations.

For example:

```text
alert-confirmation Skill: Judge whether a WAF alert is false positive, real attack, or attack success.
traceability-analysis Skill: Reconstruct attack chain from multi-source evidence.
risk-identification Skill: Identify high-risk commands, outbound connections, and file behavior on hosts.
```

## 2. What Is the Relationship Between Skills and dataasset?

They have different responsibilities.

| Object | Responsible for |
|---|---|
| `dataasset` | What data sources are, how to connect, how to query, how to link |
| `Scenario Pattern` | What to query first for a given problem, in what chain |
| `Correlation Matrix` | How evidence Joins |
| `Skill` | How to judge after getting evidence, how to output conclusions |
| LLM | Understanding user questions, invoking appropriate Skills, explaining evidence and results |

Simply:

```text
dataasset solves "where data comes from";
Skills solve "how to analyze after getting data".
```

## 3. What Main Skills Does the Project Have?

The table groups skills by offline experience, onboarding, checks, retrieval, analysis and sub-modules.

### 3.1 Skills Overview Table

| Skill | Type | Main problem solved | Typical use timing | Key inputs | Common output / next step |
|---|---|---|---|---|---|
| [log-format-discovery](../src/skills/log-format-discovery/SKILL.md) | Data onboarding | New log format field identification, field mapping, normalization suggestions | When adding data source with `status=discovery` | discovery asset, sample logs | Field mapping suggestions, parser suggestions, `discovery → draft` |
| [dataasset-validation-advisor](../src/skills/dataasset-validation-advisor/SKILL.md) | Data health check | Check whether `dataasset/` static config is correct and explain how to fix errors | After modifying assets/connectors/bundles/hosts/scenarios | `dataasset/` config, `validate.py` output | error/warning classification, blocking judgment, minimal fix suggestions |
| [dataasset-connectivity-check](../src/skills/dataasset-connectivity-check/SKILL.md) | Data health check | Check whether active data assets are truly connectable and fetchable | Before publishing assets, troubleshooting "validate passed but no data" | active asset, connector, credentials, query templates | Connection status, fetch status, failure attribution |
| [data-source-completeness](../src/skills/data-source-completeness/SKILL.md) | Data health check / gate | Judge whether current data is sufficient for alert confirmation, traceability, lateral movement, exfiltration analysis | Before formal judgment, or when user asks "what data is missing" | scenarios, params, registered_assets | Completeness conclusion, data gaps, suggested next Skill |
| [alert-confirmation](../src/skills/alert-confirmation/SKILL.md) | Security judgment | Judge WAF/WEB/IDS alerts as false positive, real attack, or attack success | User has one or batch of alerts needing secondary confirmation | primary_alerts, correlated_evidence, completeness_precheck | `alert_verdict`, `attack_outcome`, remediation suggestions; proceed to traceability on success |
| [traceability-analysis](../src/skills/traceability-analysis/SKILL.md) | Security judgment | Cross-source attack chain reconstruction, initial entry, lateral path, impact scope | Known attack IP, after attack success, need first breach point | evidence_bundles, join_edges, params, completeness_precheck | attack_chain, timeline, impact_scope, data_gaps |
| [risk-identification](../src/skills/risk-identification/SKILL.md) | Security judgment | Identify host high-risk commands, suspicious outbound connections, WebShell/C2 risk | User specifies host, listening process, host_exec/host_connect evidence | host_exec, host_connect, host_file_op, host/context | P0–P3 risk items, attack chain fragments, remediation suggestions |
| [external-listener-cmd-risk](../src/skills/external-listener-cmd-risk/SKILL.md) | Low-level sub-module | Identify high-risk commands triggered by externally listening processes | Usually invoked by `risk-identification` | host_exec | Command risk items, rule hits, severity level |
| [external-listener-connect-risk](../src/skills/external-listener-connect-risk/SKILL.md) | Low-level sub-module | Identify active outbound connection risk from externally listening processes | Usually invoked by `risk-identification` | host_connect | Outbound risk items, C2/suspicious port judgment |
| [offline-showcase](../src/skills/offline-showcase/SKILL.md) | Offline experience | Credential-free investigation and report review | First use | Public synthetic cases | Report and evidence checks |
| [evidence-fetch](../src/skills/evidence-fetch/SKILL.md) | Evidence retrieval | Fetch authorized assets within scope | After source onboarding | Assets/bundle, hosts or IP, time bounds | evidence_bundles and fetch summary for analysis |
| [prompt-risk-analysis](../src/skills/prompt-risk-analysis/SKILL.md) | Prompt-only analysis | Explain evidence, risks and gaps using prompts | Offline or fetched evidence | evidence_bundles and investigation question | Evidence-linked report; not deterministic rule matches |

### 3.2 How to Quickly Choose a Skill?

| User wants to do | Prefer this Skill |
|---|---|
| Onboard new log, unsure how to map fields | `log-format-discovery` |
| Changed JSON, want to know if config is OK | `dataasset-validation-advisor` |
| Want to know if active assets can really fetch data | `dataasset-connectivity-check` |
| Want to know if current data is enough for investigation | `data-source-completeness` |
| Confirm alert false positive / real / success | `alert-confirmation` |
| Trace attack chain, first breach point, lateral scope | `traceability-analysis` |
| Check if a host has high-risk behavior | `risk-identification` |

> Recommended order: use health-check Skills first to confirm "can we query," then judgment Skills to output "what we found."

### 3.3 Retrieval and prompt-based judgment

`evidence-fetch` retrieves, normalizes, and summarizes evidence from DataAsset and scenario configuration; it does not decide whether an attack occurred. `prompt-risk-analysis` is written entirely as prompts: the intelligent agent receives existing `evidence_bundles`, explains cross-source evidence, cites `evidence_id`, lists data gaps, and recommends follow-up investigation.

Recommended flow:

```text
evidence-fetch → data-source-completeness → prompt-risk-analysis → human review
```

See [evidence-fetch](../src/skills/evidence-fetch/SKILL.md), [prompt-risk-analysis](../src/skills/prompt-risk-analysis/SKILL.md), and the [prompt analysis examples](../examples/prompt-risk-analysis/README.md). Prompt analysis does not bypass DataAsset permissions or replace deterministic checks in the other investigation Skills.

## 4. Skills and S1–S8 Scenario Relationship

| Scenario | Common Skills |
|---|---|
| S1 External IP traceability | data-source-completeness, traceability-analysis |
| S2 WEB intrusion | alert-confirmation, traceability-analysis |
| S3 Lateral movement | data-source-completeness, traceability-analysis |
| S4 Alert confirmation | data-source-completeness, alert-confirmation |
| S5 Host risk | data-source-completeness, risk-identification |
| S6 Account compromise | data-source-completeness, traceability-analysis |
| S7 Data exfiltration | data-source-completeness, traceability-analysis |
| S8 C2 communication detection | data-source-completeness, risk-identification; traceability-analysis when needed |
| New log onboarding | log-format-discovery, dataasset-validation-advisor, dataasset-connectivity-check |

# 07. How to Use

**Languages:** English (this page) | [简体中文](07-how-to-use.zh-CN.md)

> This is the daily investigation guide. Use the [skill reference](06-skills-and-usage.md) for the catalog and individual skill guides for task parameters.

This guide explains how operators use SecWeaver day to day. The focus is not “chatting freely with a large language model,” but:

```text
Use natural language to trigger the right Skill,
so the Skill follows a fixed workflow to fetch data, correlate, assess, and output a report.
```

Read first: [06. Project Skills and Usage](06-skills-and-usage.md). That article introduces the available Skills; this one explains how to use them in daily work.

This page owns prompting, execution, review, and next steps. Choose a skill in the [06 directory](06-skills-and-usage.md).

## 1. What to Confirm Before Use

Before running a Skill, confirm:

1. Relevant data sources are configured as `active`.
2. Data sources are included in the appropriate Bundle.
3. Query templates return data.
4. Scenario Patterns cover your investigation scenario.
5. `validate.py` has no blocking errors.
6. For formal triage, run data-source completeness analysis first.

If these are not ready, a Skill may output:

```text
Insufficient evidence
Missing data sources
Preliminary assessment only
Cannot confirm whether the attack succeeded
```

That is not a failure. A good Skill should tell you clearly what is missing when evidence is insufficient, rather than forcing a conclusion.

## 2. Execution order

1. Start with the offline [quickstart](00-security-operator-quickstart.md). For live queries, confirm sources, read-only credentials, hosts, and a timezone-qualified time window.
2. Run completeness checks, review gaps and truncation, and fetch within the authorized scope.
3. Choose prompt-based or deterministic rule triage; use alert confirmation or traceability for cross-source investigation. Both triage paths are included in Community.
4. Review evidence references and distinguish confirmed facts, hypotheses, and unknowns before following next-step recommendations.
5. Generate reports locally. Sending to DingTalk or another external channel requires explicit authorization.


## 3. What Parameters to Provide When Asking

The more specific your question, the faster a Skill can fetch the right data.

Suggested parameters:

| Parameter | Example | Common Skills | Purpose |
|---|---|---|---|
| Attacker IP | `203.0.113.10` | `alert-confirmation`, `traceability-analysis` | External IP traceability, alert confirmation |
| Alert time | `2026-06-28 10:00` | All investigation Skills | Derive default time window |
| URL | `/upload.php` | `alert-confirmation` | Web attack context |
| Hostname | `web-01` | `risk-identification`, `traceability-analysis` | Host behavior investigation |
| Host IP | `10.0.1.5` | `traceability-analysis` | Lateral movement, outbound connection analysis |
| Account | `admin` | `traceability-analysis` | Account compromise, login behavior |
| Destination IP / domain | `8.8.8.8` / `example.com` | `traceability-analysis` | Outbound and exfiltration analysis |
| Time range | `10:00-12:00` | All data-fetch Skills | Control query scope |

If you provide only part of these, Scenario Pattern will try to fill gaps using default time windows — but explicit parameters work better.

## 4. Recommended Prompt Templates

### 4.1 Data-Source Completeness Template

```text
Use the data-source-completeness Skill for data-source completeness analysis.
Scenario: external IP traceability / alert confirmation / host risk / data exfiltration.
Known parameters: attacker IP=..., host=..., alert time=...
Tell me: what conclusions current data supports, what data is missing, and which Skill to run next.
```

### 4.2 Alert Confirmation Template

```text
Use the alert-confirmation Skill to confirm this alert.
Alert type: WAF / WEB / IDS.
Attacker IP: ...
Alert time: ...
URL / payload: ...
Output: false positive or not, real attack or not, attack success or not, evidence chain, data_gaps, and response recommendations.
```

### 4.3 Traceability Analysis Template

```text
Use the traceability-analysis Skill for traceability analysis.
Attacker IP: ...
Alert time: ...
Known victim host(s): ...
Focus on: first compromise point, attack-chain timeline, lateral movement path, impact scope, evidence chain, and data gaps.
```

### 4.4 Risk Identification Template

```text
Use the risk-identification Skill to analyze host risk.
Host: ...
Time range: ...
Focus on host_exec, host_connect, host_file_op. Output P0–P3 risk items, matched rules, evidence, and response recommendations.
```

### 4.5 Configuration Validation Template

```text
Use the dataasset-validation-advisor Skill to check dataasset configuration.
Distinguish blocking, error, and warning. Tell me what must be fixed, what is example noise, and the minimal fix path.
```

### 4.6 Connectivity Check Template

```text
Use the dataasset-connectivity-check Skill to check active asset connectivity.
Tell me which assets connect and return data, and which fail due to credentials, connection, template, or no data.
```

## 5. Input and Output of a Skill Call

### Input

Natural language or structured parameters.

Natural language example:

```text
Use alert-confirmation to analyze whether the WAF alert from 203.0.113.10 at 2026-06-28 10:00 was a successful attack.
```

Structured example:

```json
{
  "scenario": "S4",
  "params": {
    "attacker_ip": "203.0.113.10",
    "alert_time": "2026-06-28T10:00:00+08:00",
    "url": "/login"
  }
}
```

### Output

Output varies by Skill, but usually includes:

- `overall_verdict`: Overall conclusion.
- `confidence`: Confidence level.
- `evidence_bundles`: Retrieved evidence grouped by type.
- `join_edges`: Correlation edges between evidence items.
- `data_gaps`: Missing data or failed correlations.
- `next_skill`: Recommended next Skill.
- `user_reminders`: Reminders for operators.
- `markdown_report`: Human-readable report.

## 6. Understanding evidence_bundles

`evidence_bundles` groups evidence by data type.

For example:

```text
waf_alert: WAF alert evidence
web_access_log: Web access evidence
host_exec: Host command execution evidence
ssh_auth: SSH login evidence
firewall_log: Firewall access evidence
```

Think of it as:

```text
The raw evidence a Skill retrieved.
```

## 7. Understanding join_edges

`join_edges` are correlation edges between evidence items.

For example:

```text
WAF alert A and Web access B correlated successfully via src_ip.
Web access B and host command C correlated successfully via host.
SSH login D and firewall log E correlated successfully via src_ip/dst_ip.
```

This matters more than single log lines, because security investigation focuses on chains.

Skill conclusions should rely on `join_edges` when possible, not isolated log entries.

## 8. Understanding data_gaps

`data_gaps` indicates missing data or correlations that did not match.

For example:

```text
no_match:web_access_to_host_exec
```

means the system tried to correlate Web access with host commands but found no matching evidence.

This does not necessarily mean the attack failed. Possible reasons:

1. No host command execution actually occurred.
2. Host logs are not onboarded.
3. Time window is too narrow.
4. Field mapping is incorrect.
5. Query template did not return relevant events.

When you see `data_gaps`, interpret them together with data-source completeness.

## 9. How to Review Skill Output

Review using these questions:

1. Does the conclusion cite specific evidence?
2. Is evidence within a reasonable time window?
3. Did key joins succeed?
4. Did the Skill rely on a single log line?
5. Are `data_gaps` stated clearly?
6. If evidence is insufficient, are collection recommendations provided?
7. Is a reasonable `next_skill` suggested?

Good Skill output should:

```text
When evidence exists, explain the evidence chain clearly;
When evidence is missing, explain what is missing;
When uncertain, do not force a conclusion;
When further investigation is needed, recommend the next Skill explicitly.
```

## 10. Next Steps

Continue reading: [08. Investigation Scenarios](08-investigation-scenarios.md)

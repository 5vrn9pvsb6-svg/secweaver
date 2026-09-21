# 05. Scenario Pattern Explained: Telling AI What to Query First

**Languages:** English (this page) | [简体中文](05-scenario-patterns.zh-CN.md)

> This is the conceptual introduction to scenario patterns. For fields, runtime behavior, and maintenance rules, see the [scenario configuration reference](22-scenario-patterns.md).

`Scenario Pattern` is one of the most important configurations in SecWeaver. It turns security operations experience into machine-readable "investigation playbooks."

If you remember only one sentence:

```text
Scenario Pattern does not judge conclusions; it tells the system: for a given type of problem, where to start, which data to query, and in what chain order.
```

Corresponding configuration file:

```text
dataasset/scenarios/anchor-patterns.json
```

This page explains the concept and how to read an example. Field definitions, runtime support, configuration changes, and validation are maintained in the [configuration reference](22-scenario-patterns.md).
## 1. Why Do We Need Scenario Pattern?

Many security investigations are not "query one log" but a path.

For example, a WAF alert:

```text
WAF alert
→ Web access log
→ Host command execution
→ File operations
→ Host outbound connections
```

Without Scenario Pattern, the LLM may decide what to query first each time. This causes several problems:

| Problem | Consequence |
|---|---|
| Different investigation order each time | Same event may yield different conclusions |
| Model does not know your available data | May suggest non-existent data sources |
| Unfixed fetch scope | Hard to review |
| Time window guessed by model | Prone to false or missed links |
| Cannot clearly state missing data | Cannot stably output data_gaps |

So the value of Scenario Pattern is:

```text
Solidify "how an ops expert would investigate" into configuration so AI follows a reliable path.
```

## 2. How Do Scenario Pattern and the LLM Divide Work?

Do not treat Scenario Pattern as replacing the LLM.

A more reasonable division:

| Role | Responsible for |
|---|---|
| LLM | Understanding user questions, selecting possible scenarios, explaining evidence, outputting verdicts |
| Scenario Pattern | Specifying investigation entry, default time window, recommended data chain, asset bundle |
| Correlation Matrix | Specifying how evidence Joins |
| Query Template | Specifying how to actually query data |
| Fetch Plan | Turning investigation chain into executable fetch tasks |

In other words:

```text
LLM handles "understanding and explanation";
Scenario Pattern handles "investigation path";
Correlation Matrix handles "evidence linking rules".
```

## 3. Where Does Scenario Pattern Take Effect in an Investigation?

Typical flow:

```text
User question
  ↓
LLM or system identifies scenario, e.g. S4 alert confirmation
  ↓
Select Scenario Pattern, e.g. S4_alert_confirmation
  ↓
Read anchor, investigation_window, recommended_chain, bundle_id
  ↓
Look up Joins in Correlation Matrix from recommended_chain
  ↓
Generate fetch tasks from Join.fetch_plan
  ↓
Fetch pulls evidence
  ↓
Correlation Engine generates join_edges / data_gaps
  ↓
LLM explains evidence and outputs conclusion
```

So Scenario Pattern is the entry point for "scenario → data → link chain."

## 4. What Does a Scenario Pattern Look Like?

Simplified example:

```json
{
  "S1_external_ip_trace": {
    "label": "External IP traceability",
    "investigation_window": "trace_default",
    "anchor": {
      "field": "src_ip",
      "field_variants": ["ip", "client_ip"],
      "from": "params.attacker_ip",
      "fallback_asset_types": ["waf_alert", "web_access_log"]
    },
    "recommended_chain": [
      "waf_to_web_access_by_ip",
      "web_access_to_host_exec",
      "attacker_ip_to_ssh_auth",
      "host_ip_to_ssh_auth_lateral",
      "firewall_web_to_internal"
    ],
    "bundle_id": "bundle-incident-trace-default"
  }
}
```

This configuration expresses:

```text
If the user wants external IP traceability:
1. Start from attacker_ip;
2. Use trace_default time window by default;
3. Query WAF / Web first;
4. Then follow Web → host execution → SSH → firewall link chain;
5. Use bundle-incident-trace-default asset bundle.
```

---

## 5. How to Understand Current S1–S8 Scenarios?

| Scenario | Name | Common anchor | Main goal |
|---|---|---|---|
| S1 | External IP traceability | `attacker_ip` / `src_ip` | Whether attack IP came in, which hosts affected |
| S2 | WEB intrusion / WebShell | `url` / `src_ip` | Whether Web attack breached, whether payload landed |
| S3 | Lateral movement tracking | `host_ip` / `user` | Whether spread from one machine to others |
| S4 | Alert confirmation | WAF alert fields | False positive, real attack, success or not |
| S5 | Host behavior risk | `host` | Host commands, outbound connections, file operation risk |
| S6 | Account compromise tracking | `user` | Abnormal login and follow-up behavior |
| S7 | Data exfiltration tracking | `host` / `dst_ip` / `domain` | Outbound connections, DNS, traffic, database access |
| S8 | C2 communication detection | `host` / `dst_ip` / `domain` | Identify suspicious callbacks, correlate process and DNS context, and inspect network-session evidence |

## 6. Configuration and verification

Configuration defaults to `dataasset/`; optionally copy it to `dataasset_my/` and set `DATAASSET_ROOT` for isolation. Check supported fields and runtime behavior in the [reference](22-scenario-patterns.md), then run `python3 src/secweaver.py validate` and the relevant offline example. A matching link is not proof of attack success; no match does not establish complete coverage.

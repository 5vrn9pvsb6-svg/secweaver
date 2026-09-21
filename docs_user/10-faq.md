# 10. FAQ

**Languages:** English (this page) | [简体中文](10-faq.zh-CN.md)

This page collects the most common questions operators have when understanding, configuring, and using SecWeaver.

---

## Q1: Is SecWeaver a SIEM?

No — not a traditional SIEM.

It is closer to:

```text
Security data asset catalog + investigation orchestration rules + AI analysis execution layer
```

It can use SIEM, log platforms, databases, object storage, host files, and more as data sources. Its focus is enabling AI to investigate and triage based on that data.

---

## Q2: Why configure dataasset? Can’t the AI query logs directly?

Not recommended.

Because the AI does not know:

- Where your logs live.
- Which fields represent IP, host, or account.
- Which data sources are live.
- Which Join rules are trustworthy.
- Which query statements to use.
- What time range to use.

`dataasset` turns that information into machine-readable configuration.

---

## Q3: Do Scenario Patterns limit the LLM?

Not simply — they provide reliable investigation paths.

The LLM understands questions and interprets evidence; Scenario Patterns tell it:

```text
For this scenario, query what first, what next, and for how long by default.
```

If the LLM decides everything alone, you often get:

- Missing key logs.
- Unstable investigation order.
- Invented data sources.
- Different paths for different analysts.

Recommended approach:

```text
LLM selects or suggests the scenario; Scenario Pattern constrains fetch and correlation paths.
```

---

## Q4: What is the difference between Asset and Connector?

Simple view:

```text
Asset = what this data is
Connector = how to connect to this data
```

Example:

```text
Asset: production WAF alerts
Connector: Aliyun SLS project/logstore/endpoint configuration
```

One Asset can aggregate multiple Connectors. For example, SSH logs from many hosts can merge into one logical `ssh_auth` asset.

---

## Q5: Why Host and Network?

Many investigations need context beyond a single log line.

Host / Network help determine:

- Which business zone a machine belongs to.
- Whether it is a database server.
- Whether it is exposed to the public Internet.
- Whether access crosses network segments.
- Whether traffic moved from DMZ into production.
- Whether a normal segment accessed a high-sensitivity segment.

This matters greatly for lateral movement and data exfiltration.

---

## Q6: When should I configure field_aliases?

When source log field names differ from platform standard fields.

Example: standard field is `src_ip`, but the source log uses:

```text
client_ip
remote_addr
ip
source_ip
```

Configure field aliases.

Otherwise the system may fail to correlate logs from different sources.

---

## Q7: Why can’t I fetch data even though validate passed?

validate mainly checks static configuration correctness; it does not guarantee live data exists.

Also check:

- Data source is actually reachable.
- Query template is correct.
- Time range contains data.
- Parameters are correct.
- Credential permissions are sufficient.
- Log fields match the template.

---

## Q8: Why does the AI say “insufficient evidence”?

Two broad reasons.

### Type 1: No evidence actually exists

Example: attack request never reached the backend, or no host commands ran.

### Type 2: Missing data

Examples:

- Host logs not onboarded.
- DNS logs not onboarded.
- Incorrect field mapping.
- Unreasonable time window.
- Bundle missing the relevant Asset.

When you see “insufficient evidence,” read `data_gaps`, not only the final verdict.

---

## Q9: Should a new data source go straight to active?

Not recommended.

Recommended flow:

```text
discovery → draft → active
```

- `discovery`: new log format; fields still being identified.
- `draft`: configured, pending verification.
- `active`: verified and usable for formal investigation.

---

## Q10: Can example connectors live in the open-source project?

Yes, but do not include real secrets.

Recommendations:

- Example connectors use fake endpoints or sample configuration.
- `credentials_ref` uses example vault paths.
- Mark clearly as `status: draft` or for example use only.
- Do not commit real AccessKeys, passwords, or private keys.

---

## Q11: How do I know whether data sources are sufficient for a scenario?

Check critical data sources per scenario.

Example: S4 alert confirmation needs at least:

```text
WAF alerts
Web access logs
Host command execution
```

To judge attack success, ideally also:

```text
Host file operations
Host outbound connections
```

If critical sources are missing, the AI should output “cannot confirm” or “insufficient evidence,” not force a conclusion.

---

## Q12: Why write investigation paths as configuration?

Security operations need stability, auditability, and iteration.

If investigation paths live only in prompts or individual experience:

- Methods differ when people change.
- Results shift heavily when model versions change.
- Hard to audit why certain data was queried.
- Hard to see which log types are missing.

As configuration, you can:

- Standardize investigation methods.
- Reuse best practices.
- Let validate check configuration.
- Stabilize AI output.

---

## Q13: Which data sources should I onboard first?

Suggested priority:

### Phase 1: Minimum closed loop

```text
WAF alerts
Web access logs
Host command execution
```

### Phase 2: Traceability and lateral movement

```text
SSH login
Firewall logs
Asset inventory
```

### Phase 3: Exfiltration and deep confirmation

```text
Host outbound connections
DNS logs
Network traffic
Database audit
File operations
```

---

## Q14: Do operators need to edit Python code?

Normally, no.

Operators mainly edit:

```text
dataasset/assets/*.json
dataasset/connectors/*.json
dataasset/hosts/*.json
dataasset/networks/*.json
dataasset/bundles/*.json
dataasset/scenarios/*.json
dataasset/query-templates/*.json
```

For similar new data sources, JSON edits are usually enough.

---

## Q15: How do I judge whether an AI conclusion is trustworthy?

Check three things:

1. Specific evidence is listed.
2. `join_edges` support the evidence chain.
3. `data_gaps` are stated clearly.

Trustworthy output looks like:

```text
Because the WAF alert and Web access matched on the same src_ip, url, and time window,
and the target host then showed abnormal command execution,
the attack is likely successful.
But without file operation logs, WebShell placement cannot be confirmed.
```

Untrustworthy output looks like:

```text
Looks like a successful attack.
```

—with no evidence chain.

---

## Q16: What should I provide when contributing a new data source template?

At minimum:

- An example Connector.
- An example Asset.
- Matching Query Template.
- Field documentation.
- Sample or redacted logs.
- validate pass result.
- Which scenarios the data source supports.

---

## Q17: How do I protect sensitive information?

Follow these rules:

- Do not commit real secrets.
- Do not send secrets to the AI.
- Do not keep real user privacy in log samples.
- Before open-sourcing, scrub public IPs, internal domains, accounts, and tokens.
- Connectors should keep only non-sensitive connection configuration.

---

## Q18: Should I read `docs_user/` or `docs_dev/`?

If you are an operator or general user, read `docs_user/`.

Read `docs_dev/` when maintaining core implementation, changing the correlation engine, extending Skills, or adjusting schema.

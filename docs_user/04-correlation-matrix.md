# 04. Correlation Matrix Explained: How Evidence Is Linked

**Languages:** English (this page) | [简体中文](04-correlation-matrix.zh-CN.md)

`Correlation Matrix` is one of the most important configurations in SecWeaver. It defines how evidence retrieved from different data sources is linked together.

If you remember only one sentence:

```text
Correlation Matrix does not decide what to query first; it defines whether two types of evidence can be linked, which fields to use, and within what time window.
```

Corresponding configuration file:

```text
dataasset/assets/correlation-matrix.json
```

This page explains the concept and how to read an example. Field definitions, runtime support, configuration changes, and validation are maintained in the [configuration reference](21-cross-source-field-correlation.md).
## 1. Why Do We Need Correlation Matrix?

The key to security investigation is not reading a single log line, but whether multiple pieces of evidence can form a chain.

For example:

```text
WAF alert: 203.0.113.10 accessed /upload.php
Web access log: 203.0.113.10 requested /upload.php, returned 200
Host command log: web-01 subsequently executed whoami, id, curl
SSH log: web-01 subsequently logged into db-01
Firewall log: web-01 accessed db-01:22
```

Each log line alone only shows a local fact. Only by linking them together can you form an attack chain.

Correlation Matrix tells the system:

```text
Which evidence can be linked?
Which fields are used for linking?
What time interval is reasonable?
How should successful links be expressed to the LLM?
```

## 2. Correlation Matrix vs Scenario Pattern

These two concepts are easily confused.

| Object | Responsible for | Not responsible for |
|---|---|---|
| Scenario Pattern | What to query first for a given problem, which chains to follow, which Bundle to use | Defining specific Join fields |
| Correlation Matrix | How two types of evidence Join, time window size, field matching | Deciding the full investigation flow for a scenario |

Simple analogy:

```text
Scenario Pattern = investigation roadmap
Correlation Matrix = evidence linking rules
```

For example:

```text
Scenario Pattern says: Web intrusion should follow WAF → Web → Host Exec.
Correlation Matrix says: WAF and Web are linked by src_ip + url; Web and Host Exec are linked by host + time window.
```

## 3. How Does a Link Happen?

Suppose there is a Join:

```text
waf_to_web_access_by_ip
```

It links WAF alerts and Web access logs.

The system does the following:

```text
1. Take waf_alert events from evidence_bundles
2. Take web_access_log events from evidence_bundles
3. Read the Join rule
4. Compare whether src_ip matches
5. Optionally compare whether url matches
6. Check whether time is within a reasonable window
7. If matched, generate a join_edge
```

What the LLM receives is not "guess the link yourself," but structured results:

```json
{
  "join_id": "waf_to_web_access_by_ip",
  "left_ref": "waf-001",
  "right_ref": "web-009",
  "match_keys": {
    "src_ip": "203.0.113.10",
    "url": "/upload.php"
  },
  "time_window": "alert_context",
  "confidence": 0.9
}
```

## 4. Configuration and verification

Configuration defaults to `dataasset/`; optionally copy it to `dataasset_my/` and set `DATAASSET_ROOT` for isolation. Check supported fields and runtime behavior in the [reference](21-cross-source-field-correlation.md), then run `python3 src/secweaver.py validate` and the relevant offline example. A matching link is not proof of attack success; no match does not establish complete coverage.

# Analysis contract

This file is the normative contract for scenario selection, parameters, evidence strength, counting, WAF coverage, and redaction. Keep [analysis-contract.zh-CN.md](analysis-contract.zh-CN.md) aligned.

## Contents

1. Scenario decision table
2. Parameter contract
3. Success evidence ladder
4. Unified counting and deduplication
5. `waf_coverage`
6. Redaction contract
7. Required report behavior

## 1. Scenario decision table

Choose the primary scenario from the user's question, not merely from the declared asset. An explicit user-selected anchor wins. Add secondary scenarios when the evidence crosses stages.

| User question / strongest intent | Primary | Pattern | Notes |
|---|---|---|---|
| Did WAF block it, was it real, or did anything bypass WAF? | S4 | `S4_alert_confirmation` | Always compare WAF with gateway and host-side evidence |
| Was a WebShell/upload/RCE successful? | S2 | `S2_web_breach` | Prefer when execution or file evidence already exists |
| What did this external IP hit? | S1 | `S1_external_ip_trace` | External-source scope; do not treat a public IP as a host |
| Is this host command/syslog behavior risky? | S5 | `S5_host_risk` | Single-host behavior is primary |
| Did activity move between hosts? | S3 | `S3_lateral_movement` | Use SSH/account/target-exec evidence |
| Was an account compromised? | S6 | `S6_account_compromise` | Account is the investigation anchor |
| Was data staged or exfiltrated? | S7 | `S7_data_exfiltration` | Requires connect/DNS/traffic/database evidence |
| Is this host communicating with C2 infrastructure? | S8 | `S8_c2_detection` | Start from host egress; correlate process, DNS, and network sessions |

Tie-break order: explicit anchor > user question > confirmed evidence stage > declared asset list. For "WAF asset + external IP + bypass/missed" choose **S4 primary**, with S1/S2 secondary when supported.

## 2. Parameter contract

Use ISO 8601 timestamps with an explicit offset. Interpret a local calendar day as `00:00:00` through `23:59:59` in the user's timezone and state that timezone.

| Parameter | Meaning | Rules |
|---|---|---|
| `attacker_ip` | External or initiating source IP | Primary S1/S4 source anchor |
| `src_ip` | Connector/template source-IP alias | Mirror `attacker_ip` only when the selected template requires it |
| `host` | One canonical victim host name or IP | Use for S5/S7/S8; do not place an external public IP here |
| `hosts` | Multiple victim hosts | Use only when the investigation explicitly scopes several hosts |
| `host_ip` | Victim or lateral target IP | Prefer when the asset template distinguishes host IP from name |
| `target_ip` | Destination/victim discovered from WAF/gateway | Do not invent it; enrich from evidence |
| `alert_time` | One alert anchor | Use alert-relative windows only when a specific alert is selected |
| `time_start`, `time_end` | Inclusive investigation bounds | Required for live fetches; include timezone offset |
| `limit` | Connector result ceiling | Report truncation; never present a limited result as exhaustive |

If an IP is absent from asset host coverage and is publicly routable, treat it as `attacker_ip` unless the user explicitly identifies it as a managed host. Preserve the user's original parameters in the report and separately state any normalized/enriched parameters.

## 3. Success evidence ladder

Use the strongest supported level as `attack_status`; HTTP status alone never proves command execution.

| Level | `attack_status` | Minimum evidence | Allowed conclusion |
|---|---|---|---|
| L0 | `insufficient_evidence` | Missing/failed/truncated sources prevent a conclusion | State the gap only |
| L1 | `blocked` | WAF `block` plus no backend/upstream reach | Blocked attempt |
| L2 | `attempted` | Suspicious WAF/WEB/auth event without success evidence | Attempt observed |
| L3 | `suspected_success` | Backend reached, upload redirect, or suspicious response without D2 confirmation | Possible bypass/success |
| L4 | `confirmed_success` | Matching `host_exec`, `host_file_op`, `host_connect`, target auth success, or equivalent D2 evidence | Confirmed execution/landing/lateral stage |

Examples:

- WEB `200`/`302` with no host evidence: at most `suspected_success`.
- WEB request + same target/time/listener `host_exec`: `confirmed_success`.
- SSH client command alone: attempted or suspected; target `ssh_auth` success plus target exec confirms lateral success.
- A drill/lab hypothesis does not change `attack_status`; it belongs in context and response priority.

## 4. Unified counting and deduplication

Process and kernel context require snapshot-aware interpretation. A `process_start`
snapshot delta means first observed since the previous scan, not an exact exec time;
a kernel-module/container baseline does not prove a new load/create operation.
Keep `host_process` and `host_kernel_context` types intact instead of relabeling them
as `host_exec`. Current deterministic exec/connect detectors do not scan these types;
if only these snapshots exist, report that behavior coverage is insufficient.
For Linux container records from Agent 0.3.29 onward, `process_count` counts unique
observed PIDs; `pids` is sorted and capped at 100. A larger count than list length
means the list is truncated. Earlier records can overcount cgroup-controller entries;
deduplicating a truncated historical list does not recover its true total.

Report these counts before narrative:

| Name | Source | Use |
|---|---|---|
| `raw_count` | `fetch_summary.total_fetched_events` | Events returned before deduplication |
| `retained_count` | `fetch_summary.total_events` | Canonical count used in inventory, findings, and coverage |
| `deduplicated_count` | `fetch_summary.total_deduplicated_events` | Removed duplicates |
| `sampled_count` | Analyst-declared subset | Only when a large retained set was sampled |

Rules:

1. Use retained events for all report totals unless a field explicitly says `raw`.
2. Show raw, retained, and deduplicated counts together; never mix their denominators.
3. Count each retained `evidence_id` once. If `evidence_id` is absent, use the fetcher's retained bundle as authoritative and disclose the limitation.
4. Do not deduplicate again by timestamp or message text in the prompt.
5. If metadata conflicts with the actual bundle length, report `count_inconsistency`, use the bundle count for analysis, and lower confidence.

## 5. `waf_coverage`

Produce `waf_coverage` for S4 or whenever the user asks about WAF misses. Match in this order:

1. Exact `trace_id`/request id.
2. Normalized source IP + virtual host + method + normalized path in `alert_context`.
3. Source IP + target + short time proximity, marked lower confidence.

Normalize paths for matching only: decode safe URL encodings, remove fragments, and separate query parameters. Keep a redacted display form for evidence citations.

| Field | Counting rule |
|---|---|
| `waf_alert_count` | Retained WAF alerts in scope |
| `web_access_raw_count` | Pre-dedup gateway events for the same scope |
| `web_access_retained_count` | Retained gateway events for the same scope |
| `blocked_count` | Matched WAF block with no backend reach |
| `backend_reached_count` | Retained WEB events with a resolved upstream/target that was reached |
| `suspicious_without_waf_count` | Suspicious retained WEB events with no matching WAF alert |
| `confirmed_bypass_count` | Subset of suspicious misses confirmed by L4 host-side evidence |
| `unmatched_waf_count` | WAF alerts without a matching gateway request |
| `deduplicated_count` | WEB duplicates removed before coverage analysis |

`confirmed_bypass_count` is a subset, not an additive category. Do not call all non-alerted WEB traffic a bypass. Benign health checks and unsuccessful generic probes may be `not_alerted`, but only suspicious requests enter `suspicious_without_waf_count`.

## 6. Redaction contract

Reports and golden outputs must contain no reusable secret values.

- Replace passwords, tokens, API keys, cookies, authorization headers, private keys, and credential-bearing URI/command arguments with `[REDACTED]`.
- Redact `sshpass -p`, `password=`, `token=`, bearer values, query/body credentials, and sensitive config contents.
- Preserve only the fact that credential material appeared, the field category, and a safe command/path fragment.
- Every structured `evidence_ref` must include `evidence_id` and `redacted: true`.
- Use `excerpt`, never `raw_snippet`. Do not link an unredacted artifact without a sensitivity warning.
- Set report-level `redaction.applied=true` and `redaction.contains_reusable_secrets=false`.

## 7. Required report behavior

1. Output `fetch_summary` and counting scope first.
2. Output a separate `verdict` with severity, `attack_status`, confidence, and disposition.
3. Output `waf_coverage` for S4/WAF-miss investigations.
4. Cite stable `evidence_id` values for each finding.
5. Keep facts, interpretations, hypotheses, and data gaps distinguishable.
6. Provide `chain_coverage`, `join_refs`, and executable `fetch_next` hints.

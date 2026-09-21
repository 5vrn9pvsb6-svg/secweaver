---
name: alert-confirmation
description: >-
  Secondary triage of WAF/WEB/IDS security alerts: false positive vs real attack,
  payload analysis, and attack success confirmation using correlated host logs.
  Two-layer verdict model. Use for告警确认, alert confirmation, 误报, 真实攻击,
  WAF alert, SQL injection triage, 是否攻击成功, 有没有打穿, or SecWeaver S4
  WEB alert analysis after selecting alert assets.
---

# Alert Confirmation

SecWeaver Skill: **secondary triage** of WAF/WEB/IDS alerts — false positive, real attack, and whether the attack succeeded.

**Role:** Two-layer triage — first judge “real or not,” then “succeeded or not”; on success confirmation, hand off to traceability analysis.

Machine-readable output contract: [`output-schema.json`](output-schema.json). Single-alert
and batch outputs share the versioned envelope while retaining their domain-specific shape.

## Two-layer triage (no skipping layers)

```text
Layer 1 alert_verdict
  false_positive | scanning_or_probe | suspicious | confirmed_attack

Layer 2 attack_outcome (when layer 1 ≥ suspicious)
  not_applicable | blocked | attempt_failed | success_confirmed | success_unknown
```

**Key:** Layer 1 may use D1/WAF only; layer 2 `success_confirmed` **requires** D2 (host_exec/connect/file_op/host_persistence).

## Preconditions (soft gate)

| completeness verdict | Mode |
|---|---|
| `alert_triage_only` | `triage_only`: layer 1 only; layer 2 capped at success_unknown |
| `full/partial_traceable` | `full`: may judge success_confirmed |
| No precheck | `full`, but confidence_ceiling ≤ 0.7 |

WAF-only **can run** this Skill, but Markdown must state “cannot confirm attack success.”

## When to use

- “Is this WAF alert a false positive or a real attack?”
- “Analyze today’s security alerts for IP XX — did the attack succeed?”
- Batch WEB alert noise reduction
- public S4 alert-confirmation scenario: select WEB security alert assets for confirmation

## Input

```json
{
  "investigation_intent": "Analyze WEB security alerts; confirm FP/real/success",
  "scenario": "S4",
  "params": {
    "attacker_ip": "203.0.113.10",
    "target_ip": "10.0.1.5",
    "alert_time": "2026-06-21T14:30:00+08:00",
    "time_window_minutes": 10
  },
  "completeness_precheck": {
    "overall_verdict": "partial_traceable",
    "confidence": 0.75,
    "next_skill_blocked": false
  },
  "primary_alerts": [
    {
      "alert_id": "WAF-20260621-001",
      "timestamp": "2026-06-21T14:30:05+08:00",
      "src_ip": "203.0.113.10",
      "url": "/api/user?id=1' OR 1=1--",
      "rule_id": "942100",
      "rule_name": "SQL Injection",
      "payload": "id=1' OR 1=1--",
      "action": "blocked",
      "host": "web-01"
    }
  ],
  "correlated_evidence": {
    "web_access_log": [],
    "host_exec": [],
    "host_connect": [],
    "host_file_op": []
  }
}
```

Batch mode: `"batch_mode": true` + multiple `primary_alerts` → per-alert JSON + `batch_summary` + top-level `fetch_summary`.

## fetch_summary（输出必含）

脚本 `--fetch` 或传入 `evidence_bundles` 后，输出 JSON 顶层含 `fetch_summary`；`markdown_report` 首段为 **数据取数统计**。

| Field | Meaning |
|---|---|
| `total_events` | 拉取/传入的事件总数 |
| `by_asset_type` | 按 asset_type 计数（waf_alert、host_exec…） |
| `asset_ids` / `asset_count` | 涉及 dataasset 资产 |
| `asset_fetch_stats` | 按 dataasset 资产列出取数请求数、实际查询数、缓存命中、成功/失败、拉取数据量、最终保留数据量、去重/窗口过滤量 |
| `fetch_mode` | live / dry_run / plan_only |
| `time_window` | time_start / time_end / attacker_ip |
| `attacker_ip_log_time_range` | first_seen / last_seen for events in fetched logs matching `attacker_ip` |
| `truncated_asset_types` | 可能触顶 limit 的类型 |
| `primary_alert_count` | WAF 主告警条数（S4） |

**Agent 汇报给用户时**：先说明拉了多少资产、多少事件、是否触顶，并打印每个资产的拉取次数与数据量（`asset_fetch_stats` / Markdown “按数据资产”表），再给出 Layer 1/2 研判结论。
If `attacker_ip` is present, the data-fetch section must include that IP's first and last timestamp observed in the fetched logs.

Platform may call `scripts/confirm.py` to generate triage skeleton.

## Triage workflow

```text
Step 0  Read completeness_precheck → triage_only / full
Step 1  Parse primary_alert (rule, payload, action, host)
Step 2  Layer 1: payload + attack-types.json → alert_verdict
Step 3  Correlate web_access_log (same IP, ±10min)
Step 4  Layer 2: correlate host_exec/connect/file_op（±15~30min，**受害 target_ip** 来自 WAF/gateway `upstream_addr`，对应 D2 的 `host_ip`）
Step 5  Success indicators → attack_outcome / attack_success
Step 6  confidence, recommended_action, next_skill
Step 7  Output JSON + Markdown triage card（**必须先汇报 fetch_summary 数据取数统计**）
```

## Output JSON (single alert)

An empty `primary_alerts` list is a valid empty batch, not an engine error. Return
`status=no_primary_alerts`, `results=[]`, `attack_outcome=not_applicable`, batch
statistics and the CLI fetch summary/Markdown report. Gateway miss scanning and
campaign assessment still run independently; inspect their findings and query gaps.
No primary alerts does not establish absence of attacks. The CLI exits 0 for this
valid empty result and nonzero for an error result.

```json
{
  "alert_type": "alert_confirmation",
  "alert_id": "WAF-20260621-001",
  "alert_verdict": "confirmed_attack",
  "attack_type": "sqli",
  "attack_type_label": "SQL Injection",
  "attack_outcome": "blocked",
  "attack_success": false,
  "confidence": 0.82,
  "summary": "Real SQL injection attempt; WAF blocked; attack success not confirmed",
  "recommended_action": "log_and_monitor",
  "attacker_ip_profile": {
    "ip": "203.0.113.10",
    "scope": "public",
    "evidence_geo": {
      "event_count": 12,
      "source_bundles": ["waf_alert", "web_access_log"],
      "evidence_refs": ["waf-xxx", "web-access-log-xxx"]
    },
    "attributes": ["公网地址", "ISP: ExampleNet"],
    "online_lookup": {
      "provider": "ipwho.is",
      "status": "success",
      "isp": "ExampleNet",
      "asn": "AS64500",
      "mobile": false,
      "proxy": false,
      "hosting": false
    },
    "threat_intel": {
      "virustotal": {
        "provider": "virustotal",
        "status": "success",
        "last_analysis_stats": {"malicious": 0, "suspicious": 0},
        "reputation": 0,
        "network": "203.0.113.0/24"
      }
    }
  },
  "ip_action_guard": null,
  "next_skill": null,
  "data_gaps_impact": ["No host_exec; cannot confirm breach"]
}
```

### alert_verdict

| Value | Meaning |
|---|---|
| `false_positive` | False positive |
| `scanning_or_probe` | Scan / probe |
| `suspicious` | Suspicious |
| `confirmed_attack` | Confirmed attack |

### attack_outcome

| Value | Meaning |
|---|---|
| `not_applicable` | False positive; not evaluated |
| `blocked` | WAF blocked |
| `attempt_failed` | No success observed |
| `success_confirmed` | D2 confirms success |
| `success_unknown` | No D2; cannot judge |

### recommended_action

`close_as_fp` | `log_only` | `log_and_monitor` | `manual_review_30m` | `escalate_investigate` | `block_ip` | `isolate_host`

`block_ip` has an IP-attribute guard: when the source IP profile is missing, not verified, or indicates NAT/shared exit risk such as mobile network, proxy/VPN, CDN, or shared egress, the Skill must downgrade direct blocking to `manual_review_30m` and fill `ip_action_guard.reason_label`. Use `"ip_intel_online": true` in params when online VirusTotal / ipwho.is / ip-api enrichment is required; otherwise the Skill reports local/evidence-only attributes and requires manual confirmation before blocking. Prefer `"ip_intel_provider": "ipwhois"` when `ip-api.com` is blocked or timing out; `ip-api` remains a legacy fallback.

The Markdown report must print attacker IP attributes as direct fields and tell the user where they came from:
- `IP`, `scope`, log geo, ISP/org/ASN, network, `mobile`, `proxy`, `hosting`, tags, and attribute labels.
- **Log evidence source**: `attacker_ip_profile.evidence_geo.source_bundles`, `event_count`, and sample `evidence_refs`.
- **Online intelligence source**: `attacker_ip_profile.online_lookup.provider`, `status`, and `query`; when provider is VirusTotal, include VT stats/reputation if present.
- **VirusTotal source**: when `attacker_ip_profile.threat_intel.virustotal` exists, print VT `status`, detection stats, reputation, ASN/owner, network, tags, and error/message if lookup failed. If VT returns `status=config_missing`, explicitly tell the user to configure a VirusTotal API Key via `virustotal_api_key` / `vt_api_key`, `VIRUSTOTAL_API_KEY` / `VT_API_KEY`, or the configured `virustotal.credentials_ref`. This is printed in addition to the primary online source such as ipwho.is.

## Markdown triage card (required)

```markdown
## Alert Triage Report

### 数据取数统计
| 总事件 | 资产包 | 时间窗 | waf_alert | web_access | host_exec | … |
| 数据资产 | 取数请求/实际查询/缓存命中 | 拉取数据 | 保留数据 | 成功/失败 |
（或使用输出 JSON 的 `fetch_summary` 字段）

**Alert ID**: {alert_id}
**Time** | **Source IP** | **URL** | **Rule** | **WAF action**

### Layer 1: Alert authenticity
| Verdict | Attack type | Payload analysis | Confidence |

### Layer 2: Attack outcome
| Success? | Outcome | Success evidence |

### Recommended action
**{recommended_action_label}**

### Attacker IP attributes
Directly print IP attribute fields and information source:
`IP`, `scope`, geo, ISP/org/ASN, network, `mobile/proxy/hosting`, log evidence source, online intelligence source.

### Data gaps / next steps
{data_gaps_impact} / {next_skill}
```

## Downstream Skills

| Condition | next_skill |
|---|---|
| confirmed + success_confirmed | `traceability_analysis` |
| Missing D2 | Recommend `data-source-completeness` + deploy audit-port-execmon |
| exec needs grading | `external-listener-cmd-risk` |

This Skill **does not** perform full attack-chain / lateral investigation (→ traceability analysis).

## Prohibited

1. No payload → no `confirmed_attack` (max suspicious)
2. No D2 → no `success_confirmed` or “breached”
3. Do not fabricate correlated_evidence
4. After false_positive → no success_confirmed
5. Do not output lateral host lists (belongs to traceability)
6. WAF blocked and no D2 → attack_success defaults false

## dataasset / SOPS Vault

Minimum bundle for alert confirmation: `dataasset/bundles/bundle-alert-confirm-min.json` (WAF + WEB access + host_exec, etc.).

### S4 gateway bootstrap (WAF-only asset)

When `--asset-id asset-waf-prod-01` (or any WAF-only list) is used with `--fetch`, the platform **auto-appends** the canonical public asset `asset-secweaver-gateway-access` plus `asset-secweaver-host-exec`, `asset-secweaver-host-connect`, and `asset-secweaver-host-file-op` (Layer 2). A private registry may expose a legacy gateway asset through the compatibility alias; a live query failure is reported as a data-source gap and does not silently switch logstores. Set `SECWEAVER_S4_GATEWAY_ASSET_ID` only when a deployment intentionally overrides the default. Do not run WAF-only triage without gateway — `gateway_miss_scan` will be zero.

If the gateway attacker-IP query returns zero but the same asset has records in the investigation window, S4 performs one bounded `*_by_time` fallback query. The report distinguishes `gateway_log_no_matching_request` (gateway data exists, but no same-source/same-path request matched) from `gateway_log_missing` (the gateway query returned no records at all), and renders them under separate sections. Fallback rows from other source IPs are available for gateway miss scanning but cannot trigger D2 host-side queries.

Gateway/WAF source-IP joins normalize parser-added surrounding quotes (for example, `"39.144.124.34`) before matching. The original evidence value is preserved; the normalized value is used only for correlation and report aggregation.

`gateway_miss_scan` flags:
- `gateway_exploit_no_waf_alert` — exploit URL in access log, no WAF alert
- `waf_block_bypass` — WAF `block` matches same method/path within ±5s but gateway still returned 200/302
- `waf_partial_block_same_path` — WAF blocked same path earlier, but this request (e.g. different method or .phtml) had no alert

```bash
# WAF-only asset — gateway + D2 host sources auto-appended
python3 src/skills/alert-confirmation/scripts/confirm.py \
  --asset-id asset-waf-prod-01 \
  --params '{"time_start":"2026-07-06T07:25:00+08:00","time_end":"2026-07-06T07:27:34+08:00"}' \
  --fetch --skip-completeness
```

```bash
python3 src/skills/alert-confirmation/scripts/confirm.py \
  --from-bundle --bundle bundle-alert-confirm-min \
  --params '{"attacker_ip":"203.0.113.10","time_start":"...","time_end":"...","host":"web-01","primary_alerts":[...]}' \
  --fetch
```

- `primary_alerts` usually from WAF asset `asset-waf-prod-01` (`waf_by_alert_id` / manual fill)
- `correlated_evidence` injected by `--fetch` grouped by asset_type
- Credential path: `vault://sls/security-readonly` (see `dataasset/credentials/`)

## Additional resources

- Design: [docs_dev/14-alert-confirmation-skill-design.md](../../../docs_dev/14-alert-confirmation-skill-design.md)
- Platform docs: [docs_user/17-alert-confirmation.md](../../../docs_user/17-alert-confirmation.md)
- Rules: [rules.md](rules.md)
- Attack types: [attack-types.json](attack-types.json)
- FP patterns: [fp-patterns.json](fp-patterns.json)
- Script: [scripts/confirm.py](scripts/confirm.py) (D2 time windows and `join_edges` driven by `correlation_engine`)
- Data access layer: [../_shared/data-access/README.md](../_shared/data-access/README.md) | [correlation_engine.py](../_shared/data-access/correlation_engine.py)
- Cross-source correlation: [docs_user/21-cross-source-field-correlation.md](../../../docs_user/21-cross-source-field-correlation.md) | [correlation-matrix.json](../../../dataasset/assets/correlation-matrix.json)
- Examples: [examples.md](examples.md) | Test data: [examples/alert-confirmation/](../../../examples/alert-confirmation/)

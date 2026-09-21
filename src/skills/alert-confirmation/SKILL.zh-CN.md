---
name: alert-confirmation
description: >-
  Secondary triage of WAF/WEB/IDS security alerts: false positive vs real attack,
  payload analysis, and attack success confirmation using correlated host logs.
  Two-layer verdict model. Use for告警确认, alert confirmation, 误报, 真实攻击,
  WAF alert, SQL injection triage, 是否攻击成功, 有没有打穿, or SecWeaver S4
  WEB alert analysis after selecting alert assets.
---

# 告警确认

SecWeaver Skill：对 WAF/WEB/IDS 告警做 **二次研判**——误报、真实攻击、攻击是否成功。

**定位**：两层体检——先判「真不真」，再判「成没成功」；成功确认后移交溯源分析。

机器可读输出契约见 [`output-schema.json`](output-schema.json)。单条告警和批量告警
共享版本化 envelope，同时保留各自的领域字段结构。

## 两层研判（不可跳层）

```text
第一层 alert_verdict
  false_positive | scanning_or_probe | suspicious | confirmed_attack

第二层 attack_outcome（第一层 ≥ suspicious 时）
  not_applicable | blocked | attempt_failed | success_confirmed | success_unknown
```

**关键**：第一层可仅用 D1/WAF；第二层 `success_confirmed` **必须** 有 D2（host_exec/connect/file_op/host_persistence）。

**补充**：当无 D2 但网关访问日志（`web_access_log`）显示 HTTP 200 / upstream 200 时，输出 **`gateway_success_hint`**（应用层疑似成功提示），**不替代** `success_confirmed`。

## 前置条件（软门禁）

| completeness 结论 | 模式 |
|---|---|
| `alert_triage_only` | `triage_only`：仅第一层，第二层最高 success_unknown |
| `full/partial_traceable` | `full`：可判 success_confirmed |
| 无 precheck | `full`，但 confidence_ceiling ≤ 0.7 |

仅有 WAF **可以运行**本 Skill，但 Markdown 必须写「无法确认是否攻击成功」。

## 适用时机

- 「这条 WAF 告警是误报还是真实攻击？」
- 「分析今天 IP 为 XX 的安全报警，是否攻击成功？」
- 批量 WEB 告警降噪
- S4 公开告警确认场景：选择 WEB 安全告警资产做确认

## 适用输入

```json
{
  "investigation_intent": "分析 WEB 安全告警，确认误报/真实/是否成功",
  "scenario": "S4",
  "params": {
    "attacker_ip": "203.0.113.10",
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

批量模式：`"batch_mode": true` + 多条 `primary_alerts` → 逐条 JSON + `batch_summary` + 顶层 `fetch_summary`。

## fetch_summary（输出必含）

`--fetch` 或传入 `evidence_bundles` 后，JSON 顶层含 `fetch_summary`；`markdown_report` 首段为 **数据取数统计**（总事件数、按 asset_type、涉及资产、时间窗、是否触顶 limit、按 dataasset 资产的拉取次数与数据量）。
`fetch_summary.asset_fetch_stats` 必须按资产列出：取数请求数、实际查询数、缓存命中、成功/失败、拉取数据量、最终保留数据量、去重/窗口过滤量。
若输入包含 `attacker_ip`，`fetch_summary.attacker_ip_log_time_range` 必须输出该 IP 在已取日志里的 `first_seen` / `last_seen`、匹配事件数与来源 asset_type；Markdown 数据取数统计中也必须打印“该 IP 日志时间范围”。

**Agent 向用户汇报时**：先说明拉了多少资产、多少事件，并打印每个资产拉取了多少次、返回/保留了多少数据，再给出 Layer 1/2 研判。

平台可调用 `scripts/confirm.py` 生成研判骨架。

## 研判流程

```text
Step 0  读 completeness_precheck → triage_only / full
Step 1  解析 primary_alert（规则、payload、action、host）
Step 2  第一层：payload + attack-types.json → alert_verdict
Step 3  关联 web_access_log（同 IP，±10min）
Step 3b 网关层 gateway_success_hint（WAF pass/block + 网关 200 → likely/possible）
Step 4  第二层：关联 host_exec/connect/file_op（±15~30min，同 host）
Step 5  成功指标 → attack_outcome / attack_success
Step 6  confidence、recommended_action、next_skill
Step 7  输出 JSON + Markdown 研判卡片
```

## 输出 JSON（单条）

`primary_alerts` 为空属于有效空批次，不是引擎错误。返回 `status=no_primary_alerts`、
`results=[]`、`attack_outcome=not_applicable`、批次统计，CLI 仍附取数统计和 Markdown。
网关漏报扫描与 campaign 评估独立继续执行，应检查其发现和查询缺口。
没有主告警不能证明没有攻击。此有效空结果的 CLI 退出码为 0，错误结果为非零。

```json
{
  "alert_type": "alert_confirmation",
  "alert_id": "WAF-20260621-001",
  "alert_verdict": "confirmed_attack",
  "attack_type": "sqli",
  "attack_type_label": "SQL 注入",
  "attack_outcome": "blocked",
  "attack_success": false,
  "gateway_success_hint": {
    "level": "likely",
    "reason": "waf_pass_backend_200",
    "reason_label": "WAF 放行且网关 HTTP 200 到达 upstream",
    "evidence_refs": ["web-access-log-xxx"],
    "note": "应用层可能已成功；无 D2 证据时 attack_outcome 不得判为 success_confirmed"
  },
  "confidence": 0.82,
  "summary": "真实 SQL 注入尝试；WAF 已拦截；攻击未确认成功",
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
  "data_gaps_impact": ["无 host_exec，无法确认是否打穿"]
}
```

### alert_verdict

| 值 | 含义 |
|---|---|
| `false_positive` | 误报 |
| `scanning_or_probe` | 扫描/探测 |
| `suspicious` | 可疑 |
| `confirmed_attack` | 真实攻击 |

### attack_outcome

| 值 | 含义 |
|---|---|
| `not_applicable` | 误报，不评估 |
| `blocked` | WAF 已拦截 |
| `attempt_failed` | 未观察到成功 |
| `success_confirmed` | D2 证实成功 |
| `success_unknown` | 无 D2，无法判断 |

### gateway_success_hint（D1.5 网关提示，非 Layer 2 终判）

| 字段 | 含义 |
|---|---|
| `level: likely` | WAF pass + 网关 200，或 WAF block 但网关 200（bypass 疑似） |
| `level: possible` | 攻击 URL + 网关 200 + 较大响应体，但信号较弱 |
| `reason` | `waf_pass_backend_200` / `waf_block_bypass_backend_200` / `exploit_url_backend_200_large_body` |

**规则**：有 `gateway_success_hint` 时 `attack_success` 仍为 `false`；仅 D2 可升 `success_confirmed`。

### recommended_action

`close_as_fp` | `log_only` | `log_and_monitor` | `manual_review_30m` | `escalate_investigate` | `block_ip` | `isolate_host`

`block_ip` 必须经过 IP 属性闸门：当源 IP profile 缺失、未核验，或命中 NAT/共享出口风险（移动网络、代理/VPN、CDN、共享出口等）时，技能必须把直接封禁降级为 `manual_review_30m`，并填写 `ip_action_guard.reason_label`。如需在线查询 VirusTotal / ipwho.is / ip-api 属性，在 params 中传 `"ip_intel_online": true`；否则技能只输出本地/日志证据属性，并要求封禁前人工确认。`ip-api.com` 不稳定或被阻断时，优先用 `"ip_intel_provider": "ipwhois"`；`ip-api` 保留为 legacy fallback。

Markdown 报告必须把攻击源 IP 属性按字段直接打印，并告诉用户信息来源：
- 直接打印 `IP`、`scope`、日志地理、ISP/组织/ASN、网络段、`mobile`、`proxy`、`hosting`、tags、属性标签。
- **日志证据来源**：引用 `attacker_ip_profile.evidence_geo.source_bundles`、`event_count` 与样本 `evidence_refs`。
- **在线情报来源**：引用 `attacker_ip_profile.online_lookup.provider`、`status` 与 `query`；当 provider 为 VirusTotal 时，补充 VT 检测统计与 reputation。
- **VirusTotal 来源**：当 `attacker_ip_profile.threat_intel.virustotal` 存在时，额外打印 VT `status`、检测统计、reputation、ASN/owner、network、tags，以及失败时的 error/message。若 VT 返回 `status=config_missing`，必须明确告诉用户配置 VirusTotal API Key：可通过运行参数 `virustotal_api_key` / `vt_api_key`、环境变量 `VIRUSTOTAL_API_KEY` / `VT_API_KEY`，或修复 `virustotal.credentials_ref` 指向的 vault 密钥。该信息与 ipwho.is 等主在线源并列输出，不互相覆盖。

## Markdown 研判卡片（必出）

```markdown
## 告警研判报告

**告警 ID**：{alert_id}
**时间** | **源 IP** | **URL** | **规则** | **WAF 动作**

### 第一层：告警真实性
| 研判结果 | 攻击类型 | 载荷分析 | 置信度 |

### 第二层：攻击结果
| 是否成功 | 结果判定 | 成功证据 |

### 网关层提示（如有）
| level | reason | 关联网关日志 |

### 处置建议
**{recommended_action_label}**

### 攻击源 IP 属性
按字段直接打印 IP 属性与信息来源：
`IP`、`scope`、地理、ISP/组织/ASN、网络段、`mobile/proxy/hosting`、日志证据来源、在线情报来源。

### 数据缺口 / 下一步
{data_gaps_impact} / {next_skill}
```

## 与下游 Skill

| 条件 | next_skill |
|---|---|
| confirmed + success_confirmed | `traceability_analysis` |
| 缺 D2 | 建议 `data-source-completeness` + 接入 audit-port-execmon |
| exec 需分级 | `external-listener-cmd-risk` |

本 Skill **不做** 完整攻击链/横向调查（→ 溯源分析）。

## 禁止事项

1. 无 payload 不得 `confirmed_attack`（最高 suspicious）
2. 无 D2 不得 `success_confirmed` 或「已打穿」
3. 不得虚构 correlated_evidence
4. false_positive 后不得 success_confirmed
5. 不得输出横向主机清单（属溯源）
6. WAF blocked 且无 D2 时 attack_success 默认 false
7. `gateway_success_hint` 不得替代 `success_confirmed`，不得输出「已打穿主机」

## 与 dataasset / SOPS Vault

告警确认最小资产包：`dataasset/bundles/bundle-alert-confirm-min.json`（WAF + WEB 访问 + host_exec 等）。

### S4 网关自动追加（仅 WAF 资产时）

使用 `--asset-id asset-waf-prod-01`（或仅含 WAF 的资产列表）并 `--fetch` 时，平台**自动追加**公开标准资产 `asset-secweaver-gateway-access`，以及 `asset-secweaver-host-exec` / `asset-secweaver-host-connect` / `asset-secweaver-host-file-op`（Layer 2）。私有 DataAsset 根可通过兼容别名暴露旧网关资产；标准资产实时查询失败会原样报告为数据源缺口，不会静默切换到另一套 logstore。部署确实需要覆盖默认值时可设置 `SECWEAVER_S4_GATEWAY_ASSET_ID`。**禁止**在无网关 access 的情况下做 WAF 单源研判——`gateway_miss_scan` 将为 0。

如果网关按攻击 IP 精确查询返回 0 条，但同一资产在调查时间窗内有日志，S4 会追加一次有边界的 `*_by_time` 时间窗查询。报告会区分 `gateway_log_no_matching_request`（网关有数据，但没有匹配到同源同路径请求）和 `gateway_log_missing`（网关查询完全没有返回数据），并分别输出。时间窗回退查询到的其他源 IP 日志可用于网关漏检扫描，但不能触发 D2 主机侧查询。

WAF 与网关的源 IP 关联会在匹配前清理解析器附加的包围引号（例如 `"39.144.124.34`）。原始证据值保持不变，仅使用归一化值做关联和报告统计。

`gateway_miss_scan` 漏检类型：
- `gateway_exploit_no_waf_alert` — 网关命中攻击 URL，无对应 WAF 告警
- `waf_block_bypass` — WAF block 告警与同 method/path 的网关 200/302 在 ±5s 内高度吻合，疑似 bypass
- `waf_partial_block_same_path` — 同路径曾有 WAF 拦截，但本条请求（如不同 method、.phtml 上传、内存马 C2 GET）未告警/已放行

```bash
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

- `primary_alerts` 通常来自 WAF 资产 `asset-waf-prod-01`（`waf_by_alert_id` / 手工填入）
- `correlated_evidence` 由 `--fetch` 按 asset_type 分组注入
- 凭证路径：`vault://sls/security-readonly`（见 `dataasset/credentials/`）

## 附加资源

- 设计：[docs_dev/14-alert-confirmation-skill-design.md](../../../docs_dev/14-alert-confirmation-skill-design.md)
- 平台文档：[docs_user/17-alert-confirmation.md](../../../docs_user/17-alert-confirmation.md)
- 规则：[rules.md](rules.md)
- 攻击类型：[attack-types.json](attack-types.json)
- 误报模式：[fp-patterns.json](fp-patterns.json)
- 脚本：[scripts/confirm.py](scripts/confirm.py)（D2 时间窗与 `join_edges` 由 `correlation_engine` 驱动）
- 数据访问层：[../_shared/data-access/README.md](../_shared/data-access/README.md) | [correlation_engine.py](../_shared/data-access/correlation_engine.py)
- 跨源关联：[docs_user/21-cross-source-field-correlation.md](../../../docs_user/21-cross-source-field-correlation.md) | [correlation-matrix.json](../../../dataasset/assets/correlation-matrix.json)
- 样例：[examples.md](examples.md) | 测试数据：[examples/alert-confirmation/](../../../examples/alert-confirmation/)

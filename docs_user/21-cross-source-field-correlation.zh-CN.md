# 跨源字段关联说明

**语言：** [English](21-cross-source-field-correlation.md) | 简体中文（本文）

> 机器可读 Join 规格：[`dataasset/assets/correlation-matrix.json`](../dataasset/assets/correlation-matrix.json)  
> 场景编排配置：[`dataasset/scenarios/anchor-patterns.json`](../dataasset/scenarios/anchor-patterns.json)  
> 历史设计评估：[correlation-matrix设计评估.md](../docs_dev/history/22-correlation-matrix-design-evaluation.zh-CN.md)
> 字段归一化：[`dataasset/configure/evidence-minimum-fields.json`](../dataasset/configure/evidence-minimum-fields.json)  
> 单资产 schema：[`dataasset/assets/`](../dataasset/assets/)

本文说明 **不同数据源资产之间用什么字段关联、时间窗多大、适用于哪条调查链**。  
Skill（告警确认、溯源分析、风险识别）拼链时 **只应使用 correlation-matrix 中已定义的 Join**，无规则则标注 `data_gap`，不得臆造关联。

## 网络上下文不等于外传证据

`host_connect_to_dns`、`nta_session_correlation` 和原始 DNS 时间线使用中性的
`network_activity` 阶段，`mitre_id` 为空；保留证据引用、时间、图关系和来源覆盖。
选择 S7 或 S8 场景本身不能证明外传或 C2，中性网络关联也不计作主机执行证据。
消费报告的程序应允许上下文行没有 ATT&CK 编号。具有独立证据的攻击阶段仍单独保留；
确认数据外传需要传输方向/内容及佐证。默认 `webshell-to-ssh-lateral` 案例展示下载与横向，
不能证明外传。已保存的旧报告需重新生成才能更新标签。

下载关联外连和非白名单外连保留风险等级与复核规则，但使用 `network_activity` 标签，
不自动附加 T1048.003。入口推断说明属于被选中的候选；选中 WEB/WAF 入口后，
不能借用退化候选中“缺少 WEB/WAF”的说明。


---

**按任务阅读：** 可直接跳到需要的章节，不必从头通读。

- [二、双字段模型（v1.1）](#二双字段模型v11)
- [三、Canonical 字段语义（溯源必记）](#三canonical-字段语义溯源必记)
- [六、跨源关联（D1 ↔ D2 ↔ 网络）](#六跨源关联d1--d2--网络)
- [八、S1 完整示例（外网 IP 溯源）](#八s1-完整示例外网-ip-溯源)

## 零、设计意图

`correlation-matrix.json` 的核心目标是把安全调查里的“证据如何拼链”沉淀成一份 **机器可读、可校验、可复用的 Join 合同**。它不是字段字典，也不是查询模板，而是回答：

- 哪两类证据可以关联？
- 用哪些键关联？
- 时间上允许相差多久？
- 这条关联适用于哪个调查场景？
- 关联成功后如何支撑告警确认、溯源分析或风险识别？

### 0.1 为什么要集中设计 correlation-matrix

如果每个 Skill 自己写关联逻辑，会出现几个问题：

| 问题 | 后果 |
|---|---|
| Join 规则散落在多个脚本 / Prompt 里 | 同一条攻击链在不同 Skill 中结论不一致 |
| 字段名各写各的 | `ip`、`src_ip`、`host_name`、`host` 容易混用 |
| 时间窗靠经验写死 | 容易把相隔很久的事件误拼，或漏掉真实延迟 |
| 取数逻辑和关联逻辑混在一起 | 以后换 SLS/ES/DB 查询模板时会影响 Join 语义 |
| AI 自由发挥关联 | 报告难审计，无法解释“为什么这两条证据有关” |

因此 matrix 采用 **一份规则，多处消费**：告警确认、溯源分析、风险识别都只使用 matrix 中声明过的 Join；无规则或无命中时必须输出 `data_gap`，不能臆造攻击链。

### 0.2 为什么拆成这几层

| 层 | 解决的问题 | 设计原因 |
|---|---|---|
| `field_policy` | Join 字段怎么读 | 推荐 canonical，同时兼容源字段，降低接入成本 |
| `time_windows` | 多大时间范围内算相关 | 不同攻击阶段延迟不同，必须显式化、可审计 |
| `internal_joins` | 主机内部 D2 行为怎么串 | exec / connect / file 是同一主机上的连续行为，和跨源桥接分开更清晰 |
| `cross_source_joins` | 不同数据源之间如何桥接 | WAF、WEB、主机、SSH、防火墙、DNS 等来源语义不同，需要显式 Join |
| `priority` / `confidence` | Join 为什么先看、为什么可信 | 给 UI、报告和开发评审提供一致解释，避免只看到一个黑盒分数 |
| `scenario_patterns` | 场景按什么链路调查 | S1/S2/S4/S5 等场景有不同起点、资产包和推荐链，已拆到 `scenarios/anchor-patterns.json` |
| `fetch_plan` | 如何为某条 Join 拉取证据 | 查询参数和索引字段属于取数层；需要取数的 Join 必须显式声明 `template_id` 与 `param_map` |
| `constraints` | Skill 必须遵守什么 | 给 AI 和脚本提供硬边界，确保输出可复核 |

### 0.3 为什么区分 `internal_joins` 和 `cross_source_joins`

安全调查通常分两段：

```text
外部入口链路：WAF / WEB / SSH / 防火墙 / DNS 等跨源证据
        │
        ▼
主机内部行为：host_exec / host_connect / host_file_op 等 D2 事件
```

`cross_source_joins` 负责回答：**攻击从哪里来，打到了哪台主机，是否发生横向或外联？**

`internal_joins` 负责回答：**主机上看到的命令执行、主动外连、写文件是不是同一波攻击行为？**

这样拆分后，入口溯源和主机行为链可以独立维护，也可以在 S4 告警确认、S5 主机风险、S2 Web 入侵等场景中复用同一批 D2 规则。

### 0.4 为什么字段归一不放在 matrix 里

matrix 只描述 Join 语义，不维护全量字段别名。字段归一的权威来源是：

1. 全局别名：`evidence-minimum-fields.json` 的 `field_aliases`
2. 资产别名：`asset-*.json` 的 `field_aliases`
3. Join 局部例外：`join_keys.*_variants`

这样可以避免出现三套字段映射互相漂移：

```text
schema.fields      保留源字段
field_aliases      负责源字段 → canonical
correlation-matrix 负责 canonical / 源字段如何 Join
query-templates    负责具体查询索引字段
```

### 0.5 为什么时间窗分成 Join 窗和调查窗

- Join 时间窗：用于判断两条证据是否时间上相关，例如 `attack_success`、`host_behavior_chain`。
- 调查时间窗：用于决定拉多大范围的数据，例如 `trace_default` 通过 `scenarios/anchor-patterns.json` 的 `investigation_window` 推导 `time_start/time_end`。

也就是说，可以先按 `trace_default` 拉 30 小时范围的日志，再用更小的 Join 时间窗判断哪些事件真正相关。这样既不容易漏数据，又能降低误关联。

---

## 一、三层数据模型

```text
┌─────────────────┐     field_aliases      ┌──────────────────┐
│  源日志字段      │ ─────────────────────▶ │  canonical 字段   │
│  ip / host_name │                        │  src_ip / host    │
└─────────────────┘                        └────────┬─────────┘
                                                    │
                                                    ▼
                                           ┌──────────────────┐
                                           │ correlation-matrix│
                                           │  Join 规则 + 时间窗│
                                           └────────┬─────────┘
                                                    │
                                                    ▼
                                           evidence_bundles 拼链
```

| 层次 | 文件 | 回答的问题 |
|---|---|---|
| L1 单资产 | `assets/asset-*.json` | 这份数据有哪些字段？ |
| L2 归一化 | `evidence-minimum-fields.json` | 源字段如何变成 canonical？ |
| L3 跨源关联 | `assets/correlation-matrix.json` | canonical 字段之间如何 Join？字段归一不在 matrix 重复维护 |

---

## 二、双字段模型（v1.1）

Join 规则 **推荐写 canonical 名**，但允许在局部场景直接写源字段；匹配时会同时支持归一字段与 alias 字段：

```text
读值顺序（declared_first_then_alias）：
  1. Join 中声明的字段本身（可为 host，也可为 host_name）
  2. join_keys.*_variants                 ← 单条 Join 额外字段名（少量例外）
  3. alias 反向候选：canonical → 源字段（host → host_name）
  4. alias 正向候选：源字段 → canonical（host_name → host）
```

| 用途 | 写字段 | 读字段 |
|---|---|---|
| Join 规则定义 | 推荐 **canonical**（`host`、`src_ip`），允许源字段（`host_name`） | 声明字段 + 单条 variants + 全局/资产 alias 正反向候选 |
| SLS/ES 查询 | `fetch_plan.param_map` + `query-templates`（如 `host_name: params.host`） | 模板 params 决定索引键 |
| 证据归一化 | `evidence-minimum-fields.field_aliases` + `asset.field_aliases` | fetch 后补全 canonical |

**示例**：`web_access_to_host_exec` 可以写 `host`，也可以在确知某侧源字段时写 `host_name`。解析器会先读声明字段，再通过全局/资产级 `field_aliases` 正反向补候选字段。推荐默认写 canonical，只有在局部数据源确实需要时才写源字段。

实现：`field_resolver.py` → `resolve_field_value()` / `match_join_key()`；**执行引擎** → `correlation_engine.py`（Join 匹配、时间窗、`plan_fetch`、`join_edges` 输出契约）。

---

## 2.1 Join 优先级与可信度

每条 Join 必须声明：

```json
{
  "priority": 96,
  "confidence": {
    "base": 0.88,
    "max": 0.96,
    "optional_key_increment": 0.05,
    "reason": "WEB upstream/host 与主机执行在攻击成功窗口内对齐，是确认打穿的核心主链。",
    "signals": ["target_ip to host_ip exact", "host optional", "attack_success window"]
  }
}
```

解释口径：

| 字段 | 用途 |
|---|---|
| `priority` | 调查排序和 UI 展示顺序；90+ 为强主链，70-89 为常规调查链，60-69 为辅助线索 |
| `confidence.base` | required key 命中后的基础可信度 |
| `confidence.max` | optional / secondary key 命中后的可信度上限 |
| `optional_key_increment` | 每个 optional / secondary key 命中时的加分幅度 |
| `reason` | 安全运营可读解释，说明为什么这条边可信 |
| `signals` | 审计用信号列表，例如 exact key、短时间窗、5-tuple、CMDB 富化 |

运行时 `join_edges[]` 会带出 `priority`、`confidence_base`、`confidence_ceiling` 和 `confidence_reason`。  
`dataasset/schema/correlation-matrix.schema.json` 负责结构校验；`validate.py` 继续负责跨文件引用、字段可达、fetch_plan 和 anchor/bundle 语义校验。

---

## 三、Canonical 字段语义（溯源必记）

| Canonical | 含义 | 常见 asset_type | 易混点 |
|---|---|---|---|
| `src_ip` | **攻击源 / 客户端 IP** | waf_alert, web_access_log, ssh_auth | ≠ 受害机 IP |
| `host` | **受害主机 hostname** | host_exec, ssh_auth, web_access_log | 归一化后统一用 `host` |
| `host_ip` | **受害主机 IP** | host_exec, firewall_log, CMDB | 用于横向、防火墙 Join |
| `dst_ip` | 连接目的 IP | host_connect, firewall_log | 外连/C2/内网目的 |
| `url` | HTTP 路径+query | waf_alert, web_access_log | 建议 path 前缀匹配 |
| `alert_id` | WAF 告警唯一键 | waf_alert | 源字段常为 `trace_id` |
| `listener_pid` | 对外入口进程 PID | host_exec, host_connect | D2 行为链主锚点 |
| `user` | 登录/操作账号 | ssh_auth, host_exec | SSH 横向关键键 |

### 生产环境别名示例

**`asset-secweaver-host-exec`**（audit-port-execmon → SLS）：

| 层级 | 源字段 | Canonical | 说明 |
|---|---|---|---|
| 证据 Join | `host_name` | `host` | 未归一化日志可直接 Join |
| 查询参数 | `host_name` | — | Join 级 `fetch_plan.param_map.host_name` ← `params.host` |
| 时间 | `time` | `timestamp` | 同上 |

**`asset-waf-prod-01`**（通用 WAF 告警日志）：

| 层级 | 源字段 | Canonical |
|---|---|---|
| 证据 Join | `ip` | `src_ip` |
| 查询参数 | `ip` | — | 模板 `waf_gateway_plugin_by_ip_time` 用 `ip: {src_ip}` |
| 告警键 | `trace_id` | `alert_id` |

查询参数映射由 Join 级 `fetch_plan.param_map` 与 `query-templates` 定义；字段归一仍维护在全局 / 资产级 `field_aliases`。

---

<a id="三时间窗约定"></a>

## 四、时间窗约定

| 名称 | 范围 | 用途 |
|---|---|---|
| `alert_context` | ±10 分钟 | WAF 告警前后 WEB 访问 |
| `attack_success` | 前 5 / 后 30 分钟 | 告警确认第二层、WEB→exec |
| `host_behavior_chain` | ±5 分钟 | 同 host 的 exec/connect/file |
| `lateral_movement` | 前 30 / 后 120 分钟 | SSH/防火墙横向 |
| `trace_default` | 前 **24h** / 后 **6h** | 溯源默认 **取数调查窗**（相对 `alert_time`）；由 `scenarios/anchor-patterns.json` 的 `investigation_window` 引用，自动填充 `time_start/time_end` |

**两类时间窗**：

| 类型 | 引用方式 | 作用 |
|---|---|---|
| Join 时间窗 | Join 规则 `time_window` | 匹配两条证据是否「时间上相关」 |
| 调查时间窗 | `scenarios/anchor-patterns.json` 的 `investigation_window` | 仅有 `alert_time` 时，推导 fetch 用的 `time_start/time_end` |

S1 / S2 溯源场景已配置 `"investigation_window": "trace_default"`。若调用方已显式传入 `time_start` + `time_end`，则不会被覆盖。

**时钟偏差**：关联窗以 evidence 的 `timestamp` 为准；若某源时钟不准或缺少时区，在 **资产** `schema.time_correction` 声明校正（`normalizer` 在 fetch 时应用），见 [时间校正](../docs_dev/09-data-asset-design.zh-CN.md#asset-time-correction)。matrix 时间窗本身不变。

---

<a id="四d2-主机行为内关联同-host"></a>

## 五、D2 主机行为内关联（同 host）

audit-port-execmon 三类事件在同一 `listener_pid` / `host` 上拼链：

```text
host_exec ──(host + listener_pid, ±5min)──▶ host_connect
          ──(host + pid, ±5min)──────────▶ host_file_op
host_connect ──(host + pid, ±5min)───────▶ host_file_op
```

| Join ID | 左 | 右 | 键 |
|---|---|---|---|
| `d2_exec_connect_same_listener` | host_exec | host_connect | host, listener_pid, listener_port |
| `d2_exec_file_same_host` | host_exec | host_file_op | host, pid, listener_pid |
| `d2_connect_file_same_host` | host_connect | host_file_op | host, pid |

<a id="41-d2_exec_file_same_host命令执行关联文件落地"></a>

### 5.1 `d2_exec_file_same_host`：命令执行关联文件落地

这条规则把 **主机命令执行事件**（`host_exec`）与 **主机文件操作事件**（`host_file_op`）拼在一起，用来判断一次命令执行是否伴随 WebShell 写入、脚本落地、攻击工具下载或异常文件创建。

```json
{
  "id": "d2_exec_file_same_host",
  "from_asset_type": "host_exec",
  "to_asset_type": "host_file_op",
  "join_keys": [
    {
      "left": "host",
      "left_variants": ["host_name"],
      "right": "host",
      "right_variants": ["host_name"],
      "match": "exact"
    },
    { "left": "pid", "right": "pid", "match": "exact", "optional": true },
    { "left": "listener_pid", "right": "listener_pid", "match": "exact", "optional": true }
  ],
  "time_window": "host_behavior_chain"
}
```

| 字段 | 含义 |
|---|---|
| `host` / `host_name` | 必要条件。两边事件必须发生在同一台主机上；`host_name` 是源日志变体，读值时会按双字段模型兼容。 |
| `pid` | 可选增强条件。若两边都有 `pid` 且精确相等，说明文件操作更可能由该命令进程产生。 |
| `listener_pid` | 可选增强条件。用于把 exec 与文件操作归到同一个对外监听入口进程链路，例如 nginx、php-fpm、java、node 等。 |
| `time_window: host_behavior_chain` | 时间约束。仅在主机行为链允许的时间窗内关联，避免把同主机但相隔很久的事件误拼。 |

**适用场景**：`S2` WEB 入侵溯源、`S4` WEB 告警确认、`S5` 主机异常行为。  
**消费 Skill**：`risk-identification`、`alert-confirmation`、`traceability-analysis`。

一句话：同一台主机上，如果命令执行和文件操作在合理时间窗内发生，并且 `pid` / `listener_pid` 能进一步对上，就把它们视为同一条主机攻击行为链的一部分。

**用途**：风险识别攻击链、告警确认「是否打穿」、溯源 execution/persistence 阶段。

---

<a id="六跨源关联d1--d2--网络"></a>

## 六、跨源关联（D1 ↔ D2 ↔ 网络）

<a id="51-告警确认--web-攻击s4"></a>

### 6.1 告警确认 / WEB 攻击（S4）

```text
waf_alert                    web_access_log              host_exec
(src_ip, url, timestamp) ──▶ (src_ip, url, host) ──▶ (host, command, listener_*)
     │                              │
     └──────── attack_success ±30min ─┘
```

| Join ID | 说明 |
|---|---|
| `waf_to_web_access_by_ip` | 同源 IP + 时间窗，可选 url 前缀 |
| `web_access_to_host_exec` | **受害 host** 对齐 + 时间窗 |
| `waf_to_host_exec_via_web_access` | WAF 无 host 时 **必须经 WEB 访问桥接** |
| `d2_exec_*` | 第二层成功证据 |

> 反例：直接用 `waf.src_ip` Join `host_exec.host` — **错误**（语义不同）。

<a id="52-外网-ip-溯源s1"></a>

### 6.2 外网 IP 溯源（S1）

锚点：`params.attacker_ip` → canonical `src_ip`

```text
                    ┌──▶ web_access_log (同源请求)
attacker_ip / src_ip ─┼──▶ waf_alert (规则命中)
                    ├──▶ ssh_auth (是否 SSH 打进来/扫端口)
                    └──▶ firewall_log (是否打到内网)

web_access.host ──▶ host_exec (WEB 打穿后的命令)
host_exec.host_ip ──▶ ssh_auth.src_ip (跳板 SSH 横向)
host / host_ip ──▶ asset_inventory (资产归属)
```

推荐链见场景编排配置：`scenarios/anchor-patterns.json` → `patterns.S1_external_ip_trace`。

<a id="53-横向移动s3"></a>

### 6.3 横向移动（S3）

| Join ID | 路径 |
|---|---|
| `host_ip_to_ssh_auth_lateral` | 受害机 IP → SSH 日志中的 src_ip |
| `ssh_auth_to_host_exec_same_host` | SSH 登录 host → 该主机 exec |
| `firewall_web_to_internal` | 防火墙五元组 ↔ SSH/内网主机 |

---

<a id="六场景--资产包--关联链"></a>

## 七、场景 → 资产包 → 关联链

| 场景 | 资产包 | 主锚字段 | 推荐 Join 链 |
|---|---|---|---|
| S1 外网 IP 溯源 | `bundle-incident-trace-default` | `src_ip` | S1_external_ip_trace |
| S2 WEB 入侵 | `bundle-incident-trace-default` | `url` + `src_ip` | S2_web_breach |
| S4 告警确认 | `bundle-alert-confirm-min` | `alert_id` / `src_ip` | S4_alert_confirmation |
| S5 主机风险 | `bundle-host-risk-default` | `host` | S5_host_risk |

完整定义在 `dataasset/scenarios/anchor-patterns.json` → `patterns`。

---

<a id="七s1-完整示例外网-ip-溯源"></a>

## 八、S1 完整示例（外网 IP 溯源）

**输入**：

```json
{
  "params": {
    "attacker_ip": "203.0.113.10",
    "alert_time": "2026-06-21T10:00:00+08:00",
    "time_start": "2026-06-20T10:00:00+08:00",
    "time_end": "2026-06-21T16:00:00+08:00"
  }
}
```

**Step 1 — 锚点**：在 `waf_alert` / `web_access_log` 中按 `src_ip=203.0.113.10` 取首次/关键事件。

**Step 2 — WEB 上下文**：`waf_to_web_access_by_ip`，±10min，还原告警前后请求。

**Step 3 — 是否打穿 WEB**：`web_access_to_host_exec`，用 `web_access.host` 查 `host_exec`（±30min），找 curl/bash/webshell 命令。

**Step 4 — SSH 横向**：`attacker_ip_to_ssh_auth` + `host_ip_to_ssh_auth_lateral`，查同源 IP 或跳板 IP 的 SSH Accepted。

**Step 5 — 资产补全**：`host_to_cmdb`，得到 zone/owner，确定影响范围。

**输出 attack_chain 每条须含**：`evidence_refs`、`join_id` / `join_ids`（用了哪条规则）、`timestamp`。  
脚本输出另含 **`join_edges`** 数组（见下节）。

---

<a id="八关联引擎correlation_engine"></a>

## 九、关联引擎（correlation_engine）

matrix 已由共享模块驱动执行，不再仅是文档规格：

| 模块 | 路径 |
|---|---|
| 字段读值 | `src/skills/_shared/data-access/field_resolver.py` |
| **关联引擎** | `src/skills/_shared/data-access/correlation_engine.py` |

<a id="81-主要-api"></a>

### 9.1 主要 API

| 函数 | 用途 |
|---|---|
| `get_join(join_id)` | 读取单条 Join 定义 |
| `expand_path(join_id)` | 展开多跳 Join（如 `waf_to_host_exec_via_web_access`） |
| `match_join_pair()` / `find_join_pairs()` | 双字段匹配 + matrix 时间窗 |
| `correlate_bundles()` | 按 `scenarios/anchor-patterns.json` 跑推荐链 |
| `plan_fetch(anchor_pattern_id, params)` | 生成 `fetch_plan` 取数任务队列 |

<a id="82-join-输出契约join_edges"></a>

### 9.2 Join 输出契约（`join_edges`）

`correlate.py`、`confirm.py` 输出：

```json
{
  "join_id": "web_access_to_host_exec",
  "left_ref": "web-001",
  "right_ref": "exec-001",
  "match_keys": { "host": "web-01" },
  "time_window": "attack_success",
  "confidence": 0.9,
  "from_asset_type": "web_access_log",
  "to_asset_type": "host_exec"
}
```

<a id="83-fetch-编排fetch_plan--correlation_fetch_plan"></a>

### 9.3 fetch 编排（`fetch_plan` / `correlation_fetch_plan`）

matrix 中 Join 可声明 `fetch_plan`；`skill_input.py` 在 `--fetch` 时写入 payload：

```json
{
  "correlation_anchor_pattern": "S4_alert_confirmation",
  "correlation_fetch_plan": [
    {
      "join_id": "waf_to_web_access_by_ip",
      "side": "left",
      "asset_id": "asset-waf-prod-01",
      "template_id": "waf_gateway_plugin_by_ip_time",
      "params": { "src_ip": "203.0.113.10", "time_start": "...", "time_end": "..." }
    }
  ]
}
```

Join 级 `fetch_plan.param_map` 将桥接出的 `host` 映射为模板参数 `host_name`（`host_exec_by_host_name_time`）。

<a id="84-扩展-match-类型"></a>

### 9.4 扩展 match 类型

| match | 实现位置 |
|---|---|
| `exact` | `correlation_engine.values_match` |
| `path_prefix` | URL path 前缀 |
| `hostname_to_ip_via_cmdb` | `build_host_ip_map` + CMDB |
| `dns_answer_ip` | 解析 DNS response 中的 IP |

---

<a id="九skill-使用约束"></a>

## 十、Skill 使用约束

1. **Join 键推荐 canonical、允许源字段**：读值走 `field_resolver.py` 的 declared-first + alias 正反向解析；执行匹配用 **`correlation_engine.py`**
2. **只允许 matrix 中的 join_id**：无命中 → `data_gaps` / `data_gaps_impact` 写明缺哪条 Join
3. **success_confirmed** 须至少一条 D2 Join（`web_access_to_host_exec` 或 `d2_*`）
4. **查询参数**：live fetch 优先消费 `correlation_fetch_plan`；参数映射见 `fetch_plan.param_map` 与 query-templates
5. **时间窗**：以 matrix `time_windows` 为准（如 `attack_success` 前 5 / 后 30 分钟）
6. **输出**：须含 `join_edges`；关联命中可注明 `matched_via: canonical|variant|alias`

---

<a id="十维护方式"></a>

## 十一、维护方式

新增/变更资产时：

1. 在 `asset-*.json` 维护 `schema.fields` 与 `field_aliases`；通用别名维护到 `evidence-minimum-fields.json`
2. 若引入 **新的跨源 Join**，在 `assets/correlation-matrix.json` 增加一条 `cross_source_joins` 或 `internal_joins`
3. 更新本文「场景 → 关联链」表格
4. 运行 `python3 src/dataasset/validate.py` 校验 JSON

**不要**在每个 asset 里重复写跨源 Join 规则；**只维护一份** correlation-matrix。

---

<a id="十一相关文档"></a>

## 十二、相关文档

- [数据源资产设计.md](../docs_dev/09-data-asset-design.zh-CN.md)
- [Agent采集与Evidence规范.md](../docs_dev/12-agent-collection-and-evidence-spec.zh-CN.md)
- [溯源分析技能设计.md](../docs_dev/15-traceability-analysis-skill-design.zh-CN.md)
- [告警确认技能设计.md](../docs_dev/14-alert-confirmation-skill-design.zh-CN.md)

**语言：** [English](22-scenario-patterns.md) | 简体中文（本文）

# Scenario Patterns（调查场景编排）说明

> 机器可读配置：[`dataasset/scenarios/anchor-patterns.json`](../dataasset/scenarios/anchor-patterns.json)  
> Join 规则来源：[`dataasset/assets/correlation-matrix.json`](../dataasset/assets/correlation-matrix.json)  
> 关联引擎：`src/skills/_shared/data-access/correlation_engine.py`  
> 相关文档：[`21-cross-source-field-correlation.zh-CN.md`](21-cross-source-field-correlation.zh-CN.md)、[历史 correlation-matrix 评估](../docs_dev/history/22-correlation-matrix-design-evaluation.zh-CN.md)、[`data-asset-design.zh-CN.md`](../docs_dev/09-data-asset-design.zh-CN.md)

> 本文是场景配置与实现参考。首次使用请先阅读 [用户快速上手](00-security-operator-quickstart.zh-CN.md)；需要查看技能选择和调用方式时，阅读 [Skills 使用指南](06-skills-and-usage.zh-CN.md)。

---

**按任务阅读：** 可直接跳到需要的章节，不必从头通读。

- [五、配置结构说明](#五配置结构说明)
- [六、字段语义速查](#六pattern-字段语义)
- [七、当前已定义场景](#七当前已定义场景)
- [八、运行时如何消费 Scenario Patterns](#八运行时如何消费-scenario-patterns)
- [十一、校验规则](#十一校验规则)

## 一、它是什么

`Scenario Patterns` 是 SecWeaver 的**调查场景编排层**。

它不直接定义字段、不直接定义 Join 规则，也不直接连接数据源，而是回答一个更高层的问题：

> 当用户提出某类安全调查问题时，系统应该以哪个字段作为调查锚点、拉哪些资产、按什么 Join 链路拼证据、默认查多长时间。

换句话说：

```text
用户问题 / Skill 场景
        ↓
Scenario Pattern（调查剧本）
        ↓
选择资产包 bundle + 默认调查窗 + 推荐 Join 链
        ↓
correlation-matrix 中的 Join 规则
        ↓
fetch evidence + correlate_bundles
        ↓
join_edges / data_gaps / attack_chain / alert verdict
```

如果说 `correlation-matrix.json` 是“证据之间怎么连”的**Join 合同**，那么 `anchor-patterns.json` 就是“某个调查任务按什么顺序跑这些 Join”的**调查剧本**。

---

## 二、为什么它非常重要

安全调查不是简单地“查某个日志”。不同调查场景有不同的起点、证据优先级和停止条件。

例如：

- 外网 IP 溯源：从 `src_ip` 出发，先看 WAF / WEB，再看主机执行，再看 SSH 横向和防火墙。
- WEB 告警确认：从 WAF 告警出发，先判断 payload，再用 WEB 访问和主机行为确认是否打穿。
- 主机风险识别：从 `host` 出发，只关注该主机上的 exec/connect/file 行为链。

如果没有 `Scenario Patterns`，每个 Skill 或 Agent 都可能自己决定调查顺序，带来几个问题：

| 问题 | 后果 |
|---|---|
| 调查链路散落在 Prompt / 脚本中 | 同一个事件在不同 Skill 中跑出不同结论 |
| AI 自由选择 Join 顺序 | 容易漏查关键证据，也容易臆造关联 |
| 资产包和调查窗不固定 | 取数范围不一致，复核困难 |
| 场景与 Join 规则耦合 | 新增场景或调整调查策略需要改底层 Join |
| 缺证据时没有统一表达 | 无法稳定产出 `data_gaps`，影响可信度 |

因此 `Scenario Patterns` 的核心价值是：

1. **把调查经验固化为机器可读配置**。
2. **让不同 Skill 复用同一套调查剧本**。
3. **限制 AI 只能沿已声明的 Join 链推理**。
4. **把“查不到”显式变成 `data_gaps`，而不是编造攻击链**。
5. **把完整性评估、取数、关联、报告输出串成同一条链路**。

---

## 三、它在数据源体系中的位置

SecWeaver 当前数据源与调查编排可以理解为五层：

```text
L1 Asset / Connector / Host
  单个数据源是什么、怎么连、属于哪台主机
        ↓
L2 Normalizer / Field Aliases
  源字段归一为 canonical evidence
        ↓
L3 Correlation Matrix
  哪两类 evidence 可以 Join，用什么字段、什么时间窗
        ↓
L4 Scenario Patterns
  某个调查场景使用哪些 Join，按什么链路跑，默认查多久
        ↓
L5 Skill / Report
  告警确认、溯源分析、风险识别、完整性建议
```

对应文件：

| 层级 | 文件 | 回答的问题 |
|---|---|---|
| L1 资产层 | `dataasset/assets/asset-*.json` | 数据是什么、字段是什么、怎么归一化 |
| L1 连接层 | `dataasset/connectors/conn-*.json` | 怎么连接后端数据源 |
| L1 主机层 | `dataasset/hosts/host-*.json` | 主机是谁，IP/hostname/zone/角色是什么 |
| L2 字段归一 | `dataasset/configure/evidence-minimum-fields.json` + `asset.field_aliases` | 源字段如何变成 canonical 字段 |
| L3 关联矩阵 | `dataasset/assets/correlation-matrix.json` | evidence 之间如何 Join |
| L4 场景编排 | `dataasset/scenarios/anchor-patterns.json` | 某类调查按什么链路跑 |
| L5 执行消费 | `correlation_engine.py`、告警确认/溯源/风险识别 Skill | 产出 join_edges、data_gaps、调查结论 |

---

## 四、和 Correlation Matrix 的边界

`Scenario Patterns` 和 `Correlation Matrix` 必须分工清晰。

| 对象 | 负责什么 | 不负责什么 |
|---|---|---|
| `correlation-matrix.json` | 定义 Join 规则、Join 字段、时间窗、fetch_plan | 不决定某个场景完整调查链路 |
| `anchor-patterns.json` | 定义场景、锚点、推荐 Join 链、默认调查窗、资产包 | 不定义 Join 字段细节，不重复维护字段别名 |

典型关系：

```text
anchor-patterns.json
  patterns.S4_alert_confirmation.recommended_chain
    ├── waf_to_web_access_by_ip
    ├── waf_to_host_exec_via_web_access
    ├── d2_exec_connect_same_listener
    └── d2_exec_file_same_host

correlation-matrix.json
  cross_source_joins / internal_joins
    ├── waf_to_web_access_by_ip 的 left/right asset_type、join_keys、time_window、fetch_plan
    ├── web_access_to_host_exec 的 left/right asset_type、join_keys、time_window、fetch_plan
    └── d2_exec_connect_same_listener 的 left/right asset_type、join_keys、time_window
```

也就是说，`Scenario Patterns` 只引用 Join ID，不复制 Join 规则。

这带来两个好处：

1. 一条 Join 可被多个场景复用。
2. 调整调查顺序时不用改底层字段关联逻辑。

---

## 五、配置结构说明

当前配置文件结构如下：

```json
{
  "version": "1.0",
  "description": "SecWeaver 调查场景编排配置...",
  "patterns": {
    "S1_external_ip_trace": {
      "label": "外网 IP 溯源",
      "investigation_window": "trace_default",
      "anchor": {
        "field": "src_ip",
        "field_variants": ["ip", "client_ip"],
        "from": "params.attacker_ip",
        "fallback_asset_types": ["waf_alert", "web_access_log"]
      },
      "recommended_chain": [
        "waf_to_web_access_by_ip",
        "web_access_to_host_exec"
      ],
      "bundle_id": "bundle-incident-trace-default"
    }
  }
}
```

### 5.1 顶层字段

| 字段 | 类型 | 说明 |
|---|---|---|
| `version` | string | 场景编排配置版本 |
| `description` | string | 配置用途说明 |
| `patterns` | object | 所有调查场景编排，key 为 pattern ID |

### 5.2 Pattern ID 命名

建议格式：

```text
S<场景编号>_<英文语义>
```

例如：

| Pattern ID | 含义 |
|---|---|
| `S1_external_ip_trace` | 外网 IP 溯源 |
| `S2_web_breach` | WEB 入侵 / WebShell 溯源 |
| `S4_alert_confirmation` | WEB 告警确认 |
| `S5_host_risk` | 主机行为风险识别 |

命名原则：

- `S1` / `S2` / `S4` 与完整性场景编号保持一致。
- 后缀表达调查目标，不表达具体日志产品。
- 不把资产 ID 写进 pattern ID，避免和部署环境耦合。

---

## 六、Pattern 字段语义

### 6.1 `label`

人类可读名称，用于 UI、报告和调试输出。

示例：

```json
"label": "外网 IP 溯源"
```

### 6.2 `investigation_window`

默认调查取数窗口，引用 `correlation-matrix.json` 中的 `time_windows`。

示例：

```json
"investigation_window": "trace_default"
```

当前 `trace_default` 的语义通常是：

```text
相对 alert_time：前 24 小时，后 6 小时
```

执行时：

- 如果调用方已经显式传入 `time_start` 和 `time_end`，不覆盖。
- 如果只传入 `alert_time`，`resolve_anchor_params()` 会自动补齐 `time_start/time_end`。
- 这是“取数窗口”，不是 Join 匹配窗口。

要特别区分两类时间窗：

| 类型 | 配置位置 | 用途 |
|---|---|---|
| 调查取数窗口 | `pattern.investigation_window` | 决定 fetch 拉多大时间范围 |
| Join 匹配窗口 | `join.time_window` | 决定两条 evidence 时间上是否相关 |

### 6.3 `anchor`

调查锚点，描述这个场景从哪个关键字段或参数开始。

常见字段：

| 字段 | 说明 |
|---|---|
| `field` | canonical 锚点字段，如 `src_ip`、`url`、`host` |
| `field_variants` | 源字段候选，如 `ip`、`client_ip`、`host_name` |
| `from` | 锚点来源，如 `params.attacker_ip`、`params.host`、`waf_alert` |
| `secondary` | 次级锚点，如 S2 中 URL 外还要结合 `src_ip` |
| `fallback_asset_types` | 锚点可从哪些证据类型中回退提取 |

示例：

```json
"anchor": {
  "field": "src_ip",
  "field_variants": ["ip", "client_ip"],
  "from": "params.attacker_ip",
  "fallback_asset_types": ["waf_alert", "web_access_log"]
}
```

含义：

- 该场景以攻击源 IP 为锚点。
- 推荐使用 canonical 字段 `src_ip`。
- 兼容源字段 `ip` / `client_ip`。
- 用户参数中传入的是 `params.attacker_ip`。
- 如果参数缺失，可尝试从 `waf_alert` 或 `web_access_log` 中回退提取。

### 6.4 `recommended_chain`

该场景推荐执行的 Join ID 列表。

示例：

```json
"recommended_chain": [
  "waf_to_web_access_by_ip",
  "web_access_to_host_exec",
  "attacker_ip_to_ssh_auth",
  "host_ip_to_ssh_auth_lateral",
  "firewall_web_to_internal"
]
```

它是 `Scenario Patterns` 最核心的字段。

执行时：

1. `correlation_engine.run_recommended_chain()` 按顺序读取该链。
2. 每个 Join ID 会到 `correlation-matrix.json` 中找到 Join 定义。
3. 如果 Join 是 composite/path 类型，会通过 `expand_path()` 展开成多个真实 Join。
4. 每个 Join 执行 `find_join_pairs()`。
5. 命中则生成 `join_edges`。
6. 未命中则生成 `data_gaps`。

注意：

- `recommended_chain` 只写 Join ID。
- Join ID 必须存在于 `internal_joins` 或 `cross_source_joins`。
- 不应在这里写字段名、时间窗、查询模板。

### 6.5 `bundle_id`

该场景默认使用的资产包。

示例：

```json
"bundle_id": "bundle-incident-trace-default"
```

用途：

- 决定默认需要 fetch 哪些资产。
- 供 `plan_fetch()` 在未显式传入 `asset_ids` 时加载资产集合。
- 与完整性分析联动，判断该场景缺哪些数据域。

### 6.6 `layer1_assets` / `layer2_assets`

目前主要用于 S4 告警确认场景。

示例：

```json
"layer1_assets": ["waf_alert"],
"layer2_assets": ["web_access_log", "host_exec", "host_connect", "host_file_op"]
```

含义：

- 第一层：只基于告警本身判断 payload、规则、动作，给出初步分类。
- 第二层：结合 WEB 访问和主机行为确认是否真的打穿。

这是告警确认 Skill 的两层模型：

```text
Layer 1：告警语义层
  WAF payload / action / rule / status
        ↓
Layer 2：成功确认层
  web_access_log + host_exec + host_connect + host_file_op
```

---

## 七、当前已定义场景

### 7.1 S1：外网 IP 溯源

Pattern ID：`S1_external_ip_trace`

目标：

> 给定一个外部攻击 IP，追踪它打了哪些 WEB/WAF 入口、是否进入主机、是否发生 SSH 横向或内网访问。

关键配置：

```json
{
  "label": "外网 IP 溯源",
  "investigation_window": "trace_default",
  "anchor": {
    "field": "src_ip",
    "from": "params.attacker_ip"
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
```

推荐链路：

```text
attacker_ip
  ├─▶ waf_alert
  ├─▶ web_access_log
  ├─▶ host_exec
  ├─▶ ssh_auth
  └─▶ firewall_log / internal traffic
```

典型问题：

- 这个外网 IP 是否只是扫描？
- 是否访问到真实 WEB 入口？
- 是否触发主机命令执行？
- 是否继续 SSH 横向？
- 影响了哪些内网主机？

### 7.2 S2：WEB 入侵 / WebShell

Pattern ID：`S2_web_breach`

目标：

> 从 WEB 告警、URL 或可疑路径出发，确认是否发生 WebShell、命令执行、文件写入或外连。

关键锚点：

```json
"anchor": {
  "field": "url",
  "field_variants": ["request_uri", "path"],
  "from": "waf_alert",
  "secondary": "src_ip"
}
```

推荐链路：

```text
waf_alert.url + src_ip
  └─▶ web_access_log
        └─▶ host_exec
              ├─▶ host_file_op
              └─▶ host_connect
```

它与 S1 的区别：

| 场景 | 起点 | 重点 |
|---|---|---|
| S1 | 外部 IP | 从攻击源追完整影响范围 |
| S2 | WEB URL / WAF 告警 | 从 WEB 入口确认是否打穿与落地 |

### 7.3 S4：告警确认（两层）

Pattern ID：`S4_alert_confirmation`

目标：

> 判断 WAF/WEB 告警是误报、真实攻击但未成功，还是真实攻击且已打穿。

配置特点：

```json
"layer1_assets": ["waf_alert"],
"layer2_assets": [
  "web_access_log",
  "host_exec",
  "host_connect",
  "host_file_op"
]
```

推荐链路：

```text
waf_alert
  ├─▶ web_access_log
  ├─▶ host_exec
  ├─▶ host_connect
  └─▶ host_file_op
```

两层判断：

| 层 | 输入 | 回答 |
|---|---|---|
| Layer 1 | WAF 告警本身 | 是不是攻击？payload 是否有效？是否可能误报？ |
| Layer 2 | WEB + D2 主机行为 | 是否打穿？有没有命令执行、外连、写文件？ |

关键原则：

```text
没有 D2 主机行为证据时，不应轻易输出 success_confirmed。
```

如果 WAF 命中但没有 WEB/host 关联，应输出：

```text
alert_triage_only / insufficient_evidence / data_gap
```

而不是直接认定入侵成功。

### 7.4 S5：主机行为风险识别

Pattern ID：`S5_host_risk`

目标：

> 从某台主机出发，识别对外监听进程相关的高危命令、主动外连、文件写入等行为链。

锚点：

```json
"anchor": {
  "field": "host",
  "field_variants": ["host_name"],
  "from": "params.host"
}
```

推荐链路：

```text
host_exec
  ├─▶ host_connect
  └─▶ host_file_op
```

核心 Join：

- `d2_exec_connect_same_listener`
- `d2_exec_file_same_host`

典型问题：

- 对外监听进程是否执行了高危命令？
- 命令执行后是否主动外连？
- 是否下载/写入可疑文件？
- 是否构成 WebShell / C2 / 持久化风险？

---

## 八、运行时如何消费 Scenario Patterns

### 8.1 加载配置

`correlation_engine.py` 中：

```text
load_anchor_patterns()
  优先读取 dataasset/scenarios/anchor-patterns.json
  如果文件不存在，兼容读取 correlation-matrix.json 中旧的 anchor_patterns
```

当前新路径是权威来源：

```text
dataasset/scenarios/anchor-patterns.json
```

旧路径只保留兼容，不应继续使用。

### 8.2 场景自动匹配 Pattern

函数：`anchor_pattern_for_scenarios()`

当前优先级：

```text
S4 → S1 → S2 → S5
```

含义：

- 如果输入 scenarios 中包含 `S4`，优先走 `S4_alert_confirmation`。
- 否则匹配 `S1_external_ip_trace`、`S2_web_breach`、`S5_host_risk`。

需要注意：如果一次请求同时声明多个场景，优先级会影响最终使用哪个 Pattern。

### 8.3 自动补齐调查时间窗

函数：`resolve_anchor_params()`

流程：

```text
输入 params
  ├─ 如果已有 time_start + time_end：原样返回
  ├─ 如果有 alert_time：读取 pattern.investigation_window
  └─ 调用 fill_investigation_window() 自动生成 time_start/time_end
```

示例：

```json
{
  "attacker_ip": "203.0.113.10",
  "alert_time": "2026-06-21T10:00:00+08:00"
}
```

如果 `investigation_window = trace_default`，会推导为：

```json
{
  "time_start": "2026-06-20T10:00:00+08:00",
  "time_end": "2026-06-21T16:00:00+08:00"
}
```

### 8.4 生成 fetch 计划

函数：`plan_fetch()`

流程：

```text
pattern.bundle_id
  ↓
加载 bundle 中 asset_ids
  ↓
按 recommended_chain 遍历 Join
  ↓
读取每个 Join 的 fetch_plan.left/right
  ↓
结合 param_map 生成 task 队列
  ↓
输出 correlation_fetch_plan
```

输出任务包含：

```json
{
  "join_id": "waf_to_web_access_by_ip",
  "side": "left",
  "asset_id": "asset-waf-prod-01",
  "asset_type": "waf_alert",
  "template_id": "waf_gateway_plugin_by_ip_time",
  "params": {
    "src_ip": "203.0.113.10",
    "time_start": "...",
    "time_end": "..."
  },
  "purpose": "..."
}
```

这一步体现了一个重要原则：

```text
Scenario Pattern 决定查什么链；Join.fetch_plan 决定每一步怎么取数。
```

运行时 `skill_input --fetch` 已将 `correlation_fetch_plan` 作为主路径：

1. `fetch_scenario_evidence()` 先根据 `bundle_id + scenarios / anchor_pattern_id + params` 调用 `plan_fetch()`。
2. 如果生成 task，则调用 `fetch_correlation_plan_evidence()` 按 task 顺序拉取证据；task 内的 `template_id` 和 `params` 优先级高于传统资产默认模板选择。
3. 执行前会检查 task 是否满足模板必填参数；缺少桥接字段（如必须先从 WEB 访问日志推导出的 `host_name`）的 task 会记录为 `skipped_plan_task_count`，不让缺参查询阻断主路径。
4. 每个 task 仍会展开资产上的多个 connector，因此汇总型资产（如多主机 SSH / 多 logstore）不会失去多 connector 能力。
5. 取数结果按资产聚合、去重后回填为 `evidence_bundles`，同时 payload 保留 `correlation_fetch_plan`、`correlation_anchor_pattern` 和 `data_access.fetch_strategy=correlation_fetch_plan`，便于审计“为什么查了这些源”。
6. 如果 Pattern 不存在或 `plan_fetch()` 没有产出 task，则回退到 `bundle_full_fallback`，按 bundle 全量资产进行传统取数，保证旧流程兼容。

### 8.5 执行推荐链并输出关联结果

函数：`run_recommended_chain()` / `correlate_bundles()`

流程：

```text
输入 evidence_bundles + anchor_pattern_id
  ↓
读取 pattern.recommended_chain
  ↓
expand_path() 展开 composite Join
  ↓
find_join_pairs() 查找 evidence 对
  ↓
命中：加入 join_edges
  ↓
未命中：加入 data_gaps
```

输出结构：

```json
{
  "anchor_pattern_id": "S4_alert_confirmation",
  "recommended_chain": [
    "waf_to_web_access_by_ip",
    "waf_to_host_exec_via_web_access",
    "d2_exec_connect_same_listener",
    "d2_exec_file_same_host"
  ],
  "join_edges": [
    {
      "join_id": "waf_to_web_access_by_ip",
      "left_ref": "waf-001",
      "right_ref": "web-001",
      "match_keys": { "src_ip": "203.0.113.10" },
      "time_window": "alert_context",
      "confidence": 0.9
    }
  ],
  "data_gaps": [
    "no_match:d2_exec_connect_same_listener (...)"
  ]
}
```

`join_edges` 是后续报告中“为什么这两条证据有关”的审计依据；`data_gaps` 是“缺了哪段证据”的显式说明。

---

## 九、和完整性分析的关系

完整性分析回答：

> 这个场景需要哪些数据域？当前资产是否足够？缺什么会影响结论？

Scenario Patterns 回答：

> 如果资产足够，应该按什么链路查？

二者关系：

```text
完整性分析
  ├─ S1 需要 D1 + D2 + D3
  ├─ S4 需要 D1，最好有 D2 证明是否打穿
  └─ S5 需要 D2
        ↓
Scenario Patterns
  ├─ S1_external_ip_trace 使用 bundle-incident-trace-default
  ├─ S4_alert_confirmation 使用 bundle-alert-confirm-min
  └─ S5_host_risk 使用 bundle-host-risk-default
        ↓
correlation_engine
  ├─ plan_fetch
  └─ correlate_bundles
```

推荐约定：

| 场景 | 完整性重点 | Scenario Pattern 重点 |
|---|---|---|
| S1 外网 IP 溯源 | D1 + D2 + D3 是否覆盖 | 从 IP 到 WEB、主机、SSH、内网路径 |
| S2 WEB 入侵 | D1 + D2 是否覆盖 | 从 URL/WAF 到主机执行、文件、外连 |
| S4 告警确认 | D1 是否可判定，D2 是否能证明打穿 | 两层确认链路 |
| S5 主机风险 | D2 exec/connect/file 是否完整 | 同主机行为链 |

如果完整性评估发现 P0 数据域缺失，Scenario Pattern 仍可运行，但结论必须降级，并在 `data_gaps` 或报告中明确说明。

---

## 十、维护和新增场景的方法

### 10.1 新增一个 Pattern 的步骤

1. 明确场景编号和调查目标。
2. 确定调查锚点，例如 `src_ip`、`host`、`url`、`user`。
3. 确定默认调查窗，例如 `trace_default`、`lateral_movement`。
4. 选择资产包 `bundle_id`。
5. 从 `correlation-matrix.json` 中选择已有 Join 组成 `recommended_chain`。
6. 如果缺 Join，先补 correlation-matrix，再在 Pattern 中引用。
7. 运行 `validate.py` 检查：
   - `anchor-patterns.json` 是否符合 `anchor-patterns.schema.json`。
   - `investigation_window` 是否存在。
   - `recommended_chain` 中所有 Join ID 是否存在。
   - `bundle_id` 是否存在。
   - Pattern ID 推导出的 `S1`–`S7` 是否被 bundle 的 `investigation_scenarios` 覆盖。
   - `recommended_chain` / `layer1_assets` / `layer2_assets` 需要的 `asset_type` 是否被 bundle 的 `asset_ids` 覆盖。
8. 用样例 evidence 验证 `join_edges` 和 `data_gaps` 是否符合预期。

### 10.2 新增 Pattern 模板

```json
"S3_lateral_movement": {
  "label": "横向移动调查",
  "investigation_window": "trace_default",
  "anchor": {
    "field": "host_ip",
    "field_variants": ["src_ip", "dst_ip"],
    "from": "params.host_ip",
    "secondary": "user"
  },
  "recommended_chain": [
    "host_ip_to_ssh_auth_lateral",
    "ssh_auth_to_host_exec_same_host",
    "firewall_web_to_internal"
  ],
  "bundle_id": "bundle-incident-trace-default"
}
```

注意：上面只是模板。真正落地前必须确认这些 Join ID 在 `correlation-matrix.json` 中存在，且对应资产包包含需要的 asset_type。

### 10.3 推荐链设计原则

| 原则 | 说明 |
|---|---|
| 从用户最确定的锚点出发 | 如攻击 IP、告警 ID、host、user |
| 先查高置信入口证据 | WAF、WEB、SSH 登录等 |
| 再查主机行为证据 | exec/connect/file 证明是否打穿 |
| 横向和影响面放后面 | SSH、firewall、DNS、CMDB 等 |
| 每一步必须有 Join 定义 | 不能在 Pattern 中发明 Join |
| 缺证据要能形成 data_gap | 未命中是调查结果的一部分 |

### 10.4 不要做的事

| 不要做 | 原因 |
|---|---|
| 在 Pattern 中写具体字段 Join 逻辑 | 字段 Join 应维护在 correlation-matrix |
| 在 Pattern 中写 SLS/SQL 查询 | 查询应维护在 Join.fetch_plan + query-templates |
| 在 Pattern ID 中写资产 ID | 场景应与具体部署解耦 |
| 直接让 AI 自己决定 Join 链 | 会破坏可审计性 |
| 未命中时生成“推测链路” | 应输出 data_gap，而不是臆造 |

---

## 十一、校验规则

当前 `validate.py` 对 `anchor-patterns.json` 已执行结构校验与跨配置契约校验：

| 校验项 | 说明 |
|---|---|
| 文件存在性 | 找不到时给 warning，跳过 anchor pattern 校验 |
| JSON 格式 | JSON 解析失败时报 error |
| JSON Schema | 使用 `dataasset/schema/anchor-patterns.schema.json` 校验顶层结构、Pattern 必填字段和字段类型 |
| `patterns` 类型 | 必须是 object |
| pattern 类型 | 每个 pattern 必须是 object |
| `investigation_window` | 如果填写，必须存在于 matrix `time_windows` |
| `recommended_chain` | 必须是 array，且 Join ID 不重复 |
| Join 引用 | 每个 Join ID 必须存在于 matrix 的 `internal_joins` 或 `cross_source_joins` |
| `bundle_id` 引用 | Pattern 声明的 `bundle_id` 必须存在于 `dataasset/bundles/` |
| Pattern ↔ Bundle 场景一致性 | 从 Pattern ID 推导出的 `S1`–`S7` 必须包含在 bundle 的 `investigation_scenarios` 中 |
| Bundle 覆盖 Join 需求 | `recommended_chain` 展开后的 `from_asset_type` / `to_asset_type` 必须被 bundle 的 `asset_ids` 覆盖 |
| Layer 资产覆盖 | `layer1_assets` / `layer2_assets` 声明的 asset_type 必须被 bundle 覆盖 |
| Composite Join 展开 | 如果 Join 含 `path`，校验会递归展开 path 中的真实 Join，并把它们需要的 asset_type 纳入 bundle 覆盖检查 |
| 旧配置迁移 | 如果 `correlation-matrix.json` 仍有 `anchor_patterns`，提示迁移 |

扩展校验还会检查 anchor 字段、注册的 asset type、fallback 资产覆盖和场景声明。
函数级实现映射与演进约束见[场景模式运行时与演进](../docs_dev/29-scenario-pattern-runtime-and-evolution.zh-CN.md)。

---

## 十二、运行边界

1. S3、S6、S7 已有 Pattern；S7 的生产可用性仍取决于 DNS、全流量和数据库审计等 Connector 是否真实接入并通过验收。
2. Join 缺少完整 `fetch_plan` 时，系统可能回退到 Bundle 取数。上线前应检查授权范围、时间窗和返回上限。
3. 完整性分析的 P0/P1/P2 要求来自 `data-source-completeness/scenarios.json`，不会自动从 Pattern 的 Join 链推导；修改 Pattern 时必须同步核对场景要求。
4. 报告中的关键结论应引用 `join_edges`，并保留 `data_gaps`，避免把没有证据的推测写成确定结论。

## 十三、开发者实现说明

Pattern 加载、锚点参数解析、取数计划、回退行为、校验规则和后续扩展统一记录在
[开发者文档](../docs_dev/29-scenario-pattern-runtime-and-evolution.zh-CN.md)。安全运营人员按本文配置和验收即可。

---

## 十四、一个端到端例子：S4 告警确认

用户问题：

```text
IP 203.0.113.10 的 WAF SQLi 告警有没有打穿？
```

输入参数：

```json
{
  "scenario": "S4",
  "params": {
    "attacker_ip": "203.0.113.10",
    "alert_time": "2026-06-21T10:00:00+08:00"
  }
}
```

执行流程：

```text
1. anchor_pattern_for_scenarios(["S4"])
   → S4_alert_confirmation

2. resolve_anchor_params("S4_alert_confirmation", params)
   → 如果缺 time_start/time_end，则按 investigation_window 补齐

3. plan_fetch("S4_alert_confirmation", params)
   → 按 bundle-alert-confirm-min 选择资产
   → 按 recommended_chain 生成 correlation_fetch_plan

4. fetch evidence
   → waf_alert
   → web_access_log
   → host_exec
   → host_connect
   → host_file_op

5. correlate_bundles(..., anchor_pattern_id="S4_alert_confirmation")
   → 跑 recommended_chain
   → 输出 join_edges 和 data_gaps

6. confirm.py 综合判断
   → 误报 / 攻击未成功 / 成功打穿 / 证据不足
```

关键判断：

```text
只有 WAF 命中：只能说明有攻击尝试。
WAF + WEB 命中：说明请求到达业务入口。
WAF/WEB + host_exec：说明可能打穿。
host_exec + connect/file：说明存在后续行为，风险显著升高。
```

---

## 十五、总结

`Scenario Patterns` 是 SecWeaver 调查系统中非常关键的一层。

它的本质不是“配置几个场景名称”，而是把安全专家的调查路径沉淀成可执行、可校验、可复用的机器规则：

```text
场景 → 锚点 → 调查窗 → 资产包 → 推荐 Join 链 → join_edges/data_gaps → 可信结论
```

它和 `correlation-matrix.json` 的分层让系统具备三个核心能力：

1. **可复用**：同一 Join 可服务多个调查场景。
2. **可审计**：每个结论都能回到 Join ID 和 evidence ID。
3. **可演进**：新增调查场景时优先编排已有 Join，不破坏底层资产和字段模型。

后续如果继续建设 SecWeaver 的自动化调查能力，`Scenario Patterns` 应该被视为和 `Asset`、`Correlation Matrix` 同等重要的核心注册对象。

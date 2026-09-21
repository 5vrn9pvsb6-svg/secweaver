**语言：** [English](22-correlation-matrix-design-evaluation.md) | 简体中文（本文）

# correlation-matrix.json 设计评估报告

> **文档状态：历史评估记录（截至 2026-07-08）。** 本文保留当时的设计建议；待办不代表当前未实现。当前字段规范见[资产设计](../09-data-asset-design.zh-CN.md)，关联行为见[跨源字段关联](../../docs_user/21-cross-source-field-correlation.zh-CN.md)。

> **实现状态（2026-07-08）**：中期引擎化 **已落地** — `correlation_engine.py`、`field_resolver.py`；`correlate.py` / `confirm.py` 输出 `join_edges`；`skill_input` 以 `correlation_fetch_plan` 作为 fetch 主路径；`fetch.py` 已支持按 plan 顺序拉数并在无 plan 时回退 bundle 全量；`correlation-matrix.schema.json`、Join `priority/confidence` 与 UI 可视化解释已补。待办：Join 互斥/冲突消解、复杂横向 BFS 进一步矩阵化。

> **评估对象**：[`dataasset/assets/correlation-matrix.json`](../../dataasset/assets/correlation-matrix.json)
> **关联文档**：[跨源字段关联说明.md](../../docs_user/21-cross-source-field-correlation.zh-CN.md)（关联引擎章节） | [数据源资产设计.md](../09-data-asset-design.zh-CN.md)
> **评估日期**：2026-06-25
> **结论摘要**：**设计方向正确、语义分层清晰，已具备作为 SecWeaver 跨源关联「单一事实来源」的基础能力**；引擎化、Join 输出、按 `correlation_fetch_plan` 顺序拉数、`validate.py` 语义校验、独立 JSON Schema、Join 优先级/置信度和 UI 可视化解释已落地，剩余工作主要是 Join 互斥/冲突消解、复杂横向 BFS 全 matrix 化与更多生产样本回归。

---

## 零、核心功能与架构（读懂 correlation matrix）

本章说明 **correlation matrix 是什么、解决什么问题、在平台里怎么跑**。后文「评估范围 / 问题 / 优化」建立在理解本章之上。

### 0.1 一句话定位

**correlation-matrix.json** 是 SecWeaver 的 **跨源证据关联规格书**：规定「不同日志之间用什么字段、在什么时间窗内、可以合法地连成一条调查链」，并由 **`correlation_engine.py`** 执行匹配。

它 **不是** 单条日志的 schema（那是 `asset-*.json`），**也不是** 归一化规则全集（那是 `evidence-minimum-fields.json` + `asset.field_aliases`），而是 **L3：跨源 Join 合同**。Join 键推荐 canonical，也允许局部写源字段。

### 0.2 在平台里的位置

```text
┌──────────────────────────────────────────────────────────────────────────┐
│                         SecWeaver 安全调查链路                          │
└──────────────────────────────────────────────────────────────────────────┘

  用户意图 / 场景 S1~S7
         │
         ▼
  data-source-completeness     「数据够不够查？」
         │
         ▼
  skill_input + fetch          「按资产包把各源日志拉回来」
         │                        correlation_fetch_plan ← matrix.fetch_plan
         ▼
  normalizer + field_aliases     「源字段 → canonical（src_ip / host / …）」
         │
         ▼
  correlation_engine           「按 matrix Join 规则拼 evidence」★ 本章核心
         │
         ├── alert-confirmation   两层研判 + join_edges
         ├── traceability         attack_chain + join_edges
         └── risk-identification  D2 内链（internal_joins）
```

**单一事实来源原则**：跨源怎么关联，**只维护 correlation-matrix 一份**；Skill 文档与 AI 不得自造 Join。

### 0.3 JSON 文件里有什么（结构地图）

| 顶层块 | 作用 | 类比 |
|---|---|---|
| `field_policy` | Join 键推荐 canonical、允许源字段，读值可走 alias 正反向候选 | 字段「读写策略」 |
| `time_windows` | `alert_context`、`attack_success` 等时间窗 | 关联有效期 |
| **`internal_joins`** | **同一主机域内** D2 关联（exec/connect/file） | 主机行为链 |
| **`cross_source_joins`** | **跨数据源** 关联（WAF↔WEB↔exec↔SSH…） | 溯源主链 |
| `scenario_patterns` | 场景 → 推荐 Join 链 → `bundle_id`，现已拆到 `dataasset/scenarios/anchor-patterns.json` | 调查「剧本」 |
| `fetch_plan` | Join 绑定的查询模板与参数；`fetch_plan_defaults` 已移除 | 取数编排 |
| `constraints` | AI/脚本必须遵守的硬规则 | 合规边界 |

当前版本：**v1.1**，路径：[`dataasset/assets/correlation-matrix.json`](../../dataasset/assets/correlation-matrix.json)。

### 0.4 两类 Join（最容易混淆的概念）

#### A. D2 内关联 `internal_joins`

**范围**：同一 `asset_type` 域、同一受害主机上的行为链（audit-port-execmon 产出）。

```text
host_exec ──(host + listener_pid, ±5min)──▶ host_connect
          ──(host + pid, ±5min)──────────▶ host_file_op
```

| Join ID | 用途 |
|---|---|
| `d2_exec_connect_same_listener` | 命令执行 ↔ 同监听进程外连 |
| `d2_exec_file_same_host` | 命令执行 ↔ 异常写文件 |
| `d2_connect_file_same_host` | 外连 ↔ 文件操作 |

**服务场景**：S4 告警确认「是否打穿」、S5 风险识别攻击链、S2 溯源 execution 阶段。

#### B. 跨源关联 `cross_source_joins`

**范围**：不同 `asset_type` 之间，推荐用 canonical 字段对齐；局部可直接写源字段，由 field_resolver 通过 alias 正反向解析。

```text
waf_alert                    web_access_log              host_exec
(src_ip, url)  ──同源IP──▶  (src_ip, host)  ──host──▶  (host, command)
     │                              │
     └──────── attack_success 时间窗 ─┘
```

典型 Join：

| Join ID | 左 → 右 | 关键键 |
|---|---|---|
| `waf_to_web_access_by_ip` | WAF → WEB 访问 | `src_ip` |
| `web_access_to_host_exec` | WEB → 主机命令 | `host` |
| `waf_to_host_exec_via_web_access` | WAF → exec（**经 WEB 桥接**，多跳） | `path` 展开 |
| `host_ip_to_ssh_auth_lateral` | 跳板机 → SSH 横向 | `host_ip` ↔ `src_ip` |

**反例（禁止）**：用 `waf.src_ip` 直接 Join `host_exec.host` — 语义不同（攻击源 IP ≠ 受害主机名）。

### 0.5 双字段模型（v1.1）

Join 规则 **推荐用 canonical 名书写**（如 `host`、`src_ip`），也允许写源字段（如 `host_name`）；匹配时会读声明字段并回退 alias 候选：

```text
读值顺序（declared_first_then_alias）：
  1. Join 中声明的字段本身（canonical 或源字段）
  2. join_keys.*_variants（本条 Join 少量例外）
  3. alias 反向候选：canonical → 源字段
  4. alias 正向候选：源字段 → canonical
```

| 层 | 模块 | 职责 |
|---|---|---|
| 字段读值 | `field_resolver.py` | `resolve_field_value()` |
| Join 执行 | `correlation_engine.py` | `match_join_pair()`、`find_join_pairs()` |

**查询 vs 关联分离**：SLS 查询参数由 `fetch_plan.param_map` 与 `query-templates` 定义（如 `host_name: params.host`），不改变 Join 语义。

### 0.6 场景编排：`scenarios/anchor-patterns.json`

完整性预检回答「数据够不够」；**场景编排配置回答「够了之后按什么顺序查、怎么连」**。它不属于字段关联矩阵本体，已从 `correlation-matrix.json` 拆出。

| anchor ID | 场景 | 推荐 Join 链（节选） | 资产包 |
|---|---|---|---|
| `S1_external_ip_trace` | 外网 IP 溯源 | waf→web→exec→ssh→fw | `bundle-incident-trace-default` |
| `S4_alert_confirmation` | 告警确认 | waf→web→exec + d2_* | `bundle-alert-confirm-min` |
| `S5_host_risk` | 主机风险 | d2_exec_* | `bundle-host-risk-default` |

引擎入口：`correlate_bundles(bundles, anchor_pattern_id="S4_alert_confirmation")`
按 `recommended_chain` 逐条 Join，产出 **`join_edges`** 与 **`data_gaps`**。

### 0.7 执行引擎架构

```text
correlation-matrix.json
        │
        ├─ load_matrix() / get_join(join_id)
        ├─ expand_path()          多跳 Join 展开
        ├─ in_time_window()      读 time_windows
        ├─ match_join_pair()      单对事件匹配（含 path_prefix / cmdb / dns）
        ├─ find_join_pairs()      批量匹配
        ├─ correlate_bundles()    跑完整 anchor 链
        └─ plan_fetch()           生成 correlation_fetch_plan
                │
                ▼
        correlate.py / confirm.py / skill_input.py
```

**Join 输出契约**（`join_edges` 每条）：

```json
{
  "join_id": "web_access_to_host_exec",
  "left_ref": "web-001",
  "right_ref": "exec-001",
  "match_keys": { "host": "web-01" },
  "time_window": "attack_success",
  "confidence": 0.9
}
```

### 0.8 端到端示例：S4 告警确认

```text
① 用户：「IP 203.0.113.10 的 WAF SQLi 告警有没有打穿？」

② fetch（skill_input --fetch）
   correlation_fetch_plan 按 matrix：
     - waf_gateway_plugin_by_ip_time(src_ip=203.0.113.10)
     - web_access_by_src_ip_time(...)
     - host_exec_by_host_name_time(host_name=web-01)  ← Join 级 fetch_plan.param_map

③ normalizer：ip→src_ip，host_name→host，time→timestamp

④ confirm.py 第一层：WAF payload → alert_verdict

⑤ correlation_engine 第二层：
     - Join waf_to_web_access_by_ip（同源 IP）
     - Join web_access_to_host_exec（host 对齐）
     - Join d2_exec_connect_same_listener（exec+外连）
   → join_edges[]；若有 exec → attack_success=true

⑥ 若成功 → 移交 traceability（anchor S1/S2 链继续拼 SSH 横向）
```

### 0.9 核心功能清单（当前已实现 vs 待完善）

| 功能 | 状态 | 说明 |
|---|---|---|
| flexible Join 字段解析 | ✅ | field_resolver 支持 canonical 或源字段 + alias 正反向候选 |
| D2 / 跨源 Join 规格 | ✅ | internal + cross_source |
| 时间窗驱动匹配 | ✅ | attack_success 等 |
| 扩展 match（path_prefix / cmdb / dns） | ✅ | correlation_engine |
| join_edges 输出契约 | ✅ | correlate / confirm |
| fetch_plan 规划 | ✅ | plan_fetch → payload |
| fetch.py 按 plan 顺序拉数 | ✅ | `correlation_fetch_plan` 主路径，空 plan 回退 bundle 全量 |
| correlate 横向 BFS 全 matrix 化 | ⏳ | 部分仍硬编码 |
| validate.py 校验 matrix | ✅ | Join/time_window/Pattern/bundle 契约校验；Pattern anchor/fallback/scenario 声明已增强 |
| S3/S6/S7 anchor_patterns | ✅ | 已补 `S3_lateral_movement` / `S6_account_compromise` / `S7_data_exfiltration` |

### 0.10 与相关文档的关系

| 文档 | 读什么 |
|---|---|
| [跨源字段关联说明.md](../../docs_user/21-cross-source-field-correlation.zh-CN.md) | Join 细节、维护方式、双字段模型 |
| [数据源资产设计.md](../09-data-asset-design.zh-CN.md) | L1 资产、连接器、query-templates |
| `src/skills/_shared/data-access/README.md` | 引擎 API、fetch 用法 |
| [examples/traceability/](../../examples/traceability/) | 离线 evidence + `_meta.correlation_joins` 回归 |

---

## 一、评估范围与方法

### 1.1 评估范围

| 维度 | 内容 |
|---|---|
| 规格本身 | canonical 字段、Join 规则、时间窗、anchor_patterns、constraints |
| 与 L1/L2 一致性 | `asset-*.json`、`evidence-minimum-fields.json`、`query-templates` |
| 与 Skill 实现 | `correlate.py`、`confirm.py`、`assess.py`、`fetch.py` / `normalizer.py` |
| 与示例/实战 | `examples/traceability/`、`tmp-alert-confirm-asset-waf-prod-01.json` 暴露的问题 |

### 1.2 评估方法

- 静态审阅 JSON 结构与字段语义
- 对照 `correlate.py` / `confirm.py` 硬编码逻辑
- 核对生产资产 `asset-secweaver-host-exec`、`asset-waf-prod-01` 与 Join 级 `fetch_plan`
- 检查 `validate.py` 是否覆盖 matrix
- 用 `examples/traceability/s1-web-shell-to-ssh-lateral.json` 验证拼链意图与脚本行为

### 1.3 总体评分（5 分制）

| 维度 | 得分 | 说明 |
|---|---|---|
| 概念模型 | **4.5** | canonical + D2 内关联 + 跨源 Join + anchor 分层合理 |
| 可维护性 | **4.3** | `validate.py` 已覆盖 Join/time_window/Pattern/bundle/字段可达性；独立 JSON Schema 已补，仍需更多负例 fixture |
| 可执行性 | **4.2** | 引擎和 `correlation_fetch_plan` 主路径已落地；复杂横向 BFS 仍部分硬编码 |
| 生产对齐 | **4.0** | 12/13 个跨源 Join 已声明 fetch_plan；`host_to_cmdb_inventory` 属清单富化场景，可不自动取数 |
| AI 可消费性 | **4.5** | constraints + `join_edges` 契约已输出 |

**综合：4.2 / 5 — 架构清晰，核心执行链路已可用，进入治理与体验打磨阶段。**（初评 3.4，见 §零 实现状态对比）

---

## 二、设计亮点（合理之处）

### 2.1 三层数据模型清晰

```text
L1 asset-*.json          → 单源字段与连接器
L2 evidence-minimum      → 归一化 → canonical
L3 correlation-matrix    → canonical 之间如何 Join
```

将 **跨源关联从各 asset 中抽离为单一矩阵**，避免 N×M 重复维护，符合「定义一次、AI 反复跑」的产品理念。

### 2.2 Canonical 字段语义定义到位

`src_ip` / `host` / `host_ip` 三分法是溯源场景最容易混淆的点，matrix 在 `canonical_fields` 中显式写了 **semantics** 与 **易混点**，能有效防止典型错误（如用 `waf.src_ip` 直接 Join `host_exec.host`）。

### 2.3 D2 内关联（internal_joins）设计扎实

`d2_exec_connect_same_listener`、`d2_exec_file_same_host` 以 `listener_pid` / `listener_port` 为锚，与 audit-port-execmon 采集模型一致，同时服务：

- S5 风险识别攻击链
- S4 告警确认第二层
- S2 溯源 execution 阶段

optional 键设计（listener_pid 可选）兼顾了字段缺失时的降级关联。

### 2.4 桥接 Join 覆盖真实数据缺口

`waf_to_host_exec_via_web_access` 用 `path` 表达 **多跳桥接**，准确反映「WAF 日志常无受害 host，必须经 WEB 访问日志桥接」的生产现实。这是比简单二元 Join 更贴近实战的设计。

### 2.5 anchor_patterns 提供场景级编排

`S1_external_ip_trace`、`S4_alert_confirmation` 将 **调查场景 → 推荐 Join 链 → 资产包** 绑定，降低 AI 拼链时的搜索空间，与 `data-source-completeness/scenarios.json` 形成上下游呼应。

### 2.6 constraints 约束明确

「无 join 命中不得臆造」「success_confirmed 须至少一条 D2 Join」等约束，为 AI 输出提供了可审计边界，与 examples 中 `_meta.correlation_joins` 的测试思路一致。

---

## 三、问题与风险

### 3.1 【已缓解】规格与实现脱节 — matrix 已由引擎加载

**原状**：无脚本加载 matrix。
**现状**（2026-06-25）：

| 能力 | 模块 |
|---|---|
| 加载 matrix / Join 匹配 | `correlation_engine.py` |
| 双字段读值 | `field_resolver.py` |
| 溯源 `join_edges` | `correlate.py` → `correlate_bundles()` |
| 告警 D2 时间窗 + `join_edges` | `confirm.py` → `attack_success_window()` |
| fetch 编排计划 | `scenario_fetch.fetch_scenario_evidence()` → `correlation_engine.plan_fetch()` → `fetch.fetch_correlation_plan_evidence()` |

**仍待对齐**：`correlate.py` 内 `find_execution_chain` / `bfs_lateral` 部分逻辑仍为硬编码；fetch 主路径已切到 `correlation_fetch_plan`，后续重点是补齐更多 Join.fetch_plan 与场景 Pattern。

### 3.2 【已缓解】fetch_plan 与查询模板生产对齐

**典型案例：`asset-secweaver-host-exec`**

| 层级 | host 相关键 |
|---|---|
| SLS 原始字段 | `host_name`（已索引） |
| asset `field_aliases` | `host_name` → `host` |
| Join 级 `fetch_plan.param_map` | `host_name` ← `bridge.host` / `params.host` |
| 新增模板 | `host_exec_by_host_name_time` ✅（`plan_fetch` / `fetch_plan` 已引用） |
| 遗留模板 | `host_exec_by_host_time` 仍用 `host:`（仅兼容旧索引） |

查询参数映射统一由 Join 级 `fetch_plan.param_map` 与 `query-templates` 负责，matrix 不再维护 `query_field_resolution.index_fields`，也不再维护全局 `fetch_plan_defaults`。字段归一仍由 `evidence-minimum-fields.field_aliases` 与 `asset-*.json.field_aliases` 负责。

### 3.3 【已缓解】部分 Join 键在 evidence schema 中不存在

本轮已补齐关键资产字段声明，使以下 Join 键在静态校验中可达：

| Join | 处理 |
|---|---|
| `firewall_web_to_internal` | `ssh_auth` 资产补充 `host_ip` 字段，用于登录目标主机 IP 关联 |
| `host_connect_to_dns` | `host_connect` 资产补充 `host_ip` 字段 |
| `nta_session_correlation` | `host_connect` 资产补充 `host_ip` 字段 |
| `d2_exec_connect_same_listener` | `host_connect` 资产补充 `listener_pid` / `listener_port` 字段 |
| `d2_exec_file_same_host` | `host_file_op` 资产补充 `listener_pid` 字段 |

剩余注意：字段已在资产契约层声明可达，生产上线仍需确认采集端确实输出这些字段或由 normalizer / field_aliases 派生。

### 3.4 【已缓解】anchor_patterns 场景覆盖不全

`data-source-completeness/scenarios.json` 定义 S1–S7；当前 `dataasset/scenarios/anchor-patterns.json` 已补齐 S3/S6/S7：

| 场景 | anchor pattern | 当前状态 |
|---|---|---|
| S3 横向移动 | `S3_lateral_movement` | 复用 `bundle-incident-trace-default`，串联 SSH / firewall / host_exec / CMDB |
| S6 账号失陷 | `S6_account_compromise` | 复用 `bundle-incident-trace-default`，串联 `attacker_ip_to_ssh_auth` 与 `ssh_auth_to_host_exec_same_host` |
| S7 数据外传 | `S7_data_exfiltration` | 新增 `bundle-data-exfiltration-default`，覆盖 host_connect / DNS / NTA / DB audit |

剩余风险：S7 相关资产多处于 draft/example 状态，生产落地还需要按客户环境补齐 connector、字段别名和查询模板。

### 3.5 【已完成 / 持续治理】validate.py + JSON Schema 双层校验

`validate.py` 现在已经把 correlation-matrix 纳入发布前语义校验：

- Join 引用的 `time_window` 是否存在
- `from_asset_type` / `to_asset_type` 是否有对应资产类型
- `join_keys.left/right` 是否可通过资产字段、`field_aliases` 或 evidence-minimum 到达
- anchor pattern / fallback / scenario / bundle 引用是否闭合
- `path` 中引用的 join id 是否存在
- `fetch_plan.template_id` 与 `param_map` 是否可解析到查询模板

当前已新增 `dataasset/schema/correlation-matrix.schema.json`，负责结构类型、必填字段、match 枚举、`priority` / `confidence` 范围和 `fetch_plan` 形态校验；Python 语义校验继续负责跨文件引用、字段可达、anchor/bundle 闭合与 `fetch_plan.template_id` 解析。

剩余风险：需要补更多负例 fixture，覆盖破坏性变更、版本兼容、priority/confidence 错误范围和 path Join 悬空引用。

### 3.6 【已缓解 / P2】fetch_plan 已形成主路径，仍需覆盖率治理

当前主路径已经闭环：

```text
scenario_fetch.fetch_scenario_evidence -> correlation_engine.plan_fetch
  → payload.correlation_fetch_plan
  → fetch.py 按 plan 顺序拉数
  → 无 plan 时回退 bundle 全量取数
```

`cross_source_joins` 中大多数需要自动补拉证据的 Join 已有 `fetch_plan`；`internal_joins` 主要消费同一主机域内已取回 evidence，通常不需要独立 fetch_plan；`host_to_cmdb_inventory` 属清单富化，可按部署选择是否自动取数。

剩余风险：

- 新增 Join 时仍可能忘记补 `fetch_plan`，需要 validate 输出覆盖率摘要。
- 复杂桥接和横向 BFS 仍有部分脚本逻辑硬编码，后续应继续迁移到 matrix + engine。
- UI 还没有把 `correlation_fetch_plan` 以预览图/步骤形式展示给运营同学。

### 3.7 【P2】bundle 与资产状态漂移

| bundle | 问题 |
|---|---|
| `bundle-incident-trace-default` | 含 `asset-secweaver-host-file-op`、`asset-ssh-internal` 等 draft/placeholder |
| `bundle-alert-confirm-min` | `asset-web-access-prod` 为 **draft** |

anchor_patterns 引用的 bundle 与生产可用性不一致，完整性预检与实战 fetch 结果分化。

### 3.8 【P2】缺少反向索引与冲突消解模型

- 无从 `asset_type` 反查可用 Join
- Join `priority/confidence` 已有基础模型；仍缺互斥 / 冲突消解（如 `waf_to_host_exec_direct` vs `via_web_access` 同时命中时如何取舍）
- 置信度已经可解释，但尚未形成跨 Join 的冲突降权、替代链路和证据质量评分

---

## 四、与示例及实战的一致性

### 4.1 examples/traceability 对齐良好

`s1-web-shell-to-ssh-lateral.json` 的 `_meta.correlation_joins` 与 matrix 推荐链高度一致，`correlate.py` 能产出 `confirmed_intrusion_chain`。
说明：**matrix 作为 AI/测试规格是有效的**；当前瓶颈已从“引擎和 fetch 未落地”转为“复杂路径覆盖率、生产样本和可视化解释”。

### 4.2 历史实战 gap（告警确认 live fetch）

早期 `asset-waf-prod-01` fetch 成功，但 `host_exec` 因查询键错误失败，导致 D2 Join 无法执行。当前已通过 `host_exec_by_host_name_time` 与 Join 级 `fetch_plan.param_map` 打通主路径。

后续生产验收重点不再是“能否按 Join 生成取数计划”，而是：

- 客户真实凭证、project/logstore、index/SQL 字段是否与模板一致。
- 高并发或大时间窗下是否有 fetch 审计、限流和超时策略。
- UI 是否能解释“为什么会拉这些源、按什么参数拉”。

---

## 五、优化建议

### 5.1 短期（1–2 周）：对齐与校验 — 投入小、收益高

#### A. 统一字段解析单一来源

```text
权威顺序（建议）：
asset.field_aliases  →  normalizer  →  canonical
fetch_plan.param_map  →  query-templates params
```

- 已从 matrix 删除 `query_field_resolution.index_fields`，查询参数映射由 `fetch_plan.param_map` 负责
- `host_exec_by_host_name_time` 通过 `param_map.host_name: params.host` 对齐 SLS 索引键

#### B. 维护 matrix JSON Schema，保留 validate.py 语义校验

新增 `dataasset/schema/correlation-matrix.schema.json`，校验：

- join id 唯一
- time_window 引用存在
- path 中 join 可达
- bundle_id 存在
- Join 字段若不在 evidence-minimum 中，提示确认其为源字段并具备 alias/variants 解析路径

`validate.py` 已经负责跨文件语义校验；JSON Schema 已补结构、枚举、priority/confidence 和 IDE/CI 级快速反馈。后续重点是负例 fixture 与版本兼容策略。

#### C. 时间窗与脚本对齐

| 名称 | 建议统一值 | 消费方 |
|---|---|---|
| `attack_success` | before 5 / after 30 min | confirm.py, correlate.py |
| `host_behavior_chain` | ±5 min (300s) | correlate.py D2 |
| `alert_context` | ±10 min | confirm.py layer1 |

**已完成（2026-09-16 核对）**：`alert_confirmation/common.py` 的 `attack_success_window()` 已读取 matrix，缺省为前 5、后 30 分钟；不再需要执行原来的固定 15 分钟窗口调整建议。

#### D. 让需要取数的 Join 显式声明 fetch_plan

所有需要参与自动补拉证据的 Join，都应在 `fetch_plan.left/right` 中显式声明 `template_id` 与 `param_map`，不再依赖全局默认取数配置。

当前 `cross_source_joins` 已基本覆盖自动取数主链；后续重点是新增 Join 的覆盖率统计、可选清单 Join 的豁免说明，以及 UI 预览。

---

### 5.2 中期（3–6 周）：引擎化 — 让 matrix 真正驱动执行

#### E. 扩展共享模块 `correlation_engine.py`

```text
src/skills/_shared/data-access/correlation_engine.py
├── load_matrix()
├── resolve_field(event, asset_id)      # canonical
├── match_join(join_id, left, right)    # 含 match_type
├── expand_path("waf_to_host_exec_via_web_access")
├── apply_time_window(window_id, anchor_ts, event_ts)
└── plan_fetch(anchor_pattern, params)  # → template_id + params
```

该模块已存在并被 `correlate.py` / `confirm.py` 消费；下一步是继续把剩余硬编码路径迁移为：

1. 按 `anchor_patterns` 选链
2. 对 evidence 调用 `match_join`
3. 输出 `attack_chain[].join_id` 与 `data_gaps[]`

#### F. Join 输出契约

每条关联边强制输出：

```json
{
  "join_id": "web_access_to_host_exec",
  "left_ref": "web-001",
  "right_ref": "exec-001",
  "match_keys": { "host": "web-01" },
  "time_window": "attack_success",
  "confidence": 0.9
}
```

便于审计、回归测试与 AI 报告引用。

#### G. fetch 编排与 Join 绑定

在每条 Join 上扩展：

```json
{
  "fetch_plan": {
    "left": { "template_id": "waf_gateway_plugin_by_ip_time", "param_map": { "src_ip": "params.attacker_ip" } },
    "right": { "template_id": "host_exec_by_host_time", "param_map": { "host": "$left.bridge.host" } }
  }
}
```

`scenario_fetch.fetch_scenario_evidence` 使用 `correlation_engine.plan_fetch`
按 anchor_pattern 生成 `correlation_fetch_plan`，`fetch.py` 按计划顺序执行。
输入适配与流程执行放在 `skill_runtime`；`prepare.py` 保留一键准备与兼容入口。

#### H. 实现扩展 match 类型

| match_type | 实现要点 |
|---|---|
| `path_prefix` | URL 归一化后前缀比较 |
| `hostname_to_ip_via_cmdb` | 复用 `build_host_ip_map` |
| `dns_answer_ip` | 解析 DNS response A/AAAA 记录 |

---

### 5.3 长期（6–12 周）：场景补全与演进

#### I. 继续完善 anchor_patterns

| anchor | 后续完善要点 |
|---|---|
| `S3_lateral_movement` | 补更多横向路径证据（Windows 登录、VPN、堡垒机）与横向 BFS 矩阵化 |
| `S6_account_compromise` | 补 VPN / IAM / AD 登录 Join，避免只依赖 SSH |
| `S7_data_exfiltration` | 补 d2_exec_file → host_connect → DNS/NTA → db_audit 的更完整外传链 |

#### J. Join 优先级与互斥

为 `waf_to_host_exec_direct` vs `waf_to_host_exec_via_web_access` 增加：

```json
"preconditions": { "requires_field": { "waf_alert": "host" } },
"priority": 10,
"fallback_join": "waf_to_host_exec_via_web_access"
```

#### K. 版本化与变更日志

- matrix 升级 `version: "1.1"` 时保留 `deprecated_joins`
- `CHANGELOG-correlation-matrix.md` 记录破坏性变更
- examples 回归：`pytest` 遍历 `_meta.expected_*` + join_id

#### K. 可选：关联图可视化

从 matrix 生成 Mermaid/GraphML，供安全运营审核 Join 拓扑。

---

## 六、建议的 v1.1 结构增量（草案）

在现有结构上 **增量扩展**，避免大规模重写：

```json
{
  "version": "1.1",
  "cross_source_joins": [
    {
      "id": "web_access_to_host_exec",
      "fetch_plan": {
        "right": {
          "asset_types": ["host_exec"],
          "template_id": "host_exec_by_host_name_time",
          "param_map": {
            "host_name": "bridge.host",
            "time_start": "params.time_start",
            "time_end": "params.time_end"
          }
        }
      },
      "preconditions": { "requires": ["web_access_log.host"] },
      "output_confidence": 0.85
    }
  ],
  "join_registry_index": {
    "host_exec": ["d2_exec_connect_same_listener", "web_access_to_host_exec", "..."]
  }
}
```

---

## 七、优先级路线图

| 优先级 | 任务 | 预期效果 |
|---|---|---|
| **P0** | 修复 `host_exec` SLS 查询键（host_name） | ✅ 已完成，打通 S4 D2 主路径 |
| **P0** | confirm/correlate 时间窗与 matrix 对齐 | ✅ 已通过 engine/time_window 主路径对齐；继续防回退 |
| **P1** | matrix 语义校验进入 validate.py | ✅ 已完成 |
| **P1** | correlation-matrix 独立 JSON Schema | ✅ 已完成；继续补负例 fixture |
| **P1** | 需要取数的 Join 显式声明 fetch_plan | ✅ 主链已完成；新增 Join 需覆盖率治理 |
| **P1** | correlation_engine 骨架 + join_id 输出 | ✅ 已完成 |
| **P2** | fetch_plan 与 query_templates 绑定 | ✅ 主路径已完成；继续补 UI 预览和审计 |
| **P2** | 补 S3/S6/S7 anchor_patterns | ✅ 已补；后续扩展更多证据源 |
| **P3** | Join 互斥、替代链路和冲突降权 | 降低误关联 |

---

## 八、结论

`correlation-matrix.json` 在 **概念层是合理且重要的**：它正确回答了 SecWeaver 跨源溯源的核心问题——**用什么字段、在什么时间窗、按什么顺序 Join**。三层模型、D2 内关联、WAF 桥接 Join、constraints 等设计均达到可生产化规格的水平。

当前主要短板不再是「Join 规则想得不对」或「fetch 路径未闭环」，而是 **规格治理和复杂场景覆盖率还需继续增强**：Join 互斥/冲突消解、复杂横向 BFS、生产取数审计、更多真实样本回归与 UI 解释细节仍需要打磨。

**建议定位**：将 correlation-matrix 视为与 `scenarios.json`、`attack-patterns.json` 同级的 **平台核心资产**；当前已从「重要文档」升级为「可执行关联内核」，下一阶段应重点提升可解释性、可视化和发布治理。

---

## 九、相关文件

| 文件 | 关系 |
|---|---|
| [correlation-matrix.json](../../dataasset/assets/correlation-matrix.json) | 评估对象 |
| [跨源字段关联说明.md](../../docs_user/21-cross-source-field-correlation.zh-CN.md) | 人类可读规格 |
| [evidence-minimum-fields.json](../../dataasset/configure/evidence-minimum-fields.json) | L2 归一化 |
| [templates.json](../../dataasset/query-templates/templates.json) | 取数层，已与 Join 级 `fetch_plan` 主路径绑定 |
| [correlate.py](../../src/skills/traceability-analysis/scripts/correlate.py) | 已消费 matrix/engine；复杂横向 BFS 继续收敛 |
| [confirm.py](../../src/skills/alert-confirmation/scripts/confirm.py) | 已消费 matrix/engine 与 `join_edges` |
| [examples/traceability/](../../examples/traceability/) | 回归测试集 |

---

*报告版本：v1.0 | 评估人：SecWeaver 架构审阅*

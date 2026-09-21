**语言：** [English](10-data-asset-design-evaluation.md) | 简体中文（本文）

# 数据源资产设计评估

> **文档状态：历史评估记录。** 评估日期截至 2026-07-08；其中的完成度估算、待办和版本评分不代表当前发布承诺。当前可用入口以 [`dataasset/`](../../dataasset/)、[用户接入指南](../../docs_user/03-configure-data-sources.zh-CN.md) 和根目录 README 为准。


> 对 SecWeaver **数据源资产设计**（文档 + `dataasset/` + 数据访问层）的详细评估  
> 评估日期：2026-06-21（第八次）· **2026-06-25（第十次，关联引擎与字段治理）** · **2026-06-30（对象模型收口与解析器更新）** · **2026-07-08（文档状态同步）**  
> 关联文档：[数据源资产设计.md](../09-data-asset-design.zh-CN.md) | [当前完整接入流程](../../docs_user/03-configure-data-sources.zh-CN.md) | [字段发现](../../docs_user/20-log-format-discovery.zh-CN.md) | [Agent采集与Evidence规范.md](../12-agent-collection-and-evidence-spec.zh-CN.md) | 实现目录：[dataasset/](../../dataasset/)

---

## 总体结论

| 维度 | v2.0 | v2.2 | v2.3 | v2.5 | v2.6 | **v3.0** |
|---|---|---|---|---|---|---|
| **概念清晰度** | ★★★★★ | ★★★★★ | ★★★★★ | ★★★★★ | ★★★★★ | **★★★★★** |
| **可落地性** | ★★★★☆ | ★★★★★ | ★★★★★ | ★★★★☆ | ★★★★☆ | **★★★★☆** |
| **可扩展性** | ★★★★☆ | ★★★★☆ | ★★★★☆ | ★★★★☆ | ★★★★☆ | **★★★★★** |
| **文档与实现一致性** | ★★★★☆ | ★★★★★ | ★★★★★ | ★★★★☆ | ★★★★☆ | **★★★★☆** |
| **示例目录自洽性** | — | — | — | ★★★☆☆ | ★★★☆☆ | **★★★★☆** |
| **新源接入便利性** | — | — | — | — | ★★★★☆ | **★★★★☆** |
| **格式映射便利性** | — | — | — | — | ★★★★☆ | **★★★★★** |

**当前阶段适合**：本地编辑 + SOPS + validate/diagnose + **多源 fetch**（内置、插件、外置执行器）+ Normalizer + 多 connector 聚合 + 四类调查 Skill + `--from-bundle` 端到端演示。

**接入新数据（当前结论）**：**同类介质、已知 asset_type 时较方便**（改 JSON + connector + 查询模板即可，多数不需改 Python）；**全新 log 格式**通过 `discovery` + log-format-discovery + `schema.fields` 补充闭环处理；资产侧主机关联已收口为 `coverage.hosts` 来源 IP，避免 `host_binding` / aliases / hostname 混用。

**格式映射（当前结论）**：**JSON/结构化最省事**（`json_lines` + `field_aliases`）；字段值里还嵌套 JSON object 时使用 `json_lines2`，会展开为 `父字段.子字段`；**内置文本**一行配置；**全新文本**用 `parsers/*.json`。**per-asset `field_aliases` 已支持**；`correlation_keys` 由 matrix+fields 自动推导，勿手写。

**离产品级还差**：产品 UI 深化、真实 vendor 示例与截图教程、示例 catalog 全绿、fetch 审计、更多 connector 联调样例、远端 CI 矩阵继续增强。

**第十次增量（2026-06-25）**：`correlation_engine` / `field_resolver` / `correlation_keys` 自动推导、`time_correction`、全平台字段参考 `examples/reference-assets.json`；`schema.correlation_keys` 废弃手写。

**2026-06-30 增量**：`host_binding` 已从资产模型移除；`coverage.hosts` 明确定义为日志来源 IP 数组；Host 的 `aliases` / `interfaces` 保留但限定用途；Network 的 `zone` / `network_type` / `trust_level` 分工明确；新增 `asset_type: syslog_risk_alert`，并将 `asset-secweaver-sys-risk-alert` 收口为 `asset-secweaver-sys-risk-alert`；新增 `json_lines2` 解析器用于展开嵌套 JSON 字段。

**实现完成度估算**：核心代码约 **92–95%**；**可演示闭环**约 **75–80%**（数据资产模型、UI、配置诊断和 connector 扩展机制已明显收口，示例 catalog 与真实 vendor 联调仍需继续补）。

---

## 一、自 v1.0 以来已解决项

| v1.0 问题 | 当前状态 | 证据 |
|---|---|---|
| 无 `validate.py` | ✅ | `src/dataasset/validate.py` + JSON Schema |
| 模板选择硬编码 | ✅ | `template_select.py` + `FALLBACK_BY_ASSET_TYPE` |
| Agent vs SLS 路径混淆 | ✅ | 设计 §3.8、`agent-collection-and-evidence-spec.zh-CN.md` |
| evidence 无规范 | ✅ | `evidence-minimum-fields.json` + Normalizer |
| SSH fetch 未实现 | ✅ | `ssh_fetch.py` |
| DB / HTTP / ES fetch | ✅ | `db_fetch.py` / `http_fetch.py` / `es_fetch.py` |
| 云厂商 / SIEM / 数仓 fetch | ✅ | AWS/Azure/GCP/Tencent/Huawei/Splunk/ClickHouse/Hive 等独立 fetch 文件或外置执行器 |
| Normalizer 未实现 | ✅ | `normalizer.py` |
| 多 connector 聚合 | ✅ | `connector_ids` + `aggregate.py` |
| 格式发现 Skill | ✅ | `log-format-discovery` |
| PostgreSQL database_ro | ✅ | `db_fetch.py` + psycopg3（v2.3 新增） |
| 字段归一化运营指南 | ✅ | [日志格式发现](../../docs_user/20-log-format-discovery.zh-CN.md) |
| `status=active` vs 资产包引用语义不清 | ✅ | `registry.asset_to_registered` + `validate.check_bundle` + `--from-bundle` + `promote-after-connectivity.py` |
| coverage hint 软匹配 | ✅ | `check.py` `match_coverage_hint`（方案 B） |
| **correlation_engine + join_edges** | ✅ | `correlation_engine.py`；溯源/告警输出 Join 契约 |
| **correlation_keys 自动推导** | ✅ | `correlation_keys.py`；废弃资产内手写 |
| **time_correction** | ✅ | `schema.time_correction` + `normalizer.py` |
| **字段完整性共享检查** | ✅ | `field_inventory.py`；`data-source-completeness` 改用 `effective_fields` |
| **字段参考示例** | ✅ | `examples/reference-assets.json` + `build-field-reference.py` |
| **资产侧主机关联收口** | ✅ | 移除 `host_binding`；使用 `coverage.hosts` 来源 IP + `connector.config.host_id` |
| **Network 字段口径** | ✅ | `zone` / `network_type` / `trust_level` 分别表达分组、用途、安全信任等级 |
| **syslog-risk-json 类型化** | ✅ | 新增 `asset_type: syslog_risk_alert`，资产 ID 收口为 `asset-secweaver-sys-risk-alert` |
| **嵌套 JSON 行解析** | ✅ | 新增 `json_lines2`：字段值若是 JSON object 字符串/对象，展开为点号字段 |

### 1.1 v2.3 新增能力（相对 v2.2）

| 项 | 说明 |
|---|---|
| **asset_type 扩展** | `windows_event_log`、`linux_syslog`、`network_traffic_audit` |
| **database_ro 双引擎** | MySQL（pymysql）+ PostgreSQL（psycopg3），共用 `:param` SQL 模板 |
| **ES 示例资产** | `asset-es-waf-prod`、`asset-es-web-access-prod` |
| **MySQL 示例资产** | `asset-mysql-ssh-auth`、`asset-mysql-db-audit`、`asset-cmdb-hosts` |
| **PostgreSQL 示例** | `conn-db-pg-sec-audit`、`asset-pg-cmdb-hosts` |
| **接入 FAQ** | Q1 接入流程、Q2 text_parser、Q3 源字段 vs 归一化字段 |
| **风险识别 Skill** | 依赖 D2 exec/connect，与 dataasset 通过 `asset_type` 解耦 |

### 1.2 validate.py 当前典型输出（2026-07-08）

当前 `validate.py` 已不再存在早期 `text_parser` oneOf 歧义类 schema error；未引用 connector 也不再作为 warning。当前校验目标是 **0 error / 0 warning / 0 blocking issue**。

当前实测 `validate.py --json` 为 **0 error / 0 warning / 0 blocking issue**；需要运营可读原因和修复步骤时使用 `--diagnose`。

仍可接受的 warning 主要来自 draft 资产字段不完整、文档备注类提示或接入期状态；未被任何 asset 引用的 connector 不再作为 warning，因为它可能是备用、跳板或接入中的连接器。

| 类型 | 示例 | 性质 |
|---|---|---|
| catalog 多余引用 | 已删除的示例 network 路径 | 目录清理项，不影响当前对象模型 |

当前校验重点已经转向：`coverage.hosts` 是否为 IP、asset 引用的 connector 是否存在、`connector.config.host_id` 是否存在、host/network 归属是否合理、active asset 是否具备 owner/description/retention/evidence 字段。

### 1.3 三默认 bundle 完整性实测（`--from-bundle` 展开，2026-06-21）

| 资产包 | 场景 | active/总数 | `overall_verdict` | 阻断 P0 |
|---|---|---|---|---|
| `bundle-incident-trace-default` | S1+S3 | 3/8 | **not_traceable** | WEB 进程命令执行（`host_exec` draft） |
| `bundle-alert-confirm-min` | S4 | 1/4 | **not_traceable** | WEB 访问日志（`web_access_log` draft） |
| `bundle-host-risk-default` | S5 | 0/3 | **not_traceable** | 主机命令执行（D2 全 draft） |

结论：**设计与 Skill 链就绪**；示例目录 D2/WEB 晋升与 bundle 自洽仍为运营 P0（见 §三.7）。

### 1.4 第十次评估增量（2026-06-25）

| 项 | 说明 |
|---|---|
| **关联引擎化** | `correlation-matrix` v1.1 + `correlation_engine.py`：`match_join_pair`、`plan_fetch`、`join_edges` |
| **双字段读值** | `field_resolver.py`；matrix `field_policy` + `fetch_plan.param_map` |
| **关联键治理** | 删除资产内手写 `correlation_keys`；`registry` / 完整性 Skill 用推导结果 |
| **时间校正** | `schema.time_correction`（`assume_timezone` / `offset_minutes`） |
| **字段参考** | 合并资产 `asset-example-all-fields`（128 字段，17 类型并集） |
| **单测** | data-access **68+**（含 correlation_engine、correlation_keys、field_resolver） |

**已完成**：`fetch.py` 已消费 `correlation_fetch_plan` 顺序拉数；`validate.py` 已校验 matrix/anchor/bundle 字段契约。

**仍待办**：溯源 `correlate.py` 横向 BFS 全 matrix 化；为 correlation-matrix 的 Schema / priority / confidence 补更多负例 fixture；为 fetch_plan 覆盖率、复杂 vendor connector 和 UI 诊断继续补测试。

---

## 二、设计做得好的地方（延续 + v2.3）

### 1. 分层清楚：L1 资产 vs L2 连接器

与 Skill 解耦（bundle 用 `investigation_scenarios` S1–S7，不写 Skill 名）贯彻良好。

### 2. 多源 fetch 统一入口

```text
fetch.py → sls | ssh_file | ssh_command | local_file | database_ro
         → http_api | es | agent_stream | syslog_ingest | object_storage
         → AWS/Azure/GCP/Tencent/Huawei/Splunk/ClickHouse/Hive
         → plugin_executor / external executor
         → normalizer → evidence_bundles
```

查询模板按 `connector_type` 选字段（`sls_query` / `sql` / `es_query` / `cloudwatch_query` 等）。扩展新源优先走配置型外置执行器或插件；只有要进入核心内置能力时才需要新增/维护平台 fetch 文件。

### 3. 凭证与 AI 边界

SOPS + `vault://` ref；Skill/Claw 只见 ref 与归一化 evidence，不见 secret。

### 4. 字段两层模型（FAQ Q3 固化）

```text
查询层：logstore/ES/SQL 用源字段名
证据层：normalizer + field_aliases → canonical（src_ip、timestamp…）
```

降低「能查到数但 Skill 字段为空」类接入故障。

### 5. 文档体系

| 文档 | 角色 |
|---|---|
| 数据源资产设计.md | 主设计（**v3.1**） |
| 数据源接入FAQ.md | 运营接入与归一化 |
| Agent采集与Evidence规范.md | 采集链 + evidence |
| 日志格式发现*.md | 新 log 类型 |
| dataasset/README.md | 目录编辑 |
| 本评估 | 差距与优先级 |

---

## 三、仍不够清楚或易混淆的点

### 1. `status=active` vs 资产包引用（已落地）

**原混淆**：完整性 Skill 只认 `active`；bundle 可同时列出 draft 成员 → validate 报错 vs `--from-bundle` 评估结果看似矛盾。

**现约定**（[数据源资产设计.md §八、§十](../09-data-asset-design.zh-CN.md)）：

| 层 | 规则 | 实现 |
|---|---|---|
| 资产 JSON | `status=active` 才视为可用 | `registry.asset_to_registered` → `registered` / `not_registered` |
| 资产包 JSON | `status=active` 时成员须全为 `active` | `validate.check_bundle` 报错阻断 |
| Skill 输入 | bundle 展开后 draft 资产计为 `missing` | `bundle_to_registered_assets` + `skill_input --from-bundle` |
| 晋升 | 连通测试通过后改 status | `promote-after-connectivity.py` |

组装/接入阶段：bundle 保持 **`draft`**，可引用 draft 资产；生产发布前资产逐个 **`active`**，再将 bundle 升为 **`active`** 并通过 validate。

**状态**：✅ 契约已在 registry / validate / Skill 链对齐；当前 validate error 是**示例资产未晋升**，不是规则缺失。

### 2. `coverage` 语义（方案 B 已落地）

`check.py` 将场景 `coverage` hint 与资产 `zones`/`hosts` **逐项匹配**（含 `params.hosts` 主机级判定）；不再默认一律 `full`。词典与规则见 [数据源资产设计.md §2.3.11](../09-data-asset-design.zh-CN.md)。

**状态**：✅ 已实现（`match_coverage_hint` + `registry.coverage_detail` + 单元测试）。

### 2.1 字段完整性检查（已共享化）

原 `data-source-completeness` 只检查 `registered_assets[].fields`，会把 `asset-secweaver-host-exec` 这类资产误判为缺 `host` / `timestamp`：源字段为 `host_name` / `time`，但 `asset.field_aliases` 已映射到 canonical 字段。

**现约定**：字段完整性统一走 `src/skills/_shared/data-access/field_inventory.py`：

```text
raw_fields       = schema.fields
canonical_fields = 全局 field_aliases / asset.field_aliases / time_field 可达字段
effective_fields = raw_fields ∪ canonical_fields
```

`registry.asset_to_registered()` 输出 `field_aliases`、`canonical_fields`、`effective_fields`；`data-source-completeness` 调用 `check_required_fields()`，按 `effective_fields` 判断场景必需字段。`correlation-matrix.json` 不再维护第二套 `canonical_fields.variants`。复测 S1/S3 时，`asset-secweaver-host-exec` 的 `S1-P0-exec` 已由 `partial` 变为 `ready`，置信度从 0.59 提升到 0.68。

**状态**：✅ 已实现；后续其它 Skill 若需判断字段覆盖，应复用 `field_inventory.py`，不要自写 `set(asset.fields)`。

### 3. JSON Schema 与对象模型收口

**性质**：早期 `text_parser` oneOf 歧义已经通过 `not: { enum: [...] }` 消除；当前 `validate.py` 可做到 **0 error / 0 blocking**。Schema 重点从“能否通过”转为“能否让运营和 AI 少误解”。

#### 3.1 `text_parser` 内置枚举（已收口）

| 项 | 当前状态 |
|---|---|
| **内置 parser** | `syslog_auth`、`nginx_combined`、`json_lines`、`json_lines2`、`raw_only` |
| **自定义 parser** | 第二个字符串分支通过 `not enum` 避免与内置 ID 重叠 |
| **`json_lines`** | 每行 JSON object；字段映射走 `field_aliases` |
| **`json_lines2`** | 每行 JSON object；字段值若本身也是 JSON object 字符串/对象，则展开为 `父字段.子字段` |
| **示例** | `fields: "{\"user\":\"root(uid=0\"}"` 可展开为 `fields.user` |

验收口径：新增内置 parser 时必须同步 `text-log-parsers.json` 与 `data-asset.schema.json` 的内置枚举。

#### 3.2 `masking` / `pii_fields` 职责对齐（P2 · 已收口）

| 字段 | Schema | 运行时 | 说明 |
|---|---|---|---|
| **`masking`** | ✅ `redact` 或 `truncate_<N>` | ✅ `normalizer.apply_masking` | runtime 实际执行脱敏；键可为字段名或点号路径（如 `request.header`） |
| **`pii_fields`** | ✅ `array<string>` | 设计上 **不读取** | 仅作 PII/敏感字段标注，供治理、UI、审计使用；不自动脱敏 |

**设计选择**：不让 `pii_fields` 自动 `redact`，避免误伤溯源研判字段。需要脱敏时必须显式写入 `masking`。  
**剩余缺口**：`masking` 键名暂不校验是否存在于 `schema.fields`，属于 P3 质量增强。

#### 3.3 connector `config` / `constraints` 分支（P2 · 部分已做）

[`data-connector.schema.json`](../../dataasset/schema/data-connector.schema.json) 已对 **sls / ssh_file / database_ro（含 MySQL、PostgreSQL、Oracle/PLSQL、SQL Server、SQLite）/ http_api / es / local_file / agent_stream / AWS / Azure / GCP / Tencent / Huawei / Splunk / ClickHouse / Hive / MongoDB / Redis** 做分类型必填校验；**active** 连接器须 `credentials_ref`（`local_file` 除外）。

| 仍缺口 | 说明 |
|---|---|
| `ssh_command`、`syslog_ingest`、`object_storage` | 已有模板和 fetch 路径，但 schema 约束仍可继续细化 |
| `constraints` | 已能承载通用约束，但未完全按 connector 类型约束 `max_rows` / `max_time_span_hours` 等 |
| `bastion_id` 引用 | 未 schema 校验跳板 connector 是否存在 |

#### 3.4 其它松散项（P2–P3）

| 项 | 示例 | 建议 |
|---|---|---|
| **`environment` 枚举** | `asset-local-lab-auth` 使用 `lab` → 1 error | 增 `lab` 或改 `development` |
| **`additionalProperties: true`** | asset / connector 允许未定义字段 | 逐步改为 `false` + 显式 `properties`，或 `unevaluatedProperties` |
| **`coverage.hosts` IP 口径** | 仅允许日志来源 IP；`coverage.zones` 已移除 | 继续通过 schema/validate 防止写入 hostname、aliases 或文字别名 |
| **`field_aliases` per-asset** | ✅ 已实现 | `asset.field_aliases` 覆盖全局；`discover --apply` 默认写 per-asset |

**小结**：当前 Schema 已从阻塞校验阶段进入治理增强阶段；优先继续强化 `coverage.hosts` IP-only、`text_parser` 枚举同步、connector `constraints` 分类型约束和 catalog 清理。

### 4. 防火墙模板粒度

`firewall_by_src_dst_time` 用于源目 IP 精确关联；仅已知攻击 IP 时用 **`firewall_by_src_ip_time`**（仅需 `src_ip` + 时间窗）。`template_select` 在缺 `dst_ip` 时自动优先前者。

**状态**：✅ 已实现（`templates.json` + `asset-fw-dmz-internal`）。

### 5. live 数据与 Skill 稳定性

Normalizer 已实现，但部分 logstore（如 gateway `ip` vs `src_ip`）依赖 **field_aliases 维护**；新源接入仍须格式发现闭环。`asset-waf-api-prod` 仍在 **discovery** 队列。

### 6. taxonomy「半注册」：`dns_log` 等（P1 · 设计/实现缺口）

| asset_type | schema 枚举 | 完整性场景 | 模板 | 示例资产 | evidence 规范 |
|---|---|---|---|---|---|
| **`dns_log`** | ✅ | S1/S2 **P1** | ✅ | ✅ `asset-dns-internal-prod` | ✅ |
| `ids_alert` / `edr_event` / `vuln_scan` / `app_api_log` | ✅ | 未入场景 | ❌ | ❌ | 部分/无 |

**影响**：`dns_log` 已有 draft 示例与模板；`ids_alert` 等仍无端到端样例。`template_select.FALLBACK_BY_ASSET_TYPE` 对 `dns_log` 需确认已配置。

**修复方向**：补全 ids/edr 等 P2 类型；或场景矩阵标「可选」直至模板就绪。

### 7. 示例目录与 validate 自洽（P0 · 运营/仓库卫生）

| 问题 | 现状 | 建议 |
|---|---|---|
| **bundle 仍为 `active`** | 3 个 bundle 均 active，但引用 11 处 draft 成员 → 10 条 validate error | 接入完成前 bundle 改 **`draft`**；或按 §三.1 先晋升成员再发布 |
| **SLS 占位符** | `conn-sls-web-access-prod` 等 **7 个** connector 仍为 `YOUR_SLS_PROJECT` | 真实 project/logstore 仅放在私有部署配置中 |
| **ES/DB/HTTP 占位** | `es.example.com`、`db-audit.internal.example.com` 等 | 联调后替换或标 `status: draft` |
| **`promote-after-connectivity.py`** | 默认仅测 `host_*` / `web_access_log` | 扩展 `--types` 覆盖 CMDB、NTA、Win/Linux syslog |

### 8. SLS 与 ES 双路径选择（P2 · 运营易混）

同一 `asset_type`（如 `waf_alert`、`web_access_log`）可同时存在 SLS 与 ES 两套 draft 资产。**设计允许**，但缺「何时选哪条」的决策表 → 运营易重复注册或选错 connector。

**建议**：在设计文档或 FAQ 增 **接入路径决策**（已有 SLS 则优先 SLS；仅 ES 索引则 ES；双写则按延迟/成本选一）。

### 9. 测试与 CI 缺口（P1–P2）

| 项 | 现状 |
|---|---|
| 单元测试 | data-access **68+**、completeness **14+**，均通过 |
| **已有** | `release_scan`、docs link scan、SecWeaver CLI/dataasset UI 单测覆盖 validate 和发布门禁主路径 |
| **缺失** | `http_fetch` 定向单测仍少；matrix 负例 fixture、复杂 vendor connector smoke test 与远端 CI 矩阵仍需补 |
| validate 样例 params | `check_template_fetch_samples` 仅 **warn**，固定 IP/时间，未覆盖 ES/SQL/防火墙单 IP 等分支 |

**建议**：继续保持本地 `release_scan` + docs-check + unittest；补 matrix 负例、http_fetch 定向测试、按 asset_type 分套的 validate 样例参数，并接入远端 CI。

### 10. 平台能力未落地（P2 · 设计边界内）

| 能力 | 说明 |
|---|---|
| **fetch 审计** | 设计原则要求可回答「谁让 AI 查了哪台机器」；当前 fetch 无 query 审计落库 |
| **AccessPolicy / RBAC** | 已从资产 JSON 移除，另立文档；平台侧未实现 |
| **产品 UI** | 资产注册、bundle 勾选、连通性测试仍靠编辑 JSON + CLI |

---

## 四、可扩展性分析

| 要扩展什么 | 改哪里 | 难度 | 运营是否改 Python |
|---|---|---|---|
| 新 **SLS/ES** 资产（已有 asset_type） | connector + asset + template | **低** | ❌ |
| 新 **查询模板** | `templates.json` + asset `query_template_ids` | **低** | ❌ |
| 新 **asset_type** | schema + evidence-minimum-fields + scenarios + `FALLBACK` | **低–中** | ❌ |
| **JSON 新字段名** | `field_aliases` + 可能改模板查询字段 | **低** | ❌ |
| **内置文本**（auth/nginx） | asset `text_parser` 枚举 | **低** | ❌ |
| **自定义文本** | `parsers/<id>.json` + asset `text_parser` | **中** | ❌ |
| 新 **DB 引擎** | 已支持 MySQL/PostgreSQL/Oracle/SQL Server/SQLite；新增其它引擎走独立 fetch 文件 | **中** | ✅ 平台或插件 |
| 新 **connector 类型** | 配置型外置执行器 / 插件 / 核心内置三选一 | **低–高** | ❌（外置/插件）或 ✅（核心内置） |
| 凭证后端 | `vault.py` | 中 | ✅ 平台 |

**当前瓶颈**：

1. **运营数据**：active 20%，D2/WEB 占位 connector 阻塞晋升  
2. **taxonomy 半成品**：`dns_log` 等 enum 已开但无模板/资产  
3. **映射规模化**：per-asset 别名已支持；全局表仍大，可按 asset_type 拆文件（P3）  
4. **工程卫生**：需要更多负例 fixture、真实 vendor smoke test、远端 CI 矩阵和 fetch 审计  

---

## 四（补）、新源接入便利性评估（v3.0）

### 4.1 总评：★★★★☆（方便，但有「最后一公里」摩擦）

设计目标「**运营改 JSON，不改 Python**」在 **常见内置 connector + 外置执行器 + 插件** 上基本达成。当前接入入口为[完整接入流程](../../docs_user/03-configure-data-sources.zh-CN.md)，字段细节见[日志格式发现](../../docs_user/20-log-format-discovery.zh-CN.md)和[字段说明样例](../../docs_ai/asset-es-waf-prod-field-guide.zh-CN.md)。

| 阶段 | 便利性 | 说明 |
|---|---|---|
| 注册 connector + asset | ★★★★★ | JSON 模板 + Schema；`credentials_ref` 与 config 分离 |
| 格式发现（新 log） | ★★★★☆ | `discover.py` + log-format-discovery Skill；**须大模型审阅** |
| 写入映射/模板 | ★★★★☆ | `discover.py --apply` 写 aliases/parser/schema；**不写 correlation_keys** |
| 校验与晋升 | ★★★★☆ | `validate.py` + `test-connector.py` + `promote-after-connectivity.py` |
| 接入后 Skill 可用 | ★★★★☆ | `--from-bundle` 自动展开；需 `active` + 场景所需 asset_type |

### 4.2 按接入场景打分

| 场景 | 难度 | 典型步骤 | 样例资产 |
|---|---|---|---|
| **SLS/ES 结构化字段**（新 logstore，已知 `waf_alert` 等） | ⭐ 低 | connector → asset → `schema.fields` + aliases → 模板 → validate；不写 `text_parser` | `asset-waf-prod-01`、`asset-es-waf-prod` |
| **换 project/logstore**（同格式） | ⭐ 极低 | 只改 connector `config` + 必要时 aliases | 复制 active 资产改 ID |
| **SSH/local 内置文本** | ⭐ 低 | `text_parser: syslog_auth` / `nginx_combined` | `asset-ssh-web-01-file` |
| **MySQL/PG 结构化表** | ⭐ 低 | `database_ro` + SQL 模板 `:param` | `asset-cmdb-hosts`、`asset-pg-cmdb-hosts` |
| **全新文本行格式** | ⭐⭐ 中 | `parsers/*.json`（`line_regex`）+ 格式发现 | `parsers/iso_syslog_auth.json` |
| **全新 asset_type** | ⭐⭐ 中 | schema 枚举 + evidence-minimum-fields + scenarios + template fallback | NTA/Win/Linux 已示范 |
| **全新 connector 类型** | ⭐ 低（外置/插件）到 ⭐⭐⭐ 高（核心内置） | 外置执行器只加配置；插件加独立包；核心内置才改平台 fetch | `external_generic`、connector plugins、内置云厂商示例 |
| **HTTP API 型 WAF** | ⭐⭐ 中 | `http_api` + `waf_api_search` 模板；`asset-waf-api-prod` 仍在 discovery | 待格式发现出队 |

### 4.3 接入仍不顺的点

| 问题 | 影响 |
|---|---|
| **产品 UI 仍需打磨** | 已有 onboarding/credentials/validation 页面，但解释、预览、错误引导和截图教程仍需增强 |
| **taxonomy 半注册** | `ids_alert` / `edr_event` 等仍无模板可抄 |
| **双路径 SLS/ES** | 同 asset_type 两套资产，运营不知复制哪份 |
| **占位 connector** | 复制示例后忘记改 `YOUR_SLS_PROJECT`，promote 批量失败 |
| **bundle 与 status** | 接入期 bundle 仍为 active 时 validate 持续报错 |

### 4.4 让接入更顺的优化（建议）

| 优先级 | 项 |
|---|---|
| P1 | `discover.py --apply` | ✅ 见当前字段发现指南 |
| P1 | per-asset `field_aliases` | ✅ |
| P1 | 补全 `dns_log` + onboarding 三件套 | ✅ `dataasset/onboarding/` |
| P2 | FAQ **SLS vs ES 路径决策表**；bundle 接入期默认 `draft` |
| P2 | 产品 UI：向导式 connector → discovery → promote |

---

## 四（补2）、格式映射便利性评估（v3.0）

### 5.1 总评：★★★★☆（模型清晰，JSON 最顺，文本次之）

平台采用 **两层字段模型**，当前说明见[字段发现与归一化](../../docs_user/20-log-format-discovery.zh-CN.md)：

```text
查询层（template）  → 源字段名（ip、@timestamp、client_ip）
证据层（Skill）    → canonical（src_ip、timestamp、url…）
```

该拆分**降低**「能查到数但 Skill 字段为空」的故障，运营知道改哪一层；代价是**同一 canonical 可能对应多条别名路径**，需维护 discipline。

### 5.2 按格式类型的映射路径

| 日志格式 | 配置入口 | 是否改 Python | 便利度 | 说明 |
|---|---|---|---|---|
| **SLS/ES SDK 已展开的 JSON 字段** | 省略 `text_parser` + **`field_aliases`** | ❌ | ★★★★★ | 最常见；gateway `ip`→`src_ip` 即此路径 |
| **JSON / NDJSON + 字段内嵌 JSON object** | `text_parser: json_lines2` + **点号字段** + `field_aliases` | ❌ | ★★★★★ | 适合 `fields: "{...}"` 这类字段；展开为 `fields.user`、`fields.session.tty` |
| **syslog auth** | `text_parser: syslog_auth` | ❌ | ★★★★★ | 内置解析器，零 regex |
| **nginx combined** | `text_parser: nginx_combined` | ❌ | ★★★★★ | 内置 |
| **自定义文本** | `dataasset/parsers/<id>.json` + `line_regex` | ❌ | ★★★★☆ | 命名捕获组 → 键名；再经 aliases 对齐 canonical |
| **内联 regex** | `text_parser: { line_regex, ... }` | ❌ | ★★★☆☆ | 适合 PoC，不宜长期放 asset JSON |
| **DB 列名** | SQL 模板 `AS` 别名或 aliases | ❌ | ★★★★☆ | `:param` 绑定，列名在 SQL 中可控 |
| **ES 嵌套字段** | 模板 DSL 用源路径；aliases 拉平 | ❌ | ★★★☆☆ | 嵌套深时需格式发现 + 谨慎改 DSL |
| **全新二进制/EVTX** | 须先入 SLS/ES 为 JSON 或文本 | — | ★★☆☆☆ | 不直接 grep `.evtx`（设计已明确） |

内置解析器仅 **4 种**（[`text-log-parsers.json`](../../dataasset/configure/text-log-parsers.json)）；自定义 parser 仓库目前 **1 个**示例（`iso_syslog_auth.json`），文档足够但**样例偏少**。

### 5.3 映射机制优缺点

| 做得好的 | 仍别扭的 |
|---|---|
| 查询与证据分层，故障定位清晰 | 模板查询字段仍常硬编码源侧名，须与 aliases 同步改 |
| `discover.py --apply` 写 per-asset 别名 | 复杂 multiline / JSON 嵌套仍靠大模型 + 手工 regex |
| **correlation_keys 自动推导**，与 matrix 单一事实来源 | 新增 Join 时仍需治理 fetch_plan 覆盖率和 UI 预览 |
| `normalizer` 统一 evidence_id、时间 ISO、**time_correction**、masking | 跨源时钟偏差大时仍需源头 NTP + 手动扩取数窗 |

### 5.4 典型映射工作流（运营视角）

```text
样本日志
  → discover.py（结构探测 + 别名建议）
  → 大模型审阅（log-format-discovery）
  → ① evidence-minimum-fields.json  field_aliases
  → ② asset.json  text_parser + schema.fields
  → ③ templates.json  查询字段（源侧名！）
  → ④ parsers/*.json（仅非 JSON/非内置文本）
  → validate + test-connector + --preview-normalize
  → discovery → draft → active
```

**最少 touch 点**（JSON 新源、字段仅 rename）：**② aliases + ③ 模板** 两处。  
**最多 touch 点**（全新文本）：**①–④** 全开。

### 5.5 让映射更顺的优化（建议）

| 优先级 | 项 |
|---|---|
| P1 | **per-asset `field_aliases` 覆盖** | ✅ |
| P1 | discover **`--apply`** | ✅ |
| P1 | **correlation_keys 自动推导**（废弃手写） | ✅ 2026-06-25 |
| P2 | 模板 **字段 indirection**（模板引用 `connector.field_map` 而非硬编码 `src_ip`） |
| P2 | 扩充 **内置 parser** 或 grok 模式库（Windows Event、CEF、常见 WAF 厂商） |
| P3 | 别名表 **分域/分 asset_type** 拆文件，避免全局 JSON 无限膨胀 |

---

## 五、与实现的对照表

| 设计能力 | v2.2 | v2.3 | v2.5 | **v2.8** |
|---|---|---|---|---|
| 多源 live fetch | ✅ | ✅ | ✅ | ✅ |
| MySQL database_ro | ✅ | ✅ | ✅ | ✅ |
| PostgreSQL database_ro | ❌ | ✅ | ✅ | ✅ |
| ES fetch + es_query 模板 | ✅ | ✅ | ✅ | ✅ |
| evidence Normalizer | ✅ | ✅ | ✅ | ✅ |
| 多 connector 聚合 | ✅ | ✅ | ✅ | ✅ |
| catalog 自动扫描 | ✅ | ✅ | ✅ | ✅ |
| 日志格式发现 | ✅ | ✅ | ✅ | ✅ |
| 数据源接入 FAQ | ❌ | ✅ | ✅ | ✅ |
| asset_type：NTA / Win / Linux syslog | ❌ | ✅ | ✅ | ✅ |
| coverage hint 确定性匹配 | ❌ | ✅ | ✅ | ✅ |
| status/bundle 契约 | — | ✅ | ✅ | ✅ |
| **`dns_log` 端到端** | ❌ | ❌ | ✅ | ✅ |
| **correlation_engine + join_edges** | ❌ | ❌ | ❌ | **✅** |
| **correlation_keys 推导** | ❌ | ❌ | ❌ | **✅** |
| **time_correction** | ❌ | ❌ | ❌ | **✅** |
| **examples/reference-assets** | ❌ | ❌ | ❌ | **✅** |
| validate 0 error | ❌ | ❌ | ❌ | **✅** |
| fetch 按 correlation_fetch_plan | ❌ | ❌ | ❌ | **✅** |
| fetch 审计 | ❌ | ❌ | ❌ | ❌ |
| CI / release gate（validate + test + docs） | ❌ | ❌ | ❌ | **✅ 本地门禁；远端矩阵待补** |
| 产品 UI | ❌ | ❌ | ❌ | **✅ 基础可用；体验继续打磨** |

### 目录规模与占位符（2026-06-21）

| 类型 | 数量 | 备注 |
|---|---|---|
| assets | 24 | active **6** · draft 17 · discovery 1 |
| connectors | 21 | active **12** · draft 9；仍有示例占位符供私有部署替换 |
| bundles | 4 | active 3 · draft 1；active bundle 仍需关注 draft 成员冲突 |
| 单元测试入口 | 5 个测试文件 | 覆盖 docs links、release_scan、SecWeaver CLI、dataasset UI、report markdown |

---

## 六、优化建议（按优先级）

### P0 — 运营就绪（非代码）

| # | 项 | 说明 |
|---|---|---|
| 1 | **填真实 SLS project/logstore** | 优先 D2/WEB：`conn-sls-secweaver-host-events`、`web-access`、`host-connect` 等；真实配置不要进入公开仓 |
| 2 | **晋升 + bundle 发布** | 连通测试 → `promote-after-connectivity.py` → 成员全 active 后 bundle `active`（或接入期 bundle 改 `draft`） |
| 3 | **补 `dns_log` 或调场景** | S1 P1 需要 DNS；补模板+资产，或场景暂降级 |
| 4 | **discovery 出队** | `asset-waf-api-prod` 格式发现 → draft |

### P1 — 工程化

| # | 项 | 状态 |
|---|---|---|
| 5 | evidence Normalizer | ✅ |
| 6 | DB / HTTP / ES fetch | ✅ |
| 7 | PostgreSQL database_ro | ✅ |
| 8 | 防火墙仅 src_ip 模板 | ✅ |
| 9 | coverage hint 匹配 | ✅ |
| 10 | status / bundle 契约 | ✅ |
| 11 | 收紧 text_parser JSON Schema | ✅ 已通过 `not enum` 消除内置 parser oneOf 歧义 |
| 12 | **`dns_log` 模板 + evidence + 示例** | ✅ |
| 13 | masking / pii_fields 对齐 | ✅ 已收口（§三.3.2） |
| 14 | validate 样例 params 分 asset_type | 待做 |
| 15 | **发布门禁：validate + unittest + docs** | ✅ 本地 release_scan/docs-check 已有；远端 CI 矩阵待补 |
| 16 | `http_fetch` 定向单测 | 待做 |
| 17 | **discover `--apply`** | ✅ `discover_apply.py` + CLI |
| 18 | **per-asset `field_aliases`** | ✅ schema + `normalizer` |
| 19 | **dns_log 模板 + 示例 + onboarding 三件套** | ✅ `asset-dns-internal-prod` + `dataasset/onboarding/` |
| 20 | validate 样例 params 分 asset_type | 待做 |

### P2 — 产品化与体验

| # | 项 |
|---|---|
| 19 | 产品 UI：资产注册、凭证 ref、bundle 勾选、连通性测试继续产品化 |
| 20 | SOPS 多人 recipient / CI decrypt 文档 |
| 21 | SLS vs ES 接入路径决策表（FAQ） |
| 22 | 各 connector **最小三件套**复制模板 | 
| 23 | coverage.hosts IP-only 校验与 UI 提示 |
| 24 | asset/connector 版本字段 |
| 25 | connector `constraints` 分类型 schema |
| 26 | fetch 查询审计 |
| 27 | 内置 parser / grok 模式库扩充 |
| 28 | `json_lines2` 在 syslog-risk-json 等嵌套 JSON 日志中的应用指引 |

---

## 七、架构示意（v2.5）

```text
dataasset JSON ──► validate.py (+ JSON Schema, catalog sync)
                      │
                      ├──► template_select（按 connector_type 选 query 字段）
                      ├──► vault (SOPS)
                      ├──► fetch
                      │      ├── sls
                      │      ├── ssh_file / local_file
                      │      ├── database_ro (mysql │ postgresql)
                      │      ├── http_api
                      │      └── es (Elasticsearch _search)
                      ├──► aggregate（多 connector 去重）
                      ├──► normalizer（evidence_id, timestamp, alias, masking）
                      └──► Skill（完整性 / 溯源 / 告警 / 风险识别 --from-bundle）
```

---

## 八、总结

### 清楚吗？

**是。** 两层模型、多源 fetch、凭证分离、template 化查询、D1–D7 与 S1–S7 解耦、FAQ 补齐字段归一化，对安全运营与接入同学已可独立执行。

### 可扩展吗？

**taxonomy 与模板路径易扩展**（PG/ES/NTA 已验证）。**新 JSON 源接入成本低**；**新文本格式**靠 parsers 仍不需改 Python，但 regex 质量依赖人/模型。

### 接入新数据方便吗？（v3.0）

**同类多源、已知 asset_type：方便（★★★★☆）** — 复制三件套 + aliases/field_aliases + validate 即可。  
**全新格式/类型：中等（★★★☆☆）** — discovery + `--apply` 闭环有；`correlation_keys` 已自动推导。  
**全新 connector 类型：外置/插件方便，核心内置中等偏高** — 外置执行器只加配置，插件不改核心；只有要并入核心维护时才改平台代码。

### 不同格式映射方便吗？（v3.0）

**JSON：最方便（★★★★★）** — `json_lines` / `json_lines2` + 全局 / per-asset `field_aliases`。  
**内置文本：方便（★★★★★）** — 改 `text_parser` 枚举。  
**自定义文本：较方便（★★★★☆）** — `parsers/*.json`，不用改 Python。  
**跨源关联：较方便（★★★★☆）** — matrix 单一事实来源 + 引擎；资产只维护 `fields` + 别名。  
**复杂嵌套 / 时钟偏差：别扭（★★★☆☆）** — 靠 `time_correction` 与人工扩窗过渡。

### 最大优化点（Top 5，v3.0）

1. **运营闭环** — 填 SLS 真实 project → 晋升 D2/WEB → bundle 与 validate 自洽。  
2. **fetch 链路治理** — `fetch.py` 已消费 `correlation_fetch_plan`；继续补 coverage summary、UI 预览和审计。  
3. **Schema 快速赢** — 已消除 `text_parser` oneOf 歧义；继续收紧 catalog、connector constraints 与示例状态。  
4. **字段参考维护** — evidence/matrix 变更后跑 `build-field-reference.py`。  
5. **产品 UI** — 向导式 connector → discovery → promote。

### 仍值得做、但不阻塞联调

- SLS vs ES 双路径 FAQ（§三.8）  
- `pii_fields` 与 `masking` 职责合并（§三.3.2）  
- `promote-after-connectivity` 扩展 asset_type  
- connector `bastion_id` 引用校验  

---

## 九、与设计文档的交叉引用

主设计文档 [数据源资产设计.md](../09-data-asset-design.zh-CN.md) 已进入新口径：资产侧主机绑定字段下线，主机覆盖以 `coverage.hosts` 来源 IP 为准；新增 `syslog_risk_alert` 和 `json_lines2` 解析器说明；fetch 按 plan 拉数已进入主路径，后续重点是覆盖率治理和 UI 解释。

关联矩阵专项见 [correlation-matrix设计评估.md](22-correlation-matrix-design-evaluation.zh-CN.md)。

---

## 十、问题清单（速查，v3.0）

| 类别 | 问题 | 优先级 |
|---|---|---|
| 运营 | 7× SLS `YOUR_SLS_PROJECT`、bundle active 与 draft 冲突 | P0 |
| 运营 | 三默认 bundle 完整性 `not_traceable` | P0 |
| **接入** | discover 产出需人工改 3–4 文件，无 `--apply` | ✅ 已做 |
| **映射** | `field_aliases` 仅全局 | ✅ per-asset 已支持 |
| **关联键** | 资产内手写 `correlation_keys` 与 matrix 重复 | ✅ 自动推导 |
| Schema | `text_parser` oneOf 9 error、`environment: lab` 1 error | ✅ `text_parser` 已修；示例枚举/catalog 清理继续跟进 |
| Taxonomy | `dns_log` 无模板/资产/evidence | ✅ |
| 工程 | 远端 CI 矩阵、http_fetch 定向测试、matrix 负例 fixture 不足 | P1–P2 |
| 关联 | fetch_plan 覆盖率摘要、复杂横向 BFS 全 matrix 化不足 | P1–P2 |
| 文档/运营 | SLS vs ES 双路径易混 | P2 |
| 平台 | UI 需继续产品化、无 fetch 审计 | P2 |
| 已解决 | status/bundle、coverage hint、多源 fetch、FAQ Q3、config 驱动 parser、correlation_engine、correlation_keys 推导 | ✅ |

---

## 十一、接入 vs 映射 — 一句话对照

| 问题 | 结论 |
|---|---|
| **接入新数据方便吗？** | **方便**（已有 connector + 已知 type）；**中等**（全新格式/类型）；**外置/插件方便、核心内置中等偏高**（新 connector 类型） |
| **不同格式映射方便吗？** | **JSON/内置文本最方便**；**自定义文本**靠 parsers 仍零 Python；**复杂嵌套/跨源冲突**是主要摩擦 |
| **谁改 Python？** | 运营 **不改**；外置/插件 connector 不改核心；只有新核心内置 connector 或新 DB 引擎需平台改 fetch |
| **必读文档** | [完整接入](../../docs_user/03-configure-data-sources.zh-CN.md)、[字段发现与归一化](../../docs_user/20-log-format-discovery.zh-CN.md)、[字段说明样例](../../docs_ai/asset-es-waf-prod-field-guide.zh-CN.md)、[字段参考](../../dataasset/examples/reference-assets.json) |

---

*文档版本：v2.8 | 第十次评估：2026-06-25 | 增量：correlation_engine、correlation_keys 推导、time_correction、reference-assets*

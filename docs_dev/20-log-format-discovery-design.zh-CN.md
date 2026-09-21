# 日志格式发现设计

**语言：** [English](20-log-format-discovery-design.md) | 简体中文（本文）

> SecWeaver **大模型驱动** Skill：**新 log 类型接入前的格式分析与字段映射**  
> 实现目录：[`src/skills/log-format-discovery/`](../src/skills/log-format-discovery/)  
> 版本：1.1

**本文范围**：格式发现 Skill 的目标、架构、人机分工、报告 schema、与 dataasset / normalizer 的衔接。  
**不在本文范围**：运行时 fetch、多 connector 聚合、Skill 研判逻辑（见 [数据源资产设计.md](09-data-asset-design.zh-CN.md)、[Agent采集与Evidence规范.md](12-agent-collection-and-evidence-spec.zh-CN.md)）。

**相关文档**：

| 文档 | 说明 |
|---|---|
| [日志格式发现.md](../docs_user/20-log-format-discovery.zh-CN.md) | Skill 使用说明（对话框 / 工作流） |
| [SKILL.md](../src/skills/log-format-discovery/SKILL.md) | Agent 操作手册（何时用、命令、落地清单） |
| [reference.md](../src/skills/log-format-discovery/reference.md) | 规范对照、别名规则、文件路径速查 |
| [examples.md](../src/skills/log-format-discovery/examples.md) | auth / WAF / 未知格式端到端示例 |
| [output-schema.json](../src/skills/log-format-discovery/output-schema.json) | Agent 映射输出 JSON Schema |
| [数据源资产设计.md §Normalizer](09-data-asset-design.zh-CN.md) | 运行时归一化职责 |
| [Agent采集与Evidence规范.md §1.9](12-agent-collection-and-evidence-spec.zh-CN.md) | 平台接入流程中的位置 |

---

## 一、设计目标

### 1.1 要解决什么问题

| 缺口 | 后果 |
|---|---|
| 新日志格式字段名各异（`client_ip` vs `remote_addr`） | Skill 无法跨源关联、完整性分析误判 |
| 接入前无统一流程 | 每人手写 parser、重复踩坑、缺 validate |
| 「让 LLM 直接读 raw」与「先 normalize」争论无据 | 架构漂移，审计与 masking 失效 |
| text 日志（auth/nginx/自定义）需 regex | 缺样本驱动的 gap 分析与映射草案 |

### 1.2 设计原则

```text
1. 大模型必需：字段语义映射、未知格式 parser、correlation_keys 由 Cursor Agent（LLM）完成
2. 脚本辅助：discover.py 做格式检测 / 键统计 / gap，为大模型提供结构化上下文（不接生产、不替代 LLM）
3. normalize 优先：映射结果写入 evidence-minimum-fields + normalizer，运行时不再用 LLM 逐行解析
4. 与现有 dataasset 模型对齐：产出直接对应 asset / connector / template / schema 文件
5. 可审计：报告 JSON + output-schema 留痕，用户确认后再改仓库
6. 安全：样本与报告含敏感信息时不提交 Git；模板草案不含密钥
```

### 1.2.1 为何「依赖大模型」但 `discover.py` 不调 LLM API？

| 问题 | 说明 |
|---|---|
| 本 Skill 是否依赖大模型？ | **是**。仅跑脚本不算完成；Step 3 必须由 Agent 产出映射 JSON |
| 大模型在哪执行？ | Cursor 对话中的 Agent（即 LLM），消费 `llm_prompt` + 报告 + 样本 |
| 为何脚本不调 API？ | Agent 已是 LLM 运行时；脚本负责确定性预处理，避免重复接密钥、便于 CI 回归格式检测 |
| 与运行时 LLM 解析 raw 有何不同？ | 格式发现是**一次性接入**设计；fetch 阶段走确定性 normalizer，不对每条 log 调 LLM |

### 1.3 在平台中的位置

```text
┌─────────────────────────────────────────────────────────────┐
│  运营 / 开发：样本日志（文件、粘贴、导出 JSONL）              │
└────────────────────────────┬────────────────────────────────┘
                             ▼
┌─────────────────────────────────────────────────────────────┐
│  log-format-discovery（本 Skill）                             │
│  discover.py → 格式检测 / gap / llm_prompt（预处理）          │
│  Cursor Agent（大模型）→ 字段映射 / parser / template 设计    │
│  Agent + 用户确认 → evidence / normalizer / asset 落地       │
└────────────────────────────┬────────────────────────────────┘
                             ▼
┌─────────────────────────────────────────────────────────────┐
│  dataasset/（注册）+ validate.py + test_connector.py         │
└────────────────────────────┬────────────────────────────────┘
                             ▼
┌─────────────────────────────────────────────────────────────┐
│  数据访问层 fetch → normalizer → evidence_bundles → Skill    │
└─────────────────────────────────────────────────────────────┘
```

**与 normalize vs LLM 的关系**：

| 阶段 | 执行者 | 输入 | 输出 |
|---|---|---|---|
| 格式发现（接入前） | discover.py + **大模型（Agent）** | 样本 raw | 映射草案、parser 设计、可落地配置 |
| 运行时 normalize | `normalizer.py` | fetch 原始 event | canonical + evidence_id + masking |
| 研判语义 | 下游 Skill + LLM | normalized events | 误报/溯源结论 |

保留 `raw_line` 仅作**可选**语义补充，不作为 Skill 主输入。

---

## 二、架构

### 2.1 组件

```text
src/skills/log-format-discovery/
├── SKILL.md                 # Agent 触发与工作流
├── reference.md             # 规范对照
├── examples.md              # 用例
├── output-schema.json       # Agent 输出契约
├── scripts/discover.py      # 预处理引擎（为大模型准备报告与 llm_prompt）
├── scripts/discover_apply.py # 经校验、受写锁保护的目录应用边界
└── samples/                 # 可提交的脱敏样例

docs_dev/20-log-format-discovery-design.md     # 本文（设计文档）
```

| 组件 | 职责 |
|---|---|
| `discover.py` | 读样本；读 **dataasset/**（evidence 规范、peer assets、templates）；gap；`llm_prompt` |
| `discover_apply.py` | 要求同一 discovery Asset，先构造全部变更并校验可用 Schema，再在共享目录写锁内写入 |
| **Cursor Agent（LLM）** | **必需**：对照 dataasset 已有注册 + 样本，产出映射与落地 diff |
| `SKILL.md` | 教 Agent 何时跑脚本、**如何调用大模型完成映射**、落地哪些文件 |
| `output-schema.json` | Agent 映射方案的 JSON 结构约束 |
| `evidence-minimum-fields.json` | 规范源：required 字段、已有 `field_aliases` |
| `normalizer.py` / `ssh_fetch.py` | 运行时执行映射与 text 解析 |

### 2.2 人机分工

```text
┌──────────────┐     ┌──────────────────┐     ┌──────────────┐
│ discover.py  │ ──▶ │ Cursor Agent     │ ──▶ │ 仓库改动     │
│ （预处理）    │     │ （大模型·必需）   │     │ （经用户确认）│
└──────────────┘     └──────────────────┘     └──────────────┘
       │                     │                     │
       ▼                     ▼                     ▼
  detected_format      语义字段映射           field_aliases
  key_counts           regex / parser 设计     ssh_fetch 扩展
  gap_analysis         correlation_keys        asset/connector
  llm_prompt           confidence / 待确认项    templates.json
```

**预处理不做的事**：不替代大模型做语义映射、不解密 Vault、不 fetch 生产、不写配置。
显式 `--apply` 路径只通过 `discover_apply.py` 写入已审阅的 mapping；它拒绝非 discovery 目标，
并在首次替换文件前校验所有已构造对象。

apply 对每个 JSON 文件使用原子替换，后续写入抛出异常时会恢复之前已替换的对象。
该保证在共享写锁内覆盖普通异常，但不是跨文件的文件系统事务；进程或主机在替换间被强制
终止时无法自动回滚。

**大模型必须做的事**：对照样本与 evidence 规范完成映射；标注 confidence；列出 open_questions；用户确认后再由 Agent 改仓库。

### 2.3 格式检测（discover.py）

| `detected_format` | 判定依据 | 预览解析 |
|---|---|---|
| `json_lines` | 多数行可 `json.loads` 为 object | 键频统计 + 别名推断 |
| `syslog_auth` | 匹配 sshd auth 行头 | 配置 `text_parser: syslog_auth` |
| `nginx_combined` | 匹配 combined log | 配置 `text_parser: nginx_combined` |
| `text_unknown` | 以上均不满足 | `raw_line` + 简单 `key=value` 提取 |
| `empty` | 无有效样本 | 报错退出 |

检测基于**前 N 行抽样**（默认 ≤50），样本应 ≥3 行且覆盖变体（成功/失败、不同键名）。

---

## 三、数据流与报告 Schema

### 3.1 输入

| 参数 | 必填 | 说明 |
|---|---|---|
| `--asset-id` | 是* | dataasset 资产 ID，**必须** `status=discovery` |
| `--list-discovery` | 否 | 列出发现队列后退出 |
| `-i` / stdin / `--text` | 三选一 | 样本日志 |

\* 与 `--list-discovery` 二选一。

`asset_type`、`connector_type` 从 discovery 资产及其 connector **自动推导**，无需 CLI 指定。

### 3.1.1 dataasset 读取范围

| 范围 | 是否加载 |
|---|---|
| `assets/{asset_id}.json` 且 `status=discovery` | **是**（唯一处理对象） |
| 同 asset_type 的 draft/active 资产 | **否** |
| 绑定 connector | 是（只读 connector_type） |
| `configure/evidence-minimum-fields.json` | 是 |
| `query-templates/templates.json` | 是（匹配 asset_type + connector_type） |

### 3.2 报告核心字段

| 字段 | 含义 |
|---|---|
| `detected_format` | 格式分类 |
| `dataasset_context.discovery_asset` | 当前 discovery 队列资产 |
| `discovery_asset_hints` | 该资产已有 fields / template_ids |
| `requirements` | 来自 `evidence-minimum-fields.json` 的 required / recommended |
| `observed_json_keys` | JSON 样本中的键及出现次数 |
| `applicable_existing_aliases` | 样本键中已被全局 `field_aliases` 覆盖的部分 |
| `proposed_field_aliases` | 脚本建议的**新增**别名（source → canonical） |
| `gap_analysis` | 映射预览后仍缺的 canonical 字段 |
| `preview_events` | 最多 5 条解析预览（未写库） |
| `proposed_template_hint` | 按 connector_type 的模板建议 |
| `llm_prompt` | 给 Agent 的结构化任务文本 |
| `implementation_checklist` | 默认落地步骤 |
| `llm_review_required` | gap 缺 required 时为 true |

可选：`--preview-normalize` 时对 preview 调用 `normalizer.py` 做运行时预览。

### 3.3 Agent / 大模型输出（output-schema.json）

**本步为 Skill 核心产出**，不可跳过。Agent 审阅后产出单个 JSON，至少包含：

- `proposed_field_aliases`
- `proposed_asset_schema`（fields、correlation_keys、time_field）
- `proposed_normalizer`（`aliases_only` | `extend_parser` | `new_parser`）
- `proposed_query_template`
- `implementation_checklist`
- `confidence`（high / medium / low）

详见 [output-schema.json](../src/skills/log-format-discovery/output-schema.json)。
`proposed_template_hint.existing_templates_in_dataasset` 是供审阅的候选列表。只有
`proposed_query_template` 下一个已审阅对象可进入 apply 边界，候选列表不会合并进模板目录。

---

## 四、落地映射

### 4.1 按格式的改动路径

| detected_format | 运营配置 | 说明 |
|---|---|---|
| `json_lines` | `text_parser: json_lines` + `field_aliases` | 不改代码 |
| `syslog_auth` | `text_parser: syslog_auth` | 内置 |
| `nginx_combined` | `text_parser: nginx_combined` | 内置 |
| `text_unknown` | `dataasset/parsers/*.json` | 自定义 regex JSON |

### 4.2 field_aliases 策略

- **全局别名**：写入 `dataasset/configure/evidence-minimum-fields.json` → 所有 asset 共享
- **canonical 命名**：与 `by_asset_type.*.required` 一致（如 `src_ip` 而非 `client_ip`）
- **运行时**：`normalizer.py` 在 fetch 后应用别名；`evidence_id` 由 normalizer 生成，gap 中可忽略

### 4.3 验证闭环

```bash
python3 src/dataasset/validate.py --sync-catalog
python3 src/dataasset/test_connector.py <asset_id> --by-asset --plan --dry-run
python3 src/dataasset/test_connector.py <asset_id> --by-asset --params '{...}'
```

---

## 五、CLI 参考

开源推荐入口（封装 `discover.py`，默认 `--pretty --preview-normalize`）：

```bash
python3 src/secweaver.py asset discover-format asset-waf-api-prod \
  -i examples/log-format-discovery/waf-jsonl.sample
```

底层脚本（队列查看、报告导出、LLM prompt 等完整参数）：

```bash
python3 src/skills/log-format-discovery/scripts/discover.py --list-discovery

python3 src/skills/log-format-discovery/scripts/discover.py \
  --asset-id asset-waf-api-prod \
  [-i sample.log | --text "..." | stdin] \
  [-o report.json] [--prompt prompt.md] [--preview-normalize] [--pretty]
```

---

## 六、安全与合规

| 项 | 要求 |
|---|---|
| 样本 | 尽量脱敏；含生产 IP/账号的样本勿提交仓库 |
| 报告 / prompt | 本地使用；`-o` 输出勿进 Git |
| 模板草案 | 不得含 password、access_key、私钥 |
| masking | Agent 输出应建议 `payload`/`command` 等 truncate 或 redact |

---

## 七、非目标与后续扩展

**当前非目标**：

- 在 `discover.py` 内嵌 OpenAI/Anthropic API 调用（大模型由 Cursor Agent 承担；后续可加可选 `--llm-api`）
- 自动 PR / 自动改仓库（须大模型 + 用户确认）
- 生产 log 自动采样（用 `test_connector.py`）
- 运行时 fetch 阶段用 LLM 逐行解析 raw（与 normalize 架构相反）

**可扩展方向**（未实现）：

- 多样本文件批量对比、键名漂移检测
- 与 `validate.py` 集成 `--discover` 子命令
- 报告 diff：同一 asset 新旧样本格式变更告警
- 单元测试：`tests/test_discover.py` 覆盖格式检测与 gap

---

## 八、文档分工速查

| 读者需求 | 读哪份 |
|---|---|
| 为什么做、架构、人机分工 | **本文** |
| 对话框怎么用、步骤概览 | [日志格式发现.md](../docs_user/20-log-format-discovery.zh-CN.md) |
| Agent 怎么跑、命令与清单 | [SKILL.md](../src/skills/log-format-discovery/SKILL.md) |
| 文件路径、别名规则 | [reference.md](../src/skills/log-format-discovery/reference.md) |
| 复制即用的例子 | [examples.md](../src/skills/log-format-discovery/examples.md) |
| 新数据源完整接入生命周期 | [如何配置数据源](../docs_user/03-configure-data-sources.zh-CN.md) |
| 字段发现和归一化操作 | [日志格式发现](../docs_user/20-log-format-discovery.zh-CN.md) |

# 日志格式发现

**语言：** [English](20-log-format-discovery.md) | 简体中文（本文）

> SecWeaver Skill 文档
> 用途：处理 dataasset 中 **`status: discovery`** 的数据源，完成字段映射后把 draft Asset 交回接入验收流程
> Agent Skill：`src/skills/log-format-discovery/SKILL.md`  
> 脚本：`src/skills/log-format-discovery/scripts/discover.py`

---

## 首次使用：只预览，不改资产

先完成 `make quickstart`，并使用公开默认 `dataasset`。仓库已经包含
`status=discovery` 的 `asset-waf-api-prod`，无需先手写 Asset：

```bash
.venv/bin/python src/secweaver.py asset discover-format asset-waf-api-prod \
  -i examples/log-format-discovery/waf-jsonl.sample
```

固定样例预期 `detected_format=json_lines`、`sample_count=2`。
检查 `proposed_field_aliases`、`gap_analysis` 和 `normalized_preview`，
尤其核对不同来源的时间字段，不能仅凭格式识别成功就把资产设为 active。
该命令输出 JSON，不访问在线数据，也不写回配置。

在 智能体中可输入：

```text
使用 log-format-discovery 分析 asset-waf-api-prod，
离线样本为 examples/log-format-discovery/waf-jsonl.sample。
解释字段映射、时间格式和证据缺口，仅提出变更建议，不修改资产。
```

真实日志先脱敏、确认只处理 discovery 资产，再由用户批准写回。
字段不足时保留 draft/discovery，补齐样本和查询验收，不编造字段或生产凭证。
下面的 JSON 是字段结构片段；创建新资产应使用接入向导或完整 Schema，而不是原样替换整个文件。

## 一、技能定位

本 Skill **只处理** dataasset 发现队列中的数据源（`status: discovery`）。  
已处于 `draft` / `active` / `disabled` 的资产**不需要**也**不应**走格式发现。

### 1.1 状态流转

```text
新建 asset（status=discovery）
        ↓
log-format-discovery（discover.py + 大模型）
        ↓
更新 schema / 别名 / parser，status=draft
        ↓
返回接入流程：validate + 真实查询验收
        ↓
只有验收通过后才能 status=active
```

### 1.2 大模型角色

| 环节 | 执行者 |
|---|---|
| 加载 discovery 资产、样本分析、gap | `discover.py` |
| 字段映射、parser 设计 | **智能体（大模型）** |
| 写回 dataasset、改 status | 智能体 + 用户确认 |

---

## 二、使用方式

### 2.1 注册 discovery 资产

在 `dataasset/assets/` 新建或修改资产：

```json
{
  "asset_id": "asset-waf-api-prod",
  "status": "discovery",
  "connector_id": "conn-http-waf-api",
  "asset_type": "waf_alert",
  "schema": {
    "fields": ["src_ip", "timestamp", "url"],
    "correlation_keys": [],
    "time_field": "timestamp",
    "retention_days": 30
  }
}
```

`schema.fields` 可为占位；格式发现完成后由大模型补全。

### 2.2 查看队列

```bash
.venv/bin/python src/skills/log-format-discovery/scripts/discover.py --list-discovery
```

### 2.3 运行格式发现

推荐经 CLI（离线样本无需凭证）：

```bash
.venv/bin/python src/secweaver.py asset discover-format asset-waf-api-prod \
  -i examples/log-format-discovery/waf-jsonl.sample
```

需要 `--prompt`、`-o` 等参数时，使用底层脚本：

```bash
.venv/bin/python src/skills/log-format-discovery/scripts/discover.py \
  --asset-id asset-waf-api-prod \
  -i samples.jsonl \
  --pretty --prompt /tmp/prompt.md
```

### 2.4 发现完成后交回接入流程

1. 大模型确认映射，更新 `dataasset/assets/{asset_id}.json`
2. 设置 `"status": "draft"` 并运行 `validate.py`
3. 回到[数据源接入](03-configure-data-sources.zh-CN.md#6-校验实查和启用)完成真实查询验收
4. 验收通过后才设为 `"status": "active"`，再加入已验证 Bundle

---

## 字段发现与归一化模型

字段发现需要分别回答三个问题：源数据实际有哪些字段、上游可以查询哪些字段、
取回的事件如何变成规范证据。不能把这三层合并成一个字段列表。

### 3.1 区分查询字段和规范证据字段

| 层次 | 使用方 | 字段名称 | 配置位置 |
|---|---|---|---|
| 查询层 | SLS、ES、数据库或文件取数 | 上游真实字段或索引列名 | 查询模板的 `sls_query`、`es_query`、`sql` 或文件参数 |
| 解析层 | 原始文本或内嵌 JSON 提取 | parser 输出键 | Asset 的 `text_parser` 与 `dataasset/parsers/*.json` |
| 证据层 | 完整性和调查 Skills | `src_ip`、`timestamp`、`host`、`command` 等规范字段 | Asset 的 `field_aliases`；全局别名只用于通用映射 |

```text
调查参数使用规范字段：src_ip
    -> 查询模板使用源字段：client_ip:{src_ip}
    -> fetch 返回 client_ip
    -> 原始文本需要时先运行 parser
    -> field_aliases 把 client_ip 复制为 src_ip
    -> 规范化证据进入 Skills
```

查询模板必须使用上游真实可检索字段。别名在取数后生效，不能让上游不存在的字段变得可查询。

### 3.2 检查代表性样本并选择 parser

条件允许时至少使用三条脱敏样本，并覆盖时间格式变化和可选字段。先判断 Connector
返回的行是否已经结构化：

| 样本形态 | 配置方式 |
|---|---|
| SLS/ES/SDK 已把业务字段放在顶层 | 不设置 `text_parser`，只配置别名 |
| 某个字段包含完整 JSON 字符串 | 使用 `json_lines` 或 `json_lines2`，再配置别名 |
| Linux auth.log 或 secure 文本 | 使用 `syslog_auth` |
| Nginx combined access 文本 | 使用 `nginx_combined` |
| 无法识别的新文本格式 | 新增审阅后的 `dataasset/parsers/<id>.json` 并引用该 ID |
| 不应推断结构 | 使用 `raw_only`；该 Asset 暂不能支持依赖字段的调查 |

不能只根据日志生产端是否输出 JSON 决定 `text_parser`，应以 Connector 实际返回结果为准。
parser 选择不会关闭别名、时间归一化、脱敏或 trace profile。

### 3.3 声明原始字段和审阅后的别名

`schema.fields` 描述取回行或 parser 输出中直接可见的键；`field_aliases` 把源字段
映射为规范证据字段：

```json
{
  "schema": {
    "fields": ["remote_addr", "request_uri", "status", "time_iso8601"],
    "time_field": "timestamp",
    "retention_days": 30
  },
  "field_aliases": {
    "remote_addr": "src_ip",
    "request_uri": "url",
    "time_iso8601": "timestamp"
  }
}
```

优先使用 Asset 级别名，因为同一个源字段名在不同产品中可能含义不同。只有映射含义通用、
歧义很低时，才加入 `configure/evidence-minimum-fields.json` 的全局别名。规范字段已存在时
别名不会覆盖它；源字段会保留用于排错。

常见不匹配现象：

| 现象 | 可能所在层 | 处理方式 |
|---|---|---|
| 上游提示列不存在或始终返回空 | 查询模板使用了上游未建立索引的规范字段 | 查询改用真实源字段，参数继续使用规范字段 |
| 已取回数据，但 `src_ip` 等规范字段为空 | 别名缺失或方向写反 | 增加“源字段 → 规范字段”的 `field_aliases` |
| 文本行没有可用键 | 解析层 | 选择内置 parser，或增加审阅后的自定义 parser |
| 完整性检查提示必需字段不可达 | Schema/别名链 | 声明原始字段，并添加能够派生规范字段的别名 |
| 时间错误或不一致 | 时间字段/parser/别名 | 确认真实源时间，映射到 `timestamp` 并验证时区转换 |

客户端 IP、代理 IP、主机 IP 和目的 IP 即使值的形态相似，也不能直接视为同一含义；
有歧义的映射必须经过领域审阅。

### 3.4 预览并应用发现结果

发现报告会提出 `field_aliases`、Asset schema、parser 策略、查询模板和脱敏建议。
运行脚本不等于完成发现；写入前必须根据源文档和样本审阅建议。

```bash
# 预览启发式变更，不写文件
.venv/bin/python src/skills/log-format-discovery/scripts/discover.py \
  --asset-id asset-my-new-log -i samples.jsonl --apply --apply-dry-run

# 预览经过智能体和运营人员审阅的 mapping
.venv/bin/python src/skills/log-format-discovery/scripts/discover.py \
  --asset-id asset-my-new-log -i samples.jsonl \
  --apply /path/to/mapping.json --apply-dry-run

# 应用审阅后的 mapping；默认将 discovery 晋升为 draft
.venv/bin/python src/skills/log-format-discovery/scripts/discover.py \
  --asset-id asset-my-new-log -i samples.jsonl \
  --apply /path/to/mapping.json
```

mapping 文件必须包含相同的 `asset_id`。`--apply` 可能更新 Asset schema、
`query_template_ids`、`text_parser`、脱敏和 Asset 级别名，也可能合并建议的查询模板。
审阅未完成时使用 `--no-promote-draft`；只有确认映射适用于全部 Asset 时才使用
`--global-aliases`。
`proposed_template_hint` 中列出的已有模板只是审阅候选，apply 不会把该列表当作新模板。
需要新增或更新模板时，已审阅 mapping 可在 `proposed_query_template` 中提供一个对象。

apply 只接受同一个 `status=discovery` Asset。它会先在内存中构造 Asset 和模板变更，
校验所有可用 JSON Schema，然后在共享 DataAsset 写锁内原子替换文件。映射不合法、
目标已是 active/draft，或 Schema 校验失败时，不会修改目录对象。所选目录包含这些
Schema 时，`jsonschema` 是必需运行依赖。每个文件使用原子替换；后续替换发生普通写入
异常时，命令会在失败前恢复已替换的对象。

### 3.5 启用前验证字段

先预览规范化事件、校验目录，再查询一条已知事件：

```bash
.venv/bin/python src/skills/log-format-discovery/scripts/discover.py \
  --asset-id asset-my-new-log -i samples.jsonl --preview-normalize --pretty
.venv/bin/python src/dataasset/validate.py --sync-catalog
.venv/bin/python src/dataasset/test_connector.py asset-my-new-log --by-asset \
  --params '{"src_ip":"203.0.113.10","time_start":"2026-09-08T00:00:00Z","time_end":"2026-09-08T00:05:00Z"}'
```

确认原始源字段有值、规范化后的必需字段存在、查询过滤使用源字段、事件时间正确、
脱敏合适，并且跨源关联键没有改变原含义。随后回到[完整接入流程](03-configure-data-sources.zh-CN.md#完整接入流程)
完成启用。校验或真实查询验收失败时按[日常运营检查与排错](09-operations-troubleshooting.zh-CN.md)
处理。

### 3.6 运行时行为

配置完成后，运行时归一化是自动且确定性的：

```text
registry -> 查询模板 -> 凭证 -> fetch -> 文本解析
    -> 时间归一化 -> 字段别名 -> 脱敏 -> evidence_id -> Skill
```

运行时不会为每条原始事件调用大模型。智能体参与可审阅的发现阶段，下游 Skill 对
规范化证据进行推理。

---

## 四、与 dataasset 的关系

| dataasset 路径 | 本 Skill 如何使用 |
|---|---|
| `assets/*.json`（`status=discovery`） | **唯一处理对象** |
| `connectors/*.json` | 读取 connector_type，不修改其他连接器 |
| `configure/evidence-minimum-fields.json` | gap 对照、别名建议 |
| `query-templates/templates.json` | 列出可复用模板 |

**不读取** draft/active/disabled 资产作为对照。

---

## 五、相关文件

| 文件 | 说明 |
|---|---|
| [如何配置数据源](03-configure-data-sources.zh-CN.md) | 完整接入与启用流程 |
| [日常运营检查与排错](09-operations-troubleshooting.zh-CN.md) | 校验和真实查询排错 |
| [数据源接入 FAQ](16-data-source-onboarding-faq.zh-CN.md) | 短问答和导航 |
| [日志格式发现设计.md](../docs_dev/20-log-format-discovery-design.zh-CN.md) | 架构与设计 |
| `src/skills/log-format-discovery/SKILL.md` | Agent 执行入口 |
| `dataasset/schema/data-asset.schema.json` | `status` 含 `discovery` |
| `dataasset/assets/asset-waf-api-prod.json` | 示例 discovery 资产 |

---

*文档版本：v1.1 | 更新日期：2026-06-21*

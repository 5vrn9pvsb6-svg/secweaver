# 数据资产对象模型设计评估：Assets / Connectors / Hosts / Networks

> **文档状态：历史评估记录（截至 2026-06-30）。** 本文保留当时的设计建议；待办不代表当前未实现。当前字段规范见[资产设计](../09-data-asset-design.zh-CN.md)，关联行为见[跨源字段关联](../../docs_user/21-cross-source-field-correlation.zh-CN.md)。

**语言：** [English](11-data-object-model-evaluation.md) | 简体中文（本文）

更新时间：2026-06-30

> 示例说明：本文中的主机名、资产标识和网络分组均为虚构示例；IP 地址使用文档示例网段。接入时默认在 `dataasset/` 中配置实际值，也可复制到 `dataasset_my/` 隔离使用；客户配置不要提交公开仓库。

## 1. 最新结论

当前对象模型继续采用四层分工：

- `assets`：描述数据源语义、字段、查询模板、文本解析器和覆盖来源。
- `connectors`：描述取数路径、连接配置和凭证引用。
- `hosts`：描述主机身份、主地址、别名、网络归属和暴露面。
- `networks`：描述网段、逻辑区域、网络类型和信任等级。

为避免主机关联语义混淆，`host_binding` 暂时从资产模型中去除。后续主机关系只保留两条清晰路径：

```text
asset.coverage.hosts：日志来源 IP 数组，只放实际来源 IP。
connector.config.host_id：可选，仅用于单主机 connector 标注物理采集目标。
```

统一口径如下：

```text
host.host_ip：主机主地址，必须尽量是 IP。
host.aliases：主机别名、历史名、FQDN、日志中可能出现的 host_name 值。
host.interfaces：可选，多网卡/多地址场景才填写。
asset.coverage.hosts：只放日志来源 IP，不放 aliases/hostname。
host_binding：暂时去除，避免与 coverage.hosts、aliases、host_field 混淆。
```

近期格式与类型扩展也已收口：

```text
asset_type: syslog_risk_alert：用于 syslog-risk-json 结构化风险报警日志。
asset-secweaver-sys-risk-alert：系统风险报警日志的示例资产 ID。
text_parser: json_lines2：用于每行 JSON 且字段值内嵌 JSON object 的日志，展开为 xxx.xx 点号字段。
```

## 2. 为什么先去除 host_binding

原先 `host_binding` 同时承担两种职责：

- `single`：资产绑定某个 `host_id`。
- `aggregated`：资产声明行级主机字段 `host_field`。

这容易和以下字段混淆：

- `coverage.hosts`：到底是主机名、IP，还是覆盖范围？
- `host.aliases`：是否可以拿来匹配 coverage？
- `schema.fields`：字段存在是否就代表可用于主机关联？
- SLS `__source__` / `__tag__:__client_ip__`：是日志来源、客户端 IP，还是事件主机？

现在先去除 `host_binding`，模型更容易解释：

```text
资产是否覆盖某台日志来源主机，只看 asset.coverage.hosts 中的来源 IP。
单主机采集目标，如果需要表达，只在 connector.config.host_id 中表达。
行级事件主机字段暂不在资产模型中单独声明，由 schema.fields、field_aliases、日志发现和 correlation-matrix 共同处理。
```

这能降低 AI 和运营人员对“主机关联”的误解。

## 3. 对象职责重新定义

### 3.1 Asset

`Asset` 负责描述数据语义，不再直接声明主机绑定关系。

保留核心字段：

- `asset_id`
- `name`
- `asset_type`
- `domain`
- `owner_team`
- `environment`
- `status`
- `connector_id` / `connector_ids`
- `coverage.hosts`
- `schema.fields`
- `schema.time_field`
- `schema.retention_days`
- `field_aliases`
- `text_parser`
- `query_template_ids`
- `sensitivity`
- `masking`
- `tags`
- `description`

重点语义：

```text
coverage.hosts = 日志来源 IP 数组。
```

不要把 hostname、业务名、FQDN、aliases 写入 `coverage.hosts`。

`text_parser` 负责声明行级文本/JSON 解析器，当前内置：

| parser | 用途 |
|---|---|
| `syslog_auth` | Linux SSH/PAM 认证日志 |
| `nginx_combined` | Nginx combined 访问日志 |
| `json_lines` | 每行 JSON object，解析顶层字段 |
| `json_lines2` | 每行 JSON object，并展开字段值里的 JSON object 为 `父字段.子字段` |
| `raw_only` | 不解析，仅保留原始行 |

`json_lines2` 对 AI 友好的原因是：`fields: "{...}"` 这类半结构化字段不再只是一段字符串，而可以在证据层呈现为 `fields.user`、`fields.session.tty` 等可检索字段。

### 3.2 Connector

`Connector` 负责取数路径。

保留核心字段：

- `connector_id`
- `name`
- `connector_type`
- `credentials_ref`
- `status`
- `config`
- `constraints`

如果是单主机 connector，例如 SSH 直读、单主机 agent、本地文件，可以在 `config.host_id` 中标注物理目标：

```json
"config": {
  "host_id": "host-web-01"
}
```

聚合型 SLS / 平台级 connector 不建议填 `config.host_id`，避免误导为单主机数据源。

### 3.3 Host

`Host` 负责描述主机实体。

统一口径：

```text
host.host_ip：主机主地址，必须尽量是 IP。
host.aliases：主机别名、历史名、FQDN、日志中可能出现的 host_name 值。
host.interfaces：可选，多网卡/多地址场景才填写。
```

示例：

```json
{
  "host_id": "host-example-web-01",
  "hostname": "example-web-01",
  "host_ip": "192.0.2.10",
  "aliases": ["web-01", "web-01.example.invalid"],
  "network_id": "net-example-web"
}
```

这里 `aliases` 用于识别日志中的主机名，不用于 `asset.coverage.hosts`。

### 3.4 Network

`Network` 继续负责网络上下文：

- `network_id`
- `name`
- `cidr`
- `zone`
- `network_type`
- `gateway_ip`
- `trust_level`
- `status`

`zone`、`network_type`、`trust_level` 三者分工如下：

| 字段 | 定义 | 主要用途 |
|---|---|---|
| `zone` | 逻辑区域 / 拓扑分组 token | UI 分组、拓扑展示、按业务/区域筛选 |
| `network_type` | 网络用途/形态分类 | 描述网段是生产、DMZ、办公、管理、实验、云 VPC 还是外部网络 |
| `trust_level` | 安全信任等级/访问敏感度 | 用于横向移动、影响范围、风险优先级判断 |

关键原则：

```text
zone 不等于 network_type。
network_type 不等于 trust_level。
zone 只负责“分组在哪里”，network_type 负责“它是什么用途”，trust_level 负责“安全上有多可信/多敏感”。
```

例如生产数据库网段可以是：

```json
{
  "zone": "production_network",
  "network_type": "production",
  "trust_level": "restricted"
}
```

`zone` 仅用于逻辑分组和拓扑展示，不再要求与 host 或 asset 的 coverage 字段对齐。

## 4. 最新关系模型

当前推荐关系：

```text
Asset.connector_id / connector_ids -> Connector.connector_id
Asset.coverage.hosts               -> Host.host_ip / Host.interfaces[].ip（日志来源 IP 匹配）
Connector.config.host_id           -> Host.host_id（可选，仅单主机 connector）
Host.network_id                    -> Network.network_id
Host.interfaces[].network_id       -> Network.network_id
```

不再使用：

```text
Asset.host_binding.host_id
Asset.host_binding.host_field
```

## 5. AI 可理解性评估

去除 `host_binding` 后，AI 的解释路径更清晰：

1. 先看 `asset_type` 判断数据类型。
2. 看 `schema.fields` 和 `field_aliases` 判断字段能力。
3. 看 `text_parser` 判断原始文本/JSON 行如何转成字段。
4. 看 `connector_id` 找取数路径。
5. 看 `coverage.hosts` 判断日志来源 IP 覆盖。
6. 看 `hosts` / `networks` 解释这些来源 IP 属于哪些主机和网段。
7. 对单主机采集，必要时看 `connector.config.host_id`。

AI 不应再根据 `host_binding.host_field` 推断主机关联。

## 6. 字段优化建议

### 6.1 Asset

建议继续强化：

- `coverage.hosts` schema 约束为 IP 字符串。
- `validate.py` 对非 IP coverage 值给 warning。
- 新资产 UI 中明确提示：coverage 只填日志来源 IP。
- `text_parser` 的内置 ID 必须与 `text-log-parsers.json`、`data-asset.schema.json`、解析实现和单测同步。
- `syslog_risk_alert` 与 `linux_syslog` 区分使用：前者是结构化风险报警，后者是普通系统日志。

可选新增字段：

```json
"source_field_hint": "__source__"
```

用于说明 `coverage.hosts` 的来源字段。但这只是提示，不是主机关联模型。

### 6.2 Connector

建议后续增加查询能力描述：

```json
"constraints": {
  "search_mode": "full_text",
  "indexed_fields": [],
  "source_field_candidates": ["__source__", "__tag__:__client_ip__"]
}
```

这样 AI 在 SLS 字段不可索引时报错时，可以更准确提示用户给实际源字段增加索引。

### 6.3 Host

建议：

- 空 `aliases: []` 可以不写。
- 空 `interfaces: []` 可以不写。
- `interfaces` 只在多网卡、多地址、跨网段时填写。
- `aliases` 不建议放 IP，除非该 IP 确实作为日志中的主机名字符串出现。

### 6.4 Network

建议：

- 保留 `trust_level`，用于安全风险判断和影响面排序。
- 明确 `zone` 只做逻辑分组和拓扑展示，不承载安全等级。
- 明确 `network_type` 只描述网络用途/形态，不代表可信程度。
- 不恢复 network 级 `internet_exposed`。
- `internet_exposed` 继续放在 `host.exposure`。

推荐取值参考：

| 场景 | `zone` 示例 | `network_type` | `trust_level` |
|---|---|---|---|
| 互联网或外部地址段 | `internet` / `external_edge` | `external` | `external` |
| DMZ / 边界区 | `dmz_edge` | `dmz` | `dmz` |
| 生产 WEB 网 | `production_network` | `production` | `internal` |
| 生产数据库网 | `production_network` | `production` | `restricted` |
| 管理网 / 堡垒机网 | `management_network` | `management` | `management` |
| 办公网 | `office_network` | `office` | `internal` |
| 实验/测试网 | `lab_network` | `lab` | `internal` |
| 云 VPC 大段 | `example_vpc` | `cloud_vpc` | 视承载业务填 `internal` / `restricted` / `management` |

### 6.5 Text Parser

建议把 parser 看成“原始日志到字段”的声明，不看成主机关联字段：

- `json_lines`：只解析顶层 JSON object。
- `json_lines2`：解析顶层 JSON object，并展开字段值里的 JSON object 为点号路径。
- `raw_only`：适合尚未完成格式发现或由 SLS/ES 已结构化返回的场景。

`json_lines2` 不替代 `schema.fields` 和 `field_aliases`：它只是把嵌套内容拉平成候选源字段；字段是否进入资产能力，仍应由日志发现 Skill 补充 `schema.fields`，再用 `field_aliases` 对齐 canonical 字段。

## 7. 落地优先级

### P0

- 从所有 asset JSON 中去除 `host_binding`。
- 从 `data-asset.schema.json` 去除 `host_binding` 定义。
- `validate.py` 不再要求 active 主机相关资产填写 `host_binding`。
- UI 不再显示或写入 `host_binding`。

### P1

- 文档统一为 `coverage.hosts` IP-only。
- 拓扑图使用 `coverage.hosts` 匹配 host IP。
- 单主机 connector 仅通过 `connector.config.host_id` 表达物理目标。

### P2

- 增加 `source_field_hint` 或 connector constraints，用于解释日志来源字段。
- 后续如果主机关联需求明确，再设计新的、更明确的字段，而不是恢复旧 `host_binding`。

## 8. 最终评价

去除 `host_binding` 并补齐 `syslog_risk_alert` / `json_lines2` 后，当前模型更简单，也更符合当前运营阶段：

```text
Asset = 数据语义 + 字段能力 + 解析器 + 覆盖来源 IP
Connector = 取数路径 + 可选单主机目标
Host = 主机实体
Network = 网络上下文
```

这比原先 `coverage.hosts + host_binding + aliases + host_field` 同时存在更容易让 AI 和人理解。

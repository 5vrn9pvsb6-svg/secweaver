**语言：** [English](09-data-asset-design.md) | 简体中文（本文）

# 数据源资产设计

更新时间：2026-09-16

> 示例说明：本文中的主机名、资产标识和网络分组均为虚构示例；IP 地址使用文档示例网段。接入时默认在 `dataasset/` 中配置实际值，也可复制到 `dataasset_my/` 隔离使用；客户配置不要提交公开仓库。

## 1. 当前核心口径

SecWeaver 数据资产模型由四类对象组成：

```text
Asset ──connector_id / connector_ids──→ Connector ──credentials_ref──→ Credentials
  │
  ├── coverage.hosts(日志来源 IP) ──→ Host ──network_id / interfaces[].network_id──→ Network
  │
  ├── query_template_ids ──→ Query Template
  │
  └── asset_type ──→ Evidence Spec / Scenario / Correlation Matrix
```

为避免主机关联语义混淆，资产侧不再使用主机绑定字段。当前统一口径：

```text
host.host_ip：主机主地址，必须尽量是 IP。
host.aliases：主机别名、历史名、FQDN、日志中可能出现的 host_name 值。
host.interfaces：可选，多网卡/多地址场景才填写。
asset.coverage.hosts：只放日志来源 IP，不放 aliases/hostname。
```

## 2. 对象职责

### 2.1 Asset

Asset 描述数据语义和可用性。

核心字段：

| 字段 | 说明 |
|---|---|
| `asset_id` | 全局唯一 ID，形如 `asset-xxx` |
| `name` | 展示名 |
| `asset_type` | 数据类型，如 `waf_alert`、`host_exec`、`syslog_risk_alert` |
| `domain` | D1-D7 数据域 |
| `owner_team` | 责任团队 |
| `environment` | `production` / `staging` / `development` |
| `status` | `discovery` / `draft` / `active` / `disabled` |
| `connector_id` | 主 connector |
| `connector_ids` | 多 connector 聚合，可选 |
| `coverage.hosts` | 日志来源 IP 数组，只放 IP |
| `schema.fields` | 日志字段列表，由日志发现或人工确认维护 |
| `schema.time_field` | 时间字段 |
| `schema.retention_days` | 后端日志保留天数 |
| `field_aliases` | 源字段到 canonical 字段映射 |
| `query_template_ids` | 可用查询模板 |
| `text_parser` | 文本或 JSON 解析器 |
| `sensitivity` / `masking` | 数据治理与脱敏 |
| `tags` | 标签 |

示例：

```json
{
  "asset_id": "asset-secweaver-sys-risk-alert",
  "name": "示例 syslog-risk-json 报警日志",
  "asset_type": "syslog_risk_alert",
  "domain": "D2",
  "owner_team": "security-ops",
  "environment": "production",
  "status": "active",
  "connector_id": "conn-sls-secweaver-sys-risk-alert",
  "text_parser": "raw_only",
  "coverage": {
    "hosts": ["192.0.2.10", "192.0.2.20"]
  },
  "schema": {
    "fields": ["timestamp", "host_name", "event_type", "risk_level", "src_ip"],
    "time_field": "timestamp",
    "retention_days": 30
  },
  "query_template_ids": ["syslog_risk_by_time"],
  "tags": ["example", "syslog-risk-json", "alert"]
}
```

<a id="asset-retention"></a>

#### 日志保留期：`schema.retention_days`

填写后端实际保留日志的天数，供完整性检查评估调查时间窗是否可能被覆盖。该字段是治理元数据，不会修改 ES/SLS 的保留策略；实际日志是否存在仍须查询验证。

<a id="asset-time-correction"></a>

#### 时间校正：`schema.time_correction`

取数归一化时，`normalizer` 可根据资产配置校正证据的 `timestamp`：`assume_timezone` 用于解释没有时区的时间（如 `Asia/Shanghai` 或 `+08:00`）；`offset_minutes` 在时间戳上加减分钟，源时钟慢用正值、快用负值。使用 `reason` 记录已核实的偏差原因，避免对已经正确的时间重复校正。校正不修改原始日志或关联矩阵的 Join 时间窗。

<a id="asset-correlation-keys"></a>

#### 关联键：`schema.correlation_keys`

该字段已经废弃，不应手写。运行时根据关联矩阵、`schema.fields` 和 `field_aliases` 推导可用关联键；维护源字段和别名即可。旧配置中的手写值可能产生校验警告，不能替代实际字段或保证关联成功。字段约束见 [Asset Schema](../dataasset/schema/data-asset.schema.json)。

### 2.2 Connector

Connector 描述如何取数。

核心字段：

| 字段 | 说明 |
|---|---|
| `connector_id` | 全局唯一 ID，形如 `conn-xxx` |
| `name` | 展示名 |
| `connector_type` | `sls` / `ssh_file` / `database_ro` / `http_api` / `es` 等 |
| `credentials_ref` | `vault://...` 凭证引用 |
| `status` | `draft` / `active` / `disabled` |
| `config` | 连接目标配置 |
| `constraints` | 查询限制、能力描述 |

单主机 connector 可用 `config.host_id` 标注实际采集目标：

```json
{
  "connector_id": "conn-ssh-web-01-auth",
  "connector_type": "ssh_file",
  "credentials_ref": "vault://ssh/web-01-readonly",
  "status": "active",
  "config": {
    "host": "192.0.2.30",
    "host_id": "host-web-01",
    "log_paths": {
      "auth": "/var/log/auth.log"
    }
  }
}
```

聚合型 SLS / 平台级 connector 不建议填写 `config.host_id`。

### 2.3 Host

Host 描述主机实体。

核心字段：

| 字段 | 说明 |
|---|---|
| `host_id` | 全局唯一 ID，形如 `host-xxx` |
| `name` | 展示名 |
| `hostname` | 短主机名，用于展示和日志 `host` / `host_name` 字段匹配 |
| `host_type` | `server` / `network_device` / `endpoint` / `gateway` |
| `host_os` | `linux` / `windows` / `macos` / `network_os` / `other` |
| `host_ip` | 主机主地址，必须尽量是 IP |
| `network_id` | 主地址所属网段 |
| `aliases` | 主机别名、历史名、FQDN、日志中可能出现的 host_name 值 |
| `interfaces` | 可选，多网卡 / 多地址场景才填写 |
| `nat` | 可选，NAT/EIP 映射 |
| `exposure` | 可选，主机级互联网暴露面 |
| `roles` | 业务或安全角色 |
| `status` | `draft` / `active` / `retired` |

示例：

```json
{
  "host_id": "host-example-web-01",
  "name": "示例 Web 主机",
  "hostname": "example-web-01",
  "host_type": "server",
  "host_os": "linux",
  "host_ip": "192.0.2.10",
  "network_id": "net-example-web",
  "aliases": ["web-01", "web-01.example.invalid"],
  "roles": ["syslog-source"],
  "environment": "production",
  "status": "active"
}
```

### 2.4 Network

Network 描述网络上下文，重点回答：这个 IP 属于哪个网段、这个网段用于什么、从安全视角应当如何看待它。

核心字段：

| 字段 | 说明 |
|---|---|
| `network_id` | 全局唯一 ID，形如 `net-xxx` |
| `name` | 展示名 |
| `cidr` | IPv4/IPv6 CIDR |
| `zone` | 逻辑区域 / 拓扑分组 token，用于展示、分组和运营筛选 |
| `network_type` | 网络用途/形态分类：`dmz` / `production` / `office` / `management` / `lab` / `cloud_vpc` / `external` / `other` |
| `gateway_ip` | 网关 IP |
| `trust_level` | 安全信任等级：`external` / `dmz` / `internal` / `restricted` / `management` |
| `status` | `draft` / `active` / `retired` |

三者分工必须明确：

| 字段 | 回答的问题 | 用法 | 不应用来表达 |
|---|---|---|---|
| `zone` | “拓扑上/运营上放在哪一组？” | UI 分组、拓扑展示、按业务/区域筛选，如 `production_network`、`example_vpc`、`example_site` | 不表示用途类型，不表示安全等级 |
| `network_type` | “这个网段是什么用途/形态？” | 描述网络用途，如生产网、办公网、管理网、实验网、DMZ、云 VPC | 不表示是否可信，不表示是否高敏 |
| `trust_level` | “从安全视角有多可信/多敏感？” | 风险判断、横向移动路径、影响范围优先级 | 不表示拓扑分组，不表示业务用途 |

推荐示例：

```json
{
  "network_id": "net-prod-db",
  "name": "生产数据库网段",
  "cidr": "198.51.100.0/24",
  "zone": "production_network",
  "network_type": "production",
  "trust_level": "restricted",
  "status": "active"
}
```

常见取值建议：

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

网络级不再维护 `internet_exposed`；互联网暴露放在 `host.exposure`。

## 3. 关联关系

| 从 | 到 | 方式 | 说明 |
|---|---|---|---|
| Asset | Connector | `connector_id` / `connector_ids` | 一个资产可绑定一个或多个 connector |
| Connector | Credentials | `credentials_ref` | connector 只保存凭证引用，不保存明文 |
| Asset | Host | `coverage.hosts` | 日志来源 IP 匹配 `host.host_ip` / `interfaces[].ip` |
| Connector | Host | `config.host_id` | 可选，仅单主机 connector 使用 |
| Host | Network | `network_id` / `interfaces[].network_id` | 主机地址归属到网络 |
| Asset | Query Template | `query_template_ids` | 控制 AI / Skill 可用查询入口 |

## 4. coverage.hosts 规则

`coverage.hosts` 是日志来源 IP 数组，只放实际来源 IP。

正确：

```json
"coverage": {
  "hosts": ["192.0.2.10", "192.0.2.80"]
}
```

错误：

```json
"coverage": {
  "hosts": ["web-01", "web-02", "gateway-example"]
}
```

如果日志里出现 `host_name=web-01`，应写入对应 host 的 `aliases`，不是写入 asset coverage。

## 5. 字段发现与字段别名

`schema.fields` 表示日志中已经发现或确认的字段。字段发现 Skill 可补充它。

`field_aliases` 用于把源字段映射到 canonical 字段，例如：

```json
"field_aliases": {
  "host_name": "host",
  "time": "timestamp"
}
```

注意：字段存在不代表 SLS 已建 key-value 索引。如果出现：

```text
key (...) is not config as key value config
```

应提示用户检查实际源字段，并在对应 SLS logstore 索引配置中增加该字段索引。字段可能不是 `src_ip`，要以真实日志字段为准。

## 6. 文本解析器 text_parser

`text_parser` 只用于 connector 返回的**原始文本或 JSON 字符串**。它主要服务于 `ssh_file` / `local_file`，以及只返回 `__line__`、`content` 等原始载荷字段的 SLS。SLS/ES/云 SDK 已返回结构化字段时必须省略 `text_parser`，只使用 `schema.fields` 和 `field_aliases`；不要把 parser 当作格式说明元数据保留。

| SDK 实际返回形态 | `text_parser` | 配置方式 |
|---|---|---|
| 顶层已包含业务字段，如 `event_type`、`src_ip`、`request_uri` | **不写** | `schema.fields` + `field_aliases` |
| 只有 SLS 元字段和一个原始 JSON 字符串字段 | **必须写** | `json_lines` / `json_lines2` |
| 只有 `__line__`、`content` 等原始 syslog/nginx 文本 | **必须写** | `syslog_auth`、`nginx_combined` 或自定义 parser |
| 暂时无法解析，但需要保留原文 | **必须写** | `raw_only` |

当前内置 parser：

| parser | 适用场景 | 行为 |
|---|---|---|
| `syslog_auth` | Linux `auth.log` / `secure` | 解析 sshd 登录、失败登录等认证日志 |
| `nginx_combined` | Nginx combined access log | 解析访问日志常见字段 |
| `json_lines` | 每行一条 JSON object | 解析顶层 JSON 字段，字段映射再走 `field_aliases` |
| `json_lines2` | 每行一条 JSON object，且字段值中可能嵌套 JSON object | 在 `json_lines` 基础上，将 JSON object 字符串/对象展开为点号字段 |
| `raw_only` | 暂不解析或仅保留原文 | 输出 `raw_line` + `host`，适合未完成格式发现的日志 |

`json_lines2` 示例：

```json
{
  "event_type": "ssh_login",
  "fields": "{\"user\":\"root(uid=0\",\"session\":{\"tty\":\"pts/0\"}}"
}
```

解析后会保留原字段，并补充：

```json
{
  "fields.user": "root(uid=0",
  "fields.session.tty": "pts/0"
}
```

新增内置 parser 时需要同步：

1. `dataasset/configure/text-log-parsers.json`
2. `dataasset/schema/data-asset.schema.json` 的 `text_parser` enum / `not enum`
3. `src/skills/_shared/data-access/text_log_parser.py`
4. 对应单测

## 7. 新资产类型接入流程

新增 `asset_type` 时，同步以下位置：

1. `dataasset/schema/data-asset.schema.json`
2. `dataasset/configure/evidence-minimum-fields.json`
3. `dataasset/query-templates/templates.json`
4. `dataasset-ui/module-page.js`
5. `src/dataasset/validate.py` 中需要按类型处理的逻辑；可复用诊断和报告辅助放在 `src/dataasset/validate_lib/`
6. 相关 Skill 文档或规则

`syslog_risk_alert` 是当前新增类型，用于 `syslog-risk-json` 结构化报警日志，区别于普通 `linux_syslog`。

## 8. 校验重点

`validate.py` 仍是兼容 CLI 的校验入口。共享校验辅助放在 `src/dataasset/validate_lib/`：`diagnostics.py` 负责报告格式，`connector_contracts.py` 负责 onboarding 跨文件约束，`inventory_contracts.py` 负责 Host/Network 语义校验，`runtime_readiness.py` 推导 Bundle 静态执行就绪状态。

`validate.py` 当前重点检查：

- JSON schema 是否通过；
- ID 与文件名是否一致；
- connector 是否存在；
- query template 是否存在且适配 connector / asset_type；
- active asset 是否有 owner、description、retention、必需 evidence 字段；
- `coverage.hosts` 是否为 IP；
- `connector.config.host_id` 是否引用存在的 host；
- host 的 `network_id` / `interfaces[].network_id` 是否存在；
- host IP 是否落在对应 CIDR 内；
- bundle 是否引用不存在或非 active 资产。

Asset、Bundle、Host、Network Schema 关闭顶层未知字段；Host 的 `interfaces`、`nat`、
`exposure` 和对象形式 `exposed_ports` 也关闭未知字段。现有 `quality`、
`tenant_scope`、Bundle `notes`、Host `source_host_description` 已正式建模。
厂商或部署私有元数据必须放入 `extensions`；多个环境都需要的字段应加入正式 Schema。
这样既能拦截字段拼写错误，也不会把私有扩展散落在顶层。

### 运行时状态门禁

校验和执行各自承担不同职责。生产 Skill 的 `fetch()` 要求 Asset 与 Connector
同时为 `active`。接入工具显式使用 `onboarding_test` 执行模式，在提升前测试
`draft/discovery`。`disabled` 在任何模式下都会被拒绝，包括连通性测试。门禁发生在
模板渲染和凭证解析之前。

`validate --runtime-ready` 增加 Bundle -> Asset -> Connector -> 凭证密文的静态上线
门禁，包括 `agent_stream` 下游遍历、占位值检查和有界循环检测。它不会解密凭证或访问
后端；依赖对象的基础校验错误会进入对应 Bundle blocker。JSON 报告中的
`registry_valid` 表示整个资产根，Bundle `status` 表示局部依赖图，只有两者都通过时
`ready_for_execution` 才为 `true`。真实可达性和数据存在性仍由
`dataasset-connectivity-check` 负责。

### Catalog 与多资产根契约

`connector-catalog.json` 和 `external-connectors.json` 声明
`format_version: "2.0"`，原 `version` 继续表示内容发布版本。运行时遇到不支持的格式
会直接失败。旧 Catalog 先用 `secweaver dataasset migrate --root <root>` 预览，复核后
添加 `--write`；迁移保留旧 profile 文件供回滚。

Connector Schema 是内置 Connector 结构、必填字段和条件组合的唯一校验契约，并拒绝
顶层未知字段和内置类型的未知 `config` 字段；Catalog 负责运行能力、依赖和接入 UI
元数据。配置型外部
Connector 与插件保留开放 config 以承载厂商扩展。仓库存在本地 overlay 时运行
`make validate-all-roots`。规范文件 `dataasset/configure/shared-contracts.json` 要求每个
受管 JSON 只属于一种类型：`shared` 必须逐字节一致，`override` 可按已记录原因不同，
`root_owned` 环境清单由所属根目录维护。CI 会拒绝未分类、重复分类、失效 shared 模式
和共享内容漂移，整个过程不会读取凭证文件。

共享契约修复采用预览优先流程：`sync_shared_contracts.py --check` 只报告差异，人工复核后
使用 `--write` 从公开根复制 `shared` 文件。它不会复制凭证，也不会修改 `root_owned`
环境清单。凭证生命周期由共享 `credential-status.schema.json` 约束，只允许 `active` 和
`disabled`；未知状态在校验、Studio 和运行时均失败关闭。ES Connector 必须校验证书，
私有 CA 使用 `ca_file`，不得通过 `tls_verify: false` 绕过。

## 9. AI 使用建议

AI 使用资产时应遵循：

```text
先看 asset_type 判断数据类型。
再看 schema.fields / field_aliases 判断字段能力。
再看 text_parser 判断原始文本/JSON 行如何解析。
再看 connector_id / query_template_ids 选择取数路径。
再看 coverage.hosts 判断日志来源 IP 覆盖。
如需单主机采集目标，再看 connector.config.host_id。
```

不要再依赖资产侧主机绑定字段推断主机关联。

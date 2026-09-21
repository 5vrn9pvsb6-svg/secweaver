# 02. 核心概念

**语言：** [English](02-core-concepts.md) | 简体中文（本文）

本文解释 SecWeaver 中最重要的几个概念。理解这些概念后，你就能看懂 `dataasset/` 目录里的大部分配置。

---

## 总体关系

可以先记住这张关系图：

```text
Asset ──connector_id──→ Connector ──credentials_ref──→ Credentials
  │
  ├── coverage.hosts(IP) ──→ Host ──network_id──→ Network
  │
  ├── query_template_ids ──→ Query Template
  │
  └── asset_type ──→ Correlation Matrix / Scenario Pattern
```

简单说：

- `Asset` 说明这是什么数据。
- `Connector` 说明怎么连接这个数据。
- `Credentials` 保存真实凭证。
- `Host` 说明这台主机是谁。
- `Network` 说明这个 IP 在哪个网段。
- `Query Template` 说明怎么查询。
- `Bundle` 把多个资产打包成一个调查包。
- `Scenario Pattern` 告诉 AI 某类问题应该先查什么。
- `Correlation Matrix` 告诉系统不同证据之间怎么关联。

---

## Asset：逻辑数据资产

目录：`dataasset/assets/`

`Asset` 是最核心的对象。它回答：

```text
这份数据是什么？
属于什么类型？
有哪些字段？
覆盖哪些主机或区域？
用哪个连接器取数？
适合哪些查询模板？
```

例如：

```text
asset-waf-prod-01.json
```

可能表示“生产环境 WAF 告警数据”。

常见 `asset_type`：

| asset_type | 含义 | 常见用途 |
|---|---|---|
| `waf_alert` | WAF 告警 | 告警确认、外部 IP 溯源 |
| `web_access_log` | Web 访问日志 | 判断攻击请求是否到达业务 |
| `host_exec` | 主机命令执行 | 判断是否打到主机 |
| `host_connect` | 主机外连 | 判断 C2、数据外传 |
| `host_file_op` | 文件操作 | 判断 WebShell 或落地文件 |
| `ssh_auth` | SSH 登录 | 横向移动、账号失陷 |
| `firewall_log` | 防火墙日志 | 跨网段访问验证 |
| `dns_log` | DNS 日志 | 外连域名分析 |
| `network_traffic_audit` | 网络流量审计 | 数据外传分析 |
| `db_audit` | 数据库审计 | 敏感数据访问确认 |
| `asset_inventory` | 资产清单 | 主机名、IP、归属关系 |

---

## Connector：连接器

目录：`dataasset/connectors/`

`Connector` 回答：

```text
这个数据源怎么连接？
是 SLS、ES、数据库、SSH 文件，还是本地文件？
连接地址是什么？
项目名、索引名、表名是什么？
凭证引用是什么？
```

注意：连接器里不应该写明文密码。

正确做法：

```json
{
  "connector_id": "conn-sls-waf-prod",
  "connector_type": "sls",
  "credentials_ref": "vault://sls/security-readonly"
}
```

错误做法：

```json
{
  "access_key_secret": "明文密码"
}
```

---

## Credentials：凭证

目录：`dataasset/credentials/`

凭证保存真实密钥，例如：

- SLS AccessKey
- 数据库账号密码
- SSH 私钥
- API Token

运营配置时应只在 Connector 中写 `credentials_ref`，不要把真实密钥写进 `connectors/*.json`。

这样做的好处：

- 可以安全提交配置文件。
- AI 看不到密钥。
- 权限边界更清晰。
- 后续可以替换 Vault 实现。

---

## Host：主机

目录：`dataasset/hosts/`

`Host` 用来登记关键主机，例如：

- Web 服务器
- 应用服务器
- 数据库服务器
- 堡垒机
- 网关机

它回答：

```text
这台机器叫什么？
IP 是什么？
属于哪个区域？
绑定哪个网段？
是否对公网暴露？
有哪些端口？
```

为什么 Host 很重要？

因为很多调查都需要围绕主机展开：

- 某个 Web 请求最后到了哪台机器？
- 哪台主机执行了可疑命令？
- 这台机器是否又去连了其他内网机器？
- 它是否从 DMZ 进入了生产网？

---

## Network：网络段

目录：`dataasset/networks/`

`Network` 用来描述网段，例如：

```text
生产 Web 网段
生产 DB 网段
DMZ 网段
办公网段
云 VPC 网段
```

它回答：

```text
这个 IP 属于哪个 CIDR？
这个网段是什么区域？
是否对公网暴露？
信任级别是什么？
```

Network 对横向移动和数据外传很重要。

例如：

```text
DMZ → 生产 DB 网段
```

这个方向比普通内网访问更敏感。

---

## Query Template：查询模板

目录：`dataasset/query-templates/`

`Query Template` 回答：

```text
如果要查某类数据，具体查询语句怎么写？
需要哪些参数？
```

例如：

```text
根据 src_ip + time_start + time_end 查询 WAF 告警
根据 host + time_start + time_end 查询主机命令
根据 user + time_start + time_end 查询 SSH 登录
```

对运营同学来说，重点是：

- Asset 里要引用合适的 `query_template_ids`。
- Template 需要的参数要和调查场景能提供的参数对上。
- 字段名要和实际日志字段或字段映射一致。

---

## Bundle：资产包

目录：`dataasset/bundles/`

`Bundle` 是一组资产的集合。

例如“告警确认最小包”可以包含：

```text
WAF 告警
Web 访问日志
主机命令执行
主机外连
文件操作
```

它的作用是：

- 让某类调查不用每次手工选择资产。
- 确保调查使用统一的数据范围。
- 方便 AI 一次性获取相关证据。

---

## Scenario Pattern：调查场景

目录：`dataasset/scenarios/`

`Scenario Pattern` 告诉 AI：

```text
遇到某类问题时，应该从哪个字段开始查？
先查哪些数据？
按什么链路关联？
默认查多长时间？
用哪个资产包？
```

例如：

- 外部 IP 溯源：从 `src_ip` 开始。
- 横向移动：从 `host_ip` 或 `user` 开始。
- 数据外传：从 `host`、`dst_ip` 或 `domain` 开始。

这不是限制 AI，而是给 AI 一个可靠的调查剧本。

更详细说明见：[05. Scenario Pattern 详解：告诉 AI 先查什么](05-scenario-patterns.zh-CN.md)。

---

## Correlation Matrix：关联矩阵

文件：`dataasset/assets/correlation-matrix.json`

`Correlation Matrix` 回答：

```text
不同证据之间怎么关联？
用哪个字段 Join？
时间窗多大？
关联成功后如何生成证据边？
```

例如：

```text
WAF 告警.src_ip = Web 访问日志.src_ip
Web 访问日志.host = 主机命令.host
SSH 登录.host_ip = 主机资产.ip
```

AI 最终看到的不是一堆散乱日志，而是：

```text
evidence_bundles + join_edges + data_gaps
```

这能帮助 AI 输出更可信的结论。

更详细说明见：[04. Correlation Matrix 详解：告诉系统证据怎么关联](04-correlation-matrix.zh-CN.md)。

---

## Evidence：证据

`Evidence` 是从日志源取回并归一化后的事件。

一条 evidence 通常包含：

- `evidence_id`
- `timestamp`
- `src_ip`
- `dst_ip`
- `host`
- `user`
- `url`
- `command`
- `action`
- 其他与场景相关的字段

不同日志源字段名可能不一样，所以需要字段映射，把它们归一成统一字段。

---

## 三个最重要的状态

很多对象都有 `status`：

| status | 含义 | 是否可用于正式调查 |
|---|---|---|
| `discovery` | 新日志格式发现中 | 否 |
| `draft` | 配置中或待验证 | 通常否 |
| `active` | 已验证、可使用 | 是 |

建议新配置先使用 `draft`，验证通过后再改为 `active`。

---

## 下一步

继续阅读：[03. 如何配置数据源](03-configure-data-sources.zh-CN.md)

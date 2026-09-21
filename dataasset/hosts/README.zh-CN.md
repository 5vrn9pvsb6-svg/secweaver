# 关键主机注册表字段说明（hosts/）

`dataasset/hosts/` 存放平台关注的关键主机 / 逻辑主机定义，用来回答：这台机器是谁、主地址是什么、属于哪个网络、承担什么角色、是否对外暴露。

当前主机模型的统一口径：

```text
host.host_ip：主机主地址，必须尽量是 IP。
host.aliases：主机别名、历史名、FQDN、日志中可能出现的 host_name 值。
host.interfaces：可选，多网卡/多地址场景才填写。
asset.coverage.hosts：只放日志来源 IP，不放 aliases/hostname。
```

资产侧不再使用 `host_binding`。主机关系主要通过以下方式表达：

- `asset.coverage.hosts`：日志来源 IP 数组，用于资产覆盖和拓扑匹配。
- `connector.config.host_id`：可选，仅用于单主机 connector 标注实际采集目标。
- `host.network_id` / `host.interfaces[].network_id`：主机地址到网段的归属。

## 1. 文件命名与基本规则

| 项 | 规则 | 示例 |
|---|---|---|
| 文件路径 | `dataasset/hosts/host-{slug}.json` | `dataasset/hosts/host-web-01.json` |
| 主键字段 | `host_id` 与文件名主干一致 | 文件 `host-web-01.json` 内填 `"host_id": "host-web-01"` |
| ID 格式 | 必须匹配 `^host-[a-z0-9-]+$` | `host-db-01`、`host-bastion-dmz` |
| 是否存密钥 | 不存任何密码、私钥、AccessKey | 凭证只放在 credentials/Vault 中 |

`hosts/` 是安全调查用的关键主机索引，不是企业全量 CMDB。只登记会被安全数据源、连接器、溯源链路引用的主机即可。

## 2. 字段总览

| 字段 | 必填 | 类型 | 用途摘要 |
|---|---:|---|---|
| `host_id` | 是 | string | 全局唯一主机 ID，与文件名一致 |
| `name` | 是 | string | 展示名，给人看的名称 |
| `hostname` | 是 | string | 短主机名，用于展示和日志 `host` / `host_name` 字段匹配 |
| `host_type` | 是 | string | 主机 / 设备大类 |
| `status` | 是 | string | 生命周期状态 |
| `host_os` | 否 | string | 操作系统或设备系统类型 |
| `host_ip` | 否 | string | 主机主地址，必须尽量是 IP |
| `network_id` | 否 | string | 主地址所属网络 |
| `interfaces` | 否 | object[] | 可选，多网卡 / 多地址 / 管理网分离场景才填写；管理口使用 `role=management` |
| `nat` | 否 | object | 仅复杂 NAT / EIP 路径填写网关和映射类型 |
| `exposure` | 否 | object | 对外暴露面摘要 |
| `aliases` | 否 | string[] | 主机别名、历史名、FQDN、日志中可能出现的 host_name 值 |
| `roles` | 否 | string[] | 业务或技术角色标签 |
| `environment` | 否 | string | 环境：production / staging / development |
| `description` | 否 | string | 运维 / 安全调查备注 |
| `tags` | 否 | string[] | 自由标签 |

## 3. 关键字段说明

### 3.1 `host_ip`

`host_ip` 是主机主地址，必须尽量填写真实 IP。

推荐：

```json
{
  "host_ip": "198.51.100.2"
}
```

不推荐：

```json
{
  "host_ip": "web-01"
}
```

如果暂时只有 hostname，可以先保留 `hostname`，待确认 IP 后再补 `host_ip`。

### 3.2 `aliases`

`aliases` 用于记录主机别名、历史名、FQDN、日志中可能出现的 `host_name` 值。

推荐：

```json
{
  "aliases": [
    "gateway",
    "gateway.internal.example"
  ]
}
```

不要为了兼容 `asset.coverage.hosts` 把 hostname 或业务名写入 coverage。coverage 只放日志来源 IP。

### 3.3 `interfaces`

`interfaces` 是可选字段，只在多网卡、多地址、跨网段、管理网/业务网分离等场景填写。

普通单网卡主机只需要：

```json
{
  "host_ip": "192.0.2.5",
  "network_id": "net-prod-web"
}
```

多网卡主机可以填写：

```json
{
  "interfaces": [
    {
      "name": "eth0",
      "ip": "192.0.2.5",
      "network_id": "net-prod-web",
      "role": "primary"
    },
    {
      "name": "eth1",
      "ip": "192.0.2.15",
      "network_id": "net-management",
      "role": "management"
    }
  ]
}
```

管理口不再单独使用 `management_ip`。将管理网卡写入 `interfaces`，并通过它的 `network_id` 获取管理网关。业务默认网关同样通过主机的 `network_id` 从 Network 获取，不再在 Host 重复维护。

### 3.4 `exposure`

`exposure` 用于主机级暴露面摘要。网络级不再维护 `internet_exposed`。

```json
{
  "exposure": {
    "internet_exposed": true,
    "internet_ip": "116.62.158.63",
    "exposed_ports": [443, 80]
  }
}
```

详细证据仍应来自 `host_connect`、防火墙日志、NTA、云安全组等数据源。

### 3.5 `nat`

普通 EIP / DNAT 场景不需要重复填写公网和内网 IP：公网入口使用 `exposure.internet_ip`，内部地址使用 `host_ip` 或 `interfaces[].ip`。只有需要解释复杂 NAT 路径时才补充：

```json
{
  "nat": {
    "nat_gateway": "nat-gateway-prod",
    "mapping_type": "dnat"
  }
}
```

旧字段 `nat.public_ip`、`nat.private_ip`、`external_ip`、`management_ip`、`management_gateway_ip` 和 Host 级 `gateway_ip` 仅兼容读取，不再新增。

## 4. 与资产和连接器的关系

### 4.1 Asset -> Host

资产侧不再使用主机绑定字段。

资产覆盖主机只通过日志来源 IP 表达：

```json
{
  "coverage": {
    "hosts": ["198.51.100.2"]
  }
}
```

平台可用这些 IP 匹配：

- `host.host_ip`
- `host.interfaces[].ip`

### 4.2 Connector -> Host

单主机 connector 可以使用 `config.host_id` 标注物理采集目标：

```json
{
  "connector_id": "conn-ssh-web-01-auth",
  "connector_type": "ssh_file",
  "config": {
    "host": "192.0.2.5",
    "host_id": "host-web-01"
  }
}
```

聚合型 SLS / 平台级 connector 不建议填 `config.host_id`。

### 4.3 Host -> Network

主机通过 `network_id` 关联主地址所属网段：

```json
{
  "host_ip": "192.0.2.5",
  "network_id": "net-prod-web"
}
```

多网卡场景可在 `interfaces[].network_id` 单独声明。

## 5. 最小示例

```json
{
  "host_id": "host-demo-gateway-01",
  "name": "Gateway 主机",
  "hostname": "gateway-host",
  "host_type": "server",
  "host_os": "linux",
  "host_ip": "198.51.100.2",
  "network_id": "net-demo-web-edge",
  "aliases": [
    "gateway",
    "gateway.internal.example"
  ],
  "roles": [
    "syslog-source"
  ],
  "environment": "production",
  "status": "active",
  "tags": [
    "secweaver"
  ]
}
```

## 6. 校验规则

`validate.py` 会重点检查：

- `host_id` 与文件名一致；
- `network_id` 引用存在；
- 可解析的 `host_ip` 是否落入对应 network CIDR；
- `interfaces[].network_id` 引用存在；
- `interfaces[].ip` 是否落入对应 network CIDR；
- `exposure.exposed_ports` 是否为合法端口；
- `asset.coverage.hosts` 是否为 IP。

## 7. 常见错误

| 错误 | 原因 | 建议 |
|---|---|---|
| 在 `coverage.hosts` 写 `web-01` | coverage 只允许日志来源 IP | 改成实际来源 IP，`web-01` 放到 host.aliases |
| 单网卡主机填写空 `interfaces: []` | 无实际信息增益 | 可以不写该字段 |
| `host_ip` 写 hostname | 主地址不可用于 CIDR 校验 | 尽量补真实 IP |
| 聚合 SLS connector 填 `config.host_id` | 容易误解为单主机数据源 | 仅单主机 connector 填 |

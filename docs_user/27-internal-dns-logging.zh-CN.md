# SecWeaver 内网 DNS 查询日志建设指南

**语言：** [English](27-internal-dns-logging.md) | 简体中文（本页）

本文说明如何通过搭建内网集中 DNS 服务器获取 DNS 查询记录，并把日志接入 SecWeaver 的 `dns_log` 资产，用于攻击溯源、C2/下载域名解释、横向移动分析和数据源完整性治理。

## 目标

Linux 主机默认通常不会记录每一次 DNS 查询。依赖每台主机上的 `systemd-resolved` debug、应用日志或临时抓包都不适合作为长期审计数据源。推荐做法是把终端、服务器和容器节点的 DNS 请求统一导向内网 DNS resolver，并在 resolver 侧集中记录查询日志。

目标能力：

1. 记录内网主机发起的 DNS 查询。
2. 保留真实 `client_ip`，便于和 `host_exec`、`host_connect`、`web_access_log`、`network_traffic_audit` 关联。
3. 输出结构化 JSON Lines，接入 SecWeaver 现有 `dns_log` 资产。
4. 以分批方式上线，避免一次性影响全网解析。
5. 禁止开放递归 DNS，只允许内网网段访问。

## 推荐架构

```text
Linux / Windows / 业务主机 / 容器节点
        |
        | DHCP option 6 / resolv.conf / systemd-resolved 指向
        v
内网 DNS Resolver 集群
Unbound 或 BIND，至少两台
        |
        | query log / dnstap
        v
Vector / Filebeat / Fluent Bit
        |
        v
SLS / Elasticsearch / Kafka
        |
        v
SecWeaver dns_log 资产
```

建议至少部署两台 resolver：

```text
dns-01: 10.0.0.53
dns-02: 10.0.0.54
```

客户端通过 DHCP option 6 下发两个 DNS 地址：

```text
10.0.0.53, 10.0.0.54
```

不要一开始就使用普通四层负载均衡做 DNS 前置。普通 LB/NAT 可能导致后端 DNS 服务器只能看到 LB 地址，丢失真实 `client_ip`。如果必须做统一入口，建议使用 `dnsdist` 这类 DNS 专用前置，并在 `dnsdist` 层或支持 EDNS Client Subnet / proxy protocol 的链路上采日志。

## 方案选型

优先级建议：

| 场景 | 推荐组件 | 原因 |
| --- | --- | --- |
| 中小规模内网递归 DNS | Unbound | 配置简洁、递归缓存稳定、查询日志容易开启 |
| 已有 BIND/named 运维体系 | BIND | 适合复杂 zone、权威 DNS、已有 named 经验 |
| 高 QPS、要求低开销审计 | Unbound/BIND + dnstap | 比纯文本日志更适合高吞吐，但解析链路更复杂 |
| 需要 DNS 前置、限速、分流 | dnsdist | 适合统一入口、策略路由、限流和集中日志 |

推荐落地顺序：

1. 第一阶段使用 Unbound 文本 query log 跑通链路。
2. 用 Vector/Filebeat/Fluent Bit 采集日志到 SLS 或 ES。
3. 用 `dns_log` 资产验证查询、关联和报表。
4. QPS 上来后，再升级为 dnstap 或 dnsdist 前置采集。

## SecWeaver 字段契约

SecWeaver 当前已有 `dns_log` 资产类型，最小字段如下：

| 字段 | 要求 | 说明 |
| --- | --- | --- |
| `client_ip` | 必填 | 发起 DNS 查询的内网主机 IP |
| `timestamp` | 必填 | DNS 查询时间 |
| `query` | 必填 | 查询域名 |
| `response` | 强推荐 | DNS 响应结果，建议数组 |
| `query_type` | 推荐 | A、AAAA、CNAME、TXT 等 |
| `rcode` | 推荐 | NOERROR、NXDOMAIN、SERVFAIL 等 |
| `evidence_id` | 推荐 | 稳定证据 ID，便于去重和追踪 |

推荐输出 JSON Lines：

```json
{
  "asset_type": "dns_log",
  "timestamp": "2026-07-09T10:20:30Z",
  "client_ip": "192.0.2.92",
  "server_ip": "10.0.0.53",
  "query": "example.com.",
  "qname": "example.com.",
  "query_type": "A",
  "rcode": "NOERROR",
  "response": ["93.184.216.34"],
  "latency_ms": 8,
  "protocol": "udp",
  "evidence_id": "dns-20260709-102030-192.0.2.92-example.com-A"
}
```

当前仓库中相关资产和模板：

- `dataasset/assets/asset-dns-internal-prod.json`
- `dataasset/configure/evidence-minimum-fields.json`
- `dataasset/query-templates/templates.json`

生产接入时需要把 `asset-dns-internal-prod.json` 中的 `status`、`connector_id`、`coverage.hosts` 和实际 SLS/ES 配置改成生产值。

## Unbound 配置示例

安装：

```bash
sudo apt-get update
sudo apt-get install -y unbound
```

配置文件示例：`/etc/unbound/unbound.conf.d/secweaver-dns.conf`

```conf
server:
  interface: 0.0.0.0
  port: 53

  access-control: 10.0.0.0/8 allow
  access-control: 172.16.0.0/12 allow
  access-control: 192.168.0.0/16 allow
  access-control: 0.0.0.0/0 refuse
  access-control: ::0/0 refuse

  logfile: "/var/log/unbound/query.log"
  log-queries: yes
  log-replies: yes
  log-time-ascii: yes
  verbosity: 1

  hide-identity: yes
  hide-version: yes
  harden-glue: yes
  harden-dnssec-stripped: yes
  qname-minimisation: yes

forward-zone:
  name: "."
  forward-addr: 223.5.5.5
  forward-addr: 119.29.29.29
  forward-addr: 114.114.114.114
```

检查并重启：

```bash
sudo unbound-checkconf
sudo systemctl enable --now unbound
sudo systemctl restart unbound
```

验证：

```bash
dig @10.0.0.53 example.com A
sudo tail -f /var/log/unbound/query.log
```

生产注意：

1. `access-control` 必须只允许内网网段。
2. `forward-addr` 应根据企业网络策略选择内网出口 DNS、运营商 DNS 或可信公共 DNS。
3. 如果内网有私有域名，需要增加对应 `stub-zone` 或 `forward-zone`，不要把内部域名转发到公网。
4. 文本 query log 在高 QPS 下会有 IO 压力，需配合 logrotate 或升级 dnstap。

## BIND 配置示例

适合已有 `named` 运维体系的环境。

查询日志配置示例：

```conf
logging {
  channel query_log {
    file "/var/log/named/query.log" versions 10 size 100m;
    severity info;
    print-time yes;
    print-category yes;
    print-severity yes;
  };

  category queries { query_log; };
};

options {
  recursion yes;
  allow-recursion {
    10.0.0.0/8;
    172.16.0.0/12;
    192.168.0.0/16;
  };
  allow-query {
    10.0.0.0/8;
    172.16.0.0/12;
    192.168.0.0/16;
  };
};
```

临时打开查询日志：

```bash
sudo rndc querylog on
```

关闭：

```bash
sudo rndc querylog off
```

生产建议使用配置文件固定开启，并配好日志轮转。

## 日志采集建议

第一阶段可以使用 Filebeat、Vector 或 Fluent Bit 采文本日志，并在采集端或入库端解析为 JSON Lines。

建议采集端输出字段：

```text
timestamp
client_ip
server_ip
query
qname
query_type
rcode
response
protocol
latency_ms
resolver
raw_line
```

如果使用 SLS：

1. 新建 logstore，例如 `secweaver-dns-internal`。
2. 开启索引字段：`client_ip`、`query`、`qname`、`query_type`、`rcode`、`server_ip`。
3. 时间字段使用 `timestamp`。
4. 在 SecWeaver 的 `asset-dns-internal-prod.json` 中填真实 `connector_id` 和 logstore。

如果使用 Elasticsearch：

1. 建议索引名 `secweaver-dns-*`。
2. `client_ip`、`server_ip` 使用 `ip` 类型。
3. `query`、`qname`、`query_type`、`rcode` 使用 `keyword`。
4. `response` 可以使用 `keyword` 数组。

## 客户端切换方式

Linux 服务器可以通过以下方式切换 DNS：

1. DHCP option 6 下发 `10.0.0.53,10.0.0.54`。
2. 静态服务器修改 `/etc/resolv.conf` 或 NetworkManager 配置。
3. 使用 `systemd-resolved` 的机器，修改对应 link 的 DNS 配置，并确认 `resolvectl status` 生效。
4. Kubernetes 节点需要同步评估 CoreDNS、NodeLocal DNSCache 和 Pod DNS 策略。

不建议直接手工修改大量机器的 `/etc/resolv.conf`，因为 NetworkManager、systemd-resolved、cloud-init 或 DHCP 客户端可能覆盖它。

## 灰度上线计划

建议分四步：

1. 实验环境：只接 1 到 3 台测试服务器，验证解析、日志字段和 SecWeaver 查询模板。
2. 小流量生产：选择一组低风险业务服务器，通过 DHCP 或主机配置指向新 DNS。
3. 分网段推广：按办公网、测试网、生产网、容器节点分批切换。
4. 全量上线：确认容量、延迟、错误率和日志采集稳定后，再切全量。

每一阶段至少观察：

| 指标 | 建议关注点 |
| --- | --- |
| DNS QPS | 是否超过 resolver 和日志采集能力 |
| 解析延迟 | P50/P95/P99 是否明显上升 |
| 错误率 | NXDOMAIN、SERVFAIL、timeout 是否异常 |
| 缓存命中率 | 命中率过低会增加上游压力 |
| 日志延迟 | DNS 查询到 SecWeaver 可检索的延迟 |
| client_ip 完整性 | 是否被 NAT/LB 覆盖 |

## 回滚方案

必须预先准备回滚：

1. DHCP option 6 回退到旧 DNS。
2. 静态服务器恢复原 `/etc/resolv.conf` 或 NetworkManager 配置。
3. 保留旧 DNS 至少一个观察周期，避免缓存和配置传播导致解析异常。
4. 如果是分批上线，只回滚受影响网段，不要全网同时切换。

## 安全要求

1. 禁止开放递归 DNS，只允许内网 CIDR 查询。
2. 防火墙只放行内网到 DNS 服务器的 UDP/TCP 53。
3. DNS 服务器自身应限制 SSH 管理来源。
4. DNS 查询日志属于敏感行为数据，需要控制访问权限和保留周期。
5. 日志中可能包含内部系统域名、第三方 SaaS 访问、研发测试域名，导出和共享前需要脱敏。

## SecWeaver 后续开发建议

建议在 `secweaver-agent` 中新增 `dns-log-json` 模块，统一解析以下来源：

1. Unbound query log。
2. BIND query log。
3. dnsmasq query log。
4. dnstap 转储输出。

模块输出统一 `dns_log` JSON Lines，字段与本文的 SecWeaver 字段契约保持一致。这样运营侧只需要把 DNS 日志接进来，平台就能直接做：

1. `host_connect` 到 `dns_log` 的域名解释。
2. 攻击 IP/受害主机的 DNS 查询回溯。
3. 可疑域名、DGA、动态 DNS、矿池域名识别。
4. 数据源完整性检查，判断某个网段 DNS 日志是否覆盖。

# Agent 接入自建 Elasticsearch

**语言：** [English](README.md) | 简体中文（本文）

默认推荐使用 [SaaS SLS Proxy](../../../../docs_user/30-sls-proxy-onboarding.zh-CN.md)，
需要采集主机日志时按 [Data Cloud 快速上手](../../../../docs_user/29-secweaver-data-system-quickstart.zh-CN.md)
取得平台安装命令。平台负责 SLS 存储、字段治理和升级发布。

只有已有 ES、数据必须自管或希望自己维护输送器时，才使用本文：

```text
Linux Agent -> 本地 JSONL -> Filebeat -> 客户 Elasticsearch
                                      <- DataAsset 只读查询 <- AI Skills
```

本目录完整随 Community 发布，不需要 `secweaver-es-operator`、私有资产目录或服务端源码。
它不是 ES 安装器、托管服务替代品或生产容量保证；不会替客户安装 ES、签发 SaaS 租户、
创建用户或管理备份。不要在已加入 SaaS 的主机上使用独立安装脚本。

## 适用范围与前提

- 本接入配置面向 Linux systemd 主机、Elasticsearch 8.x 与 Filebeat 8.19.x。按 Elastic
  支持策略选择仍受维护的补丁版本；不要直接套用到 OpenSearch、ES 9 或 Windows。
- Agent 采集平台与内核前提见[工程手册](../README.zh-CN.md)。
  源码构建需要 Go 1.22+、Make；初始化脚本需要 Python 3.10+。Filebeat 由客户从 Elastic 安装，
  不随 Agent 或本目录提供二进制。Linux 审计依赖需预先安装，且不能与现有审计策略冲突。
- ES 已启用 HTTPS 和认证，主机时钟同步；准备匹配域名的 CA、至少三个独立账号：
  初始化管理员、Filebeat 写入账号、DataAsset 只读账号。只允许所需主机访问 ES。
- 本仓库测试覆盖模板、脚本请求、安全限制和配置契约；上线前必须在目标 Linux/ES
  环境执行下方真实验收，不能将单元测试当作吞吐、兼容性或不丢日志承诺。

## 1. 初始化 ES

在仓库根目录执行。默认只输出模板，完全离线，不修改 ES：

```bash
python3 src/tools/secweaver-agent/elasticsearch/init_es.py
```

管理员需要集群 `manage_index_templates` 及版本读取权限。在线执行会隐藏提示输入密码，
不把密码写入命令或配置；自动化可注入 `SECWEAVER_ES_PASSWORD`，使用后清除环境变量。

```bash
python3 src/tools/secweaver-agent/elasticsearch/init_es.py --apply \
  --endpoint https://es.example.com:9200 \
  --ca-file /absolute/path/es-ca.crt --username setup_admin
```

只创建 `secweaver-public-agent-v1` 索引模板，匹配 `secweaver-public-agent-*`。
相同配置重复运行不写入；不同配置拒绝覆盖；并发创建使用 `create=true` 防止覆盖。
失败不删除任何资源。模板只影响后续新索引，不迁移旧索引，也不覆盖其他模板。
如果其他更高优先级模板命中该前缀，由管理员先评估冲突。

默认一个主分片、一个副本。**单节点测试 ES** 可加 `--replicas 0`；无副本不适合需要
高可用的生产数据。更改副本参数后重跑会拒绝覆盖，需管理员审阅已有模板再修改。
集群必须允许写入账号自动创建此专用前缀下的每日索引；脚本不修改全局自动建索引策略。

由管理员通过现有 IAM 流程创建两种索引角色，再分别绑定不同用户。下面是角色 API 的请求体，
不是可直接导入 DataAsset 的 JSON：

```json
{
  "cluster": ["monitor"],
  "indices": [{
    "names": ["secweaver-public-agent-*"],
    "privileges": ["auto_configure", "create_doc"]
  }]
}
```

上面用于 Filebeat 写入；下面用于 DataAsset 和验收查询。`monitor` 用于版本/健康探测，
它是集群范围权限；严格隔离环境由管理员评估后进一步限制，而不要给写入端超级用户权限。

```json
{
  "cluster": ["monitor"],
  "indices": [{
    "names": ["secweaver-public-agent-*"],
    "privileges": ["read", "view_index_metadata"]
  }]
}
```

## 2. 安装独立 Agent

在目标 Linux 主机准备好公开源码和采集依赖，构建前审核代码。以下命令不创建新发布包：

```bash
make -C src/tools/secweaver-agent build
sudo bash src/tools/secweaver-agent/elasticsearch/install-agent.sh \
  "$PWD/src/tools/secweaver-agent/secweaver-agent" SECWEAVERLOCAL01
```

`SECWEAVERLOCAL01` 是 16 位本地分组示例，可换成自己的 16 位大写字母/数字标识。
它**不是 SaaS 企业身份，也不提供 ES 租户隔离**。多个租户需要独立索引权限和部署边界。

安装器只支持全新主机：拒绝已有 `/opt/secweaver-agent` 或已有同名服务，不覆盖旧数据。
它安装配置和 systemd unit，但**不会自动启动**。新建配置中授权、远程配置和自动升级均关闭，
不连接托管控制面。发生安装失败时保留部分文件供检查，不自动清理；不要通过反复删除目录
处理一台已有身份或日志的主机。

审核 `/opt/secweaver-agent/etc/` 下三份 JSON，确认采集范围、磁盘预算和审计规则符合本机要求：

```bash
sudo /opt/secweaver-agent/bin/secweaver-agent preflight \
  -config /opt/secweaver-agent/etc/config.json -strict
sudo systemctl enable --now secweaver-agent
sudo systemctl status secweaver-agent --no-pager
sudo journalctl -u secweaver-agent -n 50 --no-pager
sudo ls -l /opt/secweaver-agent/logs/
```

预检失败先修复，不继续启用服务。需要 `auditd`/net-tools 的发行版应按工程手册准备，
容器内缺少智能体权限不等同于完整主机采集。

## 3. 安装并配置 Filebeat

按 [Elastic 安装步骤](https://www.elastic.co/guide/en/beats/filebeat/8.19/filebeat-installation-configuration.html)
独立安装 Filebeat。以下使用 deb/rpm 包默认服务和路径，并假定本机没有正在采集其他业务的 Filebeat。
已有 Filebeat 时由管理员合并 input 和 output，不能覆盖业务配置或启动两个重复读取同一日志的实例。

本目录的 [filebeat.yml](filebeat.yml) 使用 JSON 形式的合法 YAML，方便机器校验和原样安装。
它包含六种默认日志及轮转文件；不要更改已运行 input 的 ID，也不要清除 Filebeat registry。

```bash
sudo install -m 0644 /absolute/path/es-ca.crt /etc/filebeat/secweaver-es-ca.crt
sudo install -m 0600 src/tools/secweaver-agent/elasticsearch/filebeat.yml /etc/filebeat/secweaver-agent.yml
sudo filebeat keystore create
sudo filebeat keystore add SECWEAVER_ES_URL
sudo filebeat keystore add SECWEAVER_ES_CA
sudo filebeat keystore add SECWEAVER_ES_WRITER_USER
sudo filebeat keystore add SECWEAVER_ES_WRITER_PASSWORD
```

依次输入 `https://es.example.com:9200`、`/etc/filebeat/secweaver-es-ca.crt`、写入账号和密码。
已有 keystore 时跳过 create，不使用 `--force` 覆盖整个 keystore；轮换单个值时按 Elastic 指引操作。
所有命令和服务必须使用相同的 `path.data`，否则可能无法找到密钥或重复读取日志。

先验证新配置，不替换服务的默认配置：

```bash
sudo filebeat test config -c /etc/filebeat/secweaver-agent.yml -e
sudo filebeat test output -c /etc/filebeat/secweaver-agent.yml -e
```

验证成功后，由管理员备份已有 `/etc/filebeat/filebeat.yml`，再将新配置用于该专用 Filebeat 服务：

```bash
sudo install -m 0600 /etc/filebeat/secweaver-agent.yml /etc/filebeat/filebeat.yml
sudo systemctl enable --now filebeat
sudo systemctl restart filebeat
sudo journalctl -u filebeat -n 50 --no-pager
```

默认 root 服务可读取 Agent 的受限日志目录。不要为方便输送而将安全日志目录改成全局可读。
配置先移除 Filebeat 的 ECS 主机元数据，再在根层解析 Agent JSON，保留原始 `host` 字符串，
避免 ECS `host.name` 与 Agent `host` 类型冲突。`time`/`timestamp` 转换为事件 `@timestamp`；
缺失或格式异常会退回采集时间，因此验收必须核对时间和解析错误，不能只看条数。

## 4. 验收并登记 DataAsset

保持 Agent 运行，等待首次进程/状态快照；在授权测试主机上执行一条无害命令，例如 `/usr/bin/id`。
在 Filebeat 和 ES 错误日志中确认没有认证、JSON 解码、mapping、只读磁盘水位或 Bulk 写入失败。
使用只读账号检查最近 30 分钟的事件，脚本不输出原始命令或敏感日志：

```bash
python3 src/tools/secweaver-agent/elasticsearch/init_es.py --check \
  --endpoint https://es.example.com:9200 \
  --ca-file /absolute/path/es-ca.crt --username secweaver_reader
```

检查有任一数据集即通过连通性验收，**不代表所有模块正常**。无近期事件、搜索超时或分片失败
均返回非零状态。风险/持久化日志可能在没有事件时为空；逐项核对已启用模块，按授权测试事件验证。

接下来在运行 智能体的分析电脑上准备配置，不必在每台采集主机重复登记。
按[资产目录准备](../../../../docs_user/03-configure-data-sources.zh-CN.md#准备资产目录)选择默认 `dataasset/`，也可复制到 `dataasset_my/` 隔离。CLI、UI 和智能体使用同一根目录。复制完成后使用 `export DATAASSET_ROOT=dataasset_my`；默认目录使用 `export DATAASSET_ROOT=dataasset`。
在 UI 凭证页保存 ES 只读账号，引用为 `vault://es/security-readonly`。
一键 ES 向导默认校验证书，私有 CA 需设置 `ca_file`；不要把 Filebeat 写入账号或初始化管理员交给 AI。

公开的 [DataAsset 接入配置](dataasset-source.example.json)可生成命令执行日志的三件套，
默认 `draft`，并显式启用 `tls_verify: true`。从仓库根目录执行：

```bash
export DATAASSET_ROOT="${DATAASSET_ROOT:-dataasset}"
cp -n src/tools/secweaver-agent/elasticsearch/dataasset-source.example.json "${DATAASSET_ROOT}/agent-es-source.json"
.venv/bin/python src/secweaver.py asset apply -f "${DATAASSET_ROOT}/agent-es-source.json" --output-dir "$DATAASSET_ROOT" --dry-run
```

先编辑本地 `agent-es-source.json` 的 ES 地址、保留天数、实际字段；使用私有 CA 时在
`connector.config` 添加 `ca_file`，路径相对于所选资产根目录。命令中的 `--output-dir` 覆盖样例自带的输出目录，避免写到另一个根目录。
`cp -n` 保留已有配置。预览确认后，去掉 `--dry-run` 生成文件；不使用 `--force` 覆盖已有资产。
该生成步骤不查询 ES、不验证凭证，也不自动启用资产。
查询覆盖通过替换生成模板的 `bool.must` 列表移除默认 WAF IP 过滤，只保留时间范围。
修改示例时保留此结构；直接增加另一个顶层 query 条件会与旧过滤深度合并，而非替换。

先用 `asset-local-agent-exec` 验收第一份日志；其他类型复制本地配置中的数据源条目，
分别使用新的 Asset、Connector、Template ID 和下表索引，并核对字段及类型过滤条件。
时间字段选择 `@timestamp`，不要将混合类型总索引登记成单一资产。

| 索引模式 | 建议资产类型 |
|---|---|
| `secweaver-public-agent-exec-*` | `host_exec` |
| `secweaver-public-agent-behavior-learning-*` | `host_behavior_summary`，仅摘要/状态，见[学习指南](../docs/behavior-learning.zh-CN.md) |
| `secweaver-public-agent-connect-*` | `host_connect` |
| `secweaver-public-agent-file-op-*` | `host_file_op` |
| `secweaver-public-agent-host-persistence-*` | `host_persistence` |
| `secweaver-public-agent-syslog-risk-json-*` | `syslog_risk_alert` |
| `secweaver-public-agent-host-process-snapshot-*` | `host_process` |
| `secweaver-public-agent-host-state-snapshot-*` | 按 `asset_type` 分别建资产，并在查询模板加类型过滤 |

未识别的审计事件保留在 `secweaver-public-agent-audit-port-execmon-*`，应审核后再纳入场景。
模板的 `dynamic: false` 保留未知字段于 `_source`，但它们不可用于搜索/聚合；需要扩展时先明确
字段契约，再修改模板并迁移或重建相关索引。不能仅在 UI 添加字段名便认为 ES 已索引该字段。

接入成功后，确认字段别名、运行 `asset test`，再加入调查 Bundle：

例如主动外连资产的 `field_aliases` 使用 `connect_address` → `dst_ip`、`connect_port` →
`dst_port`；系统风险日志使用 `host_name` → `host`。别名方向为“原始字段 → 标准字段”。
若自行增加按 IP/端口检索的 ES 查询模板，过滤条件使用实际已索引的原始字段，别名不会
在 ES 中自动创建字段。主机状态资产的 ES query 还需添加 `term` 条件限定具体 `asset_type`，
例如 `host_socket`、`host_identity`、`host_service`、`host_kernel_context`。

```bash
.venv/bin/python src/secweaver.py asset test <asset_id>
make validate
```

`<asset_id>` 使用生成结果中的实际 ID（第一份为 `asset-local-agent-exec`），
并通过 `--params` 提供已知测试事件的准确 `time_start`、`time_end` 和 `limit`。
确认返回已知事件后才把 Connector 和 Asset 改为 `active`，加入实际调查 Bundle，
再运行 `.venv/bin/python src/dataasset/validate.py --sync-catalog` 和 `make validate`。

最后向 AI 提供测试主机及准确时间窗，运行风险识别或溯源分析，核对报告能引用刚采集的事件，
并如实报告 WAF、访问日志等仍未接入的证据缺口。

## 运维边界

- 索引按 UTC 事件日期分隔；Filebeat 自带模板和 ILM 均关闭，**默认不会删除 ES 数据**。
  上线前由客户设置保留策略、容量告警、快照和恢复演练。示例分片数不是容量建议。
- Filebeat 使用最大 1 GB 磁盘队列，需为其 `path.data` 预留额外空间；Agent 有独立本地磁盘预算。
  长时间断网、队列满和日志轮转仍可能丢失数据。重试提供至少一次传输，可能重复，不保证 exactly-once。
- 重启保留 registry、Agent data 和日志；TLS/401/403 查 CA 与权限，400 查映射和原始字段，
  429 查集群压力。不使用 `verification_mode: none` 规避问题。
- 自建链路由客户负责升级。升级前备份二进制和配置，停止服务后替换经审核的新版本，保留原身份和 data，
  重新预检及验收；失败恢复旧二进制。此独立配置没有自动升级或 SaaS 灰度保障。
- [Filebeat filestream](https://www.elastic.co/guide/en/beats/filebeat/8.19/filebeat-input-filestream.html)、
  [ES output](https://www.elastic.co/guide/en/beats/filebeat/8.19/elasticsearch-output.html)
  和 [index templates](https://www.elastic.co/docs/manage-data/data-store/templates) 是对应上游参考。

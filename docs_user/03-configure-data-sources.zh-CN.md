# 03. 如何配置数据源

**语言：** [English](03-configure-data-sources.md) | 简体中文（本文）

本文配置已有日志的只读查询，不安装 ES、SLS 或主机采集端。
首次体验先完成[离线快速上手](00-security-operator-quickstart.zh-CN.md)，不必先阅读本文。

## 选择接入路径

| 当前情况 | 操作 |
|---|---|
| Community 本地客户端使用 SaaS（推荐） | 按 [SLS Proxy 接入](30-sls-proxy-onboarding.zh-CN.md)配置平台签发的查询凭证和资产 |
| 管理员已经配好分析环境 | 按 [Data Cloud 快速上手](29-secweaver-data-system-quickstart.zh-CN.md)直接调查，不重复创建凭证 |
| 已有 Elasticsearch/OpenSearch 日志 | 完成下面的本地目录准备，再配置 ES 只读查询 |
| 自己管理阿里云 SLS | 完成目录准备，再按本文 SLS 示例配置 |
| 数据在 MySQL、PostgreSQL、Oracle、SQL Server 或 SQLite | 使用 `database_ro` Connector、只读账号和对应数据库的查询模板，再按下方通用流程验收 |
| 日志位于 SSH 可访问文件或本机文件 | 使用后文 SSH/本地文件模板和验收步骤 |
| 日志来自云服务、SIEM、EDR 或 HTTP API | 从 `dataasset/onboarding/examples/` 开始；只有运行时明确支持时才使用外部 Connector 或 plugin |
| 尚未采集主机日志 | SaaS 用户按 Data Cloud 指南安装；自建 ES 用户按[独立 Agent 接入指南](../src/tools/secweaver-agent/elasticsearch/README.zh-CN.md)操作 |

先确认日志类型、存储位置、真实时间字段和调查所需字段。
Network、Host 仅在需要登记网段和主机覆盖时添加，不是平台型 WAF 日志接入的强制前置步骤。

## 准备资产目录

使用 Linux/macOS POSIX 终端或 WSL2，安装 Python 3.10+ 和 Make。Windows 用户须先完成
[WSL2 快速上手](00-security-operator-quickstart.zh-CN.md)；原生 Windows 不是受支持的
Community 查询客户端环境。保存查询凭证需要 SOPS 和 age，见
[凭证指南](../dataasset/credentials/README.zh-CN.md)。从仓库根目录执行：

```bash
make quickstart
source .venv/bin/activate
export DATAASSET_ROOT=dataasset
```

默认直接编辑 `dataasset/`。如需把本地配置与仓库样例隔离，可在写入配置和凭证前选择以下可选步骤：

```bash
if [ ! -e dataasset_my ]; then
  cp -R dataasset dataasset_my
fi
export DATAASSET_ROOT=dataasset_my
```

已有 `dataasset_my/` 保留原样。选择隔离目录后，后文配置路径中的 `dataasset/` 均替换为 `dataasset_my/`；`src/dataasset/` 是程序目录，不替换。
CLI、UI 和智能体必须使用同一资产根目录；新终端重新设置所选 `DATAASSET_ROOT` 并激活虚拟环境，桌面智能体不继承变量时在任务中明确指定。
无论选择哪个目录，Connector JSON 只保存凭证引用；真实密钥、私钥、加密凭证和客户配置不要提交公开仓库。

启动配置页面：

```bash
make ui
```

打开 `http://127.0.0.1:8765/`。UI 用于管理配置，不是 AI 分析聊天界面。它持续占用当前终端；在独立终端运行，或按 Ctrl+C 停止后执行后文命令。在“凭证”页初始化凭证环境并创建只读凭证。

## 完整接入流程

所有数据源都遵循下面的生命周期。后文 ES、SLS、SSH 和本地文件章节提供各自的
配置值，但状态流转和验收要求相同。

```text
选择资产目录并确认源信息
    -> 创建只读凭证引用和 Connector
    -> 未知格式用 discovery、已知格式用 draft 创建 Asset
    -> 必要时发现字段并人工审阅
    -> 校验配置并预览查询
    -> 在授权范围内实查一条已知事件
    -> Connector 和 Asset 晋升 active，再加入 Bundle
```

### 1. 确认数据源契约

记录日志类型、地址或文件路径、授权范围、真实时间字段、保留周期、样例事件、
预期规范字段和精确测试时间窗。不要仅凭名字相似的样例 Asset 推断这些值。

### 2. 登记 Connector 和凭证引用

在本地 Vault 或 Studio“凭证”页创建凭证。Connector JSON 只保存 `vault://...`
引用和非敏感连接参数：

仅使用 CLI 时按[凭证指南](../dataasset/credentials/README.zh-CN.md)操作。只有本地 Vault
尚不存在时才初始化，再编辑所需的只读凭证引用；不要重新生成已有 age key，也不要覆盖
已有 SOPS 策略：

```bash
bash src/dataasset/credentials/sops-vault.sh init
bash src/dataasset/credentials/sops-vault.sh edit vault://sls/your-readonly
```

| `connector_type` | 常见非敏感参数 |
|---|---|
| `sls` | endpoint、region、project、logstore |
| `es` | HTTPS URL、索引、时间字段、必要时的 CA 路径 |
| `ssh_file` | host、port、允许读取的日志路径 |
| `local_file` | base path、日志路径、hostname；无需 Vault |
| `database_ro` | engine、host、database、只读查询范围 |
| `http_api` | HTTPS base URL、endpoint 允许列表、必要时的 CA 路径 |
| `aws_s3_logs` | bucket、可选 prefix 和 region |
| `azure_monitor` | workspace ID、可选 tenant ID |
| `gcp_logging` | project ID |
| `tencent_cls` | endpoint、topic ID、region |
| `huawei_lts` | HTTPS endpoint、log group ID、log stream ID、project ID |
| `splunk` | HTTPS base URL、index、必要时的 CA 路径 |

新 Connector 保持 `draft`。密码、AccessKey、私钥和令牌不得写入 Connector JSON、
接入文件或智能体对话。

远程 ES、HTTP API、Splunk 和外部执行器必须直接配置最终 HTTPS 地址；运行时不跟随
HTTP 重定向。明文 HTTP 只允许 `localhost`、`127.0.0.1` 或 `::1` 回环联调。
私有 CA 使用 `ca_file`，相对路径从 `DATAASSET_ROOT` 解析；不能通过
`tls_verify: false` 或 `verify_tls: false` 绕过证书校验。`credentials_ref` 必须使用
`vault://namespace/name`，禁止空路径段、`.` 和 `..`。
相对 `ca_file` 解析后必须仍位于 `DATAASSET_ROOT` 内，符号链接也不能指向目录外；
由系统管理员维护的 CA 可使用绝对路径。

### 3. 登记逻辑 Asset

在选定资产目录的 `assets/{asset_id}.json` 创建 Asset，并绑定 Connector。
原始格式或字段映射未知时使用 `status: discovery`；只有格式、parser、字段和查询模板
都已明确时才直接使用 `draft`。

```jsonc
{
  "asset_id": "asset-my-new-log",
  "name": "My new log",
  "asset_type": "waf_alert",
  "domain": "D1",
  "status": "discovery",
  "connector_id": "conn-my-new-log",
  "schema": {
    "fields": ["timestamp", "src_ip", "url"],
    "time_field": "timestamp",
    "retention_days": 30
  },
  "query_template_ids": [],
  "coverage": {"zones": [], "apps": [], "hosts": []}
}
```

Asset 处于 `discovery` 时，初始字段可以不完整，但不能加入生产 Bundle 或直接设为 active。

### 4. 发现字段并写入审阅后的映射

未知格式先准备脱敏且具有代表性的样本，再按[日志格式发现](20-log-format-discovery.zh-CN.md)
操作。字段检查、`text_parser` 选择、`field_aliases`、查询字段映射、预览和审阅后写回
都归该文档说明。完成后把 Asset 从 `discovery` 晋升为 `draft`。

已知格式可以跳过发现步骤，但仍需核对真实源字段。配置完成后，运行时归一化是确定性的，
不会为每条事件调用大模型。

### 5. 预览、应用并审阅生成配置

使用接入文件时，先预览写入内容并检查差异：

```bash
.venv/bin/python src/secweaver.py asset apply --output-dir "$DATAASSET_ROOT" \
  -f /tmp/my-source.json --dry-run
.venv/bin/python src/secweaver.py asset diff --output-dir "$DATAASSET_ROOT" \
  -f /tmp/my-source.json
.venv/bin/python src/secweaver.py asset apply --output-dir "$DATAASSET_ROOT" \
  -f /tmp/my-source.json
```

如果已应用的接入包有误，先预览受控回退：

```bash
.venv/bin/python src/secweaver.py asset rollback --output-dir "$DATAASSET_ROOT" \
  -f /tmp/my-source.json --dry-run
```

回退只处理该文件生成的 Connector、Asset 和查询模板。不要手工删除生产 active 对象；
只有预览确认对象正确后才使用 `--confirm-delete`。

### 6. 校验、实查和启用

先执行 Schema/catalog 校验，再预览查询计划。实查前把示例值换成授权范围内的已知事件：

```bash
.venv/bin/python src/dataasset/validate.py --sync-catalog
.venv/bin/python src/dataasset/test_connector.py asset-my-new-log --by-asset \
  --plan --dry-run
.venv/bin/python src/dataasset/test_connector.py asset-my-new-log --by-asset \
  --params '{"src_ip":"203.0.113.10","time_start":"2026-09-08T00:00:00Z","time_end":"2026-09-08T00:05:00Z","limit":10}'
```

验收要求命令成功、后端和时间窗正确、返回已知事件、归一化后的规范字段正确，并且
证据引用可用。空结果不算验收通过。校验错误按[日常运营检查与排错](09-operations-troubleshooting.zh-CN.md)
处理。

上述检查通过后，Connector 和 Asset 才能设为 `active`。只把已验证 Asset 加入 Bundle，
重新校验，并在调查前执行完整性检查。运行时会按审阅后的配置自动完成取数、解析、别名、
时间归一化、脱敏和 `evidence_id` 生成。

## 已有 Elasticsearch：使用一键接入

浏览器向导在探测与激活时均校验 HTTPS 服务端证书，生成的 Connector 使用
`tls_verify: true`。私有 CA 通过 `ca_file` 指定，相对路径以 `DATAASSET_ROOT` 为基准。
未知 CA、证书过期或主机名不匹配时连接失败，不会自动关闭校验重试。
即使绕过向导手工写入 `tls_verify: false`，Schema、上线校验和 ES 运行时也会拒绝。
接入前向 ES 管理员取得只读账号和 CA。

在 `http://127.0.0.1:8765/onboarding.html` 打开“接入客户自有 Elasticsearch”，
依次检测集群、选择索引、识别字段并激活。搜索成功不代表字段关联、事件覆盖或生产容量
验收通过；正式调查前仍需完成下方检查。另见[取数完整性与脱敏说明](community-release-and-data-safety.zh-CN.md)。

### 生产 ES：显式配置只读查询

1. 向 ES 管理员取得 HTTPS 地址、获授权的索引、真实时间字段、只读账号和必要的 CA 文件。
2. 在本地 UI 的“凭证”页创建 `vault://es/security-readonly`，类型为 `es`。
3. 在所选资产目录编辑 `connectors/conn-es-waf-prod.json`。下面是完整 Connector 示例，
   替换地址和索引；使用私有 CA 时添加 `ca_file`，相对路径以 `DATAASSET_ROOT` 为基准。

```json
{
  "connector_id": "conn-es-waf-prod",
  "name": "Customer WAF Elasticsearch",
  "connector_type": "es",
  "status": "draft",
  "credentials_ref": "vault://es/security-readonly",
  "config": {
    "url": "https://es.example.com:9200",
    "index": "logs-waf-*",
    "time_field": "@timestamp",
    "tls_verify": true
  }
}
```

使用系统信任库时不需要 `ca_file`；私有 CA 示例值为 `credentials/ca/customer-es.pem`。
相对路径和符号链接不得越出 `DATAASSET_ROOT`；系统级 CA 文件可使用绝对路径。
不要用关闭证书校验排错，也不要使用初始化管理员或 Filebeat 写入账号查询。

4. 编辑已有 `assets/asset-es-waf-prod.json`，核对字段、别名、保留天数和
   `waf_es_by_src_ip_time` 模板。该模板的源字段必须与实际索引一致；非 WAF 数据不要照搬。
5. 按下方“查询验收与启用”验证后再启用。OpenSearch 需在目标版本验证查询兼容性；
   这里仅配置查询，不承诺 Agent 输送器支持 OpenSearch。

## 直连阿里云 SLS

只有自己管理 SLS Project 和 RAM 只读权限时才走本节；Proxy Key 不能代替 RAM Key，
SaaS 用户应回到 [SLS Proxy 指南](30-sls-proxy-onboarding.zh-CN.md)。

在凭证页创建 `vault://sls/security-readonly`，类型为 `aliyun_ram`。
在所选资产目录编辑 `connectors/conn-sls-waf-prod.json`，替换地域 endpoint、Project 和 Logstore：

```json
{
  "connector_id": "conn-sls-waf-prod",
  "name": "Customer WAF SLS",
  "connector_type": "sls",
  "credentials_ref": "vault://sls/security-readonly",
  "config": {
    "endpoint": "cn-hangzhou.log.aliyuncs.com",
    "region": "cn-hangzhou",
    "project": "YOUR_SLS_PROJECT",
    "logstore": "YOUR_WAF_LOGSTORE"
  },
  "status": "draft"
}
```

确认上游已有日志，且查询字段已建立 SLS 索引。SecWeaver 不创建 Project、Logstore 或 RAM 权限。

## 配置 Asset

Asset 表示“这份日志是什么、有哪些字段、如何查询”。下面是 SLS WAF 的完整结构示例，
对应所选资产目录 `assets/asset-waf-prod-01.json`，不是所有日志都可以直接套用：

```json
{
  "asset_id": "asset-waf-prod-01",
  "name": "Customer WAF alerts",
  "asset_type": "waf_alert",
  "domain": "D1",
  "connector_id": "conn-sls-waf-prod",
  "coverage": {"hosts": []},
  "schema": {
    "fields": ["timestamp", "src_ip", "url", "action", "rule_id", "payload"],
    "time_field": "timestamp",
    "retention_days": 30
  },
  "field_aliases": {
    "client_ip": "src_ip",
    "remote_addr": "src_ip",
    "request_uri": "url",
    "path": "url"
  },
  "query_template_ids": ["waf_gateway_plugin_by_ip_time"],
  "status": "draft"
}
```

`domain` 使用 D1～D7；`schema.time_field` 必填。保留天数填写上游真实保留期，
修改此元数据不会改变 ES/SLS 的数据删除策略。

`field_aliases` 在取回数据后把源字段映射到规范字段；查询模板仍必须使用上游真实可检索字段。
完整的源字段、parser、别名和查询层模型统一见
[日志格式发现](20-log-format-discovery.zh-CN.md#字段发现与归一化模型)。

未知格式先设为 `discovery`，按[日志格式发现](20-log-format-discovery.zh-CN.md)
检查脱敏样本，确认后转为 `draft`。
更多 Host、Network 和字段约束见 [DataAsset Schema](../dataasset/schema/)。

<a id="ssh-and-local-files"></a>

## SSH 与本地日志文件：最小接入

先完成上方的本地目录准备，并保持所选 `DATAASSET_ROOT`。以下步骤适用于 Linux/macOS/WSL2 查询端上的 `syslog_auth` 文本认证日志；JSON、Windows 事件或其他格式需要选择匹配的解析器。SSH 查询还需要目标主机的日志读取权限、SSH 网络连通性，以及凭证库中 `type: ssh` 的只读账号；字段见[SSH 凭证说明](../dataasset/credentials/README.zh-CN.md)。

从[SSH 文件模板](../dataasset/onboarding/ssh_file/)或[本地文件模板](../dataasset/onboarding/local_file/)开始。下方命令只复制到不存在的文件，避免覆盖已有配置；选择所需的一组执行：

```bash
# SSH 文件
cp -n dataasset/onboarding/ssh_file/connector.json "${DATAASSET_ROOT}/connectors/conn-my-ssh-auth.json"
cp -n dataasset/onboarding/ssh_file/asset.json "${DATAASSET_ROOT}/assets/asset-my-ssh-auth.json"

# 本地文件
cp -n dataasset/onboarding/local_file/connector.json "${DATAASSET_ROOT}/connectors/conn-my-local-auth.json"
cp -n dataasset/onboarding/local_file/asset.json "${DATAASSET_ROOT}/assets/asset-my-local-auth.json"
```

编辑复制后的 JSON，将模板占位符替换为以下配置：

| 字段 | SSH 文件 | 本地文件 |
|---|---|---|
| Connector 的 `connector_id` | `conn-my-ssh-auth` | `conn-my-local-auth` |
| Asset 的 `asset_id` | `asset-my-ssh-auth` | `asset-my-local-auth` |
| Asset 的 `connector_id` | `conn-my-ssh-auth` | `conn-my-local-auth` |
| 连接与路径 | `config.host` 填目标主机；`config.port` 填 SSH 端口；`config.log_paths.ssh_auth` 填可读取的绝对路径 | `config.base_path` 填本地日志目录的绝对路径；`config.log_paths.ssh_auth` 填该目录下的文件名 |
| 查询模板 | `query_template_ids` 改为 `["ssh_file_grep_auth"]` | `query_template_ids` 设为 `["local_file_grep_auth"]` |
| 凭证 | `credentials_ref` 使用已创建的 `vault://ssh/readonly`；密码/私钥只保存在 Vault | 不需要 SSH 凭证；由运行查询的本地用户读取文件 |

保持 `text_parser: "syslog_auth"`；按真实来源填写 `config.hostname`（本地）、保留天数和覆盖信息。SSH Asset 的 `coverage.hosts` 填实际日志来源 IP，与 Host 的 `host_ip` 或 `interfaces[].ip` 对应，不填 Host ID 或主机名；来源尚未确认时先设为空数组，后续完整性预检会反映覆盖缺口。Connector 和 Asset 均保持 `draft`，验证后再按下方“查询验收与启用”晋级。不要直接使用 SSH 模板中的 `ssh_auth_by_src_ip_time`：它用于 SLS/数据库，文件查询应使用上述 `ssh_file_grep_auth`。

先预览，不解密凭证或连接远端；路径必须与 Connector 允许读取的日志文件一致：

```bash
.venv/bin/python src/dataasset/test_connector.py asset-my-ssh-auth --by-asset --dry-run \
  --params '{"grep_pattern":"203.0.113.10","log_path":"/var/log/auth.log","max_lines":100}'

.venv/bin/python src/dataasset/test_connector.py asset-my-local-auth --by-asset --dry-run \
  --params '{"grep_pattern":"203.0.113.10","log_path":"auth.log","max_lines":100}'
```

把示例 IP 和文件名换成已授权的已知测试事件，去掉对应命令的 `--dry-run` 后执行读取。确认返回该事件，且 `host`、`timestamp`、`src_ip`、`user`、`result` 与原日志一致。空结果不能作为验收通过。

这两个模板按受约束的正则表达式匹配并保留最后 `max_lines` 行（例如 IP 中的点仍是正则通配符，返回后须核对 `src_ip`），**不会自动按 `time_start/time_end` 筛选**。应使用范围明确的日志片段，核对事件时间、时区、年份与轮转文件；本次读取不能证明整个调查时间窗没有其他事件。本地文件查询在 SecWeaver 所在机器执行，不会读取远端路径。

## 查询验收与启用

以下以 SLS WAF 为例。ES 用户将资产 ID 换成 `asset-es-waf-prod`。
先用真实目标和准确时间窗替换参数值；下面保留地址和日期仅用于离线预览：

```bash
.venv/bin/python src/dataasset/validate.py --sync-catalog
.venv/bin/python src/dataasset/test_connector.py asset-waf-prod-01 --by-asset \
  --dry-run --params '{"src_ip":"203.0.113.10","time_start":"2026-09-08T00:00:00Z","time_end":"2026-09-08T00:05:00Z","limit":10}'
```

确认实际索引/Logstore、模板及过滤字段后，替换成授权测试事件的 IP 和时间窗，
去掉 `--dry-run` 执行真实查询。不要把样例固定日期直接用于生产验收。

验收必须同时满足：命令无错误、返回已知测试事件、目标与时间正确、标准字段和证据引用可用。
空结果不代表成功，也不代表没有攻击；先检查时间、权限、字段、索引和上传延迟。

只有真实查询与字段验证通过后，才把 Connector 和 Asset 改为 `active`；
只将已验证资产加入调查 Bundle，再运行：

```bash
.venv/bin/python src/dataasset/validate.py --sync-catalog
make validate
```

公开副本中未配置的示例不是生产资产；不要批量启用或加入生产 Bundle。
UI 列表中存在配置、Schema 通过、查询成功和证据完整是四件不同的事。

最后向 AI 指定所选 `DATAASSET_ROOT`、实际 Asset/Bundle、目标与带时区的起止时间，
先运行[完整性预检](15-data-source-completeness.zh-CN.md)，再选择告警确认、风险识别或溯源。
凭证不进入对话；缺数据时如实记录缺口。

## 采集与进阶

- 新增主机日志：[SaaS Agent 安装](29-secweaver-data-system-quickstart.zh-CN.md)、
  [Agent 写入自建 ES](../src/tools/secweaver-agent/elasticsearch/README.zh-CN.md)。
  部署、升级与回滚统一由对应指南维护，本文不重复安装命令。
- 关联多个来源：[Correlation Matrix](04-correlation-matrix.zh-CN.md)。
- 校验与排错：[日常运营检查与排错](09-operations-troubleshooting.zh-CN.md)。
- 接入短问答：[数据源接入 FAQ](16-data-source-onboarding-faq.zh-CN.md)。

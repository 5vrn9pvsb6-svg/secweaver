# SecWeaver 数据源资产目录（dataasset）

本目录存放**逻辑数据资产**与**连接器配置**，供安全运营同学自行编辑。

运行和管理程序统一放在 [`../src/dataasset/`](../src/dataasset/)；不要把
Python、Shell、插件或编译程序复制到任何资产目录。

## 接入自己的数据

根据日志所在位置选择接入路径。两种方式都提供配置样例和真实查询验收步骤。

| 数据来源 | 从这里开始 | 配置样例 |
|---|---|---|
| 用户自己的 Elasticsearch | [ES 配置与查询验收](../docs_user/03-configure-data-sources.zh-CN.md) | [Connector](onboarding/es/connector.json)、[Asset](onboarding/es/asset.json)、[查询模板](onboarding/es/template.snippet.json) |
| SecWeaver SLS SaaS（推荐） | [SLS Proxy 用户接入指南](../docs_user/30-sls-proxy-onboarding.zh-CN.md) | [主机执行 Connector](connectors/conn-sls-proxy-demo.json)、[配套 Asset](assets/asset-sls-proxy-host-exec-demo.json)、[通用接入三件套](onboarding/sls_proxy/) |

- **自己的 ES：**准备 HTTPS 地址、获授权的索引、实际时间字段、只读凭证和必要的
  私有 CA。手动配置或 UI 一键向导均默认校验证书；使用私有 CA 时配置 `ca_file`。WAF 模板需要按实际日志字段和类型调整。
- **SLS SaaS：**从企业工作台取得 Proxy 查询 AK/SK，使用 `connector_type: sls_proxy`
  配置获授权的 Project/Logstore。指南包含凭证加密保存、查询验收和排错步骤。

按所选指南默认编辑 `dataasset/`，或选择 `dataasset_my/` 隔离副本，通过[凭证引用](credentials/README.zh-CN.md)
保存凭证，并查询一条已知测试事件。验证前保持 Connector/Asset 为 `draft/discovery`，
通过后再启用并加入调查 Bundle。CLI、UI 和智能体统一使用所选 `DATAASSET_ROOT`。

以上配置用于查询已有日志。需要新增主机日志采集时，分别参考
[SaaS Agent 安装指南](../docs_user/29-secweaver-data-system-quickstart.zh-CN.md)或
[Agent 写入自建 ES 指南](../src/tools/secweaver-agent/elasticsearch/README.zh-CN.md)。

## 公开发布边界

仓库发布的 `dataasset/` 是经过脱敏的示例资产目录，本地使用时默认直接编辑它。示例地址只使用
`192.0.2.0/24`、`198.51.100.0/24`、`203.0.113.0/24` 文档保留网段，
SLS Proxy 模板只使用服务端明确公开的用户侧 Project `secweaver` 和逻辑 Logstore 名称，
例如 `host-exec`、`host-sys-messages` 和 `wis-waf-access`；不包含后台物理资源名。这些名称不授予访问权限，
扫描器只允许精确全名，带前后缀的变体仍会被拦截。凭证值仍只保留占位符。本地客户配置与 SOPS 材料不能提交或随公开归档发布。需要隔离时可复制到 Git 忽略的 `dataasset_my/`，通过 `DATAASSET_ROOT` 切换；无论使用哪个目录，发布前都必须清理真实环境值。`make release-scan` 会阻止公开目录
中的 RFC1918 地址和已知内部环境标记进入发布版本。
公开 Connector 只要 `config.project` 仍为 `YOUR_SLS_PROJECT`，状态必须保持 `draft`；
替换 Project/Logstore、配置只读凭证并完成真实查询验收后才能改为 `active`。
**平台架构**：[docs_dev/06-secweaver-architecture-and-features.md](../docs_dev/06-secweaver-architecture-and-features.md)
设计说明见：[docs_dev/09-data-asset-design.md](../docs_dev/09-data-asset-design.md)
历史设计评估见：[docs_dev/history/10-data-asset-design-evaluation.zh-CN.md](../docs_dev/history/10-data-asset-design-evaluation.zh-CN.md)
**新源最小三件套**：[onboarding/](onboarding/)
**社区新增资产 + Connector 手册**：[docs_dev/03-community-add-asset-connector.zh-CN.md](../docs_dev/03-community-add-asset-connector.zh-CN.md)
Agent 采集与 Evidence 规范：[docs_dev/12-agent-collection-and-evidence-spec.md](../docs_dev/12-agent-collection-and-evidence-spec.md)
**新 log 类型接入**：[完整接入流程](../docs_user/03-configure-data-sources.zh-CN.md) | [字段发现与归一化](../docs_user/20-log-format-discovery.zh-CN.md)
**跨源字段关联**：[docs_user/21-cross-source-field-correlation.zh-CN.md](../docs_user/21-cross-source-field-correlation.zh-CN.md) | [assets/correlation-matrix.json](assets/correlation-matrix.json) | [历史设计评估](../docs_dev/history/22-correlation-matrix-design-evaluation.zh-CN.md)
**关联引擎**：`src/skills/_shared/data-access/correlation_engine.py`（Join 匹配、`join_edges`、`plan_fetch`）
**跨源测试数据**：[examples/traceability/](../examples/traceability/)（项目根目录离线 evidence_bundles）
**字段参考示例**：[examples/reference-assets.json](examples/reference-assets.json)（合并资产 `asset-example-all-fields`，含全平台 `schema.fields`）
**示例连接器**：[examples/connectors/](examples/connectors/)（非生产 connector 模板，不进入正式 catalog）

**内置 SLS Proxy 正式示例**：
[`connectors/conn-sls-proxy-demo.json`](connectors/conn-sls-proxy-demo.json) +
[`assets/asset-sls-proxy-host-exec-demo.json`](assets/asset-sls-proxy-host-exec-demo.json)。
两者会进入 Catalog，但默认保持 `draft/discovery`，替换 endpoint、logstore 和 Proxy
凭证并完成真实查询后再启用。

需要一次生成完整的托管 SLS Proxy 资产时，使用
[`onboarding/examples/secweaver-saas-sls-proxy-assets.json`](onboarding/examples/secweaver-saas-sls-proxy-assets.json)。
它覆盖当前 8 个公开 Logstore 和 13 类主机、DNS、WEB、WAF 逻辑资产，不包含凭证，
生成项默认保持 `draft/discovery`。先运行：

```bash
python3 src/secweaver.py asset apply \
  -f dataasset/onboarding/examples/secweaver-saas-sls-proxy-assets.json \
  --dry-run
```

正式写入前删除不需要或未获授权的数据源，并逐项完成真实查询验收。

公开资产 ID 统一使用 `asset-secweaver-*` 命名空间。私有 `dataasset_my/` overlay 可以
继续保留旧的私有文件名，运行时会通过兼容映射将公开 ID 解析到私有文件。新的测试、
bundle 和配置必须使用公开 ID，确保在干净的 Community checkout 中也能运行。

## 使用 dataasset 连接 SLS Proxy

开源仓包含 `sls_proxy` Connector、脱敏配置模板和公开资产生成清单，**不包含**托管的
SLS Proxy 服务端、客户目录或查询凭证。请向平台管理员获取 Proxy endpoint、已授权的
逻辑 Logstore 和只读查询凭证，或者自行部署与公开客户端合同兼容的 Proxy 服务。

默认在本地 `dataasset/` 配置实际值，也可用 `dataasset_my/` 隔离；不要提交客户配置。Connector 只需要以下字段：

```json
{
  "connector_id": "conn-sls-proxy-example",
  "connector_type": "sls_proxy",
  "status": "draft",
  "credentials_ref": "vault://sls/sls-proxy-query",
  "config": {
    "endpoint": "https://sls-proxy.id-net.cn:30443",
    "fallback_endpoint": "https://sls-proxy.id-net.cn:30443",
    "project": "secweaver",
    "logstore": "host-exec"
  }
}
```

### 用户侧接入信息和 Logstore

使用托管 SLS Proxy 时，查询地址和企业工作台地址分别是：

| 项目 | 用户填写或访问的值 |
|---|---|
| 查询接入地址 | `https://sls-proxy.id-net.cn:30443` |
| 企业工作台地址 | `https://sc.id-net.cn:30443/`（登录、智能体配置、查询日志） |
| 备用查询地址 | 默认没有独立备用地址；`fallback_endpoint` 仅为兼容字段，与主地址相同 |
| 用户侧 Project | `secweaver` |

Project 和 Logstore 使用企业工作台显示的公开名称。当前目录如下；Proxy 会在服务端把这些
逻辑名称映射到实际资源，Connector 不应填写后台物理 Project/Logstore：

| 用户侧 Logstore | 用途 |
|---|---|
| `host-persistence` | cron、systemd、`authorized_keys`、sudoers 等持久化位置的变化，用于后门、自启动和提权配置排查。 |
| `host-process` | 进程基线、启动、退出和关键属性变化，用于异常进程排查。 |
| `host-state` | 账户/会话、服务/计划任务、监听端口、内核和容器上下文的基线及变化，用于暴露面和状态核对。 |
| `host-exec` | 命令执行、主动外连和文件操作事件，按 `event_type` 区分，用于 WebShell、反弹 Shell 和高危命令排查。 |
| `host-sys-messages` | Linux messages、secure 等日志解析出的 SSH、PAM、root 会话和系统风险事件，不是完整原始系统日志。 |
| `dns` | 内网 DNS 查询，用于可疑域名、疑似 C2 和主机网络行为关联。 |
| `wis-waf-access` | TS 网关访问及上游线索，用于 Web 访问分析、告警核验和溯源；访问记录本身不是攻击告警。 |
| `wis-waf-log` | WAF 网关插件告警，包含规则、源 IP 和请求线索；需要管理员完成企业 `tenant_id` 映射，规则命中不代表攻击成功。 |

DNS、TS 访问和 WAF 只有在服务端完成租户隔离、字段索引并查询到真实事件后才算可用。
最终可选项以企业工作台“智能体配置”显示的目录为准。

默认使用 HTTPS 30443，不使用 443。示例中的 `fallback_endpoint` 为兼容字段，与主入口
相同，不提供独立故障切换；只有运营方提供独立备用地址时才修改它。

`endpoint`、`fallback_endpoint` 和 `logstore` 由 Proxy 运营方提供。不要填写
`region` 或 `enterprise_id`，这两个字段由服务端管理。允许填写 `project` 与 `logstore` 选择获授权的资源，需 Go Proxy 0.6.0-rc.14/schema 10+；Project 省略或留空兼容服务端默认 Project。Proxy AK/SK 应保存在
`credentials_ref` 指向的本地 SOPS/Vault 凭证中，不能写入 Connector JSON。

配置完成后先校验，再启用：

```bash
python3 src/dataasset/validate.py

# 只渲染 fetch 计划，不访问 Proxy，也不解密凭证。
python3 src/dataasset/test_connector.py \
  asset-sls-proxy-host-exec-demo --by-asset --plan \
  --params '{"host":"web-01","time_start":"2026-06-21T08:00:00+08:00","time_end":"2026-06-21T08:05:00+08:00"}'

# 配置好 endpoint 和 Proxy 凭证后，再执行真实连通性检查。
python3 src/dataasset/test_connector.py \
  asset-sls-proxy-host-exec-demo --by-asset \
  --params '{"host":"web-01","time_start":"2026-06-21T08:00:00+08:00","time_end":"2026-06-21T08:05:00+08:00"}'
```

该 Connector 复用普通 SLS 查询模板。客户端先探测主 endpoint，只有连接失败或临时
网关错误才使用备用 endpoint；鉴权失败、无权访问和查询策略错误会直接返回。生产配置
必须使用 HTTPS。平台侧接入、Proxy Key 签发与轮换流程见
[SLS Proxy 用户接入指南](../docs_user/30-sls-proxy-onboarding.zh-CN.md)。

## 目录结构

```text
dataasset/
├── README.md                 # 本文件
├── connectors/               # L2 正式连接器（config + credentials_ref；会进入 catalog/validate）
├── hosts/                    # 关键主机注册表（host_id、hostname、zone）
├── assets/                   # L1 逻辑数据资产 + correlation-matrix.json（跨源 Join）
├── bundles/                  # 资产包（一键勾选）
├── credentials/              # 公开凭证文档/模板；运行时生成的密钥文件会被忽略
├── query-templates/          # 参数化查询模板
├── examples/                 # 字段参考与非生产示例连接器（不进入正式 catalog）
├── onboarding/               # 一次生成 Connector、Asset、查询模板的 Quickstart 配置
├── configure/                # 运行配置与多资产根归属策略
└── schema/                   # JSON Schema 校验
```

## 编辑流程

**若是全新 log 格式**，先在 `dataasset/assets/` 注册资产并设 **`status: discovery`**，再走 [日志格式发现](../docs_user/20-log-format-discovery.md)。

1. 在 `connectors/` 填写 **非敏感** `config`，**只写** `credentials_ref`
2. 在所选资产根目录的 `credentials/` 用 SOPS 维护真实 AK/密码/私钥（见 [credentials/README.md](credentials/README.md)）
3. 在 `assets/` 注册逻辑资产，绑定 `connector_id`，**新类型用 `status: discovery`**
4. 格式发现完成后：`discovery` → `draft` → `active`

**校验**（改完 JSON 后建议运行）：

```bash
python3 src/dataasset/validate.py

# 静态检查 Bundle -> Asset -> Connector -> 凭证密文链路；不联网、不解密。
python3 src/secweaver.py validate --runtime-ready \
  --bundle bundle-incident-trace-default --json

# catalog 与目录不一致时自动重写
python3 src/dataasset/validate.py --sync-catalog

# 开发工作区中同时校验所有本地资产根及其归属策略
make validate-all-roots

# 单 connector dry-run
python3 src/dataasset/test_connector.py asset-cmdb-hosts --by-asset \
  --params '{"limit":10}' --dry-run

# 多 connector 聚合：查看 fetch 计划（不解密 Vault）
python3 src/dataasset/test_connector.py asset-ssh-internal --by-asset --plan \
  --params '{"attacker_ip":"203.0.113.10","host":"web-01","time_start":"2026-06-21T08:00:00+08:00","time_end":"2026-06-21T20:00:00+08:00"}'

# 只测聚合资产中的某一个 connector
python3 src/dataasset/test_connector.py asset-ssh-internal --by-asset \
  --connector conn-ssh-web-01-auth \
  --params '{"attacker_ip":"203.0.113.10"}' --dry-run
```

`--runtime-ready` 只根据本地配置推导执行就绪状态。通过该门禁不代表 endpoint
真实可达或时间窗内存在数据；它会把依赖对象的基础校验错误合并为 Bundle blocker，
并分别输出 `registry_valid`、Bundle `status` 与最终 `ready_for_execution`。随后还要运行
`dataasset-connectivity-check` Skill。
多资产根归属由 `configure/shared-contracts.json` 声明：`shared` 文件必须逐字节一致，
`override` 文件可按已记录原因不同，`root_owned` 文件由单个环境维护。

共享文件漂移使用 `python3 src/dataasset/sync_shared_contracts.py --check` 预览；人工复核后
使用 `--write` 同步。该命令不会处理凭证或环境清单。

Asset、Bundle、Host、Network Schema 会拒绝未知顶层字段；Host 的 `interfaces`、`nat`、
`exposure` 和对象形式的 `exposed_ports` 也会拒绝未知字段。部署或厂商私有字段应放入
`extensions`；多个环境都需要的通用字段应先加入正式 Schema。

Connector 必填字段和条件组合统一由 `schema/data-connector.schema.json` 定义；Catalog
负责运行能力、依赖和接入 UI 元数据；校验器会阻止 Catalog 漏掉 Schema 必填字段或声明
向导或 Connector Schema 不支持的字段；CLI 在写入前还会校验最终合并结果。ES、HTTP API、Splunk 与远程外部执行器必须使用最终 HTTPS 地址且
不跟随重定向，回环联调可使用 HTTP；私有 CA 使用 `ca_file`。
`credentials/credential-status.json` 只允许 `active`、`disabled`。

生产 Skill 只有在 Asset 与 Connector 都为 `active` 时才取数。接入测试、格式发现和
提升命令可查询 `draft/discovery`；`disabled` Asset 或 Connector 永远不会执行查询。
Connector Catalog 必须使用 `format_version: "2.0"`；预览优先的迁移命令见
[运行配置说明](configure/README.zh-CN.md)。

## 多 connector 聚合（`connector_ids`）

同一逻辑资产可从**多个主机 / 多个 logstore / 混合 SLS+SSH** 拉数，合并为一条 `asset_type` 的 evidence。

| 字段 | 说明 |
|---|---|
| `connector_id` | 主连接器（必填，兼容旧配置；完整性 Skill 展示用） |
| `connector_ids` | 额外数据源列表；与 `connector_id` 合并去重后依次 fetch |
| `aggregate.max_events` | 合并去重后的 event 上限 |
| `aggregate.dedupe_by` | 去重键，如 `timestamp,host,src_ip,user,result` |

**分 logstore 主机标注**：在 connector `config.hostname` 写主机名（如 `web-01`）。调查参数带 `host` 时，只拉匹配的 connector + 未标注 hostname 的全局 SLS 源。

示例见 [`assets/asset-ssh-internal.json`](assets/asset-ssh-internal.json)：

```json
{
  "connector_id": "conn-sls-ssh-auth-internal",
  "connector_ids": [
    "conn-sls-ssh-auth-internal",
    "conn-sls-ssh-auth-web-01",
    "conn-sls-ssh-auth-db-01",
    "conn-ssh-web-01-auth"
  ],
  "aggregate": {
    "max_events": 5000,
    "dedupe_by": ["timestamp", "host", "src_ip", "user", "result"]
  },
  "query_template_ids": [
    "ssh_auth_by_src_ip_time",
    "ssh_auth_by_host_time",
    "ssh_file_grep_auth"
  ]
}
```

`query_template_ids` 须覆盖聚合内**每种** `connector_type` 至少一条模板（如 SLS 用 `ssh_auth_by_src_ip_time`，ssh_file 用 `ssh_file_grep_auth`，local_file 用 `local_file_grep_auth`）。`validate.py` 会检查每个 connector 是否至少匹配一条模板。

**主机覆盖关系**：资产侧不再填写主机绑定字段。`coverage.hosts` 只填写日志来源 IP；单主机采集目标如需标注，使用对应 connector 的 `config.host_id`。

详细设计：[docs_dev/09-data-asset-design.zh-CN.md](../docs_dev/09-data-asset-design.zh-CN.md) · [历史对象模型评估](../docs_dev/history/11-data-object-model-evaluation.zh-CN.md)
模板选择规则：[query-templates/README.md](query-templates/README.md)

## 凭证规则（重要）

| 允许 | 禁止 |
|---|---|
| `"credentials_ref": "vault://sls/security-readonly"` 等 ref | AccessKey、密码、私钥明文 |
| `connectors` 里的 endpoint、project、host | 在 connectors JSON 写 secret |
| `credentials/examples/` 占位模板 | `credentials/secrets/`（本地 SOPS，不进 Git） |
| 平台运行时从本机 Vault 解密注入 | 写入 AI 对话或 Skill 文件 |

先按[数据源配置](../docs_user/03-configure-data-sources.zh-CN.md)选择资产目录：默认 `export DATAASSET_ROOT=dataasset`；隔离时使用 `export DATAASSET_ROOT=dataasset_my`。UI、CLI 和智能体保持一致。
推荐在本地 UI 初始化和编辑凭证；命令行替代步骤如下，需要 Bash 4+、SOPS 和 age：

```bash
source .venv/bin/activate
# 仅对尚未初始化的本地 Vault 执行；已有密钥和策略必须保留。
bash src/dataasset/credentials/sops-vault.sh init
bash src/dataasset/credentials/sops-vault.sh edit vault://sls/security-readonly
```

只配置实际使用的凭证，不对整套公开占位模板执行 `bootstrap`。

## 大模型 / Agent 使用方式

1. 用户勾选 `assets/` 或 `bundles/` 资产包
2. AI 只传：`asset_id`、`template_id`、`params`（及可选 `credentials_ref`）
3. 平台用 `credentials_ref` 从 SOPS 取凭证，**AI 不可见** secret
4. 查询结果经 fetch → normalizer 归一化；多 connector 资产会去重合并后注入 `evidence_bundles`

## 资产与 Skill（解耦）

- **DataAsset** 只描述数据：`asset_type`、schema、coverage
- **Skill** 通过 `asset_type` + 场景 S1–S8 声明需要什么数据
- **不在资产 JSON 里绑定 Skill 名称**

| asset_type | 典型文件 | 常见调查场景 |
|---|---|---|
| waf_alert | assets/asset-waf-prod-01.json | S1/S2/S4 |
| web_access_log | assets/asset-web-access-prod.json | S1/S2/S4 |
| host_exec / connect / file_op / persistence | assets/asset-secweaver-host-exec.json 等 | S2/S5 |
| windows_event_log | assets/asset-windows-event-prod.json | S3/S5/S6（Windows 主机） |
| linux_syslog | assets/asset-linux-syslog-prod.json | S3/S5/S6（Linux 主机） |
| ssh_auth | assets/asset-ssh-internal.json（**多源聚合** SLS+logstore+SSH） / asset-ssh-web-01-file.json（单 SSH，draft） | S1/S3/S6 |
| asset_inventory | assets/asset-cmdb-hosts.json（MySQL） / asset-pg-cmdb-hosts.json（PostgreSQL） | S1/S3 |
| db_audit | assets/asset-mysql-db-audit.json（MySQL 示例） | D7 数据库审计 |
| ssh_auth (MySQL) | assets/asset-mysql-ssh-auth.json | S1/S3/S6 示例 |
| waf_alert (ES) | assets/asset-es-waf-prod.json | S1/S2/S4 示例 |
| web_access_log (ES) | assets/asset-es-web-access-prod.json | S1/S2/S4 示例 |
| firewall_log | assets/asset-fw-dmz-internal.json | S1/S3 |
| network_traffic_audit | assets/asset-network-nta-prod.json | S1/S3/S7 |

## 资产包

| 包 ID | 场景 | 说明 |
|---|---|---|
| bundle-alert-confirm-min | S4 | WEB 告警确认 |
| bundle-incident-trace-default | S1, S3 | 外网 IP 溯源 |

## 状态字段

| status | 含义 |
|---|---|
| `discovery` | **格式发现队列**；仅 log-format-discovery Skill 处理，不可选 |
| `draft` | 映射完成、编辑中，不可选 |
| `active` | 已发布，可选 |
| `disabled` | 停用 |

文本日志解析：在 asset 上配置 **`text_parser`**（内置见 `configure/text-log-parsers.json`；自定义见 `parsers/`）。**运营不改 Python。**

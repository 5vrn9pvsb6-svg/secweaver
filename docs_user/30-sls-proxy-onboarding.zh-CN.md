# SLS Proxy 用户接入指南

接入后可在[企业工作台 → 查询日志](https://sc.id-net.cn:30443/#/query-logs)查看查询语句、执行状态、来源 IP 和 API Key 归属。Key 是企业共享身份，不能据此确定具体操作人；旧记录可能没有新增字段。

**语言：** [English](30-sls-proxy-onboarding.md) | 简体中文（本文）

本文面向使用 Community 本地客户端接入 SaaS 的用户。目标是：配置一次查询凭证，
查到一条真实日志，再让 AI 使用该资产。无需部署 SLS Proxy、Docker 或 ES。

已经由管理员配置好 DataAsset 的 Data Cloud 用户，可直接使用
[Data Cloud 客户快速上手](29-secweaver-data-system-quickstart.zh-CN.md)。
需要新增主机日志时，也从该指南获取平台签发的 Agent 安装命令；下面配置的是
**查询端，不是日志上传端**。Proxy Key 不能作为 Logtail 写入凭证。

## 1. 准备连接配置

在[企业工作台](https://sc.id-net.cn:30443/)完成注册及首次 SSO 登录后，企业与一组 Proxy 查询 AK/SK 自动创建。打开“智能体配置”，Owner/Admin 可查看 AK，并显式查看或复制 SK。旧企业缺少密钥时重新登录一次；重复登录不换密钥，已撤销/过期密钥需联系管理员处理。请将密钥保存到本地加密凭据库，不要发给 AI 对话。

核对以下配置；授权 Logstore 未绑定或日志尚不可查时，仍需管理员配置 SLS 资源：

| 配置 | 内容 |
|---|---|
| 查询接入地址 | `https://sls-proxy.id-net.cn:30443`（Connector 的 `endpoint`） |
| 企业工作台地址 | `https://sc.id-net.cn:30443/`（登录、查看“智能体配置”和“查询日志”） |
| 备用查询地址 | 默认没有独立备用地址；兼容配置中的 `fallback_endpoint` 与主入口相同 |
| Project | 企业工作台显示的对外 Project，当前为 `secweaver`；仅使用服务端默认 Project 时可省略或留空 |
| Logstore | 企业工作台显示的用户侧逻辑 Logstore 名称，见下表 |
| 查询凭证 | Proxy `access_key_id` 和 `access_key_secret`，不是阿里云 RAM Key |

企业归属、上游 SLS 资源、采集字段和索引由平台管理。不要在 Connector 中添加
`enterprise_id`、`region`，也不要手工拼接企业过滤条件。
`config.project` 与 `config.logstore` 共同选择获授权资源。显式 Project 需要 Go Proxy 0.6.0-rc.14/schema 10 或更新版本，且管理员已配置该 Project 并为企业绑定资源。旧服务可能拒绝请求；不要为绕过失败删除 Project，避免误查默认资源。以企业工作台“智能体配置”列出的 Project/Logstore 为准。平台启用资源映射后，可能只显示一个对外 Project（例如 `secweaver`）；后台会映射到实际资源，不要自行改成真实 SLS Project。旧示例中的真实名称仅适用于未启用映射的服务；Proxy 查询域名保持不变。
如尚未开通服务或拿不到授权 Logstore/Key，先联系平台管理员；公开源码不会自动开通 SaaS。
向本企业 Data Cloud 管理员取得服务开通确认和平台登录地址。上面的 endpoint 只用于查询，
不是注册页、平台登录页或 Agent 上传地址；没有管理员交付时可继续体验离线案例。

### 1.1 用户侧 Project 和 Logstore 目录

下面是企业工作台向用户展示的公开目录。所有行的用户侧 Project 都是 `secweaver`；Proxy
会在服务端把逻辑名称映射到实际 SLS 资源，因此不要把后台物理 Project、物理 Logstore
或 `wis-log/gateway_plugin_log` 填入 Connector。目录是否可查仍取决于管理员发布资源、
Agent 是否采集对应模块，以及时间范围内是否有数据。

| 用户侧 Project | 用户侧 Logstore | 主要用途和数据范围 |
|---|---|---|
| `secweaver` | `host-persistence` | cron、systemd、`authorized_keys`、sudoers、profile 等持久化位置的配置变化，用于排查后门、自启动和提权配置。 |
| `secweaver` | `host-process` | 进程基线、启动、退出和关键属性变化，用于异常进程排查；周期快照不替代短生命周期命令的实时审计。 |
| `secweaver` | `host-state` | 账户与登录会话、服务与计划任务、监听端口、内核和容器上下文的基线及变化，用于暴露面和状态核对，不是每条操作的审计。 |
| `secweaver` | `host-exec` | 命令执行、主动外连和文件操作事件，按 `event_type` 区分，用于 WebShell、反弹 Shell 和高危命令排查。 |
| `secweaver` | `host-sys-messages` | 从 Linux messages、secure 等系统日志解析出的 SSH、PAM、root 会话和系统风险事件，不等同于完整原始系统日志。 |
| `secweaver` | `dns` | 内网 DNS 查询，用于可疑域名、疑似 C2 和主机网络行为关联；只覆盖经过平台指定 DNS 服务的查询。 |
| `secweaver` | `wis-waf-access` | TS 网关请求及上游访问线索，用于 Web 访问分析、告警核验和溯源；访问记录本身不是攻击告警。 |
| `secweaver` | `wis-waf-log` | WAF 网关插件告警，包含规则、源 IP 和请求线索；需要管理员完成企业 `tenant_id` 映射，规则命中不代表攻击成功。 |

DNS、TS 访问和 WAF 资产可以先按模板生成，但在服务端完成 `enterprise_id`/租户隔离、字段
索引并查询到真实事件前，应保持 `discovery`/`draft`，不要把它们当成已接入数据。

以下示例使用已有的主机命令执行日志。其他日志类型使用平台提供的 Asset/查询模板，
或按[数据源配置](03-configure-data-sources.zh-CN.md)登记，不要把所有日志都声明为 `host_exec`。

### Project 与 TLS 校验

`project` 可省略或留空以使用服务端默认资源；非空时为 1–128 个 ASCII 字母、数字、
下划线或连字符，且以字母或数字开头。公开 schema 与查询运行时使用相同约束；
`region` 仍由服务端管理。

入口探测与实际签名查询默认验证 TLS 证书（`tls_verify: true`）。使用私有 CA 时，
将 `config.ca_file` 指向 PEM CA 证书包；相对路径基于 `DATAASSET_ROOT`，也支持绝对路径。
CA 文件缺失/无效或证书校验失败会终止请求，不切换备用入口、不自动关闭验证。
`tls_verify` 只接受布尔值。显式 `false` 仅保留诊断兼容用途，不建议生产使用，
且不能与 `ca_file` 同时配置。旧配置省略该字段时，现在必须提供受信证书；应修复信任链
或配置 CA。配置后执行第 5 节 dry-run、真实查询及 `catalog sync`/`validate`；
dry-run 本身不能验证证书或凭证是否可用。

## 2. 初始化本地查询环境

使用 Linux/macOS POSIX 终端，需要 Python 3.10+、Make、SOPS 和 age。其他环境限制见[快速上手](00-security-operator-quickstart.zh-CN.md)。从仓库根目录执行：

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

## 3. 保存查询凭证

推荐启动 UI，在“凭证”页面创建 `vault://sls/sls-proxy-query`，
选择 `aliyun_ram`，填写平台签发的 Proxy AK/SK。UI 和脚本均需要本地 SOPS/age。

```bash
make ui
```

浏览器打开 `http://127.0.0.1:8765/`。先完成凭证环境初始化，再创建凭证。
UI 在独立终端运行，或按 Ctrl+C 停止后执行 CLI 步骤；新终端需要重新执行
所选 `DATAASSET_ROOT` 和 `source .venv/bin/activate`。
也可以在具备 **Bash 4+**、`sops`、`age`、`age-keygen` 的终端执行下列流程。
macOS 默认 Bash 3.2 不满足脚本要求，应选择已安装的新版 Bash；依赖详见
[凭证指南](../dataasset/credentials/README.zh-CN.md)。

仅在该本地 Vault 尚未初始化时执行第一条；已有 Vault 保留其密钥和配置：

```bash
bash src/dataasset/credentials/sops-vault.sh init
bash src/dataasset/credentials/sops-vault.sh edit vault://sls/sls-proxy-query
bash src/dataasset/credentials/sops-vault.sh get vault://sls/sls-proxy-query
```

编辑器中的类型和字段如下，保存后自动加密。最后一条只显示脱敏结果：

```yaml
type: aliyun_ram
access_key_id: "SWAK_REPLACE_ME"
access_key_secret: "REPLACE_ME"
```

不要把真实密钥输入 AI 对话、命令行参数或 Connector JSON；不要提交私钥或密文。
不需要执行全量 `bootstrap`，`edit` 会从公开占位模板初始化这一份凭证。

## 4. 配置 Connector 和 Asset

在所选资产目录中编辑
`dataasset/connectors/conn-sls-proxy-demo.json`：
保持 ID 和凭证引用不变，将 `config.project` 和 `config.logstore` 改成企业工作台显示的授权组合，核对两个 HTTPS 地址。以下主机命令执行示例使用当前公开名称；仅使用默认 Project 时可省略或留空 `project`。

```json
{
  "endpoint": "https://sls-proxy.id-net.cn:30443",
  "fallback_endpoint": "https://sls-proxy.id-net.cn:30443",
  "project": "secweaver",
  "logstore": "host-exec"
}
```

这是 Connector 的 `config` 对象，不是完整 Connector。完整公开参考见
[conn-sls-proxy-demo.json](../dataasset/connectors/conn-sls-proxy-demo.json)。

配套 Asset 为
[asset-sls-proxy-host-exec-demo.json](../dataasset/assets/asset-sls-proxy-host-exec-demo.json)。
在所选资产目录核对 `schema.time_field`、真实字段和别名。不要把示例中的主机覆盖范围或
保留天数当成真实承诺。先保留 Connector 为 `draft`、Asset 为 `discovery`。

需要配置完整的 SecWeaver SaaS 资产时，可在 DataAsset UI 的 Quickstart 下拉中选择
[`secweaver-saas-sls-proxy-assets.json`](../dataasset/onboarding/examples/secweaver-saas-sls-proxy-assets.json)，
或先在仓库根目录预览它将生成的 13 组 Connector、Asset 和查询模板：

```bash
.venv/bin/python src/secweaver.py asset apply \
  -f dataasset/onboarding/examples/secweaver-saas-sls-proxy-assets.json \
  --dry-run
```

该模板使用公开逻辑 Project `secweaver`，覆盖 8 个公开 Logstore。Connector 不包含真实上游
Project、`enterprise_id` 取值或过滤条件，也不包含凭证；Asset schema 中的企业字段是
服务端后续补齐并用于隔离的目标数据契约。正式写入前删除不需要或未获授权的数据源；生成的
Connector/Asset 默认保持 `draft/discovery`，每项都要按下一节做真实查询后再启用。
DNS、TS 访问和 WAF 模板可先生成，但只有服务端完成 `enterprise_id` 接入、字段索引且
查询成功后，才能视为可用。

## 5. 用一条真实事件验收

先生成最近五分钟的 UTC 查询参数；下面只计算时间，不访问服务或凭证。
在与前面相同的终端中执行：

```bash
SLS_CHECK_PARAMS="$(.venv/bin/python -c 'import datetime,json; end=datetime.datetime.now(datetime.timezone.utc); print(json.dumps({"time_start":(end-datetime.timedelta(minutes=5)).isoformat(),"time_end":end.isoformat(),"limit":10}))')"
.venv/bin/python src/dataasset/test_connector.py conn-sls-proxy-demo \
  --params "$SLS_CHECK_PARAMS" --dry-run
```

检查渲染后的查询及时间窗正确后，再去掉 `--dry-run`，此时才访问平台：

```bash
.venv/bin/python src/dataasset/test_connector.py conn-sls-proxy-demo \
  --params "$SLS_CHECK_PARAMS"
```

输出可能包含真实日志，只在有权限的本地终端检查，不要原样贴到公开 Issue 或智能体对话。
确认：

- 命令正常退出，没有 `status: error`，且 `events` 包含平台确认已写入的测试事件；空结果不代表接入成功。
- 主机、命令和事件时间符合预期，租户内部字段不出现在返回数据中。
- `query_meta.endpoint_used`、`query_meta.fallback_used` 与实际入口一致。
- Asset 的时间字段、字段别名与查询结果一致。

随后在 UI 的资产测试中选择 `asset-sls-proxy-host-exec-demo`，
指定相同时间窗和真实主机，验证其查询模板可用。通过后将本地 Connector 和 Asset
分别设为 `active`，执行：

```bash
.venv/bin/python src/secweaver.py catalog sync
.venv/bin/python src/secweaver.py validate
```

只将已验收的资产加入调查 Bundle，并向智能体指定该 Bundle、主机和时间窗。
单一主机命令资产不能证明完整攻击链；先运行数据完整性检查，再做风险识别或溯源。

### 5.1 统计数量与分类（COUNT / GROUP BY）

Proxy 已支持 SLS 聚合查询，**省略 `FROM`，包括 `FROM log`**。搜索条件写在 `|`
之前，统计语句写在之后；Project/Logstore 仍由 Connector 选择，不在 SQL 中指定。
这也是 [SLS 官方查询语法](https://www.alibabacloud.com/help/zh/sls/query-syntax/)
支持的写法。以下是查询文本，不是终端命令；在支持原始 SLS 查询的工具/模板中使用，
并另外传入开始、结束时间。将示例 IP 换成获授权的真实主机：

```sql
host_ip:"192.0.2.10" | SELECT count(*) AS n
host_ip:"192.0.2.10" | SELECT event_type, count(*) AS n GROUP BY event_type ORDER BY n DESC LIMIT 100
host_ip:"192.0.2.10" | SELECT asset_type, count(*) AS n GROUP BY asset_type ORDER BY n DESC LIMIT 100
```

按资产真实字段选择示例；部分系统日志需要用 `__source__` 筛选主机。
分组字段必须已启用 SLS SQL 分析索引；字段缺失或索引未开通时联系管理员，
不要把失败当成零条数据。聚合结果是统计行，不是原始事件，不要直接交给需要
原始事件的风险分析或溯源技能。

- 企业过滤由 Proxy 在聚合前注入，签名、资源授权、时间窗、保留期限、并发和结果行数限制仍然生效。
- 不支持 `FROM`、`JOIN`、`UNION` 等跨资源 SQL，也不能查询或分组企业保留字段。
- `LIMIT 100` 限制返回的分组数量，不限制扫描量；高基数字段分组仍会增加耗时和资源开销。
  总数查询不需要 `GROUP BY`，分类统计应选择少量、低基数字段，并使用尽可能短的时间窗。
- 完整统计要求响应 `progress=Complete`（SDK `is_completed()` 为真）；分组行数达到 `LIMIT`
  时可能还有未返回的分组，不能直接把分组之和当成总数。API 的 `count`/`X-Log-Count`
  是返回的统计行数，日志数量应读取每行的 `n`。
- `COUNT(*)` 按 SLS 查询时间窗统计存储记录，不去重；不自动等于事件原始时间字段内的数量。
  统计“今天”时应明确时区、起止时间和时间口径。

## 6. 排错和轮换

| 现象 | 用户操作 |
|---|---|
| `Unauthorized` | 核对 Proxy Key、有效期和本机时间；不要换成阿里云 RAM Key |
| `Forbidden` | 联系平台确认企业/Key 状态与授权范围 |
| `ProjectNotExist` / `LogStoreNotExist` | 核对授权 Project/Logstore 组合；上游资源问题交给平台 |
| 查询成功但没有测试事件 | 核对时间窗、时区、主机字段与上传延迟，再请平台检查采集链路 |
| `QueryPolicyDenied` | 聚合查询去掉 `FROM log`；不使用企业保留字段、跨资源 SQL 或不支持的扫描语法 |
| TLS、404 或两个入口均失败 | 检查本机连通性并把脱敏错误交给平台，不关闭证书校验 |
| CLI 可查，AI 查不到 | 检查智能体的资产根目录、凭证访问权限和 Bundle |

客户端先探测主入口 `/livez`；仅连接失败、路由不存在、超时或临时
`502/503/504` 等情况切换备用入口。鉴权、授权、策略及普通查询错误不会通过
切换入口重试。证书错误应修复信任链，不应通过关闭 TLS 校验绕过。

轮换时由平台签发新查询 Key，在本地凭证中更新并重新验收，再按平台要求撤销旧 Key。
不要因此更改 Agent 的安装令牌或 SLS 采集器写入身份。

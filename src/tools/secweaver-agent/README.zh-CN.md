# secweaver-agent

源码 0.3.40 修复 Linux 父进程停止顺序：子模块退出前保持 audit 管道打开，避免正常重启
导致行为学习误降级。已降级的旧代次仍需显式重新学习，操作见行为学习指南。

源码 0.3.39 扩展 Windows 学习至合格外连和普通 `.log` 创建，各类型精确匹配、分别汇总；
认证、持久化、敏感/破坏性动作和无法验证的记录继续全量输出。

源码 0.3.38 为两个 Windows 证据 reader 接入 Sysmon exec 自动学习，新安装默认学习 24 小时。
4688 以及不完整、敏感事件仍全量输出。前提、限制与验收见[行为学习指南](docs/behavior-learning.zh-CN.md)。

源码 0.3.37 增加 Linux 行为学习与有界日志减量，新安装默认自动学习 24 小时。
资格限制、异常恢复、摘要上传和待完成的真实平台验收见[行为学习指南](docs/behavior-learning.zh-CN.md)。

源码 0.3.36 将升级清单签名改为可选。未配置升级公钥时，Agent 默认接受 HTTPS 清单，
但仍严格校验每个下载文件的大小和 SHA-256。配置 `public_key` 或 `trusted_public_keys`
后进入严格签名模式；信任变更、紧急停止和远程回退仍只能由签名清单触发。

源码 0.3.33 将安装示例改为显式填写已下载归档的实际版本，避免复制旧版包名。
运行时行为、配置和 Schema 均未改变。

源码 0.3.32 修正随包文档的 Community 与托管服务边界：自建 ES 排错只引用
公开 Filebeat/ES 流程，托管 Bootstrap 发布参数由部署方在仓库外提供。运行时行为、
配置和 Schema 均未改变。

源码 0.3.31 更新随包文档索引，改为引用 `docs_dev/history/` 下的 Agent Linux
eBPF/Audit 历史评估。运行时行为、配置和 Schema 均未改变。

源码 0.3.30 保留 0.3.29 的 Linux 容器快照修复，并将随包测试夹具中的真实环境地址
替换为 RFC 5737 文档地址。本次发布策略调整不改变运行时行为和 schema。

源码 0.3.29 修复 Linux 容器快照在 cgroup v1/v2 多控制器条目下的 PID 重复统计。
`process_count` 表示观测到的唯一 PID 数，`pids` 排序去重后最多保留 100 项；
`process_count > len(pids)` 表示列表截断。既有 parser/schema 契约不变。
升级后，修正计数在下一次完整基线或采集器重启后出现，历史事件不会重写；Windows
采集行为不变。在此目录运行
`go test ./pkg/hoststatesnapshot -run TestContainerProcessCountDeduplicatesControllersBeforeLimit`
验证。本次源码修改不代表已经发布或部署安装包。

包名中的版本号仅为已下载归档的示例；安装时使用实际归档版本。下一次构建版本以 `VERSION` 为准，源码版本更新不代表安装包已发布。

## 先选择使用路径

| 角色 / 目标 | 从这里开始 |
|---|---|
| SaaS 用户安装主机采集端 | [Data Cloud 客户快速上手](../../../docs_user/29-secweaver-data-system-quickstart.zh-CN.md) |
| Community 用户把日志写入自建 ES | [公开初始化、独立安装和 Filebeat 接入](../../../src/tools/secweaver-agent/elasticsearch/README.zh-CN.md) |
| 开发者编译公开二进制 | [构建](#构建)：`make build` 不要求 SaaS 部署参数 |
| 维护者制作托管发布包 | [托管发布打包](#托管发布打包)：需要 Bootstrap 前置配置，签名可选 |

托管 SaaS 用户指南随 Community 源码归档提供；如果使用解压后的 Agent 发布包接入自建 ES，
可直接阅读包内 `elasticsearch/README.md` 和 `elasticsearch/README.zh-CN.md`，其中包含初始化脚本
和 Filebeat 示例。本工程手册同时描述托管服务兼容行为，不表示内含 ES Operator 或自动开通 SaaS。
Agent 0.3.21 将 Bootstrap 改为动态读取安装版本；运行时和 parser 契约未变，不代表已重建或发布新 Agent 二进制。

Agent 0.3.22 修复 Linux 仅传企业令牌且启用自动更新时的安装错误，复用已注册设备 ID。
身份与失败重试要求见[注册设备身份](docs/bootstrap-channel.zh-CN.md#注册设备身份0322)，不会自动替换既有发布包。

`secweaver-agent` 是主机侧统一客户端。目标是让一台服务器只安装一个程序，后续新增采集能力也作为内置模块接入同一个二进制。

当前内置模块：

| 模块 | 系统 | 源码包 | 用途 |
|---|---|---|---|
| `audit-port-execmon` | Linux | `pkg/auditportexecmon` | 基于 auditd 采集对外监听进程的命令执行、主动外连、文件操作、敏感文件读取 |
| `syslog-risk-json` | Linux | `pkg/syslogriskjson` | 解析 Linux auth/syslog 日志，输出安全风险 JSON Lines |
| `host-persistence` | Linux/Windows | `pkg/hostpersistence` | 监控 Linux cron/systemd/authorized_keys/sudoers/profile 以及 Windows 计划任务、启动目录、profile 脚本等文件型持久化位置；Linux 可通过 auditd 富化操作者/进程信息 |
| `host-process-snapshot` | Linux/Windows | `pkg/hostprocesssnapshot` | 启动及每日输出完整进程基线，每 10 分钟输出启动、退出及程序/命令/cgroup/权限变化 |
| `host-state-snapshot` | Linux/Windows | `pkg/hoststatesnapshot` | 统一采集监听端口、登录/身份、服务/计划任务、内核模块和容器上下文，输出完整快照或状态差异 |
| `windows-eventlog-risk-json` | Windows | `pkg/windowseventlogriskjson` | 解析 Windows Event Log，输出风险 JSON Lines |
| `windows-process-execmon` | Windows | `pkg/windowsprocessexecmon` | 从 Security 4688 和 Sysmon 事件生成进程/外连/文件证据 |

专题导航：[安装、指标、健康日志、磁盘保护与发布](docs/README.zh-CN.md)。

## 按角色查阅本手册

- 安装和排错：先看下方支持矩阵，再按需查[配置](#配置)、[运行](#运行)和[迁移](#迁移)。
- 发布维护：查[托管打包](#托管发布打包)、[升级](#升级)及[公钥轮换与紧急停止](#发布公钥轮换和紧急停止)；普通使用者无需先读发布参数。
- 模块开发：查[架构](#架构)、[构建](#构建)和[新增模块](#新增模块)。
- 指标、自建 ES 和磁盘保护等操作细节统一见[专题索引](docs/README.zh-CN.md)。

## 支持矩阵与自诊断

正式采集端支持 Linux systemd 主机、Windows 服务主机和 Linux 容器工作负载。Docker 模式严格限定在工作负载容器自身，不是宿主机安全传感器的替代方案。

| 平台 | 支持状态 | 说明 |
|---|---|---|
| Linux systemd，amd64/arm64/loong64 | 支持 | 默认 Linux 发布包、`install.sh`、auditd、syslog、host_persistence 均面向该场景 |
| Windows，amd64/arm64 | 支持试点 | 支持安装为 `SecWeaverAgent` 服务，依赖 Windows Event Log、Security 审计策略、可选 Sysmon，以及文件型 host-persistence 轮询 |
| WSL2 Linux 环境 | 仅限客户端/开发 | 可按 Linux 运行 Community Python 工具，但不是 Windows 宿主机传感器，不采集宿主机 Event Log、Security 4688、Sysmon 或 Windows 服务 |
| Linux 非 systemd | 不作为默认安装目标 | 可手工运行二进制，但发布包安装脚本默认拒绝安装 systemd 服务 |
| 容器内 Linux | 支持工作负载模式 | 非 root Docker 部署采集容器自身的进程、端口、身份和 cgroup/容器上下文；不声称具备宿主机 audit 或持久化监控覆盖 |
| macOS | 暂不支持采集 | 当前可作为开发/编译环境，不作为主机采集端 |

可在安装前或排障时运行统一自检：

```bash
secweaver-agent preflight -config /opt/secweaver-agent/etc/config.json
secweaver-agent preflight -config /opt/secweaver-agent/etc/config.json -strict
secweaver-agent doctor -config /opt/secweaver-agent/etc/config.json
secweaver-agent doctor -config /opt/secweaver-agent/etc/config.json -json
```

`preflight` 会检查当前 OS 与启用模块是否匹配、systemd、root 权限、容器迹象、`auditctl`/audit log、`netstat`/`/proc`、传统 syslog 文件、`host-persistence` 配置、Windows `wevtutil`/Event Log 通道、4688 命令行审计策略，以及定时升级配置。`-strict` 会在发现 `ERROR` 时返回非 0，适合安装脚本或巡检系统使用。

`doctor` 面向线上一键诊断，会在 `preflight` 基础上继续检查 Agent 服务、授权连通性、本机 `status.json`、各模块最近 JSON 输出；检测到 SLS Logtail/LoongCollector 时，还会校验其身份。Agent 自诊断不会校验 ES/Filebeat/Fluent Bit 或其他日志输送器的配置；Community 自建 ES 用户应按[公开 ES 接入指南](elasticsearch/README.zh-CN.md)运行 Filebeat 配置、输出和入库验收，其他输送器使用各自的标准诊断。未检测到 Logtail 目录时，Agent 会明确报告已跳过 SLS 身份检查，不会误要求阿里云身份文件。`-json` 输出机器可读报告，便于企业工作台后台、巡检脚本或工单系统采集。`secweaver-agent run -dry-run` 也会输出 preflight 完整报告；正常 `run` 会把 warning/error 摘要写到 stderr。Windows service 模式不创建专用 service log 文件，排障时查看 Windows 服务状态、事件查看器/SCM 诊断以及各模块 JSONL 输出。

当前已知边界：

- `syslog-risk-json` 读取传统日志文件，journald-only 输入暂未接入。
- Windows Event Log 模块会把 `EventRecordID` 游标持久化到 `C:\ProgramData\SecWeaver\Agent\data\*.cursor.json`，服务重启后优先从游标继续查询；首次启动或未找到游标时才按 lookback 窗口回溯。
- Windows 进程命令行依赖 4688 命令行审计策略，网络连接和文件创建/删除证据依赖 Sysmon。
- Windows `host-persistence` 目前只监控文件型持久化位置，注册表持久化尚未由该模块采集。

## Docker 容器工作负载部署

每个 Linux 发布包都包含 `container/Dockerfile`、`container/docker-compose.yaml`
和 `container/config.container.example.json`。这个模式面向需要采集单个应用工作负载证据的用户。它开启 `host-process-snapshot`
和 `host-state-snapshot`，事件表示容器自身的 PID、网络、文件系统身份和 cgroup namespace。它故意关闭
`audit-port-execmon`、`host-persistence` 和 `syslog-risk-json`：这些模块需要管理或读取宿主机安全资源，必须通过宿主机上正常的 Linux systemd 安装运行。

请使用已校验 SHA-256、且与目标 CPU 架构一致的 Linux Agent 解压包。Docker Compose 使用包内已签名的二进制生成镜像，不在镜像中编译 Agent 源码。

```bash
AGENT_VERSION='<已下载版本>'
tar -xzf "secweaver-agent_${AGENT_VERSION}_linux_amd64.tar.gz"
cd "secweaver-agent_${AGENT_VERSION}_linux_amd64"
cp container/config.container.example.json config.container.json
# 编辑 config.container.json：设置 enterprise_id；如果接入 Data Cloud，
# 还需启用并配置 license.server_url 和 license.enrollment_id。
docker compose -f container/docker-compose.yaml up -d --build
docker compose -f container/docker-compose.yaml logs --tail=100 secweaver-agent
curl -fsS http://127.0.0.1:9100/metrics | head
```

Compose 模板使用 UID/GID `65532`运行、以只读根文件系统启动、删除全部 Linux capability，只把 `/var/lib/secweaver-agent` 作为命名卷持久化。它只读挂载宿主机 `/etc/machine-id`，仅作为稳定的指纹组件；Agent 设备私钥仍只保存在命名卷。正常镜像升级时不要删除该卷，否则新容器会注册为新设备身份。容器配置关闭 Agent 自升级，因为替换不可变镜像才是即时的升级方式：

```bash
# 在新版解压目录中重复执行，但保留 Compose 的命名卷。
docker compose -f container/docker-compose.yaml up -d --build
```

如果修改 Docker 配置以启用 `audit-port-execmon` 或 `host-persistence`，`secweaver-agent preflight -strict` 会返回错误。不要为绕过这个边界而增加 `privileged`、`pid: host` 或 `network_mode: host`。如果需要宿主机进程树执行、auditd、持久化和宿主机 syslog 覆盖，请在 Linux 宿主机上安装常规 Agent 服务。

## 架构

```text
systemd / shell
  └─ secweaver-agent run -config /opt/secweaver-agent/etc/config.json
       ├─ secweaver-agent module audit-port-execmon ...
       ├─ secweaver-agent module syslog-risk-json ...
       ├─ secweaver-agent module host-persistence ...
	   ├─ secweaver-agent module host-process-snapshot ...
       ├─ secweaver-agent module windows-eventlog-risk-json ...
       └─ secweaver-agent module windows-process-execmon ...
```

Supervisor 和模块都来自同一个二进制文件。这样既保持“一个客户端安装一个程序”，又保留模块进程隔离：某个模块的历史 flag、退出码或全局状态不会污染其他模块。

## 构建

Agent 使用独立版本号，不跟随 ES Server、SLS Proxy 或 Operator Bundle 版本。Agent
二进制、安装包、升级清单和升级策略目标必须使用同一个 Agent `VERSION`；服务端打包时通过
`AGENT_VERSION` 选择该发布物。

```bash
cd src/tools/secweaver-agent
go build -o secweaver-agent .
```

历史 audit 回归辅助脚本 `verify-p0-fixes.sh` 会根据脚本自身位置解析当前 Agent 目录，
可在任意导出归档或贡献者检出目录中运行；二进制、备份和验证报告写入该 Agent 源码目录。

交叉编译：

```bash
cd src/tools/secweaver-agent
make build-cross
```

`build-cross.sh` 默认生成无签名的 `dist/update-manifest.json`。设置
`UPDATE_SIGNING_PRIVATE_KEY_FILE` 后才会签名每个平台二进制和 manifest 信封，发布产物默认
使用 `ed25519-sha256` 摘要签名。私钥只留在发布环境，签名构建生成的
`update-signing-key.pub` 内容配置到客户端 `update.public_key`。
`UPDATE_BASE_URL` 设置绝对下载地址，`UPDATE_DOWNLOAD_SPREAD_SECONDS=3600` 设置一小时下载
削峰。`UPDATE_ROLLOUT_PERCENTAGE` 只用于无控制面的 standalone 部署；托管服务发布门禁会拒绝它。

### 托管发布打包

本节面向配置了托管 Bootstrap 参数的发布维护者。签名环境是可选的；省略
`UPDATE_SIGNING_PRIVATE_KEY_FILE` 即采用 HTTPS 加 SHA-256 的默认升级路径。本节不是
`make build` 或自建 ES 接入的前置步骤。

统一发布包：

```bash
cd src/tools/secweaver-agent
make package
```

`VERSION` 是 Agent 发布版本的唯一来源，构建脚本同时注入主命令和
`audit-port-execmon -version`。交叉构建和正式打包默认拒绝 Agent 源码脏
工作区，并同时生成 `SOURCE.sha256` 与 `SOURCE.commit` 溯源信息。
`ALLOW_DIRTY_RELEASE=1` 仅供本地非生产打包测试使用。
Agent 版本是不可复用的发布身份：Agent 源码、配置、安装程序、包内文档或发布策略任一变化，
都必须先提升仓库中的 `VERSION`。两个发布脚本会对比版本赋值提交之后的源码历史及当前
工作区；仅通过环境变量改版本，或者使用 `ALLOW_DIRTY_RELEASE`，都不能绕过版本提升门禁。
只有源码完全相同的可重复构建才允许沿用同一版本。

Linux unit 使用 systemd 219 兼容的 `StartLimitInterval=0` 禁用启动次数锁死，
并以 `RestartPreventExitStatus=78` 排除永久配置错误。瞬时授权错误在进程内指数
退避，不依赖 systemd 高频重启。详细语义见
[`docs/reliability-and-disk-protection.zh-CN.md`](docs/reliability-and-disk-protection.zh-CN.md)。

在执行 `make package` 前，先由 SLS Proxy 发布脚本托管阿里云官方 Logtail/LoongCollector
安装脚本，并加载它生成的环境变量：

```bash
OUTPUT_DIR=/srv/secweaver-sls-proxy/releases/logtail \
PUBLIC_BASE_URL=https://agent-gateway.id-net.cn:30443 \
LOGTAIL_REGION=cn-hangzhou \
src/tools/secweaver-agent/scripts/publish-logtail-installer.sh
source /srv/secweaver-sls-proxy/releases/logtail/release.env
```

发布脚本会自动计算 `BOOTSTRAP_LOGTAIL_INSTALL_SHA256`。`package-release.sh` 会拒绝占位
Logtail URL 和空 SHA，并在 `dist/updates/stable/` 下生成无签名 manifest；设置
`UPDATE_SIGNING_PRIVATE_KEY_FILE` 时则生成签名 manifest、公钥和各平台原始升级二进制。
私钥不得进入发布包或 Git。

发布包输出到 `dist/packages/`。Linux 输出 `.tar.gz`，Windows 输出 `.zip`，每个包只包含一个 `secweaver-agent` 二进制，同时带对应平台安装脚本和示例配置。每个平台的归档还包含 `elasticsearch/` 目录，内置独立 ES 模板初始化脚本、Filebeat 示例和中英文说明。目录顶层还会生成可托管为 `/secweaver-agent/install.sh` 和 `/secweaver-agent/install.ps1` 的双平台 Bootstrap。

Windows 服务入口和控制台入口与 Linux 统一运行入口使用相同的可选 Prometheus metrics exporter。启用后默认监听 `127.0.0.1:9100/metrics`；`/live` 仅检查 HTTP 存活，`/health` 仅在所有模块运行、授权正常且没有 error 级诊断时返回 200。Windows 构建通过显式 syscall 回调适配器对接 Service Control Manager ABI，并在发布前通过与 Linux 相同的 metrics 生命周期检查。

Agent 默认还会写入独立的运维健康 JSON Lines：`/opt/secweaver-agent/logs/secweaver-agent-health.log`，Windows 为 `C:\ProgramData\SecWeaver\Agent\logs\secweaver-agent-health.log`。它每 5 分钟输出带稳定抖动的 `health_snapshot`，并在模块、授权、持久化或 audit reader 状态变化时输出 `health_transition`；启动和正常停止输出 `agent_lifecycle`。该文件沿用 100MB/5 个备份/0600/磁盘预算策略。Community 仓库的独立 ES 接入配置包含对应 Filebeat input；原生 shipper 和 Fluent Bit 交付配置不包含在公开 Agent 包中。字段和交付边界见 [`docs/operations-health-report.zh-CN.md`](docs/operations-health-report.zh-CN.md)。

### Bootstrap 发布参数由谁维护

新安装已改为动态解析版本，见[安装版本入口的发布与验证](docs/bootstrap-channel.zh-CN.md)。

托管平台维护者需从自己的部署控制面或受控配置中取得 Bootstrap 参数，并在
打包环境中设置 `BOOTSTRAP_ENROLLMENT_ID`、`BOOTSTRAP_LOGTAIL_ALIUID`、
`BOOTSTRAP_LOGTAIL_REGION`、`BOOTSTRAP_RELEASE_BASE_URL`、`BOOTSTRAP_LOGTAIL_INSTALL_URL` 和
`BOOTSTRAP_LOGTAIL_INSTALL_SHA256`。Community 源码归档不包含生产 onboarding fixture、
企业标识或凭证。Agent 版本只能来自仓库内受跟踪的 `VERSION`，不得从部署配置或环境变量改写。

托管 SaaS 的授权地址为 `https://agent-gateway.id-net.cn:30443`，因此通常不需要填写
`endpoint` 或传入 `BOOTSTRAP_LICENSE_SERVER_URL`。只有私有化部署使用另一套授权服务时，
才配置 `endpoint` 或显式覆盖该变量。`region` 建议填写阿里云标准 Region ID
`cn-hangzhou`；输入 `hangzhou` 时，发布脚本会自动规范化。

发布脚本会把这些共享参数写入 `dist/packages/install.sh`。不要手工编辑
`packaging/bootstrap-install.sh` 或生成后的公共 `install.sh`，参数变化要重新执行发布构建。
发布前可用下面的命令检查：

```bash
sed -n \
  '/SECWEAVER_BOOTSTRAP_EMBEDDED_CONFIG_BEGIN/,/SECWEAVER_BOOTSTRAP_EMBEDDED_CONFIG_END/p' \
  dist/packages/install.sh
```

输出中不能出现 `YOUR_DATA_CLOUD_HOST`、空的 `EMBEDDED_ENROLLMENT_ID` 或示例值。客户侧
安装命令只包含 `--enterprise-enrollment-token`；服务端从令牌绑定解析
`enterprise_id`。授权地址、Logtail 机器组标识、AliUid 和 region 已写入 `install.sh`；Agent 版本在安装时读取
`releases/latest-version.txt`，不再固定在脚本内。

为保持各平台分发内容一致，每个平台归档都复制 `elasticsearch/` 辅助目录。其中 Filebeat
路径和独立 Agent 安装流程面向 Linux；初始化脚本本身也可以由管理员工作站对获准的
Elasticsearch 8.x 地址执行。

Linux 包包含：

- `etc/secweaver-agent/config.example.json`
- `etc/secweaver-agent/config.schema.json`
- `etc/secweaver-agent/config.windows.example.json`
- `etc/secweaver-agent/audit-port-execmon.example.json`
- `etc/secweaver-agent/host-persistence.example.json`
- `etc/secweaver-agent/host-persistence.windows.example.json`
- `systemd/secweaver-agent.service`
- `elasticsearch/init_es.py`
- `elasticsearch/index-template.json`
- `elasticsearch/filebeat.yml`
- `elasticsearch/README.md` 和 `elasticsearch/README.zh-CN.md`
- `examples/update-server/`
- `install.sh`
- `uninstall.sh`
- README

Windows 包包含：

- `etc/secweaver-agent/config.windows.example.json`
- `etc/secweaver-agent/config.schema.json`
- `etc/secweaver-agent/host-persistence.windows.example.json`
- `elasticsearch/init_es.py`
- `elasticsearch/index-template.json`
- `elasticsearch/filebeat.yml`
- `elasticsearch/README.md` 和 `elasticsearch/README.zh-CN.md`
- `install-service.ps1`
- `uninstall-service.ps1`
- `examples/update-server/`
- README

## 升级

自升级能力由统一 `secweaver-agent` 二进制负责，不再由单个内置模块负责：

```bash
secweaver-agent update check -manifest-url https://example.com/releases/stable/update-manifest.json -device-id IMMUTABLE_DEVICE_ID
sudo secweaver-agent update install -manifest-url https://example.com/releases/stable/update-manifest.json -device-id IMMUTABLE_DEVICE_ID
sudo secweaver-agent update rollback
```

升级命令默认向 stderr 输出一条 JSON 状态记录。需要落文件时可使用 `-status-output /opt/secweaver-agent/logs/secweaver-agent-update.log`，输出格式为 JSON Lines。

| 参数 | 说明 |
|---|---|
| `-manifest-url` | HTTPS URL 或本地 manifest 路径；默认读取 `SECWEAVER_AGENT_UPDATE_MANIFEST_URL` |
| `-public-key` | 可选的受信 Ed25519 发布公钥（Base64）；配置后强制要求签名清单 |
| `-allow-unsigned-local` | 废弃兼容参数；未配置公钥时默认就是无签名清单 |
| `-allow-insecure-http` | 仅开发诊断：允许 HTTP；默认仍要求 HTTPS |
| `-channel` | 请求的升级通道，默认 `stable` |
| `-state-dir` | 升级锁、状态、待替换文件、备份目录；默认 `/opt/secweaver-agent/data/update` 或 `C:\ProgramData\SecWeaver\Agent\data\update` |
| `-self-path` | 要替换的 agent 二进制路径；默认当前可执行文件 |
| `-device-id` | 独立执行升级时必填的不可变设备身份；受管升级从设备注册状态读取 |
| `-host-id` | `-device-id` 的废弃兼容别名；不再默认使用主机名 |
| `-status-output` | JSON Lines 状态输出位置；`-` 表示 stderr |

定时升级默认关闭。需要自动检查/安装时，在 `config.json` 中启用 `update` 配置块：

```json
{
  "enterprise_id": "REPLACE_WITH_16_CHAR_ID",
  "status_path": "/opt/secweaver-agent/data/status.json",
  "update": {
    "enabled": true,
    "manifest_url": "https://example.com/releases/stable/update-manifest.json",
    "channel": "stable",
    "interval_seconds": 21600,
    "initial_delay_seconds": 60,
    "jitter_seconds": 300,
    "retry_initial_seconds": 60,
    "retry_max_seconds": 3600,
    "auto_install": true,
    "require_server_policy": true,
    "health_timeout_seconds": 90,
    "lock_stale_seconds": 3600,
    "max_backups": 3,
    "min_free_space_mb": 256,
    "status_output": "/opt/secweaver-agent/logs/secweaver-agent-update.log"
  }
}
```

`require_server_policy=true` 时，Agent 只有收到设备密钥认证后的服务端企业升级策略才会
安装；SLS SaaS 使用已部署的 Agent Gateway 控制面，企业自建 ES 使用独立 Agent 配置，
不需要 SecWeaver 服务端源码。托管控制面负责目标版本、固定活动设备范围、稳定灰度环、维护窗口、暂停、并发百分比
和绝对台数、失败率熔断、受控回退以及自动安装开关。
灰度身份只使用注册后不可变的 `device_id`，缺失时拒绝受管升级，不再回退到主机名。服务端
没有授予升级租约、租约格式错误或剩余不足 3 分钟时，Agent 都会 fail closed。清单或二进制
临时下载失败时按 1 分钟到 1 小时指数退避并加入稳定 jitter，同时遵循 HTTP `Retry-After`。定时安装
后 Agent 会主动退出，由服务管理器启动新二进制；新版本经过默认 90 秒
模块健康观察后才提交。观察期要求所有模块持续运行且至少一个模块产生新输出；观察期重启、
模块不健康或输出链路不工作都会自动恢复上一版本，Linux 启动器还能处理
新二进制无法执行的情况。默认会回收超过 1 小时的遗留升级锁，只保留 3 份二进制备份，并在
下载前检查 256 MiB 磁盘余量。`auto_install=false` 时只检查，不替换自身。

二进制提交采用持久化预提交日志。Agent 先完成备份、恢复标记和 `commit_prepared` 状态落盘，
再原子替换 Linux 二进制或安排 Windows 退出后替换；提交开始后即使策略、租约或进程上下文同时
取消，也不会把已提交结果覆盖成 `policy_deferred`。最终状态写入失败时保留预提交日志和备份，
下次启动仍能进入健康确认或自动回滚，而不会留下“二进制已更新但控制状态未知”的静默窗口。

升级服务器、nginx、manifest 和客户端配置示例见 [`examples/update-server/README.zh-CN.md`](examples/update-server/README.zh-CN.md)。

启用签名时，对外发布的是签名信封；未配置公钥时，Agent 直接接受 HTTPS manifest，
仍校验二进制 URL、大小和 SHA-256。只要配置或曾持久化任一可信公钥，Agent 就强制要求签名，
因此完成签名信任轮换后不会静默降级到无签名 manifest。签名信封的 `payload` 是 Base64 编码的 manifest JSON，
`signature` 覆盖解码后的原始字节：

```json
{
  "key_id": "ed25519-0123456789abcdef",
  "payload": "BASE64_ENCODED_MANIFEST_WITH_ARTIFACT_SIGNATURES",
  "signature": "BASE64_ED25519_SIGNATURE"
}
```

payload 的逻辑元数据必须包含单调代次和过期时间。过渡清单可只携带旧版已识别的微秒精度
`generated_at`，Agent 从它派生 generation 和 14 天有效期；全部设备升级后应显式发布 `generation` 和
`expires_at`。Agent 按通道持久化
已经接受的最高代次和签名摘要，拒绝旧代次回放、同代次不同内容和过期清单；信任公钥变更
也只有通过这些检查后才会落盘。每个 `binaries.<platform>` 同时包含 `url`、`sha256`、`size`、
`signature_format=ed25519-sha256` 和摘要签名；0.3.2 过渡升级可暂用旧 `ed25519` 原文签名。二进制流式下载到受限临时文件，边下载边计算
SHA-256 并执行 `fsync`，不会把最大 512 MiB 物料整体读入内存；策略 revision、暂停或租约到期
会取消下载并清理临时文件。任何校验失败都不会替换当前程序。版本判断严格遵循 SemVer 2.0.0，
包括预发布版本优先级和构建元数据。

托管模式下，服务端是唯一灰度权威：Agent 收到逐设备资格和租约后，不再执行 manifest 的
`rollout.percentage`、允许名单或拒绝名单。托管服务的发布门禁会拒绝携带
这些二次灰度字段的托管清单。`download_spread_seconds` 只用于已获服务端批准设备的下载
削峰，不改变升级资格。Manifest 灰度字段仅为无控制面的 standalone 更新保留兼容能力。

### 发布公钥轮换和紧急停止

公钥轮换必须连续发布两份 manifest：先用当前私钥签名并加入新公钥，再用新私钥签名并撤销
旧 Key ID：

```bash
go run ./cmd/update-sign -manifest unsigned.json -artifact-dir dist \
  -private-key-file current.key -add-public-key-file next.key.pub -out update-manifest.json
go run ./cmd/update-sign -manifest unsigned.json -artifact-dir dist \
  -private-key-file next.key -revoke-key-id ed25519-OLD_KEY_ID -out update-manifest.json
```

Agent 会把签名 keyring 持久化到升级状态目录，拒绝已撤销签名者，也拒绝“撤销全部可信公钥”
的错误变更。发布系统需要脱离 Data Cloud 策略紧急停更时，用当前可信私钥增加
`-emergency-stop-reason "原因"` 发布签名停止 manifest；后续可信 manifest 去掉该字段即可恢复。

已经通过健康观察的版本需要远程回退时，发布人员必须同时设置
`-rollback-from-version`、`-rollback-reason` 和未来的 `-rollback-expires-at`。Agent 还要求
Data Cloud 策略显式设置 `allow_downgrade`，并逐项匹配当前版本和目标版本；普通签名清单不能
触发降级。

Windows 正式发布在完成 Authenticode 代码签名后，应在对应 artifact 中配置
`authenticode_publisher_sha256` 允许列表。Windows Agent 会先验证 Ed25519 发布签名，再调用系统
Authenticode 验证并匹配发布者证书 SHA-256；过渡包未配置该列表时保持兼容。

真实服务升级回滚测试位于
[`integration/service-upgrade/`](integration/service-upgrade/README.md)，分别使用 systemd 和
Windows SCM。

Linux 安装时会原子替换二进制并返回 `installed`，systemd 通过稳定启动器启动和必要时恢复
上一版。新安装单元将专用退出码 `75` 识别为“正常但必须重启”，避免升级窗口产生失败误告警；
二进制在旧单元上仍默认返回 `1`，保持向后兼容。Windows 不能覆盖正在运行的 `.exe`，所以
安装/回滚先把文件暂存在同一文件系统，返回 `install_scheduled` 或 `rollback_scheduled`，待进程
退出后通过 Windows `File.Replace` 原子提交。Windows 服务恢复动作在连续启动失败时执行外部
回滚脚本，回滚二进制也使用相同的原子替换语义。

## 配置

Linux 示例见 [`config.example.json`](config.example.json)：

```json
{
  "enterprise_id": "REPLACE_WITH_16_CHAR_ID",
  "update": {
    "enabled": false,
    "manifest_url": "https://updates.example.com/secweaver-agent/stable/update-manifest.json",
    "channel": "stable",
    "interval_seconds": 21600,
    "initial_delay_seconds": 60,
    "jitter_seconds": 300,
    "retry_initial_seconds": 60,
    "retry_max_seconds": 3600,
    "auto_install": true,
	"public_key": "BASE64_ED25519_PUBLIC_KEY",
    "status_output": "/opt/secweaver-agent/logs/secweaver-agent-update.log"
  },
  "modules": {
    "audit-port-execmon": {
      "enabled": true,
      "restart": "on_failure",
      "restart_delay_seconds": 5,
      "args": ["-config", "/opt/secweaver-agent/etc/audit-port-execmon.json"]
    },
    "syslog-risk-json": {
      "enabled": true,
      "restart": "on_failure",
      "restart_delay_seconds": 5,
      "args": ["-secure", "auto", "-messages", "auto", "-output", "/opt/secweaver-agent/logs/syslog-risk-json.log"]
    },
    "host-persistence": {
      "enabled": true,
      "restart": "on_failure",
      "restart_delay_seconds": 5,
      "args": ["-config", "/opt/secweaver-agent/etc/host-persistence.json"]
    }
  }
}
```

Windows 示例见 [`config.windows.example.json`](config.windows.example.json)：

```json
{
  "enterprise_id": "REPLACE_WITH_16_CHAR_ID",
  "status_path": "C:\\ProgramData\\SecWeaver\\status.json",
  "modules": {
    "windows-eventlog-risk-json": {
      "enabled": true,
      "args": ["-channels", "Security,System,Microsoft-Windows-PowerShell/Operational,Microsoft-Windows-Sysmon/Operational", "-evidence-output", "C:\\ProgramData\\SecWeaver\\windows-process-execmon.log"]
    },
    "windows-process-execmon": {
      "enabled": false,
      "args": ["-channels", "Security,Microsoft-Windows-Sysmon/Operational"]
    },
    "host-persistence": {
      "enabled": true,
      "args": ["-config", "C:\\ProgramData\\SecWeaver\\host-persistence.json"]
    }
  }
}
```

字段说明：

| 字段 | 说明 |
|---|---|
| `enterprise_id` | 必填，由 SecWeaver 平台签发的 16 位企业 ID |
| `status_path` | Agent 本地健康状态文件；记录授权检查、心跳错误、模块状态、PID、重启次数和最近启动/退出时间 |
| `operations_report` | 默认开启的 Agent 运维健康 JSONL；默认每 300 秒输出快照并加入最多 60 秒稳定抖动，记录模块、共享 audit reader、授权、持久化和 shipper 配置状态 |
| `disk_budget` | 默认启用；Agent 管理输出总预算 2048MB，最低剩余空间 512MB，每 30 秒检查；快照会比实时日志更早停写 |
| `license.outage_grace_seconds` | 控制面临时网络故障或 HTTP 408/425/429/5xx 时可使用最近一次成功授权的最长时间，默认 86400 秒，设为 `0` 禁用，最大 604800 秒 |
| `remote_config` | 可选的 Data Cloud 托管策略拉取；启用后 Agent 定时拉取完整签名配置，校验通过后替换 `config.json` 并退出，由服务管理器重启生效 |
| `modules.<name>.enabled` | 是否启用模块；不写时默认启用 |
| `modules.<name>.args` | 传给模块的原生命令行参数 |
| `modules.<name>.restart` | `never`、`on_failure`、`always`，默认 `on_failure` |
| `modules.<name>.restart_delay_seconds` | 模块重启等待时间，默认 3 秒 |
| `modules.<name>.restart_max_delay_seconds` | 指数退避上限，默认 300 秒 |
| `modules.<name>.restart_failure_limit` | 连续失败熔断阈值，默认 8 次 |
| `modules.<name>.restart_stable_seconds` | 运行多久后清零连续失败，默认 300 秒 |
| `modules.<name>.restart_circuit_seconds` | 熔断后暂停该模块多久，默认 900 秒 |

必须将 `REPLACE_WITH_16_CHAR_ID` 替换为平台签发值；发布包中的占位符故意不能通过校验。Agent 配置契约见 [`config.schema.json`](config.schema.json)，运行时也会拒绝未知字段、未知模块参数和非法重启策略。`secweaver-agent run`、`preflight` 和 Windows 服务启动会在采集模块启动前完成同一套校验。Agent 启动时会自动探测并缓存主机名与非回环主 IP，再传给所有采集模块；每条采集 JSON Lines 记录都会在统一输出边界保证包含 `enterprise_id`、`host_name`、`host_ip`。多网卡主机可通过 `SECWEAVER_HOST_IP` 显式选择地址，`SECWEAVER_HOST_NAME` 可覆盖系统主机名；非法或回环地址会使事件输出拒绝启动。

所有通过 Agent 统一输出 writer 写入的增长型日志都会内置按大小轮转，包括采集 JSON Lines 和升级状态日志。默认单文件上限 100MB，保留 5 个备份，文件名为 `*.log.1`、`*.log.2` 等。POSIX 系统上这些文件强制使用 `0600`；每次打开日志时会同时修复当前文件和已保留的数字轮转备份，因此升级后会自动收紧旧版遗留的 `0644` 权限。Windows 不依赖 POSIX mode，而由安装根目录 ACL 限制为 `SYSTEM` 和本地 Administrators。Windows service 包装层自身不创建专用 service log 文件。本地健康状态、授权 state 和 Windows EventRecordID cursor 是覆盖写的小状态文件，不按追加日志处理。

Linux 发布包的 systemd unit 默认把整个 Agent 进程树限制在单核 50% CPU、512MB 内存、128 个任务和 8192 个文件句柄以内，并降低 CPU/IO 调度优先级；同时设置 `LimitMEMLOCK=infinity`，兼容仍按 memlock 记账的旧 eBPF 内核。宿主机内存紧张时 Agent 也会优先于业务进程被回收。授权或网络瞬时故障由进程内有界退避持续重试，systemd 不再设置永久启动次数锁；本地配置非法时以状态码 78 退出并明确禁止重启，避免形成配置错误重启风暴。高密度主机确需提高限制时，通过 `systemctl edit secweaver-agent` 添加本地 override，不要直接修改发布 unit。

授权仍是 fail-closed，但控制面短暂故障不会立即停止采集：只有临时网络故障或 HTTP 408/425/429/5xx，且本地存在最近一次成功授权时，Agent 才在 `license.outage_grace_seconds` 窗口内降级运行。首次安装、设备作废、订阅过期、额度拒绝、其他 HTTP 4xx、证书错误、配置错误和本地授权状态损坏均不会使用缓存；已知订阅到期时间也会截断宽限窗口。

在 Linux 上通过 `secweaver-agent run` 托管多个 audit 消费模块时，agent 会自动启用单 `audit.log` reader/demux：如果 `audit-port-execmon` 和 `host-persistence` 使用相同 `audit_log` 且 `from_start` 策略一致，父进程只跟随一次 audit 日志，再按 audit key 分发给子模块。demux 为每个模块维护 4096 行固定容量的未投递环形队列，不缓存无关 audit ID，也不会在锁内写健康状态；订阅队列满或管道写入失败时会主动结束该订阅，由 supervisor 重启模块并补发未投递记录。若模块持续不可用并耗尽环形队列，最旧证据会被覆盖，但覆盖累计数、audit ID 和 error 诊断会明确导出，不会静默丢数。reader 首次打开、路径丢失和轮转重开失败也会进入健康状态，恢复后自动清除。单独运行 `secweaver-agent module ...` 时仍由模块自己读取 audit 日志；设置 `host-persistence` 的 `audit.follow_log=false` 会让它退出 demux 订阅。

`audit-port-execmon` 使用模块 JSON 配置，可把 [`audit-port-execmon.example.json`](audit-port-execmon.example.json) 复制到 `/opt/secweaver-agent/etc/audit-port-execmon.json` 后调整。进程树后端默认 `exec.process_tree_backend="auto"`：Linux amd64/arm64 主机存在 `/sys/kernel/btf/vmlinux` 且 eBPF 程序可加载时，使用固定的 fork/exec/exit CO-RE 程序和内核 PID 归属 map；能力、权限或 verifier 检查失败时回退到新的有界 `audit` 后端。该后端每个 arch 只安装固定的整机 exec/clone 规则，在用户态按 listener PID 树过滤和归属，规则数不再随进程数增长；默认 `b64` 配置为两条 syscall 规则，加一条 `/etc/shadow` watch。设置为 `ebpf` 可禁止回退，设置为 `audit` 可强制固定规则后端；只有明确兼容旧行为时才设置 `audit_pid`，它会恢复逐 PID/PPID 动态规则。目标主机不需要 Clang、内核头文件或 libbpf，CO-RE 对象已嵌入 Agent。eBPF 默认最多跟踪 131072 个进程，每 CPU perf buffer 为 256KB；命令最多采集 16 个、每个 96 字节的参数，截断时输出 `command_truncated=true`。

eBPF exec 事件会在进程仍存活时，从 `/proc/<pid>` 尽力补齐 `auid`、`auid_name`、`cwd`、`tty` 和 `has_tty`。`has_tty` 是三态契约：只有 `/proc/<pid>/stat` 能确认是否存在控制终端时才输出 `true` 或 `false`；短命进程已退出或 procfs 读取失败时省略该字段。下游必须把字段缺失解释为“未知”，不能解释为“无交互终端”。audit 后端仍直接从内核 audit 记录获得这些字段，通常能提供更完整的会话上下文。

eBPF 仅替换动态 exec/clone 进程树能力。`connect.monitor`、`file_ops.monitor` 和敏感文件读取仍使用 audit；前两项默认关闭，敏感文件默认只保留一条 `/etc/shadow` read watch。有界 `audit` 回退会让 auditd 记录整机 exec/clone，再在进入事件累积器前丢弃不属于目标 listener 树的记录；它显著降低内核规则匹配成本，但高进程创建率主机仍需关注 audit 日志吞吐。进程退出由每 5 分钟对账清理，PID 归属以 `/proc` starttime 防复用。`audit.max_rules=1024` 同时约束固定规则和 watch；事务回滚、启动遗留清理和退出清理保持不变。运行 `secweaver-agent preflight` 或 `doctor` 可检查 BTF、exec tracepoint 和实际回退条件。

listener 对账默认每 5 分钟运行一次，实时 clone/exec 归属仍由 eBPF 或 audit 事件维护，对账只修复 listener 变化和遗漏。发现过程先执行强制 `LC_ALL=C`、`LANG=C` 的 `netstat -tlnp`；解析器不依赖固定列宽或固定的 `LISTEN-2`/`LISTEN+1` 偏移，而是在大小写不敏感的 `LISTEN` 前寻找第一个地址字段、在后续列中寻找 PID/Program。它兼容标准 net-tools、BusyBox 风格 `*:port`、带或不带方括号的 IPv6、附加厂商列、缺失 PID 列，以及包含冒号或空格的进程标签。每次执行都会分别统计原始 TCP LISTEN、成功解析和拒绝行；任一监听行不能解析时会记录 `netstat listener parse incomplete` 并强制进入 procfs 补全，不会静默接受部分结果。

只要所有相关监听都包含有效 PID，就不会扫描 `/proc/<pid>/fd`。仅当 netstat 失败、没有结果、相关监听缺少 PID 或存在拒绝行时，才读取 `/proc/net/tcp*` 并建立 socket inode 映射。回退扫描每批最多读取 128 个 FD、批间暂停 1ms，且单轮最多检查 32768 个 FD；达到预算会输出诊断并等待下一轮修复，不会因某个 inode 未命中再次全盘扫描。生产配置应保持 `listener_rescan_seconds=300`，缩短该值会按比例增加进程和 FD 扫描开销。该链路只用于 Linux systemd 采集目标；Windows 使用 Event Log/Sysmon，macOS 不是受支持的采集端。

`audit.pressure` 默认开启，但只对 `audit_pid` 及 eBPF 下显式启用的动态 connect/file 规则执行动态规则降级。有界 `audit` 和纯 eBPF exec 模式没有 PID 规则扩展，不会每 30 秒调用 `auditctl -s`；audit reader 的 backlog、丢失和订阅覆盖仍通过 Agent 健康状态与指标观察。动态规则启用时，模块按 backlog `80%/90%/95%` 或单周期新增 lost `1/5/20` 分级降压，并在 cooldown 后限速补齐。

远程配置拉取采用 fail-closed 策略。启用 `remote_config` 时必须配置 `public_key`，Agent 默认要求 Ed25519 签名验证通过才替换本地配置。`allow_unsigned=true` 只用于隔离的开发环境。签名错误、企业 ID 不匹配、未知字段、模块参数非法、license/update 配置无效都会被拒绝。Data Cloud 暂时不可达时只记录网络错误并采用 1 分钟起、15 分钟封顶的指数退避；Agent 不会因临时网络故障退出，恢复后自动重新注册、心跳并拉取配置。明确拒绝、证书错误和本地配置损坏仍按 fail-closed 处理。

`host-persistence` 使用模块 JSON 配置。Linux 可把 [`host-persistence.example.json`](host-persistence.example.json) 复制到 `/opt/secweaver-agent/etc/host-persistence.json` 后调整；Windows 安装脚本会把 [`host-persistence.windows.example.json`](host-persistence.windows.example.json) 复制到 `C:\ProgramData\SecWeaver\Agent\etc\host-persistence.json`。首次启动默认只建立 baseline，不输出已有文件；后续新增、修改、删除会输出 `asset_type=host_persistence`、`event_type=persistence_change` 的 JSON Lines。事件会自动识别并输出 `host_ip`；多网卡主机可在模块 JSON 中设置 `host_ip`，或使用 `-host-ip` 覆盖自动识别结果。Linux 默认输出 `/opt/secweaver-agent/logs/host-persistence.log`，auditd 可用时会富化 `user`、`process`、`command` 等字段；模块每分钟把已配置且当前存在的 watch 路径与内核规则对账，补齐新路径或原子替换后失效的 watch。audit reader 异常退出会触发模块重启，不会静默丢失富化。Windows 默认输出 `C:\ProgramData\SecWeaver\Agent\logs\host-persistence.log`，关闭 audit 富化，监控计划任务、启动目录、组策略脚本、PowerShell profile 等文件型持久化位置。小文本文件会输出受限 `content_diff`。如果 Linux 同机 audit 事件量很大、且已由其他模块集中消费 audit.log，可设置 `audit.follow_log=false` 关闭本模块的 audit.log follower；此时仍可管理 watch 规则，但事件不会带 actor/process 富化。

`host-process-snapshot` 在 Linux/Windows 默认开启。启动时输出完整 `process_snapshot` 基线，之后每 10 分钟只输出 `process_start`、`process_exit`、`process_change`，每 24 小时重发完整基线。增量身份键为 `pid+start_time`，状态原子保存到平台默认状态目录。完整基线仅保留 `command_hash`；高价值增量事件保留脱敏后的命令。Linux 读取 `/proc`，Windows 使用一次 PowerShell/CIM 批量查询。详见 `docs_user/32-host-process-snapshot.zh-CN.md`。

`host-state-snapshot` 在 Linux/Windows 默认开启。监听端口、身份和服务均每 5 分钟检查，内核与容器上下文每 10 分钟检查。各类采集首次输出完整基线，中间只输出变化，每 24 小时重发完整基线。Linux 端口归属扫描默认最多检查 10 万个 FD；任一采集不完整时不更新状态，避免产生假删除事件。详见 `docs_user/33-host-state-snapshot.zh-CN.md`。

注意：旧版独立 `syslog-risk-json` 构建里的 `-update-check`、`-update-now`、`-rollback` 是“替换自身二进制”能力。进入 `secweaver-agent` 后，这组参数在内置模块中会被拒绝，避免用旧模块 manifest 覆盖统一 agent；统一客户端应使用 `secweaver-agent update ...` 或发布包升级。

## 运行

### 安装目录

新安装把 Agent 自身拥有的程序、配置、状态、日志和 shipper 放在同一产品根目录下：

```text
/opt/secweaver-agent/                 C:\ProgramData\SecWeaver\Agent\
|-- bin/       Agent/launcher         |-- bin\
|-- etc/       config/module config   |-- etc\
|-- data/      state/cursor/update    |-- data\
|-- logs/      module JSONL           |-- logs\
`-- shipper/   shipper/config/CA      `-- shipper\
```

Linux 仅在 `/usr/local/bin/secweaver-agent` 保留命令软链接，systemd unit 仍放在
`/etc/systemd/system`；它们是操作系统入口，不存放产品数据。Windows 根目录会去除继承写权限，
仅 `SYSTEM` 和本地 Administrators 可修改，避免 ProgramData 中的服务可执行文件被普通用户劫持。

查看内置模块：

```bash
./secweaver-agent modules
```

检查配置：

```bash
./secweaver-agent run -config ./config.example.json -dry-run
./secweaver-agent preflight -config ./config.example.json
```

常驻运行：

```bash
sudo ./secweaver-agent run -config /opt/secweaver-agent/etc/config.json
```

推荐从企业工作台的“secweaver-agent → 一键安装”复制 Bootstrap 命令；查询 AK/SK 在“智能体配置”中获取：

```bash
curl -fsSL 'https://YOUR_DATA_CLOUD_HOST/secweaver-agent/install.sh' \
  | sudo bash -s -- \
      --enterprise-enrollment-token 'swenr_TOKEN_ID.SECRET'
```

生产 Bootstrap 必须使用公开受信任的 HTTPS 证书，安装命令不支持 `curl -k`。

Bootstrap 只支持 Linux systemd 主机，会自动识别 `amd64`、`arm64`、`loong64`，从
脚本内置的发布根地址下的 `<version>/` 下载 `.tar.gz` 和 `.sha256`，校验后调用包内
`install.sh`。版本在本次安装开始时从 `releases/latest-version.txt` 解析一次；授权服务地址和
阿里云机器组自定义标识 `enrollment_id` 在发布时写入 Bootstrap，用户只传企业安装令牌。
SecWeaver AK/SK 只保存在 企业工作台 / SecWeaver Data Cloud 服务端，不会下发到客户主机。
安装器先生成硬件关联的 `device_id` 和 Ed25519 设备密钥，完成订阅、额度和企业归属校验后才启动采集。
运行中心跳由设备私钥签名，用于维护在线/离线和模块健康状态。
默认注册可管理 3 台设备，超过 3 台需要购买订阅或扩容授权。Bootstrap 还会安装或复用 Logtail，写入内置 AliUid 和配置的
`enrollment_id`，最后执行严格 preflight、强制重启 Agent 使升级配置生效，并执行安装后诊断。机器组和
Logstore 的绑定由 SecWeaver Data Cloud 服务端维护，不传给主机。生产下载地址必须是 HTTPS；
`--allow-http` 只用于本地测试。只需本地 Agent 时可显式使用 `--skip-logtail`。

离线环境可以手工使用发布包安装：

```bash
AGENT_VERSION='<已下载版本>'
tar -xzf "secweaver-agent_${AGENT_VERSION}_linux_amd64.tar.gz"
cd "secweaver-agent_${AGENT_VERSION}_linux_amd64"
sudo ./install.sh \
  --enterprise-enrollment-token 'swenr_TOKEN_ID.SECRET' \
  --license-server-url https://agent-gateway.id-net.cn:30443
sudo systemctl enable --now secweaver-agent
```

升级旧的分散布局时，安装器会复制旧配置和状态到统一根目录，再通过
`secweaver-agent config migrate-layout` 结构化更新已知的 SecWeaver 路径。用户自定义路径和
`/var/log/audit/audit.log` 等系统输入不会被改写。迁移只复制、不删除旧文件，便于服务启动失败时回退。
安装器还会补入缺失的主机快照设置并优化重复的 Windows reader。

ES enrollment 命令通过 `SECWEAVER_BOOTSTRAP_CA_FILE` 传入临时 CA 时，Linux 安装器会在
读取旧配置前校验并持久化该信任根。当前标准路径为
`/opt/secweaver-agent/shipper/ca.crt`；为兼容旧配置，升级时也会同步维护
`/opt/secweaver-agent/etc/shipper/ca.crt`。安装结束后可以安全删除下载到 `/tmp` 的临时文件。

新安装必须传入 `--enterprise-enrollment-token`。安装器会在本机哈希硬件信号，生成
Ed25519 设备密钥和 `device_id`，注册成功后才把服务端返回的 `enterprise_id` 原子写入配置。
`--enterprise-id` 只为 v1 旧安装迁移保留。迁移旧版本时，安装器会停止并禁用独立的
`syslog-risk-json.service`、`audit-port-execmon.service`；若仍有旧独立二进制进程，则拒绝安装。
`install.sh` 默认要求 systemd，并会检测或安装 `auditctl`、`netstat` 及其依赖。内网自行管理依赖时，
可使用 `INSTALL_DEPS=0`；非 systemd 环境可用 `REQUIRE_SYSTEMD=0`，两者都只建议在受控迁移中使用。

systemd unit 配置了 `ExecStopPost=/opt/secweaver-agent/bin/secweaver-agent audit-cleanup -quiet`，服务停止后会兜底清理 `tb_external_listener_*`、`tb_port_*`、`tb_host_persistence` audit 规则。需要手工清理时可执行：

```bash
sudo /usr/local/bin/secweaver-agent audit-cleanup
```

Linux 发布包卸载：

```bash
sudo ./uninstall.sh
```

`uninstall.sh` 会停止 Agent/shipper 服务、删除 systemd unit、清理 audit 规则，并默认删除
`/opt/secweaver-agent/bin` 与命令软链接。配置、状态、日志和 shipper 默认保留；
`sudo ./uninstall.sh --purge` 删除整个 `/opt/secweaver-agent`。其他卸载开关和 `--json` 验证输出保持不变。

直接运行单个模块：

```bash
sudo SECWEAVER_ENTERPRISE_ID=YOUR_16_CHAR_ID ./secweaver-agent module audit-port-execmon -config /opt/secweaver-agent/etc/audit-port-execmon.json
sudo SECWEAVER_ENTERPRISE_ID=YOUR_16_CHAR_ID ./secweaver-agent module syslog-risk-json -secure auto -messages auto -output -
sudo SECWEAVER_ENTERPRISE_ID=YOUR_16_CHAR_ID ./secweaver-agent module host-persistence -config /opt/secweaver-agent/etc/host-persistence.json
sudo SECWEAVER_ENTERPRISE_ID=YOUR_16_CHAR_ID ./secweaver-agent module host-process-snapshot -once -output -
```

一次性回溯已有日志：

```bash
sudo /usr/local/bin/secweaver-agent collect-existing-logs -config /opt/secweaver-agent/etc/config.json
sudo /usr/local/bin/secweaver-agent collect-existing-logs -config /opt/secweaver-agent/etc/config.json -lookback 2160h -output /opt/secweaver-agent/logs/syslog-risk-json-history.log
```

`collect-existing-logs` 默认回溯 180 天。Linux 会读取 `syslog-risk-json` 对应的 secure/auth、messages/syslog 当前日志和常见轮转文件（包含 `.gz`），输出格式与实时 `syslog-risk-json` 一致。Windows 会一次性读取 `windows-eventlog-risk-json` 对应 Event Log 的回溯窗口，并默认关闭 `EventRecordID` cursor 写入，避免影响常驻实时采集游标。该命令不会作为服务默认启动，建议在历史攻击分析、首次接入补数或演练时手动执行。

在 Windows 上可用管理员 PowerShell 直接运行模块：

```powershell
.\secweaver-agent.exe module windows-eventlog-risk-json -once -output -
.\secweaver-agent.exe module windows-process-execmon -once -output -
.\secweaver-agent.exe collect-existing-logs -config C:\ProgramData\SecWeaver\Agent\etc\config.json
```

Windows 发布包安装为系统服务：

```powershell
$AgentVersion = '<已下载版本>'
Expand-Archive ".\secweaver-agent_${AgentVersion}_windows_amd64.zip" -DestinationPath .
Set-Location ".\secweaver-agent_${AgentVersion}_windows_amd64"
Set-ExecutionPolicy -Scope Process Bypass -Force
.\install-service.ps1 `
  -EnterpriseEnrollmentToken 'swenr_TOKEN_ID.SECRET' `
  -LicenseServerUrl 'https://agent-gateway.id-net.cn:30443'
```

正式交付优先执行 Data Cloud CLI 使用 `--platform windows` 生成的一键 PowerShell
命令。安装器在本机生成硬件关联指纹和 Ed25519 设备密钥，服务端根据企业安装令牌
返回 `enterprise_id`；不要让客户手工填写企业 ID。`-EnterpriseId` 只保留给明确的
旧版 v1 迁移流程，不能与 `-EnterpriseEnrollmentToken` 同时使用。

管理员权限运行的安装脚本会使用稳定的审计子类别 GUID 自动启用“审核进程创建”的成功事件，
并设置 `ProcessCreationIncludeCmdLine_Enabled=1`。此后新产生的 Security 4688 会直接向
`windows-process-execmon.log` 提供可执行文件和命令行证据，不再要求运维手工开启策略。
如果任一策略配置失败，安装会在替换程序或停止已有 Agent 之前终止。域组策略后续仍可能覆盖
本地设置，可通过 `secweaver-agent doctor` 检查命令行审计状态。Windows 会把进程参数以明文
写入 Security 日志，因此必须继续限制该日志的读取权限。卸载 Agent 不会关闭这些主机级审计策略。

默认安装位置：

- 程序：`C:\ProgramData\SecWeaver\Agent\bin\secweaver-agent.exe`
- 配置：`C:\ProgramData\SecWeaver\Agent\etc\config.json`
- host-persistence 配置：`C:\ProgramData\SecWeaver\Agent\etc\host-persistence.json`
- 服务：`SecWeaverAgent`
- 服务包装层日志：不单独写文件；查看服务状态/事件查看器和模块 JSONL 输出

服务管理：

```powershell
Get-Service SecWeaverAgent
Restart-Service SecWeaverAgent
.\uninstall-service.ps1
```

Windows 注意事项：

- Windows 默认只由 `windows-eventlog-risk-json` 一个 `wevtutil` reader 读取 Security、System、PowerShell 和 Sysmon。它把风险写入 `windows-eventlog-risk-json.log`，同时通过 `-evidence-output` 把 Security 4688 和 Sysmon 1/3/11/23 映射为 `host_exec`、`host_connect`、`host_file_op` 写入 `windows-process-execmon.log`。
- 独立 `windows-process-execmon` 模块仍保留，供关闭统一证据输出的部署使用，默认每 5 分钟轮询一次；默认包已关闭它。若两个模块同时启用，必须给 `windows-eventlog-risk-json` 显式传入 `-evidence-output=`，把证据所有权交给 standalone reader，否则 preflight 和启动会拒绝配置，避免重复查询、重复事件和两个 writer 竞争同一日志。
- 两种 reader 共用 `internal/windowsevidence` 的 Security/Sysmon 证据分类器。Agent 自身 PowerShell 采集脚本通过完整脚本 SHA-256 精确登记；只复制 marker 或在合法脚本后追加命令不会被当作内部活动抑制。
- 活动 reader 使用 `C:\ProgramData\SecWeaver\Agent\data\windows-eventlog-risk-json.cursor.json` 持久化一份 `EventRecordID` 游标。输出 flush 并同步成功后才推进游标。可通过 `-state-file <path>` 改路径，传空值可关闭持久化。
- `host-persistence` 在 Windows 默认开启，输出到 `C:\ProgramData\SecWeaver\Agent\logs\host-persistence.log`；当前监控文件型持久化位置，尚未采集注册表持久化。
- `host-process-snapshot` 在 Windows 默认开启，每 10 分钟扫描增量、每 24 小时输出完整基线，写入 `C:\ProgramData\SecWeaver\Agent\logs\host-process-snapshot.log`；不会创建单独的 Windows service 自身日志。
- 管理员权限运行的服务安装脚本会自动启用 Audit Process Creation 成功事件和命令行数据；域组策略后续可能覆盖本地设置。网络连接和文件创建/删除证据仍需安装并启用 Sysmon。
- Windows 服务入口为 `secweaver-agent.exe service -config C:\ProgramData\SecWeaver\Agent\etc\config.json`，由安装脚本自动注册。

## 迁移

原来的两个 standalone 工具目录已删除。统一构建并安装 `src/tools/secweaver-agent`，通过 `secweaver-agent run` 或 `secweaver-agent module <name>` 运行采集模块。

唯一实现源码位于 `src/tools/secweaver-agent/pkg/`。已有模块参数和配置可以继续放到 `modules.<name>.args` 中，不需要重写采集逻辑。

`audit_demux.go` 负责 `secweaver-agent run` 托管模式下的单 audit reader、路由和重放；`audit_demux_observability.go` 独立负责 reader 状态、积压覆盖诊断和只读指标快照；`pkg/auditstream` 提供父进程跟随 audit 日志和子进程接收共享 FD 的基础能力。每个模块在自己的 `descriptor.go` 中声明 flag、平台、输出路径和可选 audit 订阅，supervisor 不再解析模块私有 JSON 或复制 audit key 规则。

`pkg/auditportexecmon` 已按职责拆分，避免后续主机采集能力继续长成一个大文件：

| 文件 | 职责 |
|---|---|
| `main.go` | CLI 参数和模块编排 |
| `config.go` | JSON 配置、默认值、校验和选项归一化 |
| `listeners.go` / `procfs.go` | 对外监听发现和 `/proc` 辅助函数 |
| `monitor_state.go` / `monitor_worker.go` | 进程树状态、异步规则队列、背压和统计快照 |
| `monitor_bootstrap.go` / `monitor_listener_reconcile.go` / `monitor_listener_roots.go` | 初始覆盖、监听对账和 Web/Java/SSH 特殊根进程策略 |
| `monitor_pid.go` / `monitor_pid_rules.go` / `monitor_pid_cleanup.go` / `monitor_ebpf.go` | PID 归属、规则预算与扩展、死亡清理和 eBPF 生命周期归属 |
| `monitor_self.go` / `companion.go` | Agent 自身进程排除和 Web 网关伴随进程发现 |
| `audit_rules.go` | auditctl 规则添加、删除和清理 |
| `audit_follow.go` / `audit_accumulator.go` | audit 日志/共享流跟随、轮转处理和多记录聚合 |
| `audit_event.go` / `audit_parse.go` / `audit_identity.go` | 事件组装、字段解析、命令与身份富化 |
| `output.go` / `types.go` | 输出 writer 辅助和共享类型 |

audit 指标只有一个生产模型：parser 使用无锁原子计数，规则扩展/压力指标由 `processTreeMonitor` 生命周期持有。模块退出时两者合并输出一条 `audit runtime stats` 到 stderr；已删除未接入真实规则路径的 listener health 子系统，不再把规则跳过错误计为安装失败。该诊断是模块本地退出快照，不等同于父进程 `/metrics` 的 Prometheus 指标。

`pkg/hostpersistence` 同样按生命周期拆分：`config.go`/`cli.go` 负责入口和配置，`platform_nonwindows.go`/`platform_windows.go` 隔离平台默认值，`runner.go`/`scanner.go` 负责轮询，`events.go`/`state_store.go` 负责事件与原子 baseline；`audit_rules.go`、`audit_follow.go`、`audit_tracker.go` 和 `audit_event.go` 分别负责规则、传输、有限关联缓存和 actor 富化。此次拆分不改变配置字段、默认值、日志路径、JSON 事件格式或运行方式。

模块内部优先在同一 package 中按变化原因拆文件。只有形成稳定、可复用的契约后才提取新 package；supervisor 不应新增对采集模块私有 JSON 字段、audit key 或输出布局的硬编码。

## 新增模块

后续新增模块建议遵循：

1. 在 `pkg/<module>` 下实现 `func Main(args []string) int`。
2. 在同一包的 `descriptor.go` 实现 `func Descriptor() modulecontract.Descriptor`，由模块自己声明 flag、平台、输出和外部资源需求。
3. 在 `module_registry.go` 的 `buildModuleRegistry(...)` 中加入该 descriptor；重复名称会在开发启动时直接失败。
4. 在 `config.example.json` 增加示例参数。
5. 补充模块 README 和最小 smoke test。

这样新增模块仍然只发布一个 `secweaver-agent` 二进制，客户端安装路径和 systemd 服务不需要增加。

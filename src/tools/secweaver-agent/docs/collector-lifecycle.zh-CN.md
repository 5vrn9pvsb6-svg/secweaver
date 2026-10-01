# 采集器生命周期与诊断

## 注册拒绝诊断（0.3.70）

支持的 Linux/Windows 主机上的 `enroll` 命令向 stderr 输出
`HTTP=<状态> reason=<错误码>`，以及固定的中英文说明和处理建议。成功时企业/设备
身份的 stdout 格式与退出码保持不变。Linux SaaS Bootstrap 在注册步骤失败时，
会在终端显示简短原因，详细安装日志保留完整 CLI 诊断。Windows 安装器通过现有
原生命令调用显示相同 CLI stderr。不会自动重试、删除身份、撤销设备或调整额度。

| HTTP / 错误码 | 含义与处理方式 |
| --- | --- |
| 403 / `DeviceIdentityConflict` | 本机身份已撤销、替换或登记企业/密钥冲突。请管理员核对设备记录与重装流程，保留本地状态和私钥用于排查。 |
| 403 / `DeviceQuotaExceeded` | 企业设备额度已满或超额。撤销确认不用的设备注册，或提高额度；离线、卸载但未撤销的设备仍占额度，删除本地状态不释放额度。 |
| 403 / `EnrollmentTokenExhausted` | 令牌累计新增设备注册次数用尽，与是否到期独立。生成新安装命令；撤销设备不会恢复令牌次数。 |
| 403 / `EnterpriseDisabled` | 企业被禁用、尚未开通或未到生效时间。请管理员启用或完成开通；换令牌不能启用企业。 |
| 403 / `SubscriptionExpired` | 企业订阅已到期。续期企业授权；换令牌不能延长订阅。 |
| 409 / `AmbiguousReinstall` | 硬件指纹匹配多个有效身份。先核对重复设备记录，再重装。 |
| 401 / `RequestReplay` | 请求 nonce 已使用。用 enroll 生成新请求重试；若重复出现，检查代理重放。 |
| 401 / `Unauthorized` | 注册认证失败。核对当前安装命令及主机时间；令牌无效、过期、撤销与请求认证失败有意共用此响应，不能据此断定令牌过期。 |
| 404 / `NotFound` | 核对 Gateway 注册路由及反向代理；不代表令牌过期。 |

前提：Gateway 返回已知 JSON `errorCode` 与匹配的 HTTP 状态。兼容旧 JSON
`reason` 错误码，以及旧式 HTTP 200 / `allowed=false` 拒绝。人类可读的 `message`
不能覆盖 `errorCode` 或 `reason`。未知错误码、非法 JSON、HTML/WAF 响应和不一致
的状态/错误码显示 `UnknownRejection`，不猜测原因，也不输出服务端原文。未知
403 提示查看 Gateway 与 WAF/代理日志。不打印令牌、私钥或 URL 用户信息/查询值。
旧服务端只有通用响应时，必须提供具体错误码才能区分这些原因。

在 Agent 源码目录运行
`go test -race . ./pkg/agentlicense -run 'TestEnroll|TestEnrollment'`，在仓库根目录
运行 `python3 -m unittest tests.test_agent_install_presentation`。使用模拟 TLS
端点及隔离日志验证各类 403、旧 JSON、非法/WAF 响应、状态不匹配、失败 stdout
为空、重试身份保留、脱敏与安装原退出码。Windows 编译不能替代真实 PowerShell/SCM
验收。发布新的不可变 0.3.70 包及生成的 Bootstrap 后，公开安装命令才有新提示；
已安装的旧二进制仍保留原输出。

## 0.3.43 安装恢复

注册 HTTP 401 会提示核对安装命令及主机时间；可能是令牌过期、撤销、无效或请求认证失败。
客户端不猜测具体失败项，不删除身份、不盲目重试授权、不关闭 TLS 校验。
指引只写 stderr，适用于 Linux/Windows 的 Agent enroll 命令。

Linux 卸载器支持标准 `/etc/init.d -> /etc/rc.d/init.d` 和
`/lib/systemd/system -> /usr/lib/systemd/system` 映射，需要 Linux coreutils 的
`readlink -f`；其他软链接删除根目录仍在停止服务前拒绝。

发布工具要求公开目录对所有用户可读/可遍历（建议 0755）、包和校验文件可读（建议 0644），
且禁止组/其他用户写入；不会隐式修复权限。`--runtime-user NAME` 使用 Linux `runuser`
以真实 Gateway 账号检查祖先目录权限、ACL 和文件可读性，每路径超时 10 秒。
发布账号需获准执行 runuser；账号/工具缺失或检查失败时保留旧版本指针。
其他发布平台省略此 Linux 专用选项，并在部署主机单独验证服务读取权限。
回归覆盖受限目录/文件权限和运行账号检查失败；发布后仍需 HTTPS 验证 catalog 与下载。
该操作不会修改全量自动更新清单。

Agent 0.3.41 修改 Linux SLS Bootstrap、Linux 卸载和 Logtail 诊断，Windows 从 0.3.46 起参见 [Windows 安装说明](windows-installation.zh-CN.md)。
Linux Bootstrap 面向 systemd 主机，兼容 systemd 219（CentOS 7），使用供应商的
`/etc/init.d/ilogtaild` 或 `loongcollectord` 启停协议。需要 `timeout`、`flock`、
`pgrep`、`readlink`。非标准路径/服务需要单独适配其生命周期。

## 网络策略

从 0.3.42 起，Linux 模板和发布脚本默认
`BOOTSTRAP_LOGTAIL_REGION=cn-hangzhou-internet`，UI/用户安装命令不需要额外地域参数。
显式 `cn-hangzhou` 保持内网含义；发布脚本中的旧别名 `hangzhou` 仍规范化为该内网模式。
其他地域的 SaaS 必须设置所属 SLS 地域支持的网络模式。不要向 SLS API connector 的
普通地域字段添加 `-internet`。没有内外网自动切换，也没有跨地域回退。

需要分别管理以下配置：

| 配置 | 用途 |
| --- | --- |
| `BOOTSTRAP_LOGTAIL_INSTALL_URL` 和 SHA-256 | 镜像安装器脚本下载和完整性校验 |
| `BOOTSTRAP_LOGTAIL_REGION` / `--logtail-region` | 供应商模式，影响内部二进制下载及 Logtail 端点 |
| `LOGTAIL_SOURCE_REGION` 或 `LOGTAIL_SOURCE_URL` | 仅发布侧的上游安装器来源，独立于运行网络 |

`publish-logtail-installer.sh` 默认 `LOGTAIL_REGION=cn-hangzhou-internet`，生成公网 OSS
来源域名时只移除 `-internet` 后缀，并把运行模式连同 URL、摘要导出到 `release.env`。
供应商脚本原始内容不会被修改。

```bash
LOGTAIL_REGION=cn-hangzhou-internet \
OUTPUT_DIR=/srv/secweaver/logtail \
PUBLIC_BASE_URL=https://downloads.example.com \
bash scripts/publish-logtail-installer.sh
source /srv/secweaver/logtail/release.env
# 仍需配置账号、机器组、授权地址等部署参数。
# 使用新的 OUT_DIR 和新的 Agent VERSION 生成发布物料。
```

迁移：公网 SaaS 渠道需要把旧发布/部署参数中的 `cn-hangzhou` 显式改成
`cn-hangzhou-internet`，重新生成带摘要的发布配置和 Bootstrap，再发布新 Agent。
旧环境变量优先于新默认值。只修改源码不会更新线上下载 URL。已有 Logtail 安装继续复用，
不会静默改写端点；迁移已有采集器时使用供应商配置变更流程并重新验收入库。

Bootstrap 的 HTTP 下载要求 GNU `timeout`（Linux coreutils）。每次下载总计最多 300 秒，
TERM 后仍不退出则再等最多 10 秒发送 KILL。curl 连接超时 10 秒、单次最多 120 秒，
可重试错误最多额外重试两次；wget DNS/连接 10 秒、I/O 30 秒，最多三次尝试。
整个供应商安装器最多执行 600 秒，强制结束额外最多 10 秒。安装已有副作用时不会自动
整段重跑。供应商按名称调用的 curl/wget 使用同样的限时包装；绝对路径或未来其他下载工具
仍受整体安装期限约束。发布侧 curl 同样受限：单次 120 秒、两次重试、260 秒重试启动
预算，最后一次尝试可能在预算结束后才退出。

错误阶段包括 `agent-version-download`、`agent-package-download`、
`agent-checksum-download`、`logtail-installer-download`、`logtail-binary-download`、
`logtail-install`。下载诊断显示目标主机，不额外暴露 URL 凭证或查询参数。退出码 124/137
代表超时/强制结束，供应商原始输出可能提供更多细节。内网失败只提示使用所属地域支持的
公网模式重试原安装命令，例如追加 `--logtail-region cn-hangzhou-internet`，不会擅自切换。
重试前检查已完成的安装步骤和服务状态；失败阶段绝不提示上传成功。

用户命令最外层的 curl 尚未进入 Bootstrap，无法被 Bootstrap 控制。运营生成命令时可在
`-fsSL` 之外增加 `--connect-timeout 10 --max-time 120 --retry 2 --retry-max-time 260`。
上述期限不覆盖独立 Agent 包安装器内部的操作系统包管理器安装过程。

网络回归覆盖公网默认、显式内网保留、其他地域、curl/wget 路径、下载失败和安装器超时。
真实云端验收仍需公网主机完整安装，加上机器组和 Logstore 查询。

## 服务交接

供应商安装器可能绕过 systemd 自行启动 Logtail。Bootstrap 用
`/run/lock/secweaver-logtail-install.lock` 串行化 Logtail 阶段，最多等待锁 120 秒。
先停止 systemd 服务，再通过供应商 init 脚本停止遗留的主机采集进程；正常停止失败时
采用其 `force-stop`。systemd 停止任务仍未完成或采集进程仍存活时终止安装，绝不删除
仍被进程使用的 PID 锁。确认无主机采集进程后才清理版本化的失效 PID 文件，再 enable
和 start 一次，同时验证 systemd 和 init 脚本状态。仅 `active (exited)` 不算通过。
`--no-start` 同样停止供应商安装器自行启动的进程。Doctor 在交接完成后执行。
共用 Logtail 上的其他采集任务在此期间会短暂停顿。

Bootstrap 在下载 Logtail 前写入 `/opt/secweaver-agent/etc/shipper-kind`，内容为
`logtail`、权限 0600，使安装中断可被诊断。不会根据 `enterprise_id` 或 ES 授权推断
SLS 模式。无标记的旧安装通过标准采集器目录识别。明确迁离 SLS 时，应在配置好替代
采集器后删除此标记。

## 卸载

```bash
sudo /opt/secweaver-agent/bin/uninstall.sh --purge --remove-logtail --remove-filebeat --json
```

压缩包中 `install.sh` 旁边的 `uninstall.sh` 只服务于安装阶段。安装完成后，正式入口固定为
`/opt/secweaver-agent/bin/uninstall.sh`；不要把 `secweaver-clean-stage-*` 测试暂存目录当作运维路径。

普通 `--purge` 只清理 Agent 所有的文件。两个独立采集器开关必须显式选择，即使没有
`--purge`，也会删除选中采集器的全部配置、状态和日志。需要继续承载其他业务采集任务
的采集器不要选择。

Agent 0.3.65 同时补齐旧分散布局的卸载。删除文件前，卸载器会停止并移除
`secweaver-agent.service`、`secweaver-agent-shipper.service`、
`swl-agent.service` 及历史独立模块 unit。unit 缺失或损坏时，会在限定时间内依次
发送 TERM/KILL；已知 Agent 进程仍存活则在删除数据前返回失败。进程识别依据产品路径
和旧采集器名称，不会误匹配 `secweaver-agent-gateway`。

默认二进制清理还包括旧 `swl-agent`、`audit-port-execmon`、
`syslog-risk-json`、`host-persistence` 命令。`--purge` 额外删除
`/etc/secweaver-agent`、`/var/lib/secweaver-agent`、
`/var/log/secweaver-filebeat`，以及 `/var/log` 下已知 SecWeaver 日志及其
轮转文件。脚本绝不递归删除 `/var/log`；无关日志和自定义的旧输出文件名会保留。
`--remove-config`、`--remove-state`、`--remove-logs` 分别采用相同的
当前布局加旧布局所有权范围。Logtail/Filebeat 程序仍需显式选择才会卸载。

- Logtail：`/usr/local/ilogtail`、`/etc/ilogtail`、`ilogtaild`/`loongcollectord`
  的 init 脚本、systemd unit 和 drop-in。
- Filebeat：RPM/DEB 包通过 `rpm -e`/`dpkg --purge` 卸载；删除 `/usr/share/filebeat`、
  `/etc/filebeat`、`/var/lib/filebeat`、`/var/log/filebeat`、标准命令路径、init 脚本、
  systemd unit 和 drop-in。非标准 tar 安装显式设置 `FILEBEAT_ROOT`、`FILEBEAT_ETC`、
  `FILEBEAT_STATE`、`FILEBEAT_LOGS`、`FILEBEAT_COMMAND`、`FILEBEAT_LOCAL_COMMAND`。
- 非标准独立 Logtail 路径可设置 `LOGTAIL_ROOT`、`LOGTAIL_ETC`。相对路径、过宽路径、
  软链接删除根目录会被拒绝。残留进程按主机命名空间和可执行文件路径确认身份后才停止；
  停不下来就保留文件并返回失败。
- 不删除 auditd、系统审计历史、其他 audit key 或云端设备注册记录。

`--json` 的 stdout 只包含一个 JSON 对象，进度及包管理输出写入 stderr。零条匹配
规则是成功。`audit.remaining_rule_count=-1` 表示无 auditctl；`-2` 表示读取失败，
除非显式跳过 audit 清理，否则验收失败。残留 unit、进程、要求删除的文件都会返回非零。
`standalone_collectors.<name>.remaining=null` 表示没有要求卸载，不代表不存在。
中途异常输出 `ok:false,error:uninstall_incomplete` 并返回非零。未指定 `--json` 时，
同样通过这些验证决定退出状态。

`files` 结果新增 `known_binaries_exist`、`legacy_config_exists`、
`legacy_state_exists`、`legacy_known_logs_exist`、
`legacy_filebeat_logs_exist`。要求清理的任一旧资产残留都会令 `ok=false`。

## 本地与云端验收

```bash
secweaver-agent doctor -config /opt/secweaver-agent/etc/config.json -json
systemctl status ilogtaild.service
sudo /etc/init.d/ilogtaild status
```

Doctor 和 `secweaver-agent-health.log` 共用 Logtail 身份、服务和进程探测。健康日志新增
`shipper.service`、`service_status`、`process_status`、`cloud_delivery`、`reason`、
`checked_at`，保留原 `type`、`configuration`。本地采集器异常增加
`shipper_local_unhealthy`，将原本 healthy 的状态降为 degraded。探测超时为 3/5 秒，
频繁状态变化时至少缓存 60 秒；安静主机在下一次健康快照刷新，默认五分钟。
`checked_at` 表示观测时刻，不是持续实时监测。

`cloud_delivery` 明确为 **unverified**：Agent 没有云端入库回执，所以本机检查正常时，
doctor 仍会保留云端未验证警告。采集器运行、身份文件存在、Agent 心跳成功、输出日志
可读，都不能证明 SLS 已入库。Agent 不增加 AK/SK。运维需在 SLS 检查机器组在线状态、
Logstore 采集绑定，再按该主机/设备和事件时间查询最新记录，也要验收运维健康日志目的地。
ES/Filebeat/原生 shipper 仅检测到配置时同样报告运行未知、上传未验证，需执行对应输送器
输出测试和服务端查询。没有健康日志不能解释成正常。

回归测试使用临时目录与模拟服务，覆盖零规则、audit 读取失败、采集器保留/卸载、正常/
强制交接、进程不退出、no-start、oneshot 活跃但进程死亡。每种交付环境正式发布验收仍需
进行真实空白机安装与服务端入库查询。

2026-09-24 已在 CentOS 7/systemd 219 测试机实测新生命周期函数：托管服务重启、
`--no-start`、供应商 init 脚本在 systemd 外启动后的接管均通过；结束时 Logtail 服务和
守护/工作进程均正常。本次定向实测没有替换已安装的 Agent，也没有发布 0.3.41 下载渠道。

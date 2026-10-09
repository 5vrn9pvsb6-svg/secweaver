# Bootstrap 动态安装版本

## Linux 审计队列预检查（0.3.80）

Linux 发布包的 `install.sh` 在依赖就绪后、注册设备及启动 Agent 前检查本机 audit
队列。SLS SaaS 与 ES 私有化使用同一安装器，适用于原生 systemd Linux 主机的标准
audit 配置布局；Windows 和 Docker workload profile 不使用本步骤。需要 root、Bash、
coreutils（包括 GNU `timeout`）、awk、auditctl 和可用的 auditd systemd unit。

| 项目 | 安装器行为 |
| --- | --- |
| audit 2.x（包括 CentOS 7 常见版本） | 原生 dispatcher 为 `/sbin/audispd` 或 `/usr/sbin/audispd` 时，检查 `/etc/audisp/audispd.conf` 的 `q_depth` |
| audit 3.x/4.x | 检查 `/etc/audit/auditd.conf` 的 `q_depth` |
| 分发队列 | 缺少或小于 `2000` 时提高到 `2000`；更大的值保留 |
| 内核 backlog | 下限为 `8192`；已有运行值或原生持久规则中更大的值作为新的下限，不降低原值 |
| 持久规则 | 检查 `/etc/audit/audit.rules` 及 `/etc/audit/rules.d/*.rules` 的 `-b`；缺少时为原生加载方式补入配置，且放在 `-e 2` 前 |

安装器仅修改偏小的队列数字，不改 `max_restarts`、`disp_qos`、插件绑定、`-e`、`-f`
或其他审计规则。每个被修改的文件先生成同目录唯一的 `.secweaver-backup.<suffix>`
备份，日志显示完整路径，再以保留权限、所有者及安全元数据的临时文件原子替换。
备份不以 `.rules` 结尾，不会被 augenrules 当作规则源。原文件在写入前发生变化时
停止安装，避免覆盖运维操作；重复安装不会再次改写符合下限的配置或触发 reload。

已运行的 auditd 仅在分发队列改变时 reload，不 restart、不 kill。有原生
`/etc/init.d/auditd` 时通过 `service auditd start/reload` 操作，兼容 CentOS 7；其他主机
通过 systemctl 操作。服务操作限时 30 秒，状态/auditctl 查询限时 10 秒，超时后最多
5 秒强制结束命令。不会执行 `auditctl -D/-R` 或 `augenrules --load`。运行 backlog 通过
`auditctl -b` 修改并复查，服务必须 active 且内核报告有效 daemon PID、`enabled=1/2`。
启动、reload、注册验证或运行队列修改失败均停止后续安装并显示具体步骤。

`enabled=2` 时保留不可变策略：保存 backlog 下限，明确警告需下次重启才可生效，
不尝试解锁；分发配置仍可 reload。未知 audit 主版本、自定义/未启用的 audit 2.x
dispatcher、重复或非法的 `q_depth` 会警告并保留分发配置。非法 backlog、符号链接、
单文件超过 1 MiB 或规则文件超过 256 个等无法可靠判定的策略拒绝自动处理。具有
自定义 auditd 配置目录的部署应选择退出，并由运维维护实际使用的配置。

只关闭队列修改（依赖和服务仍检查）：

```bash
sudo env AUDIT_TUNE=0 ./install.sh \
  --enterprise-enrollment-token 'swenr_TOKEN_ID.SECRET' \
  --license-server-url https://agent-gateway.id-net.cn:30443
```

`INSTALL_DEPS=0` 同时跳过依赖安装、audit 服务操作和队列修改，适合已由运维准备并
验收 audit 的受控环境；此时不能把安装成功视为这些配置已完成。Bootstrap 使用时
可在 `sudo env` 中传入同样的环境变量，Linux 子安装器会继承。

失败后配置可能已经提高，备份与安装日志会保留，安装器不自动回退其他已完成步骤。
需要回退时停止 Agent，按日志记录的确切备份路径恢复对应配置，再通过原生
`service auditd reload` 或 systemctl reload 使分发配置生效；backlog 恢复还需同步
持久 `-b` 和可变内核值。不可变内核的恢复同样需重启。不使用通配符批量覆盖备份。

安装后检查 `auditctl -s` 的 PID、backlog_limit 与 lost 增量、相应配置中的 `q_depth`、
auditd journal 和真实 audit.log 写入，再分别确认 Agent JSONL 及云端收件。队列容量
只能缓冲突发，不能修复慢插件或持续超量的全局 fork/exec 审计；不要因队列提高
就认为 `dispatch err (pipe full)` 已根治。隔离回归覆盖两种规则加载布局、audit 2/3/4、
较大值保留、不可变策略、幂等安装和服务/内核失败；真实 CentOS 7 验收仍需在目标
内核及插件配置上验证 reload、业务高峰和云端链路。

## 安装进度（0.3.44）

Linux SaaS Bootstrap 在 stderr 显示八个编号步骤：终端中成功为绿色 `OK`、失败为红色
`FAIL`、恢复或其他告警为黄色 `WARN`；`RUN`、`INFO`、`SKIP` 为普通文本。
颜色判断使用 stderr 是否连接终端，curl 管道占用 stdin 不影响颜色。重定向和
`TERM=dumb` 自动输出纯文本；安装参数追加 `--no-color`，或在 sudo 环境设置非空
`NO_COLOR`，可显式禁用。本次不改变 Windows PowerShell 或直接运行归档内 install.sh
的输出，适用范围是 Linux SaaS Bootstrap。

八步为：解析版本；下载/校验/解包；安装、注册和配置 Agent；预检；安装或复用 Logtail；
配置身份和服务交接；启动 Agent；检查本地健康。只有命令完成才显示 OK，并附耗时秒数。
`--skip-logtail`、`--no-start` 对省略步骤显示 SKIP。已有 Logtail 复用，不把本地检查
通过误报为云端上传成功。

子安装器、配置命令、供应商和诊断完整输出保存在每次唯一的
`/opt/secweaver-agent/install-logs/install.log.*`（文件 0600，目录 0700），开始及
结束/失败时显示路径。该目录不在采集 JSONL 路径内，安装失败后保留，完整卸载
`uninstall.sh --purge` 随安装根目录删除。日志可能包含主机/配置详情，分享前需检查
并脱敏；不主动记录命令跟踪或安装令牌参数。每次调用一份日志，无后台持续写入，
运维可按需清理旧安装记录。在另一个终端执行 `sudo tail -f <显示的日志路径>` 查看细节。

失败后停止后续步骤，保留原失败退出码并显示失败阶段及日志路径；从 0.3.70 起，
注册失败额外显示白名单错误码及对应处理摘要，见[注册诊断](collector-lifecycle.zh-CN.md#注册拒绝诊断0370)。
信号中断返回 130/143。BTF 不可用时 auto 后端回退 audit、新建事件日志
暂时为空，显示为 INFO；其他诊断警告和错误保持可见。供应商正常停止失败后，终端仅
显示一条 WARN，再执行有限时长的 force-stop；重复 PID 信息保存在日志中，服务验证
通过后才能显示 OK。独立执行 doctor 的输出和级别不改变。

回归包括真实 PTY 颜色、重定向纯文本、NO_COLOR、子安装失败、预检/doctor 失败、
版本指针失败和私有日志权限。发布后在 Linux systemd 主机验证公开脚本，并独立确认
服务运行及云端收件。

从 0.3.42 起 Linux SaaS 默认采用 `cn-hangzhou-internet`，保留显式内网模式。
下载与供应商安装增加超时、有限重试、阶段/目标主机错误提示；详见
[网络策略](collector-lifecycle.zh-CN.md#网络策略)。

Agent 0.3.41 增加 Logtail/systemd 串行交接，`--no-start` 会停止供应商安装器自动拉起的
进程；下载前记录 SLS 安装意图，采集器启动后再执行 doctor。详见
[采集器生命周期与验收](collector-lifecycle.zh-CN.md)。

Agent 源码 0.3.21 移除 Linux/Windows Bootstrap 的固定安装版本。新版 Bootstrap 按操作系统族读取版本指针：
Linux 读取 `releases/latest-linux-version.txt`，Windows 读取 `releases/latest-windows-version.txt`。
旧 Gateway 对平台指针返回 HTTP 404 时才回退到 `releases/latest-version.txt`；TLS、DNS、超时、5xx、空响应和非法内容
都会 fail closed。随后下载选定不可变目录中的安装包和 SHA-256 文件。保留 `--version` / `-Version` 用于受控测试，
普通用户不需要填写版本。

Agent 0.3.76 修复 Linux 在 Bash `set -u` 下初始化版本指针变量时中断的问题。
curl 与 GNU wget 都只在确认完整 HTTP 404 错误后回退旧入口；收到 404 响应头后超时
仍然失败。下载失败时清理临时响应内容和 wget 响应头文件。仅测试使用的 `file://`
夹具把不存在的平台文件视为 404，复制错误仍然 fail closed；这不开放生产本地文件安装。
公开入口需发布重新生成的 0.3.76 Bootstrap 脚本才能修复；不得替换已发布的 0.3.75 归档。

版本文件为最多 64 字符的 ASCII 版本，可带一个结尾 LF。除上述平台指针 404 允许读取旧入口外，
缺失、为空、非法或不可达时，在修改主机前停止，不使用缓存或内嵌的旧版本。
首次安装的信任机制仍为 HTTPS 发布和安装包 SHA-256，
该版本文件本身没有独立签名。安装后，未配置签名信任的升级使用 HTTPS 加文件大小、SHA-256 校验。
签名 SaaS Bootstrap 会配置发布公钥并强制验证签名清单；信任变更、紧急停止和远程回退仍只能在签名模式使用。
通用安装包默认关闭自动升级，详见[升级信任配置](tenant-auto-update.zh-CN.md#升级信任配置0379)。此入口仅决定新安装版本，
不会强制升级存量设备。

Linux 支持 amd64/arm64/loong64，要求 Bash、curl/wget、tar、SHA-256 工具、coreutils
和 systemd。Windows 支持 amd64/arm64，要求管理员 PowerShell 5.1+；不支持 macOS。
版本入口必须使用 `no-store`，不能缓存旧值。

## 发布操作

### 注册设备身份（0.3.22）

Linux 安装器从同一次成功注册中取得企业 ID 和自动更新设备 ID。只传企业令牌时
无需 `--update-device-id`；显式传入冲突值会拒绝继续。旧企业 ID 安装方式启用更新时
仍需显式更新设备 ID。Windows 从 0.3.46 起使用同一注册身份处理，见
[Windows 安装说明](windows-installation.zh-CN.md)。

`secweaver-agent enroll` 默认仍只向 stdout 输出企业 ID；`-output installer`
在身份落盘后输出严格的 `enterprise_id<TAB>device_id<LF>`。非法输出格式在注册前拒绝，
不输出私钥或令牌。安装脚本必须搭配同一发布的二进制，旧二进制不支持此选项。

授权状态和私钥路径显式使用 `STATE_DIR`。使用同一状态及私钥重试会复用设备身份；
部分安装失败后保留 `data/license-state.json` 和 `data/device-ed25519.key`。
注册后的安装错误不会撤销服务端注册，不要通过删除本地身份绕过设备额度。

在 Agent 目录运行 `go test -race . ./pkg/agentlicense`。测试覆盖真实 TLS 注册输出、
重试身份稳定性，以及隔离 Bash 安装的仅令牌、一致/冲突 ID、畸形输出、注册失败和
旧安装方式。这不等于真实 SLS 上传验收。该修复从 0.3.22 开始提供。发布当前版本的新不可变包、提升动态版本
指针后，在受控 Linux 测试主机上验证仅令牌安装、设备身份复用和上传链路；仅改外层 Bootstrap 不能修复旧 0.3.19 包内的安装器，禁止覆盖旧包。

先将完整 legacy 版本及校验文件以原始不可变字节发布到 `<release-root>/<legacy-version>/`，再把较新的 Linux/Windows
平台包发布到各自不可变版本目录。例如只推进 Linux 时：

```bash
python3 scripts/publish-release-channel.py \
  --release-root /srv/secweaver-agent/releases \
  --version <完整 legacy 版本> \
  --linux-version <Linux 版本> \
  --windows-version <Windows 版本> \
  --runtime-user secweaver-agent-gateway
```

工具验证完整 legacy 版本的五个平台包，以及指定 Linux/Windows 平台包的名称、哈希、大小和非符号链接条件后，分别原子替换三个指针。
替换前失败会保留旧通道；每个指针单独原子更新，因此发布操作必须串行。旧 Agent 继续读取 `latest-version.txt`，新版 Bootstrap 使用平台指针。
已安装设备仍必须走签名授权的回滚流程，不能用修改指针绕过。

只重新生成 Bootstrap 时，保留正常 `BOOTSTRAP_*` 配置，可选设置
`BOOTSTRAP_UPDATE_PUBLIC_KEY_FILE=<已有公钥路径>`，再设置 `BOOTSTRAP_ONLY=1`、
`OUT_DIR=<全新输出目录>` 后运行 `./scripts/package-release.sh`。此模式不需要签名私钥，也不重建
Agent 包；源码版本和来源门禁仍生效，脏构建仅用于测试。签名部署生成 Bootstrap 时必须提供已有公钥，
保证全新主机获得信任。从 Agent 0.3.79 起，安装器省略公钥时保留主机已有信任，只有从未配置信任的新配置保持无签名模式。
不能静默更换已有信任公钥。
普通打包不会自动提升线上安装版本；必须在真实服务目录的全部包就绪后显式提升。

Agent Gateway（服务端 rc.69+）通过白名单提供 `AGENT_RELEASE_ROOT/releases/latest-*-version.txt`；
查询服务不会提供这些路径。安装脚本、版本目录和配置好的 Logtail 安装脚本全部发布并验收后，
才能声明完整安装/升级可用；选择签名模式时还必须发布并验收对应公钥和签名升级资源。

## 验证

仓库根目录执行 `python3 -m unittest tests.test_secweaver_agent_wrappers tests.test_agent_release_channel`，
覆盖 Linux 动态选择、显式版本、缺失/非法入口和提升失败保护。服务端 `TestReleaseVersionPointer`
覆盖 GET/HEAD、no-store、非法内容和查询端隔离。Windows 仍需真实主机验证语法与安装流程，
源码检查不等于 Windows 验收。

在 Agent 目录执行 `go test . ./pkg/agentupdate -run 'TestBootstrapOptionalPointer|TestPlatformManifest'`。
回归使用确定性下载替身以及显式 Linux/Windows 平台标识，不依赖测试主机操作系统。
这些检查只证明版本选择和校验，不代替 Windows SCM 升级或真实云端上传验收。

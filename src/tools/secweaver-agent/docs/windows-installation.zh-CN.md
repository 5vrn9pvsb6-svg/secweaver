# Windows 服务与 Data Cloud 输送（0.3.58）

0.3.58 调整安装输出：绿色 OK 表示对应步骤已通过；青色 INFO 表示正常机制或配置说明；
黄色 WARN 表示能力受限或仍需验证；红色 ERROR 表示失败。Windows 自动升级的退出后替换、
服务重启机制为 INFO，不表示当前有升级失败或待重启；preflight/doctor 不再因此增加告警。
成功时不显示启动错误文件路径；失败时仅显示本次产生、大小不超过 16 KiB 的详情文件。

学习提示复用预检，不额外查询事件通道：Sysmon 缺失或不可访问时，明确告知基于 Sysmon
的白名单降量不可用，Security 4688 进程事件及风险事件全量保留，采集继续。
Sysmon 通道可用只表明可以读取，不证明已经完成基线学习或正在过滤。
云端状态保留 PENDING VERIFICATION 告警：安装器没有查询 SLS/ES，既不表示上传失败，
也不能代表已经入库；需查询本机最近事件验证。验收时检查安装输出、doctor 和云端新事件。

0.3.57 修复部分 Windows PowerShell 5.1 会话中 RuntimeInformation.OSArchitecture
为空导致的 InvokeMethodOnNull。Bootstrap 和 Logtail 检查都改为优先读取
PROCESSOR_ARCHITEW6432，再读取 PROCESSOR_ARCHITECTURE，支持原生 x64/ARM64
及 WOW64 下的系统架构识别。变量缺失或架构不受支持时，明确报 stage=platform
check=os-architecture；不猜测下载平台。Windows Logtail 托管安装仍仅支持 x64。
旧安装脚本需重新下载；不需要卸载已安装的 Agent。验证方式为重新运行公网安装器，
确认通过平台检查，并用 doctor 检查服务；云端入库需另行查询验证。

0.3.56 将卸载入口按原生 CRLF 打包并预解析完整命令块；使用 EXIT 结束专用 CMD
子进程，避免 EXIT /B 返回已被删除的批处理文件。CMD/SSH 中用 cmd /d /c 调用，保留交互会话。

## Windows 卸载

从 0.3.54 起，安装器会把 uninstall.cmd、uninstall-service.ps1 和 uninstall-layout.json
固定放到程序 bin 目录。管理员 CMD 或 SSH 终端执行：

```cmd
cmd.exe /d /c "C:\ProgramData\SecWeaver\Agent\bin\uninstall.cmd" -Purge
```

PowerShell 中也可直接执行 `& 'C:\ProgramData\SecWeaver\Agent\bin\uninstall.cmd' -Purge`，
由 PowerShell 创建 CMD 子进程。卸载不需要联网或重新下载。
不带参数只删除 Agent 服务，保留程序和数据；`-Purge` 删除 Agent 服务/进程/安装目录，
以及该主机 LogtailDaemon/LogtailWorker、已识别的采集进程、Program Files 下标准
Alibaba/Logtail 目录和 C:\LogtailData。配置、身份凭据、学习/升级状态、日志和采集断点
均删除。共享 Logtail 时增加 `-KeepLogtail`。原有 `-RemoveFiles`、`-RemoveConfig`
仍只处理 Agent。`-Json` 输出单个 JSON 结果，退出码 0 代表验收通过，1 代表未完成或拒绝。
云端数据和设备记录不删除；Filebeat、Sysmon、Windows 事件日志与审计策略不变。

支持 Agent 已支持平台的 Windows PowerShell 5.1+、标准 Logtail 1.6.1.0 服务/目录，
以及 bin/etc 位于根目录内的自定义 Agent 根目录。安装信息保留自定义服务名。
外置 InstallDir/ConfigDir 的文件删除、非标准 Logtail 布局、服务指向其他程序、目录链接/
junction 均会在清理前拒绝，需另行核实处理。与安装器互斥，每个服务阶段最多等待
30 秒，每个残留进程最多等待 10 秒，最后验证服务和目标目录是否消失。
SCM 提示等待删除时关闭服务管理窗口再重试；部分文件删除失败需检查剩余目录，
没有 Agent 程序/配置标志的未知目录不会盲删。

管理员 Windows 测试机可运行 integration/windows-install/uninstall.ps1：使用临时目录
验证自删除、JSON、重复卸载，并使用模拟采集目录验证清理/保留/拒绝，不卸载现有 Agent/Logtail。
发布验收还需在 Windows PowerShell 5.1 使用临时 Agent 根目录和 -KeepLogtail 测试包内入口，
通过后再开展真实卸载。现有 0.3.53 需升级到 0.3.54 或以上版本才会获得入口。

0.3.53 修复 PowerShell 5.1 Bootstrap 收尾错误：移除令牌引用时不再触发格式校验，
避免服务已经安装成功却返回失败；失败时也不会覆盖原始报错。两种收尾路径均有回归测试。

0.3.52 兼容 Windows Logtail 1.6.1.0 实际使用的 `metrics` 缓存以及旧的
`log_config` 格式。两个节点一起校验，八条签名路由必须完整，重复采集或目标不同
仍判定失败。缓存通过只代表配置就绪，仍须独立查询 SLS 验证真实入库。

## 0.3.51 配置迁移与验收输出

Bootstrap 和 install-service.ps1 均接受 `-LearningMode preserve|enable|shadow|disable`。
默认 preserve 不改旧选择；新安装沿用模板的学习默认值。enable 显式开启匹配过滤，
shadow 学习但保留全部原文，disable 关闭；只调整当前启用的事件读取器，保留学习时长、
范围、代数和状态，不启动第二个读取器。修改现存策略应优先用 shadow 观察。
开启不代表过滤已生效：需要正式设备身份以及 Sysmon GUID/SHA256 和足够上下文；
Security 4688、风险告警和上下文不足的事件始终输出。Doctor 会区分这些状态。

安装输出绿色 `[OK]`、黄色 `[WARN]`、红色 `[ERROR]`，分别说明采集、授权、学习、
上传配置与云端验收状态。`run -dry-run -strict-preflight` 在一次检查中校验完整配置及
平台错误，避免重复打印 preflight；普通 dry-run 行为不变。云端未查询时明确为
UNVERIFIED。关闭授权的本地测试安装不会显示“已注册 SaaS”。
PowerShell 5.1 执行脚本可使用 `powershell.exe -NoProfile -ExecutionPolicy Bypass -File ...`，
仅影响本次进程，不要求修改全机 ExecutionPolicy。
安装器通过 enroll 的 `-enterprise-enrollment-token-stdin` 管道传递令牌，避免令牌
进入 4688 子进程命令行。直接 CLI 仍兼容参数方式，但托管安装不再使用；不要自行开启
会记录输入的转录或把令牌嵌入可公开访问的脚本。

## PowerShell 风险日志格式

Agent 0.3.51 的 Windows 风险 parser_version 为 0.3.1。4104 完整脚本片段保留在
`command`，新增 UTF-8 字节长度 `script_bytes` 与精确内容 `script_sha256`；message
只存摘要，从 fields 中删除与 command 字节相同的 ScriptBlockText/CommandLine 副本。
不同内容、ScriptBlockId、MessageNumber、MessageTotal 均保留；不合并分片、不降级风险、
不按 PowerShell/CIM 关键词过滤事件。启用 raw_xml 时原始 XML 仍会带完整内容。
自定义查询应读取 command，不能再依赖 message/fields.ScriptBlockText 保存完整脚本；
旧数据继续兼容。公开资产模板 select *，现有必需字段保留；自定义索引可增设哈希精确查询。

## 0.3.22 测试报告修复

0.3.49 补齐以下行为；必须发布新不可变安装包和 Bootstrap，已有 0.3.22 不会自行获得修复。

| 报告问题 | 当前行为及验证方法 |
| --- | --- |
| Bootstrap 空值异常 | 拒绝空响应、HTML/JSON 版本指针；接受有长度限制的文本或 UTF-8 字节及单个 LF/CRLF 结尾。空校验文件在解压前失败。 |
| 服务创建后停止 | 最长 90 秒内要求 Running、最新授权及模块状态连续十次就绪。激活前失败恢复旧文件、SCM 命令和启动类型，原来运行的服务重新启动；首次安装失败删除新服务。 |
| Doctor 服务名错误 | SCM 与 doctor 共用默认标识 `SecWeaverAgent`，安装器默认名一致。自定义服务名仍需显式检查 SCM。 |
| 错误信息不明确 | 输出步骤、校验项、脱敏地址、HTTP 状态及建议。注册 401 提示检查令牌，404 提示检查路由，HTTP 200 空/非法 JSON 明确为响应错误；不打印令牌、URL 用户信息/查询参数或服务端原文。 |
| 自动升级状态不一致 | 按下表区分入口；安装结束前校验落盘配置，doctor 报告实际状态。 |

安装回滚与自动升级回滚独立。只备份并恢复二进制、Agent/模块配置、输送器意图标记及
回滚命令，保留设备身份/注册、游标、证据、审计策略和共享 Logtail；已完成的云端注册
不能靠本地回滚撤销。失败保留私有 `data/install-rollback-*` 目录供排查，确认恢复后再清理；
成功删除本次备份。启动失败输出 SCM 数字退出码、匹配本服务的近期 SCM 事件和有界错误文件，
不会向 Windows 系统/应用事件日志写 Agent 事件。回滚失败会明确说明并给出备份路径，
不输出安装成功。就绪验收通过后，如恢复策略配置失败，保留已激活服务并报具体步骤，
不再回退服务。`-NoStart` 是显式暂存，不宣称运行验收通过。

## 自动升级默认值

| 安装入口 | 实际结果 |
| --- | --- |
| 通用 Windows JSON 模板，未提供清单 | `update.enabled=false`，不存在可通用使用的升级服务地址。 |
| 已发布 SaaS Bootstrap | 要求嵌入真实 HTTPS 清单并传给安装器，落盘 `enabled=true`、`auto_install=true`。 |
| 直接安装包 / ES enrollment 提供 `UpdateManifestUrl` | 使用已注册的稳定设备 ID 启用升级；落盘开关不符则安装失败。 |
| 升级时未提供 `UpdateManifestUrl` | 保留原设置，不静默启用或关闭。 |

启用后默认每 6 小时检查，带初始延迟和抖动，且要求服务端策略批准；不意味着立即全量升级，
仍受 manifest、设备资格和灰度策略控制。提供公钥时强制验证签名，否则验证 HTTPS 和包完整性。
doctor 显示实际配置。关闭升级不属于服务名错误；应通过正式受管安装入口或提供真实 manifest
及设备身份启用，不能保留模板示例地址只把开关改为 true。

回归脚本 `integration/windows-install/contracts.ps1`、`failures.ps1` 无需管理员权限，
后者模拟网络/SCM 并执行真实文件回滚；Windows CI 在 PowerShell 5.1 运行两者。
目标 Windows 主机仍须进行真实 SCM 启动和云端入库验收。

Windows 安装器现在校验配置/preflight，从同一次持久化注册结果取得企业 ID 和升级设备 ID，
并要求 SCM 服务及本次启动的授权、模块状态连续十次就绪（最长等待 90 秒）。服务已创建、
短暂 Running、查询 HTTP 200 均不能作为验收通过。doctor 服务名修正为 `SecWeaverAgent`，
原来错误查询了 `secweaver-agent`。SCM 失败会覆盖写入最多 16 KiB 的
`<配置路径>.service-error.txt`，新服务入口启动会清除旧记录；再次启动前先保留证据。
文件继承配置目录 ACL，不作为事件 JSONL 采集。

## 前提与限制

目标为 Windows 10、Windows Server 2016/2019/2022/2025 amd64、管理员 PowerShell 5.1+、
Security 4688 审计权限及发布源/授权/SLS 网络可达。这是实现目标，发布前仍须在实际目标环境
完成 SCM 与云端验收；域策略可能覆盖本地审计。执行证据依赖 4688，网络/文件证据仍需 Sysmon。
Agent 保留 ARM64 构建，但托管 Logtail 在注册前拒绝 ARM64；只有已另行验证输送器时才使用
`-SkipLogtail`。不宣称原生 ARM64 Logtail、Windows 7/Server 2008 支持。

默认官方 amd64 Logtail 包为 `win/win64/1.6.1.0/logtail_installer.zip`，SHA-256 为
`58f4edc8d41250f05ca87e4130e52bfbc139e3c6b27e48aa60b2c86d4516ac4d`。
HTTPS 下载超时 120 秒、禁止重定向，先校验 SHA-256 再解压执行，在解压目录运行
`logtail_installer.exe install <region>`（限时 600 秒），之后检查 `LogtailDaemon` 和
`ilogtail_worker`。复用已有 daemon；遇到旧版 `LogtailWorker` 要求显式升级。
安装互斥锁最多等待 120 秒；重试保留 Agent 身份/私钥和 Logtail 已有账号、机器组行。
操作会重启主机共享的 Logtail 服务，短暂影响其他采集源。
`-NoStart` 会让两个服务保持停止，包括厂商安装器自动启动的 daemon。
`-SkipLogtail` 只跳过安装，不停止或卸载已有输送器。

参考厂商[安装文档](https://www.alibabacloud.com/help/en/sls/install-run-upgrade-and-uninstall-logtail)
和[机器组配置](https://www.alibabacloud.com/help/doc-detail/2861803.html)。
无论 Agent 根目录在哪里，Windows Logtail 身份都位于 `C:\LogtailData\users\<AliUid>` 和
`C:\LogtailData\user_defined_id`。保留共享机器组标识，旧标识需管理员明确清理。
默认 Agent 卸载保留 Logtail；0.3.54 起显式 `-Purge` 可清理标准布局的 Logtail，
共享时增加 `-KeepLogtail`。旧版本仍使用厂商卸载流程。

## 安装与发布

```powershell
$Collection = [Convert]::ToBase64String([IO.File]::ReadAllBytes('C:\Staging\windows-collection.signed.json'))
.\install-service.ps1 `
  -EnterpriseEnrollmentToken 'swenr_TOKEN_ID.SECRET' `
  -LicenseServerUrl 'https://agent-gateway.id-net.cn:30443' `
  -LogtailAliUid '1234567890123456' `
  -LogtailMachineGroup 'YOUR_WINDOWS_ONLY_GROUP' `
  -LogtailRegion 'cn-hangzhou-internet' `
  -LogtailCollectionEnvelope $Collection `
  -LogtailCollectionPublicKey 'BASE64_ED25519_PUBLIC_KEY'
```

直接安装归档包需要 SLS 账号 UID、Windows 专用机器组标识及签名采集清单。
`-LogtailPackageUrl` / `-LogtailPackageSha256` 可改为经过审核、包结构相同的 HTTPS 镜像。
自定义 `-InstallRoot`、`-InstallDir`、`-ConfigDir` 会重写产品默认 JSON 路径，保留其他路径，
且不产生 UTF-8 BOM。自定义 `-ServiceName` 通过 `service -name` 传给二进制；标准 doctor
服务检查仍查询默认名称，自定义服务请单独检查。

发布会将 `BOOTSTRAP_LOGTAIL_ALIUID`、`BOOTSTRAP_LOGTAIL_REGION` 和
`BOOTSTRAP_WINDOWS_LOGTAIL_MACHINE_GROUP` 写入 `install.ps1`。Windows 标识默认是
`<BOOTSTRAP_ENROLLMENT_ID>-windows`，不得与 Linux 相同。推广渠道前，需要在 SLS 建立
操作系统为 **Windows**、使用该自定义标识的机器组，并绑定 Windows 文件采集规则。
安装器写身份并启动客户端，不持有云管理凭据、不创建云端规则。一键安装随后只需令牌；
嵌入身份缺失时在修改主机前失败。按当前规范 `VERSION` 发布全新的不可变包及配套 Bootstrap，不能只改
外层脚本来修复旧包中的安装器。

为 `C:\ProgramData\SecWeaver\Agent\logs` 下列文件配置 JSON 行采集（自定义目录须同步），
保留解析后的企业/主机身份和事件字段。根据所用 Logtail 版本处理数字轮转后缀，避免多个规则
重复采集同一文件。Windows 路径和机器组操作系统不能复用 Linux 规则。

| 文件 | 目标/筛选 |
| --- | --- |
| `windows-process-execmon.log` | 主机证据，按 asset_type 区分 exec/connect/file 操作 |
| `windows-eventlog-risk-json.log` | Windows 风险事件 |
| `host-persistence.log` | 主机持久化 |
| `host-process-snapshot.log` | 主机进程清单 |
| `host-state-snapshot.log` | 主机状态清单 |
| `behavior-learning.log` | 行为摘要 |
| `secweaver-agent-health.log` | Agent 运行健康 |
| `secweaver-agent-update.log` | Agent 升级事件 |

## 验收与恢复

```powershell
$Root = "$env:ProgramData\SecWeaver\Agent"
Get-Service SecWeaverAgent, LogtailDaemon
Get-Process logtail_daemon, ilogtail_worker
Get-Content "$Root\etc\config.json.service-error.txt" -ErrorAction SilentlyContinue
& "$Root\bin\secweaver-agent.exe" doctor -config "$Root\etc\config.json" -json
$Marker = 'secweaver-win-accept-' + [Guid]::NewGuid().ToString('N')
cmd.exe /c "echo $Marker"
Select-String -LiteralPath "$Root\logs\windows-process-execmon.log" -SimpleMatch $Marker
```

等待配置中的事件轮询周期后检查本机证据。再按企业、本机、标记和最近时间窗查询 Data Cloud/SLS，
必须至少有一条匹配的**新** host-exec，并核对机器组心跳、规则绑定。
HTTP 200 但零行仍判入库失败。doctor/健康报告核对签名路由、下发规则、本机身份、服务与进程，
`cloud_delivery=unverified` 不会根据本机运行状态变成已入库。
服务停止时保留错误文件，运行 `run -config <路径> -dry-run` / `preflight -strict`，修正
具体配置、授权或审计问题；保留 `data/license-state.json` 与 `device-ed25519.key`。

运行 `powershell -NoProfile -File integration/windows-install/contracts.ps1` 做隔离 PowerShell
回归，`make check` 做 Go、race 与跨平台编译；真实 SCM 升级测试仍位于
`integration/service-upgrade/windows-scm.ps1`。自动检查不能代替真机标记与云端查询验收。

## Windows SLS 采集就绪

0.3.50 起，不能仅凭身份文件和 Logtail Running 宣称安装成功。Data Cloud 运营先为上述
八个文件创建原生 JSON 采集规则，并签署 version=1 清单，字段为 aliuid、machine_group、
project、region、log_path、routes（file/logstore/config_name）。SecWeaver Server 提供
`go run ./internal/windowsdelivery`，默认只检查，显式 `-apply` 才补缺失资源，回读通过后签名；
另有真实 marker 入库验收。具体命令及样例在该私有仓库的 `docs/windows-sls-collection`
中英文手册与 `config/windows-collection.example.json`。SLS 管理 AK/SK 不下发客户主机。

发布受管 Bootstrap 必须提供 `BOOTSTRAP_WINDOWS_COLLECTION_FILE`（签名信封绝对路径）
及 `BOOTSTRAP_WINDOWS_COLLECTION_PUBLIC_KEY`（base64 Ed25519 公钥），与升级签名密钥独立。
发布时校验签名/身份/region，Bootstrap 内嵌信封与固定公钥，无需新增下载接口。
直接归档安装使用 `-LogtailCollectionEnvelope`（信封的 base64）和 `-LogtailCollectionPublicKey`。
清单缺失或不匹配，在修改审计策略、注册和服务前失败；自定义根目录必须先配置对应云端规则与
清单，不能仅改本地路径。用户自定义的模块输出也必须与清单对齐。

启动 Logtail 后最多等待约 120 秒，读取运行中 worker 目录的 `user_log_config.json`；
Go 按原生 `log_config` 结构核对分离的目录/文件通配符、JSON 类型、Project、Logstore，
拒绝过滤器、插件和重叠采集。支持精确文件名加 `*`，覆盖产品数字轮转；不支持的格式失败，
不会用字符串包含文件名作为证据，也不会修改 SLS 拥有的缓存。失败会回滚 Agent 激活前文件
及服务，保留共享 Logtail 与注册身份，修正云配置后重试。

清单/固定公钥保存在实际配置目录的 `windows-collection.json`/`.pub`。
doctor 与健康日志核对精确 UID/机器组与规则；`contract_missing`、`identity_missing`、
`collection_rules_missing` 会报错，并增加 `config_path`、`missing_paths`。旧版需通过受管重装
补齐清单；仅自动更新二进制不会配置 SLS。读取缓存限 4 MiB、清单限 64 KiB，进程探测限 10 秒，
健康报告缓存一分钟。`-NoStart` 暂存并延后检查；`-SkipLogtail` 显式委托外部输送，不认证上传。
Windows ARM64 仍不支持受管 Logtail。

本地就绪不代表已入库。运营工具的 `-verify-host-ip`、`-enterprise-id`、`-marker` 要求最近
机器组心跳和新生成良性命令的完整非空 SLS 查询结果，输出带时间戳的回执；零行或查询失败仍为
未验证。生产推广前必须在 Windows x64 真机完成此验收，单元测试与跨平台编译不能代替。

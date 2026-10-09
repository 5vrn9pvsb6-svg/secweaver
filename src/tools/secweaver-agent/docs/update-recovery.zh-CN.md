# SaaS 升级信任修复与旧版本迁移

适用：Agent 0.3.84 的产品修复；随包 `recovery/` 运维脚本可单独分发。
本轮来源：2026-10-09 用户确认修复产品，并提供 0.3.79 修复脚本、0.3.45/0.3.64
一次性迁移脚本。脚本执行是显式运维操作，不会在安装或自动升级时自动运行。

## 产品修复

旧安装器使用 `-auto-install true`，Go flag 在 `true` 处停止解析，后面的
`-require-server-policy`、`-public-key`、`-ca-file` 未必生效。0.3.84 的 Linux/Windows
安装器改为 `-auto-install=true`、`-require-server-policy=true`，配置命令拒绝多余参数，
不会继续以成功状态掩盖丢失的公钥。

通用模板不再指定并不存在的 shipper CA。公网 SaaS 默认使用系统 CA，仍严格验证 HTTPS。
私有 ES 明确提供自己的 CA。配置写入前检查 CA 文件和受管升级信任；已有 CA 不会被
空参数清除。显式清除用 `config set-update -use-system-ca`，安装器对应
`--update-use-system-ca` / `-UpdateUseSystemCA`。它与非空 `-ca-file` 冲突。
公钥轮换、吊销、防重放状态和日志路径仍然保留。

`doctor` 与 `preflight` 增加 `update/ca`、`update/trust` 本地检查，不发网络请求，
不改变升级状态。缺失 CA 或密钥会报 ERROR；运行中的采集模块不会因此被终止。
清单下载、验签检查仍由升级流程执行。状态 JSON/心跳使用下列原因码：

| 原因 | 分类 | retryable |
| --- | --- | --- |
| `update_ca_missing` / `update_ca_unreadable` / `update_ca_invalid` | configuration | false |
| `update_trust_missing` / `update_trust_invalid` / `manifest_signer_untrusted` / `manifest_signer_ambiguous` | configuration | false |
| `update_tls_verification_failed` / `manifest_http_rejected`（非 408/429 的 HTTP 4xx） | configuration | false |
| `manifest_signer_revoked` / `manifest_signature_invalid` / `manifest_signature_required` / `manifest_invalid` | integrity | false |
| 连接/超时、HTTP 408/429/5xx 等 `manifest_fetch_failed` | transport | true |

`retryable=false` 表示需要修正配置或发布物，不承诺重试能自行恢复；不表示停止采集，
也不禁用后续定时检查。服务端原有活动熔断策略仍生效。本轮没有改变服务端协议、
租户权限或 `health-evidence-v1` 校验。

## 脚本与边界

完整保留 `recovery/` 目录中的脚本、Python helper 和 JSON profile，一起复制到目标机。
不要只复制 shell wrapper。目录中的 profile **只含公钥和公开发布元数据，无私钥、
安装令牌或设备密码**。默认固定到先前已发布、完成恢复测试的 0.3.83；发布 0.3.84
不会静默改变此 profile 的目标。
迁移同时修复信任配置，因此不依赖旧安装器；不是重新运行旧安装器。
每个 Linux/Windows 安装包都附带完整的五个恢复文件及 `docs/` 下的中英文指南；
打包程序在交叉编译前检查这些文件是否齐全。

| 脚本 | 对象 | 环境 |
| --- | --- | --- |
| `repair-saas-update.sh` | Linux 0.3.79；允许已到目标版后重复检查 | root、systemd（含 CentOS 7/219）、Python 3.6+、curl、256 MiB 空闲空间 |
| `migrate-saas-agent.sh` | Linux 0.3.45/0.3.64 → 0.3.83 | 同上；amd64/arm64/loong64 |
| `migrate-saas-agent.ps1` | Windows 0.3.45/0.3.64 → 0.3.83 | 管理员 PowerShell 5.1+、SCM、x64/ARM64、256 MiB 空闲空间 |

脚本需要现有服务运行、设备身份/key 完整、SaaS 地址匹配 profile。仅移除已知旧默认路径
且确实不存在的 update CA；自定义/存在的 CA、不同主公钥、ES 私有模式会拒绝操作。
未知配置不会被重置，已有 `update.enabled=false` / `auto_install=false` 也不会被偷偷打开。
不重装 Logtail/Filebeat，不卸载、不重新注册、不删除身份、学习基线或升级历史。
源版本不在表中、状态目录有锁/待健康确认时，先处理现有事务，不强行删除锁。

默认 profile 的信任链为：运维分发的 profile → 固定清单 SHA-256 → 二进制哈希/长度 →
新/现有 Agent 原生 Ed25519、有效期、防重放及吊销检查。公钥不能从待验证清单自行提取。
profile 指定的清单到期时间为 **2026-10-23 01:44:16 UTC**；过期后会拒绝迁移。
后续发布应由运维提供新的可信 profile，使用 `--profile` / `-ProfilePath` 指定，
不得移除到期/签名检查或覆盖旧版本产物。

## Linux 执行

在 `recovery/` 目录执行；第一条只检查，第二条明确写入并重启。

```bash
# 0.3.79：恢复配置，由已有租户活动决定后续自动升级
sudo bash ./repair-saas-update.sh
sudo bash ./repair-saas-update.sh --apply

# 0.3.45 / 0.3.64：一次性手工迁移到 profile 的固定版本
sudo bash ./migrate-saas-agent.sh
sudo bash ./migrate-saas-agent.sh --apply
```

非默认路径使用 `--root`、`--config`、`--binary`、`--service`。脚本核对服务 ExecStart
确实引用对应配置/二进制。`--health-timeout` 默认 180 秒，可设 30–600 秒。
批量处理应逐台执行、记录 JSON 结果，先确认一台成功再继续；离线机器不能通过脚本恢复网络。

## Windows 执行

在管理员 PowerShell 中进入完整 `recovery` 目录：

```powershell
& .\migrate-saas-agent.ps1
& .\migrate-saas-agent.ps1 -Apply
```

自定义目录/服务可用 `-InstallRoot`、`-ConfigPath`、`-BinaryPath`、`-ServiceName`。
此脚本使用实际服务名 `SecWeaverAgent`，不会创建新的设备记录。
Windows 客户端迁移完成后，后续自动升级仍需单独创建 Windows 升级活动。

## 成功、失败和恢复

只检查返回 `status=checked`，不停止服务、不修改配置/身份；允许创建临时校验目录和
本机互斥锁文件。`--apply` / `-Apply` 先备份至安装目录 `data/recovery/<时间及随机后缀>`，
再停止服务、复核配置/二进制/身份未被并发修改，原子替换配置及必要的二进制。
启动后要求设备 ID 不变、实际版本正确、状态文件新鲜、全部模块 running 持续 15 秒。
低流量主机无需制造安全日志。JSON `status=recovered` 包含实际版本和备份位置。
修复 0.3.79 后可能马上被已有活动升级，更新版本的健康状态也视为成功。

失败会尝试恢复本轮配置、二进制并启动原服务。若已经有正常自动升级接管，脚本拒绝
覆盖其二进制/回滚状态，返回人工复查提示。备份仅包含配置和二进制，**不是整盘快照**；
运行期间新产生的日志、模块状态与学习数据不会回退。断电/强杀后保留备份供运维恢复。
Linux 命令错误输出写入权限 0600 的 `secweaver-recovery-error-*.log`；Windows 失败时保留
仅 Administrators/SYSTEM 可读的临时诊断目录，不把注册凭证打印到结果 JSON。

运维恢复时先检查是否有正在进行的自动升级；确认没有后停止原服务，从结果所指备份恢复
`config.json` 和 `secweaver-agent[.exe]` 到原路径，再启动原服务。不要恢复/覆盖设备 key、
license state 或学习目录。保留恢复记录，成功确认后按本地备份保留策略清理。

脚本成功只证明本地配置、签名检查和启动健康；自动升级最终成功仍需工作台/心跳中
`last_update_status=healthy`。手工迁移不会伪造该活动成功记录。

## 验证方法

Agent 目录运行 `go test . ./pkg/agentupdate` 和
`python3 -m unittest discover -s integration/recovery -v`。
回归覆盖旧的 boolean 截断、公钥/CA 写入、错误分类、只检查无修改、校验失败不执行、
身份/学习数据保留、健康失败回退和并发升级不覆盖。脚本事务测试使用隔离的服务边界替身；
真实 Windows SCM、Linux systemd 迁移须在独立测试服务上验证，不以单元测试代替全量实机证明。

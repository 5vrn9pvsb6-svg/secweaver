# 企业自动升级许可

Agent 0.3.73 将 `auto_install` 的本地默认值设为 fail closed。SLS 受管模式
(`require_server_policy=true`) 下，心跳响应还必须包含 `auto_update_allowed=true`，并同时满足
签名升级活动、灰度资格和有效租约。企业开关关闭时，Agent 记录
`tenant_auto_update_disabled`，不会下载或替换二进制。

工作台开关只是许可，不会发布升级活动。运维仍需使用 Agent Server 的
`--auto-install` 发布目标版本；该参数现在必须显式传入，默认关闭。独立 ES 部署只有在已配置
可信 manifest/公钥和回滚路径后才设置 `update.auto_install=true`，随包生产示例保持关闭。

## 升级信任配置（0.3.79）

Linux、Windows 共用同一配置命令。通用安装包不内置 SaaS 专用升级公钥，
生产配置及 Windows 模板的 `update.enabled=false`、`auto_install=false`。
采用签名升级的 SaaS 部署，公开 Bootstrap 内嵌运营方公钥，经包内安装器的
`--update-public-key` / `-UpdatePublicKey` 传给 `config set-update -public-key`。
私有 ES 部署使用自己的公钥。仅下载通用安装包不会自动配置 SaaS 升级信任。

从 0.3.79 起，`config set-update` 在未提供相应值时保留已有的 `public_key`、
`trusted_public_keys`、`revoked_key_ids`、`ca_file` 和 `state_dir`。
状态目录保存已持久化的公钥轮换、吊销及防重放记录。显式传入非空 `-public-key`
只替换主公钥，不清空轮换公钥或吊销记录；关闭升级也保留信任。
空参数不代表删除信任。保留的公钥非法或原升级配置格式错误时，在写入之前报错。

独立非受管配置继续兼容 HTTPS/哈希校验。0.3.84 起显式配置受管升级时必须有未吊销的可信
公钥，并检查 CA 文件；已部署旧版本仍可正常采集。本次修复不会自动找回已经丢失的公钥，
仅替换二进制的自动升级也会保留原配置。缺失公钥应从运营方核验过的发布公钥或
可信备份恢复，同时保留设备身份、学习策略和升级状态。不能从待验证的 manifest
中提取公钥并将其作为自身信任依据，也不能通过删除吊销记录让升级通过。

备份并修正配置后，Linux 重启 `secweaver-agent`，Windows 重启 `SecWeaverAgent`。
核对配置公钥派生的 key ID 与发布签名者一致，再检查服务状态、实际运行版本，
以及升级状态目录内的 `state.json`。自动升级完成应显示 `last_update_status=healthy`、
`phase=healthy` 和确认时间；仅服务运行不代表升级完成。受管升级仍需企业许可、
升级活动和有效租约。

回归验证：在 Agent 目录运行 `go test . -run TestSetUpdate`，覆盖共用安装器 CLI
省略/替换公钥、关闭升级和原信任配置损坏。Windows 的运行时安装仍需真实 Windows
服务测试，交叉编译不能替代此项验收。

0.3.84 修复安装器 boolean 参数截断，并移除通用模板的默认私有 CA。
显式清除 CA、诊断原因码、0.3.79 修复与旧版本迁移步骤见
[SaaS 升级恢复](update-recovery.zh-CN.md)。

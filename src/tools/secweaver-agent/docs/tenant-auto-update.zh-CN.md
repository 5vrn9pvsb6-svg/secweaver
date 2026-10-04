# 企业自动升级许可

Agent 0.3.73 将 `auto_install` 的本地默认值设为 fail closed。SLS 受管模式
(`require_server_policy=true`) 下，心跳响应还必须包含 `auto_update_allowed=true`，并同时满足
签名升级活动、灰度资格和有效租约。企业开关关闭时，Agent 记录
`tenant_auto_update_disabled`，不会下载或替换二进制。

工作台开关只是许可，不会发布升级活动。运维仍需使用 Agent Server 的
`--auto-install` 发布目标版本；该参数现在必须显式传入，默认关闭。独立 ES 部署只有在已配置
可信 manifest/公钥和回滚路径后才设置 `update.auto_install=true`，随包生产示例保持关闭。

# Agent 部署模式

Agent 0.3.47 起，ES 和 SLS 共用二进制、版本号及采集实现，只按操作系统和架构构建安装包。
本地 `config.json` 可记录 `deployment_mode`：

| 模式 | 安装入口 | 日志输送 |
| --- | --- | --- |
| `sls_saas` | SaaS 企业工作台 / SaaS Bootstrap | Logtail / LoongCollector → SLS |
| `es_private` | ES Operator enrollment / 自管 ES 安装助手 | Filebeat、SecWeaver Shipper 或 Fluent Bit → ES/OpenSearch |

91 是 SaaS 服务端，其工作台提供 SLS SaaS 安装入口。企业 ID、Agent 版本号和授权服务器地址
不能用于推断日志后端；两个模式可以使用相同的 Agent Gateway。

## 安装与升级

Linux SaaS Bootstrap 固定传入 `--deployment-mode sls_saas`，Windows 传入
`-DeploymentMode sls_saas`；ES Operator 传入 `es_private`。参数只确定归属，
不意味着通用 Agent 包内包含日志输送器。Linux SaaS Bootstrap 管理 Logtail；
Windows SaaS 使用固定校验值的 Logtail 安装程序，要求配置 AliUid 和 Windows 机器组，
详见 [Windows 前置条件](windows-installation.zh-CN.md)。Windows ES 自动跳过 Logtail。
设置模式不能证明日志已经入云。

通用 Linux / Windows 安装器在停止服务、修改审计策略或注册设备前检查模式。
明确冲突时拒绝安装，不自动转换 ES/SLS。省略参数时保留已有模式；全新通用或独立安装
可以保持未指定；Windows 全新受管安装默认 SaaS，除非明确 ES 或指定 `-SkipLogtail`。
Windows ARM64 需要外部受支持的输送器。旧配置不强制补字段，仍能运行。

旧安装仅根据 Agent 自有目录识别：`etc/shipper-kind=logtail`，或者安装根目录下的
`shipper/filebeat.yml`、`shipper/shipper.json`、`shipper/fluent-bit.conf`，也兼容
旧 `etc/shipper/`。机器全局存在 Logtail/Filebeat 不能用于推断模式。两种证据冲突时
拒绝安装，需先检查残留配置。

```sh
secweaver-agent config set-deployment-mode \
  -config /opt/secweaver-agent/etc/config.json -mode sls_saas -check-only
secweaver-agent doctor -config /opt/secweaver-agent/etc/config.json
```

`-check-only` 不创建或修改文件；去掉它会保留其他 JSON 字段，以 0600 权限原子写入。
这是安装期操作，安装和人工配置修改须串行执行。正常二进制自动升级保留配置。
远程签名策略省略字段时保留本地值，不能远程设置或切换部署模式。模式不代替升级签名、
设备授权或入库凭证校验。

跨模式需明确迁移：停止并备份旧安装、保留调查日志、清理旧 Agent 自有渠道配置，
然后使用目标渠道重新注册。卸载默认保留配置，因此单纯卸载不会重置模式。
删除机器全局 Logtail/Filebeat 仍须显式 `--remove-logtail` / `--remove-filebeat`；
不会因为模式字段而删除其他应用共享的输送器。

## 诊断与验证

doctor 显示模式，健康日志增加可选 `deployment_mode`。明确 ES 模式不检查 SLS
机器组身份，也不把无关 Logtail 当作当前输送器；明确 SLS 模式不会用 ES 配置冒充
输送成功。配置存在只证明本地配置检查通过，服务状态和目标 SLS/ES 的最近主机事件
仍需分别验证。未指定模式的旧配置保留兼容检测。

安装器平台范围仍是 Linux/systemd、Windows 服务主机。Go 测试覆盖旧配置识别、模式冲突、
只读检查、远程策略保留。发布前应检查 shell 语法并在真实 Windows 上验证 PowerShell
服务安装，交叉编译不能替代真实安装验收。

# 企业级采集与心跳策略

Agent 0.3.87 起，Linux 和 Windows 的新安装默认主机进程增量扫描 **30 分钟**，授权心跳 **5 分钟**。每天一次的完整进程基线保持 24 小时；实时 exec、文件操作、身份和服务事件的采集周期不受此策略影响。

## 企业工作台

在“我的企业 → Agent 采集策略”设置整数分钟。Owner/Admin 可保存，其他成员只读。

| 字段 | 默认 | 允许范围 | 客户端配置 |
| --- | --- | --- | --- |
| 主机进程增量间隔 | 30 分钟 | 1–1440 分钟 | `host-process-snapshot` 的 `-interval` |
| Agent 心跳间隔 | 5 分钟 | 1–60 分钟 | `license.heartbeat_interval_seconds` |

保存后下次成功心跳下发；等待时间由**原有**心跳周期决定。Agent 校验范围、读取并合并这两个字段、严格校验整个配置、fsync 后原子替换。模块开关、采集路径、白名单、身份密钥和其他配置保持原值。Linux 服务管理器重启采集器；Windows SCM 服务保持 Running，在进程内关闭旧采集器并重载配置。学习状态及进程增量状态文件不会被删除或重置。

进程快照仍以 `pid+start_time` 对比当前存活进程，只输出启动、退出和高价值属性变化；30 分钟内出现并退出的短进程应由实时 audit/eBPF 或 Windows 4688/Sysmon 捕获。调大周期减少扫描频率，也会延后盘点变化发现。

## 兼容与失败处理

- 需要 Agent Server 0.6.0-rc.75、Server 0.6.0-rc.115 和共享数据库 migration 034。现有租户迁移后没有统一策略，保留本地设置；Owner/Admin 保存后才接管。新租户策略默认 30/5。
- 已有配置在安装/升级时继续保留。没有服务端策略的 ES 私有化/离线部署可以直接设置上述本地字段；企业工作台不直接管理离线设备。
- 安装器未指定心跳参数时使用保留模式：已有配置的周期不变，新配置使用 300 秒。Linux 安装器显式传入 `--license-heartbeat-interval-seconds 300`、Windows 包内 `install-service.ps1` 传入 `-LicenseHeartbeatIntervalSeconds 300` 才覆盖本地周期；内部参数 `0` 表示保留/默认，并不关闭心跳。
- 旧 Agent 不声明 `agent-runtime-policy-v1` 能力时，服务端省略新字段，仍正常注册/心跳；旧版需升级客户端才能远程应用。旧服务端省略策略时，新 Agent 保持本地配置。
- 写入失败、非法策略或升级正在下载/安装/健康观察时保留原配置，下一次心跳重试。网络故障继续采集并按现有退避重连。
- 完整签名远程配置与本策略共用写入互斥锁；不要让另一份全量配置持续下发相冲突的间隔，否则两项配置会交替触发重载。
- 在线状态以实际心跳间隔计算：`max(300 秒, 3 × 实际间隔 + 60 秒)`。未报告间隔的旧设备沿用 300 秒窗口。

## 验证

在工作台保存后，检查 `config.json` 的心跳秒数和进程模块 `-interval`，并确认服务运行、最近心跳成功和输出日志持续更新。Linux 用 `systemctl is-active secweaver-agent`，Windows 用 `Get-Service SecWeaverAgent`；执行 `secweaver-agent doctor` 检查本地采集状态。策略是目标值，保存成功不代表离线设备已经应用。

接口为工作台 `PATCH /api/v1/enterprises/{id}/agent-collection-policy`。请求包含两个分钟字段及读取到的 `revision`；保存有变更审计，重复网络重试保留同一幂等键，过期 revision 返回 409 并需要刷新。

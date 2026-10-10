# 企业级采集与心跳策略

Agent 0.3.87 起，Linux 和 Windows 的新安装默认主机进程增量扫描 **30 分钟**，授权心跳 **5 分钟**。完整进程基线默认 24 小时；Agent 0.3.91 起可单独调整全量基线、健康日志和持久化文件检查周期。实时 exec/audit/eBPF 事件源不受这些设置影响。

## 企业工作台

在“我的企业 → Agent 采集策略”按字段标注的分钟、秒或小时设置整数。Owner/Admin 可保存，其他成员只读。

| 字段 | 默认 | 允许范围 | 客户端配置 |
| --- | --- | --- | --- |
| 主机进程增量间隔 | 30 分钟 | 1–1440 分钟 | `host-process-snapshot` 的 `-interval` |
| Agent 心跳间隔 | 5 分钟 | 1–60 分钟 | `license.heartbeat_interval_seconds` |
| 监听端口 / `host_socket` | 5 分钟 | 1–1440 分钟 | `host-state-snapshot` 的 `-socket-interval` |
| 账户与登录 / `host_identity` | 5 分钟 | 1–1440 分钟 | `host-state-snapshot` 的 `-identity-interval` |
| 服务与计划任务 / `host_service` | 5 分钟 | 1–1440 分钟 | `host-state-snapshot` 的 `-service-interval` |
| 内核与容器 / `host_kernel_context` | 10 分钟 | 1–1440 分钟 | `host-state-snapshot` 的 `-kernel-interval` |
| 健康日志 | 5 分钟 | 1–1440 分钟 | `operations_report.snapshot_interval_seconds` |
| 持久化文件检查 | 30 秒 | 10–3600 秒 | `host-persistence` 的 `-poll-interval` |
| 进程全量基线 | 24 小时 | 1–168 小时 | `host-process-snapshot` 的 `-full-snapshot-interval` |
| 主机状态全量基线 | 24 小时 | 1–168 小时 | `host-state-snapshot` 的 `-full-snapshot-interval` |

Agent 0.3.91 的新增四项需要 Agent Server 0.6.0-rc.77/schema36 和工作台
Server 0.6.0-rc.117。客户端声明 `extended-collection-cadence-v1` 才接收。
字段分别为 `health_report_interval_minutes`、`host_persistence_interval_seconds`、
`host_process_full_snapshot_hours`、`host_state_full_snapshot_hours`。旧策略省略时
保留本地值；新租户默认5分钟/30秒/24小时/24小时，旧租户不回填。
健康周期只控制定时快照，启动/异常等健康事件仍按现有逻辑输出；健康设置缺失时
不创建或启用该功能。保留原jitter，若新周期短于现有jitter则严格校验拒绝整个写入，
原配置继续工作。持久化检查只在发现变化时输出，并非每30秒上传完整文件清单；
显式 `-poll-interval` 覆盖模块配置文件的周期，不修改watch列表或audit规则。
两种全量基线到期后在下一个实际检查轮次输出，增量检查间隔较长时可能延后。
调整不会删除或重置学习、文件比较、进程增量或host-state状态。可在配置文件核对
上述四项本地配置，重复相同策略不应产生重复重载。

Agent 0.3.90 增加 Linux/Windows 的四项 host-state 配置。保存后下次成功心跳下发；等待时间由**原有**心跳周期决定。Agent 校验所有已下发字段的范围、合并配置、严格校验整个配置、fsync 后原子替换。模块开关、采集路径、白名单、身份密钥和其他配置保持原值。Linux 服务管理器重启采集器；Windows SCM 服务保持 Running，在进程内关闭旧采集器并重载配置。学习、进程增量及 host-state 比较状态文件不会被删除或重置。host-state 仍是首次基线、变化增量和全量基线（默认每日）；每次检查无变化不会上传全量清单，调大周期会延后发现变化。

进程快照仍以 `pid+start_time` 对比当前存活进程，只输出启动、退出和高价值属性变化；30 分钟内出现并退出的短进程应由实时 audit/eBPF 或 Windows 4688/Sysmon 捕获。调大周期减少扫描频率，也会延后盘点变化发现。

## 兼容与失败处理

- 需要 Agent Server 0.6.0-rc.75、Server 0.6.0-rc.115 和共享数据库 migration 034。现有租户迁移后没有统一策略，保留本地设置；Owner/Admin 保存后才接管。新租户策略默认 30/5。
- 四项 host-state 控制需要 Agent Server 0.6.0-rc.76、Server 0.6.0-rc.116、migration 035 和 Agent 0.3.90。`host-state-cadence-v1` 单独协商；0.3.87–0.3.89 仍只接收进程/心跳。已有策略不回填，省略 host-state 字段时保留本地间隔。新租户默认 30/5/5/5/5/10，旧工作台请求不会清空已保存的四项检查间隔。
- 已有配置在安装/升级时继续保留。没有服务端策略的 ES 私有化/离线部署可以直接设置上述本地字段；企业工作台不直接管理离线设备。
- 安装器未指定心跳参数时使用保留模式：已有配置的周期不变，新配置使用 300 秒。Linux 安装器显式传入 `--license-heartbeat-interval-seconds 300`、Windows 包内 `install-service.ps1` 传入 `-LicenseHeartbeatIntervalSeconds 300` 才覆盖本地周期；内部参数 `0` 表示保留/默认，并不关闭心跳。
- 旧 Agent 不声明 `agent-runtime-policy-v1` 能力时，服务端省略新字段，仍正常注册/心跳；旧版需升级客户端才能远程应用。旧服务端省略策略时，新 Agent 保持本地配置。
- 写入失败、非法策略或升级正在下载/安装/健康观察时保留原配置，下一次心跳重试。网络故障继续采集并按现有退避重连。
- 完整签名远程配置与本策略共用写入互斥锁；不要让另一份全量配置持续下发相冲突的间隔，否则两项配置会交替触发重载。
- 在线状态以实际心跳间隔计算：`max(300 秒, 3 × 实际间隔 + 60 秒)`。未报告间隔的旧设备沿用 300 秒窗口。

## 验证

在工作台保存后，检查 `config.json` 的心跳秒数、进程模块 `-interval` 和 host-state 四项间隔，确认服务运行、最近心跳成功和输出日志持续更新。Linux 用 `systemctl is-active secweaver-agent`，Windows 用 `Get-Service SecWeaverAgent`；执行 `secweaver-agent doctor` 检查本地采集状态。策略是目标值，保存成功不代表离线设备已经应用。

接口为工作台 `PATCH /api/v1/enterprises/{id}/agent-collection-policy`。请求包含进程/心跳分钟字段、读取到的 `revision` 以及可选的 `host_socket_interval_minutes`、`host_identity_interval_minutes`、`host_service_interval_minutes`、`host_kernel_context_interval_minutes`；保存有变更审计，重复网络重试保留同一幂等键，过期 revision 返回 409 并需要刷新。

# Agent 运维健康日志

从 0.3.47 起，配置了部署模式的健康日志包含可选 `deployment_mode`
（`sls_saas` / `es_private`），据此选择本地输送链路；ES 模式不检查 SLS
机器组身份或无关 Logtail。旧配置兼容及迁移见[部署模式](deployment-modes.zh-CN.md)。

SecWeaver Agent 默认开启一条独立的运维健康 JSON Lines 流，用于 Logtail、Filebeat、Fluent Bit 或原生 `secweaver-shipper` 上传。它描述 Agent 采集和本地输送器状态，不证明云端入库，不替代审计、系统日志或主机状态证据。

从 0.3.41 起，共享 Logtail 身份、systemd 和进程探测，子进程有超时，频繁事件至少缓存
60 秒。本地异常降级健康状态；`shipper.cloud_delivery=unverified` 明确不代表入库成功。
字段与边界见[采集器生命周期与验收](collector-lifecycle.zh-CN.md)。

## 文件与默认值

Linux 默认文件为 `/opt/secweaver-agent/logs/secweaver-agent-health.log`，Windows 默认文件为 `C:\ProgramData\SecWeaver\Agent\logs\secweaver-agent-health.log`。文件使用现有 Agent 输出策略：单文件 100MB、保留 5 个数字备份、POSIX 权限 0600，并纳入全局磁盘预算。

以下片段放在 Agent 配置顶层（示例使用 Linux 路径）：

```json
"operations_report": {
  "enabled": true,
  "output": "/opt/secweaver-agent/logs/secweaver-agent-health.log",
  "snapshot_interval_seconds": 300,
  "jitter_seconds": 60,
  "include_resource_usage": true,
  "include_shipper_status": true
}
```

`enabled` 未配置时默认为 `true`。周期不能小于 60 秒，生产默认 300 秒；`jitter_seconds` 优先用持久化设备 ID 稳定计算，未注册时回退到主机名和主机 IP，避免大量主机同一秒写文件和上传。

## 事件类型

- `agent_lifecycle`：启动和正常停止。
- `health_snapshot`：周期性健康快照。
- `health_transition`：模块、授权、状态持久化或 audit reader 状态变化时立即记录。

每条记录都有 `schema_version`、`time`、`timestamp`、`asset_type=secweaver_agent_health`、企业 ID、设备 ID、主机名、主机 IP、版本、操作系统和架构。`modules` 是固定字段数组，包含模块状态、PID、重启次数、连续失败次数和输出文件 stat 信息；`resources` 包含 goroutine、Go heap、Go runtime 保留内存及 GC 次数，不执行额外进程扫描。

## Audit 与失败语义

`audit` 只读取 Agent 已有的共享 demux 内存指标，不执行 `auditctl -l`，不扫描 `/proc`，也不在 audit reader 锁内写文件。字段包括 reader 状态、订阅者、积压行数、处理总数、reader 失败数和 backlog 覆盖数。eBPF 或没有 audit 模块的主机可以合法地报告 `readers=0`，不能据此判断故障。

健康级别如下：`healthy/info` 表示正常；`degraded/medium` 表示可恢复状态；`unhealthy/high` 表示模块错误/熔断、授权失败、audit reader 不可用或 audit 证据被覆盖。

不把完整错误文本、配置、AK/SK、enrollment token、私钥或命令行写入该流；错误原因使用有限的 `reason_codes`。实际 shipper 是否把数据发送到 ES/SLS，仍应结合 shipper 自己的队列和服务指标检查。

## Shipper 接入

目的地由交付配置决定，不是 Agent 二进制的固定约定。Community 仓库根目录的
`src/tools/secweaver-agent/elasticsearch/` 独立 ES 示例包含此文件的 Filebeat input，写入
`secweaver-public-agent-secweaver-agent-health-*`，用于采集端运维监控。
该遥测数据不纳入智能体侧 DataAsset 注册表或调查 Bundle；最小 ES 模板也不等同于完整的嵌套健康分析映射。

SaaS 用户使用平台提供的运维监控和上传配置。托管交付配置不包含在公开 Agent 包内。

## 运维告警

建议告警：10 分钟没有 `health_snapshot`、模块连续重启超过 3 次、熔断、`audit.reader_ready=false`、backlog 覆盖数增量大于 0、授权拒绝、磁盘不足、版本落后和 shipper 服务停止。

Agent 或 shipper 已经完全停止时无法上报“自己停止”的记录。缺失主机应由 Data Cloud 注册表/心跳和 ES/SLS 查询超时联合判断；本地健康日志负责解释停止前的最后状态。

Windows 从 0.3.46 起通过有时限的 CIM 查询检查 `LogtailDaemon`、worker 与
`C:\LogtailData` 身份。预期采集器缺失会降级健康状态；查询失败是 unknown，
本机检查成功仍保持云端输送未验证。见 [Windows 验收](windows-installation.zh-CN.md)。

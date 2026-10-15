# SecWeaver Agent 长期运行、自愈与磁盘保护

本文说明 Agent 长期运行时的控制面自愈、输出磁盘预算、状态持久化和 Windows
子模块停止语义。这些是默认生产行为，不需要单独启用实验开关。

## 授权故障自愈

- 首次授权的 DNS、连接、超时、HTTP `408/425/429/5xx` 故障会在进程内持续重试，
  从 5 秒指数退避到 5 分钟，并按设备稳定加入 jitter。
- 存在有效缓存授权且未超过 `license.outage_grace_seconds` 时，Agent 直接进入采集，
  后续授权和心跳仍持续复查。
- 订阅过期、设备数超限、服务端明确拒绝等永久错误不重试，以免隐藏需要人工
  处理的授权状态。
- Linux 本地配置错误使用退出码 `78`；systemd 的 `RestartPreventExitStatus=78` 不会
  对这类错误空转。`StartLimitInterval=0` 避免真正的瞬时故障把服务永久锁在
  `failed`。

## 全局磁盘预算

默认配置：

```json
{
  "disk_budget": {
    "enabled": true,
    "max_total_mb": 2048,
    "min_free_mb": 512,
    "check_interval_seconds": 30
  }
}
```

Agent 父进程按实际配置的唯一输出路径数量分配 `max_total_mb`，每个子模块在
打开文件时压缩单文件大小和数字备份数，使活动文件加备份不超过其分额。升级
后首次打开也会清理超过分额的旧数字备份；不会截断正在写入的活动文件。

剩余空间分三档保护：

| 优先级 | 默认模块 | 停写水位 |
|---|---|---|
| 实时 | audit、syslog、持久化、Windows Event Log | `min_free_mb` |
| 普通 | 升级状态和未分类模块 | `min_free_mb + 单文件分额的 10%` |
| 快照 | 进程快照、主机状态快照 | `min_free_mb + 单文件分额的 25%` |

到达水位时，writer 先删除自己的最旧数字备份并重新检查。仍不足时返回明确
错误；若模块退出，supervisor 按现有退避策略重启。

### 低磁盘退避与恢复（Agent 0.3.103+）

Linux 和 Windows 的磁盘水位复查、学习模块周期持久化重试，按
**1、2、4、8、16、32、60 秒**指数退避，每个重试操作上限 60 秒。检查/写入
成功后重置该操作的退避。正常水位检查仍使用 `check_interval_seconds`（默认
30 秒）；实际恢复还取决于模块调度和输出常规 flush 周期（默认 5 秒），不会
为了写入成功而降低磁盘保护阈值。

缓冲输出不再永久缓存 `output disk reserve exhausted`。该保护在写入任何字节
之前拒写，因此外部清理释放空间后，可以安全重试已经接收的待写数据，不必
重启仍存活的采集器。缓冲不超过配置大小（默认 64 KiB）；新数据被拒绝时明确
返回错误，不建立无限内存队列。未知文件系统错误、短写及持久化错误仍保持
失败状态，避免把不确定的证据伪装成 checkpoint 成功或推进 Windows 游标。

缓冲输出、Linux/Windows 学习 checkpoint、Linux 学习事件输出和运维报告的
重复故障，首次立即记录，此后**每个操作/事件流最多每分钟一条**。期间错误
累计到 `suppressed=N`；可用空间数值变化也不会绕过限流。实际 I/O/checkpoint
处理成功后记录一次 `recovered`。空 flush、跳过重试、服务为 `running` 或仅仅
读到空闲空间，都不能作为输出恢复的证明。这不是整个进程的全局日志限额。

释放受影响文件系统的空间后保持服务运行，检查服务 stderr（Linux 可执行
`journalctl -u secweaver-agent --since '5 minutes ago'`）、输出文件更新时间及
`/health`。不要通过填满生产磁盘测试；回归用例使用注入的低空间探针和真实临时
滚动文件。已经退出的模块仍按 supervisor 重启策略恢复，不属于存活 writer 的
进程内重试路径。

恢复写入不能补齐存储不可用期间被拒绝的事件，也不会自动信任已降级的学习
基线。先验证新原始事件及健康输出，再按[学习恢复说明](learning-recovery.zh-CN.md)
显式重新学习；不要删除学习身份/状态或关闭磁盘保护来消除告警。

边界：总预算只覆盖通过 `pkg/output` 管理的 Agent JSONL/升级状态文件，不包括
`status.json`、auditd 自有日志和 Logtail/Filebeat 自身文件。不同 shipper 的消费位点格式
不统一，Agent 不伪造通用延迟值；应在 Logtail/Filebeat 监控中单独告警。

## 状态文件可靠性

- 启动时首份 `status.json` 同步写入，之后所有状态变化由单 writer 每秒最多合并
  写入一次，文件 IO 不占用模块状态锁。
- 写入失败每秒重试，stderr 最多每分钟记录一次；`/health` 返回 HTTP 503。
- 正常停止和升级退出会无条件强制刷新最新状态。
- `persistence.last_attempt_at`/`last_success_at`/`last_error`/`error_count` 用于巡检持久化
  本身。磁盘持续失败时旧文件不可能更新，应同时检查 `/health` 和服务 stderr。

## Windows 子模块停止

Windows supervisor 为每个子模块建立专用 stdin 控制管道。服务停止或升级时，父进程
发送 `shutdown`，子模块取消 context，执行输出 flush 和 EventRecordID cursor checkpoint。
15 秒未退出才进入强制终止。

子进程还会加入带 `KILL_ON_JOB_CLOSE` 的 Windows Job Object，父进程异常消失时由内核
回收。如果机器的上级 Job 策略禁止嵌套 Job，Agent 会输出 containment warning 并保留
控制管道优雅停止，不会因此拒绝启动采集。

## 版本和验证

Agent 发布版本只来自根 `VERSION`。正式 Makefile、交叉编译和打包脚本同时注入主
命令与 `audit-port-execmon -version`；事件 parser/schema 版本仍是独立的数据合约。

```bash
secweaver-agent version
secweaver-agent audit-port-execmon -version
systemctl show secweaver-agent -p NRestarts -p Result
curl --fail http://127.0.0.1:9100/health
jq '.persistence,.modules,.license' /opt/secweaver-agent/data/status.json
```

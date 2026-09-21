# 主机状态快照采集与接入

自 `secweaver-agent 0.3.9` 引入后，`host-state-snapshot` 模块默认开启，统一采集监听端口、登录与身份、服务与计划任务、内核与容器上下文。一个模块进程写一个 JSON Lines 文件，避免为四类数据启动四个常驻进程；当前 Agent 发布版本以包内 [`VERSION`](../src/tools/secweaver-agent/VERSION) 为准。

## 默认周期

| 逻辑资产 | `asset_type` | 默认周期 | 行为 |
|---|---|---:|---|
| 监听端口快照 | `host_socket` | 5 分钟 | 首次/每日完整基线，中间只输出 TCP/UDP 端点变化 |
| 登录和身份变化 | `host_identity` | 5 分钟 | 首次完整基线，随后输出账户/会话差异 |
| 服务和计划任务变化 | `host_service` | 5 分钟 | 首次完整基线，随后输出服务、timer、cron/计划任务差异 |
| 内核与容器上下文 | `host_kernel_context` | 10 分钟 | 首次完整基线，随后输出模块、驱动、容器上下文差异 |

状态型采集每 24 小时重新输出一次完整基线。首次基线事件 `action=observed`；新增、修改、删除分别为 `created`、`modified`、`deleted`，修改和删除事件带 `previous`。登录会话还会产生 `login_session_started` 和 `login_session_ended`。

## 平台采集内容

Linux 直接读取 `/proc/net/*`、`/proc/modules`、`/proc/*/cgroup`、命名空间链接和账户文件，并调用 `who`、`systemctl` 获取会话和 systemd 状态。cron 只记录路径、大小、修改时间和 SHA-256，不输出任务文件正文。

Linux 监听端口归属默认每轮最多检查 100000 个 `/proc/*/fd`，可用 `-max-fd-scan` 调整。服务模式下四类采集器依次延后 0/15/30/45 秒启动，避免启动时同时拉高 CPU 和 I/O。

Windows 通过无 Profile 的 PowerShell/CIM 批量调用 `Get-NetTCPConnection`、`Get-NetUDPEndpoint`、本地账户、`Win32_Service`、`Get-ScheduledTask`、`Win32_SystemDriver` 和系统版本信息。模块不采集口令或密码哈希，也不写单独的 Windows service 包装器日志。

## 默认文件

| 平台 | 输出 | 状态 |
|---|---|---|
| Linux | `/opt/secweaver-agent/logs/host-state-snapshot.log` | `/opt/secweaver-agent/data/host-state-snapshot-state.json` |
| Windows | `C:\ProgramData\SecWeaver\Agent\logs\host-state-snapshot.log` | `C:\ProgramData\SecWeaver\Agent\data\host-state-snapshot-state.json` |

输出沿用 Agent 的 64 KB 缓冲、默认 5 秒周期刷新和大小轮转策略。状态文件采用 `0600` 权限和原子替换；删除状态文件会在下次启动重新建立完整基线。

事件输出 flush 并同步成功后才推进状态；状态没有变化时不重复落盘。任一轮采集部分失败或超时时，保留旧状态且不产生差异，避免假删除。状态 JSON 损坏时会改名为 `.corrupt-<timestamp>` 并重建基线。

## 配置样例

下列片段放在 Agent 配置的 `modules` 对象内（示例使用 Linux 路径）：

```json
"host-state-snapshot": {
  "enabled": true,
  "restart": "on_failure",
  "restart_delay_seconds": 5,
  "args": [
    "-socket-interval", "5m",
    "-identity-interval", "5m",
    "-service-interval", "5m",
    "-kernel-interval", "10m",
    "-full-snapshot-interval", "24h",
    "-max-fd-scan", "100000",
    "-output", "/opt/secweaver-agent/logs/host-state-snapshot.log",
    "-state", "/opt/secweaver-agent/data/host-state-snapshot-state.json"
  ]
}
```

旧配置在安装/升级时会执行 `secweaver-agent config ensure-host-state-snapshot`。仅当模块缺失时补入默认配置，已有自定义配置或显式关闭不会被覆盖。可用 `SECWEAVER_ENTERPRISE_ID=YOUR_16_CHAR_ID secweaver-agent module host-state-snapshot -once -output - -state ''` 做一次性验证。

## SLS 与客户自有 ES

SLS 建议创建一个 `host-state` Logstore，让 Logtail 以 JSON 模式采集输出文件，并为 `asset_type`、`event_type`、`host`、`user`、`listen_port`、`service_name`、`task_name`、`module_name`、`container_id` 建索引。四类资产共享一个 Logstore，查询模板会附加 `asset_type` 条件。

客户自有 Elasticsearch / OpenSearch 使用只读接入流程，统一写入 `secweaver-host-state-*`。
请参阅[数据源配置](03-configure-data-sources.zh-CN.md)或开源 ES 模板
[`dataasset/onboarding/es/`](../dataasset/onboarding/es/)。Community 版不需要单独的私有资产目录；
直接将公开 DataAsset 对象配置到客户自己的 endpoint 和凭证，不要为四类资产重复读取同一文件。

## 边界

- 快照存在采集间隔，不能替代 `host_exec`、网络流量审计或 Windows 4688/Sysmon 的实时事件。
- Linux 登录会话来自当前 `who` 状态，不等同于完整认证历史；认证历史仍由 `syslog-risk-json` 提供。
- 容器识别基于 cgroup 和运行时服务状态，不等同于 Kubernetes 审计或容器运行时事件流。
- 服务和计划任务变化是轮询差异，不提供具体修改者；需要修改者/进程时，应结合 auditd、Windows Security/Sysmon 和 `host_persistence`。

# host_process 主机进程快照采集

`host_process` 用于记录主机进程基线及两次扫描之间的状态变化。它适合回答“当时有哪些进程、哪些进程新启动或退出、程序路径/命令/cgroup/权限是否变化”，是 `host_exec` 实时执行审计的补充。

## 采集方式

`secweaver-agent` 内置模块 `host-process-snapshot` 默认采用混合模式：启动后立即输出完整基线，随后每 10 分钟扫描并只输出增量，每 24 小时重新输出一次完整基线：

```bash
sudo SECWEAVER_ENTERPRISE_ID=YOUR_16_CHAR_ID \
  secweaver-agent module host-process-snapshot -once -output -
```

- Linux 直接批量读取 `/proc`，并一次读取 `/etc/passwd` 解析 UID，不会为每个进程执行 `ps` 或 NSS 查询。
- Windows 每轮执行一次无 Profile 的 PowerShell/CIM 批量查询，并排除本轮采集 PowerShell 自身。
- 单轮采集默认 45 秒超时，可用 `-collection-timeout` 调整。
- `process_snapshot` 表示每日完整基线；`process_start`、`process_exit`、`process_change` 分别表示启动、退出和关键属性变化。
- 每轮扫描共享一个 `snapshot_id`，只有 `event_type=process_snapshot` 的轮次能够恢复完整进程集合。
- 增量身份键严格使用 `pid + start_time`，不能只使用 PID。无法读取 `start_time` 的进程会进入每日基线，但不会参加增量比对，以避免 PID 复用误报。
- Linux 状态默认保存到 `/opt/secweaver-agent/data/host-process-snapshot-state.json`；Windows 状态默认保存到 `C:\ProgramData\SecWeaver\Agent\data\host-process-snapshot-state.json`。状态文件使用原子替换和 `0600` 权限，损坏时会隔离后重建基线。
- 默认输出分别为 `/opt/secweaver-agent/logs/host-process-snapshot.log` 和 `C:\ProgramData\SecWeaver\Agent\logs\host-process-snapshot.log`。
- 日志默认单文件 100MB、保留 5 个轮转备份。

默认参数等价于：

```bash
secweaver-agent module host-process-snapshot \
  -interval 10m \
  -full-snapshot-interval 24h \
  -state /opt/secweaver-agent/data/host-process-snapshot-state.json
```

如果必须使用旧式纯全量模式，建议把扫描和完整基线周期都设置为 `1h`，避免每 10 分钟重复写整机进程清单。

## 主要字段

```json
{
  "asset_type": "host_process",
  "event_type": "process_change",
	"action": "changed",
  "snapshot_id": "process-snapshot-...",
  "snapshot_process_count": 237,
  "time": "2026-07-16T12:00:00+08:00",
  "host_name": "web-01",
  "host_ip": "192.0.2.91",
  "pid": "15270",
  "ppid": "1",
  "user": "www-data",
  "process": "php-fpm",
  "exe": "/usr/sbin/php-fpm",
	"command_hash": "command-...",
	"change_fields": ["uid", "command_hash"],
	"command_line": "php-fpm: pool www",
  "start_time": "2026-07-16T08:10:00+08:00",
  "rss_bytes": 73400320,
  "thread_count": 4
}
```

还会按系统能力输出 `uid`、`cwd`、`state`、`cpu_time_ms`、`virtual_bytes`、`session_id`、`cgroup`、`is_secweaver_agent` 等字段。完整基线不重复写 `command`/`command_line`，只保留 `command_hash`；启动、退出、命令/可执行文件/cgroup/UID/用户变化事件保留脱敏后的完整命令。常见 password、token、URL 口令和 `sshpass -p` 参数默认在 Agent 落盘前脱敏。

## 数据接入

公开资产使用 `asset-secweaver-host-process`。新部署应复制为新的唯一 asset ID；目标 ES 索引或 SLS Logstore、字段索引、采集配置和样例查询全部验证通过前，Connector 和资产应保持为 `draft`。

可用查询模板：

- `host_process_by_host_time`
- `host_process_by_host_ip_time`
- `host_process_by_name_time`
- `host_process_by_snapshot_id`

## 能力边界

10 分钟扫描看不到两个采集点之间快速启动并退出的进程，`process_exit` 也只会在下一轮扫描时确认，因此不能替代 `host_exec`。Linux 应继续使用 audit/eBPF，Windows 应使用 Security 4688/Sysmon 捕获实时执行。该模块主要用于长期运行进程盘点、可疑进程存活确认、父子关系补充和现场影响面分析。

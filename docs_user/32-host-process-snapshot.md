# host_process Host Process Snapshots

**Languages:** English (this page) | [简体中文](32-host-process-snapshot.zh-CN.md)

`host_process` records periodic process baselines and changes between scans. It complements real-time `host_exec` evidence with process presence, starts, exits, ownership, ancestry, executable path, command, cgroup, and privilege changes.

## Collection

The built-in `host-process-snapshot` module emits an initial full baseline, scans for deltas every 10 minutes, and emits another full baseline every 24 hours. Linux reads `/proc` directly and resolves UIDs from one `/etc/passwd` read. Windows runs one non-profile PowerShell/CIM batch query per interval. Events are `process_snapshot`, `process_start`, `process_exit`, and `process_change`; records from one scan share `snapshot_id`. A collection is canceled after 45 seconds by default. Adjust the timeout with `-collection-timeout`. Windows excludes the PowerShell process used for collection.

On an installed Linux Agent, run a one-shot check with your configured enterprise ID:

```bash
sudo SECWEAVER_ENTERPRISE_ID=YOUR_16_CHAR_ID \
  secweaver-agent module host-process-snapshot -once -output -
```

Delta identity is strictly `pid + start_time`; processes without a start time appear in full baselines but are excluded from delta matching to prevent PID-reuse errors. State defaults to `/opt/secweaver-agent/data/host-process-snapshot-state.json` on Linux and `C:\ProgramData\SecWeaver\Agent\data\host-process-snapshot-state.json` on Windows. State is atomically replaced after output is checkpointed. Corrupt state is quarantined and a new baseline is built. POSIX state files use mode `0600`.

Default outputs are `/opt/secweaver-agent/logs/host-process-snapshot.log` on Linux and `C:\ProgramData\SecWeaver\Agent\logs\host-process-snapshot.log` on Windows. Full baselines omit repeated `command` and `command_line` payloads and retain `command_hash`; start, exit, and tracked change events retain the full redacted command. Common password, token, URL credential, and `sshpass -p` arguments are redacted before output. For legacy full-only collection, use at least a one-hour scan/full-baseline interval. Logs default to a 100 MB active file and five rotated backups.

The default continuous settings are equivalent to:

```bash
secweaver-agent module host-process-snapshot \
  -interval 10m \
  -full-snapshot-interval 24h \
  -state /opt/secweaver-agent/data/host-process-snapshot-state.json
```

## Event fields

Only a `process_snapshot` scan describes a complete process set; delta scans cannot reconstruct it alone. Example event:

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

Core fields include `time`, `host`, `host_ip`, `snapshot_id`, `event_type`, `action`, `pid`, `ppid`, `uid`, `user`, `process`, `exe`, `command_hash`, `change_fields`, `start_time`, `cpu_time_ms`, `rss_bytes`, `thread_count`, and `cgroup`. Additional fields depend on platform capabilities and may include `cwd`, `state`, `virtual_bytes`, `session_id`, and `is_secweaver_agent`.

## Data onboarding

The public asset uses `asset-secweaver-host-process`. For a new deployment, copy it to a new unique asset ID and keep the connector and asset in `draft` until the target ES index or SLS Logstore, field indexes, collection configuration, and sample query are verified.

Query templates are `host_process_by_host_time`, `host_process_by_host_ip_time`, `host_process_by_name_time`, and `host_process_by_snapshot_id`.

## Limitations

A 10-minute scan cannot observe a process that starts and exits between collection points, and exits are confirmed only at the next scan. It must not replace real-time Linux audit/eBPF or Windows Security 4688/Sysmon `host_exec` evidence.

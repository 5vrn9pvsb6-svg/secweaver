# host_persistence Data Collection

**Languages:** English (this page) | [简体中文](28-host-persistence-collection.zh-CN.md)

`host_persistence` records creation, modification, and deletion at high-value Linux persistence locations. It focuses on paths used for long-term access, automatic execution, and privilege escalation rather than general file-system activity.

Typical evidence includes cron jobs, systemd services/timers, `authorized_keys`, sudoers, shell profiles, `/etc/ld.so.preload`, and kernel module configuration.

## Collection model

The `secweaver-agent` module `host-persistence` is implemented under:

```text
src/tools/secweaver-agent/pkg/hostpersistence/
```

It combines target-path snapshots, baseline comparison, and optional auditd enrichment:

```text
load configuration -> expand watch paths -> add audit watches
-> scan files -> collect metadata/hash/small-text snapshot
-> compare previous baseline -> enrich from auditd
-> emit host_persistence JSON Lines -> save new baseline
```

The default scan interval is 30 seconds. The first run creates a baseline without emitting historical files. Set `emit_baseline=true` only when an inventory of current state is required.

If auditd is unavailable, snapshot differences are still emitted, but user, process, and command fields may be empty.

## Default coverage

| Type | `persistence_type` | Paths |
|---|---|---|
| Scheduled tasks | `cron` | `/etc/crontab`, `/etc/cron.*`, `/var/spool/cron*` |
| Service startup | `systemd` | `/etc/systemd/system` |
| SysV startup | `sysvinit` | `/etc/init.d` |
| rc.local | `rc_local` | `/etc/rc.local` |
| Privilege escalation | `sudoers` | `/etc/sudoers`, `/etc/sudoers.d` |
| SSH access | `ssh_authorized_keys` | `/root/.ssh/authorized_keys`, `/home/*/.ssh/authorized_keys` |
| Shell startup | `shell_profile` | System, root, and user profile files |
| Library preload | `ld_preload` | `/etc/ld.so.preload` |
| Kernel modules | `kernel_module` | `/etc/modules-load.d`, `/etc/modprobe.d` |

Directory watches support `recursive`, `max_depth`, and `*` path expansion. Run the Agent as root for complete access to protected paths.

## Event fields

Snapshot fields include `path`, `category`, `persistence_type`, `file_type`, `mode`, `size`, `mod_time`, `hash`, and `symlink_target`. SHA256 is calculated only for regular files up to `max_hash_bytes` (1 MiB by default).

When `include_content_diff=true`, small text files up to `max_content_bytes` produce a bounded `content_diff`; `content_diff_truncated` indicates line-limit truncation. Full sensitive file content is not logged.

Auditd enrichment can add `user`, `uid`, `auid`, `auid_name`, `pid`, `ppid`, `process`, `exe`, `command`, `audit_id`, `audit_syscall`, and `actor_source`.

| Action | Meaning |
|---|---|
| `observed` | Initial inventory, only with `emit_baseline=true` |
| `created` | New watched file |
| `modified` | Metadata, hash, permission, size, or target changed |
| `deleted` | Previously observed file removed |

All events use `asset_type=host_persistence` and `event_type=persistence_change`.

```json
{
  "asset_type": "host_persistence",
  "timestamp": "2026-07-09T10:20:30Z",
  "host": "web-01",
  "host_ip": "192.0.2.92",
  "event_type": "persistence_change",
  "action": "modified",
  "category": "account_access",
  "persistence_type": "ssh_authorized_keys",
  "path": "/home/www/.ssh/authorized_keys",
  "user": "alice",
  "process": "bash",
  "command": "bash -c echo ssh-rsa ... >> /home/www/.ssh/authorized_keys",
  "actor_source": "auditd"
}
```

## Agent configuration

The default Linux Agent configuration enables the module and points it at
`/opt/secweaver-agent/etc/host-persistence.json`:

```json
{
  "modules": {
    "host-persistence": {
      "enabled": true,
      "restart": "on_failure",
      "restart_delay_seconds": 5,
      "args": [
        "-config",
        "/opt/secweaver-agent/etc/host-persistence.json"
      ]
    }
  }
}
```

Module configuration example:

```json
{
  "output_log": "/opt/secweaver-agent/logs/host-persistence.log",
  "state_path": "/opt/secweaver-agent/data/host-persistence-state.json",
  "poll_interval_seconds": 30,
  "include_hash": true,
  "max_hash_bytes": 1048576,
  "include_content_diff": true,
  "max_content_bytes": 65536,
  "max_diff_lines": 200,
  "emit_baseline": false,
  "audit": {
    "enabled": true,
    "audit_log": "/var/log/audit/audit.log",
    "key": "tb_host_persistence",
    "perm": "wa",
    "manage_rules": true,
    "fail_on_error": false,
    "from_start": false
  },
  "watch": [
    {
      "path": "/etc/crontab",
      "category": "scheduled_task",
      "persistence_type": "cron"
    },
    {
      "path": "/etc/systemd/system",
      "category": "service_autostart",
      "persistence_type": "systemd",
      "recursive": true,
      "max_depth": 4
    },
    {
      "path": "/home/*/.ssh/authorized_keys",
      "category": "account_access",
      "persistence_type": "ssh_authorized_keys"
    }
  ]
}
```

The full example is `src/tools/secweaver-agent/host-persistence.example.json`.

## How events are produced

Each scan is compared with the saved baseline. The module emits `observed` only when `emit_baseline=true`; later additions, changes, and removals use `created`, `modified`, and `deleted`. Modification checks include permissions, size, modification time, hash, and symbolic-link target. Every emitted record uses `asset_type=host_persistence` and `event_type=persistence_change`.

## Asset onboarding

The default output and state files are:

```text
/opt/secweaver-agent/logs/host-persistence.log
/opt/secweaver-agent/data/host-persistence-state.json
```

Use these definitions:

```text
dataasset/assets/asset-secweaver-host-persistence.json
dataasset/connectors/conn-sls-secweaver-host-persistence.json
```

Available query templates include `host_persistence_by_host_time`, `host_persistence_by_host_ip_time`, `host_persistence_by_path_time`, and `host_persistence_by_type_time`.

Forward `/opt/secweaver-agent/logs/host-persistence.log` to SLS/ES, verify real events and fields, then change the Connector and Asset from `draft` to `active`.

## Why collection is selective

Full filesystem auditing produces high volume from updates, log rotation, and application releases; it also increases kernel and deployment dependencies without making every event useful for an investigation. `host-persistence` therefore monitors configured high-value persistence paths and uses auditd only to enrich those changes with actor and process context. It does not provide general-purpose full filesystem auditing.

## Operational use

Correlate persistence evidence with `host_exec`, `host_file_op`, `ssh_auth`, and `web_access_log` to determine which command caused a change, whether a new key was used, and whether persistence followed a Web intrusion.

Production recommendations:

1. Run the Agent as root and enable auditd enrichment.
2. Verify that Linux auditd is enabled and `/var/log/audit/audit.log` is readable;
   otherwise actor and process fields will be absent.
3. Keep `emit_baseline=false` for normal deployment.
4. Roll out to a small host group first and measure volume and field quality.
5. Extend watch paths for platform-specific services such as kubelet, containerd, or Docker.
6. Protect the baseline directory from non-privileged modification.
7. Declare only the hosts actually covered by the deployed Agent.
8. After forwarding to SLS/ES and verifying real events, promote
   `asset-secweaver-host-persistence` from `draft` to `active`.

## Limitations

- Detection latency follows `poll_interval_seconds`.
- Only configured paths are monitored.
- Content diffs are bounded and limited to small text files.
- Actor attribution depends on auditd availability and successful rule installation.
- A file created and removed between scans may be missed.
- Deleting the state file causes the next run to establish a new baseline.

See [SecWeaver data system quickstart](29-secweaver-data-system-quickstart.md) for SLS ingestion and bundle activation.

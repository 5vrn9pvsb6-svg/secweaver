# Tenant Collection and Heartbeat Policy

From Agent 0.3.87, new Linux and Windows installations default to **30-minute process delta scans** and **5-minute authorization heartbeats**. Full process baselines remain daily (24 hours). Real-time exec, file, identity and service collection are unaffected.

## Enterprise Workspace

Set whole minutes under My Enterprise → Agent Collection Policy. Owner/Admin can save; other members have read-only access.

| Setting | Default | Range | Local configuration |
| --- | --- | --- | --- |
| Process delta interval | 30 minutes | 1–1440 minutes | `host-process-snapshot` `-interval` |
| Agent heartbeat interval | 5 minutes | 1–60 minutes | `license.heartbeat_interval_seconds` |

The next successful heartbeat delivers the saved policy, so propagation depends on the **previous** heartbeat interval. The Agent bounds both fields, merges them into the existing configuration, strictly validates the result and replaces the file atomically after fsync. Module enablement, paths, whitelists, identity keys and other settings are preserved. Linux restarts collectors through the service manager; Windows keeps the SCM service Running while draining and reloading its collectors. Learning and process delta state files are neither deleted nor reset.

Process inventory still compares `pid+start_time` and emits starts, exits and meaningful attribute changes. Short-lived processes between scans require real-time audit/eBPF or Windows 4688/Sysmon evidence. Longer intervals reduce scans but delay inventory changes.

## Compatibility and Failure Handling

- Requires Agent Server 0.6.0-rc.75, Server 0.6.0-rc.115 and shared migration 034. Existing tenants remain locally managed after migration until Owner/Admin saves a policy. New tenant policy defaults are 30/5.
- Install/upgrade preserves existing local configuration. ES private/offline hosts without server policy can set these fields locally; the workspace cannot control disconnected hosts.
- Without an explicit heartbeat argument, installers preserve an existing interval and use 300 seconds for a new configuration. The Linux installer's `--license-heartbeat-interval-seconds 300` and the Windows package's `install-service.ps1 -LicenseHeartbeatIntervalSeconds 300` explicitly override the local interval. The internal value `0` means preserve/default, and does not disable heartbeats.
- Servers omit the additive response field for old Agents without `agent-runtime-policy-v1`; enrollment and heartbeats continue. These Agents need a client upgrade to apply managed cadence. New Agents retain local settings when older servers omit policy.
- Invalid policies, failed writes or an upgrade download/install/health probation defer application until a later heartbeat. Network failures retain collection and existing reconnect backoff.
- Signed full remote configuration shares the write mutex. Avoid repeatedly delivering conflicting cadence through a separate full configuration: conflicting sources would trigger alternating reloads.
- Presence uses the reported actual heartbeat interval: `max(300 seconds, 3 × actual interval + 60 seconds)`. Old devices without a report retain the 300-second window.

## Verification

After saving, inspect the heartbeat seconds and process `-interval` in `config.json`, verify service activity, successful heartbeats and recent local output. Linux: `systemctl is-active secweaver-agent`. Windows: `Get-Service SecWeaverAgent`. Run `secweaver-agent doctor` for local collector checks. A saved desired policy is not proof an offline host has applied it.

Workspace API: `PATCH /api/v1/enterprises/{id}/agent-collection-policy`, with both minute fields and the read `revision`. Changes are audited; retry uncertain network outcomes with the same idempotency key. A stale revision returns 409 and requires refresh.

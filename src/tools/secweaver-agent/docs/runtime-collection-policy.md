# Tenant Collection and Heartbeat Policy

From Agent 0.3.87, new Linux and Windows installations default to **30-minute process delta scans** and **5-minute authorization heartbeats**. Full process baselines default to 24 hours. Agent 0.3.91 adds configurable full baselines, health logs and persistence checks; real-time exec/audit/eBPF sources remain unaffected.

## Enterprise Workspace

Set integers in the labeled minutes, seconds or hours under My Enterprise → Agent Collection Policy. Owner/Admin can save; other members have read-only access.

| Setting | Default | Range | Local configuration |
| --- | --- | --- | --- |
| Process delta interval | 30 minutes | 1–1440 minutes | `host-process-snapshot` `-interval` |
| Agent heartbeat interval | 5 minutes | 1–60 minutes | `license.heartbeat_interval_seconds` |
| Listening sockets / `host_socket` | 5 minutes | 1–1440 minutes | `host-state-snapshot` `-socket-interval` |
| Accounts and logins / `host_identity` | 5 minutes | 1–1440 minutes | `host-state-snapshot` `-identity-interval` |
| Services and scheduled tasks / `host_service` | 5 minutes | 1–1440 minutes | `host-state-snapshot` `-service-interval` |
| Kernel and containers / `host_kernel_context` | 10 minutes | 1–1440 minutes | `host-state-snapshot` `-kernel-interval` |
| Health logs | 5 minutes | 1–1440 minutes | `operations_report.snapshot_interval_seconds` |
| Persistence file checks | 30 seconds | 10–3600 seconds | `host-persistence` `-poll-interval` |
| Process full baseline | 24 hours | 1–168 hours | `host-process-snapshot` `-full-snapshot-interval` |
| Host-state full baseline | 24 hours | 1–168 hours | `host-state-snapshot` `-full-snapshot-interval` |

The four Agent 0.3.91 additions require Agent Server 0.6.0-rc.77/schema36 and
Workspace Server 0.6.0-rc.117, negotiated by `extended-collection-cadence-v1`.
Their keys are `health_report_interval_minutes`, `host_persistence_interval_seconds`,
`host_process_full_snapshot_hours` and `host_state_full_snapshot_hours`. Omitted
values preserve local settings; new tenants default to 5m/30s/24h/24h, existing
tenants are not backfilled. Health cadence controls periodic snapshots, not
startup/error events. Missing health configuration is not created/enabled. Existing
jitter is retained; a period below local jitter fails strict validation atomically
and the original config keeps working. Persistence checks emit changes, not full
inventories every 30 seconds; explicit `-poll-interval` overrides the module JSON
timer without changing watch lists/audit rules. Full baselines are emitted on the
next actual scan after becoming due, possibly later with longer check intervals.
Learning and file/process/host-state comparison state remain intact. Inspect all
four local settings above and confirm that policy replay does not trigger reloads.

Agent 0.3.90 adds the four host-state controls on Linux and Windows. The next successful heartbeat delivers the saved policy, so propagation depends on the **previous** heartbeat interval. The Agent bounds all present fields, merges them into the existing configuration, strictly validates the result and replaces the file atomically after fsync. Module enablement, paths, whitelists, identity keys and other settings are preserved. Linux restarts collectors through the service manager; Windows keeps the SCM service Running while draining and reloading its collectors. Learning, process and host-state comparison files are neither deleted nor reset. Host-state still emits an initial baseline, changes and a full baseline (daily by default); an unchanged scan does not upload a fresh full inventory. Increasing a check interval delays change detection.

Process inventory still compares `pid+start_time` and emits starts, exits and meaningful attribute changes. Short-lived processes between scans require real-time audit/eBPF or Windows 4688/Sysmon evidence. Longer intervals reduce scans but delay inventory changes.

## Compatibility and Failure Handling

- Requires Agent Server 0.6.0-rc.75, Server 0.6.0-rc.115 and shared migration 034. Existing tenants remain locally managed after migration until Owner/Admin saves a policy. New tenant policy defaults are 30/5.
- Host-state controls require Agent Server 0.6.0-rc.76, Server 0.6.0-rc.116, migration 035 and Agent 0.3.90. Servers negotiate `host-state-cadence-v1` separately: Agents 0.3.87–0.3.89 keep receiving only process/heartbeat. Existing policies are not backfilled; omitted host-state fields preserve local intervals. New tenants default to 30/5/5/5/5/10. Old workspace requests preserve saved host-state values.
- Install/upgrade preserves existing local configuration. ES private/offline hosts without server policy can set these fields locally; the workspace cannot control disconnected hosts.
- Without an explicit heartbeat argument, installers preserve an existing interval and use 300 seconds for a new configuration. The Linux installer's `--license-heartbeat-interval-seconds 300` and the Windows package's `install-service.ps1 -LicenseHeartbeatIntervalSeconds 300` explicitly override the local interval. The internal value `0` means preserve/default, and does not disable heartbeats.
- Servers omit the additive response field for old Agents without `agent-runtime-policy-v1`; enrollment and heartbeats continue. These Agents need a client upgrade to apply managed cadence. New Agents retain local settings when older servers omit policy.
- Invalid policies, failed writes or an upgrade download/install/health probation defer application until a later heartbeat. Network failures retain collection and existing reconnect backoff.
- Signed full remote configuration shares the write mutex. Avoid repeatedly delivering conflicting cadence through a separate full configuration: conflicting sources would trigger alternating reloads.
- Presence uses the reported actual heartbeat interval: `max(300 seconds, 3 × actual interval + 60 seconds)`. Old devices without a report retain the 300-second window.

## Verification

After saving, inspect the heartbeat seconds, process `-interval` and host-state's four interval flags in `config.json`, verify service activity, successful heartbeats and recent local output. Linux: `systemctl is-active secweaver-agent`. Windows: `Get-Service SecWeaverAgent`. Run `secweaver-agent doctor` for local collector checks. A saved desired policy is not proof an offline host has applied it.

Workspace API: `PATCH /api/v1/enterprises/{id}/agent-collection-policy`, with process/heartbeat minutes, the read `revision` and optional `host_socket_interval_minutes`, `host_identity_interval_minutes`, `host_service_interval_minutes`, `host_kernel_context_interval_minutes`. Changes are audited; retry uncertain network outcomes with the same idempotency key. A stale revision returns 409 and requires refresh.

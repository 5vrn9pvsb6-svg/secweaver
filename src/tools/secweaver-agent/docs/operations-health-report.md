# Agent Operations Health Log

From 0.3.47, records include optional `deployment_mode` (`sls_saas` or
`es_private`) when configured. It selects the expected local delivery path;
ES mode does not inspect SLS machine-group identity or unrelated Logtail.
See [deployment modes](deployment-modes.md) for legacy behavior and migration.

SecWeaver Agent enables one append-only JSON Lines operations stream by default. Filebeat, Fluent Bit, or the native `secweaver-shipper` can upload it. The stream describes collector health and delivery configuration; it is not a replacement for security evidence.

## File And Defaults

Linux writes `/opt/secweaver-agent/logs/secweaver-agent-health.log`; Windows writes `C:\ProgramData\SecWeaver\Agent\logs\secweaver-agent-health.log`. It uses the existing Agent output policy: a 100 MB active file, five numeric backups, POSIX mode `0600`, and the shared disk budget.

Add this fragment at the top level of the Agent configuration (Linux path shown):

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

Omitted `enabled` defaults to `true`. The interval cannot be below 60 seconds. The production default is 300 seconds. Jitter is stable for the durable device ID and falls back to host name plus host IP before enrollment, avoiding fleet-wide write/upload bursts.

## Events And Semantics

Since 0.3.41, Logtail status includes identity, systemd and daemon checks with bounded
subprocesses and a 60-second minimum probe cache. Local faults degrade health;
`shipper.cloud_delivery=unverified` never claims successful ingestion. See
[collector lifecycle and verification](collector-lifecycle.md) for fields and limits.

`agent_lifecycle` records startup and normal shutdown, `health_snapshot` records periodic state, and `health_transition` records changes in module, authorization, persistence, or audit-reader state. Each record contains stable identity, platform, version, module status, output stat data, authorization state, shared audit-demux counters, and low-cost Go heap/runtime/GC counters without another process scan.

The reporter reads existing in-memory demux counters only. It never runs `auditctl -l`, scans `/proc`, or writes while holding the audit reader lock. A host using eBPF or no audit module may legitimately report zero readers. The reporter uses a private rotating writer and cannot block evidence collectors; an unhealthy reporter disables only this telemetry path.

`healthy/info` means collection is running; `degraded/medium` means a recoverable transition; `unhealthy/high` means a module error/circuit, authorization failure, unavailable audit reader, or overwritten audit evidence. Secrets, enrollment tokens, private keys, full configuration, and full command lines are excluded.

## Storage And Queries

Destination names depend on the delivery configuration, not the Agent binary.
The public standalone ES integration in `src/tools/secweaver-agent/elasticsearch/` at the
Community repository root tails this file and writes
`secweaver-public-agent-secweaver-agent-health-*` for collector operations.
This telemetry is outside the AI agent's DataAsset registry and investigation bundles.
Its minimal ES mapping is not a complete nested-health analytics mapping.

For SaaS, use the operational monitoring and upload settings supplied by the platform.
Managed delivery configurations are not part of the public Agent package.

Use server-side alerts for a missing snapshot, repeated restarts, circuit open, audit-reader failure, audit backlog overwrite, license denial, disk pressure, version drift, or shipper failure. A fully stopped Agent cannot upload its own shutdown event, so missing-host detection must also use Data Cloud enrollment/heartbeat state and shipper delivery telemetry.

Windows from 0.3.46 probes `LogtailDaemon`, its worker process and `C:\LogtailData`
identity with a bounded CIM query. An expected but missing collector degrades health;
query failure is unknown and local success still leaves cloud delivery unverified. See
[Windows acceptance](windows-installation.md).

# SecWeaver Agent Long-Run Recovery and Disk Protection

This document defines the production behavior for control-plane recovery, the
Agent-wide output budget, status persistence, and Windows child shutdown.

## Authorization recovery

- Initial DNS, connection, timeout, and HTTP `408/425/429/5xx` failures retry
  in-process with stable jitter and exponential backoff from 5 seconds to five
  minutes.
- A valid cached authorization within `license.outage_grace_seconds` permits
  collection immediately while scheduled authorization and heartbeat checks
  continue.
- Explicit denials such as expiration or device-limit exhaustion fail fast.
- Invalid Linux configuration exits with code `78` and is excluded by
  `RestartPreventExitStatus=78`. `StartLimitInterval=0` prevents transient
  failures from permanently latching the unit in `failed`.

## Agent-wide disk budget

The default policy is:

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

The parent divides `max_total_mb` by the number of unique configured output
paths. Each child clamps active-file size and numeric backup count to that
share. Existing oldest backups are pruned on open and rotation; an active file
is never truncated.

From Agent **0.3.105**, device-v2 custom collection alerts also reserve a slot:
`collection_rules.alert_output`, or `<installation-root>/logs/custom-risk-alert.log`
when unset. The path resolver is shared with the actual controller. Its slot is
reserved before local identity becomes readable so enrollment/recovery does not
change the divisor. An explicitly disabled controller or a legacy non-device-v2
installation reserves no alert slot. Module/learning, update, enabled health and
alert paths are deduplicated together on both Linux and Windows.

The nominal per-file defaults remain **100 MiB plus 5 numeric backups**. Enabled
host budgeting can lower these limits: `max_total_mb / unique-path-count` is the
file share, divided across active and backup slots. For example, nine default
outputs with a 2048 MiB budget receive 238,609,294 bytes per path and a 39,768,215
byte rotation threshold each. Budgeting is retention control, not a hard
filesystem quota: old active files are not truncated and an individual oversized
record can exceed the rotation threshold. Log retention is by size/count, not days.

Free-space protection is tiered:

| Priority | Default modules | Refusal threshold |
|---|---|---|
| Realtime | audit, syslog, persistence, Windows Event Log | `min_free_mb` |
| Standard | update status and future unclassified modules | base plus 10% of the file share |
| Snapshot | process and host-state snapshots | base plus 25% of the file share |

At the threshold, a writer removes its own oldest numeric backups and checks
again. If the reserve is still unavailable, the write returns an explicit error;
the supervisor marks/restarts modules that exit under its normal backoff.

### Low-space retry and recovery (Agent 0.3.103+)

On Linux and Windows, reserve probes and periodic learning persistence retries
back off through **1, 2, 4, 8, 16, 32, 60 seconds**, capped at 60 seconds per
retrying operation. A successful probe/write resets that operation's backoff.
Healthy disk checks still use `check_interval_seconds` (30 by default); actual
recovery also depends on module scheduling and the normal output flush interval
(5 seconds by default). No disk threshold is reduced to make a write succeed.

Buffered output no longer permanently latches `output disk reserve exhausted`.
This guard refuses before writing bytes, so it can safely retry accepted pending
data after external cleanup, without restarting a live collector. The buffer
remains bounded by its configured size (64 KiB by default); rejected new writes
are returned to the caller, not accumulated in an unlimited spool. Unknown I/O,
short writes and durability errors remain sticky: retrying ambiguous evidence
must not fabricate successful checkpoints or advance Windows cursors.

Recurring buffered-output, Linux/Windows learning checkpoint, Linux learning
event-output and operations-report diagnostics log the first failure immediately
and then at most once per minute **per operation/stream**. Further failures are
counted in `suppressed=N`, including failures whose free-space numbers change.
One `recovered` diagnostic follows actual successful I/O/checkpoint processing;
an empty flush, skipped retry, service `running` state or free-space reading
alone is not evidence that output recovered. This is not a process-wide log cap.

Free space on the affected filesystem, keep the service running, and inspect
service stderr (Linux: `journalctl -u secweaver-agent --since '5 minutes ago'`),
output-file modification times and `/health`. Do not fill a production disk to
test this behavior; regression tests use injected low-space probes plus real
temporary rotating files. A restarted/exited module still follows supervisor
restart policy rather than the live-writer retry path.

Recovery does not reconstruct events that were rejected while storage was
unavailable, nor does it silently trust a degraded learning baseline. Confirm
new raw evidence and health output first; explicitly relearn when required by
[learning recovery](learning-recovery.md). Never delete learning identity/state
or disable the reserve simply to silence these warnings.

The total covers Agent JSONL/update status files managed through `pkg/output`.
It does not cover `status.json`, auditd-owned logs, or Logtail/Filebeat files.
Shipper cursor formats are not portable, so shipper lag must be monitored by
the selected Logtail/Filebeat integration rather than inferred by the Agent.

### Log inventory (Agent 0.3.105)

On Linux and Windows, `doctor` lists configured Agent-owned file outputs even
without `-verbose`: module evidence and declared learning summaries, enabled
health output, update output, and the device-v2 alert sink. The JSON report adds
`logs[]`; existing `checks[]` remains unchanged in shape.

```bash
secweaver-agent doctor -config /opt/secweaver-agent/etc/config.json -check-license=false
secweaver-agent doctor -config /opt/secweaver-agent/etc/config.json -check-license=false -json
```

In administrator PowerShell (substitute your installation root):

```powershell
& 'C:\ProgramData\SecWeaver\Agent\bin\secweaver-agent.exe' doctor -config 'C:\ProgramData\SecWeaver\Agent\etc\config.json' -check-license=false -json
```

- `current_size_bytes`: active-file bytes, or `null` when missing/unreadable/nonregular.
- `max_size_bytes`, `max_backups`, `per_file_budget_bytes`: effective configured
  rotation/retention limits, using exactly the live writer's calculation;
  zero budget bytes means host budgeting is disabled, not zero space available.
- `backup_count`, `backup_size_bytes`, `total_size_bytes`: observed regular numeric
  backups and bytes, including backups above the configured retention count.
- `latest_backup_path`, `last_rotation_estimate`: `.1` and its modification time,
  with `rotation_time_source=backup_mtime_estimate`. Rename does not update mtime;
  this is the newest retained file's last write, **not an exact rotation timestamp**.
  Without `.1`, the source is `unknown`; do not infer that rotation never occurred.
- `scan_complete`, `inspection_error`: access/nonregular-path/scan-limit problems
  produce a warning and partial counts, never fabricated complete totals.

The new inventory reads metadata only: no directory creation, permission repair,
content/credential upload, rotation or pruning. Existing recent-JSON checks still
read bounded log tails. Directory scans use batches of
128 entries, capped at 16,384 entries per output; symlink/special-file backups
are not followed. Results can race active writes/rotation. Limits describe the
current configuration, not proof that an already running process has reloaded
it; shared paths show the strictest configured writer limits. Inspect the intended
configuration and restart the service when changing retention. Disabled modules,
stdout/stderr, installer/vendor logs, journald, auditd, shipper logs and state JSON
are not included. Missing optional logs may simply not have been created yet.

Verification: check both text and `-json` output and compare the listed files and
`.1`/`.2` backups with filesystem metadata. Automated tests compare diagnostic
limits with real writers, exercise numeric rotation/custom health retention and
verify that inspection does not modify/prune files. No production disk filling or
forced evidence generation is required.

## Status persistence

- The first `status.json` is synchronous. Long-running state changes are
  coalesced by one writer to at most one write per second, outside the state lock.
- Failures retry every second; stderr is throttled to once per minute and
  `/health` returns HTTP 503.
- Shutdown and update activation force a final flush.
- `persistence.last_attempt_at`, `last_success_at`, `last_error`, and
  `error_count` describe the status channel. During a continuing disk failure,
  the old file cannot update, so monitor `/health` and service stderr as well.

## Windows module shutdown

The Windows supervisor gives each child a private stdin control pipe. Stop and
upgrade send `shutdown`; the collector cancels its context, flushes output, and
checkpoints EventRecordID before exit. The existing 15-second `WaitDelay` remains
the forced-kill fallback.

Each child is also assigned to a `KILL_ON_JOB_CLOSE` Job Object so an abnormal
parent exit is contained by the kernel. If an upstream Job policy rejects nested
assignment, the Agent logs a containment warning and retains cooperative pipe
shutdown instead of refusing collection startup.

## Version and verification

The root `VERSION` is the only Agent release version. Makefile, cross-build, and
package scripts inject it into both the root command and
`audit-port-execmon -version`; parser/schema versions remain separate data
contracts.

```bash
secweaver-agent version
secweaver-agent audit-port-execmon -version
systemctl show secweaver-agent -p NRestarts -p Result
curl --fail http://127.0.0.1:9100/health
jq '.persistence,.modules,.license' /opt/secweaver-agent/data/status.json
```

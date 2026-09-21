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

Free-space protection is tiered:

| Priority | Default modules | Refusal threshold |
|---|---|---|
| Realtime | audit, syslog, persistence, Windows Event Log | `min_free_mb` |
| Standard | update status and future unclassified modules | base plus 10% of the file share |
| Snapshot | process and host-state snapshots | base plus 25% of the file share |

At the threshold, a writer removes its own oldest numeric backups and checks
again. If the reserve is still unavailable, the write returns an explicit error;
the supervisor marks/restarts the module under its normal backoff. Refused
writes recheck once per second so collection can recover promptly.

The total covers Agent JSONL/update status files managed through `pkg/output`.
It does not cover `status.json`, auditd-owned logs, or Logtail/Filebeat files.
Shipper cursor formats are not portable, so shipper lag must be monitored by
the selected Logtail/Filebeat integration rather than inferred by the Agent.

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

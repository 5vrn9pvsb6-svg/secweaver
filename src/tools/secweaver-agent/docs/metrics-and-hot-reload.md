# SecWeaver Agent metrics and configuration lifecycle

SecWeaver Agent can expose optional Prometheus metrics. The current release does
not hot-reload local configuration: changes take effect only after a controlled
Agent restart. Stating this explicitly prevents an operator from assuming that
an audit queue, module arguments, or resource policy changed when it did not.

## Metrics configuration

```json
{
  "metrics": {
    "enabled": true,
    "listen_address": "127.0.0.1:9100",
    "path": "/metrics"
  }
}
```

Defaults when enabled:

- Listen address: `127.0.0.1:9100`
- Metrics path: `/metrics`
- Liveness path: `/live`
- Readiness path: `/health`

`/live` only proves that the metrics HTTP server can respond and returns HTTP
200 while it is alive. `/health` is the Agent readiness contract. It returns
HTTP 200 only when every configured collector is `running` with a valid PID,
authorization has no current error, and no runtime diagnostic has `error`
severity. A module that has not started, is restarting, or has an open circuit,
degraded authorization, an audit reader that cannot open/reopen its source, or
an audit evidence overwrite returns HTTP 503 with a reason. Historical restart
counts do not prevent a recovered module from becoming ready again.
Failure to persist `status.json` also returns 503 and clears automatically after
the status writer recovers.

The Agent validates the address and path while loading the configuration. It
then binds the socket synchronously before starting module supervision. A bind
failure is reported as a startup warning and collection continues without a
metrics exporter; the service log records the exact failure.

The endpoint has no built-in authentication. Keep the default loopback binding,
or place a firewall/authenticated reverse proxy in front of a non-loopback
listener. The metrics path cannot be `/live` or `/health` and cannot contain Go ServeMux
wildcards.

After changing the file, restart and verify:

```bash
sudo systemctl restart secweaver-agent
curl --fail http://127.0.0.1:9100/live
curl --fail http://127.0.0.1:9100/health
curl --fail http://127.0.0.1:9100/metrics
```

## Core metrics

- `secweaver_agent_module_status`: `1` running, `0` stopped/not started, `-1` error, `-2` restarting, and `-3` circuit-open degradation.
- `secweaver_agent_module_pid`: current child PID, or `0` while it is not running.
- `secweaver_agent_audit_backlog_lines`: total shared-demux lines waiting for replay.
- `secweaver_agent_audit_backlog_overflows_total`: evidence lines overwritten after a fixed backlog filled; alert on every non-zero production increase.
- `secweaver_agent_audit_retired_subscribers_total`: subscriptions retired after a full queue or pipe failure.
- `secweaver_agent_audit_lines_processed_total`: raw lines processed by the parent's shared audit reader.
- `secweaver_agent_audit_readers` and `secweaver_agent_audit_readers_ready`: configured shared readers and readers whose source file is currently open.
- `secweaver_agent_audit_reader_failures_total`: transitions from available to unavailable; retries in one outage do not repeatedly increment it.
- `secweaver_agent_license_enabled`, `secweaver_agent_license_check_success`, and `secweaver_agent_heartbeat_success`: authorization configuration and latest control-plane results.
- `secweaver_agent_update_info`, `secweaver_agent_update_attempts_total`, and `secweaver_agent_update_failures_total`: latest update state and cumulative attempts.

The parent samples cumulative audit-demux counters every five seconds, keeping
Prometheus operations off the audit reader hot path. Each module backlog retains
4096 lines. The first overwrite and every thousand thereafter form diagnostic
throttle points handled by a separate worker. If state storage is slow, its
single-slot queue coalesces to the latest throttle point, while Prometheus totals
remain exact. Stderr and `status.json` include the oldest lost and latest audit
IDs. The resulting `error` diagnostic remains sticky for that Agent process
because later recovery cannot reconstruct evidence that was already overwritten.

The file-follow layer reports initial open, read failure, and audit.log rotation
reopen state. An unavailable reader creates a recoverable `error` diagnostic;
successfully reopening the source clears it. An idle host does not need to
produce audit events to remain ready.

## Configuration changes

Local configuration is strict JSON. Unknown fields fail preflight and startup.
Use the packaged schema and preflight before restarting:

```bash
/opt/secweaver-agent/bin/secweaver-agent preflight \
  -config /opt/secweaver-agent/etc/config.json
sudo systemctl restart secweaver-agent
```

Remote configuration follows the same rule: the signed configuration is written
atomically and the supervisor exits with its service-restart code. The service
manager then starts all modules with one coherent configuration generation.

`module_resources`, `audit_demux`, and `log_level` are not public configuration
fields in this release. Host-wide resource limits are enforced by the packaged
systemd unit. Per-module resource limits require separate cgroups/job objects and
will only be documented when that isolation is implemented and tested.

## Audit module diagnostics

`audit-port-execmon` keeps high-frequency parser counters in lock-free atomics,
while its `processTreeMonitor` owns rule queue, active-rule budget, and pressure
recovery state. A normal module exit combines these production metrics into one
`audit runtime stats` stderr record for stop/upgrade diagnosis. Internal parser
and rule details are still not exported through the parent `/metrics` endpoint
and do not persist across module restarts. Parent metrics now export shared-demux
backlog, overwrite, processed-line, and subscriber-lifecycle state.

## Release verification

Every shipped example is strict-decoded in the Agent test suite. The JSON Schema
top-level fields are also checked against the runtime model so configuration
documentation cannot silently drift from executable behavior.

See also [Chinese guide](metrics-and-hot-reload.zh-CN.md).

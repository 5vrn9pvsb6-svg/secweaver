# Learning Recovery and Empty Baselines

[中文](learning-recovery.zh-CN.md)

## Audit backpressure (0.3.102)

On Linux shared-Audit collection, short child-pipe stalls no longer immediately
close a full 8192-line queue. The subscriber pauses live enqueueing and retains
new lines in its existing 4096-line module ring. After the writer flushes/drains,
it replays older buffered lines before admitting live input. Uncertain flush
batches are capped at 256 lines; failed writes may replay duplicates rather than
silently lose evidence. Pressure diagnostics run outside the reader/writer path.
These are raw audit **line** limits, not event counts or a durable spool; no
infinite buffering or sustained-overload guarantee is provided. Other subscribers
continue independently. eBPF-only and Windows evidence paths are unchanged.

Real ring overwrite still retires the stream: the existing child EOF/restart
path records `audit_reader_failed`, disables learning filtering and keeps normal
collection running. This is fail-open evidence retention, not a reason to restore
trust automatically. A previously degraded generation stays degraded after an
upgrade/restart. Custom rules and other explicit collection exclusions still apply.
Backlog-loss health diagnostics remain sticky for the parent process.

For a high-volume/degraded host:

1. Inspect `doctor --verbose`, service logs and health JSONL. Compare internal
   `queued_lines`, `queue_capacity`, `paused_subscribers`, `backlog_lines` and the
   **increase** in `backlog_overflows_total`; kernel `auditctl -s lost=0` alone
   does not prove the Agent delivered all lines. Check disk/rotation and module
   restart counts as well. The new pressure gauges need 0.3.102+.
2. Install the repaired Agent through the usual verified update procedure.
   Stop ongoing overload/loss first. An upgrade alone does not reset learning.
3. Run the existing helper below in inspect mode, then explicit `--apply` after
   reviewing the JSON result. It backs up state/config, increments the learning
   generation, validates restart and rolls back on ordinary failure. Save the
   local backup path and result as the change receipt. No remote reset endpoint
   or silent whitelist deletion is added by this repair.
4. Verify fresh healthy exec/file learning, five-hit admissions, increasing
   suppression, no new overflow/restart loop and the next server heartbeat.
   Observe representative busy periods; a brief drop in SLS volume is not proof
   of a stable daily rate. The API's partial authorization checks must not erase
   the last telemetry report (Agent Server rc.87+).

Regression verification: `go test -race . ./pkg/metrics` covers real pipe burst
draining, FIFO partial replay, rate-limited loss retirement and queue metrics;
`make recovery-test` covers explicit recovery transactions. This is source-level
verification, not CentOS/Kylin production stress acceptance.

## Fresh Installs and Upgrades

Fresh templates enable learning with shadow=false. The first startup learns from
an empty baseline, correctly reporting filtering_active=false. Five distinct
events with the same four fields in a rolling hour admit/filter the fifth event;
there is no need to wait for the learning day to end. Originals remain until then.

Initial legacy migration archives the old baseline and starts a new baseline_id;
old logs do not replay to supply counts. Ordinary restarts and later compatible
upgrades preserve progress. The 0.3.85 Linux command-completeness change does not
restart completed learning. See [behavior learning](behavior-learning.md).

Empty baselines/lack of repetitions are not faults. Relearning cannot manufacture
events or guarantee immediate filtering. Fix missing input or continuing audit
loss first; otherwise the new generation may degrade too, including on fresh installs.

## Linux Helper

Copy recovery/restart-behavior-learning.py alone. It supports Linux systemd, root,
Python 3.6+ and Agent 0.3.81+, with either SLS SaaS or ES and no network access.
It requires the standard layout and audit module arguments
`-config <install-root>/etc/audit-port-execmon.json`. Use --root/--service for an
alternate root/service. Custom state_dir, extra module arguments, Windows,
containers and non-systemd installations need their manual procedure.

```bash
# Inspect only: JSON result; no service stop or config/state mutation
sudo python3 ./restart-behavior-learning.py

# Recover disabled/shadow/degraded or completed-empty learning
sudo python3 ./restart-behavior-learning.py --apply

# Explicitly restart healthy learning with an empty baseline (usually unnecessary)
sudo python3 ./restart-behavior-learning.py --apply --relearn
```

With the default --scope all, healthy exec baselines and active file baselines are always preserved. Healthy
empty learning is skipped without --relearn. Repeating ordinary --apply preserves
the new cycle; repeating --relearn explicitly requests another cycle. The default
healthy day limits new admissions; completed-empty baselines never create filtering.

The helper only enables learning, disables shadow and raises generation above
config/checkpoint values, preserving duration and event scope. It briefly stops
the entire Agent; Linux exec and enabled file_op streams sharing that generation
both relearn. It preserves audit policy, other module configuration, device
identity/keys, authorization, update policy and Logtail/Filebeat.

## Backup, Acceptance and Failure

Version, service paths and update transactions are checked before mutation. After
stopping, the complete learning tree (file baseline, journals, key) and collector
config are saved under `<install-root>/data/recovery/learning-*`. An atomic config
write requests native state creation; HMAC state is not edited, locks are not
deleted and entries are not invented. Unknown/invalid learning states are refused;
finish pending updates first. A local lock serializes helpers. Backups reject links
and special files, limit traversal to 10000 entries/512 MiB and require disk
headroom. Inspection may create a private mutex file.

Startup waits up to 180 seconds (--health-timeout, 30–600) for a new generation,
fresh native doctor learning observation, accrued healthy time and an active
service, returning status=relearning. This does not claim filtering is active:
five-hit admission is still required; the next heartbeat updates the Workspace.
Inspection returns checked; preserved states return skipped with a reason. Use
`secweaver-agent doctor --verbose` to inspect progress and source problems.

Normal failures restore config and the complete learning tree, then restart the
original service; failed new state is retained in the backup. Concurrent changes
or updates prevent overwriting their state and require manual recovery with the
reported backup. Forced termination/power loss also requires that backup. Do not
restore device identity or copy another host's baseline.
Failed command output stays in a local mode-0600 secweaver-learning-error-*.log;
results expose only its path, avoiding credential/config disclosure in terminals.

Validation: make recovery-test performs real temporary-filesystem transactions
for backup, rollback, repeated execution, delayed startup and baseline preservation;
service/doctor boundaries are isolated. go test . ./pkg/behaviorlearning verifies
native policy/generation behavior. Real Linux recovery needs its own host
acceptance; source verification does not mean deployment.

## Relearn only an empty file baseline (0.3.93+)

Install and verify the file-assembly fix first: file_op paths/commands must be
complete with reliable attribution. Requirements remain Linux/systemd, root,
Python 3.6+ and the standard installation layout.

```bash
sudo python3 ./restart-behavior-learning.py --scope file
sudo python3 ./restart-behavior-learning.py --scope file --apply
```

Use only when an empty file baseline needs recovery. Learning must already be
enabled with shadow=false. Nonempty file baselines are always preserved; an empty
healthy learning cycle is skipped unless --relearn explicitly restarts it.
Only behavior_learning.file_generation increases; generation, enabled and shadow
are unchanged. Exec entries/candidates/progress are retained. File effective
generation is max(generation, file_generation); omission preserves old configs.
A later whole-policy restart must raise generation above file_generation. The
helper rejects binaries older than 0.3.93, which cannot parse the new field.

The whole Agent still stops briefly. The helper backs up the complete learning
tree/config, validates the new file generation and healthy progress, and restores
the whole backup on failure. Verify new file candidates/admission after five
unique source events, suppression counts, and retained exec baseline_id/entries.
Neither upgrading nor this command guarantees immediate filtering; absent valid
file samples, the new baseline can remain empty.

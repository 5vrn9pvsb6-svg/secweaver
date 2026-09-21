# SecWeaver Agent Linux eBPF/Audit Design and Review Guide

**Languages:** English (this page) | [简体中文](28-secweaver-agent-audit-design.zh-CN.md)

> **Status: historical implementation review, based on the 2026-08-01 workspace.**
> This English companion consolidates the implementation details and review findings from the Chinese guide.
> Findings and TODOs describe that evaluation period, not verified defects in the current release.
> Use the [Agent manual](../../src/tools/secweaver-agent/README.md),
> [metrics and diagnostics](../../src/tools/secweaver-agent/docs/metrics-and-hot-reload.md), and current code
> for operational behavior. This document is a design/review reference, not an installation guide.

**Reading by task:** Jump to the relevant section; reading every section in order is optional.

- [2. Scope and Source Map](#2-scope-and-source-map)
- [5. Defaults and Their Meaning](#5-defaults-and-their-meaning)
- [15. Historical Findings and Verification Candidates](#15-historical-findings-and-verification-candidates)
- [17. Operator Review Checklist](#17-operator-review-checklist)

## 1. Design Summary

Linux monitoring has four cooperating parts:

1. eBPF tracks listener ownership through a kernel PID map and fixed fork/exec/exit CO-RE hooks; it does not generate dynamic exec/clone audit rules.
2. `auto` falls back to bounded audit when eBPF capability checks or loading fail. Explicit `ebpf` fails startup instead of silently falling back.
3. The parent shares one audit-file reader between compatible modules and routes auxiliary connect/file/sensitive records by audit key and ID.
4. `host-persistence` derives file changes from polling and diffs; audit supplies actor context only.

The eBPF backend lives in `pkg/processtracker/ebpf`, with the backend-neutral `processtracker.Tracker`
interface separating it from `pkg/auditportexecmon`. Only owned lifecycle events reach userspace.
Threads with the same TGID do not create separate ownership entries. Leader exit removes the TGID;
periodic `/proc` reconciliation repairs surviving-process state after startup races or lost events.
The default PID-map limit is 131072 and perf storage is 256 KiB **per CPU**. Arguments are bounded
and truncation is explicit.

Bounded audit uses fixed grouped exec/clone rules per architecture, filters unrelated records before
accumulation, and validates process start times against PID reuse. Rule groups are transactional;
failed rollback remains tracked and consumes budget. Normal exit, failed startup, and systemd
`ExecStopPost` provide cleanup layers. Both direct and shared readers handle inode rotation.

Exec metadata is collected at syscall entry and emitted after successful execution. Userspace enriches
AUID, TTY, and CWD from `/proc` when possible. Short-lived processes may lack these fields. The review
snapshot uses Agent receive time and `ebpf:<ktime_ns>:<pid>` audit IDs; missing session fields are unknown,
not evidence for or against WebShell/RCE.

## 2. Scope and Source Map

Paths below are relative to `src/tools/secweaver-agent/`.

| Responsibility | Code |
|---|---|
| Shared reading, routes, pipes, backlog | [audit_demux.go](../../src/tools/secweaver-agent/audit_demux.go) |
| File offsets, rotation, inherited descriptors | [pkg/auditstream/auditstream.go](../../src/tools/secweaver-agent/pkg/auditstream/auditstream.go) |
| audit-port lifecycle | [pkg/auditportexecmon/main.go](../../src/tools/secweaver-agent/pkg/auditportexecmon/main.go) |
| Backend-neutral process ownership | [pkg/processtracker/tracker.go](../../src/tools/secweaver-agent/pkg/processtracker/tracker.go) |
| CO-RE hooks and perf reader | [pkg/processtracker/ebpf](../../src/tools/secweaver-agent/pkg/processtracker/ebpf) |
| Listener discovery | `pkg/auditportexecmon/listeners.go`, `companion.go` |
| State, reconciliation, PID rules | `monitor_state.go`, `monitor_worker.go`, `monitor_pid_rules.go` in `pkg/auditportexecmon/` |
| Rule transactions | `pkg/auditportexecmon/audit_rules.go` |
| Pressure and recovery | `pkg/auditportexecmon/audit_pressure.go`, `audit_pressure_state.go` |
| Audit aggregation and output | `pkg/auditportexecmon/audit_follow.go`, `audit_event.go`, `audit_parse.go` |
| Persistence actor enrichment | `pkg/hostpersistence/audit_rules.go`, `audit_follow.go`, `audit_event.go`, `audit_tracker.go` |
| Final cleanup | [audit_cleanup.go](../../src/tools/secweaver-agent/audit_cleanup.go) |

Windows uses Event Log/Sysmon separately. `syslog-risk-json` may parse audit/SELinux text but does not
manage audit rules. Auxiliary audit evidence and persistence enrichment require readable
`/var/log/audit/audit.log`; journald/netlink are not substitutes in this path. SecWeaver manages its own
rules, not the host's entire audit policy.

## 3. Process and Data Flow

Listener roots seed the eBPF ownership map. Owned lifecycle events pass through the perf reader to
audit-port attribution and JSONL output. Auxiliary audit records flow through kernel audit → auditd →
audit.log → shared parent demux or a direct module reader. Persistence combines a path-indexed audit
actor cache with polling diffs.

Sharing requires at least two modules with the same audit-file path and `from_start` setting; a lone
module reads directly. Demux handles transport/routing, not business interpretation. Log consumption
and auditctl rule changes run in separate goroutines so rule work does not block evidence reading.

## 4. Startup Ordering

`auditportexecmon.Main` follows this sequence:

1. Check Linux, root privileges, audit directory, and `auditctl -s`.
2. Load/default/validate configuration before rule side effects.
3. Discover external TCP listeners using netstat and conditional procfs fallback.
4. Exclude the Agent process family and its own listener ports.
5. Probe BTF/tracepoints and select/load the backend; record `auto` fallback reasons.
6. Generate exec/connect/file/sensitive/clone keys and estimate rule cost.
7. In dry-run mode, probe without eBPF attachment or audit rule changes.
8. Remove leftover SecWeaver syscall rules.
9. Acquire the shared descriptor or capture the direct reader's initial EOF offset.
10. Seed listener, descendant, and companion ownership. Bounded audit installs fixed rules transactionally; only explicit `audit_pid` installs dynamic PID/PPID rules.
11. Start reconciliation; start pressure monitoring only for dynamic audit rules.
12. Consume lifecycle and auxiliary evidence concurrently.
13. On signal or reader failure, stop rule work and clean rules before closing eBPF links/maps.

Capturing the initial cursor before rule installation preserves new events written during startup.

## 5. Defaults and Their Meaning

| Setting | Default | Meaning |
|---|---|---|
| `audit.arches` | `b64` | `b32` is explicit and doubles grouped rule cost |
| `audit.max_rules` | `1024` | Module ledger plus watches and reservations, not a host-wide cap |
| `exec.monitor` | `true` | Observe selected listeners' execve/execveat |
| `exec.process_tree_backend` | `auto` | Prefer eBPF, otherwise audit |
| `exec.fallback_backend` | `audit` | Bounded audit; `audit_pid` is explicit compatibility mode |
| `exec.ebpf.max_tracked_processes` | `131072` | Tracked-PID map capacity |
| `exec.ebpf.perf_buffer_bytes_per_cpu` | `262144` | Per-CPU perf storage |
| `exec.track_descendants` | `true` | Kernel inheritance or bounded-audit userspace inheritance |
| `exec.java_monitor_mode` | `hybrid` | Executable rules plus PID-tree coverage where applicable |
| `connect.monitor` / `file_ops.monitor` | `false` | Avoid dynamic/high-volume auxiliary rules by default |
| `sensitive_file_reads.monitor` | `true` | `/etc/shadow` read watch, filtered by ownership on output |
| `listener_rescan_seconds` | `300` | Reconciliation requests coalesced by one worker |
| `audit.pressure.enabled` | `true` | Four-level pressure state machine |
| Pressure sample | `30s` | Dynamic rules only; bounded audit does not sample |
| Backlog thresholds | `80/90/95%` | Light/medium/severe |
| Lost-event deltas | `1/5/20` | Increases between samples |
| Cooldown | `120s` | Delays pressure reduction to prevent oscillation |
| Rule rates | `10/5/5` per second | Light, medium/severe, recovery |

See [the configuration example](../../src/tools/secweaver-agent/audit-port-execmon.example.json).

## 6. Listener Discovery and Monitoring Modes

`netstat -tlnp` has a five-second timeout. The parser locates case-insensitive `LISTEN`, parses the
preceding address, and searches subsequent columns for PID/program instead of assuming column widths.
It handles net-tools/BusyBox address formats, absent PIDs, extra columns, and process labels containing
spaces. It counts accepted/rejected LISTEN lines; rejected lines trigger diagnostics and procfs completion.

`/proc/net/tcp*` inode-to-FD lookup runs only when netstat fails, yields no listeners, omits relevant PIDs,
or rejects lines. FD scanning uses batches of 128, pauses 1 ms between batches, and caps one round at
32768 FDs. Exhaustion is diagnosed and deferred to the next five-minute reconciliation; unresolved
sockets do not each trigger another full process scan. Only non-loopback TCP listeners survive the
port filter/allowlist. Systemd/init socket ownership is resolved by inode where possible, with an SSH
port-22 fallback.

Modes are eBPF ownership trees, bounded fixed-rule audit, explicit growing `audit_pid` compatibility,
and companion roots such as php-fpm/uwsgi/gunicorn/puma/unicorn attributed to a gateway. Agent exclusion
applies during discovery and event handling; bounded audit avoids repeated parent-chain scans for
unrelated host events.

## 7. Audit Rule Model

Keys are `tb_external_listener_exec`, `_clone`, `_connect`, `_file`, `_sensitive`, plus
`tb_host_persistence`. A single-port invocation uses `tb_port_N_*`.

Bounded audit groups syscalls into one rule per architecture/capability without PID filters. Explicit
`audit_pid` adds separate PID and PPID filters. Unknown syscalls are identified from errors, cached by
`arch:syscall`, removed from the group, and retried as a group.

For `A` architectures, bounded exec + clone costs `2A`, plus one sensitive watch: three rules at the
b64 default. Connect and file add `2A`, giving five total. PID compatibility costs `4A` per process for
exec+clone, or `8A` with connect+file. Each sensitive path adds a watch.

`audit.max_rules` excludes host-persistence watches, other products' rules, and unknown kernel leftovers.
Fixed rules bound rule count, not audit traffic: whole-host matching syscall records still reach auditd.

## 8. Transactions, Ledger, and Cleanup

Under `processTreeMonitor.mu`, reserve a logical group's capacity before installation. Release the lock
before auditctl calls. On partial failure, delete installed members in reverse order; failed deletions
remain in the ledger and occupy capacity until reconciliation succeeds. Bootstrap wraps all initial
listener/watch groups in a larger session cleanup boundary. Auditctl defaults to a three-second timeout.

The ledger tracks installed/watched rules, monitored PIDs, `/proc` start times, pending expansion/deletion,
and reserved capacity. Dead-PID cleanup removes only confirmed deletions from the ledger. Session exit
tries key-based deletion, then exact listed-rule deletion as fallback. Startup removes current keys and
legacy `tb_` syscall rules. systemd `ExecStopPost` runs `audit-cleanup -quiet`; `--strict` provides nonzero
failure status for uninstall verification.

## 9. Process-Tree Expansion

The eBPF hooks include sched fork/exec/exit and paired execve entry/exit, plus optional paired execveat
entry/exit. Startup seeds existing roots/descendants through `Track`. Fork inherits an eligible parent's
owner; syscall entry saves bounded arguments; successful sched exec emits them; failed syscall exit
clears pending arguments. Thread exit does not remove the leader's ownership.

Perf loss increments counters, warns, and requests reconciliation. Kernel map inheritance survives
perf delivery loss, but userspace evidence from that interval may still be missing. `has_tty` is true
or false only when procfs establishes the value; otherwise omit it. Readable standard FDs can supply a
TTY name, and loginuid/CWD supply enrichment.

Bounded audit uses successful clone syscall `exit` as the child PID. If starttime cannot be read,
provisional ownership lasts five seconds and requires a matching parent. Unowned SYSCALL records are
dropped before aggregation, and their no-key auxiliary records are skipped by audit ID. Known PIDs
are checked for starttime changes. Reconciliation repairs surviving ownership every five minutes.

High-churn hosts must monitor audit backlog/lost, demux backlog, and CPU. Prefer repairing eBPF/BTF
support when fixed-rule audit traffic is excessive. Explicit PID mode retains the 4096-job queue,
three-stage starttime checks, and pressure/recovery controls for bounded-size compatibility deployments.

## 10. Shared Reader and Demux

Modules sharing `(audit_log, from_start)` receive a pipe as FD 3 through `ExtraFiles` and
`SECWEAVER_AGENT_AUDIT_STREAM_FD=3`; they do not reopen audit.log.

Keyed records establish `audit ID -> modules`; following no-key EXECVE/CWD/PATH/PROCTITLE records use
that route. Unrouted records are dropped. Routes expire after 30 seconds. This assumes the keyed
SYSCALL precedes its auxiliary records.

| Resource | Bound | Behavior |
|---|---|---|
| Live queue per module | 8192 lines | Retire subscriber and backlog undelivered data |
| Backlog ring per module | 4096 lines | Overwrite oldest data |
| Pipe buffer / flush | 64 KiB / 250 ms | Batch writes; adds transport delay |
| Reader retry | 200 ms to 5 s | Exponential retry until parent cancellation |

Subscription moves backlog into the new queue under the demux lock before publishing the subscriber,
so live data cannot overtake replay. Failed flush returns unconfirmed buffered data to backlog;
duplicate delivery is possible and downstream deduplication should use `audit_id`.

## 11. Multi-Record Parsing and Rotation

Keyed records create audit-ID accumulators. SYSCALL supplies identity/status/address, EXECVE supplies
arguments, PROCTITLE supplies preferred NUL-separated argv, and CWD/PATH supply directories/files.
Direct-reader EOF polling is 100 ms, parent file-follow polling 200 ms, and pipe reads block. Flush
runs every 100 ms with a 150 ms exec settle delay. Incomplete accumulators last at most ten seconds;
unusable main records are normally discarded after five.

Output excludes Agent-family activity, SecWeaver rule-maintenance commands, non-IP/loopback connects,
unowned sensitive reads, and expired exec records without commands. Ordinary administrator auditctl
queries can remain. Output contains audit ID, process/user identity, command, listener attribution,
and relevant network/file fields, with tri-state TTY semantics.

Readers use `os.SameFile` to detect rotation. Initial reads honor the captured offset; a replacement
inode starts at byte zero. Temporary stat failures retain the old descriptor.

## 12. Pressure and Recovery

| Level | Trigger | New dynamic work |
|---|---|---|
| Normal | Below thresholds | Configured expansion and rescans |
| Light | Backlog >=80% or lost delta >=1 | Pause expansion rescans; retain exec/clone, suppress new connect/file; 10 jobs/s |
| Medium | Backlog >=90% or lost delta >=5 | Exec allowed; clone only for critical Web/SSH roots; 5 jobs/s |
| Severe | Backlog >=95% or lost delta >=20 | Defer noncritical PIDs; critical clone only; 5 jobs/s |

Pressure does not delete existing rules or delay correctness work such as dead-PID cleanup and PID-reuse
replacement. Increases apply immediately; decreases wait for cooldown. Recovery rediscovers live
descendants and restores deferred/suppressed work using PID+starttime, feeding one job at a time at
5/s. A full rule budget blocks recovery until deletion frees capacity. Deferred storage caps at 8192 PIDs.

## 13. Persistence Actor Enrichment

Polling/diffs establish created/modified/deleted state, hashes, and content changes. Audit supplies
actor evidence. With `fail_on_error=false`, unavailable audit permits polling-only operation; a reader
that fails after successful startup exits the module so supervision can reconnect it.

Linux defaults enable audit, manage rules, and follow `/var/log/audit/audit.log`, using
`tb_host_persistence`, permission `wa`, `from_start=false`, and `fail_on_error=false`. Startup removes
old keyed watches and watches existing concrete paths. Each scan requests watch refresh for newly
appearing paths; kernel rule reconciliation is limited to once per minute.

The actor cache maps cleaned paths to at most 20 changes, retains ten minutes, and caps at 4096 paths
with oldest-active-path eviction. Global pruning is at most once per minute; touched paths are filtered
on each write. Polling chooses the nearest-time candidate within ten minutes and adds user/UID/AUID,
PID/PPID, process/executable/command, audit ID/syscall, and `actor_source=auditd`. This is approximate
path/time matching, not a one-to-one transaction linking an actor to every byte of a diff.

## 14. Concurrency and Failure Ownership

`auditDemux.mu` owns routes/subscribers/backlogs; it is not held during pipe writes or external callbacks.
One writer goroutine owns each subscriber pipe. `processTreeMonitor.mu` owns the rule ledger/queue state;
auditctl executes outside that lock. One dynamic rule worker serializes audit-port work, while
host-persistence watch reconciliation, pressure sampling, and systemd cleanup may invoke auditctl
concurrently. Hot counters are atomic; `auditTracker.mu` protects persistence actor lookup/write.

Capability/verifier failure falls back only in `auto`; failed eBPF loading closes partial resources.
Runtime perf-reader failure restarts the module. Userspace Track failure on map capacity restarts it;
failed kernel fork-map insertion can omit that subtree. Audit rule timeout/install failure rolls back;
delete failure retains ledger ownership for retry. Full dynamic queues do not block readers. Direct
reader failure restarts the module; parent demux failure retries while children remain running.
Subscriber retirement expects EOF and resubscription. Graceful signals stop work then clean rules;
SIGKILL/power loss relies on systemd or next-start cleanup.

## 15. Historical Findings and Verification Candidates

These are the 2026-08-01 review classifications, **not freshly validated current defects**. In particular,
current metrics documentation describes backlog-overwrite counters and reader-failure diagnostics;
A-09/A-13 must not be reused as current absence claims.

| ID | Historical finding/status | Review or verification action |
|---|---|---|
| A-01 | Default bounded-audit path fixed from 0.3.10; explicit hybrid PID compatibility retains its risk model | Restart nginx/Java; check stable fixed-rule count and new-worker attribution. Original hybrid executable identity could hide a changed PID and skip clone-rule reseeding. |
| A-02 | High; reconnect could seek to current EOF after prior delivery and skip records | Preserve inode/offset; inject read failure while appending records and verify no gap. |
| A-03 | High; output write/flush errors could be ignored | Propagate writer failures, report degraded state, and inject ENOSPC/EIO/read-only failures. |
| A-04 | High; processing time used instead of original audit event time | Preserve event and ingest time separately; check delayed/replayed data. |
| A-05 | High; companion PID targets lacked starttime binding; impact needed reproduction | Bind PID+starttime and independently prune unmonitored targets; test reuse under pressure/budget limits. |
| A-06 | Medium; disabling descendant tracking also skipped listener rescans | Separate listener and descendant reconciliation; test newly opened/restarted listeners. |
| A-07 | Medium; module rule cap is not a host-wide cap | Observe total rules and consider system thresholds, including persistence/third-party watches. |
| A-08 | Medium; retired subscriber writer could block draining to a non-reading pipe | Test a real non-reading child and cancellable/timed retirement. |
| A-09 | Medium; historical gaps in backlog-overwrite and actor-cache-eviction visibility | Check current counters before concluding loss is unobservable; actor eviction remains a separate check. |
| A-10 | Medium; nearest actor can misattribute a diff after multiple writes | Expose match distance/ambiguity rather than claim exact attribution. |
| A-11 | Medium; syscall-number file-action mapping depended on architecture | Validate x86_64/arm64 mappings or use architecture-aware names. |
| A-12 | Medium; startup treats `tb_` syscall keys as reserved | Document the namespace or narrow cleanup; do not use conflicting custom keys. |
| A-13 | Medium; parent retry left children alive during reader failure; historical diagnostics gap | Use current reader state/status/metrics; process liveness alone does not prove evidence delivery. |

## 16. Test Coverage and Remaining Acceptance

The review recorded component coverage for initial offsets/rotation, demux routing/rings/retirement/retry,
grouped syscalls and unsupported-syscall caching, rollback/watch cleanup, PID reuse/deletion retry,
clone propagation/queues/budgets, pressure classification/cooldown/recovery, Agent self-exclusion,
and persistence enrichment/cache bounds.

Integration acceptance should exercise service PID replacement, reader reconnect during writes,
non-reading child pipes, failed output writes, companion reuse under severe pressure, cross-architecture
file-action semantics, and real audit userspace compatibility for keyed deletion/grouped syscalls/clone3.
Unit coverage does not substitute for these host-level checks.

## 17. Operator Review Checklist

On an authorized test host, inspect `auditctl -s`, total and SecWeaver rule counts from `auditctl -l`,
Agent processes, and `secweaver-agent doctor -config /opt/secweaver-agent/etc/config.json`. Group rules
by key and compare module budget to system totals. Observe backlog/lost, queue-full/rule-limit/recovery
statistics, listener ownership after restart, and evidence freshness under known activity.

In a controlled stop test, stop the Agent and confirm its owned rules were removed. Stopping production
collection is a separate operational decision. Current [metrics](../../src/tools/secweaver-agent/docs/metrics-and-hot-reload.md)
and [health logs](../../src/tools/secweaver-agent/docs/operations-health-report.md) are the operational references.

## 18. Code Reading Order

Read audit-port `doc.go` and `main.go`, then listener/companion discovery, audit rule transactions,
monitor state/worker/PID rules, pressure state, parent demux/file following, event parsing/output,
persistence watch/cache enrichment, and finally `audit_cleanup.go` plus the systemd service.
The source map above identifies the relevant files.

## 19. Review Priorities

Historically, A-01–A-04 came first for coverage, loss, output, and time correctness; A-05/A-06/A-08
followed for ownership/recovery, then A-07/A-09/A-13 for budgets/visibility, and A-10/A-11/A-12 for
attribution, architecture semantics, and namespace boundaries. Revalidate each item's current status
before scheduling work; an old review is not a release-blocker list.

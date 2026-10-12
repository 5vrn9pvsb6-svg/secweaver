# Linux Process Attribution and Short-Lived Evidence

**Languages:** English (this page) | [简体中文](process-attribution.zh-CN.md)

Agent 0.3.96 separates historical event attribution from current process liveness, retaining the Linux output gate and instance isolation introduced through 0.3.95. A reliably admitted event no longer loses `listener_process` merely because processes exit during assembly. Unproven events still drop before original output, learning and upload. This applies to `audit`, `audit_pid`, eBPF exec and auxiliary audit output, including learning-disabled, raw-detail and final-flush paths. Windows collection is unchanged.

The gate applies to the Agent's listener-event log/stdout and its downstream upload. It does not change the operating system's `/var/log/audit/audit.log`, process/host-state/persistence collectors, or other upload sources. Dropped details are not copied to another diagnostic log, and do not enter learning counters or summaries. Previously written local backlog can still upload after an upgrade; verify events generated after the new collector starts. No automatic historical deletion is performed.

## Meaning of service attribution

`listener_process` / `listener_pid` describe verified listener context, not necessarily the event process's direct parent. `ppid` still describes that parent. Automatic Web backend association requires verified descent. Process names, backend keywords in arguments, executable equality and a shared host do not establish ownership.

For example:

```text
containerd-shim
├── mysqld
└── runc
```

MySQL ownership flows only to confirmed descendants. It cannot promote its parent shim into its own process tree. Here runc is a sibling; targeting the MySQL container does not prove mysqld initiated the call. The process name runc does not establish trust or normal activity. This fix adds neither container-task identification nor runc aggregation/filtering.

## Listener discovery and instance isolation

Discovery first uses `netstat -tlnp`. Command failure, missing PIDs or incomplete parsing trigger `/proc/net/tcp{,6}` plus `/proc/<pid>/fd` socket-inode lookup. The inode is the tenth whitespace-separated TCP field, not a column counted backwards from the end. An unresolved socket is not guessed to belong to sshd merely because its port is 22 or its reported name is systemd/init.

- Each listener PID has an independent root identity. Shared Java/Nginx executables or bind addresses do not merge distinct PIDs. Bootstrap starts at the actual socket owner and expands downward, without seeding all processes running the same executable into one service.
- Executable rules remain a collection optimization, but their hits are only candidates. Both `audit_pid` and auxiliary eBPF audit records require real ancestry and root lifetime validation, rather than an executable's old label.
- Independent PHP-FPM, Gunicorn, Puma and other backends are no longer assigned to the first Nginx/Apache gateway. Only verified descendants inherit it; independent backends need their own discoverable listener root. Independent Unix-socket-only or loopback-only backends are not automatically included. This release adds no explicit proxy-mapping configuration.
- Discovery remains limited to filtered, non-loopback TCP LISTEN sockets in the Agent's network namespace. It does not enumerate every container namespace or equate host NAT/proxies with application roots. The default listener rescan is five minutes.
- When multiple processes share a socket FD, a discovery source may expose only one owner. Other owners are not merged merely by executable equality. Verify the actual master/worker topology; arbitrary shared-FD topologies are not guaranteed complete coverage.

## Event snapshots, active tracking and historical evidence

```mermaid
flowchart TD
    A[Receive source event] --> B{Sufficient attribution evidence}
    B -->|Yes| C[Capture event-specific listener snapshot]
    B -->|No| D{Bounded historical recovery valid}
    D -->|Yes| C
    D -->|No| E[Reject business output and count reason]
    C --> F[Assemble arguments and context]
    F --> G[Learning and output]
    H[Current process and root validation] --> I[Install or remove active rules]
    H --> J[Update verified instance history]
    J --> D
```

- **Audit snapshots:** both real readers capture the listener instance and full source transaction at SYSCALL admission, binding PID, PPID, exe, key and syscall. EXECVE/PATH/PROCTITLE add context without resolving today's PID again. Exit, restart or PID reuse during assembly cannot transfer that event to a replacement. Snapshots are trusted in-memory objects; an `attribution_accepted` string in log text is not a snapshot. A conflicting primary rejects the transaction; tails with another timestamp cannot mix into the same serial.
- **Active tracking:** PID, root start time and real ancestry remain validated using uncached `/proc` reads, including before/after rule installation. Historical owners are output-only: they cannot seed descendants or install old rules for a current PID. No uploaded fields or server protocols change.
- **Reparenting:** when the child's PID and start time still identify the same process, a PPID change updates topology without discarding its service origin. A changed or unverifiable child instance is not inferred from the parent change.
- **Transient reads:** fresh proof of the original child/root lifetimes, or captured eBPF root-generation evidence, can recover subsequent events. An already rejected audit transaction is not relabeled by a later recovery; its initial proof was insufficient.

## Bounded history and limits

| Evidence | Recovery conditions | Capacity and expiry |
| --- | --- | --- |
| eBPF root history | Exact captured root PID/start token previously verified by this collector; source time inside that root's collection interval | At most 4,096 root instances; retired history remains eligible for 30s, and event age on the monotonic clock must also be at most 30s |
| Audit process history | Matching parent and source time inside a positively verified interval for the same process; a currently readable PID must retain its start time | At most 16,384 records; expire 30s after the last positive observation; PID/parent/root changes replace or invalidate records |
| Existing short fork proof | Successful clone/fork, matching parent, valid root and original source/receipt checks | Existing 5s window and 16,384-proof limit remain; replayed clones and ordinary exec cannot renew unknown instances |

History is memory-only and local to this collector lifetime, with no database or reuse across restarts. Capacity evicts the oldest record; unavailable evidence causes rejection instead of an unbounded cache or guessed name. Expired records are removed on lookup or periodic cleanup. Snapshots are released with existing assembly transactions (the current expiry window is 10s), without a separate long-lived global event map; cache eviction does not revoke an already captured snapshot.

eBPF compares `CLOCK_MONOTONIC` with kernel event timestamps, never with the opaque `RootStartTime` token. An observed root exit tightens the upper bound to its source time; otherwise, the first observed unreadability or removal from the listener inventory supplies the bound. A readable zombie cannot reactivate an explicitly exited root. Fresh discovery of a process that stops and later resumes listening starts a new interval; recovery never bridges the unmonitored gap, and older events without snapshots may be rejected.

**Audit has no eBPF-style captured process-generation token.** Delayed events inside a positively verified lifetime can survive a process living longer than five seconds. If an event occurs after the last positive observation and both process and parent have exited, a remembered PID alone cannot extend proof. Without a snapshot, valid interval or original short fork proof, it still drops. This avoids reintroducing runc/PID-reuse misattribution and cannot reconstruct all lost kernel events.

History does not automatically expand collection to new events after root retirement. Proven historical events are retained while active rules are cleaned up independently. Shared containers, executable equality, audit keys and sensitive-path watch hits do not prove inheritance. Non-bounded ancestry walks still cap each starting chain at 64 nodes and detect cycles.

## Diagnostic counters

Module stderr emits a changed `listener attribution stats:` aggregate at most once per 30s, plus a final shutdown aggregate. Use the existing module-stderr collection path; this adds no uploadable business log or management-page field.

- `snapshot_saved` / `snapshot_used`: verified snapshots at admission and output.
- `root_history_used` / `process_history_used`: source-time historical recovery.
- `reparented` / `identity_recovered`: same-instance reparenting and recovery.
- `identity_conflict`, `root_unavailable`: instance conflict or unverifiable current root.
- `history_missing`, `history_expired`, `history_evicted`, `history_time_rejected`: missing, expired, capacity-evicted or temporally invalid history.
- `transaction_conflict`, `audit_rejected`, `ebpf_rejected`, `outside_scope`: conflicting transactions, admission/output rejection or out-of-scope candidates.

These count decisions, not deduplicated events; do not sum them into a loss rate. They contain no commands, credentials or rejected event details. Compare learning suppression, kernel lost samples, audit backlog and output volume; zero empty labels does not prove zero missed events.

## Upgrade and canary verification

Upgrade with a new versioned package; never republish changed bytes under an earlier version. A normal upgrade rebuilds in-memory ownership and rules without automatically clearing learning baselines or rewriting previously uploaded logs. 0.3.96 retains more verified historical events without resetting learning state. Missing or incorrect labels in historical events are not rewritten. Check whether previous misattribution affected learning baselines; normal upgrades do not clear them automatically.

Canary on one Linux container host and record the actual backend, version, process start times and before/after windows. Existing `/proc` visibility and audit/eBPF privileges are required. The fix does not require additional Docker management API access.

Verify:

1. Compare simultaneous service-root, runtime-parent and sibling process identities; siblings must no longer inherit Java/MySQL labels.
2. Use an isolated test service to check real children and later generations, including short-lived processes, service restarts and PID reuse.
3. Confirm events without a confirmed listener are absent from original output and the upload stream, while unrelated host traffic remains filtered.
4. Check two independent services sharing one executable, IPv4/IPv6 discovery without netstat, and root PID reuse with delayed events. Commands such as pgrep queries must not become associated backends.
5. Exercise exit during assembly, reparenting, root exit arriving before a delayed exec, same-instance read recovery, capacity/expiry, and rejection outside proven source-time intervals.
6. Compare CPU, memory, output volume, latency and lost/backlog. Output reduction now includes rejected unknown attribution as well as learning suppression; learning counters only cover events admitted to that engine.

Run `make check` from the Agent directory, or `go test -race ./pkg/auditportexecmon` for attribution and `go test ./pkg/processtracker/ebpf` for the embedded-object contract. Linux additionally checks generated Go layouts and event decoding; other developer platforms only parse the object and cannot validate kernel attachment or verifier acceptance. These tests combine synthetic process lifetimes with real event assembly/output; they do not replace audit/eBPF attachment and canary verification on the target Linux host.

If rollback is required, use the existing upgrade recovery workflow to restore the previous complete release and rebuild tracking. Versions 0.3.92/0.3.93 can emit unknown events again; rollback does not retain this output gate. The gate deliberately omits even real service events when their listener identity cannot be established. Rolling back to 0.3.95 restores assembly/historical attribution loss; 0.3.94 also restores listener-identification defects. Upgrade the complete Agent package and restart the collector. 0.3.96 retains the 0.3.95 eBPF object and event layout without regeneration. Internal maps and history are not reused across restarts.

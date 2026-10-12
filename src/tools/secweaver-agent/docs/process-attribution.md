# Linux Process Attribution and Short-Lived Evidence

**Languages:** English (this page) | [简体中文](process-attribution.zh-CN.md)

Agent 0.3.95 requires a confirmed, nonblank `listener_process` before a Linux listener-scoped exec, connect, or file event is serialized. Events whose root identity cannot be verified are dropped before original output, learning, and upload; their internal unknown state is retained only for lifecycle cleanup. This applies to `audit`, `audit_pid`, and eBPF exec/auxiliary audit output, including raw-detail mode, learning disabled/shadow, queue fallback, and final file-event flush. Building on 0.3.94's output gate, this release fixes listener discovery, instance mixing, broad attribution fallbacks and lost short-lived evidence, and carries root generations through eBPF. Windows collection is unchanged.

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

## Identity checks and uncertainty

- Ownership caches validate PID and process start time. Cached owners and asynchronous jobs also bind the service root's start time. Identity gates read `/proc` directly, bypassing enrichment caches.
- PID, parent, ancestor and verified descendant ownership hits validate identity. Non-bounded backends walk at most 64 nodes per starting chain and detect cycles. Unrelated bounded-audit traffic does not walk ancestry.
- When a root PID is reused, known descendants of the old generation cannot regain ownership through the new parent/root cache. A primary record whose identity expires during assembly is marked unknown internally and dropped at the output boundary.
- Rule installation checks process/root identity before and after mutation. Queued work cannot restore ownership from an expired root. Invalid attribution is revoked immediately; the existing worker retains kernel-rule accounting and cleanup retries.
- An exited child can use short-term correlation only with successful clone/fork evidence, a matching parent PID, a valid root, and source/receipt timing within a five-second window. Duplicate or older clones cannot renew that window; ordinary exec records cannot renew it either. `audit` and `audit_pid` share source-proof registration, which does not mark rules as installed. Dead PIDs never receive new rules.
- Successful fork proofs are capped at 16,384 entries with a five-second window; cleanup scans at most once per window. At capacity, new historical proofs are refused rather than growing memory or installing rules for dead PIDs. Expired, missing, out-of-order or conflicting evidence may still be rejected.
- eBPF owner maps and fork/exec/exit events carry `RootStartTime`, an opaque userspace `/proc` start-time token inherited unchanged in the kernel. It is not directly comparable to nanosecond timestamps. Missing or stale generations cannot adopt today's root with the same PID, overwrite its ledger or remove its replacement. This is an internal contract and adds no uploaded JSON field.
- An unreadable identity is not a successful match. A conflicting event parent rejects stale ownership before trying a verified parent. Previously tracked but unresolved events remain internal unknown state and are dropped before serialization.
- Unknown-attribution events never reach original output or exec/file behavior learning. They cannot create an empty-service baseline entry, be filtered by an old baseline, or be uploaded. Normal verified events do not add this field.

Unrelated host-wide events are still filtered before accumulation in bounded `audit`. Sensitive-path watch hits alone never expand service scope on any backend. Unmatched `audit_pid` evidence already scoped by PID/executable rules is retained as internal unknown state and then dropped at output. Kernel-scoped eBPF exec events with an expired service root are also dropped without expanding auxiliary rules from that invalid owner.

Parent PID, timing and clone correlation remain limited by lost kernel events, reader delays and process visibility. This is not a complete historical process database. Missing forks or expired windows cannot guarantee a reconstructed call chain; inspect Agent loss/backlog metrics as well. Unknown attribution describes evidence quality, not risk severity or a confirmed attack.

## Upgrade and canary verification

Upgrade with a new versioned package; never republish changed bytes under an earlier version. A normal upgrade rebuilds in-memory ownership and rules without automatically clearing learning baselines or rewriting previously uploaded logs. 0.3.95 tightens attribution. Missing or incorrect labels in historical events are not rewritten. Check whether previous misattribution affected learning baselines; normal upgrades do not clear them automatically.

Canary on one Linux container host and record the actual backend, version, process start times and before/after windows. Existing `/proc` visibility and audit/eBPF privileges are required. The fix does not require additional Docker management API access.

Verify:

1. Compare simultaneous service-root, runtime-parent and sibling process identities; siblings must no longer inherit Java/MySQL labels.
2. Use an isolated test service to check real children and later generations, including short-lived processes, service restarts and PID reuse.
3. Confirm events without a confirmed listener are absent from original output and the upload stream, while unrelated host traffic remains filtered.
4. Check two independent services sharing one executable, IPv4/IPv6 discovery without netstat, and root PID reuse with delayed events. Commands such as pgrep queries must not become associated backends.
5. Compare CPU, memory, output volume, latency and lost/backlog. Output reduction now includes rejected unknown attribution as well as learning suppression; learning counters only cover events admitted to that engine.

Run `make check` from the Agent directory, or `go test -race ./pkg/auditportexecmon` for attribution and `go test ./pkg/processtracker/ebpf` for the embedded-object contract. Linux additionally checks generated Go layouts and event decoding; other developer platforms only parse the object and cannot validate kernel attachment or verifier acceptance. These tests combine synthetic process lifetimes with real event assembly/output; they do not replace audit/eBPF attachment and canary verification on the target Linux host.

If rollback is required, use the existing upgrade recovery workflow to restore the previous complete release and rebuild tracking. Versions 0.3.92/0.3.93 can emit unknown events again; rollback does not retain this output gate. The gate deliberately omits even real service events when their listener identity cannot be established. Rolling back to 0.3.94 reintroduces the identification defects fixed here. Upgrade the complete Agent package, including the regenerated eBPF object, and restart the collector. Do not mix old objects with new decoders; internal maps are not reused across restarts.

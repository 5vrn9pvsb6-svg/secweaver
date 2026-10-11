# Linux Process Attribution and Short-Lived Evidence

**Languages:** English (this page) | [简体中文](process-attribution.zh-CN.md)

Agent 0.3.92 fixes upward ownership propagation into runtime parents, stale PID-cache hits after reuse, and attribution retained when short-lived process identities are unreadable. It covers userspace attribution for Linux `audit` and `audit_pid`, including cache lookups for auxiliary audit rules with eBPF. Kernel-scoped eBPF exec events retain unknown attribution when their service root cannot be verified. Windows collection is unchanged.

## Meaning of service attribution

`listener_process` / `listener_pid` describe verified listener context, not necessarily the event process's direct parent. `ppid` still describes that parent. Explicit Web gateway/backend associations, such as PHP, are collection policy and do not prove that the gateway process directly executed a command.

For example:

```text
containerd-shim
├── mysqld
└── runc
```

MySQL ownership flows only to confirmed descendants. It cannot promote its parent shim into its own process tree. Here runc is a sibling; targeting the MySQL container does not prove mysqld initiated the call. The process name runc does not establish trust or normal activity. This fix adds neither container-task identification nor runc aggregation/filtering.

## Identity checks and uncertainty

- Ownership caches validate PID and process start time. Cached owners and asynchronous jobs also bind the service root's start time. Identity gates read `/proc` directly, bypassing enrichment caches.
- PID, parent, ancestor and explicit companion ownership hits validate identity. Non-bounded backends walk at most 64 nodes per starting chain and detect cycles. Unrelated bounded-audit traffic does not walk ancestry.
- When a root PID is reused, known descendants of the old generation cannot regain ownership through the new parent/root cache. A primary record already accepted before its identity expires during assembly is retained as unknown.
- Rule installation checks process/root identity before and after mutation. Queued work cannot restore ownership from an expired root. Invalid attribution is revoked immediately; the existing worker retains kernel-rule accounting and cleanup retries.
- An exited child can use short-term correlation only with successful clone/fork evidence, a matching parent PID, a valid root, and source/receipt timing within a five-second window. Duplicate or older clones cannot renew that window; ordinary exec records cannot renew it either.
- An unreadable identity is not a successful match. A conflicting event parent rejects stale ownership before trying a verified parent. Previously tracked but unresolved events retain their details, omit `listener_*`, and add the optional field `attribution_status: "unknown"`.
- Unknown-attribution events go directly to original event output and bypass exec/file behavior learning. They cannot create an empty-service baseline entry or be filtered by an old baseline. Normal verified events do not add this field.

Unrelated host-wide events are still filtered before accumulation in bounded `audit`. Sensitive-path watch hits alone never expand service scope on any backend. Unmatched `audit_pid` evidence already scoped by PID/executable rules is retained as unknown. Kernel-scoped eBPF exec events retain details when the service root expires, without expanding auxiliary rules from that invalid owner.

Parent PID, timing and clone correlation remain limited by lost kernel events, reader delays and process visibility. This is not a complete historical process database. Missing forks or expired windows cannot guarantee a reconstructed call chain; inspect Agent loss/backlog metrics as well. Unknown attribution describes evidence quality, not risk severity or a confirmed attack.

## Upgrade and canary verification

Upgrade with a new versioned package; never republish changed bytes as 0.3.91. A normal upgrade rebuilds in-memory ownership and rules without automatically clearing learning baselines or rewriting previously uploaded logs. Consumers must tolerate optional `attribution_status` and missing `listener_*`. Older events lack this field; that absence does not validate their historical attribution.

Canary on one Linux container host and record the actual backend, version, process start times and before/after windows. Existing `/proc` visibility and audit/eBPF privileges are required. The fix does not require additional Docker management API access.

Verify:

1. Compare simultaneous service-root, runtime-parent and sibling process identities; siblings must no longer inherit Java/MySQL labels.
2. Use an isolated test service to check real children and later generations, including short-lived processes, service restarts and PID reuse.
3. Confirm unknown events retain commands without guessed service fields, while unrelated host traffic remains filtered.
4. Compare CPU, memory, output volume, latency and lost/backlog. More unknown details can reflect corrected attribution; it does not by itself establish an attack or collection failure.

Run `go test -race ./pkg/auditportexecmon` from the Agent directory for source regressions. These tests combine synthetic process lifetimes with real event assembly/output; they do not replace audit/eBPF attachment and canary verification on the target Linux host.

If rollback is required, use the existing upgrade recovery workflow to restore the previous complete release and rebuild tracking. That release still contains these attribution defects; interpret its events using raw PID/PPID and container evidence. Rollback does not retain the fix. Evaluate health-check frequency or first-event-plus-summary runc reduction separately after attribution is stable.

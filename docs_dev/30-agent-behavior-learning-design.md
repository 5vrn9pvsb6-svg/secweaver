# Agent Behavior Learning And Log Reduction Design

**Languages:** English (this page) | [简体中文](30-agent-behavior-learning-design.zh-CN.md)

Status: design with Linux subset in 0.3.37 and a conservative Windows Sysmon adapter in
0.3.38. Design date: 2026-09-23. Current behavior/limits: [operator guide](../src/tools/secweaver-agent/docs/behavior-learning.md).
Use the [implementation guide](../src/tools/secweaver-agent/docs/behavior-learning.md) for actual support.
The target design below includes future deep-ancestry eligibility, per-entry administration,
baseline rollback and outstanding real-platform acceptance. Its JSON examples are proposed contracts;
actual checkpoints use an HMAC envelope under the Agent data directory. No binaries are published or deployed.

## 1. Objective And Decisions

New installations enable learning by default. Automatically start learning when collection first
successfully starts after installation, without a separate administrator action. Installation alone
without starting collection does not start the timer, and learning does not wait for the next midnight.
Accumulate 24 hours of healthy observation from that start, freeze a per-device baseline,
and emit behaviors outside that baseline individually. Matching normal executions remain
observed and counted but no longer produce individual upload records.
This is an output suppression list, not an execution allowlist or proof that a host is clean.

| Decision | Proposed behavior |
|---|---|
| Learning duration | 24 healthy observation hours; downtime and known event-loss intervals do not count |
| Learning output | Full original events plus local candidate statistics |
| Initial activation | Automatically activate eligible repeated behaviors at learning completion |
| Ineligible observations | Remain candidates; observing a command once never grants suppression |
| Unknown behavior | Emit every event; never absorb it automatically during enforcement |
| Known normal behavior | Suppress originals within rate bounds; emit summaries every 5 minutes |
| Always emitted | Sensitive operations, identity anomalies, failures, incomplete or undecidable evidence |
| Failure | Resume the existing full-output path and report degradation |
| Existing installations | Require explicit opt-in on upgrade |
| New installations | enabled=true; automatically learn for 24 hours from the first collection start after installation |

## 2. Scope And Current Implementation

Implementation update 0.3.39: the Windows Sysmon adapter also learns exact qualified outbound
private-network connections and ordinary `.log` creations under configured roots, correlated
to observed Event 1 identities by GUID. Each type has independent fingerprints and summary
counts. Auth/persistence/risk, sensitive/destructive operations and snapshots remain protected;
Linux non-exec output is unchanged. The operational guide linked above defines current scope,
upgrade generation requirements and source/context gaps; broader proposals below are not claims.

Phase one covers Linux exec events in audit-port-execmon, for audit and eBPF backends.
Existing kernel probing and fallback apply. Backend changes cannot silently trust a baseline
with weaker or different context semantics. Windows 0.3.38 uses separate event-time Sysmon
GUID/SHA256/service-token semantics; Security 4688 stays full-output. Native acceptance is pending.

In the original Linux phase, file operations, sensitive reads, authentication, host_persistence,
snapshots and Agent health remain outside suppression. "Only collect unlisted behavior" refers to eligible exec
output, not disabling observation or the other collectors.

Current [audit output](../src/tools/secweaver-agent/pkg/auditportexecmon/audit_event.go)
and [eBPF output](../src/tools/secweaver-agent/pkg/auditportexecmon/ebpf_events.go)
originally serialized individual events. Source 0.3.37 adds a [learning adapter](../src/tools/secweaver-agent/pkg/auditportexecmon/learning.go)
and independent engine through behavior_learning in the [configuration](../src/tools/secweaver-agent/pkg/auditportexecmon/config.go).
Audit rule-pressure controls remain distinct from upload reduction.

The supplied one-host daily sample contains 159,668 records, including 158,242 exec records
(99.1%). Java/MySQL listener trees account for 144,223 exec records (90.3%).
Listener attribution does not identify the executed command. Inspect executable, argv, parent,
and identity before deciding eligibility; no reduction percentage is promised.

## 3. Processing And Ownership

Order: receive/assemble and exclude self-events; attribute the listener; update fork/exec/exit
tracking; build backend-neutral context; apply always-emit rules and eligibility; obtain an
emit/suppress/emit_with_context decision; write originals, ancestor evidence, summaries, and
transitions through existing rotation and disk protection.

A proposed separate pkg/behaviorlearning owns policy, fingerprint, learner, matcher, store,
and summary responsibilities. Backend adapters only translate context. Generic pkg/output
must not perform semantic suppression. Readers retain process-tree ownership; the learning
module owns baseline and counters. The decision path has no network, shell, or synchronous
disk access. The Windows adapter uses exact command strings and its own token fields, not Linux argv/UID assumptions.

## 4. Lifecycle And Time

| State | Behavior and transitions |
|---|---|
| disabled | Full output; explicit enablement starts learning |
| learning | Full output and candidates; freeze after 24 healthy hours and validation |
| enforcing | Emit unknown/anomalous events, count known normal matches |
| degraded | Full output; no new suppression grants |
| relearning | Explicit request restores full output within scope and builds a replacement |

Use monotonic elapsed time and persist accumulated duration. Restarts resume progress;
downtime does not count, and wall-clock jumps cannot finish learning early. UTC is for audit display.

Audit/eBPF lost events, reader/demux failures, and missing required context pause learning.
Known loss disqualifies that learning cycle from automatic promotion until explicit relearning
or review; waiting for recovery alone cannot certify incomplete evidence. Require 10 minutes
of stable, verifiable health before resuming timing/matching.

After 72 accumulated online hours without completion, enter degraded, stop candidate growth,
and report the reason. Preserve this budget across restarts; downtime does not count.
Separately warn after 72 wall-clock hours without progress, without forced promotion.
An empty eligible baseline keeps full output and records baseline_empty.

Normal restart reuses a compatible device/policy/fingerprint baseline. Missing, corrupt, or
wrong-device state during operation restores full output and requires explicit recovery.
A never-initialized installation automatically enters learning unless explicitly configured with
enabled=false. Restart, reinstall over existing state, and upgrade must not reset progress or the
baseline. Losing an existing baseline must not masquerade as a fresh installation.

## 5. Fingerprints And Process Instances

Use versioned deterministic encoding and local HMAC-SHA-256 over:

- Device ID, local policy revision, and fingerprint version.
- Listener root executable path/digest, address/port, and verified unit or workload identity.
- Parent executable/digest and parent execution fingerprint anchored to that service.
- Executable path/digest, exact argv array with preserved argument boundaries, and cwd.
- uid/euid, gid/egid, auid, session/TTY classification; required unknown fields prevent suppression.
- Success/exit, completeness flags, and backend context capability version.

Do not include PID, PPID, audit ID, or occurrence time in the reusable behavior key.
Keep them in original evidence and local instance context.
Instance identity is boot_id + pid + start_time plus an exec sequence for multiple execs
within one process. This prevents PID reuse and same-PID replacement from inheriting identity.

Service restarts can reuse unchanged verified identity. Unstable service/container identity
prevents cross-instance reuse. A new container ID is a new scope unless an explicit workload
mapping exists; dockerd attribution cannot merge unrelated containers.

Default matching is exact: do not automatically strip numbers, timestamps, URLs, IPs, ports,
script contents, or random arguments. Variable-argument masks require explicit versioned policy.
Compute HMAC before sample redaction to distinguish actual values; never upload the local key.
Store only fingerprints and redacted examples, not plaintext sensitive argv. Key rotation
invalidates old fingerprints and requires relearning.

### 5.1. Meaning Of One Entry

An entry covers one device, service, anchored parent execution, credential/session context,
executable version, exact argument vector and working directory. It never trusts every action
by java, mysqld, a user, or a directory. It is not an auditctl kernel allowlist: matching an entry
neither removes monitoring rules nor stops descendant tracking.

For illustration, suppose Java in example-app.service directly executes
stat -- /var/lib/example/ready every minute to inspect ordinary application file metadata.
Only verified managed binaries, complete context, no always-emit match and 24 healthy observation
hours can qualify it. This is neither a built-in stat exemption nor data from a real host.

### 5.2. Example Frozen Baseline

This readable JSON illustrates the persistence contract; the actual encoding remains undecided.
Angle-bracket strings stand for full 64-character hexadecimal digests, so the example is not loadable.

```json
{
  "schema_version": 1,
  "baseline_id": "baseline-example-001",
  "device_id": "device-example-001",
  "policy_revision": 1,
  "fingerprint_version": 1,
  "hmac_key_id": "local-key-001",
  "capability_profile": "linux-exec-context-v1",
  "learning": {
    "started_at": "2026-09-23T10:00:00+08:00",
    "completed_at": "2026-09-24T10:00:00+08:00",
    "healthy_seconds": 86400,
    "known_event_loss": false
  },
  "entries": [
    {
      "entry_id": "entry-example-001",
      "behavior_fingerprint": "<HMAC-SHA-256: complete canonical behavior>",
      "match": {
        "service_context_hmac": "<HMAC-SHA-256: verified service context>",
        "parent_context_hmac": "<HMAC-SHA-256: anchored parent execution>",
        "execution_hmac": "<HMAC-SHA-256: executable identity, exact argv, cwd>",
        "identity_hmac": "<HMAC-SHA-256: credentials and session classification>",
        "result_hmac": "<HMAC-SHA-256: exec syscall result and completeness>"
      },
      "sample_redacted": {
        "listener_process": "java",
        "service_unit": "example-app.service",
        "listener_address": "0.0.0.0",
        "listener_port": 8080,
        "parent_exe": "/opt/example/jdk/bin/java",
        "exe": "/usr/bin/stat",
        "argv": [
          "stat",
          "--",
          "/var/lib/example/ready"
        ],
        "cwd": "/var/lib/example",
        "uid": 1001,
        "euid": 1001,
        "gid": 1001,
        "egid": 1001,
        "auid_state": "unset",
        "session_class": "service_noninteractive",
        "has_tty": false
      },
      "learned": {
        "observed_count": 1440,
        "distinct_hours": 24,
        "first_seen": "2026-09-23T10:00:00+08:00",
        "last_seen": "2026-09-24T09:59:00+08:00",
        "p95_count_per_5m": 5
      },
      "promotion": {
        "origin": "automatic_learning",
        "eligible": true
      },
      "action": {
        "type": "suppress_original_with_summary",
        "rolling_window_seconds": 300,
        "max_events_per_window": 15,
        "anomaly_emit_seconds": 600,
        "idle_expiry_days": 30
      }
    }
  ]
}
```

| Field group | Meaning and ownership |
|---|---|
| Device/policy/key/capability versions | Restrict device and matching semantics; incompatibility restores originals |
| behavior_fingerprint | Exact hot-path key over every required field in section 5; no partial match |
| match.*_hmac | Grouped diagnostics for changed context; no fuzzy matching or plaintext sensitive arguments |
| sample_redacted | Human-readable sample only; editing it cannot change matching |
| learned | Immutable promotion evidence, never overwritten by enforcement counters |
| promotion | Origin and eligibility at freeze; runtime always-emit rules still take precedence |
| action | Output/rate bounds; never executes or blocks a process |

Full canonical input also contains root/parent/child executable digests, service startup arguments,
the anchored parent fingerprint and capability flags not expanded in the sample.
Compute fingerprints from actual argv/values; redacted samples cannot reconstruct them.
Use distinct domain labels for component HMACs to prevent interchange between context groups.
Known unset values differ from unknown data: explicitly observed unset auid may form a verified
service_noninteractive classification, but unavailable auid/session state cannot qualify.

Success/exit describes the exec syscall result, not the eventual child program exit code.
Successful exec does not prove application success; final exit status requires separate backend evidence.
If required euid/gid, executable identity or ancestry is unavailable today, enrich the backend first.
Never fill missing fields with zero or reuse a current PID's unrelated context to qualify suppression.

### 5.3. Matching Examples

| Next observation | Decision |
|---|---|
| Same complete stable context, only child PID/time changed | Match within rate bounds; count and summarize |
| Same Java service runs stat with another target path | Different fingerprint; emit original |
| Java executes sh -c 'stat -- /var/lib/example/ready' | Always-emit shell policy; not the direct execution above |
| Java executes curl, another transfer tool or an unknown binary | Always-emit policy or baseline miss; emit original |
| Same command originates from sshd | Different service/parent/session; emit original |
| uid changes from 1001 to 0 or privileges change | Emit original |
| stat or Java binary is replaced at the same path | Pending verification or changed digest; emit original |
| Only a date, random argument or URL token changes | Exact-match miss; do not ignore changes automatically |
| Service restarts with identical verified stable context | May match after new-instance verification; PID reuse alone grants nothing |
| argv/ancestry/identity is missing or backend capability is not equivalent | Emit and report the reason |
| Example behavior occurs for the 16th time in a rolling 5-minute window | Emit this and subsequent events during the 10-minute anomaly period |

The example limit is max(10, 3 × P95=5), not a universal limit of 15.
Always-emit and completeness checks precede baseline lookup, followed by rate enforcement.

### 5.4. Separate Candidates, Baseline And Runtime State

- candidates: bounded observations, counts, hourly buckets, times and qualification reasons such as
  repeated_eligible, insufficient_occurrences, insufficient_span, always_emit_shell or
  incomplete_identity. Reason codes are proposed.
- baseline: immutable entries that qualify at 24-hour completion. Observed but ineligible activity
  does not enter entries; repeated unknown executions cannot append entries during enforcement.
- runtime: last match, sliding counters, anomaly deadlines, summary counts and evidence cache.
  Update bounded memory/checkpoints rather than rewriting the baseline on every execution.
- manifest: active revision, progress and state markers committed atomically as in section 8.
  Keep the HMAC key separately; local digest verification is not remote policy signing.

After restart, incomplete rate state requires at least one full rolling window of original output
while counters rebuild. Restart must not immediately grant a fresh suppression allowance.
Resume outstanding anomaly periods conservatively; if remaining time is uncertain, restart the
full protection period. Missing baseline/critical state degrades rather than trusting observations.

### 5.5. Operator View And Reduction Example

Group entries by service and executed command, showing redacted arguments, identity, learning count,
time span, promotion/exclusion reasons, rate limit, last match and suppressed-original count.
Keep display fields separate from matching keys; offer no blanket Java/MySQL exemption.
Operators revoke entries, disable suppression or explicitly relearn, rather than editing samples.

This once-per-minute example retains 1,440 original exec events on the learning day and produces
at most 288 normal 5-minute summaries on a stable enforcement day, plus health, transitions and
necessary ancestor replay. This is per-behavior illustration, not a host-wide saving promise.
One match per window yields one summary instead of one original, saving no record count.
Measure actual total bytes. Shell ancestry, variable arguments or incomplete identity may prevent
qualification; never relax eligibility just to meet a desired reduction percentage.

## 6. Promotion And Always-Emit Rules

Automatic promotion requires at least 5 identical observations across 3 distinct hourly buckets
spanning at least 6 hours; successful execution; complete identity, ancestry, arguments and
attribution; verified child and parent executable identity; no always-emit match; and no known
loss or unexplained coverage gap. Revalidate eligibility, policy, and budgets at freeze and
atomically commit an immutable baseline revision.

Low-frequency, daily, or newly deployed commands remain emitted. One day cannot cover weekly
jobs; continuous automatic absorption is not a remedy. Repetition is not proof of safety:
a compromised learning host can poison its baseline. Prefer installation during normal business
operation; fresh installations still learn automatically without approval. During incident response,
explicitly disable learning and start it after recovery. Retain full learning logs and reviewable samples.

Always-emit takes precedence over automatic and manual entries:

- File/sensitive operations, authentication, persistence, and all event types outside phase one.
- Failures, privilege/identity changes, unknown identity/session, truncation, or incomplete attribution.
- Shell/interpreter command text or scripts, interactive sessions, remote-execution/download/transfer
  tools covered by conservative phase-one rules.
- Executables in temporary or writable unmanaged locations, deleted files, memfd, and unverified files.
- Matches in the local high-risk rule set; matcher failures also emit.

Names alone are not complete detection. Define path/file identity and policy versions to resist
simple renaming. Scripts/interpreters are not automatically suppressible in phase one because
identical path and argv do not prove unchanged payload. Do not assume server-side Skill engines
already run on the Agent: implement and test a small independent local always-emit policy.

Hash executables with bounded asynchronous workers and verified read-only descriptors, caching
dev/inode/size/mtime/ctime plus execution-visible identity. Emit while verification is pending or
invalidated. Controlled-file change observation plus periodic verification invalidates caches.
If the executable object cannot be bound to the verified object, emit. Metadata caching cannot
defend against a compromised root. External configuration, dynamic libraries, and network input
remain unmodeled risks; fingerprints do not represent all program semantics.

## 7. Enforcement, Rates, And Evidence

Decision order: always-emit; context completeness; file identity; exact baseline; rate envelope.
Uncertainty emits. Unknown repetition never changes the frozen baseline. Entries expire after
30 days without a match; expiry or revocation restores originals. Relearning is explicit.

Record learning counts in 5-minute buckets, including zero buckets. Proposed rolling 5-minute
limit: max(10, 3 × learning P95 bucket count), implemented with bounded buckets rather than a
fixed-boundary counter. This protects reduction behavior, not a definitive attack classifier.
Crossing the threshold emits that event and subsequent matching events for 10 minutes, and
immediately reports a rate-anomaly summary including earlier suppressed occurrences.
Low-rate malicious repetition can remain below the threshold.

Continue tracking suppressed parents. For an unknown/high-risk child, emit the child and
replay available real ancestor exec evidence as context_only, preserving original time and
event_id. Never fabricate ancestry. Eviction/restart/missing context sets ancestry_context_missing.
Suppress only after successfully caching context; insufficient context capacity restores originals.

Keep context for at most 24 hours within the shared memory budget; reclaim old exited instances
first. This cannot guarantee unlimited historical reconstruction. Complete forensics requires
full mode or an optional separately quota-managed local raw archive excluded from uploader globs.

Emit at most one normal summary per matching fingerprint per 5 minutes, only for nonempty windows.
Best-effort flush on stop/policy switch. A crash can lose the last window; mark the recovery gap.
Never sample unknown events or silently discard them under a global volume limit.
Health and summary records continue even when all eligible activity matches the baseline.

## 8. Proposed Configuration And State

The following is a future module configuration fragment, not accepted configuration today:

```json
{
  "behavior_learning": {
    "enabled": true,
    "learning_duration_seconds": 86400,
    "learning_online_deadline_seconds": 259200,
    "activation": "auto_eligible",
    "event_types": ["exec"],
    "min_occurrences": 5,
    "min_distinct_hours": 3,
    "min_span_seconds": 21600,
    "summary_interval_seconds": 300,
    "baseline_idle_expiry_days": 30,
    "max_baseline_entries": 10000,
    "max_candidate_entries": 20000,
    "memory_budget_mb": 64,
    "state_budget_mb": 64,
    "on_error": "emit"
  }
}
```

Suggested duration range: 1 hour to 7 days, default 24 hours; deadline must not be smaller.
Reject unknown fields, conflicting budgets, or invalid thresholds without replacing valid policy.
If no valid policy exists, emit and report configuration failure without stopping the core collector.
Phase one only accepts exec event type and emit error behavior.

Proposed storage is behavior-learning/ within the Agent state root, normally
/opt/secweaver-agent/state/behavior-learning/ on Linux; honor custom installation layouts.
Windows 0.3.38 uses `data/behavior-learning-windows` with restricted SYSTEM/Administrators ACLs;
see the operator guide for actual paths and native validation requirements.
Use 0700 directories and 0600 files for manifest, candidate checkpoints, immutable baseline,
local HMAC key, and commit checksums. Store no unredacted full commands.

One process exclusively locks the directory; a second writer emits originals and reports conflict.
Checkpoint asynchronously every 60 seconds using temporary files, fsync, atomic rename, and
directory fsync. Losing recent candidate counts after a crash may delay, never accelerate, promotion.
Atomically commit content and active manifest, retain the previous baseline for rollback, and
reject corruption, unknown versions, or checksum mismatches.

Reuse only compatible device, fingerprint, and capability versions after upgrade.
Partition audit/eBPF baselines by capability; unknown fields never equal known values.
Remote policy uses signing, tenant/device scoping, version validation, and staged rollout.
Do not copy a learned baseline across devices. Standalone administration uses the same validation
and can disable suppression without network access.

## 9. Bounded Resources And Performance

| Resource | Proposed default and overflow behavior |
|---|---|
| Baseline | 10,000 entries; excess candidates remain emitted |
| Candidates | 20,000 entries; stop admitting new fingerprints and report overflow |
| Memory | 64 MiB total for indexes, strings, context, summaries, and queues |
| State disk | 64 MiB total including old/new revisions, temporary files, and checkpoints |
| File verification | 2 workers and 256 queue slots; queue failure/timeout emits |
| Hot path | Average O(1) lookup, no network or synchronous disk IO |

Honor collector event-size limits; never learn truncated events. Account actual allocated strings,
argv, and context bytes, not just map entries. On exhaustion stop new admission and emit; do not
randomly broaden or replace a frozen baseline via LRU. Bound summary/state queues; failed statistics
become explicitly incomplete and affected events resume original output. Existing disk protection
still applies: emit means the original writer path, not an unlimited-storage guarantee.

Benchmark CPU, RSS, P95/P99 latency, summary bytes, and high-cardinality adversarial inputs.
Proposed targets: at most 5% additional pipeline CPU under normal load; filtering P99 below 1 ms
excluding existing enrichment; memory within budget plus measured runtime overhead.
These are acceptance targets, not measured results.

## 10. Logs, DataAsset, And Skills

Preserve original exec fields, adding proposed event_id, behavior_fingerprint, baseline_id,
learning_state, learning_decision, decision_reason, and fingerprint_version.
Stable event IDs incorporate device, boot, and backend occurrence identity, not output time.

A separate behavior_summary event carries summary_id, device_id, baseline_id,
behavior_fingerprint, policy_revision, window_start/end, first_seen/last_seen,
observed_count, suppressed_count, original_emitted_count, context_reemitted_count,
counter_complete, gap_reason, redacted representative sample, service identity, backend,
fingerprint_version, and reason.

For a complete window of unique source events:
observed_count = suppressed_count + original_emitted_count.
Ancestor replay is counted separately, not as a new observation. Deduplicate retries by
event_id/summary_id and never count failed writes as successful output.
A summary is not an original exec and must not use one representative PID for all occurrences.

Propose a separate behavior-learning.log for summaries/transitions, with standard permissions,
buffering, rotation, disk quotas, and self-exclusion. ES/Filebeat, SLS/Logtail, and independent
shipper delivery owners must explicitly add routes and mappings. Introduce the logical asset
host_behavior_summary and align public templates/private asset bundles before enabling suppression.
No current uploader support is claimed.

Every 5 minutes, health reports add mode, progress, revisions, candidate/match counts,
observation/original/suppression counters, summary failures, event loss, context eviction,
resource use, and fallback reasons. Do not append an unbounded per-behavior list to health snapshots.
Skills distinguish originals, summaries, represented occurrences, and replayed context.
Completeness reports show mode and suppression windows; missing originals do not mean no execution.
Never construct real process edges from representative summary PIDs. Report missing ancestry and
measure both record reduction and actual bytes, including summaries and replay overhead.

## 11. Administration And Rollout

Proposed operations: status/progress, redacted candidate export, eligibility reasons, explicit
relearning, full-output switch, entry revocation, baseline rollback, and change audit.
CLI/API names are deferred; this proposal provides no executable new commands.

The first collection start after a fresh installation automatically enters learning with full output;
after 24 healthy observation hours, freeze eligible entries and enter enforcing. Existing installations
retain explicit upgrade opt-in; manual enablement or relearning starts timing when that action takes effect.
Business updates keep exact old matches while changed behavior emits.
Explicit relearning restores full output in scope and builds a
replacement; do not append unknown activity to the old baseline. Manual approval cannot override
always-emit rules. Threshold relaxation or argument masking records operator, revision, time,
scope, and a signature for remote policy.

Start with representative hosts, observe one day after learning, then expand. Optional shadow mode
calculates would_suppress/estimated bytes while still emitting everything; it is a rollout tool,
not a mandatory second day before default enforcement.
An incident or mistaken suppression immediately switches to full without reinstall/reboot,
retaining the baseline read-only for review. Control-service failure must not stop collection.

## 12. Acceptance And Delivery

Verify fresh installation starts learning with collection, without manual enablement or waiting for
midnight, and installation without collection does not start timing. Verify healthy learning and
ineligible low-frequency commands; malicious/sensitive learning samples;
unknown children of suppressed parents and ancestor replay; argv/cwd/identity/TTY/binary/root changes;
PID reuse, repeated exec, and container replacement; restart/downtime/clock changes; lost events,
corrupt state, full disks, lock conflicts and queue pressure; rate bursts across window boundaries;
actual ES/SLS summary ingestion, deduplication and Skill evidence semantics; 24-hour load and at
least 7-day stability runs; signing, rollout, revocation, full rollback and backend transitions.
Compare full versus enforcing against known attack exercises and record missing evidence explicitly.

Phase one implements Linux learning/matching, always-emit policy, storage, context cache,
summaries and local administration. Phase two completes ES/SLS routes, DataAsset/Skill contracts,
and rollout/rollback acceptance before release enablement. Windows Sysmon code landed in 0.3.38;
native acceptance, controlled script identity and explicit variable-argument policy remain later work.

Existing compromise can poison learning; filtering cannot provide complete original history.
The first day retains full cost. Highly variable commands or conservatively retained scripts may
yield limited reduction. Use shadow measurements of eligible exec share and actual bytes to guide
deployment, never automatic learning of unknown events just to achieve a volume target.

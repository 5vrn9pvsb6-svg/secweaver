# Behavior Learning And Log Reduction

**Languages:** English (this page) | [简体中文](behavior-learning.zh-CN.md)

## Version And Scope

Agent source 0.3.37 introduces independent pkg/behaviorlearning and Linux audit/eBPF exec
adapters. This conservative first implementation does not complete every proposed management
feature or production acceptance gate. Source 0.3.38 adds the separate Windows Sysmon exec adapter;
0.3.39 adds eligible network/file learning to that Windows adapter as described below.
Unprivileged workload-container profiles do not enable Linux learning.

Fresh installation copies enabled=true, shadow=false from audit-port-execmon.example.json.
Learning begins automatically with the first successful collection start, retaining full originals.
Existing configurations without behavior_learning remain disabled. Clean restarts retain progress.
An initial/post-interruption 10-minute healthy protection period precedes 24 accumulated healthy
hours. Downtime does not count. Incomplete events remain emitted and ineligible without preventing
other complete behaviors from learning. Known loss, reader failure, queue overflow or unclean exit
degrades the generation and requires explicit relearning.

On Linux, only verifiable noninteractive ELF executions **directly parented by the listener root**
may qualify. Child and parent binaries must be root-managed and not group/world-writable,
with complete argv, unchanged credentials, no effective capabilities and a known unset login UID.
Scripts, interpreters, interactive/sensitive operations and unknown context remain emitted.
Deep ancestry and unverifiable short-lived processes remain full-output.

Audit requires complete SYSCALL/EXECVE/CWD/PATH evidence, image inode/device and instance timing.
eBPF now captures effective UID/GID, login UID, start time and executable inode/device at exec.
Missing CO-RE fields or failed kernel reads leave identity_valid=false; those events cannot suppress.
Exited or changed /proc instances do not qualify. Reduction depends on actual eligible traffic.

## Configuration

### Windows (0.3.39)

Fresh `config.windows.example.json` installations pass `-behavior-learning` to the unified
`windows-eventlog-risk-json` reader. The optional standalone `windows-process-execmon` reader
supports the same flags, but must not run alongside unified evidence output. Existing configs
without the flag remain unchanged. This is Windows amd64/arm64 code support; live Windows
Sysmon/ACL and 24-hour acceptance are still required before production rollout.

The same 24 healthy hours, ten-minute protection period, promotion thresholds, frozen whitelist,
shadow mode, rate guards and failure-to-original policy apply. Qualification requires Sysmon
Event 1 with SHA256 enabled, valid process/parent GUIDs, exact command and parent command,
working directory, matching built-in SYSTEM/LOCAL SERVICE/NETWORK SERVICE identities and
session zero/System integrity. Images must be `.exe` under Windows System32 or Program Files.
The adapter trusts execution-time Sysmon fields, not a later PID lookup; it does not claim
Linux-style live parent-image/ACL verification or full ancestry reconstruction. Parent command,
image and user are fingerprinted; a parent executable digest is not available in Event 1.

Security 4688 remains fully emitted because it lacks execution-time hashes/GUIDs. Installing
Agent does not install/configure Sysmon. Missing Sysmon, missing SHA256/ParentUser or incomplete
records cannot produce a usable whitelist. An empty baseline degrades to full output. PowerShell,
cmd, script interpreters, sensitive utilities, interactive/elevated/different identities, historical
records and records delayed over ten minutes remain emitted. Risk logs are never filtered.
No guaranteed reduction percentage applies, especially on 4688-only deployments.

Since 0.3.39, fresh Windows configurations explicitly enable `exec,active_connect,file_op`.
Each type has separate exact fingerprints, counters and qualification evidence. Network/file
events require a previously observed eligible Event 1 from this reader session with the same
host+ProcessGuid, executable and user. Reused numeric PIDs never transfer trust. Restart does
not restore this in-memory identity cache; preexisting processes remain full-output until a
qualifying creation is observed. A 1,024-entry/4 MiB cache retains active identities, evicts after
one idle hour and is pruned once per minute. Sysmon Event 5, identity disagreement and source
faults invalidate context. Missing Event 5 delivery cannot be inferred from silence.

| Type | Automatic whitelist eligibility | Always emitted |
| --- | --- | --- |
| `exec` | Existing Event 1 SHA256, service-token and exact-command checks | 4688, sensitive tools, incomplete/interactive identities |
| `active_connect` | Sysmon 3, outbound `Initiated=true`, exact private destination IP/port, TCP/UDP, exact source IP and execution context | Public/special destinations, inbound, unknown direction/protocol, SSH/RDP/SMB/RPC/DNS/authentication/management ports |
| `file_op` | Sysmon 11, exact ordinary `.log` creation path under explicit `file_roots` and verified execution context | Delete, rename, ambiguous actions, other extensions, sensitive paths, audit/auth/security/Agent logs |
| Authentication, risk, persistence, identity/service changes | No automatic suppression | All existing evidence remains emitted |
| Process/socket/host-state snapshots | Existing snapshot delta strategy | Do not discard baseline/state changes through this whitelist |

File roots are a learning scope, not a wildcard whitelist: every exact path still needs the
full promotion thresholds. Fresh Windows examples use `C:\ProgramData`; non-C installations
must set their real absolute path. Windows/Microsoft/Startup/Tasks/credential/SSH paths are
excluded even beneath a configured root. No new Sysmon rules or network/file collectors are
enabled by learning flags; the source events must already be collected. This release does not
extend Linux audit/eBPF filtering beyond exec; raw Linux network/file evidence stays intact.

Sysmon Event 11 describes **creation or overwrite**, not content diffs; the existing normalized
`action=create` includes both. Do not put business security/audit logs into the allowed scope
just because they end in `.log`. Sysmon network Event 3 is disabled by default and must already
be enabled by the operator. See [Microsoft's event semantics](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#events).
Observed CreateRemoteThread (8) or ProcessTampering (25) degrades this generation to full output;
an unchanged process GUID is not proof that the process has never been injected into.

Add flags to the selected reader's `modules.<name>.args` in `config.json`:

```text
-behavior-learning
-learning-duration 24h
-learning-generation 0
-learning-shadow=false
-learning-event-types exec,active_connect,file_op
-learning-file-roots "C:\ProgramData\Example\logs"
```

Use `-behavior-learning=false` to disable, `-learning-shadow` to retain originals, and increase
`-learning-generation` to relearn a readable baseline. Duration changes must still satisfy the
fixed default six-hour span/three-hour-bucket thresholds. Restart `secweaver-agent` after editing.
`-learning-event-types` is comma-separated; `-learning-file-roots` uses semicolons between
absolute directories (up to 16, no wildcard). Omitting event types keeps legacy exec-only
behavior; omitting roots keeps all file events. On an existing baseline, expand types/roots
only with an increased generation; unchanged generation refuses the policy mismatch and emits
originals. Existing on-disk configuration is not silently rewritten during upgrade.
`-learning-state-dir` and `-learning-output` accept absolute overrides. Defaults are
`C:\ProgramData\SecWeaver\Agent\data\behavior-learning-windows` and a
`behavior-learning.log` beside `windows-process-execmon.log`. A custom cursor directory determines
the default state directory. An enrolled `SECWEAVER_DEVICE_ID` is required; missing identity or
invalid/locked state disables filtering with a warning. State uses a protected inheritable
SYSTEM/Administrators ACL, exclusive non-shared lock and write-through atomic replacement.
Unix 0600 claims below do not substitute for Windows ACLs.

Both readers feed one synchronous, bounded-field adapter: no extra Windows queries, process scans
or executable hashing subprocesses are added. A one-second ticker owns time/checkpoint work under
the adapter lock. Only recent successful complete polls renew source health. Query failures,
Sysmon restart/config/error records and observed event-log clear notifications invalidate the
generation. This does not detect all events lost to unobserved channel rollover or Sysmon filters.
Summaries and originals checkpoint before EventRecordID; Windows additionally flushes nonempty
counts at cursor checkpoints, so summary windows may be shorter than 300 seconds. Source
cursor/learning state are separate files: crashes degrade instead of promising exactly-once counts.
Shutdown syncs both sinks before marking the baseline clean; a final sync error persists degradation.

Managed Windows SaaS 0.3.50 requires the signed collection plan to include this
summary file before installation succeeds; see [Windows readiness](windows-installation.md#windows-sls-collection-readiness).
For external delivery, configure Filebeat/ES Shipper or Logtail to upload the Windows summary file to
`host_behavior_summary`, separately from `host_exec`; the cloud Logstore may be named
`host-behavior-summary`. Linux-only path examples do not configure Windows shipping automatically.
Validate `behavior_learning_status` in the local file and backend, use shadow mode first, and
compare changed command/hash, PowerShell, interactive and 4688 records against raw Event Logs.

### Linux

Add this block to audit-port-execmon.json, retaining the other module settings:

```json
{
  "behavior_learning": {
    "enabled": true,
    "learning_duration_seconds": 86400,
    "generation": 0,
    "shadow": false
  }
}
```

Defaults: 300-second summaries; at least 5 observations in 3 distinct healthy-hour buckets
spanning 6 hours. Baseline/candidate limits are 10,000/20,000; memory/state budgets are 64 MiB each.
Conservative byte admission may stop before entry limits. One background worker owns verification/output,
with a 128-event queue and 64 KiB event admission limit; overflow restores originals and degrades. Checkpoints occur every 60 seconds;
a failure may lose the latest candidate minute. See pkg/behaviorlearning/config.go for the fields.
Unknown learning settings disable this feature with stderr diagnostics while core collection continues.
Shorter duration also requires consistent promotion thresholds.

shadow=true preserves originals to validate the baseline; it is not an extra default learning day.

Since 0.3.40, the Linux supervisor keeps its shared audit reader alive until child modules
finish stopping. A normal restart preserves a healthy learning generation; downtime does not
advance its clock. Unexpected stream loss still degrades learning. Versions 0.3.37-0.3.39
can incorrectly persist `audit_reader_failed` during normal shutdown. Upgrading does not
silently trust such a generation: back up config/state, increase `behavior_learning.generation`
by one in the audit module config, and restart to begin a fresh 24 healthy hours. Do not edit
authenticated state. Verify status before/after a second normal restart: baseline ID and
generation must remain unchanged, mode must remain `learning`/`enforcing`, and no new
`audit_reader_failed` should appear. This fix concerns supervised Linux collection; Windows
learning prerequisites and genuine fault recovery are unchanged.

enabled=false disables filtering. Increment generation to explicitly relearn; changed thresholds
without a generation increase reject old state and preserve originals.
Use the existing module-config restart workflow, or manually:

```bash
sudo systemctl restart secweaver-agent
```

Deleting state.json does not request relearning: the initialization marker detects damage.
generation cannot repair unreadable state. Disable learning, back up the complete state directory,
resolve storage faults, then configure a new state_dir during a stopped-service maintenance window.
Never edit a live baseline/key or copy a baseline between hosts.

## Status And Files

Use the Agent data layout, superseding the proposal's earlier state path:

- /opt/secweaver-agent/data/behavior-learning/state.json: authenticated envelope containing
  progress, candidates, frozen entries, recent matches and clean-shutdown marker.
- key, initialized, lock in that directory: local HMAC key, initialization marker and exclusive lock.
- /opt/secweaver-agent/logs/behavior-learning.log: summaries/status using existing 0600 permissions,
  buffering, rotation, disk protection and host/enterprise injection.
- state_dir/output_log accept absolute overrides. Custom roots with sibling logs/data directories follow that layout; other custom roots must set
  state_dir. An omitted output_log follows the original event log directory.

Directories are 0700, files 0600. Persist fingerprints, executable paths, counts and qualification
evidence, never full argv or reversible credential samples. schema_version=1 is the implemented
format, not the proposal's illustrative JSON. HMAC is local integrity protection, not protection
against a compromised root.

Read the latest checkpoint without competing for the collector lock:

```bash
sudo /opt/secweaver-agent/bin/secweaver-agent module audit-port-execmon \
  -config /opt/secweaver-agent/etc/audit-port-execmon.json -learning-status
```

Status may lag by 60 seconds. In summaries, source_healthy reports input health,
filtering_active reports effective filtering, and shadow identifies validation mode.
learning_state=enforcing alone does not imply the restart protection period has elapsed.
A missing checkpoint fails open to original output instead of silently starting fresh.
 Device/policy/baseline mismatch never widens matching.
Clean restart uses 10 minutes of full output to rebuild rate state; crashes/forced termination
degrade. Increment generation to relearn from otherwise valid readable state.
Per-entry revocation, baseline-version rollback and a dedicated remote management API are not implemented.

## Matching And Evidence

HMAC covers device/policy, service/parent context, executable digest, exact argv, cwd, credentials
and backend capability. PID is excluded from reusable matching but instance identity is verified.
Changed files, arguments, user or service emit originals. Unknown repetition never grows the baseline.

The rolling five-minute ceiling is max(10, 3 × learning P95). Monotonic five-second buckets
conservatively include up to five extra seconds to avoid split-window double allowances.
Exceeding the limit emits the current event and an immediate summary, then at least ten minutes
of originals; continued high rate extends protection. Entries idle for 30 days expire.

Process tracking precedes learning. Available suppressed ancestor events can be replayed as
context_only with real event IDs. Unavailable ancestry sets ancestry_context_missing; no fabricated
chain is created. Deep ancestry reconstruction remains limited in this release. Disable filtering
when full original history is required. Insufficient context-cache capacity restores originals.

Original events routed through learning add event_id, baseline_id, behavior_fingerprint, learning_state,
learning_decision, decision_reason, fingerprint_version and ancestry_context_missing.
Existing original-log permissions/redaction behavior is unchanged; state never stores full commands.

## ES, SLS And Assets

New event types are behavior_summary and behavior_learning_status, with
asset_type=host_behavior_summary. They never substitute for host_exec.
Complete summaries satisfy observed_count = suppressed_count + original_emitted_count;
context_reemitted_count is separate. Deduplicate summary_id before counting.
counter_complete=false and restart gaps prevent complete-execution-count claims.
Nonempty summaries add `source_event_type` (`exec`, `active_connect` or `file_op`), while
status records omit it. Older summaries without this field refer to exec. Count each type
separately; a network/file summary must not be interpreted as execution count or a process-tree
edge. Configure this field as keyword in ES and text in SLS; packaged templates/assets include it.

- Packaged elasticsearch/filebeat.yml adds the new file and
  secweaver-public-agent-behavior-learning-* index. index-template.json adds typed fields.
  Follow the ES guide for existing-template drift/migration; initialization does not overwrite it.
- For SLS, operators must create a JSON file collection configuration and attach their existing
  user-defined machine group. logtail/behavior-learning.example.json is a field/index reference,
  not a universal version-independent Logtail API payload.
- Community includes separate ES, SLS and SLS Proxy draft summary assets/connectors and host/time
  templates. Configure and verify real ingestion before marking active.
- Private Operator, physical SaaS Logstore and separate shipper delivery configurations need
  corresponding routes. Community changes do not remotely update deployed shippers/private assets.

Before rollout, verify the new stream is uploaded; shadow=true can preserve all evidence meanwhile.
Skills must consult summary/status coverage, disclose suppression/gaps, and never infer no execution
from missing originals or construct PID edges from aggregates.

## Verification And Outstanding Gates

From the Agent source directory:

```bash
go test ./pkg/behaviorlearning ./pkg/auditportexecmon ./pkg/processtracker/...
go test -race ./pkg/behaviorlearning ./pkg/auditportexecmon
go test ./pkg/behaviorlearning -run '^$' -bench BenchmarkKnownBehavior -benchmem
```

Linux eBPF tests verify object layout/decoding; compilation does not prove kernel attachment.
Real amd64/arm64/loong64 attachment, a 24-hour learning run, at least seven days of stability,
attack-evidence comparison and live ES/SLS reconciliation remain release acceptance gates.
Source changes neither publish nor deploy binaries.

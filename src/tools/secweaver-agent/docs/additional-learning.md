# Additional learning: source0.3.108

[简体中文](additional-learning.zh-CN.md) · [Learning overview](behavior-learning.md)

This candidate adds24 **healthy** hours to selected existing, enabled, non-shadow,
healthy enforcing native learning engines. Linux supports exec/file; Windows has
independent exec/file/network/risk adapters. Disabled, missing, stale, degraded or
already-learning streams are not enabled/reset. An intact empty baseline may qualify.
No Linux network-learning support is added. Real Linux/Windows runtime acceptance
remains pending; local unit tests and cross-builds do not prove native deployment readiness.

## Eligibility and execution

Requires managed V2 identity, complete `behavior-relearning-v1` heartbeats and a
matching Gateway/Workspace feature enabled by the database owner. Old services without
this optional protocol leave normal collection unchanged. The installed collection
verification public key also verifies purpose-separated30-second start grants.
The sole collector checks installation/device, stream, baseline token, monotonic
operation sequence, fixed duration86400 and signed deadlines under its existing lock.
No arbitrary commands, network paths, new event readers or service restarts are used.

Entries, store HMAC key, baseline ID, generation, policy hash and source dedup history
are retained. Only unpromoted candidates are cleared at start. Existing protected-event,
admission and filtering rules stay in force. Lifetime healthy/online counters do not
reset; progress is the additional window's counter delta. Offline time adds no healthy
seconds. The window freezes admissions at24 healthy hours,72 additional online hours,
7 calendar days from actual start, or acceptance+8days, whichever applies first.
Deadline/fault/unknown execution is not successful completion. Normal clean restarts
resume durable facts; unclean restart/corruption keeps the existing degraded safeguards.

Only engine-owned durable state proves a start/result. Inbox delivery is pending,
not completion. Duplicate/renewed grants cannot restart a window; a durable no-start
rejection remains terminal. Temporary missing collector observations do not erase
previous durable progress. Failed receipt persistence withdraws optional reporting,
not ordinary licensing or collection. Upgrade/configuration mutation locks defer
claims during in-flight/unknown upgrades; no configuration restart is requested.

## Storage and limits

Parent/worker coordination uses a fixed private `learning-operations` directory under
the installation data directory: `current.json` (16KiB), `receipt.json` (8KiB), and
four fixed per-stream refusal files (4KiB each); total directory budget128KiB.
No user-selected filenames. Unix0700/0600 and Windows SYSTEM/Administrators ACLs,
regular files and no links are required. Worker environment `SECWEAVER_RELEARNING_DATA`
and `SECWEAVER_RELEARNING_INSTALLATION` is internal supervisor binding, not remote configuration.

The learning checkpoint remains version1 until an additional window is committed;
then version2 persists its operation identity/counter bases/result. New code reads
versions1/2; old code must not load version2 as a fresh baseline. Each store retains
one authenticated `relearning-backup.json` of the complete pre-window state/key/journal.
Backup, state and journal replacements count against the configured per-stream budget;
128KiB coordination reserve is included for stores of at least8MiB. Space failure rejects
extension and preserves the trusted copy. Backup replacement never deletes the only copy first.

### Independent stream directories and budgets

The Linux exec state root may contain `file-operations/`; the Windows exec root may
contain `file-operations/` and `network-operations/`. These product-created streams
have independent lifetime locks, HMAC keys, checkpoints, additional-learning backups
and configured budgets. The exec budget counts its own regular files without
traversing child stores, charging their bytes, acquiring their locks or changing
their files. File, network, risk and the `learning-operations` coordination directory
receive no child-directory exemptions. Unknown directories, symlinks and special files
are still refused. Starting additional learning never automatically deletes files.

0.3.108 fixes normal child directories being rejected as `unexpected learning state file`,
which blocked exec additional learning. No directory migration or baseline reset is
required; a normal clean upgrade retains existing entries and independent file-learning
progress. Upgrading does not replay a previously rejected operation. If another stream
in that operation is still learning, preserve it until terminal before requesting a new
exec operation through the workspace. Do not delete receipts, SQL records or learning
directories to bypass terminal results.

New refusal receipts use the existing `reason` field to distinguish `state_layout_invalid`
(unexpected directory/file type) and `state_budget_exceeded` (this stream's budget).
Other unclassified failures remain `engine_refused`. Only fixed reason codes are reported,
not local paths, keys or entries; detailed errors remain in local logs. Historical receipts
are not rewritten. Inspect each stream result: an overall learning state does not mean
every selected stream has started.

## Explicit offline recovery

This is maintenance tooling, **not** the UI action. It stages a new directory and
never switches a live directory, restores device credentials or clears server fences.
Use the source0.3.108 tool from this directory (Go required), or build it explicitly;
it is not automatically installed as an Agent service command:

```bash
go run ./cmd/learning-recovery -source /absolute/stopped-stream-state -destination /absolute/new-recovery-state -state-mb 64
```

1. Disable new requests/claims at the owner gate, stop the Agent and affected collectors,
   and wait beyond the last30-second grant plus clock-safety margin. Preserve the complete
   new installation state and operation inbox separately; quarantine old pending grants
   during manual cutover. Do not delete the SQL operation/sequence/receipt history.
2. Choose the actual per-stream state source and its original configured budget8..256MiB;
   `64` above is only an example. Destination must be a new, absolute, disjoint directory.
   The tool takes the source lifetime lock and verifies backup HMAC/key/state/journal.
3. Confirm success and inspect the staged state before an explicitly approved directory
   switch. Source is retained. A failed partial destination is retained for inspection
   and must not be reused as a valid baseline. Do not run this against a live writer.
4. Restore only the same stream/device/policy. Learning entries/progress added after the
   backup are lost in a downgrade. The latest backup may itself contain a prior version2
   window: that backup requires a compatible new Agent, not an old binary. Never promise
   old-binary compatibility without inspecting the restored checkpoint version.
5. Reconcile unknown server operations with compatible software. Local recovery is not
   authorization to clear a server fence or start another learning operation.

## Verification before release

Local checks cover contract signature/binding/renewal, exact window accounting,
candidate/entry retention, restart/idempotency, terminal refusal, resource failures,
backup tamper/locked-source/overwrite denials, and coordinator receipt preservation.
0.3.108 also tests real nested Linux/Windows layouts, starting exec while file is learning,
independent budgets, concurrent checkpoints, clean restarts and directory/symlink denials.
These are local temporary-directory filesystem tests, not native-host acceptance.
Run from the Agent module:

```bash
go test -p 2 ./pkg/learningoperation ./pkg/behaviorlearning ./pkg/agentlicense ./pkg/auditportexecmon ./internal/windowsevidence ./pkg/windowseventlogriskjson . ./cmd/learning-recovery
```

Still required: real Linux audit and Windows event-source exercises, crash/resource and
configuration/upgrade concurrency under native load, reviewed cross-repository immutable
contract pins, and canary rollout authorization. There has been no production deployment.

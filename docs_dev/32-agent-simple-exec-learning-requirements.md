# Simplified Agent Execution Baseline Requirements

The subsequent 0.3.82 file extension has [separate requirements](34-agent-simple-file-learning-requirements.md).
The other-event scope described here applies to 0.3.81.

**Languages:** English (this page) | [简体中文](32-agent-simple-exec-learning-requirements.zh-CN.md)

Date: 2026-10-08. Status: user approved and implemented in Agent 0.3.81 source;
not packaged or deployed.
The user explicitly requested identical listener_process, pid_name, exe and
command_line events to enter the baseline after five occurrences within one hour
during learning and start filtering immediately. This document makes that rule
testable. Keep the one-day learning duration; filtering no longer waits for its end.
Scope, boundaries and migration are detailed in the [architecture](33-agent-simple-exec-learning-architecture.md).
See the [usage guide](../src/tools/secweaver-agent/docs/behavior-learning.md)
for installation, recovery and server prerequisites.

The same rule now covers the Windows streams defined by the
[0.3.83 unified requirements](36-agent-unified-simple-learning-requirements.md).
Use those requirements for current cross-platform scope.

## 1. Matching Key

Within one device and exec stream, match exactly:

```text
(listener_process, pid_name, exe, command_line)
```

No patterns, case folding, whitespace folding or argument templates.
Use structured encoding with unambiguous field boundaries for local fingerprints.
Device/stream partition the baseline; they do not add another behavior field.
Numeric PID/PPID/listener PID, credentials, TTY, CWD, inode/image hash, cgroup,
parent command, starttime, success/failure and backend do not affect matching
or add admission gates. pid_name is the process name, not numeric PID.

## 2. Five Occurrences Within One Hour

Use a rolling 60-minute window, not aligned clock-hour buckets. Expire older
occurrences and count the new event; the fifth qualifies and starts filtering immediately without
distinct-hour or six-hour-span requirements. Exactly 60 minutes is included.
Use reception time of complete events in the live collection path; historical
backfill does not train this installation baseline. Distinct executions count,
not rereads/retries of the same source event or separate audit records making
up one execution.

| Times/context | Result |
| --- | --- |
| 10:05/15/25/35/55, identical tuple | Enter at 10:55; summarize instead of emitting the fifth original |
| 10:50,11:00/10/20/40, identical | Enter and filter at 11:40 despite hour boundary |
| 10:00/10/20/30,11:01, identical | Only four retained at 11:01 |
| Same source event read five times | Count once |
| One of five has different command_line | Separate behavior counters |

## 3. Learning And Activation

Keep default one-day effective learning starting with successful collection;
downtime/known source failure does not count. Learning and filtering run together.
Unlisted behaviors retain originals while accumulating occurrences. Once the
fifth event qualifies and its entry is successfully admitted, summarize that
event and subsequent exact matches instead of emitting their originals.
Do not remove the first four originals or count them again as suppressed events.
An admitted entry does not need five occurrences in each subsequent hour;
later low-frequency matches still filter. Admission or summary failures retain
originals; reaching the count alone must not discard an event.

Continue learning other behaviors during the learning period. Completion freezes
new admissions only; existing entries continue filtering, and unknown behaviors
retain originals without automatic admission in enforcement.

```text
Learning: miss -> original + rolling hour count
          fifth occurrence successfully admitted -> summary from that event
          entry match -> summary; continue learning other behaviors
Learning ends: freeze new admissions; continue filtering existing entries
Afterward: exact entry match -> summary; miss -> original without admission
```

Empty completion displays "learning complete, no filterable behaviors", not
degraded; real input/state/output failures have separate diagnostics.
Shadow retains everything; disable stops filtering; preserve does not silently
enable machines whose existing policy is disabled.
During normal learning, report filtering_active=true when an effective entry
exists and filtering is enabled and healthy. The learning phase alone must not
force false. Shadow, disabled filtering or fault fallback reports false.

## 4. Removed Admission Rules

Remove three distinct healthy hours, six-hour span, direct-root-parent,
matching .service cgroups, equal credentials/zero CapEff, live /proc/image
inode/SHA256 verification and blocked executable-name admission checks.
Listener attribution itself remains the existing collector's responsibility.
Replace large parent/child-context matching with the four-field tuple.

Repeated bash/curl/ssh executions may qualify, including repeated attacks with
identical fields. Qualification means reduction, not safety. Separate login,
authentication, persistence and risk streams are not suppressed by this exec
baseline. Do not add previous P95/hour-bucket conditions to the simplified match.
Collection, tracking, rotation, summaries and fault fallback remain independent
operational responsibilities and must not silently reintroduce removed gates.

## 5. Field Quality

Missing fields or truncated commands retain originals without training; a
complete key cannot be formed. This is not /proc/credential/service verification.
Prefer complete EXECVE evidence over shorter PROCTITLE.
Compare the collector's complete normalized command_line as an exact string.
If the existing serialization maps different argv boundaries to one string,
they match under this rule; do not silently add argv as a fifth field. Record
this contract ambiguity during implementation design.
Match before output redaction; persist only irreversible fingerprints,
necessary redacted display and counts, never plaintext passwords/tokens.
Redaction placeholders must not merge distinct real commands.

## 6. Stream Scope

Linux audit/eBPF exec currently supplies these four fields directly, establishing
the initial explicit contract; backend is not part of matching. This does not
expand listener discovery/kernel collection/attribution scope.
Windows executions, operations and PowerShell risk do not universally supply
them. Do not treat missing fields as wildcards, guess listener ancestry from
ParentImage or suppress different targets using execution-only fields.
Cross-platform/other-event expansion requires a separately defined field
contract; their existing learning policies are not changed by this revision.

## 7. Operations And Migration

Expose enabled/start/remaining/entry count/filtering/reason, with the direct
description "five identical four-field events in one hour".
The UI must allow "learning" and "filtering active" to appear together.
Old complex entries cannot be reused as four-field entries. Define a new policy
identity and explicit relearning migration. On enabled hosts, behaviors outside
the new baseline retain originals; newly admitted entries filter immediately.
Never silently mix fingerprints. Clean restarts preserve
readable progress/entries; corrupt state or known loss retains originals with
actionable diagnostics. Output/storage failure must not claim successful reduction.
0.3.81 implements migration with a separate strategy identity, authenticated admission
journal and checkpoints. Deploy Agent Server 0.6.0-rc.72 and workspace server
0.6.0-rc.112 before the new Agent so they accept and display filtering during learning.

## 8. Performance

The learning path only encodes/hashes four fields, deduplicates source IDs,
looks up entries and updates at most five recent timestamps per candidate.
Once qualified, do not retain all occurrences. No learning-specific /proc scan,
image reads/hashes or external command calls. Bound candidates, entries and
dedup by count/bytes; retain originals and expose capacity reasons on exhaustion.
Do not loosen matching, hide unknown inputs or block the reader to handle limits.

## 9. Acceptance

Verify same tuple across PID/credential/parent/cgroup/backend changes; fifth
unique event, window boundaries/hour crossing/source retries; changes in each
field, missing/truncated data; first four originals versus immediate filtering
from the admitted fifth event; continued learning of other behaviors; freezing
only new admissions at completion; shadow retaining all originals;
tool execution versus protected separate streams; empty versus fault state;
old-entry migration, restart/corruption/capacity/count observability; and local
original/entry/summary comparison with cloud delivery; filtering_active=true
during effective learning; no duplicate suppression count for the first four;
low-frequency matches staying filtered; admission/summary failure retaining
originals with diagnostics. Bump release version
before building changed code under repository rules.

This iteration implements source, comments, regression tests and documentation;
it does not publish packages or change deployed hosts.

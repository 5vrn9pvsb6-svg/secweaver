# Behavior Learning and Log Reduction

**Language:** English (this page) | [简体中文](behavior-learning.zh-CN.md)

## Current Rule (0.3.85)

Every integrated whitelist stream uses one rule: **during learning, five distinct
source events with exactly the same fields on the same device and event type
within a rolling hour admit the behavior. The fifth event is filtered immediately,
after durable admission, without waiting for the learning period to finish.**
The first four originals remain. An admitted behavior does not need another five
hits every hour. Learning starts with the first successful collection after
installation, accumulates 24 healthy hours by default, then freezes new admissions.

| Event | Exact Fields | Prerequisites |
| --- | --- | --- |
| Linux exec | listener_process, pid_name, exe, command_line | Four nonempty valid fields; match collected strings without requiring complete argv |
| Windows exec | listener_process, pid_name, exe, command_line | Native complete command from Sysmon 1 or Security 4688 |
| Linux/Windows file_op | file_paths, listener_process, pid_name, exe, command_line | Complete path and command evidence; see File Events |
| Windows active_connect | listener_process, pid_name, exe, command_line, protocol, destination IP, destination port | Sysmon 3, Initiated=true, same-host/ProcessGuid Sysmon 1 |
| Windows powershell_script_block | provider, channel, user_sid, Path, whole-script SHA-256 | Complete native 4104 fragments; native empty Path is valid |

Windows listener_process is a literal empty string; other process fields must be
complete. pid_name comes from exe. Matching uses the normalized fields above
without folding command whitespace/case or using wildcards. file_paths order is
significant. Linux command_line keeps the existing space-joined argv format;
identical joined strings represent identical fields.
Starting in 0.3.85, Linux exec does not use adapter completeness or reason
diagnostics as candidate/matching gates. Missing EXECVE, PROCTITLE fallback,
truncated arguments and failed executions count when the four fields are valid
and the source event ID is verifiable. success, exit and reason diagnostics are
not match keys. Different actual commands captured as the same truncated string
therefore share admission and filtering. This explicitly matches collected
fields; it does not reconstruct the original command. Use shadow or disable
learning to retain those originals.
Windows destination uses normalized dst_ip/dst_port. Source IP/ephemeral port,
numeric PID, ProcessGuid, parent, user, file digest and file action are not
additional process/network/file keys. PowerShell SID is one of its own keys;
empty Path is a literal value, never a wildcard.

The old service-account, image-directory, tool, private-address/port, CDXML-class,
three-hour-bucket, six-hour-span, P95-rate, ten-minute-warmup, thirty-day-expiry
and ancestor-replay policies no longer control installed learning adapters.
Learning reduces output without changing process tracking or blocking execution;
admission is not a safety verdict. Bursts do not automatically bypass an admitted
behavior. Use shadow or disable learning when complete original history is needed.

Scope: authentication, persistence, identity/service changes and recognized
high/critical risk alerts retain their existing output rules. Snapshots retain
their delta mechanism. Linux connections were not integrated with learning and
still emit originals. Learning does not install Sysmon, add audit/Sysmon source
rules, change severity filtering, remove Agent self-noise exclusions or expand
collection scope. Windows network/file events must already exist at the source.

## Shared Flow

1. Existing collectors parse, classify and attribute the event.
2. Missing required match fields, invalid fields or an unverifiable source ID
   retain originals without training. Linux exec command truncation/incompleteness
   and adapter reasons do not block counting; other streams still require complete
   evidence, valid correlation and nonhistorical records.
3. Only distinct source records count; retrying one record cannot supply five hits.
4. While healthy and learning, an unknown tuple records reception times within
   the last hour.
5. The fifth hit appends a durable admission journal entry before suppression.
   Failure retains the original and degrades the baseline.
6. A healthy admitted match is counted and filtered; shadow retains its original.
7. Learning completion removes candidates and freezes admissions. Unknown
   behaviors continue to emit. Empty completion is enforcing + baseline_empty
   with filtering_active=false, not degradation solely due to an empty list.

Exactly sixty minutes remains inside the window. Healthy learning time and the
rolling clock differ: downtime/unhealthy input does not advance healthy time but
does not pause the real one-hour window. Windows accepts only records after the
current reader started, at most ten minutes delayed and one minute ahead. This
excludes lookback; it is not an admission warmup. Security 4688 and Sysmon 1 are
separate native records, not a promise of cross-channel exactly-once execution counts.

## Installation Choices and Status (0.3.71)

Linux install.sh/Bootstrap accepts --learning-mode preserve|shadow|enable|disable.
Windows uses -LearningMode with the same semantics; both default to preserve.

| Choice | Behavior |
| --- | --- |
| preserve | Fresh installs use first-day-learning templates; upgrades retain existing choices and absent configuration remains disabled |
| shadow | Learn while retaining every original, including admitted matches |
| enable | Enable learning and immediate filtering on admission |
| disable | Stop learning/filtering while retaining state |

Preserved disabled configuration prints:
`behavior learning: disabled; reason=existing-config-preserved`.
These options neither reset generation nor repair corrupt state. Upgrades do not
silently enable previously disabled learning.

```bash
sudo secweaver-agent config set-learning-mode \
  -config /opt/secweaver-agent/etc/audit-port-execmon.json -mode enable
sudo systemctl restart secweaver-agent
sudo secweaver-agent doctor -config /opt/secweaver-agent/etc/config.json
```

Standard Linux configuration:

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

Omitted Linux event_types covers exec/file_op; an explicit list restricts scope.
Summaries default to 300 seconds; learning duration accepts one hour through seven days.
Legacy min_occurrences, min_distinct_hours, min_span_seconds and
baseline_idle_expiry_days remain parseable but no longer control any integrated
simple policy. Resource/path parameters remain effective. Unknown fields reject
the learning configuration with a diagnostic while ordinary collection continues.

## Windows (0.3.39)

Current 0.3.83 source supports Windows amd64/arm64. The unified
windows-eventlog-risk-json reader and alternate windows-process-execmon share
one adapter; only one reader may own evidence output.
A registered SECWEAVER_DEVICE_ID, readable native channels and full commands are
required. 4688 no longer requires Sysmon hashes, parents or service tokens.
A 4688-only deployment must keep every configured channel query healthy;
a configured but unavailable Sysmon or other channel still stops filtering and
retains originals through the source-fault path.

Use these arguments on the reader that owns evidence output:

```text
-behavior-learning
-learning-duration 24h
-learning-generation 0
-learning-shadow=false
-learning-event-types exec,active_connect,file_op
```

Fresh templates select all three types; omitted learning-event-types remains
exec-only. learning-file-roots remains accepted for compatibility without
restricting file admission. learning-state-dir and learning-output override the
default absolute paths.

File/network adapters share a host+ProcessGuid command cache without live-PID
queries or hashing subprocesses: at most 1024 entries/4 MiB, one-hour idle expiry,
one sweep per minute. Exit, source faults or conflicting exe immediately remove
the context. It is not persisted across restarts; preexisting processes without
an observed create retain originals for file/network events.
Sysmon 3 needs existing source configuration. Inbound/unknown direction and
invalid addresses/protocols/ports do not train. Public targets and SSH/RDP ports
no longer fail admission merely because of their destination class.

## Windows Risk Logs (0.3.78)

0.3.83 applies the shared five-hit rule to ordinary PowerShell 4104 blocks,
including any known SID, business scripts, ordinary paths and inline empty Path.
SYSTEM and built-in CDXML classes are no longer required. Whole-script SHA-256
includes whitespace. PID, ScriptBlockId and record IDs assemble/deduplicate
evidence but do not define the behavior. high/critical alerts and suspicious
commands detected across fragment boundaries retain originals.

```text
-risk-behavior-learning
-risk-learning-duration 24h
-risk-learning-generation 0
-risk-learning-shadow=false
```

Fresh templates enable this; upgrades preserve choices. Risk state is independent
of exec/file/network: use risk-learning-generation, not learning-generation, to
reset it. Default state is behavior-learning-windows-risk beside the cursor;
risk-learning-state-dir overrides it. Only native PowerShell Operational/4104 is
required, independently of Sysmon.

Fragments can span query pages, but cannot remain only in memory across a
committed polling round: at most 64 fragments, 512 KiB per full script,
64 pending scripts and an 8 MiB assembly budget. One whole script counts once;
five fragments cannot supply five occurrences. Missing/conflicting/oversized
groups emit all available originals before the cursor checkpoint. Existing
classification runs again on the assembled script to catch split suspicious text.

Risk summaries remain in windows-eventlog-risk-json.log and use the existing
host-sys-messages/ES risk route: asset_type=host_behavior_summary,
source_stream=windows_risk, source_event_type=powershell_script_block,
count_unit=script_blocks, risk_level=info. Native event_id=4104 remains intact;
script_block_sha256 describes the whole script, unlike each fragment's script_sha256.
Exit suppression statistics count fragments. No new shipper route is required.

## File Events (0.3.82)

Linux audit file_op and Windows Sysmon 11/23 use the same five-field rule.
file_paths is ordered. Create/overwrite/delete/read actions, suffixes and
directories are not extra gates; equal tuples combine counts, including sensitive
paths. Independent persistence/risk records remain unaffected. Sysmon 11 create
includes creation or overwrite and does not describe content differences.

Linux needs complete PATH groups and either complete EXECVE or valid PROCTITLE
shorter than 128 bytes. Missing/capped evidence emits originals; PROCTITLE is a
mutable sampled process title, not immutable launch-argument proof.
Windows fills the command only from same-host/ProcessGuid Sysmon 1, with a literal
empty listener. It preserves path and emits file_paths, pid_name,
listener_process and command_line.

## State, Migration and Recovery

| Baseline | Default State Location |
| --- | --- |
| Linux exec | /opt/secweaver-agent/data/behavior-learning |
| Linux file_op | Above directory/file-operations |
| Windows exec | Cursor directory/behavior-learning-windows |
| Windows file_op | Windows exec directory/file-operations |
| Windows active_connect | Windows exec directory/network-operations |
| Windows PowerShell | Cursor directory/behavior-learning-windows-risk |

Each directory owns key, initialized, lock, state.json and admissions.jsonl.
Linux permissions are 0700 directories/0600 files; Windows uses protected
SYSTEM/Administrators ACLs and exclusive handles. Baselines persist only HMAC
fingerprints, counts, times and progress, not commands/scripts. Matching precedes
output redaction so distinct secrets do not collapse into one behavior.
Existing schema_version=1 remains readable.

Version 0.3.85 preserves the Linux exec policy hash, baseline_id, admitted entries,
candidates and learning progress; it does not restart learning automatically.
Hosts still learning count newly received events, without replaying old logs to
fill counters. Finished/degraded baselines do not gain entries from this relaxed
gate; explicitly relearn using the recovery procedure below. Rolling back keeps
the same state format, but old code emits incomplete-command originals again.

The first Linux 0.3.81 or Windows exec/PowerShell 0.3.83 migration authenticates
the same device, generation and old policy hash. A complete readable old state is
archived as legacy-state.json, then a new baseline_id starts learning without
importing old entries. Windows reports simple_policy_migrated; Linux keeps
simple_exec_policy_migrated. Old network entries stay in the archived exec state
while network-operations starts independently. Existing 0.3.82 file baselines
retain progress. Only enabled adapters migrate; disk configuration is unchanged.
Foreign-device, mismatched-policy or corrupt state is never treated as a fresh install.

Normal shutdown flushes originals, summaries and state before marking clean.
Clean restarts retain entries, candidates and healthy progress. Every current
policy can match again with healthy input, without the old ten-minute wait.
Missing health pauses learning/filtering. Known loss, overflow, sink/persistence
failure, broken continuity, unclean restart or clock regression degrades the
generation and subsequent originals remain. Sysmon 8/25 retains its integrity
fault protection. The online learning deadline defaults to 72 hours; failure to
accumulate the required healthy duration by then degrades learning.

For readable degraded state, back up and increase the appropriate generation,
then restart to relearn explicitly. For corruption, disable learning and back up
the whole directory, fix disk issues, and select a new state_dir during stopped
maintenance. Do not edit HMAC state, delete only state.json or copy another host's
baseline. Before rollback, stop and back up, then restore the legacy archive or
disable learning. There is no per-entry edit or remote-revocation API.

Each engine defaults to 10000 entries, 20000 candidates and 64 MiB memory/state
budgets; conservative byte admission may stop earlier. Source-ID HMAC dedup lasts
one hour with at most 65536 entries. A candidate holds at most five reception
times. Capacity failures emit without training. Linux has a 128-event queue and
64 KiB event ceiling. Windows processes synchronously before cursor commits.
Admissions are journaled before filtering; a 60-second checkpoint compacts the
journal. There are no per-event full-map scans and no archive of every suppressed
original. A crash may lose recent candidates/counters; degradation cannot restore
previously filtered originals or guarantee exactly-once/complete forensic history.

## Diagnostics and Shipping

Doctor reports independent exec, file, network and risk baselines. Windows keys
are exec-learning/status, file-learning/status, network-learning/status and
risk-learning/status; Linux retains learning/status and file-learning/status.
filtering_active requires healthy input, non-shadow mode and a nonempty valid
baseline. Both learning and enforcing can filter. Inspection reads authenticated
checkpoints and at most 128 KiB of summary tail without taking the writer lock;
checkpoint progress can lag sixty seconds. Missing/stale startup summaries do
not prove filtering readiness.

The existing SaaS behavior_learning heartbeat describes only the main exec
baseline, not every independent stream, and keeps the default three-minute cadence.
Gateway 0.6.0-rc.72+ accepts learning + filtering_active; Workspace rc.112+
displays it. Deploy compatible servers before enabling new Agents.

Process/file/connection summaries remain in behavior-learning.log beside the
event log. Linux exec originals use decision_reason for the learning/output
decision, such as learning, shadow, baseline_miss or a fault; incomplete commands
no longer reject candidates. Optional command_evidence_reason preserves adapter
diagnostics such as incomplete_or_truncated_command, without affecting matching
or counting. Existing collected fields such as command_truncated remain; an
absent truncation flag is not proof that argv is complete.
Group by baseline_id/source_event_type. behavior_summary and
behavior_learning_status are not raw host_exec events or PID-tree edges.
fingerprint_version is Linux exec=2, file=3, new Windows exec/network/PowerShell=4.
No new ancestor replays are produced. Complete counters satisfy
observed_count=suppressed_count+original_emitted_count; pre-admission originals
are not recounted. Deduplicate summary_id; counter_complete=false/restart gaps
cannot be interpreted as complete execution counts.

ES uses the existing behavior-learning binding, summary index and keyword
mappings. SLS/Logtail must bind behavior-learning.log to the custom-identifier
machine group and summary Logstore; see logtail/behavior-learning.example.json.
Managed Windows installation requires the signed collection contract to include
summaries. Learning readiness does not prove delivery: verify local and ES/SLS
originals, summaries and status after deployment.

## Verification and Limits

```bash
make check
go test ./pkg/behaviorlearning ./internal/windowsevidence ./pkg/windowseventlogriskjson
go test ./pkg/behaviorlearning -run '^$' -bench BenchmarkSimpleExecKnown -benchmem
```

Regressions cover failed exec without EXECVE, truncated-command admission and
separate diagnostics, other streams' completeness gates, fourth/fifth boundaries,
window expiry, exact field changes,
deduplication, freeze, shadow, persistence failures, migration/clean restart,
GUID reuse, cache budgets and whole-script/fragment counts.
Cross-platform builds do not replace native Linux audit/eBPF, Windows Event
Log/SCM, 24-hour learning or ES/SLS delivery acceptance. Source changes do not
publish or deploy binaries.

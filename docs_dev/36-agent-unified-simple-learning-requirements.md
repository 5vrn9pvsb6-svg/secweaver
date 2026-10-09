# Agent Unified Simple Learning Requirements

**Language:** English | [简体中文](36-agent-unified-simple-learning-requirements.zh-CN.md)

Applies to Agent source 0.3.83, following 0.3.81 exec and 0.3.82 file_op.
Scope comes from the user's request to simplify the remaining complex learning
logic in the same way. Retain five events per hour, immediate fifth-hit filtering,
first-day learning and the agreed empty Windows listener.
No database, new toggle or deployment operation is introduced; state remains
protected HMAC JSON and an admission journal.

## Behavior Contract

| Stream | Match Fields |
| --- | --- |
| Windows exec | Empty listener_process, pid_name, exe, complete command_line |
| Windows active_connect | The four process fields, protocol, destination IP and port |
| Windows PowerShell 4104 | provider, channel, user_sid, Path, whole-script SHA-256 |

All streams reuse the rolling-hour/five-hit counter already used by Linux/files.
Durable fifth-hit admission filters immediately while other behaviors continue
learning. After 24 healthy hours, only new admissions freeze. An empty baseline
does not degrade solely due to its size. Remove service identity, parent hashes,
path prefixes, tool lists, private-address/port lists, CDXML classes and old rate
models. Complete native 4688 commands can participate with healthy configured
sources; Sysmon 1 no longer needs SHA256. Record IDs/GUIDs deduplicate/correlate
evidence without entering stable keys. Missing fields are never wildcards.

Network targets use normalized dst_ip/dst_port; source IP/port is excluded.
Only source-proven outbound connections qualify, with protocol/address/port
completeness checks. File/network commands come from same-host/GUID creation
records, never current-PID lookup. Empty PowerShell Path is a valid inline
origin; a complete script counts once, not once per fragment.

## Preserved Boundaries

- Existing Linux exec/file exact policies remain compatible. Linux network had no learning adapter and retains originals.
- Authentication, persistence, identity/service changes and snapshots gain no whitelist; recognized high/critical risk alerts still emit.
- Missing fields, history, source/sink/persistence faults and capacity limits retain originals.
- Process tracking, risk classification, collection scope, severity filtering and Agent self-noise exclusions retain existing behavior.
- Shadow, activation and configured scope remain explicit; upgrades never enable previously disabled learning.

## Migration and Acceptance

Compatible readable legacy Windows exec/risk state is archived before new learning
starts; no old entries are imported. Network creates independent state and file
progress remains intact. Clean restarts retain new entries; fault recovery still
requires explicit generation. Summaries identify source_event_type and doctor
reports each baseline. SaaS keeps the existing main-exec heartbeat contract.

Acceptance covers fifth-hit boundaries, expiry, field changes, replay dedup,
freeze, shadow, persistence failures, compatible migration and clean restart,
including native-shaped Windows records through classification and JSONL output.
Go/race tests and cross-platform builds validate source; native Windows/SLS/ES
and long-duration acceptance require deployment. See the [operating guide](../src/tools/secweaver-agent/docs/behavior-learning.md)
for configuration, budgets and recovery.

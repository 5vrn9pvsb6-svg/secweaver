# Agent Simple File Learning Requirements

Status: implementation authorized by the user. Applies to Agent 0.3.82.

## Scope and Rules

- Linux audit `file_op` and Windows Sysmon 11/23 use an independent file baseline.
- Match exactly `file_paths`, `listener_process`, `pid_name`, `exe`, and `command_line`. Preserve array order, case, whitespace, paths and arguments.
- Windows uses the literal empty string for `listener_process`; all other fields must be complete. Obtain commands only from Sysmon 1 on the same host and ProcessGuid, never from PID guesses or an executable fallback.
- Five distinct source events in a rolling hour admit a behavior during learning; suppress the fifth immediately. Emit the first four. Default learning is one healthy day; completion freezes new admissions.
- Action, user, suffix, directory, executable hash and ancestry are not admission gates. Create/delete share a counter when the five fields match. Independent `host-persistence` output is unaffected.
- Retain enable/shadow, explicit event_types scope and generation-based relearning. Linux without explicit event_types covers exec/file_op; Windows respects installation arguments.
- Missing/truncated fields, unavailable correlation, source faults, capacity limits and persistence failures preserve originals. This feature does not enable additional kernel rules.

## Acceptance

Cover immediate fifth-event filtering, every field mutation, hour boundaries, replay deduplication, shadow, health faults, stop/restart and cursor ordering. Verify Windows GUID isolation/missing commands and incomplete Linux PATH/PROCTITLE. Keep exec, network, PowerShell and risk regression tests passing.

# Agent Simple File Learning Architecture

Implements the [requirements](34-agent-simple-file-learning-requirements.md), Agent 0.3.82.

## Flow and Ownership

Normalized file_op → platform completeness/correlation → five-field HMAC → rolling-hour count → durable fifth admission before suppression → behavior-learning.log summaries.

Reuse the bounded exact engine, admission journal, healthy clock and fail-open handling. File state lives in `file-operations/` under the existing learning directory with a platform-specific strategy; do not import old file entries. Preserve existing exec/network policies and progress. Each engine has independent configured resource ceilings.

Linux reuses the bounded queue and single worker, without another audit reader. Require complete PATH items and complete EXECVE or PROCTITLE below the kernel length cap. PROCTITLE is a kernel-sampled process title, not immutable startup argv; absent, invalid or capped titles cannot train.

Windows reuses the unified reader with an independent host+ProcessGuid command cache (1024 entries, 4 MiB, one-hour idle expiry). Cache genuine Sysmon 1 CommandLine independently of legacy exec eligibility. Exit, duplicate/conflicting creates and source continuity faults invalidate context. The cache is not persisted; missing context after restart preserves file originals. The same mutex owns both engines and caches. Both engines and sinks must checkpoint before the source cursor commits.

## Contract and Status

Windows file_op retains `path` and adds `file_paths`, `pid_name` and literal empty `listener_process`; correlated events also carry command/command_line. File fingerprint version is 3; Linux exec remains version 2. Baselines store keyed hashes and counts, never command text.

Both engines share the existing summary file. File summaries carry `source_event_type=file_op`; status reads select a matching baseline to avoid replacing exec health with file health. Existing host learning heartbeats still describe the original exec/activity baseline; inspect file summaries or the separate status reader for file progress.

## Failure and Verification

Queue overflow, source loss and shared sink failures invalidate both engines. File state initialization failure alone preserves file originals. Test journal failure, cursor ordering, cache capacity/invalidation, exact matching and platform isolation. Cross compilation does not replace live Windows Sysmon/Linux audit acceptance.

2026-10-08 source verification: `make check` (fmt/vet, full tests, race tests and Linux/Windows amd64 builds), Linux/Windows arm64 builds, `make docs-check` and `git diff --check` passed. Final adapter cleanup additionally passed auditportexecmon/windowsevidence race regressions, including native audit multi-record assembly through the learning boundary. No release archive, deployment or live-host/SLS acceptance was performed.

package auditportexecmon

import (
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"secweaver-agent/pkg/behaviorlearning"
)

const fileRecordSettleDelay = 250 * time.Millisecond

// fileRecordPending keeps all PATH records and the sampled command together.
// The first PATH is not an end marker: filtering it before the rest arrive can
// discard a later sensitive path. A fixed deadline from the primary record
// bounds latency even when a damaged source keeps adding auxiliary records.
// An explicit age-based flush still permits partial evidence, never admission.
func fileRecordPending(acc *auditAccumulator, now time.Time, maxAge time.Duration) bool {
	return maxAge == 0 && !completeFileEvidence(acc) && now.Sub(acc.firstSeen) < fileRecordSettleDelay
}

// resolveFileCommand preserves spaces inside the sampled title. The exec
// display fallback tokenizes short titles; using that fallback for file keys
// would merge titles that differ only in whitespace.
func resolveFileCommand(acc *auditAccumulator, comm string) []string {
	if completeAuditArgv(acc) {
		return orderedArgs(acc.argv)
	}
	if title, err := hexStringToBytes(acc.proctitle); err == nil && len(title) > 0 {
		return strings.Split(strings.TrimRight(string(title), "\x00"), "\x00")
	}
	return resolveAuditCommand(acc, comm)
}

// completeFileEvidence rejects partial PATH groups and capped/invalid titles.
// File syscalls have no EXECVE record, so PROCTITLE is the normal command source.
// It describes the kernel-sampled title, not an immutable launch-time argv.
func completeFileEvidence(acc *auditAccumulator) bool {
	return fileEvidenceReason(acc) == ""
}

// completeFilePaths proves the full indexed group is available before a
// negative sensitive-path decision; a partial group cannot prove absence.
func completeFilePaths(acc *auditAccumulator) bool {
	items, err := strconv.Atoi(acc.fields["items"])
	if err != nil || items < 1 || items > 64 || items != len(acc.paths) {
		return false
	}
	for i := 0; i < items; i++ {
		if acc.paths[i] == "" || acc.paths[i] == "(null)" || !utf8.ValidString(acc.paths[i]) {
			return false
		}
	}
	return true
}

// fileEvidenceReason is bounded diagnostic metadata, never raw path/command
// content. Invalid or capped titles retain originals instead of qualifying.
func fileEvidenceReason(acc *auditAccumulator) string {
	if !completeFilePaths(acc) {
		return "incomplete_file_paths"
	}
	if completeAuditArgv(acc) {
		return ""
	}
	if !acc.seenProctitle {
		return "missing_file_command"
	}
	title, err := hexStringToBytes(acc.proctitle)
	if err != nil || len(title) == 0 || !utf8.Valid(title) {
		return "invalid_file_command"
	}
	// MAX_PROCTITLE_AUDIT_LEN is 128; at that boundary completeness is unknown.
	if len(title) >= 128 {
		return "capped_file_command"
	}
	return ""
}

// fileLearningObservation matches normalized fields verbatim. Source IDs only
// deduplicate reader retries; actions and identity metadata are not match keys.
func fileLearningObservation(e auditEvent, backend, boot string) behaviorlearning.Observation {
	o := execLearningObservation(e, backend, boot)
	o.Context = behaviorlearning.Context{File: &behaviorlearning.FileFields{
		ExecFields: behaviorlearning.ExecFields{ListenerProcess: e.ListenerProcess, PIDName: e.PIDName, Exe: e.Exe, CommandLine: e.CommandLine},
		FilePaths:  e.FilePaths,
	}}
	o.Complete = !e.CommandTruncated && e.Fields["learning_file_fields_complete"] == "yes"
	o.Reason = ""
	if !o.Complete {
		o.Reason = e.Fields["learning_file_incomplete_reason"]
		if o.Reason == "" {
			o.Reason = "incomplete_file_evidence"
		}
	}
	return o
}

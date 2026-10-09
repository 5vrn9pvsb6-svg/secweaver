package auditportexecmon

import (
	"strconv"
	"strings"
	"unicode/utf8"

	"secweaver-agent/pkg/behaviorlearning"
)

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
	items, err := strconv.Atoi(acc.fields["items"])
	if err != nil || items < 1 || items > 64 || items != len(acc.paths) {
		return false
	}
	for i := 0; i < items; i++ {
		if acc.paths[i] == "" || acc.paths[i] == "(null)" || !utf8.ValidString(acc.paths[i]) {
			return false
		}
	}
	if completeAuditArgv(acc) {
		return true
	}
	if !acc.seenProctitle {
		return false
	}
	title, err := hexStringToBytes(acc.proctitle)
	// MAX_PROCTITLE_AUDIT_LEN is 128 in the supported audit record format.
	// At that boundary completeness is unknown; retain the original instead.
	return err == nil && len(title) > 0 && len(title) < 128 && utf8.Valid(title)
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
		o.Reason = "incomplete_file_evidence"
	}
	return o
}

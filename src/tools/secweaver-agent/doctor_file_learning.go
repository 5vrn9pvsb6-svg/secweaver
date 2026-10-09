package main

import (
	"fmt"

	"secweaver-agent/pkg/behaviorlearning"
)

// doctorReportFileLearning keeps the separate file baseline observable without
// changing the legacy host heartbeat contract or querying native event sources.
func doctorReportFileLearning(status behaviorlearning.StatusSnapshot, err error, add func(doctorLevel, string, string, string)) {
	doctorReportStreamLearning("file", status, err, add)
}

// doctorReportStreamLearning gives each independent baseline its own status;
// an active exec baseline is never evidence of file or network suppression.
func doctorReportStreamLearning(stream string, status behaviorlearning.StatusSnapshot, err error, add func(doctorLevel, string, string, string)) {
	if err != nil {
		add(doctorWarn, stream+"-learning/status", "Learning state is unavailable or invalid", err.Error())
		return
	}
	level := doctorOK
	if status.Enabled && (status.Mode == "unknown" || status.Mode == "degraded" || status.UpdatedAt == "") {
		level = doctorWarn
	}
	add(level, stream+"-learning/status", "Behavior learning status", fmt.Sprintf("enabled=%t mode=%s started_at=%s remaining_seconds=%d filtering_active=%t baseline_entries=%d candidate_entries=%d updated_at=%s reason=%s",
		status.Enabled, status.Mode, status.StartedAt, status.RemainingSeconds, status.FilteringActive, status.BaselineEntries, status.CandidateEntries, status.UpdatedAt, status.Reason))
}

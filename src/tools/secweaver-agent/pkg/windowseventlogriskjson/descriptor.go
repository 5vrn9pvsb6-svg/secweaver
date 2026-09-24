package windowseventlogriskjson

import (
	"secweaver-agent/internal/modulecontract"
	"secweaver-agent/internal/windowsevidence"
	"secweaver-agent/pkg/layout"
)

// Descriptor defines the unified Windows Event Log reader contract.
func Descriptor() modulecontract.Descriptor {
	return modulecontract.Descriptor{
		Name:        "windows-eventlog-risk-json",
		Description: "Windows Event Log risk parser that emits JSON Lines",
		Platforms:   []string{"windows"},
		Flags: modulecontract.Flags(
			[]string{"channels", "output", "evidence-output", "state-file", "lookback", "poll-interval", "max-events", "min-level", "learning-duration", "learning-generation", "learning-state-dir", "learning-output", "learning-event-types", "learning-file-roots"},
			[]string{"once", "raw", "fail-on-query-error", "stats", "version", "behavior-learning", "learning-shadow"},
		),
		OutputPaths: descriptorOutputPaths,
		Run:         Main,
	}
}

// descriptorOutputPaths reports both files owned by the unified reader. An
// explicitly empty evidence-output disables that second output and transfers
// ownership to an optional standalone reader.
func descriptorOutputPaths(args []string) []string {
	riskPath := layout.WindowsLogs + `\windows-eventlog-risk-json.log`
	if value, ok := modulecontract.StringFlag(args, "output"); ok {
		riskPath = value
	}
	evidencePath := layout.WindowsLogs + `\windows-process-execmon.log`
	if value, ok := modulecontract.StringFlag(args, "evidence-output"); ok {
		evidencePath = value
	}
	paths := []string{riskPath}
	if evidencePath != "" {
		paths = append(paths, evidencePath)
	}
	return windowsevidence.WithLearningOutput(args, evidencePath, paths)
}

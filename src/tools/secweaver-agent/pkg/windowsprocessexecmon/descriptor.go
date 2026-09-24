package windowsprocessexecmon

import (
	"secweaver-agent/internal/modulecontract"
	"secweaver-agent/internal/windowsevidence"
	"secweaver-agent/pkg/layout"
)

// Descriptor defines the standalone Windows evidence reader contract. The
// supervisor prevents it from competing with the unified reader for one stream.
func Descriptor() modulecontract.Descriptor {
	return modulecontract.Descriptor{
		Name:        "windows-process-execmon",
		Description: "Windows process/network/file evidence collector from Security and Sysmon events",
		Platforms:   []string{"windows"},
		Flags: modulecontract.Flags(
			[]string{"channels", "output", "state-file", "lookback", "poll-interval", "max-events", "learning-duration", "learning-generation", "learning-state-dir", "learning-output", "learning-event-types", "learning-file-roots"},
			[]string{"once", "raw", "fail-on-query-error", "stats", "version", "behavior-learning", "learning-shadow"},
		),
		OutputPaths: func(args []string) []string {
			paths := modulecontract.FlagOutputPaths(layout.WindowsLogs+`\windows-process-execmon.log`, "output")(args)
			return windowsevidence.WithLearningOutput(args, paths[0], paths)
		},
		Run: Main,
	}
}

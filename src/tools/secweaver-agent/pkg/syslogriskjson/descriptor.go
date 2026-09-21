package syslogriskjson

import (
	"secweaver-agent/internal/modulecontract"
	"secweaver-agent/pkg/layout"
)

// Descriptor defines the syslog collector's complete supervisor contract.
func Descriptor() modulecontract.Descriptor {
	return modulecontract.Descriptor{
		Name:        "syslog-risk-json",
		Description: "Linux syslog/auth risk parser that emits JSON Lines",
		Platforms:   []string{"linux"},
		Flags: modulecontract.Flags(
			[]string{"secure", "messages", "output", "year", "min-level", "lookback", "poll-interval", "rules-file"},
			[]string{"raw", "stats", "fail-on-read-error", "once", "backfill", "version"},
		),
		OutputPaths: modulecontract.FlagOutputPaths(layout.LinuxLogs+"/syslog-risk-json.log", "output"),
		Run:         Main,
	}
}

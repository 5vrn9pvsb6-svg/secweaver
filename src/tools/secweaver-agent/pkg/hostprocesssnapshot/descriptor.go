package hostprocesssnapshot

import "secweaver-agent/internal/modulecontract"

// Descriptor defines process snapshot capabilities without exporting its
// internal state, delta, or platform collection implementation.
func Descriptor() modulecontract.Descriptor {
	return modulecontract.Descriptor{
		Name:        "host-process-snapshot",
		Description: "Linux/Windows daily process baseline with periodic process deltas",
		Platforms:   []string{"linux", "windows"},
		Flags: modulecontract.Flags(
			[]string{"output", "state", "host-ip", "interval", "full-snapshot-interval", "collection-timeout"},
			[]string{"once", "redact-sensitive", "stats", "version"},
		),
		OutputPaths:           modulecontract.FlagOutputPaths(defaultOutputPath(), "output"),
		UpgradeOutputRequired: true,
		Run:                   Main,
	}
}

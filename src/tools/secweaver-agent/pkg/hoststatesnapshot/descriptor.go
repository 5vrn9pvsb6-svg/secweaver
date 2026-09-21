package hoststatesnapshot

import "secweaver-agent/internal/modulecontract"

// Descriptor defines host state snapshot capabilities for the supervisor.
func Descriptor() modulecontract.Descriptor {
	return modulecontract.Descriptor{
		Name:        "host-state-snapshot",
		Description: "Linux/Windows listening sockets, identities, services, scheduled tasks, kernel, and container context",
		Platforms:   []string{"linux", "windows"},
		Flags: modulecontract.Flags(
			[]string{"output", "state", "host-ip", "socket-interval", "identity-interval", "service-interval", "kernel-interval", "full-snapshot-interval", "max-fd-scan"},
			[]string{"container-workload", "once", "stats", "version"},
		),
		OutputPaths:           modulecontract.FlagOutputPaths(defaultOutputPath(), "output"),
		UpgradeOutputRequired: true,
		Run:                   Main,
	}
}

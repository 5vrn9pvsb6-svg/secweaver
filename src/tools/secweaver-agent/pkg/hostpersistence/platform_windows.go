//go:build windows

package hostpersistence

// copyDefaultTargets returns an owned slice because configuration normalization
// mutates target values and must never alter the package-level default catalog.
func copyDefaultTargets() []watchTarget {
	out := make([]watchTarget, len(defaultWindowsWatchTargets))
	copy(out, defaultWindowsWatchTargets)
	return out
}

func defaultOutputLogPath() string {
	return defaultWindowsOutputLog
}

func defaultStatePath() string {
	return defaultWindowsStatePath
}

// defaultAuditRuntimeConfig disables Linux auditd integration on Windows while
// preserving the same config shape for cross-platform packaged examples.
func defaultAuditRuntimeConfig() auditRuntimeConfig {
	return auditRuntimeConfig{
		Enabled:     false,
		AuditLog:    defaultAuditLogPath,
		Key:         defaultAuditKey,
		Perm:        defaultAuditPerm,
		ManageRules: false,
		FollowLog:   false,
	}
}

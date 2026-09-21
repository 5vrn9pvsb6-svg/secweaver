//go:build !windows

package hostpersistence

// copyDefaultTargets returns an owned slice because configuration normalization
// mutates target values and must never alter the package-level default catalog.
func copyDefaultTargets() []watchTarget {
	out := make([]watchTarget, len(defaultLinuxWatchTargets))
	copy(out, defaultLinuxWatchTargets)
	return out
}

func defaultOutputLogPath() string {
	return defaultLinuxOutputLog
}

func defaultStatePath() string {
	return defaultLinuxStatePath
}

// defaultAuditRuntimeConfig enables actor enrichment on supported Linux hosts.
// The CLI rejects other non-Windows collection targets before this default can
// start a reader, while retaining buildability on development workstations.
func defaultAuditRuntimeConfig() auditRuntimeConfig {
	return auditRuntimeConfig{
		Enabled:     true,
		AuditLog:    defaultAuditLogPath,
		Key:         defaultAuditKey,
		Perm:        defaultAuditPerm,
		ManageRules: true,
		FollowLog:   true,
	}
}

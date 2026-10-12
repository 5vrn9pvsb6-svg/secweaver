//go:build !linux

package auditportexecmon

// The collector cannot attach on non-Linux systems. Tests inject a clock with
// the same epoch as their synthetic kernel events.
func attributionMonotonicNS() uint64 { return 0 }

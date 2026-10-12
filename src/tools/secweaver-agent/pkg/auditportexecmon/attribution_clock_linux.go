//go:build linux

package auditportexecmon

import "golang.org/x/sys/unix"

// BPF timestamps use CLOCK_MONOTONIC, not wall time or CLOCK_BOOTTIME. A failed
// clock read disables historical BPF recovery instead of mixing clock domains.
func attributionMonotonicNS() uint64 {
	var ts unix.Timespec
	if unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts) != nil || ts.Sec < 0 {
		return 0
	}
	return uint64(ts.Nano())
}

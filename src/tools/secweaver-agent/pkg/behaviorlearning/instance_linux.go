//go:build linux

package behaviorlearning

import (
	"fmt"
	"golang.org/x/sys/unix"
	"strconv"
	"strings"
	"time"
)

// verifyAuditInstance requires the audited executable inode/device to match
// the running image. Ancient events and process instances born after the event
// are rejected; wall-clock discontinuities therefore reduce coverage, not trust.
func verifyAuditInstance(in Execution, process processView) error {
	inode, err := strconv.ParseUint(in.Inode, 10, 64)
	if err != nil || inode == 0 {
		return fmt.Errorf("missing audited inode")
	}
	parts := strings.Split(in.Device, ":")
	if len(parts) != 2 {
		return fmt.Errorf("missing audited device")
	}
	major, err := strconv.ParseUint(parts[0], 16, 32)
	if err != nil {
		return err
	}
	minor, err := strconv.ParseUint(parts[1], 16, 32)
	if err != nil {
		return err
	}
	var st unix.Stat_t
	if err = unix.Stat(fmt.Sprintf("/proc/%d/exe", in.PID), &st); err != nil {
		return err
	}
	if st.Ino != inode || unix.Major(uint64(st.Dev)) != uint32(major) || unix.Minor(uint64(st.Dev)) != uint32(minor) {
		return fmt.Errorf("audited image differs")
	}
	if in.Backend == "ebpf" {
		start, err := strconv.ParseUint(process.Start, 10, 64)
		if err != nil || in.StartBootNS == 0 || in.StartBootNS/10000000 != start {
			return fmt.Errorf("kernel process start differs")
		}
		return nil
	}
	seconds, err := strconv.ParseFloat(in.SourceTime, 64)
	if err != nil {
		return err
	}
	if seconds <= 0 {
		return fmt.Errorf("missing event time")
	}
	elapsed := float64(time.Now().UnixNano())/1e9 - seconds
	if elapsed < 0 || elapsed > 2 {
		return fmt.Errorf("stale or clock-shifted event")
	}
	var boot unix.Timespec
	if err = unix.ClockGettime(unix.CLOCK_BOOTTIME, &boot); err != nil {
		return err
	}
	start, err := strconv.ParseUint(process.Start, 10, 64)
	if err != nil {
		return err
	}
	// Linux procfs exports starttime in USER_HZ (100 on supported targets).
	// One tick margin rejects ambiguous same-tick births instead of attributing
	// an old event to a recycled PID that happens to execute the same binary.
	eventBootSeconds := float64(boot.Sec) + float64(boot.Nsec)/1e9 - elapsed
	if float64(start+1)/100 > eventBootSeconds {
		return fmt.Errorf("ambiguous process birth")
	}
	return nil
}

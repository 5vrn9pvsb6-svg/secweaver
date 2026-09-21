package auditportexecmon

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

type processExecutionContext struct {
	AUID   string
	CWD    string
	TTY    string
	HasTTY *bool
}

// readProcExecutionContext enriches an eBPF exec while the process still
// exists. Every field is best-effort: a process can exit between the kernel
// event and these reads, and that race is represented as unknown rather than a
// fabricated value. tty_nr is authoritative for presence; fd links are used
// only to recover a human-readable terminal name.
func readProcExecutionContext(pid int) processExecutionContext {
	if pid <= 1 {
		return processExecutionContext{}
	}
	context := processExecutionContext{}
	if body, err := os.ReadFile(fmt.Sprintf("/proc/%d/loginuid", pid)); err == nil {
		context.AUID = normalizeProcLoginUID(string(body))
	}
	if cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid)); err == nil {
		context.CWD = cwd
	}
	if body, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid)); err == nil {
		if ttyNumber, ok := parseProcStatTTYNumber(string(body)); ok {
			hasTTY := ttyNumber != 0
			context.HasTTY = &hasTTY
			if hasTTY {
				context.TTY = readProcTTYName(pid)
			}
		}
	}
	return context
}

// parseProcStatTTYNumber reads field 7 (tty_nr) without splitting the
// parenthesized comm field, which may contain spaces or closing parentheses.
// The boolean reports whether the field was observed, independently of zero.
func parseProcStatTTYNumber(stat string) (int64, bool) {
	end := strings.LastIndex(stat, ")")
	if end < 0 || end+2 >= len(stat) {
		return 0, false
	}
	fields := strings.Fields(strings.TrimSpace(stat[end+1:]))
	// fields[0] is process state (field 3); tty_nr is field 7.
	if len(fields) <= 4 {
		return 0, false
	}
	ttyNumber, err := strconv.ParseInt(fields[4], 10, 64)
	if err != nil {
		return 0, false
	}
	return ttyNumber, true
}

func normalizeProcLoginUID(value string) string {
	value = strings.TrimSpace(value)
	if value == "-1" {
		return value
	}
	if _, err := strconv.ParseUint(value, 10, 32); err != nil {
		return ""
	}
	return value
}

// readProcTTYName does not infer TTY presence from redirected standard file
// descriptors. It runs only after tty_nr proved a controlling terminal exists;
// failure to find its device name leaves tty empty while has_tty remains true.
func readProcTTYName(pid int) string {
	for _, fd := range []int{0, 1, 2} {
		target, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", pid, fd))
		if err != nil {
			continue
		}
		target = strings.TrimSuffix(target, " (deleted)")
		if strings.HasPrefix(target, "/dev/pts/") || target == "/dev/tty" || target == "/dev/console" {
			return strings.TrimPrefix(target, "/dev/")
		}
	}
	return ""
}

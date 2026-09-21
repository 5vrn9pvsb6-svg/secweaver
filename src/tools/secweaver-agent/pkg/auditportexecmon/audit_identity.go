package auditportexecmon

import (
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"time"
)

// This file resolves host, account, command, and self-maintenance identity used during audit event enrichment.

func resolveHostIdentity() hostIdentity {
	name, err := os.Hostname()
	if err != nil {
		name = "unknown"
	}
	return hostIdentity{HostName: name, HostIP: primaryHostIP()}
}

func primaryHostIP() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	var fallback string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok || ipNet.IP.IsLoopback() {
				continue
			}
			ip4 := ipNet.IP.To4()
			if ip4 != nil {
				return ip4.String()
			}
			if fallback == "" {
				fallback = ipNet.IP.String()
			}
		}
	}
	return fallback
}

func resolveCommand(argv map[int]string, proctitle, exe, comm string) []string {
	// PROCTITLE is preferred because it preserves the complete NUL-separated
	// argv. EXECVE arguments are the fallback; comm/exe only prevent an otherwise
	// useful exec event from becoming empty when audit emits incomplete records.
	if decoded := decodeProctitle(proctitle); len(decoded) > 0 {
		return decoded
	}
	args := orderedArgs(argv)
	if len(args) > 0 && !argvLooksInvalid(args) {
		return args
	}
	if comm != "" {
		return []string{comm}
	}
	if exe != "" {
		return []string{exe}
	}
	return nil
}

// isSelfAuditctlMaintenance suppresses only SecWeaver rule maintenance. Generic
// administrator auditctl queries remain visible because they can be relevant
// security evidence; mutation commands targeting our keys are implementation
// noise and can otherwise recursively dominate the output.
func isSelfAuditctlMaintenance(fields map[string]string, command []string) bool {
	if !isAuditctlCommand(command) || !auditctlMaintenanceAction(command) {
		return false
	}
	if commandReferencesSecweaverAuditKey(command) {
		return auditctlRuleMutationAction(command) || auditEventProcessUnknown(fields)
	}
	return auditEventProcessUnknown(fields) && isSecweaverAuditKey(fields["key"])
}

func isAuditctlCommand(command []string) bool {
	if len(command) == 0 {
		return false
	}
	base := filepath.Base(cleanDeletedSuffix(command[0]))
	return base == "auditctl"
}

func auditctlMaintenanceAction(command []string) bool {
	for _, arg := range command[1:] {
		switch arg {
		case "-a", "-d", "-D", "-w", "-W", "-l", "-s":
			return true
		}
	}
	return false
}

func auditctlRuleMutationAction(command []string) bool {
	for _, arg := range command[1:] {
		switch arg {
		case "-a", "-d", "-D", "-w", "-W":
			return true
		}
	}
	return false
}

func auditEventProcessUnknown(fields map[string]string) bool {
	pidText := strings.TrimSpace(fields["pid"])
	ppidText := strings.TrimSpace(fields["ppid"])
	pid, pidErr := strconv.Atoi(pidText)
	ppid, ppidErr := strconv.Atoi(ppidText)
	pidUnknown := pidText == "" || (pidErr == nil && pid <= 0)
	ppidUnknown := ppidText == "" || (ppidErr == nil && ppid <= 0)
	if !pidUnknown || !ppidUnknown {
		return false
	}
	comm := strings.TrimSpace(fields["comm"])
	exe := strings.TrimSpace(fields["exe"])
	if comm == "" && exe == "" {
		return true
	}
	return comm == "auditctl" || filepath.Base(cleanDeletedSuffix(exe)) == "auditctl"
}

func commandReferencesSecweaverAuditKey(command []string) bool {
	for i, arg := range command {
		if isSecweaverAuditKey(arg) {
			return true
		}
		if strings.HasPrefix(arg, "key=") && isSecweaverAuditKey(strings.TrimPrefix(arg, "key=")) {
			return true
		}
		if (arg == "-k" || arg == "key" || arg == "-F") && i+1 < len(command) {
			next := command[i+1]
			if isSecweaverAuditKey(next) || (strings.HasPrefix(next, "key=") && isSecweaverAuditKey(strings.TrimPrefix(next, "key="))) {
				return true
			}
		}
		if arg == "-F" && i+2 < len(command) && command[i+1] == "key" && isSecweaverAuditKey(command[i+2]) {
			return true
		}
	}
	return false
}

func isSecweaverAuditKey(key string) bool {
	key = strings.Trim(strings.TrimSpace(key), `"`)
	return key == "tb_host_persistence" ||
		strings.HasPrefix(key, "tb_external_listener_") ||
		strings.HasPrefix(key, "tb_port_")
}

func execRecordPending(acc *auditAccumulator, now time.Time, maxAge time.Duration) bool {
	// A SYSCALL can arrive before EXECVE/PROCTITLE. The short settle window trades
	// a bounded amount of latency for a complete command line. Age-based flushes
	// bypass it to guarantee eventual emission.
	if maxAge > 0 {
		return false
	}
	if acc.seenProctitle {
		return false
	}
	return now.Sub(acc.lastRecordAt) < execRecordSettleDelay
}

func execCommandIncomplete(acc *auditAccumulator, now time.Time) bool {
	if hasValidExecArgv(acc) {
		return false
	}
	if len(decodeProctitle(acc.proctitle)) > 0 {
		return false
	}
	// 等待同 audit 事件内后续 EXECVE/PROCTITLE；以最后一条子记录时间为准
	return now.Sub(acc.lastRecordAt) < execRecordSettleDelay
}

func hasValidExecArgv(acc *auditAccumulator) bool {
	args := orderedArgs(acc.argv)
	return len(args) > 0 && !argvLooksInvalid(args)
}

func argvLooksInvalid(args []string) bool {
	// Generic field parsing can expose raw syscall pointer arguments as a0..aN.
	// Reject pointer-looking/all-small-integer sets instead of publishing a fake
	// command line; PROCTITLE or comm/exe will supply a safer fallback.
	if len(args) == 0 {
		return true
	}
	for _, arg := range args {
		if pointerArgPattern.MatchString(arg) {
			return true
		}
	}
	// SYSCALL 泄漏的 argc 等小整数，与指针 argv 混在一起
	if len(args) <= 6 {
		suspicious := 0
		for _, arg := range args {
			if looksLikeSyscallLeak(arg) {
				suspicious++
			}
		}
		if suspicious == len(args) {
			return true
		}
	}
	return false
}

func looksLikeSyscallLeak(arg string) bool {
	if pointerArgPattern.MatchString(arg) {
		return true
	}
	if len(arg) <= 3 {
		for _, r := range arg {
			if r < '0' || r > '9' {
				return false
			}
		}
		return true
	}
	return false
}

func decodeProctitle(hexStr string) []string {
	raw, err := hexStringToBytes(hexStr)
	if err != nil || len(raw) == 0 {
		return nil
	}
	text := strings.TrimRight(string(raw), "\x00")
	if text == "" {
		return nil
	}
	parts := strings.Split(text, "\x00")
	if len(parts) == 1 {
		parts = strings.Fields(text)
	}
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func normalizeComm(comm, exe string) string {
	if comm != "" && !invalidComm(comm) {
		return comm
	}
	if exe != "" {
		return filepath.Base(exe)
	}
	return comm
}

func invalidComm(comm string) bool {
	if comm == "" {
		return true
	}
	if len(comm) <= 2 {
		for _, r := range comm {
			if r < '0' || r > '9' {
				return false
			}
		}
		return true
	}
	return false
}

func splitProcessFields(pidStr, comm, exe string) (pid, name string) {
	if pidStr == "" {
		return "", ""
	}
	pidNum, err := strconv.Atoi(pidStr)
	if err != nil {
		return pidStr, ""
	}
	name = normalizeComm(comm, exe)
	if name == "" && pidNum > 0 {
		name = readProcComm(pidNum)
	}
	return pidStr, name
}

func resolveAccountName(idStr string) string {
	// NSS lookup can be slow or remote. Cache both hits and misses so high-volume
	// audit processing does not perform one account lookup per event.
	idStr = strings.TrimSpace(idStr)
	if idStr == "" {
		return ""
	}
	if isUnsetAuditUID(idStr) {
		return "unset"
	}
	if cached, ok := accountNameCache.Load(idStr); ok {
		return cached.(string)
	}
	name := ""
	if u, err := user.LookupId(idStr); err == nil {
		name = u.Username
	}
	accountNameCache.Store(idStr, name)
	return name
}

func isUnsetAuditUID(idStr string) bool {
	switch idStr {
	case "4294967295", "18446744073709551615", "-1", "unset":
		return true
	}
	if id, err := strconv.ParseUint(idStr, 10, 64); err == nil && id == ^uint64(0) {
		return true
	}
	return false
}

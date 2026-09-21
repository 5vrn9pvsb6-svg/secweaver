package auditportexecmon

import (
	"strconv"
)

// This file owns self-process exclusion so audit maintenance performed by the agent cannot recursively become monitored workload.

func (m *processTreeMonitor) selfBranchCount() int {
	if len(m.selfBranch) == 0 {
		return 0
	}
	return len(m.selfBranch)
}

func (m *processTreeMonitor) isSelfProcessTree(pid int) bool {
	// Walk current parent links rather than checking only the startup PID set.
	// auditctl processes are short-lived descendants created after startup and
	// must also be excluded to avoid monitoring our own rule maintenance.
	if pid <= 1 {
		return false
	}
	seen := map[int]bool{}
	for p := pid; p > 1; p = readProcPPID(p) {
		if seen[p] {
			break
		}
		seen[p] = true
		if p == m.selfPID || m.selfBranch[p] {
			return true
		}
	}
	return false
}

// isSelfProcessIdentity avoids /proc ancestry walks for the host-wide bounded
// audit stream. Direct parent identity is sufficient for Agent-spawned auditctl
// helpers, while unrelated host events are discarded by ownership lookup.
func (m *processTreeMonitor) isSelfProcessIdentity(pid, ppid int, exe string) bool {
	if m.usesBoundedAudit() {
		return pid == m.selfPID || ppid == m.selfPID || m.selfBranch[pid] || m.selfBranch[ppid] || sameExecutablePath(exe, m.selfExe)
	}
	return m.isSelfProcessTree(pid) || m.isSelfProcessTree(ppid) || sameExecutablePath(exe, m.selfExe)
}

func (m *processTreeMonitor) isSelfAuditFields(fields map[string]string) bool {
	pid, _ := strconv.Atoi(fields["pid"])
	ppid, _ := strconv.Atoi(fields["ppid"])
	return m.isSelfProcessIdentity(pid, ppid, fields["exe"])
}

func collectSelfBranchPIDs(pid int, selfExe string) map[int]bool {
	// The supervisor and module are the same executable in separate processes.
	// Stop at the first different executable so unrelated service ancestors such
	// as systemd are not globally excluded.
	branch := map[int]bool{}
	selfExe = cleanDeletedSuffix(selfExe)
	for p := pid; p > 1; {
		branch[p] = true
		ppid := readProcPPID(p)
		if ppid <= 1 {
			break
		}
		parentExe := cleanDeletedSuffix(readProcExe(ppid))
		if selfExe == "" || !sameExecutablePath(parentExe, selfExe) {
			break
		}
		p = ppid
	}
	return branch
}

func sameExecutablePath(a, b string) bool {
	a = cleanDeletedSuffix(a)
	b = cleanDeletedSuffix(b)
	return a != "" && b != "" && a == b
}

func filterSelfListeners(listeners []listenerInfo, selfPID int, selfExe string, selfBranch map[int]bool) ([]listenerInfo, int) {
	if len(listeners) == 0 {
		return listeners, 0
	}
	monitor := &processTreeMonitor{
		selfPID:    selfPID,
		selfExe:    selfExe,
		selfBranch: selfBranch,
	}
	out := make([]listenerInfo, 0, len(listeners))
	skipped := 0
	for _, listener := range listeners {
		if monitor.isSelfListener(listener) {
			skipped++
			continue
		}
		out = append(out, listener)
	}
	return out, skipped
}

func (m *processTreeMonitor) isSelfListener(listener listenerInfo) bool {
	if listener.PID > 1 && m.isSelfProcessTree(listener.PID) {
		return true
	}
	if sameExecutablePath(listener.MonitorExe, m.selfExe) {
		return true
	}
	if listener.PID > 1 && sameExecutablePath(readProcExe(listener.PID), m.selfExe) {
		return true
	}
	return false
}

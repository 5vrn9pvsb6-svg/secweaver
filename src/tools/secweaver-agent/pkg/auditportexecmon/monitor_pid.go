package auditportexecmon

import (
	"strconv"
	"strings"
	"time"
)

// This file owns process attribution, PID lifetime tracking, rule-budget reservations, and dead-process cleanup.

func (m *processTreeMonitor) rescanDescendants() {
	// This function runs on the rule worker, not the audit reader. Slow netstat or
	// /proc traversal therefore delays reconciliation but cannot block raw event
	// consumption. Under pressure only cleanup runs; growth waits for recovery.
	m.retryPendingRuleCleanup()
	m.pruneDeadPIDs()
	if !m.trackDescendants {
		return
	}
	if m.usesDynamicPIDRules() && m.pressureDegraded() {
		return
	}
	m.rescanNewListeners()
	m.mu.Lock()
	listeners := append([]listenerInfo(nil), m.listeners...)
	m.mu.Unlock()
	for _, listener := range listeners {
		if isWebGatewayListener(listener) {
			m.bootstrapCompanionBackends(listener)
		}
	}
	for _, listener := range listeners {
		if listener.ExeOnly {
			if !m.usesEBPF() && !m.usesBoundedAudit() {
				continue
			}
		}
		if listener.MonitorExe != "" {
			for _, pid := range findMonitorSeedPIDs(listener) {
				if m.usesEBPF() {
					trackListener := listener
					trackListener.ExeOnly = false
					_ = m.seedEBPFProcessTree(pid, trackListener)
				} else if m.usesBoundedAudit() {
					trackListener := listener
					trackListener.ExeOnly = false
					_ = m.seedUserspaceProcessTree(pid, trackListener)
				} else {
					_ = m.expandPID(pid, listener)
				}
			}
			continue
		}
		if m.usesEBPF() {
			_ = m.seedEBPFProcessTree(listener.PID, listener)
		} else if m.usesBoundedAudit() {
			_ = m.seedUserspaceProcessTree(listener.PID, listener)
		} else {
			_ = m.expandPID(listener.PID, listener)
		}
		if isSSHDListener(listener) {
			_ = m.expandSSHDSessionPIDs(listener)
		}
	}
}

func findMonitorSeedPIDs(listener listenerInfo) []int {
	if listener.MonitorExe == "" {
		if listener.PID > 1 {
			return []int{listener.PID}
		}
		return nil
	}
	if listener.MonitorExe == "/usr/sbin/sshd" || strings.HasSuffix(listener.MonitorExe, "/sshd") {
		return findSSHDMonitorPIDs()
	}
	return findRootPIDsByExe(listener.MonitorExe)
}

func findRootPIDsByExe(exe string) []int {
	all := findPIDsByExe(exe)
	exeSet := map[int]bool{}
	for _, pid := range all {
		exeSet[pid] = true
	}
	var roots []int
	for _, pid := range all {
		ppid := readProcPPID(pid)
		if !exeSet[ppid] {
			roots = append(roots, pid)
		}
	}
	return roots
}

func (m *processTreeMonitor) observeAuditFields(fields map[string]string) {
	// Clone SYSCALL records are control-plane input as well as evidence. Resolve
	// their listener ownership immediately and enqueue both the observed process
	// chain and the returned child PID before the periodic /proc scan.
	if !m.trackDescendants {
		return
	}
	key := fields["key"]
	if key != m.execKey && key != m.connectKey && key != m.fileKey && key != m.sensitiveFileKey && key != m.cloneKey {
		return
	}
	pid, _ := strconv.Atoi(fields["pid"])
	ppid, _ := strconv.Atoi(fields["ppid"])
	if pid <= 1 || m.isSelfProcessIdentity(pid, ppid, fields["exe"]) {
		return
	}
	if target, ok := m.companionTargetForProcess(pid, ppid); ok {
		if target.ExpandDescendants && (key == m.cloneKey || key == m.execKey) {
			m.trackProcessChain(pid, ppid, target.Gateway)
			m.trackSuccessfulCloneChild(fields, pid, target.Gateway)
		}
		if key == m.cloneKey || key == m.execKey {
			return
		}
	}
	listener, ok := m.findListenerForProcess(pid, ppid, fields["exe"])
	if !ok || listener.ExeOnly {
		return
	}
	m.trackProcessChain(pid, ppid, listener)
	m.trackSuccessfulCloneChild(fields, pid, listener)
	if key == m.cloneKey && isSSHDListener(listener) && !m.isSelfProcessIdentity(ppid, 0, "") {
		_ = m.expandSSHDSessionPIDs(listener)
	}
}

// trackSuccessfulCloneChild uses the successful clone/fork syscall return value
// as the child PID. This closes much of the race where a short-lived child can
// exec and exit before it appears in a later /proc snapshot.
func (m *processTreeMonitor) trackSuccessfulCloneChild(fields map[string]string, parentPID int, listener listenerInfo) {
	if fields["key"] != m.cloneKey || strings.EqualFold(fields["success"], "no") {
		return
	}
	childPID, err := strconv.Atoi(strings.TrimSpace(fields["exit"]))
	if err != nil || childPID <= 1 || childPID == parentPID || m.isSelfProcessIdentity(childPID, parentPID, "") {
		return
	}
	m.trackProcessChain(childPID, parentPID, listener)
}

func (m *processTreeMonitor) findListenerForProcess(pid, ppid int, exe string) (listenerInfo, bool) {
	if m.isSelfProcessIdentity(pid, ppid, exe) {
		return listenerInfo{}, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.findListenerLocked(pid, ppid, exe)
}

func (m *processTreeMonitor) findListenerLocked(pid, ppid int, exe string) (listenerInfo, bool) {
	exe = cleanDeletedSuffix(exe)
	if m.processBackend == processTreeBackendAudit {
		if listener, ok := m.boundedAuditListenerLocked(pid, ppid); ok {
			return listener, true
		}
		if listener, ok := m.boundedAuditListenerLocked(ppid, 0); ok {
			return listener, true
		}
		return listenerInfo{}, false
	}
	for _, listener := range m.listeners {
		if !listener.ExeOnly || listener.MonitorExe == "" || exe != listener.MonitorExe {
			continue
		}
		if isJavaListener("", listener.MonitorExe) {
			if pid == listener.PID || isDescendantOf(listener.PID, pid) {
				return listener, true
			}
			continue
		}
		return listener, true
	}
	if exe != "" {
		if target, ok := m.exeTargets[exe]; ok {
			return target.Gateway, true
		}
	}
	return m.gatewayForProcessChainLocked(pid, ppid)
}

func (m *processTreeMonitor) trackProcessChain(pid, ppid int, listener listenerInfo) {
	// Enqueue both sides because a keyed event can be the first observation of a
	// previously missed parent. Queue-level PID/starttime deduplication keeps this
	// idempotent under repeated SYSCALL and auxiliary records.
	if listener.ExeOnly {
		return
	}
	if m.usesBoundedAudit() {
		m.rememberBoundedAuditPID(pid, ppid, listener)
		return
	}
	m.enqueuePIDExpansion(pid, listener)
	if ppid > 1 && !m.isSelfProcessTree(ppid) {
		m.enqueuePIDExpansion(ppid, listener)
	}
	for p := readProcPPID(pid); p > 1; p = readProcPPID(p) {
		if m.isSelfProcessTree(p) {
			break
		}
		m.enqueuePIDExpansion(p, listener)
		if p == listener.PID {
			break
		}
		for _, root := range m.listeners {
			if root.ExeOnly {
				continue
			}
			if root.PID > 1 && root.PID == p {
				return
			}
		}
	}
}

func (m *processTreeMonitor) resolveTrackingTarget(pid, ppid int, exe string) (trackingTarget, bool) {
	if m.isSelfProcessIdentity(pid, ppid, exe) {
		return trackingTarget{}, false
	}
	if target, ok := m.companionTargetForProcess(pid, ppid); ok {
		return target, true
	}
	listener, ok := m.findListenerForProcess(pid, ppid, exe)
	if !ok {
		return trackingTarget{}, false
	}
	return trackingTarget{Gateway: listener, ExpandDescendants: !listener.ExeOnly, Source: "listener"}, true
}

const unknownProcessStartTime = ^uint64(0)
const unknownProcessIdentityTTL = 5 * time.Second

// rememberBoundedAuditPID updates only userspace ownership. A child may already
// have exited when its clone record is read; an unknown start time is retained
// briefly so its queued exec evidence can still be attributed, then periodic
// pruning removes it.
func (m *processTreeMonitor) rememberBoundedAuditPID(pid, ppid int, listener listenerInfo) {
	if pid <= 1 {
		return
	}
	startTime := readProcessStartTime(pid)
	if startTime == 0 {
		startTime = unknownProcessStartTime
	}
	m.mu.Lock()
	if m.processParentPIDs == nil {
		m.processParentPIDs = map[int]int{}
	}
	if m.processObservedAt == nil {
		m.processObservedAt = map[int]time.Time{}
	}
	m.monitored[pid] = true
	m.processStartTimes[pid] = startTime
	m.processParentPIDs[pid] = ppid
	m.processObservedAt[pid] = time.Now()
	m.pidListener[pid] = listener
	m.mu.Unlock()
}

// boundedAuditListenerLocked validates known PID lifetimes only on ownership
// hits. Unrelated host-wide audit events therefore remain O(1) and perform no
// /proc ancestry walk, while PID reuse cannot silently inherit an old listener.
func (m *processTreeMonitor) boundedAuditListenerLocked(pid, eventPPID int) (listenerInfo, bool) {
	listener, ok := m.pidListener[pid]
	if !ok || pid <= 1 {
		return listenerInfo{}, false
	}
	expected := m.processStartTimes[pid]
	current := readProcessStartTime(pid)
	if expected == unknownProcessStartTime {
		observedAt := m.processObservedAt[pid]
		originalPPID := m.processParentPIDs[pid]
		observedPPID := eventPPID
		if observedPPID <= 1 && current != 0 {
			observedPPID = readProcPPID(pid)
		}
		if observedAt.IsZero() || time.Since(observedAt) > unknownProcessIdentityTTL || (current == 0 && eventPPID <= 1) || (originalPPID > 1 && observedPPID > 1 && originalPPID != observedPPID) {
			m.forgetBoundedAuditPIDLocked(pid)
			return listenerInfo{}, false
		}
		if current != 0 {
			m.processStartTimes[pid] = current
		}
		return listener, true
	}
	if expected != 0 && current != 0 && expected != current {
		m.forgetBoundedAuditPIDLocked(pid)
		return listenerInfo{}, false
	}
	return listener, true
}

// forgetBoundedAuditPIDLocked clears every identity and attribution index for a
// PID together; callers hold mu so no reader can observe a partially stale owner.
func (m *processTreeMonitor) forgetBoundedAuditPIDLocked(pid int) {
	delete(m.monitored, pid)
	delete(m.processStartTimes, pid)
	delete(m.processParentPIDs, pid)
	delete(m.processObservedAt, pid)
	delete(m.pidListener, pid)
	delete(m.pidTargets, pid)
}

func (m *processTreeMonitor) matchListener(fields map[string]string) (listenerInfo, bool) {
	pid, _ := strconv.Atoi(fields["pid"])
	ppid, _ := strconv.Atoi(fields["ppid"])
	return m.findListenerForProcess(pid, ppid, fields["exe"])
}

// shouldDropBoundedAuditPrimary rejects unrelated host-wide SYSCALL records
// before an accumulator is allocated. Clone records are retained only as
// control-plane input and are already skipped by the caller after observation.
func (m *processTreeMonitor) shouldDropBoundedAuditPrimary(fields map[string]string) bool {
	if !m.usesBoundedAudit() || fields["type"] != "SYSCALL" || fields["key"] == m.cloneKey {
		return false
	}
	_, ok := m.matchListener(fields)
	return !ok
}

func (m *processTreeMonitor) shouldMonitorExec(listener listenerInfo) bool {
	if !m.monitorExec {
		return false
	}
	return m.portEnabled(listener.Port, m.execListenerPorts)
}

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
		// eBPF-only has no audit reader's reconciliation path. Root socket
		// changes still need repair when the operator disables child tracking;
		// this stays on the bounded worker and never expands descendants.
		if m.isEBPFOnly() {
			m.rescanNewListeners()
		}
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

// findMonitorSeedPIDs starts from the actual socket owner only. Executable
// equality is a collection optimization, never proof that two service instances
// share a root; descendants are expanded by the existing tree bootstrap.
func findMonitorSeedPIDs(listener listenerInfo) []int {
	if listener.PID > 1 {
		return []int{listener.PID}
	}
	return nil
}

func (m *processTreeMonitor) observeAuditFields(fields map[string]string) {
	// Clone SYSCALL records are control-plane input as well as evidence. Resolve
	// their listener ownership immediately and enqueue the observed process and
	// returned child PID, never the service root's runtime parent.
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
	// Resolve before companion lookup: that lookup can invalidate stale ownership,
	// and the event must retain the resulting uncertainty through assembly.
	listener, matched := m.matchListener(fields)
	if target, ok := m.companionTargetForProcess(pid, ppid); ok && matched {
		if target.ExpandDescendants && (key == m.cloneKey || key == m.execKey) {
			m.trackProcessChain(pid, ppid, target.Gateway)
			m.trackSuccessfulCloneChild(fields, pid, target.Gateway)
		}
		if key == m.cloneKey || key == m.execKey {
			return
		}
	}
	if !matched || listener.ExeOnly {
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
	if listener.Historical {
		return
	}
	if fields["key"] != m.cloneKey || strings.EqualFold(fields["success"], "no") {
		return
	}
	childPID, err := strconv.Atoi(strings.TrimSpace(fields["exit"]))
	if err != nil || childPID <= 1 || childPID == parentPID || m.isSelfProcessIdentity(childPID, parentPID, "") {
		return
	}
	if liveParent := readProcessParentPID(childPID); liveParent > 0 && liveParent != parentPID {
		return
	}
	// Record source-time evidence before async rule work. A process can already
	// be gone when the record is read; historical attribution must not depend
	// on whether installing a rule for that PID is still possible.
	birth := auditSourceTime(fields)
	if !birth.IsZero() && !m.rememberAuditFork(childPID, parentPID, listener, birth) {
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

func (m *processTreeMonitor) findListenerLocked(pid, ppid int, _ string) (listenerInfo, bool) {
	if m.processBackend == processTreeBackendAudit {
		listener, state := m.cachedListenerLocked(pid, ppid, time.Time{})
		if state == attributionVerified {
			return listener, true
		}
		if state == attributionRootUnknown {
			return listenerInfo{}, false
		}
		if listener, ok := m.boundedAuditListenerLocked(ppid, 0); ok {
			return listener, true
		}
		return listenerInfo{}, false
	}
	// Executable rules can collect unrelated instances of the same binary.
	// Resolve their actual ancestry through the same lifetime gate as every
	// other event; neither ExeOnly nor exeTargets establishes ownership.
	return m.gatewayForProcessChainLocked(pid, ppid)
}

func (m *processTreeMonitor) trackProcessChain(pid, ppid int, listener listenerInfo) {
	// Ownership flows downward only. A service root's parent may be a runtime
	// shared with sibling processes; promoting it would attribute those siblings
	// to the service. Missed intermediate descendants are repaired by rescans.
	if listener.ExeOnly || listener.Historical {
		return
	}
	// A delayed record may describe an earlier occupant of this PID. Its event
	// can still be emitted, but it must not seed rules for today's unrelated
	// process. Reparenting likewise requires a fresh discovery snapshot.
	if currentParent := readProcessParentPID(pid); ppid > 0 && currentParent > 0 && currentParent != ppid {
		return
	}
	if m.usesBoundedAudit() {
		m.rememberBoundedAuditPID(pid, ppid, listener)
		return
	}
	m.enqueuePIDExpansion(pid, listener)
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
	if pid <= 1 || listener.Historical {
		return
	}
	listener = bindListenerLifetime(listener)
	startTime := readProcessStartTime(pid)
	if startTime == 0 {
		startTime = unknownProcessStartTime
	}
	m.mu.Lock()
	// Historical matches and roots retired between admission and observation may
	// preserve an event, but cannot establish active tracking for today's PID.
	if m.listenerLifetimeLocked(listener) != attributionVerified {
		m.mu.Unlock()
		return
	}
	if m.processParentPIDs == nil {
		m.processParentPIDs = map[int]int{}
	}
	if m.processObservedAt == nil {
		m.processObservedAt = map[int]time.Time{}
	}
	// Exec records do not renew an unknown identity's TTL. Keep a known
	// lifetime when /proc has disappeared so it cannot become a fresh unknown.
	if old, ok := m.pidListener[pid]; ok && old.PID == listener.PID && old.RootStartTime == listener.RootStartTime && m.processParentPIDs[pid] == ppid &&
		(startTime == unknownProcessStartTime || m.processStartTimes[pid] == startTime) {
		// A fork proof may have created this identity before normal tracking.
		// Bounded audit needs no rule installation; adopt its ledger membership
		// without renewing the proof, so live children survive proof expiration.
		m.monitored[pid] = true
		if startTime != unknownProcessStartTime && m.listenerLifetimeLocked(listener) == attributionVerified {
			m.rememberRootHistoryLocked(listener)
			m.rememberProcessHistoryLocked(pid, ppid, startTime, listener, time.Now())
		}
		m.mu.Unlock()
		return
	}
	delete(m.processCloneTimes, pid)
	m.monitored[pid] = true
	m.processStartTimes[pid] = startTime
	m.processParentPIDs[pid] = ppid
	m.processObservedAt[pid] = time.Now()
	m.pidListener[pid] = listener
	if startTime != unknownProcessStartTime && m.listenerLifetimeLocked(listener) == attributionVerified {
		m.rememberRootHistoryLocked(listener)
		m.rememberProcessHistoryLocked(pid, ppid, startTime, listener, time.Now())
	}
	m.mu.Unlock()
}

// boundedAuditListenerLocked validates known PID lifetimes only on ownership
// hits. Unrelated host-wide audit events therefore remain O(1) and perform no
// /proc ancestry walk, while PID reuse cannot silently inherit an old listener.
func (m *processTreeMonitor) boundedAuditListenerLocked(pid, eventPPID int) (listenerInfo, bool) {
	listener, state := m.cachedListenerLocked(pid, eventPPID, time.Time{})
	return listener, state == attributionVerified
}

// forgetBoundedAuditPIDLocked clears every identity and attribution index for a
// PID together; callers hold mu so no reader can observe a partially stale owner.
func (m *processTreeMonitor) forgetBoundedAuditPIDLocked(pid int) {
	delete(m.monitored, pid)
	delete(m.processStartTimes, pid)
	delete(m.processParentPIDs, pid)
	delete(m.processObservedAt, pid)
	delete(m.processCloneTimes, pid)
	delete(m.pidListener, pid)
	delete(m.pidTargets, pid)
}

func (m *processTreeMonitor) matchListener(fields map[string]string) (listenerInfo, bool) {
	return m.matchAuditListener(fields)
}

// shouldDropBoundedAuditPrimary rejects unrelated host-wide SYSCALL records
// before an accumulator is allocated. Clone records are retained only as
// control-plane input and are already skipped by the caller after observation.
func (m *processTreeMonitor) shouldDropBoundedAuditPrimary(fields map[string]string) bool {
	if !m.usesBoundedAudit() || fields["type"] != "SYSCALL" || fields["key"] == m.cloneKey {
		return false
	}
	_, ok := m.matchListener(fields)
	if ok {
		fields["attribution_accepted"] = "yes"
	}
	return !ok && fields["attribution_status"] != "unknown"
}

func (m *processTreeMonitor) shouldMonitorExec(listener listenerInfo) bool {
	if !m.monitorExec {
		return false
	}
	return m.portEnabled(listener.Port, m.execListenerPorts)
}

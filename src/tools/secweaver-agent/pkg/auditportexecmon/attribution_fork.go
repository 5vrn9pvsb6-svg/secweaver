package auditportexecmon

import "time"

// Historical fork proofs have a separate admission budget from installed rules.
// A burst may reduce coverage at this limit, but cannot grow memory indefinitely
// or cause a dead child to reserve audit rules. The reader never runs auditctl.
const maxAuditForkProofs = 16384

// rememberAuditFork records successful source-time evidence for every audit
// backend. Identity maps describe history; monitored describes the backend's
// durable tracking/rule ledger and is intentionally untouched here. mu serializes
// proofs and rule workers; bounded audit adopts proofs through its normal tracker.
func (m *processTreeMonitor) rememberAuditFork(pid, parent int, listener listenerInfo, birth time.Time) bool {
	now := time.Now()
	if birth.IsZero() || birth.After(now) || now.Sub(birth) > unknownProcessIdentityTTL {
		return false
	}
	listener = bindListenerLifetime(listener)
	start := readProcessStartTime(pid)
	if start == 0 {
		start = unknownProcessStartTime
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pruneAuditForksLocked(now)
	if m.listenerLifetimeLocked(listener) != attributionVerified {
		return false
	}
	if previous := m.processCloneTimes[pid]; !previous.IsZero() && !birth.After(previous) {
		return false // replay must not extend the trust window
	}
	if m.monitored[pid] {
		owner := m.pidListener[pid]
		known := m.processStartTimes[pid]
		if owner.PID != listener.PID || owner.RootStartTime != listener.RootStartTime ||
			(start != unknownProcessStartTime && known != 0 && known != unknownProcessStartTime && start != known) {
			return false // only the rule worker may replace an installed identity
		}
	}
	if _, exists := m.processCloneTimes[pid]; !exists && len(m.processCloneTimes) >= maxAuditForkProofs {
		return false
	}
	if m.processCloneTimes == nil {
		m.processCloneTimes = map[int]time.Time{}
	}
	if m.processObservedAt == nil {
		m.processObservedAt = map[int]time.Time{}
	}
	if m.processParentPIDs == nil {
		m.processParentPIDs = map[int]int{}
	}
	if m.processStartTimes == nil {
		m.processStartTimes = map[int]uint64{}
	}
	if m.pidListener == nil {
		m.pidListener = map[int]listenerInfo{}
	}
	// Preserve a known lifetime when procfs has disappeared. A clone proof must
	// not downgrade identity so that an unrelated replacement becomes acceptable.
	if known := m.processStartTimes[pid]; start == unknownProcessStartTime && known != 0 {
		start = known
	}
	m.processStartTimes[pid] = start
	m.processParentPIDs[pid] = parent
	m.pidListener[pid] = listener
	m.processCloneTimes[pid] = birth
	m.processObservedAt[pid] = now
	return true
}

// pruneAuditForksLocked runs at most once per trust window and never deletes
// installed-rule state. Uninstalled historical entries expire without auditctl.
func (m *processTreeMonitor) pruneAuditForksLocked(now time.Time) {
	if !m.lastForkPrune.IsZero() && now.Sub(m.lastForkPrune) < unknownProcessIdentityTTL {
		return
	}
	m.lastForkPrune = now
	for pid, birth := range m.processCloneTimes {
		if !birth.IsZero() && !birth.After(now) && now.Sub(birth) <= unknownProcessIdentityTTL {
			continue
		}
		delete(m.processCloneTimes, pid)
		delete(m.processObservedAt, pid)
		if !m.monitored[pid] {
			delete(m.processStartTimes, pid)
			delete(m.processParentPIDs, pid)
			delete(m.pidListener, pid)
			delete(m.pidTargets, pid)
		}
	}
}

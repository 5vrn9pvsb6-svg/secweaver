package auditportexecmon

import (
	"strconv"
	"strings"
	"time"
)

type attributionState uint8

const (
	attributionUnrelated attributionState = iota
	attributionVerified
	attributionUnknown
	// A known child's root generation is uncertain. A freshly reseeded parent
	// with the same numeric PID must not override that stronger old-generation
	// evidence. Ordinary stale-child misses may still try a different parent.
	attributionRootUnknown
)

// bindListenerLifetime copies the root identity into owners/jobs. A later root
// reseed must not make an old child or queued job belong to the new process.
func bindListenerLifetime(listener listenerInfo) listenerInfo {
	if listener.RootStartTime == 0 && listener.PID > 1 {
		listener.RootStartTime = readProcessStartTime(listener.PID)
	}
	return listener
}

// listenerLifetimeLocked performs only bounded procfs reads under mu, never
// external commands or an ancestry scan. Legacy in-memory callers without a
// bound root use the existing root ledger; an unreadable root is not proof.
func (m *processTreeMonitor) listenerLifetimeLocked(listener listenerInfo) attributionState {
	if m.processBackend == processTreeBackendEBPF && m.activeListenerRoots != nil && !m.knownEBPFRootLocked(listener) {
		return attributionUnknown
	}
	if m.rootHistoryClosedLocked(listener) {
		return attributionUnknown
	}
	expected := listener.RootStartTime
	if expected == 0 {
		expected = m.processStartTimes[listener.PID]
	}
	current := readProcessStartTime(listener.PID)
	if expected == 0 || expected == unknownProcessStartTime || current == 0 {
		return attributionUnknown
	}
	if current != expected {
		return attributionUnrelated
	}
	return attributionVerified
}

// invalidateOwnerLocked revokes attribution immediately, but leaves the rule
// ledger for the rule worker to remove/retry. Deleting monitored here would
// allow duplicate kernel rule installation while old rules still exist.
func (m *processTreeMonitor) invalidateOwnerLocked(pid int) {
	m.invalidateProcessHistoryLocked(pid)
	m.recordAttributionLocked("identity_conflict")
	delete(m.pidListener, pid)
	delete(m.pidTargets, pid)
	delete(m.processCloneTimes, pid)
	if m.processBackend != processTreeBackendAudit && m.monitored[pid] {
		if m.pendingPIDRuleCleanup == nil {
			m.pendingPIDRuleCleanup = map[int]bool{}
		}
		m.pendingPIDRuleCleanup[pid] = true
	}
}

// cachedListenerLocked is shared by audit backends, ancestors and companions.
// Event lookups may recover bounded historical proof; zero-time active lookups
// cannot. Unknown still rejects output, and unrelated means contradictory
// identity or no owner. Source time must never be replaced by receipt time.
func (m *processTreeMonitor) cachedListenerLocked(pid, eventPPID int, eventTime time.Time) (listenerInfo, attributionState) {
	listener, ok := m.pidListener[pid]
	if !ok || pid <= 1 {
		if historical, verified := m.historicalAuditListenerLocked(pid, eventPPID, eventTime); verified {
			return historical, attributionVerified
		}
		return listenerInfo{}, attributionUnrelated
	}
	expected, current := m.processStartTimes[pid], readProcessStartTime(pid)
	if expected != 0 && expected != unknownProcessStartTime && current != 0 && expected != current {
		m.invalidateOwnerLocked(pid)
		return listenerInfo{}, attributionUnrelated
	}
	parent := m.processParentPIDs[pid]
	if eventPPID > 0 && parent > 0 && eventPPID != parent {
		if expected != 0 && expected != unknownProcessStartTime && current == expected {
			// Reparenting changes the topology, not this verified process instance.
			// Keep its origin while replacing only the current parent metadata.
			parent = eventPPID
			m.processParentPIDs[pid] = parent
			m.recordAttributionLocked("reparented")
		} else {
			m.invalidateOwnerLocked(pid)
			// Once the process is gone we cannot decide whether this was PID reuse
			// or a reparented/delayed tracked event. Keep uncertainty, never the old label.
			if current == 0 {
				return listenerInfo{}, attributionUnknown
			}
			return listenerInfo{}, attributionUnrelated
		}
	}
	rootState := m.listenerLifetimeLocked(listener)
	if rootState != attributionVerified {
		m.retireRootHistoryLocked(listener, 0)
		if historical, verified := m.historicalAuditListenerLocked(pid, eventPPID, eventTime); verified {
			return historical, attributionVerified
		}
		if rootState == attributionUnrelated {
			// Quarantine the old generation until cleanup. Removing it outright
			// would let the next event fall through to a reused root's new owner.
			listener.AttributionUnknown = true
			m.pidListener[pid] = listener
			delete(m.pidTargets, pid)
		}
		return listenerInfo{}, attributionRootUnknown
	}
	if listener.AttributionUnknown {
		// Recovery requires the same positively verified child AND root lifetime.
		// Root liveness alone must not rehabilitate a reused or unreadable child.
		if expected == 0 || expected == unknownProcessStartTime || current != expected {
			return listenerInfo{}, attributionRootUnknown
		}
		listener.AttributionUnknown = false
		m.pidListener[pid] = listener
		m.recordAttributionLocked("identity_recovered")
	}
	m.rememberRootHistoryLocked(listener)
	if expected != 0 && expected != unknownProcessStartTime && current == expected {
		m.rememberProcessHistoryLocked(pid, parent, expected, listener, time.Now())
		return listener, attributionVerified
	}
	if historical, verified := m.historicalAuditListenerLocked(pid, eventPPID, eventTime); verified {
		return historical, attributionVerified
	}
	// An observed clone can bridge a short /proc race, but never establish the
	// identity of a newly readable PID: a scan must verify that new lifetime.
	birth := m.processCloneTimes[pid]
	observed := m.processObservedAt[pid]
	if current == 0 && parent > 1 && parent == eventPPID && !birth.IsZero() &&
		!eventTime.Before(birth) && eventTime.Sub(birth) <= unknownProcessIdentityTTL &&
		!observed.IsZero() && time.Since(observed) >= 0 && time.Since(observed) <= unknownProcessIdentityTTL &&
		time.Since(birth) >= 0 && time.Since(birth) <= unknownProcessIdentityTTL {
		return listener, attributionVerified
	}
	return listenerInfo{}, attributionUnknown
}

// auditSourceTime reads the kernel timestamp, including fractional seconds,
// without floating-point rounding. Missing or malformed times disable clone
// correlation rather than substituting the time the reader happened to run.
func auditSourceTime(fields map[string]string) time.Time {
	value := strings.TrimPrefix(fields["msg"], "audit(")
	value, _, _ = strings.Cut(value, ":")
	seconds, fraction, _ := strings.Cut(value, ".")
	sec, err := strconv.ParseInt(seconds, 10, 64)
	if err != nil || sec <= 0 || len(fraction) > 9 {
		return time.Time{}
	}
	ns, err := strconv.ParseInt(fraction+strings.Repeat("0", 9-len(fraction)), 10, 64)
	if err != nil {
		return time.Time{}
	}
	return time.Unix(sec, ns)
}

// matchAuditListener preserves an uncertain result on the event itself before
// invalidating any stale cache. Rechecks during assembly must not rescue that
// event with a different root after uncertainty has already rejected its label.
func (m *processTreeMonitor) matchAuditListener(fields map[string]string) (listenerInfo, bool) {
	if fields["attribution_status"] == "unknown" {
		return listenerInfo{}, false
	}
	pid, _ := strconv.Atoi(fields["pid"])
	ppid, _ := strconv.Atoi(fields["ppid"])
	if m.isSelfProcessIdentity(pid, ppid, fields["exe"]) {
		return listenerInfo{}, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	// Primary admission is evidence of collection scope. If its identity expires
	// while EXECVE/PATH records assemble, retain unknown internally so the output
	// gate drops the event instead of restoring a guessed listener on recheck.
	uncertain := fields["attribution_accepted"] == "yes"
	for _, candidate := range []struct{ pid, parent int }{{pid, ppid}, {ppid, 0}} {
		listener, state := m.cachedListenerLocked(candidate.pid, candidate.parent, auditSourceTime(fields))
		if state == attributionVerified {
			return listener, true
		}
		if state == attributionRootUnknown {
			fields["attribution_status"] = "unknown"
			return listenerInfo{}, false
		}
		uncertain = uncertain || state == attributionUnknown
	}
	if m.processBackend != processTreeBackendAudit {
		if listener, ok := m.findListenerLocked(pid, ppid, fields["exe"]); ok {
			return listener, true
		}
		// PID/executable audit rules already bound collection scope, but do not
		// prove a current listener. Mark unresolved events for output rejection.
		// Sensitive-path watches are host-wide on every backend; a watch hit
		// alone must not expand the configured service collection scope.
		uncertain = uncertain || (fields["key"] != "" && fields["key"] != m.sensitiveFileKey)
	}
	if uncertain {
		fields["attribution_status"] = "unknown"
	}
	return listenerInfo{}, false
}

// validCompanionTargetLocked applies the same PID lifetime gate to explicit
// gateway/backend associations, preventing this earlier lookup from bypassing
// the listener cache checks. Caller holds mu.
func (m *processTreeMonitor) validCompanionTargetLocked(pid, ppid int) (trackingTarget, bool) {
	target, ok := m.pidTargets[pid]
	if !ok {
		return trackingTarget{}, false
	}
	_, state := m.cachedListenerLocked(pid, ppid, time.Time{})
	return target, state == attributionVerified
}

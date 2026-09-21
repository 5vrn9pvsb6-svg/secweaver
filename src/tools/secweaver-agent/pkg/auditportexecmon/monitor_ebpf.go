package auditportexecmon

import (
	"secweaver-agent/pkg/processtracker"
)

// This file owns eBPF process-lifecycle attribution and schedules any auxiliary audit coverage off the reader path.

func (m *processTreeMonitor) observeEBPFEvent(event processtracker.Event) (listenerInfo, bool) {
	// P2-7: Validate PID ranges to prevent integer overflow on 32-bit systems
	// Linux PID max is typically 32768 or 4194304, well within int32 range,
	// but we defensively check to prevent any potential overflow
	if event.PID > 0x7FFFFFFF || event.RootPID > 0x7FFFFFFF {
		// PID exceeds int32 max - should never happen on Linux but be defensive
		return listenerInfo{}, false
	}

	pid := int(event.PID)
	rootPID := int(event.RootPID)

	// Additional sanity check: PIDs should be positive
	if pid <= 0 || rootPID <= 0 {
		return listenerInfo{}, false
	}

	startTime := uint64(0)
	if event.Type != processtracker.EventExit {
		startTime = readProcessStartTime(pid)
	}
	m.mu.Lock()
	listener, ok := m.pidListener[rootPID]
	if !ok {
		for _, candidate := range m.listeners {
			if candidate.PID == rootPID {
				listener = candidate
				listener.ExeOnly = false
				ok = true
				break
			}
		}
	}
	// Optional connect/file collection still relies on per-PID audit rules. Do
	// not mark a newly observed eBPF child complete until the existing async rule
	// worker has installed those auxiliary groups. Track() is idempotent, so the
	// worker can safely reseed the already inherited kernel owner entry.
	needsAuxRules := ok && event.Type != processtracker.EventExit && m.needsAuxiliaryAuditRules(listener)
	if ok && event.Type != processtracker.EventExit && !needsAuxRules {
		m.monitored[pid] = true
		m.processStartTimes[pid] = startTime
		m.pidListener[pid] = listener
	}
	hasRules := event.Type == processtracker.EventExit && hasPIDRules(m.rules, pid)
	if event.Type == processtracker.EventExit {
		if !hasRules {
			delete(m.monitored, pid)
			delete(m.processStartTimes, pid)
			delete(m.processParentPIDs, pid)
			delete(m.processObservedAt, pid)
			delete(m.pidListener, pid)
			delete(m.pidTargets, pid)
			delete(m.pendingRuleExpansion, pid)
			delete(m.suppressedCloneRules, pid)
		}
	}
	m.mu.Unlock()
	if needsAuxRules {
		m.enqueuePIDExpansion(pid, listener)
	}
	if hasRules {
		m.enqueuePIDRemoval(pid)
	}
	return listener, ok
}

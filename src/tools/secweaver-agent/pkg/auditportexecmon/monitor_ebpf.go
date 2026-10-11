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
	// A root PID can be reseeded while its older descendants are still alive.
	// Prefer the generation captured on the child or parent over the root's
	// current entry, or a delayed event would inherit the replacement service.
	listener, ok := m.ebpfEventOwnerLocked(pid, int(event.PPID), rootPID, startTime)
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
	// Kernel tracking proves scope even if the service root exits before the
	// reader runs. Preserve exec evidence as unknown, but do not seed userspace
	// verified ownership or auxiliary rules from an expired/reused root identity.
	if ok {
		if listener.RootStartTime == 0 {
			for _, candidate := range m.listeners {
				if candidate.PID == listener.PID {
					listener.RootStartTime = candidate.RootStartTime
					break
				}
			}
		}
		listener.AttributionUnknown = listener.AttributionUnknown || m.listenerLifetimeLocked(listener) != attributionVerified
	} else {
		// A kernel-tracked event can outlive both userspace root and parent
		// entries. Its raw evidence remains in scope without a guessed owner.
		listener.AttributionUnknown = true
		ok = true
	}
	// Optional connect/file collection still relies on per-PID audit rules. Do
	// not mark a newly observed eBPF child complete until the existing async rule
	// worker has installed those auxiliary groups. Track() is idempotent, so the
	// worker can safely reseed the already inherited kernel owner entry.
	needsAuxRules := ok && !listener.AttributionUnknown && event.Type != processtracker.EventExit && m.needsAuxiliaryAuditRules(listener)
	if ok && event.Type != processtracker.EventExit && !needsAuxRules {
		// Unknown entries retain only kernel-proven scope for later exec/fork
		// events; cache lookups never treat them as verified ownership. Exit and
		// reconciliation share the existing bounded PID cleanup lifecycle.
		m.monitored[pid] = true
		m.processStartTimes[pid] = startTime
		if m.processParentPIDs == nil {
			m.processParentPIDs = map[int]int{}
		}
		m.processParentPIDs[pid] = int(event.PPID)
		m.pidListener[pid] = listener
	}
	hasRules := event.Type == processtracker.EventExit && hasPIDRules(m.rules, pid)
	if event.Type == processtracker.EventExit {
		if !hasRules {
			delete(m.monitored, pid)
			delete(m.processStartTimes, pid)
			delete(m.processParentPIDs, pid)
			delete(m.processObservedAt, pid)
			delete(m.processCloneTimes, pid)
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

// ebpfEventOwnerLocked checks existing child/parent lifetimes before using the
// current root entry. mu is held; these are bounded, uncached procfs reads.
func (m *processTreeMonitor) ebpfEventOwnerLocked(pid, ppid, rootPID int, current uint64) (listenerInfo, bool) {
	for _, candidate := range []int{pid, ppid} {
		owner, ok := m.pidListener[candidate]
		if !ok || (owner.PID != rootPID && !owner.AttributionUnknown) {
			continue
		}
		observed := current
		if candidate != pid {
			observed = readProcessStartTime(candidate)
		}
		expected := m.processStartTimes[candidate]
		if observed != 0 && expected != 0 && expected != unknownProcessStartTime && observed != expected {
			continue
		}
		return owner, true
	}
	owner, ok := m.pidListener[rootPID]
	return owner, ok
}

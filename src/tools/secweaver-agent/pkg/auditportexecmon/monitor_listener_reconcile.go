package auditportexecmon

import (
	"fmt"
	"os"

	"time"
)

// This file owns listener discovery reconciliation, stale executable-rule cleanup, and pressure-recovery retries.

func (m *processTreeMonitor) knownListenerIdentities() map[string]bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	seen := make(map[string]bool, len(m.listeners))
	for _, listener := range m.listeners {
		seen[listenerIdentity(listener)] = true
	}
	return seen
}

func (m *processTreeMonitor) rescanNewListeners() {
	// Listener discovery is a reconciliation source, not the real-time source.
	// Clone events cover the interval between scans; this pass repairs socket
	// ownership changes, daemon restarts, and processes missed by audit races.
	listeners, err := findExternalListeners(m.portFilter, m.whitelistPorts)
	if err != nil {
		return
	}
	listeners, _ = filterSelfListeners(listeners, m.selfPID, m.selfExe, m.selfBranch)
	m.mu.Lock()
	previous := append([]listenerInfo(nil), m.listeners...)
	refreshed, newIndexes, removed := reconcileListeners(previous, listeners)
	m.listeners = refreshed
	m.mu.Unlock()
	if removed > 0 {
		fmt.Fprintf(os.Stderr, "pruned stale external listeners: count=%d active=%d\n", removed, len(refreshed))
		m.cleanupRemovedListenerRules(previous, refreshed)
	}
	for _, index := range newIndexes {
		m.mu.Lock()
		l := m.listeners[index]
		m.mu.Unlock()
		if l.ExeOnly && l.MonitorExe != "" {
			fmt.Fprintf(os.Stderr, "new external listener (exe-only): exe=%s process=%s address=%s port=%d pid=%d\n", l.MonitorExe, l.Process, l.Address, l.Port, l.PID)
		} else {
			fmt.Fprintf(os.Stderr, "new external listener: pid=%d process=%s address=%s port=%d\n", l.PID, l.Process, l.Address, l.Port)
		}
		if err := m.bootstrapListenerAt(index); err != nil {
			fmt.Fprintf(os.Stderr, "bootstrap new listener failed: pid=%d process=%s port=%d err=%v\n", l.PID, l.Process, l.Port, err)
		}
	}
}

// cleanupRemovedListenerRules removes all PID descendants and executable rules
// whose owning listener disappeared. Companion executable targets are detached
// with their gateway so a future same-path process is not misattributed.
func (m *processTreeMonitor) cleanupRemovedListenerRules(previous, active []listenerInfo) {
	activePIDs := map[int]bool{}
	activeExes := map[string]bool{}
	for _, listener := range active {
		if listener.PID > 1 {
			activePIDs[listener.PID] = true
		}
		if listener.MonitorExe != "" {
			activeExes[cleanDeletedSuffix(listener.MonitorExe)] = true
		}
	}
	staleRoots := map[int]bool{}
	staleExes := map[string]bool{}
	for _, listener := range previous {
		if listener.PID > 1 && !activePIDs[listener.PID] {
			staleRoots[listener.PID] = true
		}
		exe := cleanDeletedSuffix(listener.MonitorExe)
		if exe != "" && !activeExes[exe] {
			staleExes[exe] = true
		}
	}
	m.mu.Lock()
	var stalePIDs []int
	for pid, owner := range m.pidListener {
		if staleRoots[owner.PID] {
			stalePIDs = append(stalePIDs, pid)
		}
	}
	for exe, target := range m.exeTargets {
		if staleRoots[target.Gateway.PID] {
			delete(m.exeTargets, exe)
			staleExes[cleanDeletedSuffix(exe)] = true
		}
	}
	m.mu.Unlock()
	for _, pid := range stalePIDs {
		m.enqueuePIDRemoval(pid)
	}
	for exe := range staleExes {
		m.removeExeRules(exe)
	}
}

func (m *processTreeMonitor) removeExeRules(exe string) {
	m.removeExeRulesInternal(exe, false)
}

func (m *processTreeMonitor) removeExeRulesInternal(exe string, force bool) {
	// Normal listener cleanup preserves an executable still registered as a
	// companion target. force is used only for retrying a previously failed
	// deletion whose ownership has already been removed.
	//
	// CRITICAL: To prevent memory leaks from perpetually failing exe deletions, we:
	// 1. Track failure count and first failure time per exe
	// 2. After maxCleanupRetries or maxCleanupAge, force release memory state
	// 3. Log detailed error for manual intervention
	const (
		maxCleanupRetries = 10               // Max retry attempts before giving up
		maxCleanupAge     = 10 * time.Minute // Max time before forcing cleanup
	)

	exe = cleanDeletedSuffix(exe)
	if exe == "" {
		return
	}

	m.mu.Lock()
	if _, companion := m.exeTargets[exe]; companion && !force {
		m.mu.Unlock()
		return
	}

	var remove []auditRule
	for _, rule := range m.rules {
		if rule.Field == "exe" && cleanDeletedSuffix(rule.Exe) == exe {
			remove = append(remove, rule)
		}
	}

	// Check if we should force cleanup due to excessive failures
	failureCount := m.exeCleanupFailureCount[exe]
	firstFailed := m.exeCleanupFirstFailed[exe]
	forceCleanup := false

	if failureCount >= maxCleanupRetries {
		forceCleanup = true
		fmt.Fprintf(os.Stderr, "CRITICAL: force cleanup exe=%s after %d failed attempts; kernel rules may be orphaned\n", exe, failureCount)
	} else if !firstFailed.IsZero() && time.Since(firstFailed) > maxCleanupAge {
		forceCleanup = true
		fmt.Fprintf(os.Stderr, "CRITICAL: force cleanup exe=%s after %s of failures; kernel rules may be orphaned\n", exe, time.Since(firstFailed))
	}

	m.mu.Unlock()

	if len(remove) == 0 {
		m.mu.Lock()
		delete(m.pendingExeRuleCleanup, exe)
		// The kernel rule may have been removed by auditd reload or an
		// administrator. Do not leave a stale in-memory reservation that would
		// prevent this executable from being monitored when it appears again.
		delete(m.exeMonitored, exe)
		delete(m.exeCleanupFailureCount, exe)
		delete(m.exeCleanupFirstFailed, exe)
		m.mu.Unlock()
		return
	}

	var deleted []auditRule
	failed := false
	for i := len(remove) - 1; i >= 0; i-- {
		if err := runAuditctl(remove[i].auditctlArgs("-d")...); err != nil {
			failed = true
			fmt.Fprintf(os.Stderr, "remove stale exe rule failed: exe=%s err=%v\n", exe, err)
			continue
		}
		deleted = append(deleted, remove[i])
	}

	m.mu.Lock()
	m.rules = subtractAuditRules(m.rules, deleted)

	// Determine if we should clear memory state
	shouldClearMemory := false

	if len(deleted) == len(remove) {
		// Success: all rules removed
		shouldClearMemory = true
	} else if failed && forceCleanup {
		// Force cleanup: too many failures or too old
		shouldClearMemory = true

		// Log residual rules for manual cleanup
		residualCount := len(remove) - len(deleted)
		fmt.Fprintf(os.Stderr, "CRITICAL: forced memory cleanup for exe=%s with %d residual kernel rules; manual auditctl cleanup may be required\n", exe, residualCount)
	} else if failed {
		// Track failure for future force cleanup decision
		if m.pendingExeRuleCleanup == nil {
			m.pendingExeRuleCleanup = map[string]bool{}
		}
		m.pendingExeRuleCleanup[exe] = true

		// Increment failure tracking
		if m.exeCleanupFailureCount == nil {
			m.exeCleanupFailureCount = map[string]int{}
		}
		if m.exeCleanupFirstFailed == nil {
			m.exeCleanupFirstFailed = map[string]time.Time{}
		}

		m.exeCleanupFailureCount[exe]++
		if m.exeCleanupFirstFailed[exe].IsZero() {
			m.exeCleanupFirstFailed[exe] = time.Now()
		}

		newCount := m.exeCleanupFailureCount[exe]
		if newCount%5 == 0 {
			fmt.Fprintf(os.Stderr, "WARNING: exe cleanup failed %d times for exe=%s (first failed %s ago)\n",
				newCount, exe, time.Since(m.exeCleanupFirstFailed[exe]))
		}
	}

	if shouldClearMemory {
		// Clear all memory state for this exe
		delete(m.exeMonitored, exe)
		delete(m.pendingExeRuleCleanup, exe)
		delete(m.exeCleanupFailureCount, exe)
		delete(m.exeCleanupFirstFailed, exe)
	}

	m.mu.Unlock()

	if len(deleted) > 0 {
		m.resumeRuleBudgetRecovery()
	}
}

// retryPendingRuleCleanup retries only kernel deletions that previously failed.
// Keeping failed rules in the ledger prevents duplicate re-adds and ensures they
// continue to consume the hard rule budget until deletion is confirmed.
func (m *processTreeMonitor) retryPendingRuleCleanup() {
	m.mu.Lock()
	pids := make([]int, 0, len(m.pendingPIDRuleCleanup))
	for pid := range m.pendingPIDRuleCleanup {
		pids = append(pids, pid)
	}
	exes := make([]string, 0, len(m.pendingExeRuleCleanup))
	for exe := range m.pendingExeRuleCleanup {
		exes = append(exes, exe)
	}
	m.mu.Unlock()
	for _, pid := range pids {
		m.removePIDRules(pid)
	}
	for _, exe := range exes {
		m.removeExeRulesInternal(exe, true)
	}
}

func (m *processTreeMonitor) resumeRuleBudgetRecovery() {
	m.mu.Lock()
	resume := m.pressureRecovering && m.pressureRecoveryBlocked
	if resume {
		m.pressureRecoveryBlocked = false
	}
	m.mu.Unlock()
	if resume {
		m.pumpDeferredRecovery()
	}
}

func reconcileListeners(existing, active []listenerInfo) ([]listenerInfo, []int, int) {
	// Match exact process identity first, then socket identity. Socket matching
	// preserves listener metadata when a daemon restarts on the same address and
	// port but receives a new PID.
	byIdentity := make(map[string]listenerInfo, len(existing))
	bySocket := make(map[string]listenerInfo, len(existing))
	for _, listener := range existing {
		byIdentity[listenerIdentity(listener)] = listener
		bySocket[listenerSocketIdentity(listener)] = listener
	}

	refreshed := make([]listenerInfo, 0, len(active))
	newIndexes := make([]int, 0)
	matchedExisting := map[string]bool{}
	for _, listener := range active {
		identity := listenerIdentity(listener)
		previous, found := byIdentity[identity]
		if !found {
			previous, found = bySocket[listenerSocketIdentity(listener)]
		}
		if found {
			matchedExisting[listenerIdentity(previous)] = true
			// Preserve an exe-rule fallback for the same live socket. A restarted
			// process has a different PID and should use the freshly detected mode.
			if previous.PID == listener.PID && !previous.ExeOnly && previous.MonitorExe == "" && listener.ExeOnly {
				listener.ExeOnly = false
				listener.MonitorExe = ""
			}
		} else {
			newIndexes = append(newIndexes, len(refreshed))
		}
		refreshed = append(refreshed, listener)
	}

	removed := 0
	for _, listener := range existing {
		if !matchedExisting[listenerIdentity(listener)] {
			removed++
		}
	}
	return refreshed, newIndexes, removed
}

func listenerSocketIdentity(listener listenerInfo) string {
	return fmt.Sprintf("%d/%s/%d", listener.PID, listener.Address, listener.Port)
}

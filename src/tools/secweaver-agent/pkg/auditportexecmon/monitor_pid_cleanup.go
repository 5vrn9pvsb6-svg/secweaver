package auditportexecmon

import (
	"fmt"
	"os"

	"time"
)

// This file owns dead-process detection and idempotent removal of PID-scoped audit rules.

func (m *processTreeMonitor) pruneDeadPIDs() {
	// kill(pid, 0) alone is insufficient because Linux can reuse a numeric PID.
	// starttime from /proc/<pid>/stat identifies the original process lifetime.
	m.mu.Lock()
	pids := make(map[int]uint64, len(m.monitored))
	for pid := range m.monitored {
		pids[pid] = m.processStartTimes[pid]
	}
	m.mu.Unlock()
	for pid, expectedStartTime := range pids {
		alive := isProcessAlive(pid)
		if alive {
			currentStartTime := readProcessStartTime(pid)
			if expectedStartTime == 0 || currentStartTime == 0 || currentStartTime == expectedStartTime {
				continue
			}
			fmt.Fprintf(os.Stderr, "pid identity changed; removing stale audit rules: pid=%d old_starttime=%d new_starttime=%d\n", pid, expectedStartTime, currentStartTime)
		} else {
			fmt.Fprintf(os.Stderr, "pid exited; removing audit rules: pid=%d\n", pid)
		}
		m.removePIDRules(pid)
	}
}

func procAlive(pid int) bool {
	if pid <= 1 {
		return false
	}
	_, err := os.Stat(fmt.Sprintf("/proc/%d", pid))
	return err == nil
}

func (m *processTreeMonitor) removePIDRules(pid int) {
	// Delete exact rules one at a time and subtract only confirmed deletions from
	// the ledger. A partial kernel failure leaves the PID monitored and schedules
	// retry, preventing both orphaned ownership and duplicate reinstallation.
	//
	// CRITICAL: To prevent memory leaks from perpetually failing deletions, we:
	// 1. Track failure count and first failure time per PID
	// 2. After maxCleanupRetries or maxCleanupAge, force release memory state
	// 3. Log detailed error for manual intervention
	const (
		maxCleanupRetries = 10               // Max retry attempts before giving up
		maxCleanupAge     = 10 * time.Minute // Max time before forcing cleanup
	)

	m.mu.Lock()
	tracker := m.processTracker
	var remove []auditRule
	for _, rule := range m.rules {
		if rule.Field != "exe" && rule.PID == pid {
			remove = append(remove, rule)
		}
	}

	// Check if we should force cleanup due to excessive failures
	failureCount := m.pidCleanupFailureCount[pid]
	firstFailed := m.pidCleanupFirstFailed[pid]
	forceCleanup := false

	if failureCount >= maxCleanupRetries {
		forceCleanup = true
		fmt.Fprintf(os.Stderr, "CRITICAL: force cleanup pid=%d after %d failed attempts; kernel rules may be orphaned\n", pid, failureCount)
	} else if !firstFailed.IsZero() && time.Since(firstFailed) > maxCleanupAge {
		forceCleanup = true
		fmt.Fprintf(os.Stderr, "CRITICAL: force cleanup pid=%d after %s of failures; kernel rules may be orphaned\n", pid, time.Since(firstFailed))
	}

	m.mu.Unlock()

	if tracker != nil {
		_ = tracker.Untrack(uint32(pid))
	}

	var deleted []auditRule
	failed := false
	for i := len(remove) - 1; i >= 0; i-- {
		if err := runAuditctl(remove[i].auditctlArgs("-d")...); err != nil {
			failed = true
			fmt.Fprintf(os.Stderr, "remove dead pid rule failed: pid=%d err=%v\n", pid, err)
			continue
		}
		deleted = append(deleted, remove[i])
	}

	m.mu.Lock()
	m.rules = subtractAuditRules(m.rules, deleted)

	// Determine if we should clear memory state
	shouldClearMemory := false

	if !failed && !hasPIDRules(m.rules, pid) {
		// Success: all rules removed
		shouldClearMemory = true
	} else if failed && forceCleanup {
		// Force cleanup: too many failures or too old
		shouldClearMemory = true

		// Log residual rules for manual cleanup
		residualCount := 0
		for _, rule := range m.rules {
			if rule.Field != "exe" && rule.PID == pid {
				residualCount++
			}
		}
		fmt.Fprintf(os.Stderr, "CRITICAL: forced memory cleanup for pid=%d with %d residual kernel rules; manual auditctl cleanup may be required\n", pid, residualCount)
	} else if failed {
		// Track failure for future force cleanup decision
		if m.pendingPIDRuleCleanup == nil {
			m.pendingPIDRuleCleanup = map[int]bool{}
		}
		m.pendingPIDRuleCleanup[pid] = true

		// Increment failure tracking
		if m.pidCleanupFailureCount == nil {
			m.pidCleanupFailureCount = map[int]int{}
		}
		if m.pidCleanupFirstFailed == nil {
			m.pidCleanupFirstFailed = map[int]time.Time{}
		}

		m.pidCleanupFailureCount[pid]++
		if m.pidCleanupFirstFailed[pid].IsZero() {
			m.pidCleanupFirstFailed[pid] = time.Now()
		}

		newCount := m.pidCleanupFailureCount[pid]
		if newCount%5 == 0 {
			fmt.Fprintf(os.Stderr, "WARNING: pid cleanup failed %d times for pid=%d (first failed %s ago)\n",
				newCount, pid, time.Since(m.pidCleanupFirstFailed[pid]))
		}
	}

	if shouldClearMemory {
		// Clear all memory state for this PID
		delete(m.monitored, pid)
		delete(m.processStartTimes, pid)
		delete(m.processParentPIDs, pid)
		delete(m.processObservedAt, pid)
		delete(m.pidListener, pid)
		delete(m.pidTargets, pid)
		delete(m.pendingRuleExpansion, pid)
		delete(m.suppressedCloneRules, pid)
		delete(m.pendingPIDRuleCleanup, pid)
		delete(m.pidCleanupFailureCount, pid)
		delete(m.pidCleanupFirstFailed, pid)
	}

	m.mu.Unlock()

	if len(deleted) > 0 {
		m.resumeRuleBudgetRecovery()
	}
}

func (m *processTreeMonitor) forgetTrackedPID(pid int) {
	m.mu.Lock()
	delete(m.monitored, pid)
	delete(m.processStartTimes, pid)
	delete(m.processParentPIDs, pid)
	delete(m.processObservedAt, pid)
	delete(m.pidListener, pid)
	delete(m.pidTargets, pid)
	delete(m.pendingRuleExpansion, pid)
	delete(m.suppressedCloneRules, pid)
	delete(m.pendingPIDRuleCleanup, pid)
	m.mu.Unlock()
}

// observeEBPFEvent mirrors kernel map ownership into the userspace attribution
// cache. Fork and exit events never invoke auditctl on the event-reader path.

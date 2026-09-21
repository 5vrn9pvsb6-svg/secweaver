package auditportexecmon

import (
	"fmt"
	"os"

	"sync/atomic"
)

// This file owns executable and PID audit-rule expansion, budget reservation, and rule identity helpers.

func (m *processTreeMonitor) addExeRules(listener listenerInfo) error {
	// Reserve the complete group before the first auditctl call. exeMonitored is
	// then set as an in-flight ownership marker so concurrent companion discovery
	// cannot install the same executable group twice.
	if sameExecutablePath(listener.MonitorExe, m.selfExe) {
		return nil
	}
	m.mu.Lock()
	if m.exeMonitored[listener.MonitorExe] {
		m.mu.Unlock()
		return nil
	}
	m.mu.Unlock()
	estimatedRules := len(normalizeAuditArches(m.auditArches)) * m.estimateExeRuleGroupCount(listener)
	if estimatedRules == 0 {
		return nil
	}
	if !m.reserveAdditionalAuditRules(estimatedRules, listener.PID, "exe") {
		return nil
	}
	defer m.releaseRuleReservation(estimatedRules)

	m.mu.Lock()
	if m.exeMonitored[listener.MonitorExe] {
		m.mu.Unlock()
		return nil
	}
	// Reserve the executable before invoking auditctl so concurrent or periodic
	// companion discovery cannot add the same rule set more than once.
	m.exeMonitored[listener.MonitorExe] = true
	m.mu.Unlock()

	var added []auditRule
	// The outer transaction spans exec, connect, and file groups. Individual
	// addAuditRulesByExe calls are atomic per group; this rollback provides atomic
	// behavior across all enabled capabilities for the executable.
	rollback := func(cause error) error {
		residual, err := rollbackAuditRules(added)
		if err != nil {
			cause = fmt.Errorf("%w; rollback exe rules: %v", cause, err)
			m.appendRules(residual)
		}
		m.mu.Lock()
		if len(residual) == 0 {
			delete(m.exeMonitored, listener.MonitorExe)
		} else {
			if m.pendingExeRuleCleanup == nil {
				m.pendingExeRuleCleanup = map[string]bool{}
			}
			m.pendingExeRuleCleanup[cleanDeletedSuffix(listener.MonitorExe)] = true
		}
		m.mu.Unlock()
		return cause
	}
	if m.shouldMonitorExec(listener) && m.usesDynamicPIDRules() {
		rules, err := addAuditRulesByExe(listener.MonitorExe, m.execKey, []string{"execve", "execveat"}, m.auditArches)
		if err != nil {
			added = append(added, rules...)
			return rollback(err)
		}
		added = append(added, rules...)
	}
	if m.shouldMonitorConnect(listener) && !m.usesBoundedAudit() {
		connectRules, err := addAuditRulesByExe(listener.MonitorExe, m.connectKey, []string{"connect"}, m.auditArches)
		if err != nil {
			added = append(added, connectRules...)
			return rollback(err)
		}
		added = append(added, connectRules...)
	}
	if m.monitorFileOps && m.portEnabled(listener.Port, m.fileListenerPorts) && !m.usesBoundedAudit() {
		fileRules, err := addAuditRulesByExe(listener.MonitorExe, m.fileKey, fileAuditSyscalls(), m.auditArches)
		if err != nil {
			added = append(added, fileRules...)
			return rollback(err)
		}
		added = append(added, fileRules...)
	}
	m.appendRules(added)
	return nil
}

func (m *processTreeMonitor) estimateExeRuleGroupCount(listener listenerInfo) int {
	count := 0
	if m.shouldMonitorExec(listener) && m.usesDynamicPIDRules() {
		count++
	}
	if m.shouldMonitorConnect(listener) && !m.usesBoundedAudit() {
		count++
	}
	if m.monitorFileOps && m.portEnabled(listener.Port, m.fileListenerPorts) && !m.usesBoundedAudit() {
		count++
	}
	return count
}

func (m *processTreeMonitor) expandPID(pid int, listener listenerInfo) error {
	return m.expandPIDExpected(pid, readProcessStartTime(pid), listener)
}

func (m *processTreeMonitor) expandPIDExpected(pid int, expectedStartTime uint64, listener listenerInfo) error {
	// Validate identity before reserving budget and again after installation.
	// A process can exit and its PID can be reused while auditctl commands are in
	// flight; the second check removes rules installed for the wrong lifetime.
	if pid <= 1 || !isProcessAlive(pid) || m.isSelfProcessTree(pid) {
		return nil
	}
	if m.usesDynamicPIDRules() && m.shouldPauseDynamicExpansion(pid, listener) {
		m.deferRuleExpansion(pid, listener)
		return nil
	}
	startTime := readProcessStartTime(pid)
	if expectedStartTime != 0 && startTime != 0 && startTime != expectedStartTime {
		return nil
	}
	if m.usesBoundedAudit() {
		// Fixed-rule audit needs only userspace identity state. Registering here
		// keeps bootstrap and reconciliation on the same PID-reuse path as clone
		// events and guarantees this backend never enters rule reservations.
		m.rememberBoundedAuditPID(pid, readProcPPID(pid), listener)
		return nil
	}
	estimatedRules := m.estimatePIDRuleCount(pid, listener)
	already, reserved := m.reservePIDExpansion(pid, startTime, listener, estimatedRules)
	if already {
		if m.usesDynamicPIDRules() && m.trackDescendants && m.shouldMonitorExec(listener) {
			m.expandExistingDescendants(pid, listener)
		}
		return nil
	}
	if !reserved {
		m.deferExpansionBlockedByRuleBudget(pid, listener)
		return nil
	}
	defer m.releaseRuleReservation(estimatedRules)
	if m.usesEBPF() {
		m.mu.Lock()
		tracker := m.processTracker
		m.mu.Unlock()
		if err := tracker.Track(uint32(pid), uint32(readProcPPID(pid)), uint32(listener.PID), m.trackDescendants); err != nil {
			m.forgetTrackedPID(pid)
			return err
		}
	}

	if m.shouldMonitorExec(listener) && m.usesDynamicPIDRules() {
		rules, err := addAuditRules(pid, m.execKey, true, []string{"execve", "execveat"}, m.auditArches)
		if err != nil {
			m.appendRules(rules)
			m.removePIDRules(pid)
			return err
		}
		m.appendRules(rules)

		if m.trackDescendants && m.shouldAddDynamicCloneRules(pid, listener) {
			cloneRules, err := addAuditRules(pid, m.cloneKey, true, auditCloneSyscalls(), m.auditArches)
			if err != nil {
				m.appendRules(cloneRules)
				m.removePIDRules(pid)
				return err
			}
			m.appendRules(cloneRules)
		} else if m.trackDescendants {
			m.markCloneRulesSuppressed(pid, listener)
		}
	}

	pressureDegraded := m.pressureDegraded()
	if !pressureDegraded && m.shouldMonitorConnect(listener) && !m.usesBoundedAudit() {
		connectRules, err := addAuditRules(pid, m.connectKey, true, []string{"connect"}, m.auditArches)
		if err != nil {
			m.appendRules(connectRules)
			m.removePIDRules(pid)
			return err
		}
		m.appendRules(connectRules)
	}
	if !pressureDegraded && m.monitorFileOps && m.portEnabled(listener.Port, m.fileListenerPorts) && !m.usesBoundedAudit() {
		fileRules, err := addAuditRules(pid, m.fileKey, true, fileAuditSyscalls(), m.auditArches)
		if err != nil {
			m.appendRules(fileRules)
			m.removePIDRules(pid)
			return err
		}
		m.appendRules(fileRules)
	}
	if startTime != 0 {
		if current := readProcessStartTime(pid); current != 0 && current != startTime {
			m.removePIDRules(pid)
			return nil
		}
	}
	if m.usesDynamicPIDRules() && m.trackDescendants && m.shouldMonitorExec(listener) && m.allowSynchronousDescendantExpansion() {
		m.expandExistingDescendants(pid, listener)
	}
	return nil
}

func (m *processTreeMonitor) estimatePIDRuleCount(pid int, listener listenerInfo) int {
	arches := normalizeAuditArches(m.auditArches)
	perPIDRuleGroup := 2 * len(arches) // pid and ppid filters
	count := 0
	pressureDegraded := m.pressureDegraded()
	if m.shouldMonitorExec(listener) && m.usesDynamicPIDRules() {
		count += perPIDRuleGroup
		if m.trackDescendants && m.shouldAddDynamicCloneRules(pid, listener) {
			count += perPIDRuleGroup
		}
	}
	if !pressureDegraded && m.shouldMonitorConnect(listener) && !m.usesBoundedAudit() {
		count += perPIDRuleGroup
	}
	if !pressureDegraded && m.monitorFileOps && m.portEnabled(listener.Port, m.fileListenerPorts) && !m.usesBoundedAudit() {
		count += perPIDRuleGroup
	}
	return count
}

func (m *processTreeMonitor) reservePIDExpansion(pid int, startTime uint64, listener listenerInfo, estimatedRules int) (already, reserved bool) {
	// Reservation and monitored ownership are committed under one lock. This is
	// the hard max_rules gate: concurrent jobs count both installed and in-flight
	// rules, so they cannot collectively oversubscribe the configured budget.
	m.mu.Lock()
	if m.monitored[pid] {
		m.mu.Unlock()
		return true, false
	}
	if estimatedRules > 0 && m.maxAuditRules > 0 && m.currentAuditRuleCountLocked()+m.reservedAuditRules+estimatedRules > m.maxAuditRules {
		currentRules := m.currentAuditRuleCountLocked()
		reservedRules := m.reservedAuditRules
		maxRules := m.maxAuditRules
		firstLimitHit := !m.ruleLimitReached
		m.ruleLimitReached = true
		m.mu.Unlock()
		skips := atomic.AddUint64(&m.ruleExpansionRuleLimited, 1)
		if firstLimitHit || skips%100 == 0 {
			fmt.Fprintf(os.Stderr, "audit rule limit reached; skip pid expansion: pid=%d process=%s port=%d current_rules=%d reserved_rules=%d estimated_new_rules=%d max_rules=%d skipped=%d\n",
				pid,
				listener.Process,
				listener.Port,
				currentRules,
				reservedRules,
				estimatedRules,
				maxRules,
				skips,
			)
		}
		return false, false
	}
	m.monitored[pid] = true
	if m.processStartTimes == nil {
		m.processStartTimes = map[int]uint64{}
	}
	m.processStartTimes[pid] = startTime
	m.pidListener[pid] = listener
	if estimatedRules > 0 {
		m.reservedAuditRules += estimatedRules
	}
	m.mu.Unlock()
	return false, true
}

func (m *processTreeMonitor) releaseRuleReservation(count int) {
	if count <= 0 {
		return
	}
	m.mu.Lock()
	m.reservedAuditRules -= count
	if m.reservedAuditRules < 0 {
		m.reservedAuditRules = 0
	}
	m.mu.Unlock()
}

func (m *processTreeMonitor) reserveAdditionalAuditRules(count, pid int, kind string) bool {
	// Used by executable, watch, and clone-recovery paths that do not reserve a
	// new PID. It shares the same installed+reserved accounting as PID expansion.
	if count <= 0 {
		return true
	}
	m.mu.Lock()
	if m.maxAuditRules > 0 && m.currentAuditRuleCountLocked()+m.reservedAuditRules+count > m.maxAuditRules {
		currentRules := m.currentAuditRuleCountLocked()
		reservedRules := m.reservedAuditRules
		maxRules := m.maxAuditRules
		m.ruleLimitReached = true
		m.mu.Unlock()
		skips := atomic.AddUint64(&m.ruleExpansionRuleLimited, 1)
		if skips == 1 || skips%100 == 0 {
			fmt.Fprintf(os.Stderr, "audit rule limit reached; skip additional rules: kind=%s pid=%d current_rules=%d reserved_rules=%d estimated_new_rules=%d max_rules=%d skipped=%d\n",
				kind, pid, currentRules, reservedRules, count, maxRules, skips)
		}
		return false
	}
	m.reservedAuditRules += count
	m.mu.Unlock()
	return true
}

func (m *processTreeMonitor) currentAuditRuleCountLocked() int {
	return len(m.rules) + len(m.watchRules)
}

func (m *processTreeMonitor) deferExpansionBlockedByRuleBudget(pid int, listener listenerInfo) {
	m.mu.Lock()
	if m.pressureRecovering {
		m.pressureRecoveryBlocked = true
		m.deferRuleExpansionLocked(pid, listener)
	}
	m.mu.Unlock()
}

func (m *processTreeMonitor) forgetPID(pid int) {
	m.mu.Lock()
	delete(m.monitored, pid)
	delete(m.processStartTimes, pid)
	delete(m.processParentPIDs, pid)
	delete(m.processObservedAt, pid)
	delete(m.pidListener, pid)
	delete(m.pendingRuleExpansion, pid)
	delete(m.pendingPIDRuleCleanup, pid)
	delete(m.suppressedCloneRules, pid)
	m.mu.Unlock()
}

func (m *processTreeMonitor) expandExistingDescendants(pid int, listener listenerInfo) {
	skipSelf := func(p int) bool { return m.isSelfProcessTree(p) }
	for _, child := range collectDescendantPIDs(pid, skipSelf) {
		_ = m.expandPID(child, listener)
	}
}

func (m *processTreeMonitor) needsAuxiliaryAuditRules(listener listenerInfo) bool {
	return m.shouldMonitorConnect(listener) || (m.monitorFileOps && m.portEnabled(listener.Port, m.fileListenerPorts))
}

func hasPIDRules(rules []auditRule, pid int) bool {
	for _, rule := range rules {
		if rule.Field != "exe" && rule.PID == pid {
			return true
		}
	}
	return false
}

func subtractAuditRules(rules, remove []auditRule) []auditRule {
	if len(remove) == 0 {
		return rules
	}
	remaining := append([]auditRule(nil), rules...)
	for _, target := range remove {
		for i, rule := range remaining {
			if !sameAuditRule(rule, target) {
				continue
			}
			remaining = append(remaining[:i], remaining[i+1:]...)
			break
		}
	}
	return remaining
}

func sameAuditRule(a, b auditRule) bool {
	if a.Arch != b.Arch || a.Field != b.Field || a.PID != b.PID || a.Exe != b.Exe || a.Key != b.Key || len(a.Syscalls) != len(b.Syscalls) {
		return false
	}
	for i := range a.Syscalls {
		if a.Syscalls[i] != b.Syscalls[i] {
			return false
		}
	}
	return true
}

func (m *processTreeMonitor) appendRules(rules []auditRule) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rules = append(m.rules, rules...)
}

func (m *processTreeMonitor) shouldMonitorConnect(listener listenerInfo) bool {
	return shouldMonitorListenerConnect(listener, m.monitorConnect, m.connectListenerPorts, m.skipConnectListenerPorts, m.skipConnectProcessNames, m.skipConnectExePatterns)
}

func (m *processTreeMonitor) portEnabled(port int, selected map[int]bool) bool {
	return len(selected) == 0 || selected[port]
}

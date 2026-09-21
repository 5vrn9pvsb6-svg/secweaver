package auditportexecmon

import (
	"fmt"
	"os"
	"sync/atomic"
	"time"
)

type auditPressureLevel uint8

const (
	auditPressureNormal auditPressureLevel = iota
	auditPressureLight
	auditPressureMedium
	auditPressureSevere
	// Deferred work is bounded independently from the live worker queue. During
	// sustained pressure, dropping the oldest opportunity is preferable to
	// unbounded agent memory growth.
	maxDeferredRuleExpansions = 8192
)

func (level auditPressureLevel) String() string {
	switch level {
	case auditPressureLight:
		return "light"
	case auditPressureMedium:
		return "medium"
	case auditPressureSevere:
		return "severe"
	default:
		return "normal"
	}
}

func (m *processTreeMonitor) configureAuditPressure(cfg auditPressureRuntimeConfig) {
	m.mu.Lock()
	m.pressureConfig = cfg
	m.mu.Unlock()
}

func (m *processTreeMonitor) enterPressureDegraded(cooldown time.Duration, reason string) {
	m.updateAuditPressure(auditPressureLight, cooldown, reason, time.Now())
}

func (m *processTreeMonitor) updateAuditPressure(sample auditPressureLevel, cooldown time.Duration, reason string, now time.Time) {
	// Escalation is immediate. De-escalation waits for the current cooldown and
	// can move one or more levels based on the latest valid sample. Returning to
	// normal starts a separate, rate-limited reconciliation phase.
	//
	// CRITICAL: This function must maintain atomicity between pressure level updates
	// and recovery state changes. We hold the lock through the entire state transition
	// and defer recovery initiation until after the lock is released.
	if cooldown <= 0 {
		cooldown = 2 * time.Minute
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	previous := m.pressureLevel
	target := previous

	// Determine target pressure level based on sample and cooldown
	switch {
	case sample == auditPressureNormal:
		if previous != auditPressureNormal && !now.Before(m.pressureDegradedUntil) {
			target = auditPressureNormal
		}
	case previous == auditPressureNormal || sample > previous:
		target = sample
		m.pressureDegradedUntil = now.Add(cooldown)
	case sample == previous:
		m.pressureDegradedUntil = now.Add(cooldown)
	case !now.Before(m.pressureDegradedUntil):
		target = sample
		m.pressureDegradedUntil = now.Add(cooldown)
	}

	// Early exit if no state change
	if target == previous {
		return
	}

	// Atomically update all pressure-related state under the lock
	m.pressureLevel = target
	m.pressureReason = reason
	atomic.AddUint64(&m.pressureTransitions, 1)

	// Update recovery state based on target level
	if target == auditPressureNormal {
		m.pressureRecovering = true
		m.pressureRecoveryScanning = true
		m.pressureRecoveryBlocked = false
	} else {
		m.pressureRecovering = false
		m.pressureRecoveryScanning = false
		m.pressureRecoveryBlocked = false
	}

	until := m.pressureDegradedUntil
	shouldStartRecovery := (target == auditPressureNormal)

	// Release lock before potentially expensive recovery operation
	m.mu.Unlock()

	// Log the state change
	if shouldStartRecovery {
		fmt.Fprintf(os.Stderr, "audit pressure recovered after cooldown; starting rate-limited process-tree reconciliation\n")
	} else {
		fmt.Fprintf(os.Stderr, "audit pressure level changed: from=%s to=%s reason=%s until=%s\n", previous, target, reason, until.Format(time.RFC3339))
	}

	// Start recovery outside the lock to avoid blocking other operations
	if shouldStartRecovery {
		m.beginPressureRecovery()
	}

	// Re-acquire lock after recovery initiation (defer will unlock again)
	m.mu.Lock()
}

func (m *processTreeMonitor) pressureLevelSnapshot() auditPressureLevel {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.pressureLevel
}

func (m *processTreeMonitor) pressureDegraded() bool {
	return m.pressureLevelSnapshot() != auditPressureNormal
}

func (m *processTreeMonitor) criticalPressureRoot(pid int, listener listenerInfo) bool {
	// Web gateways and sshd are trust-boundary roots. Losing their clone coverage
	// would hide the first process created after exploitation, so they retain it
	// even when ordinary descendants are degraded.
	return pid == listener.PID && (isWebGatewayListener(listener) || isSSHDListener(listener))
}

func (m *processTreeMonitor) shouldPauseDynamicExpansion(pid int, listener listenerInfo) bool {
	return m.pressureLevelSnapshot() == auditPressureSevere && !m.criticalPressureRoot(pid, listener)
}

func (m *processTreeMonitor) shouldAddDynamicCloneRules(pid int, listener listenerInfo) bool {
	level := m.pressureLevelSnapshot()
	return level < auditPressureMedium || m.criticalPressureRoot(pid, listener)
}

func (m *processTreeMonitor) allowSynchronousDescendantExpansion() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.pressureLevel == auditPressureNormal && !m.pressureRecovering
}

func (m *processTreeMonitor) deferQueuedExpansionForPressure(job ruleExpansion) bool {
	// Removal and PID-reuse replacement are correctness operations, not optional
	// coverage growth, so pressure must never defer them.
	if job.Remove || job.Replace {
		return false
	}
	if job.CloneOnly {
		if m.pressureLevelSnapshot() >= auditPressureMedium && !m.criticalPressureRoot(job.PID, job.Listener) {
			m.markCloneRulesSuppressed(job.PID, job.Listener)
			return true
		}
		return false
	}
	if !m.shouldPauseDynamicExpansion(job.PID, job.Listener) {
		return false
	}
	m.deferRuleExpansion(job.PID, job.Listener)
	return true
}

func (m *processTreeMonitor) markCloneRulesSuppressed(pid int, listener listenerInfo) {
	// Store identity with the deferred job. Recovery verifies starttime before
	// adding rules so a reused PID cannot inherit another process's coverage.
	m.mu.Lock()
	if m.suppressedCloneRules == nil {
		m.suppressedCloneRules = map[int]ruleExpansion{}
	}
	if _, exists := m.suppressedCloneRules[pid]; !exists {
		startTime := m.processStartTimes[pid]
		if startTime == 0 {
			startTime = readProcessStartTime(pid)
		}
		m.suppressedCloneRules[pid] = ruleExpansion{PID: pid, Listener: listener, CloneOnly: true, StartTime: startTime}
		atomic.AddUint64(&m.pressurePausedExpansions, 1)
	}
	m.mu.Unlock()
}

// restoreSuppressedCloneRules reinstalls clone coverage omitted at medium
// pressure. Capacity exhaustion leaves the job suppressed and marks recovery as
// blocked; deletion of existing rules will wake recovery later.
func (m *processTreeMonitor) restoreSuppressedCloneRules(pid int, expectedStartTime uint64, listener listenerInfo) error {
	// P1-6: Fix TOCTOU - check process alive while holding lock
	m.mu.Lock()
	if !isProcessAlive(pid) {
		delete(m.suppressedCloneRules, pid)
		m.mu.Unlock()
		return nil
	}
	m.mu.Unlock()

	if current := readProcessStartTime(pid); expectedStartTime != 0 && current != 0 && current != expectedStartTime {
		m.removePIDRules(pid)
		return nil
	}
	estimatedRules := 2 * len(normalizeAuditArches(m.auditArches))
	if !m.reserveAdditionalAuditRules(estimatedRules, pid, "clone_recovery") {
		m.markCloneRulesSuppressed(pid, listener)
		m.mu.Lock()
		m.pressureRecoveryBlocked = true
		m.mu.Unlock()
		return nil
	}
	defer m.releaseRuleReservation(estimatedRules)
	rules, err := addAuditRules(pid, m.cloneKey, true, auditCloneSyscalls(), m.auditArches)
	if err != nil {
		return err
	}
	m.appendRules(rules)
	m.mu.Lock()
	delete(m.suppressedCloneRules, pid)
	m.mu.Unlock()
	return nil
}

func (m *processTreeMonitor) deferRuleExpansion(pid int, listener listenerInfo) {
	m.mu.Lock()
	m.deferRuleExpansionLocked(pid, listener)
	m.mu.Unlock()
}

func (m *processTreeMonitor) deferRuleExpansionLocked(pid int, listener listenerInfo) {
	// Caller holds m.mu. Deduplication by PID bounds repeated clone events, while
	// StartTime makes the eventual job safe against PID reuse.
	if pid <= 1 || m.monitored[pid] {
		return
	}
	if m.deferredRuleExpansion == nil {
		m.deferredRuleExpansion = map[int]ruleExpansion{}
	}
	if _, exists := m.deferredRuleExpansion[pid]; exists {
		return
	}
	if len(m.deferredRuleExpansion) >= maxDeferredRuleExpansions {
		atomic.AddUint64(&m.ruleExpansionQueueFull, 1)
		return
	}
	m.deferredRuleExpansion[pid] = ruleExpansion{PID: pid, Listener: listener, StartTime: readProcessStartTime(pid)}
	paused := atomic.AddUint64(&m.pressurePausedExpansions, 1)
	if paused == 1 || paused%100 == 0 {
		fmt.Fprintf(os.Stderr, "audit pressure expansion paused: level=%s pid=%d process=%s deferred=%d paused_total=%d\n", m.pressureLevel, pid, listener.Process, len(m.deferredRuleExpansion), paused)
	}
}

func (m *processTreeMonitor) ruleExpansionRateLocked() int {
	if m.pressureRecovering {
		return m.pressureConfig.RecoveryRateLimitPerSecond
	}
	switch m.pressureLevel {
	case auditPressureLight:
		return m.pressureConfig.LightRateLimitPerSecond
	case auditPressureMedium, auditPressureSevere:
		return m.pressureConfig.MediumRateLimitPerSecond
	default:
		return 0
	}
}

func (m *processTreeMonitor) waitForRuleExpansionPermit(stop <-chan struct{}) bool {
	// A single worker plus this inter-operation delay is a simple global rate
	// limiter for auditctl mutations. Waiting remains interruptible so service
	// stop is not delayed by recovery throttling.
	m.mu.Lock()
	rate := m.ruleExpansionRateLocked()
	wait := time.Duration(0)
	if rate > 0 {
		interval := time.Second / time.Duration(rate)
		wait = time.Until(m.lastRuleExpansionAt.Add(interval))
	}
	m.mu.Unlock()
	if wait > 0 {
		timer := time.NewTimer(wait)
		select {
		case <-stop:
			timer.Stop()
			return false
		case <-timer.C:
		}
	}
	m.mu.Lock()
	m.lastRuleExpansionAt = time.Now()
	m.mu.Unlock()
	return true
}

// beginPressureRecovery snapshots current roots and discovers live descendants
// missed during degradation. It only enqueues work; the normal worker preserves
// serialization, deduplication, rule budgets, and rate limits.
func (m *processTreeMonitor) beginPressureRecovery() {
	m.mu.Lock()
	if m.pressureLevel != auditPressureNormal {
		m.mu.Unlock()
		return
	}
	m.pressureRecovering = true
	m.pressureRecoveryScanning = true
	listeners := append([]listenerInfo(nil), m.listeners...)
	targets := make(map[int]listenerInfo, len(m.pidTargets))
	for pid, target := range m.pidTargets {
		targets[pid] = target.Gateway
	}
	m.mu.Unlock()

	for _, listener := range listeners {
		if listener.ExeOnly || listener.PID <= 1 {
			continue
		}
		for _, pid := range collectDescendantPIDs(listener.PID, func(p int) bool { return m.isSelfProcessTree(p) }) {
			m.enqueuePIDExpansion(pid, listener)
		}
	}
	for rootPID, listener := range targets {
		for _, pid := range collectDescendantPIDs(rootPID, func(p int) bool { return m.isSelfProcessTree(p) }) {
			m.enqueuePIDExpansion(pid, listener)
		}
	}

	m.mu.Lock()
	m.pressureRecoveryScanning = false
	m.maybeFinishPressureRecoveryLocked()
	m.mu.Unlock()
	m.pumpDeferredRecovery()
}

// pumpDeferredRecovery moves at most one job into the worker queue. The worker
// calls it after each completion, producing controlled draining rather than a
// burst that would recreate the audit pressure that triggered degradation.
func (m *processTreeMonitor) pumpDeferredRecovery() {
	m.mu.Lock()
	if !m.pressureRecovering || m.pressureLevel != auditPressureNormal || m.ruleExpansionQueue == nil {
		m.mu.Unlock()
		return
	}
	if m.pressureRecoveryBlocked {
		m.mu.Unlock()
		return
	}
	var job ruleExpansion
	found := false
	for pid, candidate := range m.deferredRuleExpansion {
		if m.monitored[pid] || m.pendingRuleExpansion[pid] || !isProcessAlive(pid) {
			delete(m.deferredRuleExpansion, pid)
			continue
		}
		job = candidate
		delete(m.deferredRuleExpansion, pid)
		m.pendingRuleExpansion[pid] = true
		found = true
		break
	}
	if !found {
		for pid, candidate := range m.suppressedCloneRules {
			if m.pendingRuleExpansion[pid] || !isProcessAlive(pid) {
				if !isProcessAlive(pid) {
					delete(m.suppressedCloneRules, pid)
				}
				continue
			}
			job = candidate
			delete(m.suppressedCloneRules, pid)
			m.pendingRuleExpansion[pid] = true
			found = true
			break
		}
	}
	queue := m.ruleExpansionQueue
	if !found {
		m.maybeFinishPressureRecoveryLocked()
		m.mu.Unlock()
		return
	}
	m.mu.Unlock()
	select {
	case queue <- job:
		atomic.AddUint64(&m.ruleExpansionEnqueued, 1)
	default:
		m.mu.Lock()
		delete(m.pendingRuleExpansion, job.PID)
		if job.CloneOnly {
			if m.suppressedCloneRules == nil {
				m.suppressedCloneRules = map[int]ruleExpansion{}
			}
			m.suppressedCloneRules[job.PID] = job
		} else {
			m.deferRuleExpansionLocked(job.PID, job.Listener)
		}
		m.mu.Unlock()
	}
}

func (m *processTreeMonitor) maybeFinishPressureRecoveryLocked() {
	// Recovery is complete only when the source maps, pending ownership map, and
	// channel are all empty. Checking just channel depth can race with a job that
	// has been dequeued but has not finished its auditctl transaction.
	if !m.pressureRecovering || m.pressureRecoveryScanning || m.pressureLevel != auditPressureNormal {
		return
	}
	queueEmpty := m.ruleExpansionQueue == nil || len(m.ruleExpansionQueue) == 0
	if len(m.deferredRuleExpansion) == 0 && len(m.suppressedCloneRules) == 0 && len(m.pendingRuleExpansion) == 0 && queueEmpty {
		m.pressureRecovering = false
		fmt.Fprintf(os.Stderr, "audit pressure recovery reconciliation complete\n")
	}
}

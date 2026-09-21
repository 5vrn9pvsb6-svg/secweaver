package auditportexecmon

import (
	"fmt"
	"os"

	"sync/atomic"
)

// This file owns asynchronous rule-expansion queue lifecycle, backpressure accounting, and immutable snapshots used by observability.

func (m *processTreeMonitor) startRuleExpansionWorker() {
	m.mu.Lock()
	if m.ruleExpansionQueue != nil {
		m.mu.Unlock()
		return
	}

	queue := make(chan ruleExpansion, 4096)
	rescanQueue := make(chan struct{}, 1)
	stop := make(chan struct{})
	done := make(chan struct{})
	m.ruleExpansionQueue = queue
	m.rescanQueue = rescanQueue
	m.ruleExpansionStop = stop
	m.ruleExpansionDone = done
	m.mu.Unlock()

	go func() {
		defer close(done)
		for {
			select {
			case job := <-queue:
				if m.usesDynamicPIDRules() {
					if m.deferQueuedExpansionForPressure(job) {
						m.finishQueuedExpansion(job.PID)
						continue
					}
					if !m.waitForRuleExpansionPermit(stop) {
						return
					}
					if m.deferQueuedExpansionForPressure(job) {
						m.finishQueuedExpansion(job.PID)
						continue
					}
				}
				m.expandQueuedPID(job)
				m.pumpDeferredRecovery()
			case <-rescanQueue:
				m.rescanDescendants()
			case <-stop:
				return
			}
		}
	}()
}

func (m *processTreeMonitor) setMaxAuditRules(limit int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.maxAuditRules = limit
}

func (m *processTreeMonitor) stopRuleExpansionWorker() {
	// Unpublish queues before closing stop so new producers fall back to the
	// synchronous startup/shutdown path instead of sending into an abandoned
	// channel. Waiting for done guarantees no auditctl mutation races with final
	// cleanupSessionRules.
	m.mu.Lock()
	stop := m.ruleExpansionStop
	done := m.ruleExpansionDone
	if stop == nil || done == nil {
		m.mu.Unlock()
		return
	}
	m.ruleExpansionQueue = nil
	m.rescanQueue = nil
	m.ruleExpansionStop = nil
	m.ruleExpansionDone = nil
	m.mu.Unlock()

	close(stop)
	<-done
}

func (m *processTreeMonitor) requestRescan() {
	m.mu.Lock()
	queue := m.rescanQueue
	m.mu.Unlock()
	if queue == nil {
		return
	}
	select {
	case queue <- struct{}{}:
	default:
		// A rescan is already pending. One current-state scan subsumes all
		// duplicate timer requests.
	}
}

func (m *processTreeMonitor) enqueuePIDExpansion(pid int, listener listenerInfo) {
	// P0-2: Enhanced PID reuse protection with atomic lock-held validation
	//
	// CRITICAL: This function must avoid TOCTOU (time-of-check-time-of-use) races
	// where a PID is reused between reading startTime and acquiring the lock.
	//
	// Strategy: We use a three-phase validation with minimal lock release:
	// 1. Quick pre-check without lock (optimization)
	// 2. Lock-held validation and state check
	// 3. Final validation before commit (after pressure check)
	if pid <= 1 || m.isSelfProcessTree(pid) {
		return
	}

	// Phase 1: Quick pre-check without lock (optimization to avoid lock contention)
	startTime := readProcessStartTime(pid)
	if startTime == 0 || !isProcessAlive(pid) {
		// Process dead or /proc read failed
		return
	}

	// Phase 2: Acquire lock and perform atomic validation
	m.mu.Lock()

	// CRITICAL: Re-read startTime while holding lock to ensure atomicity
	// This eliminates the TOCTOU window between the initial read and lock acquisition
	currentStartTime := readProcessStartTime(pid)
	if currentStartTime != startTime || currentStartTime == 0 {
		// PID was reused or process died between reads - abort safely
		m.mu.Unlock()
		return
	}

	// Now we have a consistent view: the PID's startTime is stable
	expectedStartTime := m.processStartTimes[pid]
	monitored := m.monitored[pid]
	replace := false

	if monitored {
		if expectedStartTime == startTime {
			// Same process, already monitored - deduplicate
			delete(m.deferredRuleExpansion, pid)
			atomic.AddUint64(&m.ruleExpansionDeduped, 1)
			m.mu.Unlock()
			return
		}
		// Different startTime means PID was reused - need to replace rules
		replace = expectedStartTime != 0 && startTime != 0
	}

	// Check if already pending
	if m.pendingRuleExpansion[pid] {
		delete(m.deferredRuleExpansion, pid)
		atomic.AddUint64(&m.ruleExpansionDeduped, 1)
		m.mu.Unlock()
		return
	}

	// Check pressure before committing to expansion
	replaceHint := replace
	m.mu.Unlock()

	if m.usesDynamicPIDRules() && !replaceHint && m.shouldPauseDynamicExpansion(pid, listener) {
		m.deferRuleExpansion(pid, listener)
		return
	}

	// Phase 3: Final validation and enqueue
	m.mu.Lock()

	// CRITICAL: Triple-check - verify process identity one more time before committing
	// This catches any PID reuse that occurred during the pressure check
	finalStartTime := readProcessStartTime(pid)
	if finalStartTime != startTime || finalStartTime == 0 {
		// Process changed during pressure check - abort safely
		m.mu.Unlock()
		return
	}

	// Re-check monitored state (may have changed during pressure check)
	if m.monitored[pid] && m.processStartTimes[pid] == startTime {
		delete(m.deferredRuleExpansion, pid)
		atomic.AddUint64(&m.ruleExpansionDeduped, 1)
		m.mu.Unlock()
		return
	}

	if m.pendingRuleExpansion[pid] {
		delete(m.deferredRuleExpansion, pid)
		atomic.AddUint64(&m.ruleExpansionDeduped, 1)
		m.mu.Unlock()
		return
	}

	queue := m.ruleExpansionQueue
	if queue == nil {
		// No queue - process synchronously
		m.mu.Unlock()
		if replace {
			m.removePIDRules(pid)
		}
		_ = m.expandPID(pid, listener)
		return
	}

	// Mark as pending and enqueue
	m.pendingRuleExpansion[pid] = true
	delete(m.deferredRuleExpansion, pid)
	m.mu.Unlock()

	job := ruleExpansion{PID: pid, Listener: listener, Replace: replace, StartTime: startTime}
	select {
	case queue <- job:
		atomic.AddUint64(&m.ruleExpansionEnqueued, 1)
	default:
		skips := atomic.AddUint64(&m.ruleExpansionQueueFull, 1)
		m.mu.Lock()
		delete(m.pendingRuleExpansion, pid)
		if m.pressureRecovering {
			m.deferRuleExpansionLocked(pid, listener)
		}
		m.mu.Unlock()
		if skips == 1 || skips%100 == 0 {
			fmt.Fprintf(os.Stderr, "audit rule expansion queue full; skip pid expansion: pid=%d process=%s port=%d skipped=%d\n", pid, listener.Process, listener.Port, skips)
		}
	}
}

// expandQueuedPID applies lifecycle jobs after the pressure gate and global
// auditctl rate limiter. Clone-only failures are returned to the suppressed map
// so recovery remains retryable rather than falsely completing.
func (m *processTreeMonitor) expandQueuedPID(job ruleExpansion) {
	if job.Remove {
		m.removePIDRules(job.PID)
		m.finishQueuedExpansion(job.PID)
		return
	}
	var err error
	if job.Replace {
		m.removePIDRules(job.PID)
	}
	if job.CloneOnly {
		err = m.restoreSuppressedCloneRules(job.PID, job.StartTime, job.Listener)
	} else {
		err = m.expandPIDExpected(job.PID, job.StartTime, job.Listener)
	}
	if err != nil {
		atomic.AddUint64(&m.ruleExpansionFailed, 1)
		fmt.Fprintf(os.Stderr, "async audit rule expansion failed: pid=%d process=%s port=%d err=%v\n", job.PID, job.Listener.Process, job.Listener.Port, err)
		if job.CloneOnly {
			m.markCloneRulesSuppressed(job.PID, job.Listener)
		}
	}
	atomic.AddUint64(&m.ruleExpansionExpanded, 1)
	m.finishQueuedExpansion(job.PID)
}

// enqueuePIDRemoval serializes stale-root cleanup with expansion work. This
// prevents a listener rescan from deleting rules while the same worker is still
// installing another group for that PID.
func (m *processTreeMonitor) enqueuePIDRemoval(pid int) {
	if pid <= 1 {
		return
	}
	m.mu.Lock()
	if !m.monitored[pid] || m.pendingRuleExpansion[pid] {
		m.mu.Unlock()
		return
	}
	queue := m.ruleExpansionQueue
	if queue == nil {
		m.mu.Unlock()
		m.removePIDRules(pid)
		return
	}
	m.pendingRuleExpansion[pid] = true
	m.mu.Unlock()
	select {
	case queue <- ruleExpansion{PID: pid, Remove: true}:
		atomic.AddUint64(&m.ruleExpansionEnqueued, 1)
	default:
		m.mu.Lock()
		delete(m.pendingRuleExpansion, pid)
		m.mu.Unlock()
		atomic.AddUint64(&m.ruleExpansionQueueFull, 1)
	}
}

func (m *processTreeMonitor) finishQueuedExpansion(pid int) {
	m.mu.Lock()
	delete(m.pendingRuleExpansion, pid)
	m.maybeFinishPressureRecoveryLocked()
	m.mu.Unlock()
}

func (m *processTreeMonitor) ruleExpansionStatsSnapshot() ruleExpansionStats {
	m.mu.Lock()
	pending := len(m.pendingRuleExpansion)
	queueDepth := 0
	if m.ruleExpansionQueue != nil {
		queueDepth = len(m.ruleExpansionQueue)
	}
	currentRules := m.currentAuditRuleCountLocked()
	reservedRules := m.reservedAuditRules
	maxRules := m.maxAuditRules
	pressureLevel := m.pressureLevel.String()
	recoveryActive := m.pressureRecovering
	recoveryPending := len(m.deferredRuleExpansion) + len(m.suppressedCloneRules) + len(m.pendingRuleExpansion)
	m.mu.Unlock()
	return ruleExpansionStats{
		Enqueued:        atomic.LoadUint64(&m.ruleExpansionEnqueued),
		Deduped:         atomic.LoadUint64(&m.ruleExpansionDeduped),
		QueueFull:       atomic.LoadUint64(&m.ruleExpansionQueueFull),
		Expanded:        atomic.LoadUint64(&m.ruleExpansionExpanded),
		Failed:          atomic.LoadUint64(&m.ruleExpansionFailed),
		RuleLimitSkips:  atomic.LoadUint64(&m.ruleExpansionRuleLimited),
		Pending:         pending,
		QueueDepth:      queueDepth,
		CurrentRules:    currentRules,
		ReservedRules:   reservedRules,
		MaxAuditRules:   maxRules,
		PressureLevel:   pressureLevel,
		PressurePaused:  atomic.LoadUint64(&m.pressurePausedExpansions),
		PressureEvents:  atomic.LoadUint64(&m.pressureTransitions),
		RecoveryActive:  recoveryActive,
		RecoveryPending: recoveryPending,
	}
}

func (m *processTreeMonitor) logRuleExpansionStats() {
	stats := m.ruleExpansionStatsSnapshot()
	parser := auditParserMetricsSnapshotNow()
	if stats.Enqueued == 0 && stats.Deduped == 0 && stats.QueueFull == 0 && stats.Expanded == 0 && stats.Failed == 0 && stats.RuleLimitSkips == 0 && stats.PressurePaused == 0 && stats.PressureEvents == 0 && parser.AccumulatorsCreated == 0 {
		return
	}
	// One shutdown record combines monitor-owned rule gauges with parser-owned
	// counters instead of maintaining a second listener-health metric model.
	fmt.Fprintf(os.Stderr, "audit runtime stats: events_processed=%d accumulators_created=%d accumulators_completed=%d accumulators_expired=%d rule_enqueued=%d rule_expanded=%d rule_failed=%d rule_deduped=%d queue_full=%d rule_limit_skips=%d pending=%d queue_depth=%d current_rules=%d reserved_rules=%d max_rules=%d pressure_level=%s pressure_paused=%d pressure_transitions=%d recovery_active=%v recovery_pending=%d\n",
		parser.EventsProcessed,
		parser.AccumulatorsCreated,
		parser.AccumulatorsCompleted,
		parser.AccumulatorsExpired,
		stats.Enqueued,
		stats.Expanded,
		stats.Failed,
		stats.Deduped,
		stats.QueueFull,
		stats.RuleLimitSkips,
		stats.Pending,
		stats.QueueDepth,
		stats.CurrentRules,
		stats.ReservedRules,
		stats.MaxAuditRules,
		stats.PressureLevel,
		stats.PressurePaused,
		stats.PressureEvents,
		stats.RecoveryActive,
		stats.RecoveryPending,
	)
}

func (m *processTreeMonitor) rulesSnapshot() []auditRule {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]auditRule, len(m.rules))
	copy(out, m.rules)
	return out
}

func (m *processTreeMonitor) watchRulesSnapshot() []auditWatchRule {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]auditWatchRule, len(m.watchRules))
	copy(out, m.watchRules)
	return out
}

func (m *processTreeMonitor) trackedCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.monitored)
}

package auditportexecmon

import (
	"fmt"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
)

// P1 Optimization: Batch /proc reading with parallel workers
// Significantly improves performance when scanning large process trees

// procStatBatch represents a batch of /proc reads
type procStatBatch struct {
	pid       int
	stat      string
	startTime uint64
	ppid      int
	err       error
}

// readMultipleProcStats reads /proc/[pid]/stat for multiple PIDs in parallel
func readMultipleProcStats(pids []int) map[int]procStatBatch {
	if len(pids) == 0 {
		return nil
	}

	results := make(map[int]procStatBatch, len(pids))
	if len(pids) == 1 {
		// Fast path for single PID
		pid := pids[0]
		stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if err != nil {
			results[pid] = procStatBatch{pid: pid, err: err}
		} else {
			statStr := string(stat)
			results[pid] = procStatBatch{
				pid:       pid,
				stat:      statStr,
				startTime: parseProcStatStartTime(statStr),
				ppid:      parseProcStatPPID(statStr),
			}
		}
		return results
	}

	// Parallel processing for multiple PIDs
	workers := runtime.NumCPU()
	if workers > len(pids) {
		workers = len(pids)
	}

	jobs := make(chan int, len(pids))
	resultsCh := make(chan procStatBatch, len(pids))

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for pid := range jobs {
				stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
				if err != nil {
					resultsCh <- procStatBatch{pid: pid, err: err}
					continue
				}
				statStr := string(stat)
				resultsCh <- procStatBatch{
					pid:       pid,
					stat:      statStr,
					startTime: parseProcStatStartTime(statStr),
					ppid:      parseProcStatPPID(statStr),
				}
			}
		}()
	}

	// Submit jobs
	for _, pid := range pids {
		jobs <- pid
	}
	close(jobs)

	// Wait for completion
	go func() {
		wg.Wait()
		close(resultsCh)
	}()

	// Collect results
	for result := range resultsCh {
		results[result.pid] = result
	}

	return results
}

// batchExpandPIDs expands multiple PIDs using batch /proc reading
func (m *processTreeMonitor) batchExpandPIDs(pids []int, listener listenerInfo) {
	if len(pids) == 0 {
		return
	}

	// Batch read all /proc stats
	stats := readMultipleProcStats(pids)

	// Process each PID with pre-read data
	for pid, stat := range stats {
		if stat.err != nil {
			// Process died or unreadable
			continue
		}

		// Use pre-read startTime instead of reading again
		m.enqueuePIDExpansionWithStartTime(pid, stat.startTime, listener)
	}
}

// enqueuePIDExpansionWithStartTime is an optimized version that uses pre-read startTime
func (m *processTreeMonitor) enqueuePIDExpansionWithStartTime(pid int, startTime uint64, listener listenerInfo) {
	if pid <= 1 || m.isSelfProcessTree(pid) || startTime == 0 {
		return
	}

	// Phase 1: Check if already monitored (with pre-read startTime)
	m.mu.Lock()
	expectedStartTime := m.processStartTimes[pid]
	monitored := m.monitored[pid]

	if monitored && expectedStartTime == startTime {
		// Same process, already monitored - deduplicate
		delete(m.deferredRuleExpansion, pid)
		atomic.AddUint64(&m.ruleExpansionDeduped, 1)
		m.mu.Unlock()
		return
	}

	// Check if already pending
	if m.pendingRuleExpansion[pid] {
		delete(m.deferredRuleExpansion, pid)
		atomic.AddUint64(&m.ruleExpansionDeduped, 1)
		m.mu.Unlock()
		return
	}

	replace := monitored && expectedStartTime != 0 && startTime != 0 && expectedStartTime != startTime
	m.mu.Unlock()

	// Phase 2: Check pressure
	if m.usesDynamicPIDRules() && !replace && m.shouldPauseDynamicExpansion(pid, listener) {
		m.deferRuleExpansion(pid, listener)
		return
	}

	// Phase 3: Enqueue
	m.mu.Lock()

	// Verify startTime one more time (already validated above, but keep for safety)
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

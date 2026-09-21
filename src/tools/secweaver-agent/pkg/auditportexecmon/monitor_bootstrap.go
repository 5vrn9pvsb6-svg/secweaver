package auditportexecmon

import (
	"context"
	"fmt"

	"runtime"
)

// This file owns initial coverage establishment and listener reconciliation. PID lifetime expansion is isolated in monitor_pid.go.

func (m *processTreeMonitor) bootstrap(ctx context.Context) error {
	// P1 Optimization: Parallel bootstrap for faster startup
	// Use worker pool to bootstrap listeners concurrently while maintaining
	// error handling and cancellation semantics.

	if err := m.bootstrapBoundedAuditRules(); err != nil {
		return err
	}
	if len(m.listeners) == 0 {
		return m.bootstrapSensitiveFileWatch()
	}

	// Result structure for collecting bootstrap results
	type bootstrapResult struct {
		index int
		err   error
	}

	// Use buffered channel to avoid goroutine leaks
	results := make(chan bootstrapResult, len(m.listeners))

	// Limit concurrency to number of CPUs to avoid overwhelming auditctl
	workers := runtime.GOMAXPROCS(0)
	if workers > len(m.listeners) {
		workers = len(m.listeners)
	}

	// Semaphore to limit concurrent workers
	sem := make(chan struct{}, workers)

	// Launch bootstrap for each listener
	for i := range m.listeners {
		go func(index int) {
			// Acquire semaphore
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				results <- bootstrapResult{index: index, err: ctx.Err()}
				return
			}
			defer func() { <-sem }() // Release semaphore

			// Check for cancellation
			if err := ctx.Err(); err != nil {
				results <- bootstrapResult{index: index, err: err}
				return
			}

			// Bootstrap this listener
			err := m.bootstrapListenerAt(index)
			results <- bootstrapResult{index: index, err: err}
		}(i)
	}

	// Collect results
	var firstErr error
	for i := 0; i < len(m.listeners); i++ {
		result := <-results
		if result.err != nil && firstErr == nil {
			firstErr = result.err
		}
	}

	if firstErr != nil {
		return firstErr
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	return m.bootstrapSensitiveFileWatch()
}

// bootstrapInitialContext gives initial rule installation transaction semantics
// across all listeners and watches. Any failure triggers key-based cleanup of
// everything already installed during this session.
func (m *processTreeMonitor) bootstrapInitialContext(ctx context.Context) error {
	if err := m.bootstrap(ctx); err != nil {
		if _, cleanupErr := m.cleanupSessionRules(); cleanupErr != nil {
			return fmt.Errorf("%w; rollback audit rules: %v", err, cleanupErr)
		}
		return err
	}
	return nil
}

func (m *processTreeMonitor) bootstrapInitial() error {
	return m.bootstrapInitialContext(context.Background())
}

func (m *processTreeMonitor) bootstrapSensitiveFileWatch() error {
	// Watch rules share the same hard budget as syscall rules. Successfully added
	// watches are recorded even when a later path fails so bootstrap rollback can
	// still remove the partial prefix.
	if !m.monitorSensitiveFileReads || len(m.sensitiveFilePaths) == 0 {
		return nil
	}
	if !m.reserveAdditionalAuditRules(len(m.sensitiveFilePaths), 0, "sensitive_watch") {
		return nil
	}
	defer m.releaseRuleReservation(len(m.sensitiveFilePaths))
	watches, err := addAuditWatchRules(m.sensitiveFilePaths, "r", m.sensitiveFileKey)
	m.mu.Lock()
	m.watchRules = append(m.watchRules, watches...)
	m.mu.Unlock()
	return err
}

func (m *processTreeMonitor) bootstrapListenerAt(index int) error {
	listener := m.listeners[index]
	if m.isSelfListener(listener) {
		return nil
	}
	if m.usesEBPF() {
		return m.bootstrapEBPFListener(listener)
	}
	if m.usesBoundedAudit() {
		return m.bootstrapBoundedAuditListener(listener)
	}
	var err error
	switch {
	case listener.ExeOnly && listener.MonitorExe != "":
		if isJavaListener(listener.Process, listener.MonitorExe) {
			err = m.bootstrapJava(listener)
			break
		}
		if isWebGatewayListener(listener) {
			err = m.bootstrapWebGateway(listener)
			break
		}
		if addErr := m.addExeRules(listener); addErr != nil {
			if fallbackErr := m.fallbackExeOnlyToPIDTree(index, listener, addErr); fallbackErr != nil {
				return fallbackErr
			}
		}
	case listener.MonitorExe != "":
		if addErr := m.addExeRules(listener); addErr != nil {
			err = addErr
			break
		}
		if m.trackDescendants {
			for _, pid := range findMonitorSeedPIDs(listener) {
				if expandErr := m.expandPID(pid, listener); expandErr != nil {
					err = expandErr
					break
				}
			}
		}
	case isSSHDListener(listener):
		err = m.bootstrapSSHD(listener)
	default:
		err = m.expandPID(listener.PID, listener)
	}
	if err != nil {
		return err
	}
	if isWebGatewayListener(listener) {
		m.bootstrapCompanionBackends(listener)
	}
	return nil
}

// bootstrapBoundedAuditListener seeds a userspace ownership map from one
// coherent /proc snapshot. Future clone records extend this map without adding
// audit rules, and periodic reconciliation repairs events missed during log
// rotation or reader restart.
func (m *processTreeMonitor) bootstrapBoundedAuditListener(listener listenerInfo) error {
	trackListener := listener
	trackListener.ExeOnly = false
	seeds := findMonitorSeedPIDs(listener)
	if len(seeds) == 0 && listener.PID > 1 {
		seeds = []int{listener.PID}
	}
	for _, pid := range seeds {
		if err := m.seedUserspaceProcessTree(pid, trackListener); err != nil {
			return err
		}
	}
	if isWebGatewayListener(listener) {
		m.bootstrapCompanionBackends(listener)
	}
	return nil
}

// seedUserspaceProcessTree snapshots descendants once and registers each PID
// without recursive per-node walks. This bounds startup procfs work and avoids
// the quadratic expansion pattern of the historical PID-rule backend.
func (m *processTreeMonitor) seedUserspaceProcessTree(pid int, listener listenerInfo) error {
	if err := m.expandPID(pid, listener); err != nil {
		return err
	}
	if !m.trackDescendants {
		return nil
	}
	skipSelf := func(candidate int) bool { return m.isSelfProcessTree(candidate) }
	for _, child := range collectDescendantPIDs(pid, skipSelf) {
		if err := m.expandPID(child, listener); err != nil {
			return err
		}
	}
	return nil
}

// bootstrapEBPFListener seeds process ownership without installing exec/clone
// audit rules. Auxiliary connect/file audit rules remain available when those
// explicitly enabled features require them.
func (m *processTreeMonitor) bootstrapEBPFListener(listener listenerInfo) error {
	trackListener := listener
	trackListener.ExeOnly = false
	if listener.MonitorExe != "" {
		if err := m.addExeRules(listener); err != nil {
			return err
		}
	}
	seeds := findMonitorSeedPIDs(listener)
	if len(seeds) == 0 && listener.PID > 1 {
		seeds = []int{listener.PID}
	}
	for _, pid := range seeds {
		if err := m.seedEBPFProcessTree(pid, trackListener); err != nil {
			return err
		}
	}
	if isSSHDListener(trackListener) {
		if err := m.expandSSHDSessionPIDs(trackListener); err != nil {
			return err
		}
	}
	if isWebGatewayListener(listener) {
		m.bootstrapCompanionBackends(listener)
	}
	return nil
}

func (m *processTreeMonitor) seedEBPFProcessTree(pid int, listener listenerInfo) error {
	if err := m.expandPID(pid, listener); err != nil {
		return err
	}
	if !m.trackDescendants {
		return nil
	}
	skipSelf := func(candidate int) bool { return m.isSelfProcessTree(candidate) }
	for _, child := range collectDescendantPIDs(pid, skipSelf) {
		if err := m.expandPID(child, listener); err != nil {
			return err
		}
	}
	return nil
}

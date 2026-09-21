package auditportexecmon

import "fmt"

// bootstrapBoundedAuditRules installs the complete fixed-rule transaction before
// listener ownership is seeded. A partial failure is rolled back immediately;
// residual rules stay in the monitor ledger so outer startup rollback can retry.
func (m *processTreeMonitor) bootstrapBoundedAuditRules() error {
	if !m.usesBoundedAudit() {
		return nil
	}
	m.mu.Lock()
	listeners := append([]listenerInfo(nil), m.listeners...)
	m.mu.Unlock()

	monitorExec := false
	monitorConnect := false
	monitorFileOps := false
	for _, listener := range listeners {
		monitorExec = monitorExec || m.shouldMonitorExec(listener)
		monitorConnect = monitorConnect || m.shouldMonitorConnect(listener)
		monitorFileOps = monitorFileOps || (m.monitorFileOps && m.portEnabled(listener.Port, m.fileListenerPorts))
	}
	type ruleGroup struct {
		key      string
		syscalls []string
	}
	groups := make([]ruleGroup, 0, 4)
	if monitorExec {
		groups = append(groups, ruleGroup{key: m.execKey, syscalls: []string{"execve", "execveat"}})
		if m.trackDescendants {
			groups = append(groups, ruleGroup{key: m.cloneKey, syscalls: auditCloneSyscalls()})
		}
	}
	if monitorConnect {
		groups = append(groups, ruleGroup{key: m.connectKey, syscalls: []string{"connect"}})
	}
	if monitorFileOps {
		groups = append(groups, ruleGroup{key: m.fileKey, syscalls: fileAuditSyscalls()})
	}
	if len(groups) == 0 {
		return nil
	}

	estimatedRules := len(groups) * len(normalizeAuditArches(m.auditArches))
	if !m.reserveAdditionalAuditRules(estimatedRules, 0, "bounded_global") {
		return fmt.Errorf("audit rule budget cannot reserve %d bounded global rules", estimatedRules)
	}
	defer m.releaseRuleReservation(estimatedRules)

	var added []auditRule
	for _, group := range groups {
		rules, err := addGlobalAuditRules(group.key, group.syscalls, m.auditArches)
		if err == nil {
			added = append(added, rules...)
			continue
		}
		added = append(added, rules...)
		residual, rollbackErr := rollbackAuditRules(added)
		m.appendRules(residual)
		if rollbackErr != nil {
			return fmt.Errorf("%w; rollback bounded global rules: %v", err, rollbackErr)
		}
		return err
	}
	m.appendRules(added)
	return nil
}

// estimateBoundedAuditRuleCount mirrors bootstrapBoundedAuditRules without
// touching kernel state. The estimate is exact unless an unsupported syscall is
// removed during installation, in which case the installed count is lower.
func estimateBoundedAuditRuleCount(monitorExec, trackDescendants, monitorConnect, monitorFileOps, monitorSensitive bool, sensitivePaths, arches []string) int {
	groups := 0
	if monitorExec {
		groups++
		if trackDescendants {
			groups++
		}
	}
	if monitorConnect {
		groups++
	}
	if monitorFileOps {
		groups++
	}
	count := groups * len(normalizeAuditArches(arches))
	if monitorSensitive {
		count += len(sensitivePaths)
	}
	return count
}

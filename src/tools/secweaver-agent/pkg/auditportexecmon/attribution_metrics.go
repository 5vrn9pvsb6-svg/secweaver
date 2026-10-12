package auditportexecmon

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// Reasons are fixed implementation literals, never values from audit records.
// Counts describe decisions (not unique events) and contain no command data.
var attributionReasons = []string{"snapshot_saved", "snapshot_used", "root_history_used", "process_history_used", "reparented", "identity_recovered", "identity_conflict", "root_unavailable", "history_missing", "history_expired", "history_evicted", "history_time_rejected", "transaction_conflict", "audit_rejected", "ebpf_rejected", "outside_scope"}

func (m *processTreeMonitor) recordAttribution(reason string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.recordAttributionLocked(reason)
}

func (m *processTreeMonitor) recordAttributionLocked(reason string) {
	if m.attributionCounts == nil {
		m.attributionCounts = make(map[string]uint64)
	}
	m.attributionCounts[reason]++
	m.attributionChanges++
}

// Both readers share this rate gate: at most one aggregate per 30s plus shutdown.
// Only fixed counters are formatted under mu; stderr is written after unlocking.
func (m *processTreeMonitor) logAttributionStats(force bool) {
	m.mu.Lock()
	if m.attributionChanges == m.attributionLogged || (!force && time.Since(m.attributionLogAt) < 30*time.Second) {
		m.mu.Unlock()
		return
	}
	var b strings.Builder
	b.WriteString("listener attribution stats:")
	for _, reason := range attributionReasons {
		fmt.Fprintf(&b, " %s=%d", reason, m.attributionCounts[reason])
	}
	fmt.Fprintf(&b, " root_history=%d process_history=%d\n", len(m.attributionHistory.roots), len(m.attributionHistory.processes))
	m.attributionLogged, m.attributionLogAt = m.attributionChanges, time.Now()
	m.mu.Unlock()
	fmt.Fprint(os.Stderr, b.String())
}

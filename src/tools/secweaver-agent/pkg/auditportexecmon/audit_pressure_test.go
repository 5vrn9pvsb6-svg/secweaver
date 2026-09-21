package auditportexecmon

import (
	"strings"
	"testing"
	"time"
)

func TestClassifyAuditPressureLevels(t *testing.T) {
	cfg := auditPressureRuntimeConfig{
		BacklogHighPercent: 80, MediumBacklogPercent: 90, SevereBacklogPercent: 95,
		LostDelta: 1, MediumLostDelta: 5, SevereLostDelta: 20,
	}
	tests := []struct {
		backlog   int
		lostDelta int
		want      auditPressureLevel
	}{
		{backlog: 10, want: auditPressureNormal},
		{backlog: 80, want: auditPressureLight},
		{backlog: 90, want: auditPressureMedium},
		{backlog: 95, want: auditPressureSevere},
		{backlog: 10, lostDelta: 5, want: auditPressureMedium},
		{backlog: 10, lostDelta: 20, want: auditPressureSevere},
	}
	for _, test := range tests {
		if got := classifyAuditPressure(test.backlog, 100, test.lostDelta, cfg); got != test.want {
			t.Fatalf("backlog=%d lost_delta=%d level=%s, want %s", test.backlog, test.lostDelta, got, test.want)
		}
	}
}

func TestMediumPressureSkipsCloneRulesForOrdinaryProcesses(t *testing.T) {
	originalCommand := runAuditctlCommand
	originalAlive := isProcessAlive
	originalStartTime := readProcessStartTime
	defer func() {
		runAuditctlCommand = originalCommand
		isProcessAlive = originalAlive
		readProcessStartTime = originalStartTime
	}()
	isProcessAlive = func(int) bool { return true }
	// The production queue validates PID identity twice; keep the synthetic PID alive
	// and stable so this test exercises pressure deferral instead of /proc lookup.
	readProcessStartTime = func(int) uint64 { return 100 }
	var calls [][]string
	runAuditctlCommand = func(timeout time.Duration, args ...string) ([]byte, error) {
		calls = append(calls, append([]string(nil), args...))
		return nil, nil
	}
	monitor := pressureTestMonitor()
	now := time.Now()
	monitor.updateAuditPressure(auditPressureMedium, time.Minute, "test", now)
	listener := listenerInfo{PID: 100, Process: "app", Port: 8080}
	if err := monitor.expandPID(999999, listener); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 {
		t.Fatalf("auditctl calls = %d, want two exec pid/ppid rules: %#v", len(calls), calls)
	}
	for _, call := range calls {
		if strings.Contains(strings.Join(call, " "), "clone") {
			t.Fatalf("ordinary medium-pressure expansion added clone rule: %#v", call)
		}
	}
}

func TestMediumPressureKeepsCloneRulesForWebRoot(t *testing.T) {
	originalCommand := runAuditctlCommand
	originalAlive := isProcessAlive
	defer func() {
		runAuditctlCommand = originalCommand
		isProcessAlive = originalAlive
	}()
	isProcessAlive = func(int) bool { return true }
	var calls [][]string
	runAuditctlCommand = func(timeout time.Duration, args ...string) ([]byte, error) {
		calls = append(calls, append([]string(nil), args...))
		return nil, nil
	}
	monitor := pressureTestMonitor()
	monitor.updateAuditPressure(auditPressureMedium, time.Minute, "test", time.Now())
	listener := listenerInfo{PID: 999999, Process: "nginx", Port: 80, MonitorExe: "/usr/sbin/nginx"}
	if err := monitor.expandPID(listener.PID, listener); err != nil {
		t.Fatal(err)
	}
	foundClone := false
	for _, call := range calls {
		if strings.Contains(strings.Join(call, " "), "clone") {
			foundClone = true
		}
	}
	if !foundClone {
		t.Fatalf("critical web root should retain clone rules: %#v", calls)
	}
}

func TestMediumPressureRestoresSuppressedCloneRulesAfterCooldown(t *testing.T) {
	originalCommand := runAuditctlCommand
	originalAlive := isProcessAlive
	defer func() {
		runAuditctlCommand = originalCommand
		isProcessAlive = originalAlive
	}()
	isProcessAlive = func(int) bool { return true }
	var calls [][]string
	runAuditctlCommand = func(timeout time.Duration, args ...string) ([]byte, error) {
		calls = append(calls, append([]string(nil), args...))
		return nil, nil
	}
	monitor := pressureTestMonitor()
	monitor.configureAuditPressure(auditPressureRuntimeConfig{RecoveryRateLimitPerSecond: 1000})
	monitor.startRuleExpansionWorker()
	defer monitor.stopRuleExpansionWorker()
	now := time.Now()
	monitor.updateAuditPressure(auditPressureMedium, 10*time.Millisecond, "test", now)
	listener := listenerInfo{PID: 100, Process: "app", Port: 8080}
	if err := monitor.expandPID(999999, listener); err != nil {
		t.Fatal(err)
	}
	if len(monitor.suppressedCloneRules) != 1 {
		t.Fatalf("suppressed clone rules = %d, want 1", len(monitor.suppressedCloneRules))
	}
	monitor.updateAuditPressure(auditPressureNormal, 10*time.Millisecond, "recovered", now.Add(20*time.Millisecond))
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		monitor.mu.Lock()
		pending := len(monitor.suppressedCloneRules)
		recovering := monitor.pressureRecovering
		monitor.mu.Unlock()
		if pending == 0 && !recovering {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	foundClone := false
	for _, call := range calls {
		if strings.Contains(strings.Join(call, " "), "clone") {
			foundClone = true
		}
	}
	if !foundClone {
		t.Fatalf("suppressed clone rule was not restored: %#v", calls)
	}
	stats := monitor.ruleExpansionStatsSnapshot()
	if stats.RecoveryActive || stats.RecoveryPending != 0 {
		t.Fatalf("clone recovery did not finish: %+v", stats)
	}
}

func TestSeverePressureDefersAndRecoversPIDExpansion(t *testing.T) {
	originalCommand := runAuditctlCommand
	originalAlive := isProcessAlive
	originalStartTime := readProcessStartTime
	defer func() {
		runAuditctlCommand = originalCommand
		isProcessAlive = originalAlive
		readProcessStartTime = originalStartTime
	}()
	isProcessAlive = func(int) bool { return true }
	// Keep the synthetic PID identity stable so the test reaches the pressure queue.
	readProcessStartTime = func(int) uint64 { return 100 }
	calls := 0
	runAuditctlCommand = func(timeout time.Duration, args ...string) ([]byte, error) {
		calls++
		return nil, nil
	}
	monitor := pressureTestMonitor()
	monitor.configureAuditPressure(auditPressureRuntimeConfig{
		LightRateLimitPerSecond: 1000, MediumRateLimitPerSecond: 1000, RecoveryRateLimitPerSecond: 1000,
	})
	monitor.startRuleExpansionWorker()
	defer monitor.stopRuleExpansionWorker()
	now := time.Now()
	monitor.updateAuditPressure(auditPressureSevere, 10*time.Millisecond, "test", now)
	listener := listenerInfo{PID: 100, Process: "app", Port: 8080}
	monitor.enqueuePIDExpansion(999999, listener)
	if calls != 0 {
		t.Fatalf("severe pressure should not call auditctl, calls=%d", calls)
	}
	if got := len(monitor.deferredRuleExpansion); got != 1 {
		t.Fatalf("deferred expansions = %d, want 1", got)
	}
	monitor.updateAuditPressure(auditPressureNormal, 10*time.Millisecond, "recovered", now.Add(20*time.Millisecond))
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if monitor.trackedCount() == 1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if monitor.trackedCount() != 1 || calls == 0 {
		t.Fatalf("deferred expansion was not recovered: tracked=%d calls=%d", monitor.trackedCount(), calls)
	}
	stats := monitor.ruleExpansionStatsSnapshot()
	if stats.PressurePaused != 1 || stats.RecoveryActive || stats.RecoveryPending != 0 {
		t.Fatalf("unexpected pressure recovery stats: %+v", stats)
	}
}

func TestQueuedExpansionRejectsReusedPID(t *testing.T) {
	originalCommand := runAuditctlCommand
	originalAlive := isProcessAlive
	originalStartTime := readProcessStartTime
	defer func() {
		runAuditctlCommand = originalCommand
		isProcessAlive = originalAlive
		readProcessStartTime = originalStartTime
	}()
	isProcessAlive = func(int) bool { return true }
	readProcessStartTime = func(int) uint64 { return 200 }
	calls := 0
	runAuditctlCommand = func(timeout time.Duration, args ...string) ([]byte, error) {
		calls++
		return nil, nil
	}
	monitor := pressureTestMonitor()
	if err := monitor.expandPIDExpected(999999, 100, listenerInfo{PID: 100, Process: "app", Port: 8080}); err != nil {
		t.Fatal(err)
	}
	if calls != 0 || monitor.trackedCount() != 0 {
		t.Fatalf("reused queued pid should be discarded: calls=%d tracked=%d", calls, monitor.trackedCount())
	}
}

func TestCloneRecoveryRespectsAuditRuleLimit(t *testing.T) {
	originalCommand := runAuditctlCommand
	originalAlive := isProcessAlive
	defer func() {
		runAuditctlCommand = originalCommand
		isProcessAlive = originalAlive
	}()
	isProcessAlive = func(int) bool { return true }
	calls := 0
	runAuditctlCommand = func(timeout time.Duration, args ...string) ([]byte, error) {
		calls++
		return nil, nil
	}
	monitor := pressureTestMonitor()
	monitor.pressureRecovering = true
	monitor.maxAuditRules = 2
	monitor.rules = []auditRule{
		{Arch: "b64", Field: "pid", PID: 999999, Key: monitor.execKey, Syscalls: []string{"execve"}},
		{Arch: "b64", Field: "ppid", PID: 999999, Key: monitor.execKey, Syscalls: []string{"execve"}},
	}
	if err := monitor.restoreSuppressedCloneRules(999999, 0, listenerInfo{PID: 100, Process: "app", Port: 8080}); err != nil {
		t.Fatal(err)
	}
	if calls != 0 || len(monitor.rulesSnapshot()) != 2 {
		t.Fatalf("clone recovery exceeded rule budget: calls=%d rules=%d", calls, len(monitor.rulesSnapshot()))
	}
	if got := monitor.ruleExpansionStatsSnapshot().RuleLimitSkips; got != 1 {
		t.Fatalf("rule limit skips = %d, want 1", got)
	}
	if len(monitor.suppressedCloneRules) != 1 || !monitor.pressureRecoveryBlocked {
		t.Fatalf("budget-blocked clone recovery must remain deferred: suppressed=%d blocked=%v", len(monitor.suppressedCloneRules), monitor.pressureRecoveryBlocked)
	}
}

func pressureTestMonitor() *processTreeMonitor {
	return &processTreeMonitor{
		pidListener:           map[int]listenerInfo{},
		monitored:             map[int]bool{},
		processStartTimes:     map[int]uint64{},
		pendingRuleExpansion:  map[int]bool{},
		deferredRuleExpansion: map[int]ruleExpansion{},
		exeMonitored:          map[string]bool{},
		pidTargets:            map[int]trackingTarget{},
		execKey:               "tb_external_listener_exec",
		cloneKey:              "tb_external_listener_clone",
		selfBranch:            map[int]bool{},
		trackDescendants:      true,
		monitorExec:           true,
		auditArches:           []string{"b64"},
	}
}

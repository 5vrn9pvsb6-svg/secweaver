package auditportexecmon

import (
	"os"
	"path/filepath"

	"testing"
	"time"
)

// These tests cover PID identity, async expansion, process attribution, listener reconciliation, and companion discovery.

func TestPressureDegradedSkipsHighCostPIDRuleEstimate(t *testing.T) {
	monitor := newProcessTreeMonitor(nil, 0, map[int]bool{}, "exec", "connect", "file", "sensitive", "clone", true, true, map[int]bool{}, true, map[int]bool{}, nil, nil, nil, true, map[int]bool{}, false, nil, []string{"b64"}, javaMonitorModeExeOnly)
	listener := listenerInfo{PID: 100, Process: "nginx", Port: 80}
	normal := monitor.estimatePIDRuleCount(listener.PID, listener)
	monitor.enterPressureDegraded(time.Minute, "test")
	degraded := monitor.estimatePIDRuleCount(listener.PID, listener)
	if !(degraded < normal) {
		t.Fatalf("degraded estimate=%d should be lower than normal=%d", degraded, normal)
	}
}

func TestParseProcStatStartTimeHandlesParenthesesInComm(t *testing.T) {
	stat := "123 (worker ) name) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 424242"
	if got := parseProcStatStartTime(stat); got != 424242 {
		t.Fatalf("starttime = %d, want 424242", got)
	}
}

func TestPruneDeadPIDsRemovesRulesForReusedPID(t *testing.T) {
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
	deleteCalls := 0
	runAuditctlCommand = func(timeout time.Duration, args ...string) ([]byte, error) {
		deleteCalls++
		return nil, nil
	}
	monitor := &processTreeMonitor{
		monitored:         map[int]bool{1234: true},
		processStartTimes: map[int]uint64{1234: 100},
		pidListener:       map[int]listenerInfo{1234: {PID: 1234}},
		pidTargets:        map[int]trackingTarget{},
		rules: []auditRule{{
			Arch: "b64", Field: "pid", PID: 1234, Key: "tb_external_listener_exec", Syscalls: []string{"execve"},
		}},
	}
	monitor.pruneDeadPIDs()
	if deleteCalls != 1 || len(monitor.rulesSnapshot()) != 0 || monitor.trackedCount() != 0 {
		t.Fatalf("reused pid cleanup failed: calls=%d rules=%d tracked=%d", deleteCalls, len(monitor.rulesSnapshot()), monitor.trackedCount())
	}
}

func TestResolveJavaExeUsesUsablePath(t *testing.T) {
	binDir := filepath.Join(t.TempDir(), "jdk", "bin")
	if err := os.MkdirAll(binDir, 0755); err != nil {
		t.Fatal(err)
	}
	javaPath := filepath.Join(binDir, "java")
	if err := os.WriteFile(javaPath, []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if got := resolveJavaExe(0, javaPath+" (deleted)"); got != javaPath {
		t.Fatalf("resolveJavaExe = %q, want %q", got, javaPath)
	}
}

func TestBuildProcessExeCandidatesUsesHomeAndPath(t *testing.T) {
	candidates := buildProcessExeCandidates("/missing/java (deleted)", "java", []string{"java", "-jar", "app.jar"}, map[string]string{
		"JAVA_HOME": "/opt/jdk",
		"PATH":      "/usr/local/bin:/usr/bin",
	}, []string{"JAVA_HOME", "JRE_HOME"}, []string{"/usr/bin/java"})
	want := []string{"/missing/java (deleted)", "/opt/jdk/bin/java", "/usr/local/bin/java", "/usr/bin/java"}
	for _, expected := range want {
		if !containsString(candidates, expected) {
			t.Fatalf("expected candidate %q in %#v", expected, candidates)
		}
	}
}

func TestResolveProcessExeUsesGenericBinaryName(t *testing.T) {
	binDir := filepath.Join(t.TempDir(), "openresty", "nginx", "sbin")
	if err := os.MkdirAll(binDir, 0755); err != nil {
		t.Fatal(err)
	}
	nginxPath := filepath.Join(binDir, "nginx")
	if err := os.WriteFile(nginxPath, []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if got := resolveProcessExe(0, nginxPath+" (deleted)", "nginx", nil, nil); got != nginxPath {
		t.Fatalf("resolveProcessExe = %q, want %q", got, nginxPath)
	}
}

func TestIsProcNetLoopbackHandlesIPv6EndianForms(t *testing.T) {
	for _, addr := range []string{
		"00000000000000000000000000000001",
		"00000000000000000000000001000000",
	} {
		if !isProcNetLoopback(addr) {
			t.Fatalf("expected %s to be loopback", addr)
		}
	}
	if isProcNetLoopback("00000000000000000000000000000000") {
		t.Fatal("unspecified IPv6 address should not be loopback")
	}
}

func TestParseProcStatPPIDHandlesSpacesInComm(t *testing.T) {
	stat := "1234 (worker process) S 4321 1 1 0 -1 4194560"
	if got := parseProcStatPPID(stat); got != 4321 {
		t.Fatalf("parseProcStatPPID = %d, want 4321", got)
	}
}

func TestEnqueuePIDExpansionReplacesReusedPID(t *testing.T) {
	originalAlive := isProcessAlive
	originalStartTime := readProcessStartTime
	defer func() {
		isProcessAlive = originalAlive
		readProcessStartTime = originalStartTime
	}()
	isProcessAlive = func(int) bool { return true }
	readProcessStartTime = func(int) uint64 { return 200 }
	queue := make(chan ruleExpansion, 1)
	monitor := &processTreeMonitor{
		monitored:             map[int]bool{1234: true},
		processStartTimes:     map[int]uint64{1234: 100},
		pendingRuleExpansion:  map[int]bool{},
		deferredRuleExpansion: map[int]ruleExpansion{},
		ruleExpansionQueue:    queue,
		selfBranch:            map[int]bool{},
	}
	monitor.enqueuePIDExpansion(1234, listenerInfo{PID: 100, Process: "nginx", Port: 80})
	select {
	case job := <-queue:
		if !job.Replace || job.StartTime != 200 {
			t.Fatalf("replacement job = %+v", job)
		}
	default:
		t.Fatal("reused PID did not enqueue replacement")
	}
}

func TestSuccessfulCloneQueuesReturnedChildPID(t *testing.T) {
	originalAlive := isProcessAlive
	originalStartTime := readProcessStartTime
	defer func() {
		isProcessAlive = originalAlive
		readProcessStartTime = originalStartTime
	}()
	isProcessAlive = func(int) bool { return true }
	readProcessStartTime = func(int) uint64 { return 100 }
	queue := make(chan ruleExpansion, 4)
	monitor := &processTreeMonitor{
		pendingRuleExpansion:  map[int]bool{},
		deferredRuleExpansion: map[int]ruleExpansion{},
		monitored:             map[int]bool{},
		processStartTimes:     map[int]uint64{},
		ruleExpansionQueue:    queue,
		selfBranch:            map[int]bool{},
		cloneKey:              "tb_external_listener_clone",
	}
	listener := listenerInfo{PID: 100, Process: "nginx", Port: 80}
	monitor.trackSuccessfulCloneChild(map[string]string{
		"key": "tb_external_listener_clone", "success": "yes", "exit": "4321",
	}, 100, listener)
	foundChild := false
	for len(queue) > 0 {
		if job := <-queue; job.PID == 4321 {
			foundChild = true
		}
	}
	if !foundChild {
		t.Fatal("successful clone return value was not tracked as child PID")
	}
}

func TestExpandPIDSkipsWhenAuditRuleLimitReached(t *testing.T) {
	orig := runAuditctlCommand
	origAlive := isProcessAlive
	defer func() {
		runAuditctlCommand = orig
		isProcessAlive = origAlive
	}()
	isProcessAlive = func(int) bool { return true }
	calls := 0
	runAuditctlCommand = func(timeout time.Duration, args ...string) ([]byte, error) {
		calls++
		return nil, nil
	}

	monitor := &processTreeMonitor{
		pidListener:          map[int]listenerInfo{},
		monitored:            map[int]bool{},
		pendingRuleExpansion: map[int]bool{},
		exeMonitored:         map[string]bool{},
		execKey:              "tb_external_listener_exec",
		cloneKey:             "tb_external_listener_clone",
		selfBranch:           map[int]bool{},
		trackDescendants:     true,
		monitorExec:          true,
		auditArches:          []string{"b64"},
		maxAuditRules:        3,
	}
	if err := monitor.expandPID(999999, listenerInfo{PID: 100, Process: "nginx", Port: 80}); err != nil {
		t.Fatalf("expandPID: %v", err)
	}
	if calls != 0 {
		t.Fatalf("auditctl calls = %d, want 0", calls)
	}
	if monitor.trackedCount() != 0 {
		t.Fatalf("tracked count = %d, want 0", monitor.trackedCount())
	}
	stats := monitor.ruleExpansionStatsSnapshot()
	if stats.RuleLimitSkips != 1 {
		t.Fatalf("rule limit skips = %d, want 1", stats.RuleLimitSkips)
	}
}

func TestExpandPIDAllowsWithinAuditRuleLimit(t *testing.T) {
	orig := runAuditctlCommand
	origAlive := isProcessAlive
	defer func() {
		runAuditctlCommand = orig
		isProcessAlive = origAlive
	}()
	isProcessAlive = func(int) bool { return true }
	calls := 0
	runAuditctlCommand = func(timeout time.Duration, args ...string) ([]byte, error) {
		calls++
		return nil, nil
	}

	monitor := &processTreeMonitor{
		pidListener:          map[int]listenerInfo{},
		monitored:            map[int]bool{},
		pendingRuleExpansion: map[int]bool{},
		exeMonitored:         map[string]bool{},
		execKey:              "tb_external_listener_exec",
		cloneKey:             "tb_external_listener_clone",
		selfBranch:           map[int]bool{},
		trackDescendants:     true,
		monitorExec:          true,
		auditArches:          []string{"b64"},
		maxAuditRules:        4,
	}
	if err := monitor.expandPID(999999, listenerInfo{PID: 100, Process: "nginx", Port: 80}); err != nil {
		t.Fatalf("expandPID: %v", err)
	}
	if calls != 4 {
		t.Fatalf("auditctl calls = %d, want 4", calls)
	}
	if monitor.trackedCount() != 1 {
		t.Fatalf("tracked count = %d, want 1", monitor.trackedCount())
	}
	if got := len(monitor.rulesSnapshot()); got != 4 {
		t.Fatalf("rules = %d, want 4", got)
	}
	stats := monitor.ruleExpansionStatsSnapshot()
	if stats.ReservedRules != 0 {
		t.Fatalf("reserved rules = %d, want 0", stats.ReservedRules)
	}
}

func TestExpandPIDSkipsExitedProcess(t *testing.T) {
	orig := runAuditctlCommand
	origAlive := isProcessAlive
	defer func() {
		runAuditctlCommand = orig
		isProcessAlive = origAlive
	}()
	calls := 0
	runAuditctlCommand = func(timeout time.Duration, args ...string) ([]byte, error) {
		calls++
		return nil, nil
	}
	isProcessAlive = func(int) bool { return false }

	monitor := &processTreeMonitor{
		pidListener:          map[int]listenerInfo{},
		monitored:            map[int]bool{},
		pendingRuleExpansion: map[int]bool{},
		exeMonitored:         map[string]bool{},
		execKey:              "tb_external_listener_exec",
		cloneKey:             "tb_external_listener_clone",
		selfBranch:           map[int]bool{},
		trackDescendants:     true,
		monitorExec:          true,
		auditArches:          []string{"b64"},
	}
	if err := monitor.expandPID(999999, listenerInfo{PID: 100, Process: "nginx", Port: 80}); err != nil {
		t.Fatalf("expandPID: %v", err)
	}
	if calls != 0 || monitor.trackedCount() != 0 || len(monitor.rulesSnapshot()) != 0 {
		t.Fatalf("exited pid should not create rules: calls=%d tracked=%d rules=%d", calls, monitor.trackedCount(), len(monitor.rulesSnapshot()))
	}
}

func TestAddExeRulesDeduplicatesConnectOnlyMonitoring(t *testing.T) {
	orig := runAuditctlCommand
	defer func() { runAuditctlCommand = orig }()
	calls := 0
	runAuditctlCommand = func(timeout time.Duration, args ...string) ([]byte, error) {
		calls++
		return nil, nil
	}
	monitor := &processTreeMonitor{
		exeMonitored:         map[string]bool{},
		pidListener:          map[int]listenerInfo{},
		monitored:            map[int]bool{},
		pendingRuleExpansion: map[int]bool{},
		connectKey:           "tb_external_listener_connect",
		monitorConnect:       true,
		auditArches:          []string{"b64"},
	}
	listener := listenerInfo{PID: 100, Process: "php-fpm", MonitorExe: "/usr/sbin/php-fpm", Port: 9000, ExeOnly: true}

	if err := monitor.addExeRules(listener); err != nil {
		t.Fatalf("first addExeRules: %v", err)
	}
	if err := monitor.addExeRules(listener); err != nil {
		t.Fatalf("second addExeRules: %v", err)
	}
	if calls != 1 {
		t.Fatalf("auditctl calls = %d, want one deduplicated connect rule", calls)
	}
	if got := len(monitor.rulesSnapshot()); got != 1 {
		t.Fatalf("tracked rules = %d, want 1", got)
	}
}

func TestQueueFullSkipsPIDExpansion(t *testing.T) {
	orig := runAuditctlCommand
	originalAlive := isProcessAlive
	originalStartTime := readProcessStartTime
	defer func() {
		runAuditctlCommand = orig
		isProcessAlive = originalAlive
		readProcessStartTime = originalStartTime
	}()
	isProcessAlive = func(int) bool { return true }
	readProcessStartTime = func(int) uint64 { return 100 }
	calls := 0
	runAuditctlCommand = func(timeout time.Duration, args ...string) ([]byte, error) {
		calls++
		return nil, nil
	}

	monitor := &processTreeMonitor{
		pidListener:            map[int]listenerInfo{},
		monitored:              map[int]bool{},
		pendingRuleExpansion:   map[int]bool{},
		exeMonitored:           map[string]bool{},
		execKey:                "tb_external_listener_exec",
		cloneKey:               "tb_external_listener_clone",
		selfBranch:             map[int]bool{},
		trackDescendants:       true,
		monitorExec:            true,
		auditArches:            []string{"b64"},
		ruleExpansionQueue:     make(chan ruleExpansion),
		ruleExpansionQueueFull: 0,
	}
	monitor.enqueuePIDExpansion(999999, listenerInfo{PID: 100, Process: "nginx", Port: 80})
	if calls != 0 {
		t.Fatalf("auditctl calls = %d, want 0", calls)
	}
	stats := monitor.ruleExpansionStatsSnapshot()
	if stats.QueueFull != 1 || stats.Enqueued != 0 || stats.Pending != 0 {
		t.Fatalf("unexpected queue stats: %+v", stats)
	}
	if monitor.trackedCount() != 0 {
		t.Fatalf("tracked count = %d, want 0", monitor.trackedCount())
	}
}

func TestNginxAndPhpFPMHybridMonitorDefaults(t *testing.T) {
	nginx := listenerInfo{PID: 100, Process: "nginx", MonitorExe: "/usr/sbin/nginx", Port: 443, ExeOnly: true}
	if !nginx.ExeOnly {
		t.Fatal("nginx should keep exe-path attribution in hybrid mode")
	}
	phpBackend := webGatewayCompanionBackends[0]
	if !phpBackend.PathMonitor {
		t.Fatal("php-fpm should use exe-path monitoring by default")
	}
	monitor := &processTreeMonitor{
		listeners:   []listenerInfo{nginx},
		exeTargets:  map[string]trackingTarget{"/usr/sbin/php-fpm": {Gateway: nginx, Source: "companion-exe"}},
		pidListener: map[int]listenerInfo{},
		pidTargets:  map[int]trackingTarget{},
	}
	monitor.mu.Lock()
	if gw, ok := monitor.findListenerLocked(999, 23443, "/usr/sbin/php-fpm"); !ok || gw.Port != 443 {
		t.Fatalf("php-fpm exe event should map to gateway listener, got ok=%v gw=%+v", ok, gw)
	}
	if gw, ok := monitor.findListenerLocked(500, 100, "/usr/sbin/nginx"); !ok || gw.Process != "nginx" {
		t.Fatalf("nginx exe event should map to nginx listener, got ok=%v gw=%+v", ok, gw)
	}
	monitor.mu.Unlock()
}

func TestWebGatewayAndCompanionMatching(t *testing.T) {
	gateway := listenerInfo{PID: 100, Process: "nginx", MonitorExe: "/usr/sbin/nginx", Port: 80}
	if !isWebGatewayListener(gateway) {
		t.Fatal("nginx should be a web gateway listener")
	}
	apache := listenerInfo{PID: 200, Process: "httpd", Port: 80}
	if !isWebGatewayListener(apache) {
		t.Fatal("httpd should be a web gateway listener")
	}
	if isWebGatewayListener(listenerInfo{PID: 300, Process: "java", MonitorExe: "/usr/bin/java", Port: 8080}) {
		t.Fatal("java external listener should not be treated as web gateway")
	}

	phpBackend := webGatewayCompanionBackends[0]
	if !matchesCompanionBackend("php-fpm", "/usr/sbin/php-fpm", phpBackend) {
		t.Fatal("expected php-fpm process to match companion backend")
	}
	if !cmdlineMatchesCompanionBackend([]string{"php-fpm: master process (/etc/php-fpm.conf)"}, phpBackend) {
		t.Fatal("expected php-fpm master cmdline to match")
	}
	if !cmdlineMatchesCompanionBackend([]string{"php-fpm: pool www"}, phpBackend) {
		t.Fatal("expected php-fpm pool worker cmdline to match")
	}
	if !matchesCompanionBackend("pool www", "/usr/sbin/php-fpm", phpBackend) {
		t.Fatal("expected pool worker comm with php-fpm exe to match via exe suffix")
	}
	if matchesCompanionBackend("nginx", "/usr/sbin/nginx", phpBackend) {
		t.Fatal("nginx should not match php-fpm backend")
	}
	if !commMatchesAny("puma cluster worker 0", []string{"puma"}) {
		t.Fatal("expected puma worker comm prefix to match")
	}

	monitor := &processTreeMonitor{
		listeners: []listenerInfo{
			{PID: 100, Process: "nginx", Port: 80, MonitorExe: "/usr/sbin/nginx"},
			{PID: 500, Process: "java", Port: 8080, MonitorExe: "/usr/bin/java", ExeOnly: true},
		},
		companionLogged: map[string]bool{},
	}
	if !monitor.companionAlreadyPrimaryListener(companionBackend{CommNames: []string{"java"}}, "/usr/bin/java") {
		t.Fatal("external java listener should skip companion bootstrap")
	}
	if monitor.companionAlreadyPrimaryListener(phpBackend, "/usr/sbin/php-fpm") {
		t.Fatal("php-fpm should not be skipped when not an external listener")
	}
}

func TestKnownListenerIdentities(t *testing.T) {
	monitor := &processTreeMonitor{
		listeners: []listenerInfo{{PID: 100, Process: "nginx", Address: "0.0.0.0", Port: 443, MonitorExe: "/usr/sbin/nginx"}},
	}
	id := listenerIdentity(monitor.listeners[0])
	seen := monitor.knownListenerIdentities()
	if !seen[id] {
		t.Fatalf("expected listener identity %q to be known, got %#v", id, seen)
	}
}

func TestReconcileListenersPrunesStaleAndRefreshesRestartedProcess(t *testing.T) {
	existing := []listenerInfo{
		{PID: 100, Process: "sshd", Address: "0.0.0.0", Port: 22},
		{PID: 200, Process: "nginx", Address: "0.0.0.0", Port: 80, MonitorExe: "/usr/sbin/nginx", ExeOnly: true},
	}
	active := []listenerInfo{
		{PID: 201, Process: "nginx", Address: "0.0.0.0", Port: 80, MonitorExe: "/usr/sbin/nginx", ExeOnly: true},
		{PID: 300, Process: "sshd", Address: "0.0.0.0", Port: 22},
	}

	refreshed, newIndexes, removed := reconcileListeners(existing, active)
	if len(refreshed) != 2 || refreshed[0].PID != 201 || refreshed[1].PID != 300 {
		t.Fatalf("unexpected refreshed listeners: %#v", refreshed)
	}
	if len(newIndexes) != 1 || newIndexes[0] != 1 {
		t.Fatalf("new indexes = %#v, want [1]", newIndexes)
	}
	if removed != 1 {
		t.Fatalf("removed = %d, want 1 stale sshd listener", removed)
	}
}

func TestReconcileListenersPreservesSameProcessExeFallback(t *testing.T) {
	existing := []listenerInfo{{PID: 200, Process: "nginx", Address: "0.0.0.0", Port: 80}}
	active := []listenerInfo{{PID: 200, Process: "nginx", Address: "0.0.0.0", Port: 80, MonitorExe: "/usr/sbin/nginx", ExeOnly: true}}

	refreshed, newIndexes, removed := reconcileListeners(existing, active)
	if len(refreshed) != 1 || refreshed[0].ExeOnly || refreshed[0].MonitorExe != "" {
		t.Fatalf("same process fallback was not preserved: %#v", refreshed)
	}
	if len(newIndexes) != 0 || removed != 0 {
		t.Fatalf("new indexes=%#v removed=%d, want no listener churn", newIndexes, removed)
	}
}

func TestListenerRescanIntervalFromConfig(t *testing.T) {
	if defaultListenerRescanInterval != 5*time.Minute {
		t.Fatalf("default listener rescan interval = %v, want 5m", defaultListenerRescanInterval)
	}
	if got := listenerRescanIntervalFromConfig(config{}); got != defaultListenerRescanInterval {
		t.Fatalf("default interval = %v, want %v", got, defaultListenerRescanInterval)
	}
	if got := listenerRescanIntervalFromConfig(config{ListenerRescanSeconds: 12}); got != 12*time.Second {
		t.Fatalf("custom interval = %v, want 12s", got)
	}
}

func TestCompanionTrackingTargetClearsExeOnly(t *testing.T) {
	nginx := listenerInfo{PID: 100, Process: "nginx", Port: 80, MonitorExe: "/usr/sbin/nginx", ExeOnly: true}
	target := companionTrackingTarget(nginx)
	if target.Gateway.ExeOnly {
		t.Fatal("companion tracking target must clear gateway ExeOnly")
	}
	if !target.ExpandDescendants || target.Source != "companion" {
		t.Fatalf("unexpected target metadata: %+v", target)
	}
	if target.Gateway.Port != 80 || target.Gateway.Process != "nginx" {
		t.Fatalf("unexpected gateway fields: %+v", target.Gateway)
	}
}

func TestCompanionTargetForProcessWalksChain(t *testing.T) {
	nginx := listenerInfo{PID: 100, Process: "nginx", Port: 80, MonitorExe: "/usr/sbin/nginx", ExeOnly: true}
	workerTarget := companionTrackingTarget(nginx)
	monitor := &processTreeMonitor{
		pidTargets: map[int]trackingTarget{23443: workerTarget},
	}
	if target, ok := monitor.companionTargetForProcess(50001, 50000); ok {
		t.Fatalf("unrelated pids should not match, got %+v", target)
	}
	// id(50001) -> sh(50000) -> worker(23443): only worker registered; ppid walk from id won't reach worker without /proc.
	// Direct child of worker (sh) should match via ppid.
	if target, ok := monitor.companionTargetForProcess(50000, 23443); !ok || target.Gateway.Port != 80 || !target.ExpandDescendants {
		t.Fatalf("shell forked from php-fpm worker should map to expandable target, ok=%v target=%+v", ok, target)
	}
}

func TestSelfProcessTreeIncludesAgentSupervisorBranch(t *testing.T) {
	monitor := &processTreeMonitor{
		selfPID:    200,
		selfExe:    "/usr/local/bin/secweaver-agent",
		selfBranch: map[int]bool{100: true, 200: true},
	}
	if !monitor.isSelfProcessTree(100) {
		t.Fatal("expected supervisor branch pid to be treated as self")
	}
	if !monitor.isSelfAuditFields(map[string]string{"pid": "300", "ppid": "100", "exe": "/usr/bin/auditctl"}) {
		t.Fatal("expected child of supervisor branch to be treated as self")
	}
	if !monitor.isSelfAuditFields(map[string]string{"pid": "999", "ppid": "1", "exe": "/usr/local/bin/secweaver-agent"}) {
		t.Fatal("expected matching secweaver-agent exe to be treated as self")
	}
}

func TestFilterSelfListenersDropsAgentFamily(t *testing.T) {
	listeners := []listenerInfo{
		{PID: 100, Process: "secweaver-agent", Address: "0.0.0.0", Port: 9000},
		{PID: 300, Process: "secweaver-agent", Address: "0.0.0.0", Port: 9001, MonitorExe: "/usr/local/bin/secweaver-agent", ExeOnly: true},
		{PID: 400, Process: "nginx", Address: "0.0.0.0", Port: 80, MonitorExe: "/usr/sbin/nginx", ExeOnly: true},
	}
	filtered, skipped := filterSelfListeners(listeners, 200, "/usr/local/bin/secweaver-agent", map[int]bool{100: true, 200: true})
	if skipped != 2 {
		t.Fatalf("skipped = %d, want 2", skipped)
	}
	if len(filtered) != 1 || filtered[0].Process != "nginx" {
		t.Fatalf("unexpected filtered listeners: %#v", filtered)
	}
}

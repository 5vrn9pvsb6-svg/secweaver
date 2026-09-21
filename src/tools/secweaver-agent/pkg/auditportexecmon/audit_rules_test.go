package auditportexecmon

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// These tests cover transactional rule installation, rule-budget accounting, cleanup, and sensitive watch lifecycle.

func TestSensitiveWatchRulesAreCleanedOnExit(t *testing.T) {
	original := runAuditctlCommand
	defer func() { runAuditctlCommand = original }()
	var calls [][]string
	runAuditctlCommand = func(timeout time.Duration, args ...string) ([]byte, error) {
		calls = append(calls, append([]string(nil), args...))
		return nil, nil
	}
	monitor := &processTreeMonitor{
		monitorSensitiveFileReads: true,
		sensitiveFilePaths:        []string{"/etc/shadow"},
		sensitiveFileKey:          "tb_external_listener_sensitive",
	}
	if err := monitor.bootstrapSensitiveFileWatch(); err != nil {
		t.Fatal(err)
	}
	if len(monitor.watchRulesSnapshot()) != 1 {
		t.Fatalf("tracked watch rules = %d, want 1", len(monitor.watchRulesSnapshot()))
	}
	if _, err := monitor.cleanupSessionRules(); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 || len(calls[1]) != 3 || calls[1][0] != "-D" || calls[1][2] != "tb_external_listener_sensitive" {
		t.Fatalf("unexpected auditctl calls: %#v", calls)
	}
	if len(monitor.watchRulesSnapshot()) != 0 {
		t.Fatal("watch rules should be cleared after successful cleanup")
	}
}

func TestSensitiveWatchCleanupFallsBackWhenDeleteByKeyIsUnsupported(t *testing.T) {
	original := runAuditctlCommand
	defer func() { runAuditctlCommand = original }()
	var calls [][]string
	runAuditctlCommand = func(timeout time.Duration, args ...string) ([]byte, error) {
		calls = append(calls, append([]string(nil), args...))
		switch {
		case len(args) == 3 && args[0] == "-D":
			return nil, errors.New("delete by key unsupported")
		case len(args) == 1 && args[0] == "-l":
			return []byte("-w /etc/shadow -p r -k tb_external_listener_sensitive\n"), nil
		default:
			return nil, nil
		}
	}
	monitor := &processTreeMonitor{
		watchRules: []auditWatchRule{{Path: "/etc/shadow", Perm: "r", Key: "tb_external_listener_sensitive"}},
	}
	if _, err := monitor.cleanupSessionRules(); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 3 {
		t.Fatalf("auditctl calls = %#v", calls)
	}
	want := []string{"-W", "/etc/shadow", "-p", "r", "-k", "tb_external_listener_sensitive"}
	if strings.Join(calls[2], " ") != strings.Join(want, " ") {
		t.Fatalf("watch fallback delete = %#v, want %#v", calls[2], want)
	}
}

func TestBootstrapInitialRollsBackPartiallyAddedWatchRules(t *testing.T) {
	original := runAuditctlCommand
	defer func() { runAuditctlCommand = original }()
	var calls [][]string
	runAuditctlCommand = func(timeout time.Duration, args ...string) ([]byte, error) {
		calls = append(calls, append([]string(nil), args...))
		if len(args) > 1 && args[0] == "-w" && args[1] == "/etc/shadow" {
			return nil, errors.New("forced add failure")
		}
		return nil, nil
	}
	monitor := &processTreeMonitor{
		monitorSensitiveFileReads: true,
		sensitiveFilePaths:        []string{"/etc/passwd", "/etc/shadow"},
		sensitiveFileKey:          "tb_external_listener_sensitive",
	}
	if err := monitor.bootstrapInitial(); err == nil {
		t.Fatal("expected bootstrap failure")
	}
	if len(calls) != 3 || calls[2][0] != "-D" || calls[2][2] != "tb_external_listener_sensitive" {
		t.Fatalf("partial bootstrap was not rolled back: %#v", calls)
	}
	if len(monitor.watchRulesSnapshot()) != 0 {
		t.Fatal("rolled back watch rules should not remain tracked")
	}
}

func TestCloneAuditSyscallsIncludeModernVariants(t *testing.T) {
	syscalls := auditCloneSyscalls()
	for _, expected := range []string{"clone3", "vfork"} {
		if !containsString(syscalls, expected) {
			t.Fatalf("expected clone syscall %q in %#v", expected, syscalls)
		}
	}
}

func TestUnknownAuditSyscallErrorsAreCached(t *testing.T) {
	unsupportedAuditSyscalls.Delete(auditSyscallKey("b64", "clone3"))
	defer unsupportedAuditSyscalls.Delete(auditSyscallKey("b64", "clone3"))
	err := errors.New("auditctl -a always,exit -F arch=b64 -S clone3: Syscall name unknown: clone3")
	if !markUnsupportedAuditSyscall("b64", "clone3", err) {
		t.Fatal("first unknown syscall error should be marked and reported")
	}
	if !auditSyscallUnsupported("b64", "clone3") {
		t.Fatal("clone3 should be cached as unsupported")
	}
	if markUnsupportedAuditSyscall("b64", "clone3", err) {
		t.Fatal("second unknown syscall error should not be reported again")
	}
}

func TestAddAuditRulesMergesSyscallsPerArchAndField(t *testing.T) {
	original := runAuditctlCommand
	defer func() { runAuditctlCommand = original }()
	var calls [][]string
	runAuditctlCommand = func(timeout time.Duration, args ...string) ([]byte, error) {
		if timeout != auditctlTimeout {
			t.Fatalf("timeout = %v, want %v", timeout, auditctlTimeout)
		}
		calls = append(calls, append([]string(nil), args...))
		return nil, nil
	}

	rules, err := addAuditRules(100, "tb_test_exec", true, []string{"execve", "execveat"}, []string{"b64"})
	if err != nil {
		t.Fatalf("addAuditRules: %v", err)
	}
	if len(rules) != 2 || len(calls) != 2 {
		t.Fatalf("rules=%d calls=%d, want 2 pid/ppid grouped rules", len(rules), len(calls))
	}
	fields := map[string]bool{}
	for _, call := range calls {
		if countArg(call, "-S") != 2 || !argsContainPair(call, "-S", "execve") || !argsContainPair(call, "-S", "execveat") {
			t.Fatalf("expected merged exec syscalls in one auditctl call, got %#v", call)
		}
		if argsContainPair(call, "-F", "pid=100") {
			fields["pid"] = true
		}
		if argsContainPair(call, "-F", "ppid=100") {
			fields["ppid"] = true
		}
	}
	if !fields["pid"] || !fields["ppid"] {
		t.Fatalf("expected pid and ppid rules, got calls %#v", calls)
	}
}

func TestAddAuditRulesRollsBackPartialFieldFailure(t *testing.T) {
	original := runAuditctlCommand
	defer func() { runAuditctlCommand = original }()
	var calls [][]string
	runAuditctlCommand = func(timeout time.Duration, args ...string) ([]byte, error) {
		calls = append(calls, append([]string(nil), args...))
		if argsContainPair(args, "-F", "ppid=100") && args[0] == "-a" {
			return nil, errors.New("forced ppid failure")
		}
		return nil, nil
	}

	rules, err := addAuditRules(100, "tb_test_exec", true, []string{"execve", "execveat"}, []string{"b64"})
	if err == nil || len(rules) != 0 {
		t.Fatalf("partial apply = rules=%#v err=%v, want complete rollback", rules, err)
	}
	if len(calls) != 3 || calls[2][0] != "-d" || !argsContainPair(calls[2], "-F", "pid=100") {
		t.Fatalf("partial apply was not rolled back exactly: %#v", calls)
	}
}

func TestAddAuditRulesReturnsRollbackResidualForManagedRetry(t *testing.T) {
	original := runAuditctlCommand
	defer func() { runAuditctlCommand = original }()
	runAuditctlCommand = func(timeout time.Duration, args ...string) ([]byte, error) {
		switch {
		case args[0] == "-a" && argsContainPair(args, "-F", "ppid=100"):
			return nil, errors.New("forced ppid add failure")
		case args[0] == "-d" && argsContainPair(args, "-F", "pid=100"):
			return nil, errors.New("forced rollback failure")
		default:
			return nil, nil
		}
	}

	residual, err := addAuditRules(100, "tb_test_exec", true, []string{"execve", "execveat"}, []string{"b64"})
	if err == nil || len(residual) != 1 {
		t.Fatalf("residual rules = %#v err=%v, want one managed residual", residual, err)
	}
	if residual[0].Field != "pid" || residual[0].PID != 100 {
		t.Fatalf("unexpected rollback residual: %#v", residual)
	}
}

func TestAuditRuleBudgetIncludesWatchRules(t *testing.T) {
	monitor := &processTreeMonitor{
		rules:         []auditRule{{Arch: "b64", Field: "pid", PID: 10, Key: "exec"}},
		watchRules:    []auditWatchRule{{Path: "/etc/shadow", Key: "sensitive"}},
		maxAuditRules: 2,
	}
	if monitor.reserveAdditionalAuditRules(1, 20, "test") {
		t.Fatal("watch rules must consume the hard audit rule budget")
	}
}

func TestAddAuditRulesByExeMergesSyscalls(t *testing.T) {
	original := runAuditctlCommand
	defer func() { runAuditctlCommand = original }()
	var calls [][]string
	runAuditctlCommand = func(timeout time.Duration, args ...string) ([]byte, error) {
		calls = append(calls, append([]string(nil), args...))
		return nil, nil
	}

	rules, err := addAuditRulesByExe("/usr/sbin/nginx", "tb_test_exec", []string{"execve", "execveat"}, []string{"b64"})
	if err != nil {
		t.Fatalf("addAuditRulesByExe: %v", err)
	}
	if len(rules) != 1 || len(calls) != 1 {
		t.Fatalf("rules=%d calls=%d, want one grouped exe rule", len(rules), len(calls))
	}
	call := calls[0]
	if countArg(call, "-S") != 2 || !argsContainPair(call, "-S", "execve") || !argsContainPair(call, "-S", "execveat") {
		t.Fatalf("expected merged exec syscalls in one exe auditctl call, got %#v", call)
	}
	if !argsContainPair(call, "-F", "exe=/usr/sbin/nginx") {
		t.Fatalf("expected exe filter in auditctl call, got %#v", call)
	}
}

func TestAddGlobalAuditRulesUsesNoProcessFilter(t *testing.T) {
	original := runAuditctlCommand
	defer func() { runAuditctlCommand = original }()
	var calls [][]string
	runAuditctlCommand = func(timeout time.Duration, args ...string) ([]byte, error) {
		calls = append(calls, append([]string(nil), args...))
		return nil, nil
	}

	rules, err := addGlobalAuditRules("tb_test_exec", []string{"execve", "execveat"}, []string{"b64"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 || len(calls) != 1 {
		t.Fatalf("rules=%d calls=%d, want one fixed rule", len(rules), len(calls))
	}
	call := calls[0]
	for _, forbidden := range []string{"pid=", "ppid=", "exe="} {
		if strings.Contains(strings.Join(call, " "), forbidden) {
			t.Fatalf("global rule must not contain %s filter: %#v", forbidden, call)
		}
	}
	if !argsContainPair(call, "-F", "arch=b64") || countArg(call, "-S") != 2 {
		t.Fatalf("unexpected grouped global rule: %#v", call)
	}
}

func TestBoundedAuditBootstrapRuleCountDoesNotDependOnListeners(t *testing.T) {
	original := runAuditctlCommand
	defer func() { runAuditctlCommand = original }()
	var calls [][]string
	runAuditctlCommand = func(timeout time.Duration, args ...string) ([]byte, error) {
		calls = append(calls, append([]string(nil), args...))
		return nil, nil
	}
	monitor := &processTreeMonitor{
		processBackend: processTreeBackendAudit,
		listeners: []listenerInfo{
			{PID: 100, Process: "nginx", Port: 80},
			{PID: 200, Process: "sshd", Port: 22},
			{PID: 300, Process: "java", Port: 8080},
		},
		monitorExec:       true,
		trackDescendants:  true,
		execKey:           "tb_test_exec",
		cloneKey:          "tb_test_clone",
		auditArches:       []string{"b64"},
		execListenerPorts: map[int]bool{},
	}
	if err := monitor.bootstrapBoundedAuditRules(); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 || len(monitor.rulesSnapshot()) != 2 {
		t.Fatalf("bounded backend should install one exec and one clone rule, calls=%#v rules=%#v", calls, monitor.rulesSnapshot())
	}
	for _, call := range calls {
		if argsContainPair(call, "-F", "pid=100") || argsContainPair(call, "-F", "ppid=100") {
			t.Fatalf("bounded bootstrap unexpectedly installed listener PID rule: %#v", call)
		}
	}
}

func TestBoundedAuditCloneChurnDoesNotAddRules(t *testing.T) {
	original := runAuditctlCommand
	defer func() { runAuditctlCommand = original }()
	var calls [][]string
	runAuditctlCommand = func(timeout time.Duration, args ...string) ([]byte, error) {
		calls = append(calls, append([]string(nil), args...))
		return nil, nil
	}
	listener := listenerInfo{PID: 900001, Process: "nginx", Port: 443}
	monitor := &processTreeMonitor{
		processBackend:    processTreeBackendAudit,
		listeners:         []listenerInfo{listener},
		pidListener:       map[int]listenerInfo{listener.PID: listener},
		monitored:         map[int]bool{listener.PID: true},
		processStartTimes: map[int]uint64{listener.PID: 1},
		processParentPIDs: map[int]int{},
		processObservedAt: map[int]time.Time{},
		pidTargets:        map[int]trackingTarget{},
		selfBranch:        map[int]bool{},
		monitorExec:       true,
		trackDescendants:  true,
		execKey:           "tb_test_exec",
		cloneKey:          "tb_test_clone",
		auditArches:       []string{"b64"},
		execListenerPorts: map[int]bool{},
	}
	if err := monitor.bootstrapBoundedAuditRules(); err != nil {
		t.Fatal(err)
	}
	for child := 910000; child < 910100; child++ {
		monitor.observeAuditFields(map[string]string{
			"type": "SYSCALL", "key": monitor.cloneKey, "pid": "900001", "ppid": "1",
			"exit": strconv.Itoa(child), "success": "yes",
		})
	}
	if len(calls) != 2 || len(monitor.rulesSnapshot()) != 2 {
		t.Fatalf("100 clone events changed fixed rule count: calls=%d rules=%d", len(calls), len(monitor.rulesSnapshot()))
	}
}

func TestAddAuditRulesRetriesMergedGroupWithoutUnknownSyscall(t *testing.T) {
	unsupportedAuditSyscalls.Delete(auditSyscallKey("b64", "clone3"))
	defer unsupportedAuditSyscalls.Delete(auditSyscallKey("b64", "clone3"))
	original := runAuditctlCommand
	defer func() { runAuditctlCommand = original }()
	var calls [][]string
	runAuditctlCommand = func(timeout time.Duration, args ...string) ([]byte, error) {
		calls = append(calls, append([]string(nil), args...))
		if len(calls) == 1 {
			if !argsContainPair(args, "-S", "clone3") {
				t.Fatalf("first grouped call should include clone3, got %#v", args)
			}
			return nil, errors.New("auditctl -a always,exit -F arch=b64 -S clone -S clone3 -S fork -S vfork: exit status 1: Syscall name unknown: clone3")
		}
		if argsContainPair(args, "-S", "clone3") {
			t.Fatalf("retry should remove unsupported clone3, got %#v", args)
		}
		for _, syscallName := range []string{"clone", "fork", "vfork"} {
			if !argsContainPair(args, "-S", syscallName) {
				t.Fatalf("retry should keep supported syscall %s, got %#v", syscallName, args)
			}
		}
		return nil, nil
	}

	rules, err := addAuditRules(100, "tb_test_clone", false, []string{"clone", "clone3", "fork", "vfork"}, []string{"b64"})
	if err != nil {
		t.Fatalf("addAuditRules: %v", err)
	}
	if len(calls) != 2 {
		t.Fatalf("calls=%d, want initial grouped call plus grouped retry: %#v", len(calls), calls)
	}
	if len(rules) != 1 {
		t.Fatalf("rules=%d, want one grouped retry rule: %#v", len(rules), rules)
	}
	if containsString(rules[0].Syscalls, "clone3") {
		t.Fatalf("stored retry rule should not include clone3: %#v", rules[0].Syscalls)
	}
	if !auditSyscallUnsupported("b64", "clone3") {
		t.Fatal("clone3 should be cached as unsupported after grouped error")
	}
}

func TestRequireAuditLogDir(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no-audit-log")
	if err := requireAuditLogDir(filepath.Join(missing, "audit.log")); err == nil {
		t.Fatal("expected error for missing audit log directory")
	} else if !strings.Contains(err.Error(), "audit 日志目录不存在") {
		t.Fatalf("unexpected error: %v", err)
	}

	readyDir := t.TempDir()
	if err := requireAuditLogDir(filepath.Join(readyDir, "audit.log")); err != nil {
		t.Fatalf("existing audit log directory should be accepted: %v", err)
	}

	filePath := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(filePath, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := requireAuditLogDir(filepath.Join(filePath, "audit.log")); err == nil {
		t.Fatal("expected error when audit log parent is a file")
	}
}

func TestToolAuditRuleKeyPrefixMatchesPreviousRuns(t *testing.T) {
	lines := []string{
		`-a always,exit -F arch=b64 -S execve -k tb_external_listener_exec`,
		`-a always,exit -F arch=b64 -S execve -k tb_port_8080_exec`,
		`-a always,exit -F arch=b64 -S execve -k other_exec`,
	}
	matched := 0
	for _, line := range lines {
		key := auditRuleKeyFromListLine(line)
		if strings.HasPrefix(key, toolAuditRuleKeyPrefix) {
			matched++
		}
	}
	if matched != 2 {
		t.Fatalf("matched = %d, want 2", matched)
	}
}

func TestParseAuditStatusAndRuleCount(t *testing.T) {
	status := parseAuditStatus("enabled 1\nfailure 1\nbacklog 3\nbacklog_limit 8192\nlost 0\n")
	if status["enabled"] != "1" || status["backlog"] != "3" || status["backlog_limit"] != "8192" {
		t.Fatalf("unexpected status: %#v", status)
	}
	status = parseAuditStatus("enabled 0\n")
	if status["enabled"] != "0" {
		t.Fatalf("enabled = %q, want 0", status["enabled"])
	}
	rules := "-a always,exit -F arch=b64 -S execve -k a\n-w /etc/passwd -p wa -k b\n"
	if got := countAuditRules(rules); got != 2 {
		t.Fatalf("countAuditRules = %d, want 2", got)
	}
}

func TestEstimatePlannedAuditRules(t *testing.T) {
	listeners := []listenerInfo{
		{PID: 100, Process: "sshd", Port: 22},
		{PID: 200, Process: "nginx", Port: 443, MonitorExe: "/usr/sbin/nginx", ExeOnly: true},
	}
	planned := estimatePlannedAuditRules(listeners, true, true, map[int]bool{}, true, map[int]bool{}, nil, nil, nil, false, map[int]bool{}, false, nil, javaMonitorModeExeOnly)
	if planned <= 0 {
		t.Fatalf("planned rules should be positive, got %d", planned)
	}
	skipped := estimatePlannedAuditRules(listeners, true, true, map[int]bool{}, true, map[int]bool{}, nil, buildStringSet([]string{"nginx"}), nil, false, map[int]bool{}, false, nil, javaMonitorModeExeOnly)
	if skipped >= planned {
		t.Fatalf("skipped planned rules should be less than planned: skipped=%d planned=%d", skipped, planned)
	}
}

func TestEstimatePlannedAuditRulesWithExplicitB32(t *testing.T) {
	listeners := []listenerInfo{{PID: 100, Process: "php-fpm", Port: 9000}}
	b64Only := estimatePlannedAuditRulesWithArches(listeners, true, true, map[int]bool{}, false, nil, nil, nil, nil, false, nil, false, nil, []string{"b64"}, javaMonitorModeExeOnly)
	withB32 := estimatePlannedAuditRulesWithArches(listeners, true, true, map[int]bool{}, false, nil, nil, nil, nil, false, nil, false, nil, []string{"b64", "b32"}, javaMonitorModeExeOnly)
	if b64Only == 0 || withB32 != b64Only*2 {
		t.Fatalf("expected b64+b32 to double planned rules: b64=%d both=%d", b64Only, withB32)
	}
}

func TestEstimatePlannedAuditRulesCountsMergedSyscallGroups(t *testing.T) {
	listeners := []listenerInfo{{PID: 100, Process: "php-fpm", Port: 9000}}
	planned := estimatePlannedAuditRulesWithArches(listeners, true, true, map[int]bool{}, false, nil, nil, nil, nil, false, nil, false, nil, []string{"b64"}, javaMonitorModeExeOnly)
	if planned != 4 {
		t.Fatalf("planned rules = %d, want 4 grouped rules for pid/ppid exec and clone", planned)
	}
}

func TestEstimatePlannedAuditRulesJavaHybrid(t *testing.T) {
	listeners := []listenerInfo{
		{PID: 300, Process: "java", Port: 8080, MonitorExe: "/usr/bin/java", ExeOnly: true},
	}
	exeOnly := estimatePlannedAuditRules(listeners, true, true, map[int]bool{}, true, map[int]bool{}, nil, nil, nil, false, map[int]bool{}, false, nil, javaMonitorModeExeOnly)
	hybrid := estimatePlannedAuditRules(listeners, true, true, map[int]bool{}, true, map[int]bool{}, nil, nil, nil, false, map[int]bool{}, false, nil, javaMonitorModeHybrid)
	pidTree := estimatePlannedAuditRules(listeners, true, true, map[int]bool{}, true, map[int]bool{}, nil, nil, nil, false, map[int]bool{}, false, nil, javaMonitorModePIDTree)
	if hybrid <= exeOnly {
		t.Fatalf("hybrid should estimate more rules than exe_only: hybrid=%d exe_only=%d", hybrid, exeOnly)
	}
	if pidTree >= hybrid {
		t.Fatalf("pid_tree should estimate fewer rules than hybrid exe+tree: pid_tree=%d hybrid=%d", pidTree, hybrid)
	}
}

func TestEstimatePlannedAuditRulesWebGatewayHybrid(t *testing.T) {
	nginx := []listenerInfo{{PID: 400, Process: "nginx", Port: 80, MonitorExe: "/usr/sbin/nginx", ExeOnly: true}}
	plainExe := []listenerInfo{{PID: 401, Process: "other", Port: 80, MonitorExe: "/usr/bin/other", ExeOnly: true}}
	nginxRules := estimatePlannedAuditRules(nginx, true, true, map[int]bool{}, true, map[int]bool{}, nil, nil, nil, false, map[int]bool{}, false, nil, javaMonitorModeHybrid)
	plainRules := estimatePlannedAuditRules(plainExe, true, true, map[int]bool{}, true, map[int]bool{}, nil, nil, nil, false, map[int]bool{}, false, nil, javaMonitorModeHybrid)
	if nginxRules <= plainRules {
		t.Fatalf("web gateway hybrid should estimate more rules than plain exe-only: nginx=%d plain=%d", nginxRules, plainRules)
	}
}

func TestAuditRuleKeyFromListLineSupportsFormats(t *testing.T) {
	cases := map[string]string{
		`-a always,exit -F arch=b64 -S execve -k tb_exec`:            "tb_exec",
		`-a always,exit -F arch=b64 -S execve -F key=tb_exec`:        "tb_exec",
		`-a always,exit -F arch=b64 -S execve key="tb_exec"`:         "tb_exec",
		`-a always,exit -F arch=b64 -S execve -F key="tb_exec_more"`: "tb_exec_more",
	}
	for line, want := range cases {
		if got := auditRuleKeyFromListLine(line); got != want {
			t.Fatalf("auditRuleKeyFromListLine(%q) = %q, want %q", line, got, want)
		}
	}
}

func TestListenAddressMatchesAddressAndWildcard(t *testing.T) {
	if !listenAddressMatches("10.0.0.80", "10.0.0.80") {
		t.Fatal("same IPv4 address should match")
	}
	if listenAddressMatches("10.0.0.80", "10.0.0.81") {
		t.Fatal("different concrete IPv4 addresses should not match")
	}
	if !listenAddressMatches("0.0.0.0", "0.0.0.0") || !listenAddressMatches("::", "::") {
		t.Fatal("wildcard addresses should match same-family wildcard")
	}
}

func TestAuditArchesReturnsAuditArchNames(t *testing.T) {
	arches := auditArches()
	if len(arches) == 0 {
		t.Fatal("auditArches should not be empty")
	}
	for _, arch := range arches {
		if arch != "b64" && arch != "b32" {
			t.Fatalf("unexpected audit arch %q", arch)
		}
	}
	if runtime.GOARCH == "amd64" && containsString(arches, "b32") {
		t.Fatalf("amd64 default audit arches should not include b32: %#v", arches)
	}
}

func TestCleanupSessionRulesDeletesTrackedRulesByKey(t *testing.T) {
	original := runAuditctlCommand
	defer func() { runAuditctlCommand = original }()
	var calls [][]string
	runAuditctlCommand = func(timeout time.Duration, args ...string) ([]byte, error) {
		if timeout != auditctlTimeout {
			t.Fatalf("timeout = %v, want %v", timeout, auditctlTimeout)
		}
		calls = append(calls, append([]string(nil), args...))
		return nil, nil
	}
	monitor := &processTreeMonitor{
		rules: []auditRule{
			{Arch: "b64", Field: "pid", PID: 100, Key: "tb_external_listener_exec", Syscalls: []string{"execve"}},
			{Arch: "b64", Field: "ppid", PID: 100, Key: "tb_external_listener_exec", Syscalls: []string{"clone"}},
			{Arch: "b64", Field: "pid", PID: 100, Key: "tb_external_listener_clone", Syscalls: []string{"clone"}},
		},
	}
	removed, err := monitor.cleanupSessionRules()
	if err != nil {
		t.Fatalf("cleanupSessionRules returned error: %v", err)
	}
	if removed != 2 || len(calls) != 2 {
		t.Fatalf("removed=%d calls=%d, want 2 unique keys", removed, len(calls))
	}
	got := map[string]bool{}
	for _, call := range calls {
		if len(call) != 3 || call[0] != "-D" || call[1] != "-k" {
			t.Fatalf("expected bulk delete by key, got %#v", calls)
		}
		got[call[2]] = true
	}
	if !got["tb_external_listener_exec"] || !got["tb_external_listener_clone"] {
		t.Fatalf("unexpected deleted keys: %#v", calls)
	}
	if len(monitor.rulesSnapshot()) != 0 {
		t.Fatalf("rules should be cleared after cleanup")
	}
}

func TestRemovePIDRulesRetainsStateWhenAuditctlDeleteFails(t *testing.T) {
	original := runAuditctlCommand
	defer func() { runAuditctlCommand = original }()
	runAuditctlCommand = func(timeout time.Duration, args ...string) ([]byte, error) {
		return []byte("delete failed"), errors.New("exit status 1")
	}
	monitor := &processTreeMonitor{
		monitored:   map[int]bool{100: true},
		pidListener: map[int]listenerInfo{100: {PID: 100, Process: "sshd", Port: 22}},
		pidTargets:  map[int]trackingTarget{100: {Source: "listener"}},
		rules: []auditRule{
			{Arch: "b64", Field: "pid", PID: 100, Key: "tb_external_listener_exec", Syscalls: []string{"execve", "execveat"}},
			{Arch: "b64", Field: "ppid", PID: 100, Key: "tb_external_listener_clone", Syscalls: []string{"clone", "fork"}},
		},
	}

	monitor.removePIDRules(100)
	if got := len(monitor.rulesSnapshot()); got != 2 {
		t.Fatalf("rules = %d, want failed deletions retained", got)
	}
	if !monitor.monitored[100] {
		t.Fatal("failed deletion must keep pid monitored to prevent duplicate re-add")
	}
	if !monitor.pendingPIDRuleCleanup[100] {
		t.Fatal("failed deletion must be scheduled for a later cleanup retry")
	}
}

func TestPendingPIDRuleCleanupRetriesSuccessfully(t *testing.T) {
	original := runAuditctlCommand
	defer func() { runAuditctlCommand = original }()
	runAuditctlCommand = func(timeout time.Duration, args ...string) ([]byte, error) {
		return nil, nil
	}
	monitor := &processTreeMonitor{
		monitored:             map[int]bool{100: true},
		processStartTimes:     map[int]uint64{100: 10},
		pidListener:           map[int]listenerInfo{100: {PID: 100}},
		pidTargets:            map[int]trackingTarget{},
		pendingRuleExpansion:  map[int]bool{},
		pendingPIDRuleCleanup: map[int]bool{100: true},
		suppressedCloneRules:  map[int]ruleExpansion{},
		rules: []auditRule{
			{Arch: "b64", Field: "pid", PID: 100, Key: "tb_external_listener_exec", Syscalls: []string{"execve", "execveat"}},
		},
	}
	monitor.retryPendingRuleCleanup()
	if len(monitor.rulesSnapshot()) != 0 || monitor.monitored[100] || monitor.pendingPIDRuleCleanup[100] {
		t.Fatalf("pending cleanup state was not cleared: rules=%d monitored=%v pending=%v",
			len(monitor.rulesSnapshot()), monitor.monitored[100], monitor.pendingPIDRuleCleanup[100])
	}
}

func TestRemovePIDRulesClearsStateAfterSuccessfulDelete(t *testing.T) {
	original := runAuditctlCommand
	defer func() { runAuditctlCommand = original }()
	runAuditctlCommand = func(timeout time.Duration, args ...string) ([]byte, error) {
		return nil, nil
	}
	monitor := &processTreeMonitor{
		monitored:   map[int]bool{100: true},
		pidListener: map[int]listenerInfo{100: {PID: 100, Process: "sshd", Port: 22}},
		pidTargets:  map[int]trackingTarget{100: {Source: "listener"}},
		rules: []auditRule{
			{Arch: "b64", Field: "pid", PID: 100, Key: "tb_external_listener_exec", Syscalls: []string{"execve", "execveat"}},
			{Arch: "b64", Field: "ppid", PID: 100, Key: "tb_external_listener_clone", Syscalls: []string{"clone", "fork"}},
		},
	}

	monitor.removePIDRules(100)
	if got := len(monitor.rulesSnapshot()); got != 0 {
		t.Fatalf("rules = %d, want 0", got)
	}
	if monitor.monitored[100] || monitor.pidListener[100].PID != 0 {
		t.Fatal("successful deletion should clear pid tracking state")
	}
	if _, ok := monitor.pidTargets[100]; ok {
		t.Fatal("successful deletion should clear companion pid target")
	}
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func countArg(values []string, target string) int {
	count := 0
	for _, value := range values {
		if value == target {
			count++
		}
	}
	return count
}

func argsContainPair(values []string, flag, value string) bool {
	for i := 0; i+1 < len(values); i++ {
		if values[i] == flag && values[i+1] == value {
			return true
		}
	}
	return false
}

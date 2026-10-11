package auditportexecmon

import (
	"testing"
	"time"
)

// These regressions exercise the observer, queued expansion and ownership lookup
// with deterministic PID lifetimes. auditctl is stubbed: no host rules change.
func TestAttributionRuntimeParentMustNotInheritListener(t *testing.T) {
	oldAlive, oldStart := isProcessAlive, readProcessStartTime
	defer func() { isProcessAlive, readProcessStartTime = oldAlive, oldStart }()
	isProcessAlive = func(int) bool { return true }
	readProcessStartTime = func(int) uint64 { return 100 }
	listener := listenerInfo{PID: 900001, Process: "mysqld", Port: 3306}
	queue := make(chan ruleExpansion, 8)
	m := &processTreeMonitor{
		processBackend:        processTreeBackendAuditPID,
		listeners:             []listenerInfo{listener},
		monitored:             map[int]bool{listener.PID: true},
		processStartTimes:     map[int]uint64{listener.PID: 100},
		pidListener:           map[int]listenerInfo{listener.PID: listener},
		pendingRuleExpansion:  map[int]bool{},
		deferredRuleExpansion: map[int]ruleExpansion{},
		ruleExpansionQueue:    queue,
	}
	// The listener itself is the root of its monitored tree. Its runtime
	// parent (containerd-shim) must not become part of that descendant tree.
	m.trackProcessChain(listener.PID, 930001, listener)
	for len(queue) > 0 {
		job := <-queue
		if job.PID == 930001 {
			t.Fatalf("unrelated runtime parent PID=%d was queued as listener=%s root=%d", job.PID, job.Listener.Process, job.Listener.PID)
		}
	}
}

func TestAttributionBoundedExitedReusedPIDMustNotKeepOldOwner(t *testing.T) {
	oldStart := readProcessStartTime
	defer func() { readProcessStartTime = oldStart }()
	readProcessStartTime = func(int) uint64 { return 0 }
	java := listenerInfo{PID: 900001, Process: "java", Port: 8888}
	m := &processTreeMonitor{
		processBackend:    processTreeBackendAudit,
		pidListener:       map[int]listenerInfo{910001: java},
		monitored:         map[int]bool{910001: true},
		processStartTimes: map[int]uint64{910001: 100},
		processParentPIDs: map[int]int{910001: java.PID},
		processObservedAt: map[int]time.Time{910001: time.Now()},
	}
	// A later short-lived runc reused the PID and has already exited by the
	// time the audit record is consumed; its event PPID differs from the cache.
	got, ok := m.matchListener(map[string]string{"pid": "910001", "ppid": "930001", "exe": "/usr/bin/runc"})
	if ok {
		t.Fatalf("exited/reused PID with changed parent inherited stale listener=%s root=%d", got.Process, got.PID)
	}
}

func TestAttributionBoundedStaleChildMustFallBackToVerifiedParent(t *testing.T) {
	oldStart := readProcessStartTime
	defer func() { readProcessStartTime = oldStart }()
	readProcessStartTime = func(pid int) uint64 {
		if pid == 900002 {
			return 300
		}
		return 0
	}
	java := listenerInfo{PID: 900001, Process: "java", Port: 8888}
	mysql := listenerInfo{PID: 900002, Process: "mysqld", Port: 3306}
	m := &processTreeMonitor{
		processBackend:    processTreeBackendAudit,
		pidListener:       map[int]listenerInfo{910001: java, mysql.PID: mysql},
		monitored:         map[int]bool{910001: true, mysql.PID: true},
		processStartTimes: map[int]uint64{910001: 100, mysql.PID: 300},
		processParentPIDs: map[int]int{910001: java.PID, mysql.PID: 1},
		processObservedAt: map[int]time.Time{910001: time.Now()},
	}
	got, ok := m.matchListener(map[string]string{"pid": "910001", "ppid": "900002", "exe": "/usr/bin/id"})
	if !ok || got.PID != mysql.PID {
		t.Fatalf("verified parent is mysqld, got listener=%s root=%d owned=%v", got.Process, got.PID, ok)
	}
}

func TestAttributionLegacyLookupMustRejectLiveReusedPID(t *testing.T) {
	oldStart := readProcessStartTime
	defer func() { readProcessStartTime = oldStart }()
	readProcessStartTime = func(int) uint64 { return 200 }
	java := listenerInfo{PID: 900001, Process: "java", Port: 8888}
	m := &processTreeMonitor{
		processBackend:    processTreeBackendAuditPID,
		pidListener:       map[int]listenerInfo{910001: java},
		monitored:         map[int]bool{910001: true},
		processStartTimes: map[int]uint64{910001: 100},
	}
	got, ok := m.matchListener(map[string]string{"pid": "910001", "ppid": "930001", "exe": "/usr/bin/runc"})
	if ok {
		t.Fatalf("live PID starttime changed 100->200 but lookup returned listener=%s root=%d", got.Process, got.PID)
	}
}

func TestAttributionBoundedLiveReuseUsesVerifiedParentControl(t *testing.T) {
	oldStart := readProcessStartTime
	defer func() { readProcessStartTime = oldStart }()
	readProcessStartTime = func(pid int) uint64 {
		if pid == 910001 {
			return 200
		}
		if pid == 900002 {
			return 300
		}
		return 0
	}
	java := listenerInfo{PID: 900001, Process: "java", Port: 8888}
	mysql := listenerInfo{PID: 900002, Process: "mysqld", Port: 3306}
	m := &processTreeMonitor{
		processBackend:    processTreeBackendAudit,
		pidListener:       map[int]listenerInfo{910001: java, mysql.PID: mysql},
		monitored:         map[int]bool{910001: true, mysql.PID: true},
		processStartTimes: map[int]uint64{910001: 100, mysql.PID: 300},
		processParentPIDs: map[int]int{910001: java.PID, mysql.PID: 1},
		processObservedAt: map[int]time.Time{},
		pidTargets:        map[int]trackingTarget{},
	}
	got, ok := m.matchListener(map[string]string{"pid": "910001", "ppid": "900002", "exe": "/usr/bin/id"})
	if !ok || got.PID != mysql.PID {
		t.Fatalf("control: live reuse should return verified mysqld parent, got=%+v owned=%v", got, ok)
	}
}

// Exercise the real observer, expansion worker, and lookup in sequence. Only
// process identity reads and auditctl are stubbed; no host rules are changed.
func TestAttributionRuntimeParentPromotionMislabelsSiblingRunc(t *testing.T) {
	oldAlive, oldStart, oldCommand := isProcessAlive, readProcessStartTime, runAuditctlCommand
	defer func() { isProcessAlive, readProcessStartTime, runAuditctlCommand = oldAlive, oldStart, oldCommand }()
	isProcessAlive = func(int) bool { return true }
	readProcessStartTime = func(int) uint64 { return 100 }
	runAuditctlCommand = func(time.Duration, ...string) ([]byte, error) { return nil, nil }
	mysql := listenerInfo{PID: 900001, Process: "mysqld", Port: 3306}
	m := newProcessTreeMonitor([]listenerInfo{mysql}, 0, map[int]bool{}, "exec", "connect", "file", "sensitive", "clone", true, true, map[int]bool{}, false, nil, nil, nil, nil, false, nil, false, nil, []string{"b64"}, javaMonitorModeExeOnly)
	m.processBackend = processTreeBackendAuditPID
	m.monitored[mysql.PID] = true
	m.processStartTimes[mysql.PID] = 100
	m.pidListener[mysql.PID] = mysql
	m.ruleExpansionQueue = make(chan ruleExpansion, 8)
	// The business listener forks a child. Its own PPID is a runtime shim,
	// which is outside the listener's descendant tree.
	m.observeAuditFields(map[string]string{"type": "SYSCALL", "key": "clone", "pid": "900001", "ppid": "930001", "exe": "/usr/sbin/mysqld", "success": "yes", "exit": "940000"})
	for len(m.ruleExpansionQueue) > 0 {
		m.expandQueuedPID(<-m.ruleExpansionQueue)
	}
	if owner, ok := m.matchListener(map[string]string{"pid": "940000", "ppid": "900001", "exe": "/bin/sh"}); !ok || owner.PID != mysql.PID {
		t.Fatalf("real child lost its MySQL ownership: %+v, matched=%v", owner, ok)
	}
	got, ok := m.matchListener(map[string]string{"pid": "950001", "ppid": "930001", "exe": "/usr/bin/runc"})
	if ok {
		t.Fatalf("runtime sibling runc was attributed to listener=%s root=%d; runtime parent owner=%s", got.Process, got.PID, m.pidListener[930001].Process)
	}
}

// Install immutable synthetic identity readers; tests using this process-wide
// seam run serially and restore it after all local workers have stopped.
func stubAttributionStartTimes(t *testing.T, read func(int) uint64) {
	t.Helper()
	original := readProcessStartTime
	readProcessStartTime = read
	t.Cleanup(func() { readProcessStartTime = original })
}

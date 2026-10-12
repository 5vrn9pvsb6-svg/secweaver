package auditportexecmon

import (
	"bytes"
	"fmt"
	"strconv"
	"testing"
	"time"

	"secweaver-agent/pkg/processtracker"
)

// newAttributionMonitor uses high synthetic PIDs and immutable process readers;
// tests exercise real parser/ownership/output code without touching host audit.
func newAttributionMonitor(backend string) *processTreeMonitor {
	listener := listenerInfo{PID: 900001, RootStartTime: 100, Process: "mysqld", Port: 3306}
	m := newProcessTreeMonitor([]listenerInfo{listener}, 0, nil, "exec", "connect", "file", "sensitive", "clone", true, true, nil, false, nil, nil, nil, nil, false, nil, false, nil, []string{"b64"}, javaMonitorModeHybrid)
	m.processBackend = backend
	m.pidListener[listener.PID] = listener
	m.monitored[listener.PID] = true
	m.processStartTimes[listener.PID] = 100
	m.processParentPIDs[listener.PID] = 930001
	return m
}

func TestAttributionUnknownDroppedAfterAssembly(t *testing.T) {
	for _, backend := range []string{processTreeBackendAudit, processTreeBackendAuditPID} {
		t.Run(backend, func(t *testing.T) {
			stubAttributionStartTimes(t, func(pid int) uint64 {
				if pid == 900001 {
					return 100
				}
				return 0
			})
			m := newAttributionMonitor(backend)
			m.pidListener[910001] = m.listeners[0]
			m.processStartTimes[910001] = 200
			m.processParentPIDs[910001] = 900001
			line := `type=SYSCALL msg=audit(1791733161.591:123): syscall=59 success=yes exit=0 pid=910001 ppid=930001 comm="runc" exe="/usr/bin/runc" key="exec"`
			fields := parseFields(line)
			m.observeAuditFields(fields)
			if m.shouldDropBoundedAuditPrimary(fields) || fields["attribution_status"] != "unknown" {
				t.Fatalf("uncertain primary was dropped/unmarked: %v", fields)
			}
			accs := map[string]*auditAccumulator{}
			consumeAuditLineParsed(accs, line, fields, false)
			consumeAuditLine(accs, `type=EXECVE msg=audit(1791733161.591:123): argc=2 a0="runc" a1="exec"`)
			consumeAuditLine(accs, `type=PROCTITLE msg=audit(1791733161.591:123): proctitle=72756e630065786563`)
			var out bytes.Buffer
			// Admission may retain lifecycle uncertainty in memory, but neither
			// original output nor learning may receive an unconfirmed listener.
			sink := &learningOutput{Writer: &out, queue: make(chan auditEvent, 1)}
			emitReady(accs, m.execKey, m.connectKey, m.fileKey, m, hostIdentity{}, false, sink, 0)
			if out.Len() != 0 || len(sink.queue) != 0 || len(accs) != 0 {
				t.Fatalf("uncertain event escaped or accumulator leaked: output=%s queued=%d pending=%d", out.String(), len(sink.queue), len(accs))
			}
		})
	}
}

func TestAttributionRootGenerationSurvivesReseed(t *testing.T) {
	for _, backend := range []string{processTreeBackendAudit, processTreeBackendAuditPID} {
		t.Run(backend, func(t *testing.T) {
			stubAttributionStartTimes(t, func(pid int) uint64 {
				if pid == 900001 {
					return 300
				}
				if pid == 910001 {
					return 200
				}
				return 0
			})
			m := newAttributionMonitor(backend)
			m.pidListener[910001] = m.listeners[0]
			m.processStartTimes[910001] = 200
			// A discovery pass has reseeded the same root PID with a new lifetime.
			m.processStartTimes[900001] = 300
			m.listeners[0].RootStartTime = 300
			m.pidListener[900001] = m.listeners[0]
			for _, parent := range []string{"1", "900001"} {
				if listener, ok := m.matchListener(map[string]string{"pid": "910001", "ppid": parent, "exe": "/usr/bin/sh"}); ok {
					t.Fatalf("old child inherited reseeded root: %+v", listener)
				}
			}
		})
	}
}

func TestAttributionQueuedWorkRejectsRestartedRoot(t *testing.T) {
	rootStart := uint64(100)
	stubAttributionStartTimes(t, func(pid int) uint64 {
		if pid == 900001 {
			return rootStart
		}
		return 200
	})
	oldAlive, oldCommand := isProcessAlive, runAuditctlCommand
	isProcessAlive = func(int) bool { return true }
	defer func() { isProcessAlive, runAuditctlCommand = oldAlive, oldCommand }()
	calls := 0
	runAuditctlCommand = func(time.Duration, ...string) ([]byte, error) { calls++; return nil, nil }
	m := newAttributionMonitor(processTreeBackendAuditPID)
	m.ruleExpansionQueue = make(chan ruleExpansion, 1)
	m.enqueuePIDExpansion(910001, m.listeners[0])
	if len(m.ruleExpansionQueue) != 1 {
		t.Fatal("expected a pending child expansion")
	}
	rootStart = 300
	m.expandQueuedPID(<-m.ruleExpansionQueue)
	if calls != 0 || m.monitored[910001] || m.pendingRuleExpansion[910001] {
		t.Fatalf("old job survived root restart: calls=%d monitored=%v pending=%v", calls, m.monitored, m.pendingRuleExpansion)
	}
}

func TestAttributionShortLivedCloneRequiresEventOrderAndLifetime(t *testing.T) {
	stubAttributionStartTimes(t, func(pid int) uint64 {
		if pid == 900001 {
			return 100
		}
		return 0
	})
	for _, tc := range []struct {
		name   string
		offset time.Duration
		expire bool
		want   bool
	}{
		{"ordered", time.Millisecond, false, true},
		{"before_clone", -time.Millisecond, false, false},
		{"late_event", 6 * time.Second, false, false},
		{"expired_receipt", time.Millisecond, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newAttributionMonitor(processTreeBackendAudit)
			birth := time.Now().Add(-time.Second)
			msg := func(at time.Time) string { return fmt.Sprintf("audit(%d.%09d:1):", at.Unix(), at.Nanosecond()) }
			clone := map[string]string{"key": "clone", "pid": "900001", "ppid": "930001", "success": "yes", "exit": "910001", "msg": msg(birth)}
			m.observeAuditFields(clone)
			if tc.expire {
				m.processObservedAt[910001] = time.Now().Add(-6 * time.Second)
			}
			// Remove the direct-parent lookup: only clone evidence may match here.
			// Keep the root readable, but force parent lookup to have no owner so
			// it cannot mask an invalid child proof with a direct-parent match.
			delete(m.pidListener, 900001)
			fields := map[string]string{"pid": "910001", "ppid": "900001", "exe": "/bin/sh", "msg": msg(birth.Add(tc.offset))}
			_, ok := m.matchListener(fields)
			if ok != tc.want {
				t.Fatalf("verified=%v want=%v fields=%v", ok, tc.want, fields)
			}
			if !ok && fields["attribution_status"] != "unknown" {
				t.Fatalf("lost uncertain evidence: %v", fields)
			}
		})
	}
}

func TestAttributionCloneReplayDoesNotRefreshTrust(t *testing.T) {
	stubAttributionStartTimes(t, func(pid int) uint64 {
		if pid == 900001 {
			return 100
		}
		return 0
	})
	m := newAttributionMonitor(processTreeBackendAudit)
	birth := time.Now().Add(-time.Second)
	clone := map[string]string{"key": "clone", "pid": "900001", "ppid": "930001", "success": "yes", "exit": "910001", "msg": fmt.Sprintf("audit(%d.%09d:1):", birth.Unix(), birth.Nanosecond())}
	m.observeAuditFields(clone)
	old := time.Now().Add(-10 * time.Second)
	m.processObservedAt[910001] = old
	m.observeAuditFields(clone)
	if !m.processObservedAt[910001].Equal(old) {
		t.Fatal("replayed clone renewed identity TTL")
	}
}

func TestAttributionExpiredEBPFRootDropsOutput(t *testing.T) {
	stubAttributionStartTimes(t, func(pid int) uint64 {
		if pid == 900001 {
			return 300
		}
		return 200
	})
	m := newAttributionMonitor(processTreeBackendEBPF)
	source := processtracker.Event{Type: processtracker.EventExec, RootPID: 900001, RootStartTime: 100, PID: 910001, PPID: 930001, Args: []string{"runc", "exec"}}
	owner, ok := m.observeEBPFEvent(source)
	if !ok || !owner.AttributionUnknown || len(m.rules) != 0 || m.pidListener[910001].AttributionUnknown != true {
		t.Fatalf("expired root created ownership: %+v %v", owner, ok)
	}
	var out bytes.Buffer
	if err := emitEBPFExecEventWithContext(source, owner, "exec", hostIdentity{}, &out, processExecutionContext{}); err != nil {
		t.Fatal(err)
	}
	if out.Len() != 0 {
		t.Fatalf("expired listener reached event output: %s", out.String())
	}
}

func TestAttributionUnrelatedBoundedTrafficDoesNotReadProc(t *testing.T) {
	reads := 0
	stubAttributionStartTimes(t, func(int) uint64 { reads++; return 0 })
	m := newAttributionMonitor(processTreeBackendAudit)
	reads = 0
	for i := 0; i < 1000; i++ {
		fields := map[string]string{"type": "SYSCALL", "key": "exec", "pid": strconv.Itoa(950000 + i), "ppid": "1"}
		if !m.shouldDropBoundedAuditPrimary(fields) {
			t.Fatalf("unrelated traffic accepted: %v", fields)
		}
	}
	if reads != 0 {
		t.Fatalf("unrelated bounded traffic performed %d proc reads", reads)
	}
}

func TestAttributionReconcileRecognizesReusedRootPID(t *testing.T) {
	old := listenerInfo{PID: 900001, RootStartTime: 100, Process: "mysqld", Port: 3306}
	current := old
	current.RootStartTime = 200
	_, added, removed := reconcileListeners([]listenerInfo{old}, []listenerInfo{current})
	if len(added) != 1 || removed != 1 {
		t.Fatalf("same numeric PID hid root restart: added=%v removed=%d", added, removed)
	}
}

func TestAttributionIdentityReaderBypassesEnrichmentCache(t *testing.T) {
	// A fake PID can have stale enrichment even though /proc has no process.
	// The production identity seam must return unreadable, never that old value.
	const pid = 2147483647
	procCacheMu.Lock()
	old := startTimeCache
	startTimeCache.Value = map[int]uint64{pid: 12345}
	startTimeCache.ExpiresAt = time.Now().Add(time.Hour)
	procCacheMu.Unlock()
	t.Cleanup(func() { procCacheMu.Lock(); startTimeCache = old; procCacheMu.Unlock() })
	if readProcStartTime(pid) != 12345 {
		t.Fatal("enrichment fixture was not cached")
	}
	if got := readProcessStartTime(pid); got != 0 {
		t.Fatalf("identity trusted stale enrichment: %d", got)
	}
}

func TestAttributionDelayedEventCannotSeedReusedProcess(t *testing.T) {
	stubAttributionStartTimes(t, func(int) uint64 { return 100 })
	oldParent, oldAlive := readProcessParentPID, isProcessAlive
	readProcessParentPID = func(int) int { return 930002 }
	isProcessAlive = func(int) bool { return true }
	defer func() { readProcessParentPID, isProcessAlive = oldParent, oldAlive }()
	for _, backend := range []string{processTreeBackendAudit, processTreeBackendAuditPID} {
		m := newAttributionMonitor(backend)
		m.ruleExpansionQueue = make(chan ruleExpansion, 4)
		m.trackProcessChain(910001, 900001, m.listeners[0])
		if len(m.ruleExpansionQueue) != 0 || m.monitored[910001] {
			t.Fatalf("%s seeded another process from delayed PPID", backend)
		}
	}
}

func TestAttributionStaleCompanionCannotBypassIdentity(t *testing.T) {
	stubAttributionStartTimes(t, func(pid int) uint64 {
		if pid == 900001 {
			return 100
		}
		return 300
	})
	m := newAttributionMonitor(processTreeBackendAuditPID)
	m.pidTargets = map[int]trackingTarget{910001: companionTrackingTarget(m.listeners[0])}
	m.pidListener[910001] = m.listeners[0]
	m.processStartTimes[910001] = 200
	if target, ok := m.companionTargetForProcess(910002, 910001); ok {
		t.Fatalf("stale companion inherited by another child: %+v", target)
	}
}

func TestAttributionEBPFOldDescendantsDoNotInheritReseededRoot(t *testing.T) {
	stubAttributionStartTimes(t, func(pid int) uint64 {
		if pid == 900001 {
			return 300
		}
		return 200
	})
	m := newAttributionMonitor(processTreeBackendEBPF)
	oldOwner := m.listeners[0]
	m.pidListener[910001] = oldOwner
	m.processStartTimes[910001] = 200
	m.listeners[0].RootStartTime = 300
	m.pidListener[900001] = m.listeners[0]
	m.processStartTimes[900001] = 300
	// A child from the old service generation forks after the numeric root PID
	// was reused. RootPID alone must not relabel either generation's descendants.
	owner, _ := m.observeEBPFEvent(processtracker.Event{Type: processtracker.EventFork, RootPID: 900001, RootStartTime: 100, PID: 910002, PPID: 910001})
	if !owner.AttributionUnknown {
		t.Fatal("old parent's child inherited the new root")
	}
	m.observeEBPFEvent(processtracker.Event{Type: processtracker.EventExit, RootPID: 900001, RootStartTime: 100, PID: 910001, PPID: 1})
	owner, _ = m.observeEBPFEvent(processtracker.Event{Type: processtracker.EventExec, RootPID: 900001, RootStartTime: 100, PID: 910002, PPID: 1})
	if !owner.AttributionUnknown {
		t.Fatal("parent exit erased the child's uncertain generation")
	}
}

func TestAttributionRejectedCloneDoesNotLeakTrackingState(t *testing.T) {
	stubAttributionStartTimes(t, func(int) uint64 { return 100 })
	oldParent := readProcessParentPID
	readProcessParentPID = func(int) int { return 930002 }
	defer func() { readProcessParentPID = oldParent }()
	m := newAttributionMonitor(processTreeBackendAudit)
	for i := 0; i < 1000; i++ {
		m.trackSuccessfulCloneChild(map[string]string{"key": "clone", "success": "yes", "exit": strconv.Itoa(950000 + i), "msg": fmt.Sprintf("audit(%d.000:1):", time.Now().Unix())}, 900001, m.listeners[0])
	}
	if len(m.processCloneTimes) != 0 || len(m.monitored) != 1 {
		t.Fatal("rejected clones leaked unowned PID state")
	}
}

func TestAttributionAcceptedPrimarySurvivesIdentityChangeDuringAssembly(t *testing.T) {
	start := uint64(100)
	stubAttributionStartTimes(t, func(int) uint64 { return start })
	m := newAttributionMonitor(processTreeBackendAudit)
	fields := map[string]string{"type": "SYSCALL", "key": "exec", "pid": "900001", "ppid": "930001", "exe": "/usr/sbin/mysqld"}
	if m.shouldDropBoundedAuditPrimary(fields) {
		t.Fatal("live root's primary was rejected")
	}
	start = 200
	if _, ok := m.matchListener(fields); ok || fields["attribution_status"] != "unknown" {
		t.Fatalf("accepted event lost scope or retained old owner: %v", fields)
	}
}

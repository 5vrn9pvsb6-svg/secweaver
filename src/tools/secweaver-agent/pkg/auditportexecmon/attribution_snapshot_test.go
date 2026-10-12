package auditportexecmon

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"testing"
	"time"

	"secweaver-agent/pkg/processtracker"
)

// The fixture substitutes only OS identity/clock reads; the real transport
// admission, accumulator, attribution and output functions remain in use.
func snapshotFixture(t *testing.T, backend string) (*processTreeMonitor, map[int]uint64, *uint64) {
	t.Helper()
	starts := map[int]uint64{900001: 100, 910001: 200, 920001: 300}
	stubAttributionStartTimes(t, func(pid int) uint64 { return starts[pid] })
	oldParent, oldAlive, oldClock := readProcessParentPID, isProcessAlive, readAttributionMonotonicNS
	readProcessParentPID = func(pid int) int {
		if pid == 920001 {
			return 910001
		}
		if pid == 910001 {
			return 900001
		}
		return 930001
	}
	isProcessAlive = func(pid int) bool { return starts[pid] != 0 }
	clock := uint64(time.Second)
	readAttributionMonotonicNS = func() uint64 { return clock }
	t.Cleanup(func() {
		readProcessParentPID, isProcessAlive, readAttributionMonotonicNS = oldParent, oldAlive, oldClock
	})
	m := newAttributionMonitor(backend)
	for _, pid := range []int{910001, 920001} {
		m.pidListener[pid] = m.listeners[0]
		m.monitored[pid] = true
		m.processStartTimes[pid] = starts[pid]
		m.processParentPIDs[pid] = readProcessParentPID(pid)
	}
	return m, starts, &clock
}

func snapshotPrimary(at time.Time, serial int, pid, ppid int) string {
	return fmt.Sprintf(`type=SYSCALL msg=audit(%d.%09d:%d): syscall=59 success=yes exit=0 pid=%d ppid=%d comm="helper" exe="/bin/helper" key="exec"`, at.Unix(), at.Nanosecond(), serial, pid, ppid)
}

func snapshotTail(m *processTreeMonitor, accs map[string]*auditAccumulator, fields map[string]string) {
	for _, line := range []string{`type=EXECVE msg=` + fields["msg"] + ` argc=1 a0="helper"`, `type=PROCTITLE msg=` + fields["msg"] + ` proctitle=68656c706572`} {
		m.consumeAttributedAuditLine(accs, line, parseFields(line), false)
	}
}

func snapshotOutput(t *testing.T, m *processTreeMonitor, accs map[string]*auditAccumulator) auditEvent {
	t.Helper()
	var out bytes.Buffer
	emitReady(accs, m.execKey, m.connectKey, m.fileKey, m, hostIdentity{}, false, &out, time.Nanosecond)
	var event auditEvent
	if err := json.Unmarshal(out.Bytes(), &event); err != nil {
		t.Fatalf("missing output: %v %q", err, out.String())
	}
	if event.ListenerProcess != "mysqld" || event.ListenerPID != 900001 || event.AttributionStatus != "" {
		t.Fatalf("wrong historical owner: %+v", event)
	}
	return event
}

func TestSnapshotAuditPreservesAcceptedEventAfterExitOrReuse(t *testing.T) {
	for _, backend := range []string{processTreeBackendAudit, processTreeBackendAuditPID, processTreeBackendEBPF} {
		for _, reuse := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/reuse=%v", backend, reuse), func(t *testing.T) {
				m, starts, _ := snapshotFixture(t, backend)
				m.trackDescendants = false // no async worker needed for an existing tree
				accs := map[string]*auditAccumulator{}
				line := snapshotPrimary(time.Now(), 41, 920001, 910001)
				fields := parseFields(line)
				m.consumeAttributedAuditLine(accs, line, fields, false)
				if !accs["41"].attribution.verified {
					t.Fatal("primary not verified")
				}
				starts[900001], starts[910001], starts[920001] = 0, 0, 0
				if reuse {
					starts[900001], starts[910001], starts[920001] = 400, 500, 600
				}
				m.forgetTrackedPID(910001)
				m.forgetTrackedPID(920001)
				snapshotTail(m, accs, fields)
				got := snapshotOutput(t, m, accs)
				if got.CommandLine != "helper" || len(accs) != 0 {
					t.Fatal("assembly lost context or retained transaction")
				}
			})
		}
	}
}

func TestSnapshotUnknownCannotBeRescuedDuringAssembly(t *testing.T) {
	m, starts, _ := snapshotFixture(t, processTreeBackendAudit)
	starts[900001] = 0
	line := snapshotPrimary(time.Now(), 42, 920001, 910001)
	fields := parseFields(line)
	accs := map[string]*auditAccumulator{}
	m.consumeAttributedAuditLine(accs, line, fields, false)
	starts[900001] = 100
	snapshotTail(m, accs, fields)
	var out bytes.Buffer
	emitReady(accs, m.execKey, m.connectKey, m.fileKey, m, hostIdentity{}, false, &out, time.Nanosecond)
	if out.Len() != 0 || len(accs) != 0 {
		t.Fatal("unknown admission acquired a later label")
	}
}

func TestSnapshotAuditRejectsConflictingPrimaryAndForeignTail(t *testing.T) {
	for _, conflict := range []bool{false, true} {
		t.Run(strconv.FormatBool(conflict), func(t *testing.T) {
			m, _, _ := snapshotFixture(t, processTreeBackendAudit)
			m.trackDescendants = false
			accs := map[string]*auditAccumulator{}
			at := time.Now()
			line := snapshotPrimary(at, 43, 920001, 910001)
			fields := parseFields(line)
			m.consumeAttributedAuditLine(accs, line, fields, false)
			if conflict {
				other := snapshotPrimary(at, 43, 920001, 1)
				m.consumeAttributedAuditLine(accs, other, parseFields(other), false)
			} else {
				foreign := fmt.Sprintf(`type=EXECVE msg=audit(%d.%09d:43): argc=1 a0="foreign"`, at.Unix()-1, at.Nanosecond())
				m.consumeAttributedAuditLine(accs, foreign, parseFields(foreign), false)
			}
			snapshotTail(m, accs, fields)
			if !conflict {
				snapshotOutput(t, m, accs)
				return
			}
			var out bytes.Buffer
			emitReady(accs, m.execKey, m.connectKey, m.fileKey, m, hostIdentity{}, false, &out, time.Nanosecond)
			if out.Len() != 0 {
				t.Fatal("conflicting primary reused verified snapshot")
			}
		})
	}
	// A returned pooled accumulator must not confer its decision to another event.
	acc := getAccumulator("old")
	acc.attribution = auditAttributionSnapshot{decided: true, verified: true}
	putAccumulator(acc)
	next := getAccumulator("new")
	defer putAccumulator(next)
	if next.attribution.decided {
		t.Fatal("pool retained attribution")
	}
}

func TestSnapshotReparentPreservesSameInstanceOnly(t *testing.T) {
	for _, reuse := range []bool{false, true} {
		t.Run(strconv.FormatBool(reuse), func(t *testing.T) {
			m, starts, _ := snapshotFixture(t, processTreeBackendAudit)
			if reuse {
				starts[920001] = 400
			}
			fields := parseFields(snapshotPrimary(time.Now(), 44, 920001, 1))
			owner, ok := m.matchListener(fields)
			if ok == reuse {
				t.Fatalf("reparent/reuse decision wrong: matched=%v owner=%+v", ok, owner)
			}
			if !reuse && (owner.Process != "mysqld" || m.processParentPIDs[920001] != 1) {
				t.Fatal("reparent erased known lineage")
			}
		})
	}
}

func TestSnapshotEBPFQueuedExecSurvivesRootExitAndCleanup(t *testing.T) {
	for _, reuse := range []bool{false, true} {
		t.Run(strconv.FormatBool(reuse), func(t *testing.T) {
			m, starts, clock := snapshotFixture(t, processTreeBackendEBPF)
			*clock = uint64(3 * time.Second)
			event := processtracker.Event{Type: processtracker.EventExec, RootPID: 900001, RootStartTime: 100, PID: 920001, PPID: 910001, TimestampNS: uint64(2 * time.Second), Args: []string{"helper"}}
			starts[900001] = 0
			m.pruneDeadPIDs() // removes active entries but retains historical root identity
			m.listeners = nil
			if reuse {
				starts[900001] = 400
				starts[920001] = 600
				replacement := listenerInfo{PID: 900001, RootStartTime: 400, Process: "replacement"}
				m.pidListener[920001] = replacement
				m.processStartTimes[920001] = 600
				m.monitored[920001] = true
			}
			owner, ok := m.observeEBPFEvent(event)
			if !ok || owner.AttributionUnknown || !owner.Historical || owner.Process != "mysqld" {
				t.Fatalf("queued source lost: %+v %v", owner, ok)
			}
			var out bytes.Buffer
			if err := emitEBPFExecEventWithContext(event, owner, "exec", hostIdentity{}, &out, processExecutionContext{}); err != nil || out.Len() == 0 {
				t.Fatalf("no historical output: %v", err)
			}
			if reuse && (m.pidListener[920001].Process != "replacement" || m.processStartTimes[920001] != 600) {
				t.Fatal("history mutated replacement")
			}
			if !reuse && m.monitored[920001] {
				t.Fatal("history reseeded dead process")
			}
		})
	}
}

func TestSnapshotEBPFTransientReadDoesNotPoisonFutureEvents(t *testing.T) {
	m, starts, _ := snapshotFixture(t, processTreeBackendEBPF)
	// No source timestamp means this event cannot use historical recovery.
	event := processtracker.Event{Type: processtracker.EventExec, RootPID: 900001, RootStartTime: 100, PID: 920001, PPID: 910001}
	starts[900001] = 0
	owner, _ := m.observeEBPFEvent(event)
	if !owner.AttributionUnknown {
		t.Fatal("unproven event accepted")
	}
	starts[900001] = 100
	owner, ok := m.observeEBPFEvent(event)
	if !ok || owner.AttributionUnknown || m.pidListener[920001].AttributionUnknown {
		t.Fatal("same-generation fresh proof stayed unknown")
	}
}

func TestSnapshotEBPFHistoryRequiresSourceInterval(t *testing.T) {
	for _, tc := range []struct {
		name    string
		eventNS uint64
		expire  bool
	}{
		{"before_tracking", 1, false}, {"after_retirement", uint64(4 * time.Second), false},
		{"missing_time", 0, false}, {"expired", uint64(2 * time.Second), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, starts, clock := snapshotFixture(t, processTreeBackendEBPF)
			*clock = uint64(3 * time.Second)
			starts[900001] = 0
			m.pruneDeadPIDs()
			*clock = uint64(5 * time.Second)
			if tc.expire {
				*clock = uint64(40 * time.Second)
			}
			owner, _ := m.observeEBPFEvent(processtracker.Event{Type: processtracker.EventExec, RootPID: 900001, RootStartTime: 100, PID: 920001, PPID: 910001, TimestampNS: tc.eventNS})
			if !owner.AttributionUnknown {
				t.Fatalf("invalid interval accepted: %+v", owner)
			}
		})
	}
}

func TestSnapshotAuditHistoryUsesVerifiedIntervalNotForkAge(t *testing.T) {
	m, starts, _ := snapshotFixture(t, processTreeBackendAudit)
	at := time.Now()
	owner := m.listeners[0]
	m.rememberProcessHistoryLocked(920001, 910001, 300, owner, at.Add(-20*time.Second))
	m.rememberProcessHistoryLocked(920001, 910001, 300, owner, at)
	starts[910001], starts[920001] = 0, 0
	m.forgetTrackedPID(910001)
	m.forgetTrackedPID(920001)
	fields := parseFields(snapshotPrimary(at.Add(-time.Millisecond), 45, 920001, 910001))
	listener, ok := m.matchListener(fields)
	if !ok || !listener.Historical || listener.Process != "mysqld" {
		t.Fatal("verified old process interval was discarded")
	}
	m.observeAuditFields(fields)
	if m.monitored[920001] || m.monitored[910001] {
		t.Fatal("history created active tracking")
	}
	for _, at := range []time.Time{at.Add(time.Millisecond), at.Add(-21 * time.Second)} {
		if _, ok := m.matchListener(parseFields(snapshotPrimary(at, 46, 920001, 910001))); ok {
			t.Fatal("unobserved lifetime was guessed")
		}
	}
	starts[920001] = 400
	if _, ok := m.matchListener(parseFields(snapshotPrimary(at.Add(-time.Millisecond), 47, 920001, 910001))); ok {
		t.Fatal("reused process accepted old history")
	}
}

func TestSnapshotRootExitCannotReopenFromZombieProc(t *testing.T) {
	m, _, clock := snapshotFixture(t, processTreeBackendEBPF)
	*clock = uint64(3 * time.Second)
	m.observeEBPFEvent(processtracker.Event{Type: processtracker.EventExit, RootPID: 900001, RootStartTime: 100, PID: 900001, TimestampNS: uint64(2 * time.Second)})
	// The root's proc entry deliberately remains readable, as for a zombie.
	owner, _ := m.observeEBPFEvent(processtracker.Event{Type: processtracker.EventExec, RootPID: 900001, RootStartTime: 100, PID: 920001, PPID: 910001, TimestampNS: uint64(2500 * time.Millisecond)})
	if !owner.AttributionUnknown {
		t.Fatal("zombie liveness reopened retired root")
	}
	owner, _ = m.observeEBPFEvent(processtracker.Event{Type: processtracker.EventExec, RootPID: 900001, RootStartTime: 100, PID: 920001, PPID: 910001, TimestampNS: uint64(1500 * time.Millisecond)})
	if owner.AttributionUnknown || !owner.Historical {
		t.Fatal("pre-exit buffered exec lost historical root")
	}
	m.pruneDeadPIDs()
	if m.monitored[920001] {
		t.Fatal("zombie root retained active child tracking")
	}
	m.pruneAttributionHistoryLocked(time.Now().Add(2 * attributionHistoryTTL))
	owner, _ = m.observeEBPFEvent(processtracker.Event{Type: processtracker.EventExec, RootPID: 900001, RootStartTime: 100, PID: 920001, PPID: 910001, TimestampNS: uint64(2500 * time.Millisecond)})
	if !owner.AttributionUnknown {
		t.Fatal("expired tombstone resurrected retired root")
	}
}

func TestSnapshotHistoryBudgetsAndExpiry(t *testing.T) {
	m, _, _ := snapshotFixture(t, processTreeBackendAudit)
	now := time.Now()
	for i := 0; i < maxProcessHistory+10; i++ {
		m.rememberProcessHistoryLocked(1000000+i, 900001, uint64(i+1), m.listeners[0], now)
	}
	if len(m.attributionHistory.processes) != maxProcessHistory || m.attributionHistory.processOrder.Len() != maxProcessHistory {
		t.Fatal("process history exceeded cap")
	}
	if m.attributionHistory.processes[1000000] != nil {
		t.Fatal("oldest process was not evicted")
	}
	for i := 0; i < maxRootHistory+10; i++ {
		owner := listenerInfo{PID: 2000000 + i, RootStartTime: uint64(i + 1), Process: "service"}
		m.rememberRootHistoryLocked(owner)
		m.closeRootHistoryLocked(owner, 1)
	}
	if len(m.attributionHistory.roots) != maxRootHistory || m.attributionHistory.rootOrder.Len() != maxRootHistory {
		t.Fatal("root history exceeded cap")
	}
	if m.attributionCounts["history_evicted"] == 0 {
		t.Fatal("eviction was not counted")
	}
	m.pruneAttributionHistoryLocked(now.Add(2 * attributionHistoryTTL))
	if len(m.attributionHistory.roots) != 0 || len(m.attributionHistory.processes) != 0 || m.attributionHistory.rootOrder.Len() != 0 || m.attributionHistory.processOrder.Len() != 0 {
		t.Fatal("retired history leaked")
	}
}

func TestSnapshotDiscoveryReopensWithoutBridgingCollectionGap(t *testing.T) {
	m, _, clock := snapshotFixture(t, processTreeBackendEBPF)
	root := m.listeners[0]
	*clock = uint64(2 * time.Second)
	m.closeRootHistoryLocked(root, 0)
	*clock = uint64(4 * time.Second)
	m.reopenDiscoveredRootLocked(root)
	*clock = uint64(6 * time.Second)
	m.closeRootHistoryLocked(root, 0)
	for _, tc := range []struct {
		at   uint64
		want bool
	}{{uint64(3 * time.Second), false}, {uint64(5 * time.Second), true}} {
		_, ok := m.historicalEBPFListenerLocked(processtracker.Event{RootPID: 900001, RootStartTime: 100, TimestampNS: tc.at})
		if ok != tc.want {
			t.Fatal("reopened interval bridged unmonitored gap")
		}
	}
}

package auditportexecmon

import (
	"bytes"
	"testing"
	"time"

	"secweaver-agent/pkg/processtracker"
)

// Admission must reject the unrelated backend even if both gateways are live,
// while still accepting the real descendant. No live /proc tree is consulted.
func TestCompanionRegistrationRequiresActualGatewayTree(t *testing.T) {
	stubAttributionStartTimes(t, func(int) uint64 { return 100 })
	previous := readProcessParentPID
	readProcessParentPID = func(pid int) int {
		if pid == 910001 {
			return 900001
		}
		return 1
	}
	t.Cleanup(func() { readProcessParentPID = previous })
	m := newAttributionMonitor(processTreeBackendAuditPID)
	a := m.listeners[0]
	b := a
	b.PID = 900002
	b.Port = 8080
	m.listeners = []listenerInfo{b, a}
	m.registerCompanionPID(910001, companionTrackingTarget(b))
	if _, exists := m.pidListener[910001]; exists {
		t.Fatal("unrelated gateway registered ownership")
	}
	m.registerCompanionPID(910001, companionTrackingTarget(a))
	if owner, ok := m.matchListener(map[string]string{"pid": "910001", "ppid": "900001"}); !ok || owner.PID != a.PID {
		t.Fatalf("real descendant lost ownership: %+v/%v", owner, ok)
	}
	readProcessParentPID = func(pid int) int { return pid }
	if verifiedListenerDescendant(a, 910099) {
		t.Fatal("cyclic process data established ownership")
	}
}

func TestListenerSocketIdentityDoesNotCollapseIndependentOwners(t *testing.T) {
	a := listenerInfo{PID: 100, Process: "java", MonitorExe: "/usr/bin/java", Address: "0.0.0.0", Port: 8080, ExeOnly: true}
	b := a
	b.PID = 200
	if listenerIdentity(a) == listenerIdentity(b) {
		t.Fatal("shared executable/address collapsed independent socket owners")
	}
}

// A flood of already-exited children must remain memory-bounded without making
// historical ownership look like successfully installed audit rules.
func TestHistoricalForkBudgetAndCleanup(t *testing.T) {
	stubAttributionStartTimes(t, func(pid int) uint64 {
		if pid == 900001 {
			return 100
		}
		return 0
	})
	m := newAttributionMonitor(processTreeBackendAuditPID)
	birth := time.Now()
	for i := 0; i < maxAuditForkProofs; i++ {
		if !m.rememberAuditFork(1000000+i, 900001, m.listeners[0], birth) {
			t.Fatalf("proof admission unexpectedly failed at %d", i)
		}
	}
	if m.rememberAuditFork(2000000, 900001, m.listeners[0], birth) {
		t.Fatal("history exceeded admission budget")
	}
	if len(m.monitored) != 1 || len(m.rules) != 0 {
		t.Fatal("historical identities reserved rules")
	}
	m.mu.Lock()
	m.pruneAuditForksLocked(birth.Add(2 * unknownProcessIdentityTTL))
	m.mu.Unlock()
	if len(m.processCloneTimes) != 0 || len(m.pidListener) != 1 || len(m.processStartTimes) != 1 {
		t.Fatal("expired uninstalled identities leaked")
	}
}

func TestHistoricalForkDoesNotRenewOnReplayOrReplaceInstalledIdentity(t *testing.T) {
	stubAttributionStartTimes(t, func(pid int) uint64 {
		if pid == 900001 {
			return 100
		}
		return 0
	})
	for _, backend := range []string{processTreeBackendAudit, processTreeBackendAuditPID} {
		m := newAttributionMonitor(backend)
		birth := time.Now().Add(-time.Second)
		if !m.rememberAuditFork(910001, 900001, m.listeners[0], birth) {
			t.Fatal("valid proof rejected")
		}
		observed := m.processObservedAt[910001]
		if m.rememberAuditFork(910001, 900001, m.listeners[0], birth) || !m.processObservedAt[910001].Equal(observed) {
			t.Fatal("duplicate proof renewed trust")
		}
		if m.rememberAuditFork(910002, 900001, m.listeners[0], birth.Add(-10*time.Second)) {
			t.Fatal("expired evidence entered the ledger")
		}
		m.monitored[910001] = true
		other := m.listeners[0]
		other.PID = 999001
		m.pidListener[910001] = other
		if m.rememberAuditFork(910001, 900001, m.listeners[0], birth.Add(time.Millisecond)) || m.pidListener[910001].PID != other.PID {
			t.Fatal("proof overwrote another installed identity")
		}
	}
}

// A live bounded-audit child graduates into the normal tracked ledger. Expiring
// its short historical proof must not erase a still-verifiable process tree.
func TestLiveBoundedChildSurvivesForkProofExpiry(t *testing.T) {
	stubAttributionStartTimes(t, func(pid int) uint64 {
		if pid == 900001 {
			return 100
		}
		return 200
	})
	m := newAttributionMonitor(processTreeBackendAudit)
	birth := time.Now().Add(-time.Second)
	if !m.rememberAuditFork(910001, 900001, m.listeners[0], birth) {
		t.Fatal("valid fork rejected")
	}
	m.trackProcessChain(910001, 900001, m.listeners[0])
	m.mu.Lock()
	m.pruneAuditForksLocked(birth.Add(2 * unknownProcessIdentityTTL))
	m.mu.Unlock()
	if !m.monitored[910001] || m.pidListener[910001].PID != 900001 {
		t.Fatal("proof expiry erased a live bounded-audit descendant")
	}
}

// Old exec/fork/exit events must neither adopt nor destroy a new generation.
// A current event is the positive control, with identical numeric PIDs.
func TestEBPFGenerationRejectsStaleEventsWithoutMutatingReplacement(t *testing.T) {
	stubAttributionStartTimes(t, func(pid int) uint64 {
		if pid == 900001 {
			return 300
		}
		return 400
	})
	for _, eventType := range []uint32{processtracker.EventFork, processtracker.EventExec, processtracker.EventExit} {
		for _, generation := range []uint64{0, 100} {
			m := newAttributionMonitor(processTreeBackendEBPF)
			current := m.listeners[0]
			current.RootStartTime = 300
			current.Process = "replacement"
			m.listeners[0] = current
			// Mirror a fresh discovery's membership/history update as well as the
			// PID ledger; an old event alone cannot activate a replacement root.
			m.reopenDiscoveredRootLocked(current)
			m.pidListener[900001] = current
			m.processStartTimes[900001] = 300
			m.pidListener[910001] = current
			m.processStartTimes[910001] = 400
			m.monitored[910001] = true
			event := processtracker.Event{Type: eventType, RootPID: 900001, RootStartTime: generation, PID: 910001, PPID: 900001}
			owner, ok := m.observeEBPFEvent(event)
			if !ok || !owner.AttributionUnknown || !m.monitored[910001] || m.pidListener[910001] != current {
				t.Fatalf("stale event mutated replacement: type=%d generation=%d owner=%+v", eventType, generation, owner)
			}
			event.Type, event.RootStartTime = processtracker.EventExec, 300
			owner, ok = m.observeEBPFEvent(event)
			if !ok || owner.AttributionUnknown || owner.RootStartTime != 300 {
				t.Fatalf("current event rejected: %+v/%v", owner, ok)
			}
		}
	}
}

func TestUnknownListenerPlaceholderCannotReachOutput(t *testing.T) {
	var out bytes.Buffer
	for _, name := range []string{"", " ", "unknown", " UNKNOWN "} {
		if err := emitNormalizedEvent(&out, auditEvent{EventType: "exec", ListenerProcess: name}); err != nil {
			t.Fatal(err)
		}
	}
	if out.Len() != 0 {
		t.Fatalf("placeholder reached output: %s", out.String())
	}
}

func TestProcNetInodeColumnValidatesInput(t *testing.T) {
	for _, tc := range []struct{ field, want string }{{"000123", "123"}, {"0", ""}, {"-1", ""}, {"inode", ""}, {"18446744073709551616", ""}} {
		fields := make([]string, 10)
		fields[9] = tc.field
		if got := procNetSocketInode(fields); got != tc.want {
			t.Fatalf("inode %q became %q, want %q", tc.field, got, tc.want)
		}
	}
	if procNetSocketInode(nil) != "" || procNetSocketInode(make([]string, 9)) != "" {
		t.Fatal("truncated TCP row accepted")
	}
}

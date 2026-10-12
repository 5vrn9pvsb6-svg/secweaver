package auditportexecmon

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"secweaver-agent/pkg/processtracker"
)

// These regression fixtures replace procfs inputs, never auditctl or live
// services. They cover the listener identity contract across admission paths.
func TestListenerAccuracyCompanionCommandIsNotService(t *testing.T) {
	backend := webGatewayCompanionBackends[len(webGatewayCompanionBackends)-1]
	if cmdlineMatchesCompanionBackend([]string{"pgrep", "-fl", "unicorn.* worker"}, backend) {
		t.Fatal("pgrep command was classified as an actual Unicorn backend")
	}
}

func TestListenerAccuracyExecutableFallbackRejectsExpiredRoot(t *testing.T) {
	stubAttributionStartTimes(t, func(int) uint64 { return 300 })
	for _, backend := range []string{processTreeBackendAuditPID, processTreeBackendEBPF} {
		for _, companion := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/companion=%v", backend, companion), func(t *testing.T) {
				m := newAttributionMonitor(backend)
				gateway := listenerInfo{PID: 900002, RootStartTime: 100, Process: "nginx", Port: 443, MonitorExe: "/usr/sbin/nginx", ExeOnly: true}
				m.listeners = []listenerInfo{gateway}
				exe := "/usr/sbin/nginx"
				if companion {
					exe = "/opt/runtime/ruby"
					m.exeTargets[exe] = trackingTarget{Gateway: gateway, Source: "companion-exe"}
				}
				fields := map[string]string{"pid": "910002", "ppid": "930002", "exe": exe, "key": "exec"}
				owner, ok := m.matchListener(fields)
				if ok {
					var out bytes.Buffer
					_ = emitNormalizedEvent(&out, auditEvent{EventType: "exec", ListenerProcess: owner.Process, ListenerPID: owner.PID, CommandLine: "probe"})
					t.Fatalf("expired root assigned through executable fallback: root=%d label=%s emitted=%v", owner.PID, owner.Process, out.Len() > 0)
				}
			})
		}
	}
}

func TestListenerAccuracySharedExecutableSeedsOnlyActualRoot(t *testing.T) {
	const exe = "/synthetic/runtime/java"
	procCacheMu.Lock()
	oldExe, oldParents := pidsByExeCache, ppidMapCache
	pidsByExeCache = map[string]pidListCacheEntry{exe: {Value: []int{900001, 900002}, ExpiresAt: time.Now().Add(time.Minute)}}
	ppidMapCache = intMapCacheEntry{Value: map[int]int{}, ExpiresAt: time.Now().Add(time.Minute)}
	procCacheMu.Unlock()
	t.Cleanup(func() { procCacheMu.Lock(); pidsByExeCache, ppidMapCache = oldExe, oldParents; procCacheMu.Unlock() })
	stubAttributionStartTimes(t, func(pid int) uint64 {
		if pid == 900001 {
			return 100
		}
		if pid == 900002 {
			return 200
		}
		return 0
	})
	oldAlive := isProcessAlive
	isProcessAlive = func(pid int) bool { return pid == 900001 || pid == 900002 }
	t.Cleanup(func() { isProcessAlive = oldAlive })
	m := newAttributionMonitor(processTreeBackendAudit)
	m.trackDescendants = false
	rootA := listenerInfo{PID: 900001, RootStartTime: 100, Process: "java", MonitorExe: exe, ExeOnly: true, Port: 8080}
	rootB := listenerInfo{PID: 900002, RootStartTime: 200, Process: "java", MonitorExe: exe, ExeOnly: true, Port: 9090}
	m.listeners = []listenerInfo{rootA, rootB}
	if err := m.bootstrapBoundedAuditListener(rootA); err != nil {
		t.Fatal(err)
	}
	if got, ok := m.matchListener(map[string]string{"pid": "900002", "ppid": "1", "exe": exe, "key": "exec"}); ok && got.PID == rootA.PID {
		t.Fatalf("independent Java root B assigned to root A: got root=%d port=%d, want root=%d port=%d", got.PID, got.Port, rootB.PID, rootB.Port)
	}
	// Reseeding in the opposite order must preserve both legitimate services,
	// not merely reject every event to make the isolation assertion pass.
	for _, root := range []listenerInfo{rootB, rootA} {
		if err := m.bootstrapBoundedAuditListener(root); err != nil {
			t.Fatal(err)
		}
	}
	for _, root := range []listenerInfo{rootA, rootB} {
		got, ok := m.matchListener(map[string]string{"pid": fmt.Sprint(root.PID), "ppid": "1", "exe": exe})
		if !ok || got.PID != root.PID || got.Port != root.Port {
			t.Fatalf("valid root lost after reseed: got=%+v ok=%v want=%+v", got, ok, root)
		}
	}

}

func TestListenerAccuracyDelayedEBPFRootCannotUseReplacement(t *testing.T) {
	stubAttributionStartTimes(t, func(pid int) uint64 {
		if pid == 900001 {
			return 300
		}
		return 0
	})
	m := newAttributionMonitor(processTreeBackendEBPF)
	current := listenerInfo{PID: 900001, RootStartTime: 300, Process: "replacement", Port: 9090}
	m.listeners = []listenerInfo{current}
	m.pidListener[900001] = current
	m.processStartTimes[900001] = 300
	// A delayed event from the old root's kernel map arrives after userspace
	// replaced the root entry. No child/parent cache or root generation survives.
	oldEvent := processtracker.Event{Type: processtracker.EventExec, RootPID: 900001, RootStartTime: 100, PID: 910099, PPID: 930099, TimestampNS: 100, StartBootNS: 50, IdentityValid: true, Args: []string{"old-command"}}
	owner, ok := m.observeEBPFEvent(oldEvent)
	if ok && !owner.AttributionUnknown {
		t.Fatalf("historical event was labeled as current replacement root: %+v", owner)
	}
}

func TestListenerAccuracyShortLivedGrandchildKeepsObservedForkChain(t *testing.T) {
	for _, backend := range []string{processTreeBackendAudit, processTreeBackendAuditPID} {
		t.Run(backend, func(t *testing.T) {
			stubAttributionStartTimes(t, func(pid int) uint64 {
				if pid == 900001 {
					return 100
				}
				return 0
			})
			oldParent, oldAlive := readProcessParentPID, isProcessAlive
			readProcessParentPID = func(int) int { return 0 }
			isProcessAlive = func(pid int) bool { return pid == 900001 }
			t.Cleanup(func() { readProcessParentPID, isProcessAlive = oldParent, oldAlive })
			m := newAttributionMonitor(backend)
			m.ruleExpansionQueue = make(chan ruleExpansion, 8)
			birth := time.Now().Add(-100 * time.Millisecond)
			msg := func(at time.Time) string { return fmt.Sprintf("audit(%d.%09d:1):", at.Unix(), at.Nanosecond()) }
			m.observeAuditFields(map[string]string{"type": "SYSCALL", "key": "clone", "pid": "900001", "ppid": "930001", "success": "yes", "exit": "910001", "msg": msg(birth)})
			m.observeAuditFields(map[string]string{"type": "SYSCALL", "key": "clone", "pid": "910001", "ppid": "900001", "success": "yes", "exit": "910002", "msg": msg(birth.Add(time.Millisecond))})
			fields := map[string]string{"type": "SYSCALL", "key": "exec", "pid": "910002", "ppid": "910001", "exe": "/usr/bin/pgrep", "msg": msg(birth.Add(2 * time.Millisecond))}
			got, ok := m.matchListener(fields)
			if !ok || got.PID != 900001 {
				t.Fatalf("two observed forks lost attribution solely because child and grandchild exited: matched=%v owner=%+v status=%q", ok, got, fields["attribution_status"])
			}
		})
	}
}

// Standard Linux TCP rows include fields after inode; ownership must not depend
// on how many optional transport statistics follow the fixed inode column.
func TestListenerAccuracyProcNetListenerUsesInodeColumn(t *testing.T) {
	for _, address := range []string{"00000000", "00000000000000000000000000000000"} {
		t.Run(address, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "tcp")
			row := fmt.Sprintf("0: %s:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 54165785 1 0000000000000000 100 0 0 10 0\n", address)
			if err := os.WriteFile(path, []byte(row), 0600); err != nil {
				t.Fatal(err)
			}
			got, err := parseProcNetListeners(path, map[string]int{"54165785": 900001})
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 1 || got[0].PID != 900001 || got[0].Port != 8080 {
				t.Fatalf("known listening socket with inode 54165785 lost: listeners=%+v", got)
			}
		})
	}
}

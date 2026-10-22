package auditportexecmon

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"secweaver-agent/pkg/processtracker"
)

// The topology deliberately has independent nginx/PHP masters (both PPID=1)
// and a shared-FD PHP worker. No same-executable or first-gateway attribution
// shortcut is permitted between the two trees or the second PHP instance.
func localBackendFixture() (listenerInfo, []localBackendListener, map[int]localBackendProcess) {
	l := listenerInfo{PID: 920002, Process: "php-fpm", Address: "127.0.0.1", Port: 9000}
	selectors := []localBackendListener{{Address: "127.0.0.1", Port: 9000, Exe: "/usr/sbin/php-fpm"}}
	processes := map[int]localBackendProcess{
		910001: {PID: 910001, PPID: 1, StartTime: 100, Comm: "nginx", Exe: "/usr/sbin/nginx"},
		920001: {PID: 920001, PPID: 1, StartTime: 200, Comm: "php-fpm", Exe: "/usr/sbin/php-fpm"},
		920002: {PID: 920002, PPID: 920001, StartTime: 210, Comm: "php-fpm", Exe: "/usr/sbin/php-fpm"},
		930001: {PID: 930001, PPID: 1, StartTime: 300, Comm: "php-fpm", Exe: "/usr/sbin/php-fpm"},
	}
	return l, selectors, processes
}

func localBackendFixtureSources(l listenerInfo, processes map[int]localBackendProcess) listenerDiscoverySources {
	return listenerDiscoverySources{
		netstatCandidates: func() (netstatListenerScan, error) {
			return netstatListenerScan{TCPListenLines: 2, Candidates: []listenerInfo{
				{PID: 910001, Process: "nginx", Address: "0.0.0.0", Port: 80}, l,
			}}, nil
		},
		socketOwners:   func() (map[string]int, socketInodeScanStats) { return nil, socketInodeScanStats{} },
		procListeners:  func(map[string]int) []listenerInfo { return []listenerInfo{l} },
		inspectProcess: func(pid int) localBackendProcess { return processes[pid] },
	}
}

func TestLocalBackendDiscoveryIndependentPHP(t *testing.T) {
	l, selectors, processes := localBackendFixture()
	sources := localBackendFixtureSources(l, processes)
	// The old public-only entry still excludes loopback by default.
	public, err := findExternalListenersWithSources(0, nil, sources)
	if err != nil || len(public) != 1 || public[0].PID != 910001 {
		t.Fatalf("default public scope changed: %#v %v", public, err)
	}
	selected, err := findMonitoredListenersWithSources(0, nil, selectors, sources)
	if err != nil || len(selected) != 2 {
		t.Fatalf("explicit backend missing: %#v %v", selected, err)
	}
	php := selected[1]
	if php.PID != 920001 || php.Process != "php-fpm" || php.Port != 9000 || php.RootStartTime != 200 || php.ExeOnly || php.MonitorExe != "" || php.LocalBackendExe != selectors[0].Exe {
		t.Fatalf("backend must own its master tree, not nginx/all PHP: %#v", php)
	}
}

func TestLocalBackendAdmissionRejectsMismatchesAndReuse(t *testing.T) {
	for _, name := range []string{"address", "port", "exe", "unknown", "reused", "independent"} {
		t.Run(name, func(t *testing.T) {
			l, selectors, processes := localBackendFixture()
			inspect := func(pid int) localBackendProcess { return processes[pid] }
			switch name {
			case "address":
				l.Address = "127.0.0.2"
			case "port":
				l.Port = 9001
			case "exe":
				p := processes[l.PID]
				p.Exe = "/tmp/php-fpm"
				processes[l.PID] = p
			case "unknown":
				delete(processes, l.PID)
			case "reused":
				calls := 0
				inspect = func(pid int) localBackendProcess {
					p := processes[pid]
					if pid == l.PID {
						calls++
						if calls > 1 {
							p.StartTime++
						}
					}
					return p
				}
			case "independent":
				l.PID = 930001
			}
			root, ok := resolveLocalBackendRoot(l, selectors, inspect)
			if name == "independent" {
				if !ok || root.PID != 930001 {
					t.Fatalf("independent instance merged: %#v %t", root, ok)
				}
			} else if ok {
				t.Fatalf("mismatched/unverifiable backend admitted: %#v", root)
			}
		})
	}
}

func TestLocalBackendDiscoveryFallbackAndExclusions(t *testing.T) {
	for _, name := range []string{"netstat-failure", "missing-pid", "partial-parse", "whitelist", "port-filter", "fd-budget"} {
		t.Run(name, func(t *testing.T) {
			l, selectors, processes := localBackendFixture()
			sources := localBackendFixtureSources(l, processes)
			sources.netstatCandidates = func() (netstatListenerScan, error) {
				switch name {
				case "netstat-failure", "fd-budget":
					return netstatListenerScan{}, errors.New("missing netstat")
				case "missing-pid":
					return netstatListenerScan{TCPListenLines: 1, Candidates: []listenerInfo{{Address: l.Address, Port: l.Port}}}, nil
				case "partial-parse":
					return netstatListenerScan{TCPListenLines: 1, RejectedListenLines: 1}, nil
				default:
					return netstatListenerScan{TCPListenLines: 1, Candidates: []listenerInfo{l}}, nil
				}
			}
			if name == "fd-budget" {
				sources.socketOwners = func() (map[string]int, socketInodeScanStats) { return nil, socketInodeScanStats{BudgetExhausted: true} }
			}
			var whitelist map[int]bool
			port := 0
			if name == "whitelist" {
				whitelist = map[int]bool{9000: true}
			}
			if name == "port-filter" {
				port = 80
			}
			got, err := findMonitoredListenersWithSources(port, whitelist, selectors, sources)
			if name == "fd-budget" {
				if err == nil {
					t.Fatal("partial discovery must not prune a previous local scope")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			want := 1
			if name == "whitelist" || name == "port-filter" {
				want = 0
			}
			if len(got) != want {
				t.Fatalf("listeners=%#v want %d", got, want)
			}
		})
	}
}

func TestLocalBackendProcCandidatesRetainLoopback(t *testing.T) {
	for _, tc := range []struct{ hex, address string }{
		{"0100007F", "127.0.0.1"}, {"00000000000000000000000001000000", "::1"},
	} {
		path := filepath.Join(t.TempDir(), "tcp")
		data := fmt.Sprintf("0: %s:2328 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 555\n", tc.hex)
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		got, err := parseProcNetListeners(path, map[string]int{"555": 920002})
		if err != nil || len(got) != 1 || got[0].Address != tc.address || !isLoopback(got[0].Address) {
			t.Fatalf("proc loopback candidate=%#v err=%v", got, err)
		}
		if listenerMatchesFilter(got[0], 0, nil) {
			t.Fatal("default public filter admitted loopback")
		}
	}
}

func TestLocalBackendConfigValidation(t *testing.T) {
	_, selectors, _ := localBackendFixture()
	for _, name := range []string{"valid", "wildcard", "hostname", "port", "relative-exe", "unclean-exe", "duplicate", "limit"} {
		t.Run(name, func(t *testing.T) {
			entries := append([]localBackendListener(nil), selectors...)
			switch name {
			case "wildcard":
				entries[0].Address = "0.0.0.0"
			case "hostname":
				entries[0].Address = "localhost"
			case "port":
				entries[0].Port = 65536
			case "relative-exe":
				entries[0].Exe = "php-fpm"
			case "unclean-exe":
				entries[0].Exe = "/usr/../tmp/php-fpm"
			case "duplicate":
				entries = append(entries, entries[0])
			case "limit":
				entries = make([]localBackendListener, maxLocalBackendListeners+1)
			}
			data, _ := json.Marshal(map[string]any{"exec": map[string]any{"local_backend_listeners": entries}})
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			_, err := loadConfig(path)
			if (err == nil) != (name == "valid") {
				t.Fatalf("validation=%v", err)
			}
		})
	}
}

func TestLocalBackendCoverageDiagnostics(t *testing.T) {
	l, selectors, processes := localBackendFixture()
	sources := localBackendFixtureSources(l, processes)
	for _, tc := range []struct {
		name  string
		cfg   config
		state string
	}{
		{"unconfigured", config{}, "unconfigured"},
		{"configured", config{Exec: execSettings{LocalBackendListeners: selectors}}, "eligible"},
		{"limited", config{Exec: execSettings{LocalBackendListeners: selectors, ListenerPorts: []int{80}}}, "policy_limited"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rows, err := inspectLocalBackendCoverage(tc.cfg, 0, sources)
			if err != nil || len(rows) != 1 || rows[0].State != tc.state {
				t.Fatalf("rows=%#v err=%v", rows, err)
			}
		})
	}
	wrong := append([]localBackendListener(nil), selectors...)
	wrong[0].Exe = "/different/php-fpm"
	rows, err := inspectLocalBackendCoverage(config{Exec: execSettings{LocalBackendListeners: wrong}}, 0, sources)
	if err != nil || len(rows) != 1 || rows[0].State != "identity_mismatch" {
		t.Fatalf("rows=%#v err=%v", rows, err)
	}
	rows, err = localBackendCoverageFromCandidates(config{Exec: execSettings{LocalBackendListeners: selectors}}, 0, nil, sources.inspectProcess)
	if err != nil || len(rows) != 1 || rows[0].State != "not_listening" {
		t.Fatalf("rows=%#v err=%v", rows, err)
	}
}

func TestLocalBackendWaitsAndReconcilesRestart(t *testing.T) {
	l, selectors, processes := localBackendFixture()
	sources := localBackendFixtureSources(l, processes)
	sources.netstatCandidates = func() (netstatListenerScan, error) {
		return netstatListenerScan{}, nil
	}
	sources.procListeners = func(map[string]int) []listenerInfo { return nil }
	if got, err := findMonitoredListenersWithSources(0, nil, selectors, sources); err != nil || len(got) != 0 {
		t.Fatalf("late-start backend should wait for rescan: %#v %v", got, err)
	}
	root, ok := resolveLocalBackendRoot(l, selectors, func(pid int) localBackendProcess { return processes[pid] })
	if !ok {
		t.Fatal("initial root missing")
	}
	p := processes[root.PID]
	p.StartTime++ // the same numeric PID now belongs to a new master lifetime
	processes[root.PID] = p
	replacement, ok := resolveLocalBackendRoot(l, selectors, func(pid int) localBackendProcess { return processes[pid] })
	if !ok {
		t.Fatal("replacement root missing")
	}
	active, added, removed := reconcileListeners([]listenerInfo{root}, []listenerInfo{replacement})
	if len(active) != 1 || len(added) != 1 || removed != 1 || active[0].RootStartTime == root.RootStartTime {
		t.Fatalf("restart must retire/rebootstrap, not reuse old generation: %#v %#v %d", active, added, removed)
	}
}

func TestLocalBackendCoverageBoundsDiagnostics(t *testing.T) {
	var candidates []listenerInfo
	for i := 0; i < 140; i++ {
		candidates = append(candidates, listenerInfo{Address: "127.0.0.1", Port: 9000 + i, PID: 920002, Process: "php-fpm"})
	}
	rows, err := localBackendCoverageFromCandidates(config{}, 0, candidates, func(pid int) localBackendProcess {
		return localBackendProcess{PID: pid, PPID: 1, StartTime: 1, Exe: "/usr/sbin/php-fpm"}
	})
	if len(rows) != 128 || err == nil {
		t.Fatalf("diagnostics must be bounded and explicitly partial: %d %v", len(rows), err)
	}
}

// This exercises shared admission -> tracker registration -> fork ownership ->
// JSONL assembly. It uses the existing tracker fake, not native eBPF attachment.
func TestLocalBackendExecPipelineKeepsIndependentOwner(t *testing.T) {
	l, selectors, processes := localBackendFixture()
	root, ok := resolveLocalBackendRoot(l, selectors, func(pid int) localBackendProcess { return processes[pid] })
	if !ok {
		t.Fatal("backend was not admitted")
	}
	oldStart, oldParent, oldAlive := readProcessStartTime, readProcessParentPID, isProcessAlive
	t.Cleanup(func() { readProcessStartTime, readProcessParentPID, isProcessAlive = oldStart, oldParent, oldAlive })
	readProcessStartTime = func(pid int) uint64 { return processes[pid].StartTime }
	readProcessParentPID = func(pid int) int { return processes[pid].PPID }
	isProcessAlive = func(pid int) bool { return processes[pid].StartTime != 0 }
	for _, backend := range []string{processTreeBackendAudit, processTreeBackendEBPF} {
		t.Run(backend, func(t *testing.T) {
			m := newProcessTreeMonitor([]listenerInfo{root}, 0, nil, "exec", "connect", "file", "sensitive", "clone", true, true, nil, false, nil, nil, nil, nil, false, nil, false, nil, []string{"b64"}, javaMonitorModeHybrid)
			tracker := newFakeProcessTracker()
			m.setProcessTracker(backend, tracker)
			m.setEBPFOnly(backend == processTreeBackendEBPF)
			if err := m.expandPID(root.PID, root); err != nil {
				t.Fatal(err)
			}
			if err := m.expandPID(l.PID, root); err != nil {
				t.Fatal(err)
			}
			if backend == processTreeBackendEBPF {
				if len(tracker.tracked) != 2 || tracker.tracked[1].rootPID != uint32(root.PID) || !tracker.tracked[1].descendants {
					t.Fatalf("tracker=%#v", tracker.tracked)
				}
			}
			owner, matched := m.matchListener(map[string]string{"pid": "940001", "ppid": "920002", "exe": "/usr/bin/id"})
			if !matched || owner.PID != root.PID || owner.Process != "php-fpm" {
				t.Fatalf("owner=%#v matched=%t", owner, matched)
			}
			var output bytes.Buffer
			if backend == processTreeBackendAudit {
				accs := map[string]*auditAccumulator{}
				for _, line := range []string{
					`type=SYSCALL msg=audit(1792650000.123:12345): syscall=59 success=yes exit=0 pid=940001 ppid=920002 comm="id" exe="/usr/bin/id" key="exec"`,
					`type=EXECVE msg=audit(1792650000.123:12345): argc=1 a0="id"`,
				} {
					m.consumeAttributedAuditLine(accs, line, parseFields(line), false)
				}
				emitReady(accs, "exec", "connect", "file", m, hostIdentity{}, false, &output, time.Nanosecond)
			} else {
				event := processtracker.Event{Type: processtracker.EventFork, RootPID: uint32(root.PID), RootStartTime: root.RootStartTime, TimestampNS: 12345, PID: 940001, PPID: 920002}
				if _, ok := m.observeEBPFEvent(event); !ok {
					t.Fatal("kernel-proven backend fork rejected")
				}
				event.Type, event.Comm, event.Filename, event.Args = processtracker.EventExec, "id", "/usr/bin/id", []string{"id"}
				owner, ok := m.observeEBPFEvent(event)
				if !ok || owner.AttributionUnknown {
					t.Fatal("backend exec lost ownership")
				}
				if err := emitEBPFExecEventWithContext(event, owner, "exec", hostIdentity{}, &output, processExecutionContext{}); err != nil {
					t.Fatal(err)
				}
			}
			var event auditEvent
			if err := json.Unmarshal(output.Bytes(), &event); err != nil {
				t.Fatal(err)
			}
			if event.ListenerProcess != "php-fpm" || event.ListenerAddress != "127.0.0.1" || event.ListenerPort != 9000 || event.CommandLine != "id" {
				t.Fatalf("event=%#v", event)
			}
			if _, matched := m.matchListener(map[string]string{"pid": "930002", "ppid": "930001", "exe": "/usr/bin/id"}); matched {
				t.Fatal("unselected independent PHP instance was admitted")
			}
		})
	}
}

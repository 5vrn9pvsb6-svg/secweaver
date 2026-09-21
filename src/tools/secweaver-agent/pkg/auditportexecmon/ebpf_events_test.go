package auditportexecmon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"

	"secweaver-agent/pkg/processtracker"
)

type fakeProcessTrackerFactory struct {
	probeErr error
	newErr   error
	tracker  processtracker.Tracker
	options  processtracker.Options
}

func (factory *fakeProcessTrackerFactory) Probe() error { return factory.probeErr }

func (factory *fakeProcessTrackerFactory) New(_ context.Context, options processtracker.Options) (processtracker.Tracker, error) {
	factory.options = options
	return factory.tracker, factory.newErr
}

type fakeProcessTracker struct {
	mu        sync.Mutex
	tracked   []fakeTrackedProcess
	untracked []uint32
	events    chan processtracker.Event
	errors    chan error
}

type fakeTrackedProcess struct {
	pid         uint32
	ppid        uint32
	rootPID     uint32
	descendants bool
}

func newFakeProcessTracker() *fakeProcessTracker {
	return &fakeProcessTracker{
		events: make(chan processtracker.Event, 8),
		errors: make(chan error, 1),
	}
}

func (tracker *fakeProcessTracker) Track(pid, ppid, rootPID uint32, descendants bool) error {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	tracker.tracked = append(tracker.tracked, fakeTrackedProcess{pid: pid, ppid: ppid, rootPID: rootPID, descendants: descendants})
	return nil
}

func (tracker *fakeProcessTracker) Untrack(pid uint32) error {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	tracker.untracked = append(tracker.untracked, pid)
	return nil
}

func (tracker *fakeProcessTracker) Events() <-chan processtracker.Event { return tracker.events }
func (tracker *fakeProcessTracker) Errors() <-chan error                { return tracker.errors }
func (tracker *fakeProcessTracker) LostSamples() uint64                 { return 0 }
func (tracker *fakeProcessTracker) Close() error                        { return nil }

func TestProcessTreeBackendDefaultsToAutoEBPF(t *testing.T) {
	resolved := resolveProcessTreeConfig(config{})
	if resolved.Backend != processTreeBackendAuto || resolved.FallbackBackend != processTreeBackendAudit {
		t.Fatalf("unexpected defaults: %#v", resolved)
	}
	if resolved.MaxTrackedProcesses != defaultEBPFMaxTrackedProcesses || resolved.PerfBufferBytesPerCPU != defaultEBPFPerfBufferBytes {
		t.Fatalf("unexpected eBPF defaults: %#v", resolved)
	}
}

func TestAutoProcessTrackerUsesEBPFWhenFactorySucceeds(t *testing.T) {
	original := processTrackerFactory
	defer func() { processTrackerFactory = original }()
	tracker := newFakeProcessTracker()
	factory := &fakeProcessTrackerFactory{tracker: tracker}
	processTrackerFactory = factory
	cfg := processTreeRuntimeConfig{Backend: processTreeBackendAuto, FallbackBackend: processTreeBackendAudit, MaxTrackedProcesses: 77, PerfBufferBytesPerCPU: 8192}

	backend, got, _, err := startConfiguredProcessTracker(context.Background(), cfg, true, true)
	if err != nil {
		t.Fatal(err)
	}
	if backend != processTreeBackendEBPF || got != tracker {
		t.Fatalf("backend=%q tracker=%T", backend, got)
	}
	if factory.options.MaxTrackedProcesses != 77 || factory.options.PerfBufferBytesPerCPU != 8192 {
		t.Fatalf("options not propagated: %#v", factory.options)
	}
}

func TestAutoProcessTrackerFallsBackToAudit(t *testing.T) {
	original := processTrackerFactory
	defer func() { processTrackerFactory = original }()
	processTrackerFactory = &fakeProcessTrackerFactory{probeErr: processtracker.ErrUnsupported}
	cfg := processTreeRuntimeConfig{Backend: processTreeBackendAuto, FallbackBackend: processTreeBackendAudit}

	backend, tracker, reason, err := startConfiguredProcessTracker(context.Background(), cfg, true, true)
	if err != nil {
		t.Fatal(err)
	}
	if backend != processTreeBackendAudit || tracker != nil || reason == "" {
		t.Fatalf("backend=%q tracker=%T reason=%q", backend, tracker, reason)
	}
}

func TestExplicitAuditPIDBackendSkipsEBPFProbe(t *testing.T) {
	original := processTrackerFactory
	defer func() { processTrackerFactory = original }()
	processTrackerFactory = &fakeProcessTrackerFactory{probeErr: errors.New("probe must not be required")}
	cfg := processTreeRuntimeConfig{Backend: processTreeBackendAuditPID, FallbackBackend: processTreeBackendAudit}

	backend, tracker, _, err := startConfiguredProcessTracker(context.Background(), cfg, true, true)
	if err != nil {
		t.Fatal(err)
	}
	if backend != processTreeBackendAuditPID || tracker != nil {
		t.Fatalf("backend=%q tracker=%T", backend, tracker)
	}
}

func TestRequiredEBPFDoesNotSilentlyFallback(t *testing.T) {
	original := processTrackerFactory
	defer func() { processTrackerFactory = original }()
	processTrackerFactory = &fakeProcessTrackerFactory{newErr: errors.New("verifier rejected program")}
	cfg := processTreeRuntimeConfig{Backend: processTreeBackendEBPF, FallbackBackend: processTreeBackendAudit}

	_, _, _, err := startConfiguredProcessTracker(context.Background(), cfg, true, true)
	if err == nil {
		t.Fatal("expected forced eBPF startup failure")
	}
}

func TestEmitEBPFExecEventPreservesListenerContract(t *testing.T) {
	var output bytes.Buffer
	source := processtracker.Event{
		Type:          processtracker.EventExec,
		TimestampNS:   12345,
		RootPID:       100,
		PID:           102,
		PPID:          101,
		UID:           0,
		Comm:          "sh",
		Filename:      "/usr/bin/curl",
		Args:          []string{"curl", "https://example.invalid"},
		ArgsTruncated: true,
	}
	listener := listenerInfo{PID: 100, Process: "nginx", Address: "0.0.0.0", Port: 443}
	hasTTY := true
	processContext := processExecutionContext{AUID: "1000", CWD: "/var/www/html", TTY: "pts/0", HasTTY: &hasTTY}
	if err := emitEBPFExecEventWithContext(source, listener, "tb_external_listener_exec", hostIdentity{HostName: "host-a", HostIP: "10.0.0.1"}, &output, processContext); err != nil {
		t.Fatal(err)
	}
	var event auditEvent
	if err := json.Unmarshal(output.Bytes(), &event); err != nil {
		t.Fatal(err)
	}
	if event.EventType != "exec" || event.AuditID != "ebpf:12345:102" || event.ListenerPID != 100 || event.ListenerPort != 443 {
		t.Fatalf("unexpected event attribution: %#v", event)
	}
	if event.CommandLine != "curl https://example.invalid" || !event.CommandTruncated {
		t.Fatalf("unexpected command: %#v", event)
	}
	if event.AUID != "1000" || event.CWD != "/var/www/html" || event.TTY != "pts/0" || event.HasTTY == nil || !*event.HasTTY {
		t.Fatalf("unexpected process context: %#v", event)
	}
}

func TestEmitEBPFExecEventOmitsUnknownTTY(t *testing.T) {
	var output bytes.Buffer
	source := processtracker.Event{Type: processtracker.EventExec, TimestampNS: 1, PID: 42, PPID: 1, UID: 0, Comm: "id", Args: []string{"id"}}
	if err := emitEBPFExecEventWithContext(source, listenerInfo{PID: 10, Process: "nginx", Port: 443}, "exec", hostIdentity{HostName: "host-a", HostIP: "10.0.0.1"}, &output, processExecutionContext{}); err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(output.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	if _, exists := raw["has_tty"]; exists {
		t.Fatalf("unknown TTY must be omitted: %s", output.String())
	}
}

func TestParseProcStatTTYNumber(t *testing.T) {
	for _, test := range []struct {
		name string
		stat string
		want int64
		ok   bool
	}{
		{name: "interactive", stat: "42 (command with ) paren) S 1 2 3 34816 0", want: 34816, ok: true},
		{name: "non-interactive", stat: "42 (worker) S 1 2 3 0 0", want: 0, ok: true},
		{name: "malformed", stat: "42 worker", ok: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, ok := parseProcStatTTYNumber(test.stat)
			if got != test.want || ok != test.ok {
				t.Fatalf("tty_nr = %d/%v, want %d/%v", got, ok, test.want, test.ok)
			}
		})
	}
}

func TestObserveEBPFForkAndExitMaintainsAttribution(t *testing.T) {
	listener := listenerInfo{PID: 100, Process: "nginx", Address: "0.0.0.0", Port: 443}
	monitor := newProcessTreeMonitor([]listenerInfo{listener}, 0, nil, "exec", "connect", "file", "sensitive", "clone", true, true, nil, false, nil, nil, nil, nil, false, nil, false, nil, []string{"b64"}, javaMonitorModeHybrid)
	monitor.pidListener[100] = listener

	owned, ok := monitor.observeEBPFEvent(processtracker.Event{Type: processtracker.EventFork, RootPID: 100, PID: 102, PPID: 100})
	if !ok || owned.PID != 100 || !monitor.monitored[102] {
		t.Fatalf("fork attribution missing: listener=%#v ok=%v monitored=%v", owned, ok, monitor.monitored)
	}
	monitor.observeEBPFEvent(processtracker.Event{Type: processtracker.EventExit, RootPID: 100, PID: 102, PPID: 100})
	if monitor.monitored[102] {
		t.Fatalf("exit did not remove pid: %v", monitor.monitored)
	}
}

func TestObserveEBPFChildQueuesOptionalAuditRules(t *testing.T) {
	originalAlive := isProcessAlive
	originalStartTime := readProcessStartTime
	defer func() {
		isProcessAlive = originalAlive
		readProcessStartTime = originalStartTime
	}()
	isProcessAlive = func(int) bool { return true }
	readProcessStartTime = func(int) uint64 { return 100 }

	listener := listenerInfo{PID: 100, Process: "nginx", Address: "0.0.0.0", Port: 443}
	monitor := newProcessTreeMonitor([]listenerInfo{listener}, 0, nil, "exec", "connect", "file", "sensitive", "clone", true, true, nil, true, nil, nil, nil, nil, false, nil, false, nil, []string{"b64"}, javaMonitorModeHybrid)
	monitor.pidListener[100] = listener
	monitor.processBackend = processTreeBackendEBPF
	monitor.processTracker = newFakeProcessTracker()
	monitor.ruleExpansionQueue = make(chan ruleExpansion, 1)

	_, ok := monitor.observeEBPFEvent(processtracker.Event{Type: processtracker.EventFork, RootPID: 100, PID: 102, PPID: 100})
	if !ok {
		t.Fatal("fork event lost listener attribution")
	}
	if monitor.monitored[102] {
		t.Fatal("child was marked complete before optional audit rules were installed")
	}
	select {
	case job := <-monitor.ruleExpansionQueue:
		if job.PID != 102 || job.Listener.PID != 100 {
			t.Fatalf("unexpected expansion job: %#v", job)
		}
	default:
		t.Fatal("optional audit rule expansion was not queued")
	}
}

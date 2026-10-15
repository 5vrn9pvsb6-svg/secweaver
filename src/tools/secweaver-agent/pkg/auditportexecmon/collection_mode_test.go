package auditportexecmon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"secweaver-agent/pkg/processtracker"
)

// Exercise transport selection independently from this test host's kernel.
// Explicit policy never falls back; auto keeps ordinary Audit hosts unchanged.
func TestCollectionProfileSelection(t *testing.T) {
	for _, tc := range []struct {
		name, mode, backend, wantMode, wantError string
		auditOK, ebpfOK, attachFail, execOff     bool
	}{
		{name: "legacy-auto-audit", auditOK: true, wantMode: "audit"},
		{name: "explicit-audit", mode: "audit", auditOK: true, wantMode: "audit"},
		{name: "audit-missing-ebpf", ebpfOK: true, wantMode: "ebpf_only"},
		{name: "both-missing", wantError: "Linux collection unavailable"},
		{name: "attach-rejected", ebpfOK: true, attachFail: true, wantError: "verifier rejected"},
		{name: "explicit-audit-no-fallback", mode: "audit", ebpfOK: true, wantError: "audit.mode=audit"},
		{name: "explicit-pid-no-fallback", backend: "audit_pid", ebpfOK: true, wantError: "explicitly requires Audit"},
		{name: "forced-ebpf-conflict", mode: "ebpf_only", backend: "audit", ebpfOK: true, wantError: "explicitly requires Audit"},
		{name: "forced-ebpf", mode: "ebpf_only", auditOK: true, ebpfOK: true, wantMode: "ebpf_only"},
		{name: "exec-disabled", ebpfOK: true, execOff: true, wantError: "exec.monitor=true"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			original := processTrackerFactory
			t.Cleanup(func() { processTrackerFactory = original })
			tracker := &probeCloseTracker{fakeProcessTracker: newFakeProcessTracker()}
			factory := &fakeProcessTrackerFactory{tracker: tracker}
			if !tc.ebpfOK {
				factory.probeErr = processtracker.ErrUnsupported
			}
			if tc.attachFail {
				factory.newErr = errors.New("verifier rejected")
			}
			processTrackerFactory = factory
			cfg := config{}
			cfg.Audit.Mode = tc.mode
			cfg.Exec.ProcessTreeBackend = tc.backend
			if tc.execOff {
				value := false
				cfg.Exec.Monitor = &value
			}
			profile, err := resolveCollectionProfile(context.Background(), cfg, true, func() error {
				if tc.auditOK {
					return nil
				}
				return errors.New("audit kernel disabled")
			})
			if tc.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantError) {
					t.Fatalf("profile=%+v error=%v, want %q", profile, err, tc.wantError)
				}
				return
			}
			if err != nil || profile.Mode != tc.wantMode {
				t.Fatalf("profile=%+v error=%v", profile, err)
			}
			if tc.wantMode == "ebpf_only" && !tracker.closed {
				t.Fatal("capability probe left its tracker attached")
			}
		})
	}
}

func TestCollectionProfileKeepsRestartingWorkersOnOneTransport(t *testing.T) {
	initial, err := resolveCollectionProfile(context.Background(), config{}, false, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	cfg := config{}
	cfg.Audit.Mode = initial.Mode
	if _, err := resolveCollectionProfile(context.Background(), cfg, false, func() error { return errors.New("Audit stopped") }); err == nil || !strings.Contains(err.Error(), "audit.mode=audit") {
		t.Fatalf("child changed transport while parent owns Audit subscriptions: %v", err)
	}
}

type probeCloseTracker struct {
	*fakeProcessTracker
	closed bool
}

func (t *probeCloseTracker) Close() error { t.closed = true; return nil }

func TestEBPFOnlyHasNoAuditSubscriptionOrRules(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.json")
	if err := os.WriteFile(path, []byte(`{"audit":{"mode":"ebpf_only"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"-config", path}, {"-collection-mode=ebpf_only"}} {
		if _, subscribed, err := Descriptor().AuditSubscription(args); err != nil || subscribed {
			t.Fatalf("eBPF-only subscribed to audit.log: subscribed=%v err=%v", subscribed, err)
		}
	}
	// All Audit features deliberately start enabled: the product mode must
	// suppress them rather than depend on the shipped default policy.
	monitor := newProcessTreeMonitor(nil, 0, nil, "exec", "connect", "file", "sensitive", "clone", false, true, nil, true, nil, nil, nil, nil, true, nil, true, []string{"/etc/shadow"}, []string{"b64"}, javaMonitorModeHybrid)
	monitor.setProcessTracker(processTreeBackendEBPF, newFakeProcessTracker())
	monitor.setEBPFOnly(true)
	if err := monitor.bootstrapInitial(); err != nil {
		t.Fatal(err)
	}
	if err := monitor.addExeRules(listenerInfo{PID: 123, MonitorExe: "/test/binary"}); err != nil {
		t.Fatal(err)
	}
	monitor.rescanDescendants()
	if count, err := monitor.cleanupSessionRules(); err != nil || count != 0 {
		t.Fatalf("unexpected Audit cleanup: count=%d err=%v", count, err)
	}
	if len(monitor.rulesSnapshot()) != 0 || len(monitor.watchRulesSnapshot()) != 0 {
		t.Fatal("eBPF-only created Audit rules")
	}
}

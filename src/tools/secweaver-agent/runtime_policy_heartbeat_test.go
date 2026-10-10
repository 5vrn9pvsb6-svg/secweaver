package main

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"secweaver-agent/pkg/agentlicense"
)

// Exercise the real TLS heartbeat worker through its policy parse/write/reload
// signal, rather than only testing a local merger or a fabricated response.
func TestHeartbeatAppliesRuntimePolicyAndRequestsReload(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "config.json")
	if err := os.WriteFile(config, []byte(`{"enterprise_id":"0123456789ABCDEF","license":{"heartbeat_interval_seconds":180},"modules":{"host-process-snapshot":{"enabled":false,"args":["-interval","10m"]},"syslog-risk-json":{"enabled":true}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request agentlicense.Request
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		if len(request.RuntimePolicyCapabilities) != 1 || request.RuntimePolicyCapabilities[0] != "agent-runtime-policy-v1" || request.HeartbeatIntervalSeconds != 1 {
			t.Error("heartbeat capability/report missing")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(agentlicense.Response{Allowed: true, Registered: true, AgentRuntimePolicy: &agentlicense.RuntimePolicy{HostProcessIntervalMinutes: 45, HeartbeatIntervalMinutes: 10, Revision: 2}})
	}))
	defer server.Close()
	ca := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(dir, "license-state.json")
	if err := agentlicense.SaveState(state, agentlicense.State{DeviceID: "runtime-test-device"}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	t.Cleanup(func() { configMutationMu.Lock(); runtimeConfigRestartScheduled = false; configMutationMu.Unlock() })
	err := runScheduledHeartbeat(ctx, nil, config, agentlicense.Config{Enabled: true, Protocol: "legacy_v1", ServerURL: server.URL, CAFile: ca, EnrollmentID: "test-enrollment", StatePath: state, HeartbeatSeconds: 1}, "0123456789ABCDEF", nil, nil, nil, nil)
	if !errors.Is(err, errRemoteConfigApplied) {
		t.Fatal("heartbeat did not request reload", err)
	}
	cfg, err := loadConfig(config)
	if err != nil || cfg.License.HeartbeatSeconds != 600 {
		t.Fatal(cfg.License, err)
	}
	if value, _ := stringFlag(cfg.Modules["host-process-snapshot"].Args, "interval"); value != "45m0s" {
		t.Fatal("process cadence was not applied", value)
	}
}

// Config changes must wait without blocking heartbeat behind an active binary
// transaction. Once committed they fence another transaction until reload.
func TestRuntimePolicyConfigFence(t *testing.T) {
	configMutationMu.Lock()
	changed, err := applyManagedRuntimePolicy("unused-path", &agentlicense.RuntimePolicy{HostProcessIntervalMinutes: 30, HeartbeatIntervalMinutes: 5, Revision: 1})
	configMutationMu.Unlock()
	if err != nil || changed {
		t.Fatal("policy blocked/mutated during active transaction", changed, err)
	}
	configMutationMu.Lock()
	runtimeConfigRestartScheduled = true
	configMutationMu.Unlock()
	defer func() { configMutationMu.Lock(); runtimeConfigRestartScheduled = false; configMutationMu.Unlock() }()
	_, err, _ = runScheduledUpdateWithConfigFence(context.Background(), scheduledUpdateConfig{}, nil)
	if !errors.Is(err, errRemoteConfigApplied) {
		t.Fatal("new upgrade not fenced", err)
	}
}

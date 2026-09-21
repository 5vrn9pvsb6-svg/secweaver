package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"secweaver-agent/pkg/agentlicense"
)

func TestLoadConfigRequiresEnterpriseID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"modules":{"syslog-risk-json":{"enabled":true}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := loadConfig(path)
	if err == nil || !strings.Contains(err.Error(), "enterprise_id") {
		t.Fatalf("missing enterprise_id error = %v", err)
	}
}

func TestLoadConfigNormalizesEnterpriseID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	body := []byte(`{"enterprise_id":"6x13ngv4g9cvk92e","modules":{"syslog-risk-json":{"enabled":true}}}`)
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.EnterpriseID != "6X13NGV4G9CVK92E" {
		t.Fatalf("enterprise ID = %q", cfg.EnterpriseID)
	}
	modules, err := enabledModules(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(modules) != 1 || modules[0].EnterpriseID != cfg.EnterpriseID {
		t.Fatalf("enterprise ID not propagated: %+v", modules)
	}
}

func TestEnabledModulesRejectsCompetingWindowsEvidenceReaders(t *testing.T) {
	cfg := agentConfig{EnterpriseID: "6X13NGV4G9CVK92E", Modules: map[string]moduleConfig{
		"windows-eventlog-risk-json": {},
		"windows-process-execmon":    {},
	}}
	if _, err := enabledModules(cfg); err == nil || !strings.Contains(err.Error(), "both own Windows process evidence") {
		t.Fatalf("expected reader ownership conflict, got %v", err)
	}
}

func TestEnabledModulesAllowsExplicitStandaloneWindowsEvidenceOwner(t *testing.T) {
	cfg := agentConfig{EnterpriseID: "6X13NGV4G9CVK92E", Modules: map[string]moduleConfig{
		"windows-eventlog-risk-json": {Args: []string{"-evidence-output="}},
		"windows-process-execmon":    {},
	}}
	modules, err := enabledModules(cfg)
	if err != nil || len(modules) != 2 {
		t.Fatalf("standalone ownership should be valid: modules=%d err=%v", len(modules), err)
	}
}

func TestLoadConfigRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	body := []byte(`{"enterprise_id":"6X13NGV4G9CVK92E","future_option":true,"modules":{"syslog-risk-json":{"enabled":true}}}`)
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("expected unknown field error, got %v", err)
	}
}

func TestWithEnvValueReplacesExistingEnterpriseID(t *testing.T) {
	got := withEnvValue(
		[]string{"PATH=/usr/bin", "SECWEAVER_ENTERPRISE_ID=OLD0000000000000"},
		"SECWEAVER_ENTERPRISE_ID",
		"6X13NGV4G9CVK92E",
	)
	joined := strings.Join(got, "\n")
	if strings.Contains(joined, "OLD0000000000000") {
		t.Fatalf("old enterprise ID survived: %v", got)
	}
	if strings.Count(joined, "SECWEAVER_ENTERPRISE_ID=") != 1 || !strings.Contains(joined, "6X13NGV4G9CVK92E") {
		t.Fatalf("enterprise ID not enforced: %v", got)
	}
}

func TestScheduledUpdateDisabledByDefault(t *testing.T) {
	cfg, err := scheduledUpdateFromConfig(updateConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if cfg != nil {
		t.Fatalf("scheduled updater = %+v, want nil", cfg)
	}
}

func TestScheduledUpdateRequiresManifest(t *testing.T) {
	t.Setenv("SECWEAVER_AGENT_UPDATE_MANIFEST_URL", "")
	_, err := scheduledUpdateFromConfig(updateConfig{Enabled: true})
	if err == nil {
		t.Fatal("expected missing manifest error")
	}
}

func TestScheduledUpdateDefaults(t *testing.T) {
	cfg, err := scheduledUpdateFromConfig(updateConfig{
		Enabled:     true,
		ManifestURL: "https://updates.example.com/secweaver-agent/stable/update-manifest.json",
		PublicKey:   base64.StdEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Options.Channel != "stable" || cfg.Options.CurrentVersion != version {
		t.Fatalf("unexpected options: %+v", cfg.Options)
	}
	if cfg.Interval != 6*time.Hour {
		t.Fatalf("interval = %s, want 6h", cfg.Interval)
	}
	if cfg.RetryInitial != time.Minute || cfg.RetryMax != time.Hour {
		t.Fatalf("retry range = %s..%s, want 1m..1h", cfg.RetryInitial, cfg.RetryMax)
	}
	if !cfg.AutoInstall {
		t.Fatal("auto_install should default to true")
	}
	if cfg.Options.DeviceID != "" || cfg.Options.HostID != "" {
		t.Fatal("update identity must not default to mutable hostname")
	}
}

func TestScheduledUpdateRejectsInvalidRetryRange(t *testing.T) {
	_, err := scheduledUpdateFromConfig(updateConfig{
		Enabled:             true,
		ManifestURL:         "https://updates.example.com/secweaver-agent/stable/update-manifest.json",
		PublicKey:           base64.StdEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize)),
		RetryInitialSeconds: 120,
		RetryMaxSeconds:     60,
	})
	if err == nil || !strings.Contains(err.Error(), "retry_max_seconds") {
		t.Fatalf("invalid retry range error = %v", err)
	}
}

func TestServiceRestartExitCodeIsBackwardCompatible(t *testing.T) {
	t.Setenv("SECWEAVER_AGENT_RESTART_EXIT_CODE", "")
	if got := serviceRestartExitCode(); got != 1 {
		t.Fatalf("default restart exit code = %d, want 1", got)
	}
	t.Setenv("SECWEAVER_AGENT_RESTART_EXIT_CODE", "75")
	if got := serviceRestartExitCode(); got != 75 {
		t.Fatalf("configured restart exit code = %d, want 75", got)
	}
	t.Setenv("SECWEAVER_AGENT_RESTART_EXIT_CODE", "invalid")
	if got := serviceRestartExitCode(); got != 1 {
		t.Fatalf("invalid restart exit code = %d, want fallback 1", got)
	}
}

func TestScheduledUpdateCanCheckOnly(t *testing.T) {
	autoInstall := false
	cfg, err := scheduledUpdateFromConfig(updateConfig{
		Enabled:     true,
		ManifestURL: "https://updates.example.com/secweaver-agent/stable/update-manifest.json",
		AutoInstall: &autoInstall,
		PublicKey:   base64.StdEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AutoInstall {
		t.Fatal("auto_install should be false")
	}
}

func TestHeartbeatBackoff(t *testing.T) {
	base := 3 * time.Minute
	if got := heartbeatBackoff(base, base); got != 6*time.Minute {
		t.Fatalf("first backoff = %s", got)
	}
	if got := heartbeatBackoff(12*time.Minute, base); got != 15*time.Minute {
		t.Fatalf("capped backoff = %s", got)
	}
	if got := heartbeatBackoff(30*time.Second, base); got != 6*time.Minute {
		t.Fatalf("below-base backoff = %s", got)
	}
}

func TestRemoteConfigRetryDelayIsBounded(t *testing.T) {
	if got := remoteConfigRetryDelay(time.Minute, 15*time.Minute, "device-a"); got < time.Minute || got > 75*time.Second {
		t.Fatalf("initial remote config retry delay = %s", got)
	}
	if got := remoteConfigRetryDelay(15*time.Minute, 15*time.Minute, "device-a"); got != 15*time.Minute {
		t.Fatalf("capped remote config retry delay = %s", got)
	}
}

func TestCheckAgentLicenseUsesFreshCacheDuringTransientOutage(t *testing.T) {
	failClosed := true
	graceSeconds := 86400
	now := time.Now().UTC()
	original := checkAndRegisterAgentLicense
	t.Cleanup(func() { checkAndRegisterAgentLicense = original })
	checkAndRegisterAgentLicense = func(context.Context, agentlicense.Config, string, string) (agentlicense.Result, error) {
		return agentlicense.Result{State: agentlicense.State{
			DeviceID:     "device-123",
			RegisteredAt: now.Add(-time.Hour).Format(time.RFC3339),
			LastCheckAt:  now.Add(-time.Hour).Format(time.RFC3339),
		}}, &agentlicense.HTTPStatusError{Operation: "license server", StatusCode: 503}
	}
	err := checkAgentLicense(context.Background(), agentlicense.Config{
		Enabled: true, FailClosed: &failClosed, OutageGraceSeconds: &graceSeconds,
	}, "6X13NGV4G9CVK92E", nil, nil)
	if err != nil {
		t.Fatalf("fresh cached authorization was not accepted: %v", err)
	}
}

func TestCheckAgentLicenseRejectsExpiredCacheDuringTransientOutage(t *testing.T) {
	failClosed := true
	graceSeconds := 3600
	now := time.Now().UTC()
	original := checkAndRegisterAgentLicense
	t.Cleanup(func() { checkAndRegisterAgentLicense = original })
	checkAndRegisterAgentLicense = func(context.Context, agentlicense.Config, string, string) (agentlicense.Result, error) {
		return agentlicense.Result{State: agentlicense.State{
			DeviceID:     "device-123",
			RegisteredAt: now.Add(-2 * time.Hour).Format(time.RFC3339),
			LastCheckAt:  now.Add(-2 * time.Hour).Format(time.RFC3339),
		}}, &agentlicense.HTTPStatusError{Operation: "license server", StatusCode: 503}
	}
	if err := checkAgentLicense(context.Background(), agentlicense.Config{
		Enabled: true, FailClosed: &failClosed, OutageGraceSeconds: &graceSeconds,
	}, "6X13NGV4G9CVK92E", nil, nil); err == nil {
		t.Fatal("expired cached authorization must fail closed")
	}
}

func TestInitialLicenseRetriesTransientFailureUntilRecovery(t *testing.T) {
	failClosed := true
	original := checkAndRegisterAgentLicense
	t.Cleanup(func() { checkAndRegisterAgentLicense = original })
	attempts := 0
	checkAndRegisterAgentLicense = func(context.Context, agentlicense.Config, string, string) (agentlicense.Result, error) {
		attempts++
		if attempts < 3 {
			return agentlicense.Result{}, &agentlicense.HTTPStatusError{Operation: "license server", StatusCode: 503}
		}
		return agentlicense.Result{State: agentlicense.State{DeviceID: "device-123"}}, nil
	}
	err := waitForInitialAgentLicense(context.Background(), agentlicense.Config{
		Enabled: true, FailClosed: &failClosed,
	}, "6X13NGV4G9CVK92E", nil, nil, time.Millisecond, 2*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if attempts != 3 {
		t.Fatalf("license attempts=%d, want 3", attempts)
	}
}

func TestInitialLicenseDoesNotRetryPermanentDenial(t *testing.T) {
	original := checkAndRegisterAgentLicense
	t.Cleanup(func() { checkAndRegisterAgentLicense = original })
	attempts := 0
	checkAndRegisterAgentLicense = func(context.Context, agentlicense.Config, string, string) (agentlicense.Result, error) {
		attempts++
		return agentlicense.Result{}, agentlicense.DeniedError{Response: agentlicense.Response{Reason: "subscription_expired"}}
	}
	err := waitForInitialAgentLicense(context.Background(), agentlicense.Config{Enabled: true}, "6X13NGV4G9CVK92E", nil, nil, time.Millisecond, time.Millisecond)
	if err == nil {
		t.Fatal("permanent denial must fail startup")
	}
	if attempts != 1 {
		t.Fatalf("permanent denial attempts=%d, want 1", attempts)
	}
}

func TestConfiguredOutputFileCountDeduplicatesPaths(t *testing.T) {
	modules := []runtimeModule{
		{Spec: moduleRegistry["syslog-risk-json"], Config: moduleConfig{Args: []string{"-output", "/logs/shared.log"}}},
		{Spec: moduleRegistry["host-process-snapshot"], Config: moduleConfig{Args: []string{"-output", "/logs/shared.log"}}},
		{Spec: moduleRegistry["host-state-snapshot"], Config: moduleConfig{Args: []string{"-output", "/logs/state.log"}}},
	}
	updater := &scheduledUpdateConfig{StatusOutput: "/logs/update.log"}
	if got := configuredOutputFileCount(modules, updater, nil); got != 3 {
		t.Fatalf("configured output files=%d, want 3", got)
	}
}

func TestCheckAgentLicenseNeverCachesExplicitDenial(t *testing.T) {
	failClosed := true
	graceSeconds := 86400
	now := time.Now().UTC()
	original := checkAndRegisterAgentLicense
	t.Cleanup(func() { checkAndRegisterAgentLicense = original })
	checkAndRegisterAgentLicense = func(context.Context, agentlicense.Config, string, string) (agentlicense.Result, error) {
		response := agentlicense.Response{Allowed: false, Reason: "device_revoked"}
		return agentlicense.Result{Response: response, State: agentlicense.State{
			DeviceID:     "device-123",
			RegisteredAt: now.Format(time.RFC3339),
			LastCheckAt:  now.Format(time.RFC3339),
		}}, agentlicense.DeniedError{Response: response}
	}
	if err := checkAgentLicense(context.Background(), agentlicense.Config{
		Enabled: true, FailClosed: &failClosed, OutageGraceSeconds: &graceSeconds,
	}, "6X13NGV4G9CVK92E", nil, nil); err == nil {
		t.Fatal("explicit authorization denial must fail closed")
	}
}

func TestCachedAuthorizationDoesNotOutliveSubscription(t *testing.T) {
	graceSeconds := 86400
	now := time.Now().UTC()
	state := agentlicense.State{
		DeviceID:              "device-123",
		RegisteredAt:          now.Add(-time.Hour).Format(time.RFC3339),
		LastCheckAt:           now.Add(-time.Hour).Format(time.RFC3339),
		SubscriptionExpiresAt: now.Add(-time.Minute).Format(time.RFC3339),
	}
	if _, ok := cachedAuthorizationGraceRemaining(state, agentlicense.Config{OutageGraceSeconds: &graceSeconds}, now); ok {
		t.Fatal("cached authorization must not outlive the known subscription expiry")
	}
}

func TestVerifyRemoteConfigIntegrityWithSignature(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	configBytes := []byte(`{"enterprise_id":"6X13NGV4G9CVK92E","modules":{"syslog-risk-json":{"enabled":true}}}`)
	resp := agentlicense.RemoteConfigResponse{
		Config:    configBytes,
		SHA256:    sha256Hex(configBytes),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, configBytes)),
	}
	if err := verifyRemoteConfigIntegrity(configBytes, resp, scheduledRemoteConfig{PublicKey: publicKey}); err != nil {
		t.Fatal(err)
	}
}

func TestValidateRemoteAgentConfigRejectsEnterpriseMismatch(t *testing.T) {
	configBytes := []byte(`{"enterprise_id":"AAAAAAAAAAAAAAAA","modules":{"syslog-risk-json":{"enabled":true}}}`)
	err := validateRemoteAgentConfig(configBytes, "6X13NGV4G9CVK92E")
	if err == nil || !strings.Contains(err.Error(), "enterprise_id mismatch") {
		t.Fatalf("expected enterprise mismatch, got %v", err)
	}
}

func TestModuleAuditStreamSpecAuditPortExecmon(t *testing.T) {
	module := runtimeModule{
		Spec: moduleRegistry["audit-port-execmon"],
		Config: moduleConfig{Args: []string{
			"-audit-log", "/tmp/audit.log",
			"-from-start",
		}},
	}
	spec, ok, err := moduleAuditStreamSpec(module)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("audit-port-execmon should use audit stream")
	}
	if spec.Path != "/tmp/audit.log" || !spec.FromStart {
		t.Fatalf("unexpected spec: %+v", spec)
	}
	if !containsString(spec.Keys, "tb_external_listener_exec") || !containsString(spec.Keys, "tb_external_listener_clone") {
		t.Fatalf("unexpected audit keys: %+v", spec.Keys)
	}
}

func TestModuleAuditStreamSpecSkipsAuditPortDryRun(t *testing.T) {
	module := runtimeModule{
		Spec:   moduleRegistry["audit-port-execmon"],
		Config: moduleConfig{Args: []string{"-dry-run"}},
	}
	if _, ok, err := moduleAuditStreamSpec(module); err != nil || ok {
		t.Fatalf("dry-run should not use audit stream: ok=%v err=%v", ok, err)
	}
}

func TestModuleAuditStreamSpecHostPersistenceConfig(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "host-persistence.json")
	body := []byte(`{"audit":{"audit_log":"/tmp/host-audit.log","follow_log":true,"from_start":true}}`)
	if err := os.WriteFile(configPath, body, 0644); err != nil {
		t.Fatal(err)
	}
	module := runtimeModule{
		Spec:   moduleRegistry["host-persistence"],
		Config: moduleConfig{Args: []string{"-config", configPath}},
	}
	spec, ok, err := moduleAuditStreamSpec(module)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("host-persistence should use audit stream")
	}
	if spec.Path != "/tmp/host-audit.log" || !spec.FromStart {
		t.Fatalf("unexpected spec: %+v", spec)
	}
	if len(spec.Keys) != 1 || spec.Keys[0] != "tb_host_persistence" {
		t.Fatalf("unexpected audit keys: %+v", spec.Keys)
	}
}

func TestModuleAuditStreamSpecHostPersistenceFollowLogDisabled(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "host-persistence.json")
	body := []byte(`{"audit":{"follow_log":false}}`)
	if err := os.WriteFile(configPath, body, 0644); err != nil {
		t.Fatal(err)
	}
	module := runtimeModule{
		Spec:   moduleRegistry["host-persistence"],
		Config: moduleConfig{Args: []string{"-config", configPath}},
	}
	if _, ok, err := moduleAuditStreamSpec(module); err != nil || ok {
		t.Fatalf("follow_log=false should not use audit stream: ok=%v err=%v", ok, err)
	}
}

func TestAuditDemuxLineIDAndKey(t *testing.T) {
	id, key := auditDemuxLineIDAndKey(`type=SYSCALL msg=audit(1782320671.957:88922): arch=c000003e syscall=59 key="tb_external_listener_exec"`)
	if id != "88922" || key != "tb_external_listener_exec" {
		t.Fatalf("id/key = %q/%q", id, key)
	}
	id, key = auditDemuxLineIDAndKey(`type=EXECVE msg=audit(1782320671.957:88922): argc=2 a0="ps" a1="-ef"`)
	if id != "88922" || key != "" {
		t.Fatalf("aux id/key = %q/%q", id, key)
	}
	id, key = auditDemuxLineIDAndKey(`type=SYSCALL msg="audit(1782320671.957:88923):" arch=c000003e key=tb_host_persistence`)
	if id != "88923" || key != "tb_host_persistence" {
		t.Fatalf("quoted msg/unquoted key id/key = %q/%q", id, key)
	}
	id, key = auditDemuxLineIDAndKey(`type=SYSCALL msg=audit(1782320671.957:88924): arch=c000003e key=(null)`)
	if id != "88924" || key != "" {
		t.Fatalf("null key id/key = %q/%q", id, key)
	}
}

func TestAuditLineRingKeepsNewestLinesInOrder(t *testing.T) {
	var ring auditLineRing
	for _, line := range []string{"1", "2", "3", "4", "5"} {
		ring.Append(line, 3)
	}
	got := ring.Snapshot()
	if strings.Join(got, ",") != "3,4,5" {
		t.Fatalf("ring snapshot = %#v, want [3 4 5]", got)
	}
}

func TestAuditDemuxBacklogsOnlyRoutedModuleRecords(t *testing.T) {
	demux := &auditDemux{
		subscribers: map[string]*auditSubscriber{},
		moduleKeys: map[string]map[string]bool{
			"audit-port-execmon": {"tb_external_listener_exec": true},
			"host-persistence":   {"tb_host_persistence": true},
		},
		backlogs: map[string]*auditLineRing{
			"audit-port-execmon": {},
			"host-persistence":   {},
		},
		routes: map[string]auditDemuxRoute{},
	}
	demux.broadcast(`type=SYSCALL msg=audit(1.0:10): key="unrelated"`)
	demux.broadcast(`type=EXECVE msg=audit(1.0:10): argc=1 a0="true"`)
	if got := len(demux.backlogs["audit-port-execmon"].Snapshot()); got != 0 {
		t.Fatalf("unrelated lines leaked into audit-port backlog: %d", got)
	}
	if got := len(demux.backlogs["host-persistence"].Snapshot()); got != 0 {
		t.Fatalf("unrelated lines leaked into host-persistence backlog: %d", got)
	}

	demux.broadcast(`type=SYSCALL msg=audit(1.0:11): key="tb_external_listener_exec"`)
	demux.broadcast(`type=EXECVE msg=audit(1.0:11): argc=1 a0="id"`)
	if got := len(demux.backlogs["audit-port-execmon"].Snapshot()); got != 2 {
		t.Fatalf("routed backlog lines = %d, want 2", got)
	}
	if got := len(demux.backlogs["host-persistence"].Snapshot()); got != 0 {
		t.Fatalf("cross-module backlog lines = %d, want 0", got)
	}
}

func TestAuditDemuxRetiresFullSubscriberAndBacklogsFailedLine(t *testing.T) {
	lines := make(chan string, 1)
	lines <- "already queued"
	sub := &auditSubscriber{
		id:     "audit-port-execmon-1",
		module: "audit-port-execmon",
		lines:  lines,
	}
	demux := &auditDemux{
		subscribers: map[string]*auditSubscriber{sub.id: sub},
		moduleKeys: map[string]map[string]bool{
			"audit-port-execmon": {"tb_external_listener_exec": true},
		},
		backlogs: map[string]*auditLineRing{
			"audit-port-execmon": {},
		},
		routes: map[string]auditDemuxRoute{},
	}
	line := `type=SYSCALL msg=audit(1.0:12): key="tb_external_listener_exec"`
	demux.broadcast(line)
	if len(demux.subscribers) != 0 {
		t.Fatal("full subscriber must be retired so its module reconnects")
	}
	got := demux.backlogs["audit-port-execmon"].Snapshot()
	if len(got) != 1 || got[0] != line {
		t.Fatalf("failed line backlog = %#v, want %#v", got, []string{line})
	}
	if queued, ok := <-lines; !ok || queued != "already queued" {
		t.Fatalf("queued line = %q ok=%v", queued, ok)
	}
	if _, ok := <-lines; ok {
		t.Fatal("retired subscriber queue should be closed")
	}
}

func TestAuditDemuxBacklogOverflowIsCountedAndReported(t *testing.T) {
	var notices []auditOverflowNotice
	demux := &auditDemux{
		subscribers: map[string]*auditSubscriber{},
		moduleKeys: map[string]map[string]bool{
			"audit-port-execmon": {"tb_external_listener_exec": true},
		},
		backlogs: map[string]*auditLineRing{
			"audit-port-execmon": {},
		},
		overflows: map[string]uint64{},
		routes:    map[string]auditDemuxRoute{},
		onOverflow: func(notice auditOverflowNotice) {
			notices = append(notices, notice)
		},
	}
	for i := 0; i <= auditDemuxBacklogLines; i++ {
		demux.broadcast(fmt.Sprintf(`type=SYSCALL msg=audit(1.0:%d): key="tb_external_listener_exec"`, i+1))
	}
	snapshot := demux.metricsSnapshot()
	if snapshot.backlogLines != auditDemuxBacklogLines || snapshot.backlogOverflows != 1 {
		t.Fatalf("overflow snapshot = %+v", snapshot)
	}
	if snapshot.linesProcessed != auditDemuxBacklogLines+1 {
		t.Fatalf("processed lines = %d", snapshot.linesProcessed)
	}
	if len(notices) != 1 || notices[0].total != 1 || notices[0].lostAuditID == "" || notices[0].latestAuditID == "" {
		t.Fatalf("overflow notices = %+v", notices)
	}
	retained := demux.backlogs["audit-port-execmon"].Snapshot()
	if strings.Contains(retained[0], "audit(1.0:1)") {
		t.Fatal("oldest line was not overwritten after backlog reached capacity")
	}
}

func TestAuditDemuxOverflowReporterRunsOutsideRoutingPath(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	defer func() {
		cancel()
		<-done
	}()
	reported := make(chan auditOverflowNotice, 1)
	demux := &auditDemux{
		overflowQ: make(chan auditOverflowNotice, 1),
		onOverflow: func(notice auditOverflowNotice) {
			reported <- notice
		},
	}
	go func() {
		defer close(done)
		demux.runOverflowReporter(ctx)
	}()
	want := auditOverflowNotice{module: "audit-port-execmon", total: 1, lostAuditID: "10", latestAuditID: "11"}
	demux.reportOverflowNotices([]auditOverflowNotice{want})
	select {
	case got := <-reported:
		if got != want {
			t.Fatalf("reported notice = %+v, want %+v", got, want)
		}
	case <-time.After(time.Second):
		t.Fatal("overflow reporter did not drain the asynchronous queue")
	}
}

func TestAuditDemuxRegistryMetricsDeduplicatesSharedReader(t *testing.T) {
	demux := &auditDemux{
		backlogs:  map[string]*auditLineRing{"one": {lines: []string{"line"}}},
		overflows: map[string]uint64{"one": 2},
		linesRead: 3,
	}
	registry := &auditDemuxRegistry{byModule: map[string]auditDemuxBinding{
		"audit-port-execmon": {demux: demux},
		"host-persistence":   {demux: demux},
	}}
	snapshot := registry.metricsSnapshot()
	if snapshot.backlogLines != 1 || snapshot.backlogOverflows != 2 || snapshot.linesProcessed != 3 {
		t.Fatalf("deduplicated snapshot = %+v", snapshot)
	}
}

func TestAuditDemuxReaderStatusCountsOutagesAndRecovery(t *testing.T) {
	var notices []auditReaderNotice
	demux := &auditDemux{onReader: func(notice auditReaderNotice) {
		notices = append(notices, notice)
	}}
	demux.observeReaderStatus(nil)
	demux.observeReaderStatus(errors.New("read failed"))
	demux.observeReaderStatus(errors.New("same outage retry"))
	demux.observeReaderStatus(nil)
	snapshot := demux.metricsSnapshot()
	if snapshot.readersReady != 1 || snapshot.readerFailures != 1 {
		t.Fatalf("reader snapshot = %+v", snapshot)
	}
	if len(notices) != 3 || !notices[0].ready || notices[1].ready || !notices[2].ready {
		t.Fatalf("reader transition notices = %+v", notices)
	}
}

func TestAuditDemuxRetriesReaderFailureWithoutClosingSubscribers(t *testing.T) {
	original := followAuditFile
	defer func() { followAuditFile = original }()
	secondAttempt := make(chan struct{})
	attempts := 0
	followAuditFile = func(ctx context.Context, path string, fromStart bool, startOffset int64, handleLine func(string), pollInterval time.Duration, observer func(error)) error {
		attempts++
		if attempts == 1 {
			observer(errors.New("forced reader failure"))
			return errors.New("forced reader failure")
		}
		observer(nil)
		close(secondAttempt)
		<-ctx.Done()
		return ctx.Err()
	}
	demux := &auditDemux{
		key:         auditDemuxKey{Path: filepath.Join(t.TempDir(), "missing-audit.log")},
		subscribers: map[string]*auditSubscriber{},
		routes:      map[string]auditDemuxRoute{},
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		demux.run(ctx)
		close(done)
	}()
	select {
	case <-secondAttempt:
	case <-time.After(2 * time.Second):
		t.Fatal("demux did not retry reader failure")
	}
	cancel()
	<-done
	if attempts != 2 {
		t.Fatalf("reader attempts = %d, want 2", attempts)
	}
}

func TestPreflightReportsModulePlatformMismatch(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("windows event log module matches windows")
	}
	module := runtimeModule{Spec: moduleRegistry["windows-eventlog-risk-json"]}
	report := collectPreflightReport("config.json", []runtimeModule{module}, nil)
	if !preflightHasErrors(report) {
		t.Fatalf("expected platform mismatch error, report=%+v", report)
	}
	if !preflightReportContains(report, preflightError, "module/windows-eventlog-risk-json") {
		t.Fatalf("missing module platform error: %+v", report.Checks)
	}
}

func TestHostPersistenceSupportsLinuxAndWindowsPlatforms(t *testing.T) {
	for _, goos := range []string{"linux", "windows"} {
		if !moduleSupportsPlatform("host-persistence", goos) {
			t.Fatalf("host-persistence should support %s", goos)
		}
	}
	if moduleSupportsPlatform("host-persistence", "darwin") {
		t.Fatal("host-persistence should not report darwin support")
	}
}

func TestHostProcessSnapshotSupportsLinuxAndWindowsPlatforms(t *testing.T) {
	for _, goos := range []string{"linux", "windows"} {
		if !moduleSupportsPlatform("host-process-snapshot", goos) {
			t.Fatalf("host-process-snapshot should support %s", goos)
		}
	}
	if moduleSupportsPlatform("host-process-snapshot", "darwin") {
		t.Fatal("host-process-snapshot should not report darwin support")
	}
}

func TestHostStateSnapshotSupportsLinuxAndWindowsPlatforms(t *testing.T) {
	for _, goos := range []string{"linux", "windows"} {
		if !moduleSupportsPlatform("host-state-snapshot", goos) {
			t.Fatalf("host-state-snapshot should support %s", goos)
		}
	}
	if moduleSupportsPlatform("host-state-snapshot", "darwin") {
		t.Fatal("host-state-snapshot should not report darwin support")
	}
}

func TestWindowsExampleEnablesHostPersistence(t *testing.T) {
	body, err := os.ReadFile("config.windows.example.json")
	if err != nil {
		t.Fatal(err)
	}
	var cfg agentConfig
	if err := json.Unmarshal(body, &cfg); err != nil {
		t.Fatal(err)
	}
	module, ok := cfg.Modules["host-persistence"]
	if !ok {
		t.Fatal("windows config should include host-persistence")
	}
	if module.Enabled == nil || !*module.Enabled {
		t.Fatalf("host-persistence should be enabled by default in windows config: %+v", module)
	}
	configPath, ok := stringFlag(module.Args, "config")
	if !ok || !strings.Contains(configPath, `C:\ProgramData\SecWeaver\Agent\etc\host-persistence.json`) {
		t.Fatalf("unexpected host-persistence config args: %v", module.Args)
	}
}

func TestExamplesEnableHostProcessSnapshotDeltasAndDailyBaseline(t *testing.T) {
	for _, path := range []string{"config.example.json", "config.windows.example.json"} {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var cfg agentConfig
		if err := json.Unmarshal(body, &cfg); err != nil {
			t.Fatal(err)
		}
		module, ok := cfg.Modules["host-process-snapshot"]
		if !ok || module.Enabled == nil || !*module.Enabled {
			t.Fatalf("%s should enable host-process-snapshot: %+v", path, module)
		}
		interval, ok := stringFlag(module.Args, "interval")
		if !ok || interval != "10m" {
			t.Fatalf("%s interval args=%v", path, module.Args)
		}
		if full, ok := stringFlag(module.Args, "full-snapshot-interval"); !ok || full != "24h" {
			t.Fatalf("%s full snapshot args=%v", path, module.Args)
		}
		if state, ok := stringFlag(module.Args, "state"); !ok || state == "" {
			t.Fatalf("%s state args=%v", path, module.Args)
		}
	}
}

func TestExamplesEnableHostStateSnapshot(t *testing.T) {
	for _, path := range []string{"config.example.json", "config.windows.example.json"} {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var cfg agentConfig
		if err := json.Unmarshal(body, &cfg); err != nil {
			t.Fatal(err)
		}
		module := cfg.Modules["host-state-snapshot"]
		if module.Enabled == nil || !*module.Enabled {
			t.Fatalf("%s should enable host-state-snapshot: %+v", path, module)
		}
		if interval, ok := stringFlag(module.Args, "socket-interval"); !ok || interval != "5m" {
			t.Fatalf("%s socket interval args=%v", path, module.Args)
		}
	}
}

func TestWindowsChannelsFromModulesDedupesConfiguredChannels(t *testing.T) {
	modules := []runtimeModule{
		{
			Spec: moduleRegistry["windows-eventlog-risk-json"],
			Config: moduleConfig{Args: []string{
				"-channels", "Security,System,Security",
			}},
		},
		{
			Spec: moduleRegistry["windows-process-execmon"],
			Config: moduleConfig{Args: []string{
				"-channels=Security,Microsoft-Windows-Sysmon/Operational",
			}},
		},
	}
	got := windowsChannelsFromModules(modules)
	want := []string{"Microsoft-Windows-Sysmon/Operational", "Security", "System"}
	if len(got) != len(want) {
		t.Fatalf("channels=%v want=%v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("channels=%v want=%v", got, want)
		}
	}
}

func TestBuildExistingLogArgsUseBackfillAndDisableWindowsCursor(t *testing.T) {
	enabled := true
	cfg := agentConfig{
		Modules: map[string]moduleConfig{
			"syslog-risk-json": {
				Enabled: &enabled,
				Args:    []string{"-secure", "auto", "-output", "/var/log/syslog-risk-json.log"},
			},
			"windows-eventlog-risk-json": {
				Enabled: &enabled,
				Args:    []string{"-channels", "Security", "-state-file", `C:\ProgramData\SecWeaver\windows-eventlog-risk-json.cursor.json`},
			},
		},
	}
	linuxArgs := buildLinuxExistingLogArgs(cfg, 180*24*time.Hour, "/tmp/history.log", "high", true, "", "", true)
	if !hasArg(linuxArgs, "-backfill") || !hasArgValue(linuxArgs, "-lookback", "4320h0m0s") || !hasArgValue(linuxArgs, "-output", "/tmp/history.log") {
		t.Fatalf("unexpected linux backfill args: %v", linuxArgs)
	}
	if !hasArg(linuxArgs, "-raw") || !hasArg(linuxArgs, "-fail-on-read-error") {
		t.Fatalf("missing linux backfill toggles: %v", linuxArgs)
	}

	winArgs := buildWindowsExistingLogArgs(cfg, 180*24*time.Hour, "", "medium", false, "", 1000, false)
	if !hasArg(winArgs, "-once") || !hasArgValue(winArgs, "-lookback", "4320h0m0s") || !hasArgValue(winArgs, "-state-file", "") {
		t.Fatalf("unexpected windows history args: %v", winArgs)
	}
}

func hasArg(args []string, want string) bool {
	for _, arg := range args {
		if arg == want {
			return true
		}
	}
	return false
}

func hasArgValue(args []string, name, want string) bool {
	for i := 0; i < len(args)-1; i++ {
		if args[i] == name && args[i+1] == want {
			return true
		}
	}
	return false
}

func TestAuditCleanupMatchesSecweaverRules(t *testing.T) {
	cases := []string{
		`-a always,exit -F arch=b64 -S execve,execveat -F exe=/usr/sbin/nginx -F key=tb_external_listener_exec`,
		`-a always,exit -F arch=b64 -S execve,execveat -F pid=162106 -F key=tb_external_listener_exec`,
		`-a always,exit -F arch=b64 -S clone,fork,vfork,clone3 -F ppid=162106 -F key=tb_external_listener_clone`,
		`-a always,exit -F arch=b64 -S execve,execveat -F pid=443 -k tb_port_443_exec`,
		`-w /etc/cron.d -p wa -k tb_host_persistence`,
	}
	for _, line := range cases {
		if !auditCleanupLineMatches(line) {
			t.Fatalf("expected cleanup to match %q", line)
		}
	}
}

func TestAuditCleanupIgnoresNonSecweaverRules(t *testing.T) {
	cases := []string{
		`-a always,exit -F arch=b64 -S execve -F key=other_tool_exec`,
		`-w /etc/passwd -p wa -k other_watch`,
		`-a always,exit -F arch=b64 -S execve`,
	}
	for _, line := range cases {
		if auditCleanupLineMatches(line) {
			t.Fatalf("expected cleanup to ignore %q", line)
		}
	}
}

func TestAuditCleanupWatchPath(t *testing.T) {
	fields := strings.Fields(`-w /etc/cron.d -p wa -k tb_host_persistence`)
	if got := auditCleanupWatchPath(fields); got != "/etc/cron.d" {
		t.Fatalf("watch path = %q, want /etc/cron.d", got)
	}
}

func TestDoctorOutputLogPathsFromModuleConfig(t *testing.T) {
	dir := t.TempDir()
	auditCfg := filepath.Join(dir, "audit.json")
	hostCfg := filepath.Join(dir, "host.json")
	if err := os.WriteFile(auditCfg, []byte(`{"output_log":"/tmp/audit-json.log"}`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hostCfg, []byte(`{"output_log":"/tmp/host-json.log"}`), 0644); err != nil {
		t.Fatal(err)
	}
	modules := []runtimeModule{
		{Spec: moduleRegistry["audit-port-execmon"], Config: moduleConfig{Args: []string{"-config", auditCfg}}},
		{Spec: moduleRegistry["host-persistence"], Config: moduleConfig{Args: []string{"-config", hostCfg, "-output", "/tmp/host-flag.log"}}},
		{Spec: moduleRegistry["syslog-risk-json"], Config: moduleConfig{Args: []string{"-output", "/tmp/syslog.log"}}},
		{Spec: moduleRegistry["host-process-snapshot"], Config: moduleConfig{Args: []string{"-output", "/tmp/process.log"}}},
		{Spec: moduleRegistry["host-state-snapshot"], Config: moduleConfig{Args: []string{"-output", "/tmp/state.log"}}},
	}
	got := doctorOutputLogPaths(modules)
	paths := map[string]string{}
	for _, item := range got {
		paths[item.Module] = item.Path
	}
	if paths["audit-port-execmon"] != "/tmp/audit-json.log" {
		t.Fatalf("audit path = %q", paths["audit-port-execmon"])
	}
	if paths["host-persistence"] != "/tmp/host-flag.log" {
		t.Fatalf("host path = %q", paths["host-persistence"])
	}
	if paths["syslog-risk-json"] != "/tmp/syslog.log" {
		t.Fatalf("syslog path = %q", paths["syslog-risk-json"])
	}
	if paths["host-process-snapshot"] != "/tmp/process.log" {
		t.Fatalf("process path = %q", paths["host-process-snapshot"])
	}
	if paths["host-state-snapshot"] != "/tmp/state.log" {
		t.Fatalf("state path = %q", paths["host-state-snapshot"])
	}
}

func TestReadRecentLinesSkipsPartialFirstLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.log")
	body := strings.Join([]string{
		`{"n":1}`,
		`{"n":2}`,
		`{"n":3}`,
	}, "\n") + "\n"
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	got, err := readRecentLines(path, 2, 19)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{`{"n":2}`, `{"n":3}`}
	if len(got) != len(want) {
		t.Fatalf("lines=%v want=%v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("lines=%v want=%v", got, want)
		}
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func preflightReportContains(report preflightReport, level preflightLevel, component string) bool {
	for _, check := range report.Checks {
		if check.Level == level && check.Component == component {
			return true
		}
	}
	return false
}

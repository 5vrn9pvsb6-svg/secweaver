package main

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"secweaver-agent/pkg/agentlicense"
	"secweaver-agent/pkg/agentupdate"
)

func TestApplyUpdatePolicyDefersUnsafeRollouts(t *testing.T) {
	cfg := scheduledUpdateConfig{
		Options:             agentupdate.Options{ManifestURL: "https://updates.example.com/original.json"},
		RequireServerPolicy: true,
		AutoInstall:         true,
	}

	tests := []struct {
		name   string
		policy *agentlicense.UpdatePolicy
		reason string
	}{
		{name: "missing", reason: "server_policy_missing"},
		{name: "disabled", policy: &agentlicense.UpdatePolicy{}, reason: "server_policy_disabled"},
		{name: "paused", policy: &agentlicense.UpdatePolicy{Enabled: true, Paused: true}, reason: "rollout_paused"},
		{name: "outside-window", policy: &agentlicense.UpdatePolicy{Enabled: true, MaintenanceWindowOpen: boolPointer(false)}, reason: "outside_maintenance_window"},
		{name: "no-lease", policy: &agentlicense.UpdatePolicy{Enabled: true, Eligible: true, AutoInstall: true, TargetVersion: "0.3.1", MaintenanceWindowOpen: boolPointer(true), LeaseGranted: boolPointer(false)}, reason: "concurrent_update_limit_reached"},
		{name: "ineligible", policy: &agentlicense.UpdatePolicy{Enabled: true, Eligible: false}, reason: "device_not_in_rollout"},
		{name: "manual", policy: &agentlicense.UpdatePolicy{Enabled: true, Eligible: true}, reason: "automatic_install_disabled"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, allowed, status := applyUpdatePolicy(cfg, test.policy)
			if allowed || status.Status != "policy_deferred" || status.Reason != test.reason {
				t.Fatalf("unexpected policy result: allowed=%v status=%+v", allowed, status)
			}
		})
	}
}

func TestBindUpdateRuntimeUsesImmutableEnrolledDeviceID(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "license-state.json")
	if err := agentlicense.SaveState(statePath, agentlicense.State{DeviceID: "swdev_immutable_123"}); err != nil {
		t.Fatal(err)
	}
	updater := &scheduledUpdateConfig{
		Options:             agentupdate.Options{HostID: "mutable-hostname"},
		RequireServerPolicy: true,
	}
	licenseCfg := agentlicense.Config{
		Enabled:          true,
		Protocol:         "device_v2",
		HeartbeatSeconds: 180,
		StatePath:        statePath,
	}
	if err := bindUpdateRuntimeToDevice(updater, licenseCfg); err != nil {
		t.Fatal(err)
	}
	if updater.Options.DeviceID != "swdev_immutable_123" || updater.Options.HostID != "swdev_immutable_123" {
		t.Fatalf("rollout identity was not rebound to immutable device ID: %+v", updater.Options)
	}
}

func TestManagedUpdateRejectsMissingDeviceID(t *testing.T) {
	updater := &scheduledUpdateConfig{RequireServerPolicy: true}
	licenseCfg := agentlicense.Config{
		Enabled:          true,
		Protocol:         "device_v2",
		HeartbeatSeconds: 180,
		StatePath:        filepath.Join(t.TempDir(), "missing-state.json"),
	}
	if err := bindUpdateRuntimeToDevice(updater, licenseCfg); err == nil {
		t.Fatal("expected managed update without enrollment device ID to fail closed")
	}
}

func TestApplyUpdatePolicyPinsServerTarget(t *testing.T) {
	cfg := scheduledUpdateConfig{
		Options: agentupdate.Options{
			ManifestURL: "https://updates.example.com/original.json",
			Channel:     "stable",
		},
		RequireServerPolicy: true,
		AutoInstall:         true,
	}
	policy := &agentlicense.UpdatePolicy{
		Enabled:        true,
		Eligible:       true,
		AutoInstall:    true,
		TargetVersion:  "0.3.1",
		Channel:        "canary",
		ManifestURL:    "https://updates.example.com/canary/update-manifest.json",
		LeaseGranted:   boolPointer(true),
		LeaseExpiresAt: time.Now().Add(10 * time.Minute).Format(time.RFC3339),
	}

	effective, allowed, _ := applyUpdatePolicy(cfg, policy)
	if !allowed {
		t.Fatal("expected eligible signed rollout to be allowed")
	}
	if effective.Options.DesiredVersion != "0.3.1" || effective.Options.Channel != "canary" {
		t.Fatalf("server target was not applied: %+v", effective.Options)
	}
	if effective.Options.ManifestURL != policy.ManifestURL {
		t.Fatalf("manifest URL was not applied: got %q want %q", effective.Options.ManifestURL, policy.ManifestURL)
	}
	if !effective.Options.ServerManaged {
		t.Fatal("server-approved update did not disable the manifest rollout authority")
	}
}

func TestApplyUpdatePolicyRequiresFreshLease(t *testing.T) {
	cfg := scheduledUpdateConfig{
		Options:             agentupdate.Options{ManifestURL: "https://updates.example.com/original.json"},
		RequireServerPolicy: true,
		AutoInstall:         true,
	}
	base := agentlicense.UpdatePolicy{
		Enabled:       true,
		Eligible:      true,
		AutoInstall:   true,
		TargetVersion: "0.3.1",
		LeaseGranted:  boolPointer(true),
	}
	tests := []struct {
		name   string
		expiry string
		reason string
	}{
		{name: "missing", reason: "server_policy_missing_lease_expiry"},
		{name: "invalid", expiry: "not-a-time", reason: "server_policy_invalid_lease_expiry"},
		{name: "expired", expiry: time.Now().Add(-time.Minute).Format(time.RFC3339), reason: "server_policy_lease_expiring"},
		{name: "too-close", expiry: time.Now().Add(time.Minute).Format(time.RFC3339), reason: "server_policy_lease_expiring"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy := base
			policy.LeaseExpiresAt = test.expiry
			_, allowed, status := applyUpdatePolicy(cfg, &policy)
			if allowed || status.Reason != test.reason {
				t.Fatalf("allowed=%v status=%+v", allowed, status)
			}
		})
	}
}

func TestScheduledUpdateRetryDelayBacksOffAndHonorsServerDelay(t *testing.T) {
	cfg := scheduledUpdateConfig{
		Options:      agentupdate.Options{DeviceID: "swd_retry_test"},
		RetryInitial: time.Minute,
		RetryMax:     10 * time.Minute,
	}
	first := scheduledUpdateRetryDelay(cfg, 1, errors.New("network failure"))
	if first < time.Minute || first > 75*time.Second {
		t.Fatalf("first retry delay = %s", first)
	}
	if capped := scheduledUpdateRetryDelay(cfg, 10, errors.New("network failure")); capped != 10*time.Minute {
		t.Fatalf("capped retry delay = %s", capped)
	}
	serverDelay := &agentupdate.HTTPStatusError{RetryDelay: 7 * time.Minute}
	if got := scheduledUpdateRetryDelay(cfg, 2, serverDelay); got < 7*time.Minute || got > 10*time.Minute {
		t.Fatalf("Retry-After delay = %s", got)
	}
}

func TestManagedInstallCommitGateFencesPolicyRevocation(t *testing.T) {
	gate := &managedInstallCommitGate{}
	if !gate.revoke("campaign paused") {
		t.Fatal("revocation before commit should close the gate")
	}
	if err := gate.begin(context.Background()); err == nil {
		t.Fatal("revoked gate allowed commit")
	}

	gate = &managedInstallCommitGate{}
	if err := gate.begin(context.Background()); err != nil {
		t.Fatal(err)
	}
	if gate.revoke("late pause") {
		t.Fatal("revocation after the commit boundary must not interrupt the local transaction")
	}
}

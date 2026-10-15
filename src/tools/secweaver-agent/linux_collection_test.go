package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"secweaver-agent/pkg/auditportexecmon"
)

func TestCollectionProfileRemovesAllAuditInputsWithoutChangingConfig(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "persistence.json")
	body := []byte(`{"audit":{"enabled":true,"manage_rules":true,"follow_log":true}}`)
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	modules := []runtimeModule{
		{Spec: moduleRegistry["audit-port-execmon"], Config: moduleConfig{Args: []string{"-collection-mode", "auto"}}},
		{Spec: moduleRegistry["host-persistence"], Config: moduleConfig{Args: []string{"-config", path, "-audit=true"}}},
	}
	prepared := modulesForCollectionProfile(modules, auditportexecmon.CollectionProfile{Mode: "ebpf_only"})
	for _, module := range prepared {
		if _, subscribed, err := module.Spec.AuditSubscription(module.Config.Args); err != nil || subscribed {
			t.Fatalf("module=%s subscribed=%v err=%v", module.Spec.Name, subscribed, err)
		}
	}
	if !reflect.DeepEqual(modules[0].Config.Args, []string{"-collection-mode", "auto"}) || modules[1].Config.Args[2] != "-audit=true" {
		t.Fatal("runtime preparation mutated configuration slices")
	}
	if actual, err := os.ReadFile(path); err != nil || string(actual) != string(body) {
		t.Fatalf("persistence policy was rewritten: %s, err=%v", actual, err)
	}
}

func TestAuditModeConfigPreservesLearningAndExplicitPolicy(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		wantError  bool
	}{
		{"legacy", `{"exec":{"process_tree_backend":"auto"},"behavior_learning":{"enabled":true,"generation":7}}`, false},
		{"null-audit", `{"audit":null,"behavior_learning":{"generation":7}}`, false},
		{"explicit-audit", `{"audit":{"mode":"audit"},"behavior_learning":{"generation":7}}`, true},
		{"explicit-backend", `{"exec":{"process_tree_backend":"audit_pid"},"behavior_learning":{"generation":7}}`, true},
		{"invalid-mode", `{"audit":{"mode":"invalid"},"behavior_learning":{"generation":7}}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "audit.json")
			if err := os.WriteFile(path, []byte(tc.body), 0600); err != nil {
				t.Fatal(err)
			}
			changed, _, err := setAuditModeInModuleConfig(path, "ebpf_only", true)
			if (err != nil) != tc.wantError {
				t.Fatalf("changed=%v err=%v", changed, err)
			}
			actual, readErr := os.ReadFile(path)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if tc.wantError {
				if string(actual) != tc.body {
					t.Fatal("failed mode change altered user policy")
				}
				return
			}
			var before, after map[string]any
			if err := json.Unmarshal([]byte(tc.body), &before); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(actual, &after); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(before["behavior_learning"], after["behavior_learning"]) || !reflect.DeepEqual(before["exec"], after["exec"]) {
				t.Fatal("mode change modified learning or process policy")
			}
			if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0600 {
				t.Fatalf("config permissions changed: info=%v err=%v", info, err)
			}
			if changed, _, err := setAuditModeInModuleConfig(path, "ebpf_only", true); err != nil || changed {
				t.Fatalf("repeat mode change is not idempotent: changed=%v err=%v", changed, err)
			}
		})
	}
}

func TestOverrideModuleFlagPreservesOtherFlagValues(t *testing.T) {
	module := runtimeModule{Spec: moduleRegistry["audit-port-execmon"], Config: moduleConfig{Args: []string{
		"-config", "-collection-mode", "-collection-mode=auto", "--collection-mode", "audit", "--", "positional",
	}}}
	want := []string{"-config", "-collection-mode", "-collection-mode=ebpf_only", "--", "positional"}
	if got := overrideModuleFlag(module, "collection-mode", "ebpf_only"); !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%q want=%q", got, want)
	}
}

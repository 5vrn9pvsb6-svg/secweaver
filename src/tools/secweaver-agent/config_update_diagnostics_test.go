package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// This is the actual flag order emitted by the installers. Previously the
// boolean's separate 'true' token silently discarded both CA and signing key.
func TestInstallerUpdateFlagsConsumeTrustAndRejectTrailingArguments(t *testing.T) {
	for _, splitBoolean := range []bool{false, true} {
		path := filepath.Join(t.TempDir(), "config.json")
		original, err := os.ReadFile("config.example.json")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, original, 0600); err != nil {
			t.Fatal(err)
		}
		args := []string{"set-update", "-config", path, "-manifest-url", "https://gateway.example.net/manifest.json"}
		if splitBoolean {
			args = append(args, "-auto-install", "true")
		} else {
			args = append(args, "-auto-install=true")
		}
		key := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
		args = append(args, "-require-server-policy=true", "-public-key", key, "-use-system-ca")
		code := runConfigCommand(args)
		body, _ := os.ReadFile(path)
		if splitBoolean {
			if code != 2 || !bytes.Equal(body, original) {
				t.Fatal("invalid flag sequence did not fail without mutation")
			}
			continue
		}
		var cfg agentConfig
		if err := json.Unmarshal(body, &cfg); err != nil {
			t.Fatal(err)
		}
		if code != 0 || cfg.Update.PublicKey != key || cfg.Update.CAFile != "" || cfg.Update.StatusOutput == "" {
			t.Fatalf("trust/output not provisioned: code=%d update=%+v", code, cfg.Update)
		}
	}
}

func TestUpdateCARequiresExplicitClearAndChecksBeforeWriting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	body := []byte(`{"enterprise_id":"TESTENTERPRISE01","modules":{"host-process-snapshot":{"enabled":true}},"update":{"ca_file":"/missing/secweaver-ca.crt"}}`)
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"set-update", "-config", path, "-manifest-url", "https://gateway.example.net/manifest.json", "-public-key", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}
	if code := runConfigCommand(args); code != 1 {
		t.Fatalf("missing CA accepted: %d", code)
	}
	got, _ := os.ReadFile(path)
	if !bytes.Equal(got, body) {
		t.Fatal("failed check modified config")
	}
	if code := runConfigCommand(append(args, "-use-system-ca")); code != 0 {
		t.Fatalf("explicit system CA failed: %d", code)
	}
	cfg, err := loadConfig(path)
	if err != nil || cfg.Update.CAFile != "" {
		t.Fatalf("CA was not cleared: %+v %v", cfg.Update, err)
	}
}

func TestManagedUpdateTrustAndDoctorDiagnostics(t *testing.T) {
	updater, err := scheduledUpdateFromConfig(updateConfig{Enabled: true, ManifestURL: "https://gateway.example.net/manifest.json", RequireServerPolicy: true, CAFile: filepath.Join(t.TempDir(), "missing.crt"), StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	} // Runtime creation cannot stop collection for a missing CA.
	errors := map[string]bool{}
	checkScheduledUpdate(updater, func(level preflightLevel, component, _, _ string) {
		if level == preflightError {
			errors[component] = true
		}
	})
	if !errors["update/ca"] || !errors["update/trust"] {
		t.Fatalf("missing doctor diagnostics: %v", errors)
	}
}

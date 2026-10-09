package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"secweaver-agent/pkg/agentupdate"
)

// Exercise the CLI used by both installers: omitted trust flags must not undo
// operator provisioning or signed key rotation when connection settings change.
func TestSetUpdateCommandPreservesExistingTrust(t *testing.T) {
	primary := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	rotated := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	primaryText := base64.StdEncoding.EncodeToString(primary)
	rotatedText := base64.StdEncoding.EncodeToString(rotated)
	for _, tc := range []struct {
		name    string
		args    []string
		wantKey string
		enabled bool
	}{
		{"omitted_key", nil, primaryText, true},
		{"explicit_replacement", []string{"-public-key", rotatedText}, rotatedText, true},
		{"disable_preserves_trust", []string{"-enabled=false"}, primaryText, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "config.json")
			previous := updateConfig{
				Enabled:           true,
				ManifestURL:       "https://old.example.com/manifest.json",
				PublicKey:         primaryText,
				TrustedPublicKeys: map[string]string{agentupdate.PublicKeyID(rotated): rotatedText},
				RevokedKeyIDs:     []string{agentupdate.PublicKeyID(primary)},
				StateDir:          filepath.Join(dir, "operator-update-state"),
				CAFile:            filepath.Join(dir, "operator-ca.crt"),
			}
			body, err := json.Marshal(agentConfig{
				EnterpriseID: "TESTENTERPRISE01",
				Modules:      map[string]moduleConfig{"host-process-snapshot": {Enabled: boolPointer(true)}},
				Update:       previous,
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, body, 0600); err != nil {
				t.Fatal(err)
			}
			before, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			args := []string{"set-update", "-config", path, "-manifest-url", "https://new.example.com/manifest.json", "-device-id", "test-device"}
			if code := runConfigCommand(append(args, tc.args...)); code != 0 {
				t.Fatalf("config set-update exit code = %d", code)
			}
			cfg, err := loadConfig(path)
			if err != nil {
				t.Fatal(err)
			}
			got := cfg.Update
			if got.PublicKey != tc.wantKey || !reflect.DeepEqual(got.TrustedPublicKeys, previous.TrustedPublicKeys) || !reflect.DeepEqual(got.RevokedKeyIDs, previous.RevokedKeyIDs) {
				t.Fatalf("installer lost update trust: %+v", got)
			}
			if got.StateDir != previous.StateDir || got.CAFile != previous.CAFile {
				t.Fatalf("installer lost trust store or TLS CA location: %+v", got)
			}
			if got.Enabled != tc.enabled || got.ManifestURL != "https://new.example.com/manifest.json" || got.DeviceID != "test-device" {
				t.Fatalf("requested settings were not applied: %+v", got)
			}
			// Compare native permissions: Windows does not report Unix 0600 bits.
			if info, err := os.Stat(path); err != nil || info.Mode().Perm() != before.Mode().Perm() {
				t.Fatalf("config permissions changed: info=%v err=%v", info, err)
			}
		})
	}
}

// Invalid existing trust requires operator repair; an installer must not silently
// replace it with an empty trust set and report a successful configuration write.
func TestSetUpdateInConfigRejectsInvalidExistingTrustWithoutWriting(t *testing.T) {
	for _, previous := range []string{
		`{"public_key":"invalid-key"}`,
		`{"trusted_public_keys":{"invalid-id":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}}`,
		`{"revoked_key_ids":"invalid-list"}`,
	} {
		t.Run(previous, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			body := []byte(`{"enterprise_id":"TESTENTERPRISE01","modules":{"host-process-snapshot":{"enabled":true}},"update":` + previous + `}`)
			if err := os.WriteFile(path, body, 0600); err != nil {
				t.Fatal(err)
			}
			if err := setUpdateInConfig(path, updateConfig{Enabled: true, ManifestURL: "https://updates.example.com/manifest.json"}); err == nil {
				t.Fatal("invalid trust was silently discarded")
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, body) {
				t.Fatal("failed configuration update changed the file")
			}
		})
	}
}

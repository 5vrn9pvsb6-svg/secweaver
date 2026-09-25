package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Fixtures are rooted under a private directory so another application's
// system-wide collector can never influence migration or conflict decisions.
func TestDeploymentModeMigrationAndConflict(t *testing.T) {
	for _, tc := range []struct {
		name, marker, shipper, requested, want string
		conflict                               bool
	}{
		{"fresh", "", "", deploymentSLS, deploymentSLS, false},
		{"legacy-sls", "logtail", "", "", deploymentSLS, false},
		{"legacy-es", "", "filebeat.yml", "", deploymentES, false},
		{"sls-to-es", "logtail", "", deploymentES, "", true},
		{"es-to-sls", "", "shipper.json", deploymentSLS, "", true},
		{"ambiguous", "logtail", "fluent-bit.conf", deploymentSLS, "", true},
		{"unspecified", "", "", "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			dir := filepath.Join(root, "etc")
			if err := os.MkdirAll(dir, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "config.json")
			original := []byte(`{"modules":{},"license":{"server_url":"https://example.test"}}`)
			if err := os.WriteFile(path, original, 0600); err != nil {
				t.Fatal(err)
			}
			if tc.marker != "" {
				if err := os.WriteFile(filepath.Join(dir, "shipper-kind"), []byte(tc.marker), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if tc.shipper != "" {
				if err := os.MkdirAll(filepath.Join(root, "shipper"), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(root, "shipper", tc.shipper), []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			_, err := configureDeploymentMode(path, tc.requested, true)
			if (err != nil) != tc.conflict {
				t.Fatalf("check: %v", err)
			}
			body, _ := os.ReadFile(path)
			if !bytes.Equal(body, original) {
				t.Fatal("check-only modified configuration")
			}
			got, err := configureDeploymentMode(path, tc.requested, false)
			if (err != nil) != tc.conflict || got != tc.want {
				t.Fatalf("mode=%q err=%v", got, err)
			}
			body, _ = os.ReadFile(path)
			if tc.conflict && !bytes.Equal(body, original) {
				t.Fatal("conflict modified configuration")
			}
			if !tc.conflict && tc.want != "" {
				if got, err := configureDeploymentMode(path, "", false); err != nil || got != tc.want {
					t.Fatalf("upgrade lost mode: %q %v", got, err)
				}
				other := deploymentSLS
				if tc.want == other {
					other = deploymentES
				}
				if _, err := configureDeploymentMode(path, other, false); err == nil {
					t.Fatal("explicit mode overwritten")
				}
			}
		})
	}
}

func TestDeploymentModeRemotePolicy(t *testing.T) {
	for _, tc := range []struct {
		current, next, want string
		reject              bool
	}{
		{`{"deployment_mode":"sls_saas"}`, `{"modules":{}}`, deploymentSLS, false},
		{`{"deployment_mode":"es_private"}`, `{"deployment_mode":"es_private"}`, deploymentES, false},
		{`{"deployment_mode":"es_private"}`, `{"deployment_mode":"sls_saas"}`, "", true},
		{`{}`, `{"deployment_mode":"sls_saas"}`, "", true},
		{`{}`, `{}`, "", false},
		{`{"deployment_mode":"es_private"}`, `null`, "", true},
	} {
		body, err := preserveDeploymentMode([]byte(tc.current), []byte(tc.next))
		if (err != nil) != tc.reject {
			t.Fatalf("policy err=%v", err)
		}
		if !tc.reject {
			var cfg agentConfig
			if err := json.Unmarshal(body, &cfg); err != nil {
				t.Fatal(err)
			}
			if cfg.DeploymentMode != tc.want {
				t.Fatalf("lost local ownership: %s", body)
			}
		}
	}
}

func TestDeploymentModeMissingConfigCheckAndInvalidMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if _, err := configureDeploymentMode(path, deploymentES, true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("check created configuration")
	}
	if _, err := configureDeploymentMode(path, "typo", true); err == nil {
		t.Fatal("invalid mode accepted")
	}
}

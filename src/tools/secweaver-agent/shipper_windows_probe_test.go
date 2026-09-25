package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"secweaver-agent/pkg/windowscollection"
)

// Synthetic CIM responses are paired with real signed files and vendor caches.
// A healthy service without delivery rules must never pass local readiness.
func TestWindowsLogtailRuntime(t *testing.T) {
	for _, scenario := range []string{"running", "stopped", "no-worker", "multiple-workers", "missing", "CIM-denied", "invalid-JSON", "no-contract", "wrong-identity", "missing-rule", "wrong-target"} {
		t.Run(scenario, func(t *testing.T) {
			root := t.TempDir()
			write := func(path string, b []byte) {
				t.Helper()
				if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, b, 0600); err != nil {
					t.Fatal(err)
				}
			}
			manifest := windowscollection.Manifest{Version: 1, AliUID: "123456", MachineGroup: "test-windows", Project: "host-project", Region: "cn-hangzhou", LogPath: "C:\\Agent\\logs"}
			rules := map[string]any{}
			for _, f := range windowscollection.Files {
				manifest.Routes = append(manifest.Routes, windowscollection.Route{File: f, Logstore: "host-logs", ConfigName: f[:len(f)-4]})
				rules[f] = map[string]any{"log_path": manifest.LogPath, "file_pattern": f + "*", "project_name": manifest.Project, "category": "host-logs", "log_type": "json_log"}
			}
			raw, _ := json.Marshal(manifest)
			pub, key, _ := ed25519.GenerateKey(rand.Reader)
			envelope, _ := json.Marshal(struct {
				Manifest  json.RawMessage `json:"manifest"`
				Signature string          `json:"signature"`
			}{raw, base64.StdEncoding.EncodeToString(ed25519.Sign(key, raw))})
			write(filepath.Join(root, "windows-collection.json"), envelope)
			write(filepath.Join(root, "windows-collection.pub"), []byte(base64.StdEncoding.EncodeToString(pub)))
			write(filepath.Join(root, "users", "123456"), nil)
			write(filepath.Join(root, "user_defined_id"), []byte("test-windows\r\nother-app\r\n"))
			if scenario == "wrong-identity" {
				write(filepath.Join(root, "user_defined_id"), []byte("other-app"))
			}
			if scenario == "no-contract" {
				os.Remove(filepath.Join(root, "windows-collection.json"))
			}
			if scenario == "missing-rule" {
				delete(rules, windowscollection.Files[0])
			}
			if scenario == "wrong-target" {
				rules[windowscollection.Files[0]].(map[string]any)["category"] = "wrong"
			}
			cache := filepath.Join(root, "user_log_config.json")
			b, _ := json.Marshal(map[string]any{"log_config": rules})
			write(cache, b)
			reply := map[string]any{"installed": true, "state": "Running", "service_pid": 42, "workers": 1, "user_config_path": cache}
			switch scenario {
			case "stopped":
				reply["state"] = "Stopped"
				reply["service_pid"] = 0
				reply["workers"] = 0
			case "missing":
				reply["installed"] = false
				reply["workers"] = 0
			case "no-worker":
				reply["workers"] = 0
			case "multiple-workers":
				reply["workers"] = 2
			}
			s := probeWindowsLogtail(root, true, root, func(timeout time.Duration, command string, args ...string) ([]byte, error) {
				if timeout > 10*time.Second || command != "powershell.exe" {
					t.Fatal("unexpected probe")
				}
				if scenario == "CIM-denied" {
					return nil, errors.New("denied")
				}
				if scenario == "invalid-JSON" {
					return []byte("{"), nil
				}
				return json.Marshal(reply)
			})
			if s.CloudDelivery != "unverified" || s.Type != "logtail" {
				t.Fatalf("invented receipt: %+v", s)
			}
			if shipperLocallyBroken(s) != (scenario != "running") {
				t.Fatalf("scenario %s: %+v", scenario, s)
			}
			if scenario == "running" && (s.Configuration != "configured" || s.ConfigPath != cache) {
				t.Fatalf("%+v", s)
			}
			if scenario == "missing-rule" && len(s.MissingPaths) != 1 {
				t.Fatalf("missing route not exposed: %+v", s)
			}
		})
	}
}

func TestWindowsLogtailIntent(t *testing.T) {
	root := filepath.Join(t.TempDir(), "missing")
	run := func(time.Duration, string, ...string) ([]byte, error) { return []byte("{\"installed\":false}"), nil }
	if s := probeWindowsLogtail(root, false, root, run); s.Type != "unknown" {
		t.Fatal(s)
	}
	if s := probeWindowsLogtail(root, true, root, run); !shipperLocallyBroken(s) {
		t.Fatal(s)
	}
}

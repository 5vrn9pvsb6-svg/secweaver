package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Fixtures reproduce the vendor oneshot service without invoking host services.
func TestLogtailStatusSeparatesProcessAndCloudEvidence(t *testing.T) {
	for _, scenario := range []string{"healthy", "oneshot-dead", "inactive", "probe-error", "missing-identity", "expected-missing", "not-configured"} {
		t.Run(scenario, func(t *testing.T) {
			root := t.TempDir()
			config, binary, initDir := filepath.Join(root, "etc"), filepath.Join(root, "bin"), filepath.Join(root, "init")
			if scenario != "expected-missing" && scenario != "not-configured" {
				for _, p := range []string{filepath.Join(config, "users"), binary, initDir} {
					if err := os.MkdirAll(p, 0755); err != nil {
						t.Fatal(err)
					}
				}
				for p, body := range map[string]string{filepath.Join(config, "users", "1234"): "", filepath.Join(config, "user_defined_id"): "test-group", filepath.Join(initDir, "ilogtaild"): "#!/bin/sh\n"} {
					if err := os.WriteFile(p, []byte(body), 0755); err != nil {
						t.Fatal(err)
					}
				}
				if scenario == "missing-identity" {
					if err := os.Remove(filepath.Join(config, "user_defined_id")); err != nil {
						t.Fatal(err)
					}
				}
			}
			calls := 0
			run := func(limit time.Duration, name string, args ...string) ([]byte, error) {
				calls++
				if limit <= 0 || limit > 5*time.Second {
					t.Fatal("unbounded probe")
				}
				joined := strings.Join(args, " ")
				if strings.Contains(joined, "--value") {
					t.Fatal("systemd 219 incompatible flag")
				}
				if scenario == "probe-error" {
					return nil, errors.New("timeout")
				}
				if strings.Contains(joined, "loongcollectord") {
					return []byte("LoadState=not-found"), nil
				}
				if name == "systemctl" && args[0] == "show" {
					return []byte("LoadState=loaded\n"), nil
				}
				if name == "systemctl" {
					if scenario == "inactive" {
						return []byte("inactive"), errors.New("inactive")
					}
					return []byte("active"), nil
				}
				if scenario == "oneshot-dead" {
					return nil, errors.New("no daemon")
				}
				return nil, nil
			}
			s := probeLogtail(config, binary, initDir, scenario != "not-configured", run)
			if s.CloudDelivery != "unverified" || s.CheckedAt == "" {
				t.Fatalf("invented cloud proof: %+v", s)
			}
			if calls > 4 {
				t.Fatalf("too many subprocesses: %d", calls)
			}
			broken := scenario != "healthy" && scenario != "not-configured"
			if shipperLocallyBroken(s) != broken {
				t.Fatalf("scenario=%s status=%+v", scenario, s)
			}
			if scenario == "oneshot-dead" && (s.ServiceStatus != "active" || s.ProcessStatus != "unhealthy") {
				t.Fatal(s)
			}
			if scenario == "not-configured" && (s.Type != "unknown" || calls != 0) {
				t.Fatal(s)
			}
		})
	}
}

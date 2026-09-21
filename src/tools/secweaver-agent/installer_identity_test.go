package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Exercise the actual installer in a disposable layout. Only the Agent binary
// and host service probes are fixtures; no host services or package manager run.
func TestLinuxInstallerEnrollmentUpdateIdentity(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash required")
	}
	device := "swd_" + strings.Repeat("a", 52)
	for _, scenario := range []string{"token-only", "matching", "conflicting", "malformed", "enroll-failed", "legacy"} {
		t.Run(scenario, func(t *testing.T) {
			root := t.TempDir()
			pkg := filepath.Join(root, "package")
			installed := filepath.Join(root, "installed")
			write := func(name, body string, mode os.FileMode) {
				t.Helper()
				p := filepath.Join(root, name)
				if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, []byte(body), mode); err != nil {
					t.Fatal(err)
				}
			}
			body, err := os.ReadFile("packaging/install.sh")
			if err != nil {
				t.Fatal(err)
			}
			write("package/install.sh", string(body), 0755)
			write("package/bin/secweaver-agent", `#!/usr/bin/env bash
set -euo pipefail
if [[ "$1" == enroll ]]; then
  [[ "$*" == *'-output installer'* ]]
  [[ "$SCENARIO" != enroll-failed ]] || exit 1
  if [[ "$SCENARIO" == malformed ]]; then printf 'ABCD1234EFGH5678\textra\n'; else printf 'ABCD1234EFGH5678\t%s\n' "$DEVICE"; fi
elif [[ "$*" == 'config set-update'* ]]; then
  [[ "$*" == *"-device-id $DEVICE"* ]]
  touch "$MARKER"
elif [[ "$*" == 'config set-license'* && "$SCENARIO" != legacy ]]; then
  [[ "$*" == *"-state-path $STATE_DIR/license-state.json"* ]]
  [[ "$*" == *"-identity-key-path $STATE_DIR/device-ed25519.key"* ]]
fi
`, 0755)
			for _, p := range []string{"config.example.json", "audit-port-execmon.example.json", "host-persistence.example.json"} {
				write("package/etc/secweaver-agent/"+p, "{}", 0600)
			}
			write("installed/etc/config.json", "{}", 0600)
			write("installed/data/preserved", "identity", 0600)
			write("package/libexec/secweaver-agent-launch", "#!/bin/sh\n", 0755)
			write("stubs/systemctl", "#!/bin/sh\nexit 1\n", 0755)
			write("stubs/pgrep", "#!/bin/sh\nexit 1\n", 0755)
			args := []string{filepath.Join(pkg, "install.sh"), "--license-server-url", "https://gateway.example.com", "--update-manifest-url", "https://gateway.example.com/manifest.json", "--update-public-key", strings.Repeat("A", 43) + "="}
			if scenario == "legacy" {
				args = append(args, "--enterprise-id", "ABCD1234EFGH5678", "--license-enrollment-id", "legacy", "--update-device-id", device)
			} else {
				args = append(args, "--enterprise-enrollment-token", "swenr_test."+strings.Repeat("A", 43))
			}
			if scenario == "matching" {
				args = append(args, "--update-device-id", device)
			}
			if scenario == "conflicting" {
				args = append(args, "--update-device-id", "wrong")
			}
			cmd := exec.Command("bash", args...)
			marker := filepath.Join(root, "updated")
			cmd.Env = append(os.Environ(), "PATH="+filepath.Join(root, "stubs")+":"+os.Getenv("PATH"), "INSTALL_ROOT="+installed, "STATE_DIR="+filepath.Join(installed, "data"), "COMMAND_LINK="+filepath.Join(root, "command/agent"), "SYSTEMD_DIR="+filepath.Join(root, "no-systemd"), "INSTALL_DEPS=0", "REQUIRE_SYSTEMD=0", "DEVICE="+device, "SCENARIO="+scenario, "MARKER="+marker)
			out, err := cmd.CombinedOutput()
			success := scenario == "token-only" || scenario == "matching" || scenario == "legacy"
			if (err == nil) != success {
				t.Fatalf("installer result: %v\n%s", err, out)
			}
			_, statErr := os.Stat(marker)
			if (statErr == nil) != success {
				t.Fatal("unexpected update configuration mutation")
			}
		})
	}
}

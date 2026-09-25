package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Execute production network helpers with deterministic transports. No fixture
// accesses the network, installs services, or waits for a real 600s deadline.
func TestBootstrapNetworkBudgetsAndRegionPreservation(t *testing.T) {
	body, err := os.ReadFile("packaging/bootstrap-install.sh")
	if err != nil {
		t.Fatal(err)
	}
	start := strings.Index(string(body), "download_host() {")
	end := strings.Index(string(body), "\nsha256_file() {")
	if start < 0 || end < start {
		t.Fatal("network helpers not found")
	}
	helpers := string(body)[start:end]
	for _, scenario := range []string{"public", "internal", "other-region", "vendor-wget", "download-failure", "vendor-failure", "installer-timeout", "wget-fallback"} {
		t.Run(scenario, func(t *testing.T) {
			root := t.TempDir()
			bin := filepath.Join(root, "bin")
			if err := os.MkdirAll(bin, 0755); err != nil {
				t.Fatal(err)
			}
			trace := filepath.Join(root, "trace")
			vendor := filepath.Join(root, "vendor.sh")
			write := func(path, body string) {
				t.Helper()
				if err := os.WriteFile(path, []byte("#!/usr/bin/env bash\nset -euo pipefail\n"+body), 0755); err != nil {
					t.Fatal(err)
				}
			}
			write(filepath.Join(bin, "timeout"), `printf 'timeout:%s\n' "$*" >> "$TRACE"
[[ "$1" == --kill-after=10 ]] || exit 91
shift
if [[ "$1" == 600 && "$SCENARIO" == installer-timeout ]]; then exit 124; fi
shift
exec "$@"
`)
			for _, tool := range []string{"curl", "wget"} {
				write(filepath.Join(bin, tool), `printf 'transport:%s\n' "$*" >> "$TRACE"
[[ "$*" == *--connect-timeout* ]] || exit 92
case "$SCENARIO" in download-failure) exit 28;; vendor-failure) [[ "$*" != *vendor.example.test* ]] || exit 28;; esac
`)
			}
			write(vendor, `printf 'vendor:%s\n' "$*" >> "$TRACE"
# The daemon must not inherit the bootstrap lock descriptor.
if ( : >&9 ) 2>/dev/null; then exit 93; fi
if [[ "$SCENARIO" == vendor-wget ]]; then
 wget http://vendor.example.test/package.tar.gz -O /dev/null
else
 curl http://vendor.example.test/package.tar.gz -o /dev/null
fi
`)
			region := "cn-hangzhou-internet"
			if scenario == "internal" {
				region = "cn-hangzhou"
			}
			if scenario == "other-region" {
				region = "eu-central-1-internet"
			}
			harness := "set -euo pipefail\nlog() { echo \"$*\"; }\nfatal() { echo \"$*\" >&2; exit 1; }\nALLOW_HTTP=0\n" + helpers + "\n"
			if scenario == "wget-fallback" {
				harness += `command() { if [[ "$*" == '-v curl' ]]; then return 1; fi; builtin command "$@"; }
`
			}
			harness += `exec 9>"$LOCK"
download https://release.example.test/archive "$OUTPUT" agent-package-download
run_logtail_installer "$VENDOR"
`
			cmd := exec.Command("bash", "-c", harness)
			cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "TRACE="+trace, "SCENARIO="+scenario, "LOGTAIL_REGION="+region, "VENDOR="+vendor, "OUTPUT="+filepath.Join(root, "partial"), "LOCK="+filepath.Join(root, "lock"))
			out, err := cmd.CombinedOutput()
			success := scenario != "download-failure" && scenario != "vendor-failure" && scenario != "installer-timeout"
			if (err == nil) != success {
				t.Fatalf("%v: %s", err, out)
			}
			data, _ := os.ReadFile(trace)
			calls := string(data)
			if !strings.Contains(calls, "--kill-after=10 300") || !strings.Contains(calls, "--connect-timeout") {
				t.Fatal(calls)
			}
			if scenario == "download-failure" {
				if !strings.Contains(string(out), "stage=agent-package-download host=release.example.test download failed") || strings.Contains(calls, "vendor:") {
					t.Fatalf("%s\n%s", out, calls)
				}
			} else if scenario == "installer-timeout" {
				if !strings.Contains(string(out), "stage=logtail-install") || !strings.Contains(string(out), "exit=124") {
					t.Fatal(string(out))
				}
			} else {
				if !strings.Contains(calls, "vendor:install "+region) {
					t.Fatal(calls)
				}
				if !strings.Contains(string(out), "stage=logtail-binary-download host=vendor.example.test") {
					t.Fatal(string(out))
				}
			}
			if scenario == "internal" && strings.Contains(calls, "vendor:install cn-hangzhou-internet") {
				t.Fatal("implicit network fallback")
			}
		})
	}
}

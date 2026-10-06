package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Invoke the production helper under nounset with isolated transports. Only a
// confirmed missing pointer may permit fallback; failures must remove partials.
func TestBootstrapOptionalPointer(t *testing.T) {
	body, err := os.ReadFile("packaging/bootstrap-install.sh")
	if err != nil {
		t.Fatal(err)
	}
	start := strings.Index(string(body), "download_optional_pointer() {")
	if start < 0 {
		t.Fatal("optional pointer helper not found")
	}
	end := strings.Index(string(body)[start:], "\n# Interpose")
	if end < 0 {
		t.Fatal("optional pointer helper not found")
	}
	helper := string(body)[start : start+end]
	for _, transport := range []string{"curl", "wget", "file"} {
		for _, scenario := range []string{"success", "missing", "server-error", "tls-error", "timeout", "interrupted-404", "redirect-missing"} {
			if transport == "file" && scenario != "success" && scenario != "missing" && scenario != "server-error" {
				continue
			}
			t.Run(transport+"/"+scenario, func(t *testing.T) {
				root := t.TempDir()
				output := filepath.Join(root, "pointer")
				source := filepath.Join(root, "source")
				if scenario != "missing" {
					if err := os.WriteFile(source, []byte("0.3.76\n"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				wantRC := 2
				if scenario == "success" {
					wantRC = 0
				} else if scenario == "missing" || scenario == "redirect-missing" {
					wantRC = 1
				}
				harness := `set -euo pipefail
ALLOW_HTTP=0
# A function wrapper removes the GNU timeout dependency on the macOS test host.
timeout() { [[ "$1" == --kill-after=10 && "$2" == 300 ]]; shift 2; "$@"; }
command() {
  if [[ "$1" == -v && "$2" == curl && "$TRANSPORT" == wget ]]; then return 1; fi
  builtin command "$@"
}
curl() {
  local output="" status=200 rc=0
  while [[ $# -gt 0 ]]; do
    if [[ "$1" == --output ]]; then output="$2"; shift; fi
    shift
  done
  case "$SCENARIO" in
    missing|redirect-missing) status=404; rc=22;;
    server-error) status=503; rc=22;;
    tls-error) status=000; rc=60;;
    timeout) status=000; rc=28;;
    interrupted-404) status=404; rc=28;;
  esac
  printf '0.3.76\n' > "$output"
  printf '%s' "$status"
  return "$rc"
}
wget() {
  local output="" status=200 rc=0
  for arg in "$@"; do
    case "$arg" in --output-document=*) output="${arg#*=}";; esac
  done
  case "$SCENARIO" in
    missing|redirect-missing) status=404; rc=8;;
    server-error) status=503; rc=8;;
    tls-error) status=000; rc=5;;
    timeout) status=000; rc=4;;
    interrupted-404) status=404; rc=4;;
  esac
  if [[ "$SCENARIO" == redirect-missing ]]; then printf '  HTTP/1.1 302 Found\n' >&2; fi
  printf '  HTTP/1.1 %s response\n' "$status" >&2
  printf '0.3.76\n' > "$output"
  return "$rc"
}
# A deterministic copy error avoids permission tests depending on the test UID.
cp() { [[ "$SCENARIO" != server-error ]] || return 1; builtin command cp "$@"; }
` + helper + fmt.Sprintf(`
url=https://release.example.test/latest-linux-version.txt
if [[ "$TRANSPORT" == file ]]; then
  SECWEAVER_BOOTSTRAP_ALLOW_FILE=1
  url="file://$SOURCE"
fi
rc=0
download_optional_pointer "$url" "$OUTPUT" || rc=$?
[[ "$rc" == %d ]] || { printf 'unexpected pointer result: %%s\n' "$rc" >&2; exit 91; }
`, wantRC)
				cmd := exec.Command("bash", "-c", harness)
				cmd.Env = append(os.Environ(), "TRANSPORT="+transport, "SCENARIO="+scenario, "OUTPUT="+output, "SOURCE="+source)
				out, err := cmd.CombinedOutput()
				if err != nil {
					t.Fatalf("%v: %s", err, out)
				}
				data, readErr := os.ReadFile(output)
				if wantRC == 0 {
					if readErr != nil || string(data) != "0.3.76\n" {
						t.Fatalf("pointer = %q, error = %v", data, readErr)
					}
				} else if !os.IsNotExist(readErr) {
					t.Fatalf("failed pointer left output: %q, error = %v", data, readErr)
				}
				partials, err := filepath.Glob(output + ".tmp.*")
				if err != nil || len(partials) != 0 {
					t.Fatalf("temporary files = %v, error = %v", partials, err)
				}
			})
		}
	}
}

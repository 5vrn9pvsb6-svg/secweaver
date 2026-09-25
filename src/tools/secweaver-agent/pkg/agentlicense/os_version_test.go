package agentlicense

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"secweaver-agent/internal/agentactivity"
)

func TestWindowsOSVersionReportsProductAndBuild(t *testing.T) {
	for _, caption := range []string{"Microsoft Windows 11 Pro", "Microsoft Windows Server 2019 Standard", "Microsoft Windows 11 专业版"} {
		t.Run(caption, func(t *testing.T) {
			calls := 0
			got := windowsOSVersion(func(timeout time.Duration, name string, args ...string) string {
				calls++
				if timeout != 3*time.Second || name != "powershell.exe" || len(args) != 5 || !reflect.DeepEqual(args[:4], []string{"-NoLogo", "-NoProfile", "-NonInteractive", "-Command"}) {
					t.Fatalf("unexpected inventory command: %v %q %q", timeout, name, args)
				}
				if !agentactivity.IsInternalPowerShellScript(args[4]) || agentactivity.IsInternalPowerShellScript(args[4]+"; Write-Output attacker") {
					t.Fatal("inventory script must use the exact self-activity allowlist")
				}
				encoded, _ := json.Marshal(map[string]string{"caption": caption, "version": "10.0.22631"})
				return "\ufeff" + string(encoded) + "\r\n"
			})
			if want := caption + " (10.0.22631)"; got != want || calls != 1 {
				t.Fatalf("got %q in %d calls, want %q without fallback", got, calls, want)
			}
		})
	}
}

func TestWindowsOSVersionFallbackIsBoundedAndOptional(t *testing.T) {
	oversized, _ := json.Marshal(map[string]string{"caption": strings.Repeat("系统", 30), "version": "10.0.22631"})
	for _, output := range []string{"", "PowerShell is blocked", `null`, `{}`, `{"caption":"Windows"}`, `{"caption":true,"version":"10.0.22631"}`, `{"caption":"Windows \ufffd","version":"10.0.22631"}`, "{\"caption\":\"Windows \xff\",\"version\":\"10.0.22631\"}", string(oversized)} {
		t.Run(output, func(t *testing.T) {
			for _, fallback := range []string{"\r\nMicrosoft Windows [Version 10.0.22631]\r\n", "", strings.Repeat("x", 129), string([]byte{0xff})} {
				calls := 0
				got := windowsOSVersion(func(timeout time.Duration, name string, args ...string) string {
					calls++
					if calls == 1 {
						return output
					}
					if timeout != 2*time.Second || name != "cmd" || !reflect.DeepEqual(args, []string{"/d", "/c", "ver"}) {
						t.Fatalf("unexpected fallback: %v %q %q", timeout, name, args)
					}
					return fallback
				})
				want := ""
				if strings.HasPrefix(fallback, "\r\nMicrosoft") {
					want = "Windows (10.0.22631)"
				}
				if got != want || calls != 2 {
					t.Fatalf("got %q in %d calls, want %q from fallback", got, calls, want)
				}
			}
		})
	}
}

func TestWindowsOSVersionPreservesBuildAcrossCodePages(t *testing.T) {
	// CP936 encodes 版本 as B0 E6 B1 BE. The old raw-string JSON path replaces B0
	// and interprets E6 B1 BE as 汾, reproducing the exact field reported in the UI.
	cp936 := "Microsoft Windows [\xb0\xe6\xb1\xbe 10.0.17763.9245]"
	oldJSON, err := json.Marshal(cp936)
	if err != nil {
		t.Fatal(err)
	}
	var oldReport string
	if err := json.Unmarshal(oldJSON, &oldReport); err != nil {
		t.Fatal(err)
	}
	if oldReport != "Microsoft Windows [�汾 10.0.17763.9245]" {
		t.Fatalf("legacy reproduction: %q", oldReport)
	}
	for _, output := range []string{cp936, oldReport, "Microsoft Windows [版本 10.0.17763.9245]", "\r\nMicrosoft Windows [Version 10.0.17763.9245]\r\n"} {
		got := windowsOSVersion(func(_ time.Duration, name string, _ ...string) string {
			if name == "cmd" {
				return output
			}
			return ""
		})
		if got != "Windows (10.0.17763.9245)" {
			t.Fatalf("fallback for %q: %q", output, got)
		}
	}
	for _, malformed := range []string{"10.0.17763.9245", "Microsoft Windows [Version 10.0]", "Microsoft Windows [Version 10.0.17763.9245.1]", "Microsoft Windows [Version 10.0.17763.9245] extra", "Microsoft Windows [Version 10.0.17763.9245"} {
		if got := windowsCommandVersion(malformed); got != "" {
			t.Errorf("accepted incomplete/unknown output %q: %q", malformed, got)
		}
	}
}

func TestLinuxOSVersionIncludesDistribution(t *testing.T) {
	for _, tc := range []struct{ release, want string }{
		{"PRETTY_NAME=\"Ubuntu 22.04.5 LTS\"\nNAME=Ubuntu\nVERSION_ID=22.04\n", "Ubuntu 22.04.5 LTS"},
		{"PRETTY_NAME=\"CentOS Stream 9\"\nNAME=CentOS\nVERSION_ID=9\n", "CentOS Stream 9"},
		{"NAME=\"Debian GNU/Linux\"\nVERSION_ID=12\n", "Debian GNU/Linux 12"},
	} {
		path := filepath.Join(t.TempDir(), "os-release")
		if err := os.WriteFile(path, []byte(tc.release), 0600); err != nil {
			t.Fatal(err)
		}
		if got := linuxOSVersion(path); got != tc.want {
			t.Errorf("got %q, want %q", got, tc.want)
		}
	}
}

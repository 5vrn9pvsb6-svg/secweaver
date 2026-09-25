package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Extract only the path normalization function: these compatibility checks
// cannot stop services or delete files, including when run on a developer host.
func TestUninstallSystemServiceSymlinks(t *testing.T) {
	body, err := os.ReadFile("packaging/uninstall.sh")
	if err != nil {
		t.Fatal(err)
	}
	source := string(body)
	start := strings.Index(source, "normalize_service_directories() {")
	end := strings.Index(source[start:], "\nneed_cmd()") + start
	if start < 0 || end <= start {
		t.Fatal("missing normalization function")
	}
	for _, tc := range []struct {
		path, target string
		ok           bool
	}{
		{"/etc/init.d", "/etc/rc.d/init.d", true},
		{"/lib/systemd/system", "/usr/lib/systemd/system", true},
		{"/etc/init.d", "/tmp/attacker", false},
		{"/custom/init", "/etc/rc.d/init.d", false},
	} {
		t.Run(tc.path+tc.target, func(t *testing.T) {
			// Relocate exact allowlisted paths to real temporary symlinks, while
			// keeping the disallowed cases outside the relocated whitelist.
			root, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			fn := source[start:end]
			var replacements []string
			for _, p := range []string{"/etc/init.d", "/etc/rc.d/init.d", "/lib/systemd/system", "/usr/lib/systemd/system"} {
				replacements = append(replacements, p, root+p)
			}
			fn = strings.NewReplacer(replacements...).Replace(fn)
			path, target := root+tc.path, root+tc.target
			if err := os.MkdirAll(target, 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(path[:strings.LastIndex(path, "/")], 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, path); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("bash", "-c", "set -eu; warn() { :; }; "+fn+"\nINIT_DIR=$TEST_LINK; LEGACY_SYSTEMD_DIR=$TEST_ABSENT; normalize_service_directories")
			cmd.Env = append(os.Environ(), "TEST_LINK="+path, "TEST_ABSENT="+root+"/absent")
			if out, err := cmd.CombinedOutput(); (err == nil) != tc.ok {
				t.Fatalf("%v %s", err, out)
			}
		})
	}
}

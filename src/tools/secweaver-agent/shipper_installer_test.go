package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Run real lifecycle functions with synthetic services and PID locks. Absolute
// vendor paths are relocated before execution, so tests cannot stop host agents.
func TestLogtailInstallerHandoff(t *testing.T) {
	body, err := os.ReadFile("packaging/bootstrap-install.sh")
	if err != nil {
		t.Fatal(err)
	}
	start := strings.Index(string(body), "stop_logtail_for_handoff() {")
	end := strings.Index(string(body)[start:], "\nTEMP_DIR=") + start
	if start < 0 || end < start {
		t.Fatal("missing handoff functions")
	}
	for _, scenario := range []string{"normal", "force", "stubborn", "stopping", "no-start"} {
		t.Run(scenario, func(t *testing.T) {
			root := t.TempDir()
			trace := filepath.Join(root, "trace")
			live := filepath.Join(root, "live")
			if err := os.WriteFile(live, []byte("running"), 0600); err != nil {
				t.Fatal(err)
			}
			init := filepath.Join(root, "ilogtaild")
			script := `#!/usr/bin/env bash
echo "init:$1" >> "$TRACE"
case "$1" in
stop) [[ "$SCENARIO" == normal || "$SCENARIO" == no-start ]] && rm -f "$LIVE"; exit 0 ;;
force-stop) [[ "$SCENARIO" != stubborn ]] && rm -f "$LIVE"; exit 0 ;;
status) test -f "$LIVE" ;;
esac
`
			if err := os.WriteFile(init, []byte(script), 0755); err != nil {
				t.Fatal(err)
			}
			functions := strings.ReplaceAll(string(body)[start:end], "/etc/init.d/", root+"/")
			functions = strings.ReplaceAll(functions, "/usr/local/ilogtail/", root+"/")
			lock := filepath.Join(root, "ilogtail_2.1.14.pid")
			if err := os.WriteFile(lock, []byte("123"), 0600); err != nil {
				t.Fatal(err)
			}
			harness := `
set -euo pipefail
log() { :; }
fatal() { echo "$*" >&2; exit 1; }
timeout() { shift; "$@"; }
sleep() { :; }
logtail_processes() { if [[ -f "$LIVE" ]]; then echo 123; fi; }
systemctl() {
 echo "systemctl:$*" >> "$TRACE"
 case "$1" in
 cat) [[ "$2" == ilogtaild.service ]] ;;
 show) if [[ "$SCENARIO" == stopping ]]; then echo ActiveState=deactivating; else echo ActiveState=inactive; fi ;;
 start) [[ ! -e "$LOCK" && ! -e "$LIVE" ]]; touch "$LIVE" ;;
 *) return 0 ;;
 esac
}
START_SERVICE=1
[[ "$SCENARIO" != no-start ]] || START_SERVICE=0
` + functions + "\nstart_logtail\n"
			cmd := exec.Command("bash", "-c", harness)
			cmd.Env = append(os.Environ(), "TRACE="+trace, "LIVE="+live, "LOCK="+lock, "SCENARIO="+scenario)
			out, err := cmd.CombinedOutput()
			success := scenario != "stubborn" && scenario != "stopping"
			if (err == nil) != success {
				t.Fatalf("%v: %s", err, out)
			}
			data, _ := os.ReadFile(trace)
			actions := string(data)
			if strings.Contains(actions, "--now") || strings.Contains(actions, "restart") {
				t.Fatal(actions)
			}
			wantStart := success && scenario != "no-start"
			if strings.Contains(actions, "systemctl:start ") != wantStart {
				t.Fatal(actions)
			}
			if !success {
				if _, err := os.Stat(lock); err != nil {
					t.Fatal("live PID lock removed")
				}
			}
			if scenario == "force" && !strings.Contains(actions, "init:force-stop") {
				t.Fatal(actions)
			}
		})
	}
}

// The complete uninstaller runs in a disposable layout with every external
// process/package/service operation stubbed. stdout must contain exactly JSON.
func TestUninstallerZeroRulesAndStandaloneCollectors(t *testing.T) {
	source, err := os.ReadFile("packaging/uninstall.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"zero", "audit-error", "remaining-rules", "collectors", "preserve", "rpm", "deb", "package-failure", "collector-residue"} {
		t.Run(scenario, func(t *testing.T) {
			root := t.TempDir()
			stubs := filepath.Join(root, "stubs")
			if err := os.MkdirAll(stubs, 0755); err != nil {
				t.Fatal(err)
			}
			packageTrace := filepath.Join(root, "package-trace")
			env := append(os.Environ(), "PATH="+stubs+":"+os.Getenv("PATH"), "SCENARIO="+scenario, "PACKAGE_TRACE="+packageTrace)
			paths := map[string]string{}
			for _, key := range []string{"INSTALL_ROOT", "BIN_DIR", "CONFIG_DIR", "STATE_DIR", "LOG_DIR", "SHIPPER_DIR", "SYSTEMD_DIR", "VENDOR_SYSTEMD_DIR", "LEGACY_SYSTEMD_DIR", "INIT_DIR", "LOGTAIL_ROOT", "LOGTAIL_ETC", "FILEBEAT_ROOT", "FILEBEAT_ETC", "FILEBEAT_STATE", "FILEBEAT_LOGS"} {
				p := filepath.Join(root, key)
				paths[key] = p
				env = append(env, key+"="+p)
				if err := os.MkdirAll(p, 0755); err != nil {
					t.Fatal(err)
				}
			}
			for _, key := range []string{"COMMAND_LINK", "FILEBEAT_COMMAND", "FILEBEAT_LOCAL_COMMAND"} {
				env = append(env, key+"="+filepath.Join(root, key))
			}
			mocks := map[string]string{
				"systemctl": `case "$1" in cat) [ "$SCENARIO" = collector-residue ] && [ "$2" = filebeat.service ];; *) exit 0;; esac`,
				"auditctl": `if [ "$1" = -l ]; then
case "$SCENARIO" in audit-error) exit 1;; remaining-rules) echo '-a always,exit -k tb_external_listener_exec';; *) echo 'No rules';; esac
fi`,
				"ps": "exit 0", "pgrep": "exit 1", "chkconfig": "exit 0", "update-rc.d": "exit 0",
				"rpm": `case "$SCENARIO" in rpm|package-failure) ;; *) exit 1;; esac
if [ "$1" = -e ]; then
 echo rpm >> "$PACKAGE_TRACE"
 [ "$SCENARIO" != package-failure ]
fi`,
				"dpkg-query": `[ "$SCENARIO" = deb ]`,
				"dpkg":       `echo deb >> "$PACKAGE_TRACE"`,
				"timeout":    `shift; exec "$@"`,
			}
			for name, body := range mocks {
				if err := os.WriteFile(filepath.Join(stubs, name), []byte("#!/bin/sh\n"+body+"\n"), 0755); err != nil {
					t.Fatal(err)
				}
			}
			// Exercise the installed entrypoint: removing bin also unlinks the
			// running script, which must still finish verification and JSON output.
			script := filepath.Join(paths["BIN_DIR"], "uninstall.sh")
			// Root authorization is the sole production guard bypassed by this fixture.
			text := strings.Replace(string(source), "\nrequire_root\n", "\n:\n", 1)
			if err := os.WriteFile(script, []byte(text), 0755); err != nil {
				t.Fatal(err)
			}
			log := filepath.Join(paths["LOG_DIR"], "host-behavior-summary.log.1")
			if err := os.WriteFile(log, []byte("event"), 0600); err != nil {
				t.Fatal(err)
			}
			args := []string{script, "--purge", "--json"}
			removeCollectors := scenario == "collectors" || scenario == "rpm" || scenario == "deb" || scenario == "package-failure" || scenario == "collector-residue"
			if removeCollectors {
				args = append(args, "--remove-logtail", "--remove-filebeat")
			}
			cmd := exec.Command("bash", args...)
			cmd.Env = env
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			out, err := cmd.Output()
			success := scenario != "audit-error" && scenario != "remaining-rules" && scenario != "package-failure" && scenario != "collector-residue"
			if (err == nil) != success {
				t.Fatalf("%v\nstdout=%s\nstderr=%s", err, out, stderr.String())
			}
			var result struct {
				OK    bool `json:"ok"`
				Audit struct {
					Count int `json:"remaining_rule_count"`
				} `json:"audit"`
			}
			if err := json.Unmarshal(out, &result); err != nil {
				t.Fatalf("invalid JSON: %s: %v", out, err)
			}
			if result.OK != success {
				t.Fatal(string(out))
			}
			if scenario == "rpm" || scenario == "deb" {
				trace, err := os.ReadFile(packageTrace)
				if err != nil || strings.TrimSpace(string(trace)) != scenario {
					t.Fatalf("package manager not used: %s %v", trace, err)
				}
			}
			if scenario == "package-failure" {
				if !strings.Contains(string(out), "uninstall_incomplete") {
					t.Fatal(string(out))
				}
				if _, err := os.Stat(paths["FILEBEAT_ROOT"]); err != nil {
					t.Fatal("files deleted after package removal failure")
				}
				return
			}
			if scenario == "zero" && result.Audit.Count != 0 {
				t.Fatal(string(out))
			}
			if scenario == "audit-error" && result.Audit.Count != -2 {
				t.Fatal(string(out))
			}
			_, logErr := os.Stat(log)
			if !os.IsNotExist(logErr) {
				t.Fatal("rotated summary log remains")
			}
			for _, key := range []string{"LOGTAIL_ROOT", "FILEBEAT_ROOT"} {
				_, err := os.Stat(paths[key])
				if os.IsNotExist(err) != removeCollectors {
					t.Fatalf("unexpected removal %s: %v", key, err)
				}
			}
		})
	}
}

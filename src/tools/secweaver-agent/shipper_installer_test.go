package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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
	for _, scenario := range []string{"zero", "audit-error", "remaining-rules", "collectors", "preserve", "rpm", "deb", "package-failure", "collector-residue", "process-residue", "gateway-safe", "legacy-data-preserve"} {
		t.Run(scenario, func(t *testing.T) {
			root := t.TempDir()
			stubs := filepath.Join(root, "stubs")
			if err := os.MkdirAll(stubs, 0755); err != nil {
				t.Fatal(err)
			}
			packageTrace := filepath.Join(root, "package-trace")
			// Force the script's bounded ps fallback on every test platform.
			// Production Linux uses authoritative procfs executable identity.
			env := append(os.Environ(),
				"PATH="+stubs+":"+os.Getenv("PATH"),
				"SCENARIO="+scenario, "PACKAGE_TRACE="+packageTrace,
				"PROC_ROOT="+filepath.Join(root, "no-proc"))
			paths := map[string]string{}
			for _, key := range []string{"INSTALL_ROOT", "BIN_DIR", "CONFIG_DIR", "STATE_DIR", "LOG_DIR", "SHIPPER_DIR", "LEGACY_CONFIG_DIR", "LEGACY_STATE_DIR", "LEGACY_LOG_DIR", "LEGACY_FILEBEAT_LOG_DIR", "LEGACY_COMMAND_DIR", "SYSTEMD_DIR", "VENDOR_SYSTEMD_DIR", "LEGACY_SYSTEMD_DIR", "INIT_DIR", "LOGTAIL_ROOT", "LOGTAIL_ETC", "FILEBEAT_ROOT", "FILEBEAT_ETC", "FILEBEAT_STATE", "FILEBEAT_LOGS"} {
				p := filepath.Join(root, key)
				paths[key] = p
				env = append(env, key+"="+p)
				if err := os.MkdirAll(p, 0755); err != nil {
					t.Fatal(err)
				}
			}
			for _, key := range []string{"COMMAND_LINK", "FILEBEAT_COMMAND", "FILEBEAT_LOCAL_COMMAND"} {
				p := filepath.Join(root, key)
				paths[key] = p
				env = append(env, key+"="+p)
			}
			mocks := map[string]string{
				"systemctl": `case "$1" in
cat)
  [ "$SCENARIO" = collector-residue ] && [ "$2" = filebeat.service ] && exit 0
  for root in "$SYSTEMD_DIR" "$VENDOR_SYSTEMD_DIR" "$LEGACY_SYSTEMD_DIR"; do
    [ -e "$root/$2" ] && exit 0
  done
  exit 1
  ;;
*) exit 0 ;;
esac`,
				"auditctl": `if [ "$1" = -l ]; then
case "$SCENARIO" in audit-error) exit 1;; remaining-rules) echo '-a always,exit -k tb_external_listener_exec';; *) echo 'No rules';; esac
fi`,
				"ps": `case "$SCENARIO" in
process-residue) echo "999999 swl-agent swl-agent" ;;
gateway-safe) echo "999998 secweaver-agent /opt/secweaver-agent-gateway" ;;
esac`, "pgrep": "exit 1", "sleep": "exit 0", "chkconfig": "exit 0", "update-rc.d": "exit 0",
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
			// Seed every historical layout with exact product-owned artifacts.
			// The fixture proves purge removes them without broad /var/log deletion.
			writeFixture := func(path string, mode os.FileMode) {
				t.Helper()
				if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte("fixture"), mode); err != nil {
					t.Fatal(err)
				}
			}
			log := filepath.Join(paths["LOG_DIR"], "host-behavior-summary.log.1")
			legacyDataArtifacts := []string{
				filepath.Join(paths["LEGACY_CONFIG_DIR"], "config.json"),
				filepath.Join(paths["LEGACY_STATE_DIR"], "license-state.json"),
				filepath.Join(paths["LEGACY_LOG_DIR"], "audit-port-execmon.log.3"),
				filepath.Join(paths["LEGACY_LOG_DIR"], "behavior-learning.log.1"),
				filepath.Join(paths["LEGACY_FILEBEAT_LOG_DIR"], "registry.log"),
			}
			legacyRemovalArtifacts := []string{
				filepath.Join(paths["INSTALL_ROOT"], "swl-agent"),
				paths["COMMAND_LINK"],
				filepath.Join(paths["LEGACY_COMMAND_DIR"], "audit-port-execmon"),
				filepath.Join(paths["LEGACY_COMMAND_DIR"], "syslog-risk-json"),
				filepath.Join(paths["LEGACY_COMMAND_DIR"], "host-persistence"),
				filepath.Join(paths["LEGACY_COMMAND_DIR"], "swl-agent"),
			}
			writeFixture(log, 0600)
			for _, artifact := range append(legacyDataArtifacts, legacyRemovalArtifacts...) {
				writeFixture(artifact, 0700)
			}

			serviceLocations := map[string]string{
				"secweaver-agent.service":         paths["SYSTEMD_DIR"],
				"secweaver-agent-shipper.service": paths["SYSTEMD_DIR"],
				"swl-agent.service":               paths["SYSTEMD_DIR"],
				"audit-port-execmon.service":      paths["VENDOR_SYSTEMD_DIR"],
				"syslog-risk-json.service":        paths["LEGACY_SYSTEMD_DIR"],
				"host-persistence.service":        paths["SYSTEMD_DIR"],
			}
			for service, directory := range serviceLocations {
				unit := filepath.Join(directory, service)
				writeFixture(unit, 0644)
				legacyRemovalArtifacts = append(legacyRemovalArtifacts, unit)
			}
			dropIn := filepath.Join(paths["SYSTEMD_DIR"], "swl-agent.service.d", "override.conf")
			writeFixture(dropIn, 0644)
			legacyRemovalArtifacts = append(legacyRemovalArtifacts, filepath.Dir(dropIn))
			wantsDir := filepath.Join(paths["SYSTEMD_DIR"], "multi-user.target.wants")
			if err := os.MkdirAll(wantsDir, 0755); err != nil {
				t.Fatal(err)
			}
			wantsLink := filepath.Join(wantsDir, "swl-agent.service")
			if err := os.Symlink(filepath.Join("..", "swl-agent.service"), wantsLink); err != nil {
				t.Fatal(err)
			}
			legacyRemovalArtifacts = append(legacyRemovalArtifacts, wantsLink)

			args := []string{script, "--json"}
			if scenario != "legacy-data-preserve" {
				args = append(args, "--purge")
			}
			removeCollectors := scenario == "collectors" || scenario == "rpm" || scenario == "deb" || scenario == "package-failure" || scenario == "collector-residue"
			if removeCollectors {
				args = append(args, "--remove-logtail", "--remove-filebeat")
			}
			cmd := exec.Command("bash", args...)
			cmd.Env = env
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			out, err := cmd.Output()
			success := scenario != "audit-error" && scenario != "remaining-rules" && scenario != "package-failure" && scenario != "collector-residue" && scenario != "process-residue"
			if (err == nil) != success {
				t.Fatalf("%v\nstdout=%s\nstderr=%s", err, out, stderr.String())
			}
			var result struct {
				OK    bool `json:"ok"`
				Audit struct {
					Count int `json:"remaining_rule_count"`
				} `json:"audit"`
				Files struct {
					KnownBinariesExist      bool `json:"known_binaries_exist"`
					LegacyConfigExists      bool `json:"legacy_config_exists"`
					LegacyStateExists       bool `json:"legacy_state_exists"`
					LegacyKnownLogsExist    bool `json:"legacy_known_logs_exist"`
					LegacyFilebeatLogsExist bool `json:"legacy_filebeat_logs_exist"`
				} `json:"files"`
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
			if scenario == "process-residue" {
				if !strings.Contains(string(out), "uninstall_incomplete") {
					t.Fatal(string(out))
				}
				if _, err := os.Stat(filepath.Join(paths["LEGACY_CONFIG_DIR"], "config.json")); err != nil {
					t.Fatal("files deleted while a legacy process remained")
				}
				return
			}
			if scenario == "zero" && result.Audit.Count != 0 {
				t.Fatal(string(out))
			}
			if scenario == "audit-error" && result.Audit.Count != -2 {
				t.Fatal(string(out))
			}
			if scenario == "legacy-data-preserve" {
				if _, err := os.Stat(log); err != nil {
					t.Fatal("normal uninstall removed the current rotated log")
				}
				for _, artifact := range legacyDataArtifacts {
					if _, err := os.Lstat(artifact); err != nil {
						t.Fatalf("normal uninstall removed legacy data: %s (%v)", artifact, err)
					}
				}
				if result.Files.KnownBinariesExist || !result.Files.LegacyConfigExists ||
					!result.Files.LegacyStateExists || !result.Files.LegacyKnownLogsExist ||
					!result.Files.LegacyFilebeatLogsExist {
					t.Fatalf("normal uninstall verification fields are inconsistent: %s", out)
				}
			} else {
				if _, err := os.Stat(log); !os.IsNotExist(err) {
					t.Fatal("rotated summary log remains")
				}
				for _, artifact := range legacyDataArtifacts {
					if _, err := os.Lstat(artifact); !os.IsNotExist(err) {
						t.Fatalf("legacy data remains: %s (%v)", artifact, err)
					}
				}
				if result.Files.KnownBinariesExist || result.Files.LegacyConfigExists ||
					result.Files.LegacyStateExists || result.Files.LegacyKnownLogsExist ||
					result.Files.LegacyFilebeatLogsExist {
					t.Fatalf("legacy verification fields report residue: %s", out)
				}
			}
			for _, artifact := range legacyRemovalArtifacts {
				if _, err := os.Lstat(artifact); !os.IsNotExist(err) {
					t.Fatalf("legacy service/binary artifact remains: %s (%v)", artifact, err)
				}
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

// Production residual-process discovery must use executable identity rather
// than Linux's truncated comm field, which the Agent and gateway can share.
func TestUninstallerProcfsProcessOwnership(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("procfs symlink fixture is POSIX-only")
	}
	source, err := os.ReadFile("packaging/uninstall.sh")
	if err != nil {
		t.Fatal(err)
	}
	start := strings.Index(string(source), "secweaver_pid_is_owned() {")
	if start < 0 {
		t.Fatal("missing procfs process-ownership functions")
	}
	endOffset := strings.Index(string(source)[start:], "# systemd stop is best effort")
	if endOffset < 0 {
		t.Fatal("missing procfs process-ownership boundary")
	}
	end := start + endOffset

	root := t.TempDir()
	procRoot := filepath.Join(root, "proc")
	installRoot := filepath.Join(root, "secweaver-agent")
	link := func(path, target string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
	}
	link(filepath.Join(procRoot, "1", "ns", "pid"), "pid:[100]")
	writeProcess := func(pid, executable, namespace string) {
		t.Helper()
		processRoot := filepath.Join(procRoot, pid)
		link(filepath.Join(processRoot, "exe"), executable)
		link(filepath.Join(processRoot, "ns", "pid"), namespace)
	}
	writeProcess("32101", filepath.Join(installRoot, "bin", "secweaver-agent")+" (deleted)", "pid:[100]")
	writeProcess("32102", installRoot+"-gateway", "pid:[100]")
	writeProcess("32103", filepath.Join(installRoot, "bin", "secweaver-agent"), "pid:[200]")

	harness := `set -euo pipefail
` + string(source)[start:end] + "\nsecweaver_process_pids\n"
	cmd := exec.Command("bash", "-c", harness)
	cmd.Env = append(os.Environ(),
		"PROC_ROOT="+procRoot,
		"INSTALL_ROOT="+installRoot,
		"COMMAND_LINK="+filepath.Join(root, "secweaver-agent"),
		"LEGACY_COMMAND_DIR="+filepath.Join(root, "legacy-bin"))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if got := strings.TrimSpace(string(out)); got != "32101" {
		t.Fatalf("unexpected owned processes %q", got)
	}
}

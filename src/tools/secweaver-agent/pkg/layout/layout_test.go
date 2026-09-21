package layout

import "testing"

func TestMigratePathOnlyRewritesOwnedLinuxPaths(t *testing.T) {
	tests := map[string]string{
		"/etc/secweaver-agent/config.json":           LinuxEtc + "/config.json",
		"/var/lib/secweaver-agent/status.json":       LinuxData + "/status.json",
		"/var/log/syslog-risk-json.log.1":            LinuxLogs + "/syslog-risk-json.log.1",
		"/usr/local/bin/secweaver-agent":             LinuxBin + "/secweaver-agent",
		"/var/log/audit/audit.log":                   "/var/log/audit/audit.log",
		"/srv/custom/secweaver/syslog-risk-json.log": "/srv/custom/secweaver/syslog-risk-json.log",
	}
	for input, expected := range tests {
		actual, _ := MigratePath("linux", input)
		if actual != expected {
			t.Fatalf("MigratePath(%q) = %q, want %q", input, actual, expected)
		}
	}
}

func TestMigratePathClassifiesKnownWindowsArtifacts(t *testing.T) {
	tests := map[string]string{
		`C:\Program Files\SecWeaver\secweaver-agent.exe`:          WindowsBin + `\secweaver-agent.exe`,
		`C:\ProgramData\SecWeaver\config.json`:                    WindowsEtc + `\config.json`,
		`C:\ProgramData\SecWeaver\license-state.json`:             WindowsData + `\license-state.json`,
		`C:\ProgramData\SecWeaver\windows-eventlog-risk-json.log`: WindowsLogs + `\windows-eventlog-risk-json.log`,
		`C:\Windows\System32\Tasks`:                               `C:\Windows\System32\Tasks`,
	}
	for input, expected := range tests {
		actual, _ := MigratePath("windows", input)
		if actual != expected {
			t.Fatalf("MigratePath(%q) = %q, want %q", input, actual, expected)
		}
	}
}

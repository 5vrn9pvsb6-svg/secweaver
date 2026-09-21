// Package layout defines the on-host SecWeaver Agent directory layout.
//
// Keeping these paths in one package prevents collectors, installers, and
// diagnostics from silently drifting to different locations.
package layout

import (
	"os"
	"path/filepath"
	"strings"
)

const (
	LinuxRoot    = "/opt/secweaver-agent"
	LinuxBin     = LinuxRoot + "/bin"
	LinuxEtc     = LinuxRoot + "/etc"
	LinuxData    = LinuxRoot + "/data"
	LinuxLogs    = LinuxRoot + "/logs"
	LinuxShipper = LinuxRoot + "/shipper"

	WindowsRoot    = `C:\ProgramData\SecWeaver\Agent`
	WindowsBin     = WindowsRoot + `\bin`
	WindowsEtc     = WindowsRoot + `\etc`
	WindowsData    = WindowsRoot + `\data`
	WindowsLogs    = WindowsRoot + `\logs`
	WindowsShipper = WindowsRoot + `\shipper`
)

// WindowsRootDir honors a redirected ProgramData directory while retaining the
// conventional C:\ProgramData fallback for restricted service environments.
func WindowsRootDir() string {
	if programData := strings.TrimSpace(os.Getenv("ProgramData")); programData != "" {
		return filepath.Join(programData, "SecWeaver", "Agent")
	}
	return WindowsRoot
}

var linuxLogNames = []string{
	"audit-port-execmon.log",
	"host-persistence.log",
	"host-process-snapshot.log",
	"host-state-snapshot.log",
	"secweaver-agent-update.log",
	"secweaver-agent-health.log",
	"syslog-risk-json-history.log",
	"syslog-risk-json.log",
}

// MigratePath rewrites only paths owned by the legacy SecWeaver installation.
// It deliberately leaves arbitrary user paths and operating-system inputs such
// as /var/log/audit/audit.log unchanged. This makes installer migration safe for
// customized configurations while consolidating known Agent-owned artifacts.
func MigratePath(platform, value string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(platform)) {
	case "linux":
		return migrateLinuxPath(value)
	case "windows":
		return migrateWindowsPath(value)
	default:
		return value, false
	}
}

func migrateLinuxPath(value string) (string, bool) {
	prefixes := [][2]string{
		{"/etc/secweaver-agent", LinuxEtc},
		{"/var/lib/secweaver-agent", LinuxData},
		{"/usr/local/libexec/secweaver-agent-launch", LinuxBin + "/secweaver-agent-launch"},
		{"/usr/local/bin/secweaver-agent", LinuxBin + "/secweaver-agent"},
		{"/usr/local/bin/secweaver-shipper", LinuxShipper + "/bin/secweaver-shipper"},
	}
	for _, pair := range prefixes {
		if migrated, ok := replacePathPrefix(value, pair[0], pair[1], false); ok {
			return migrated, true
		}
	}
	if migrated, ok := replacePathPrefix(value, "/var/log/secweaver-filebeat", LinuxLogs+"/filebeat", false); ok {
		return migrated, true
	}
	for _, name := range linuxLogNames {
		if migrated, ok := replaceLogPath(value, "/var/log/"+name, LinuxLogs+"/"+name); ok {
			return migrated, true
		}
	}
	return value, false
}

// replaceLogPath accepts the conventional .1/.timestamp rotation suffix but
// does not broaden generic path migration to similarly prefixed file names.
func replaceLogPath(value, oldPath, newPath string) (string, bool) {
	if value == oldPath {
		return newPath, true
	}
	if strings.HasPrefix(value, oldPath+".") {
		return newPath + value[len(oldPath):], true
	}
	return value, false
}

func migrateWindowsPath(value string) (string, bool) {
	prefixes := [][2]string{
		{`C:\Program Files\SecWeaver\secweaver-agent.exe`, WindowsBin + `\secweaver-agent.exe`},
		{`C:\ProgramData\SecWeaver\shipper`, WindowsShipper},
	}
	for _, pair := range prefixes {
		if migrated, ok := replacePathPrefix(value, pair[0], pair[1], true); ok {
			return migrated, true
		}
	}
	const legacyRoot = `C:\ProgramData\SecWeaver`
	relative, ok := trimPathPrefix(value, legacyRoot, true)
	if !ok || relative == "" {
		return value, false
	}
	name := filepath.Base(strings.ReplaceAll(relative, `\`, string(filepath.Separator)))
	lowerName := strings.ToLower(name)
	switch {
	case lowerName == "config.json", lowerName == "host-persistence.json":
		return WindowsEtc + `\` + name, true
	case lowerName == "device-ed25519.key":
		return WindowsData + `\` + name, true
	case strings.EqualFold(relative, "update") || strings.HasPrefix(strings.ToLower(relative), "update\\"):
		return WindowsData + `\` + relative, true
	case strings.HasSuffix(lowerName, ".log"):
		return WindowsLogs + `\` + name, true
	case lowerName == "status.json", strings.HasSuffix(lowerName, "-state.json"), strings.HasSuffix(lowerName, ".cursor.json"):
		return WindowsData + `\` + name, true
	default:
		return value, false
	}
}

func replacePathPrefix(value, oldPrefix, newPrefix string, caseInsensitive bool) (string, bool) {
	relative, ok := trimPathPrefix(value, oldPrefix, caseInsensitive)
	if !ok {
		return value, false
	}
	if relative == "" {
		return newPrefix, true
	}
	separator := "/"
	if strings.Contains(newPrefix, `\`) {
		separator = `\`
	}
	return strings.TrimRight(newPrefix, `/\`) + separator + relative, true
}

func trimPathPrefix(value, prefix string, caseInsensitive bool) (string, bool) {
	comparedValue, comparedPrefix := value, prefix
	if caseInsensitive {
		comparedValue, comparedPrefix = strings.ToLower(value), strings.ToLower(prefix)
	}
	if comparedValue == comparedPrefix {
		return "", true
	}
	for _, separator := range []string{"/", `\`} {
		candidate := comparedPrefix + separator
		if strings.HasPrefix(comparedValue, candidate) {
			return value[len(candidate):], true
		}
	}
	return "", false
}

package agentlicense

import (
	"encoding/json"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"secweaver-agent/internal/agentactivity"
)

// CIM supplies the actual product caption (including Server/edition), unlike
// build-number heuristics or registry ProductName values retained after upgrades.
// UTF-8 output preserves localized captions on Windows PowerShell 5.1.
const windowsOSVersionScript = `$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false); $os=Get-CimInstance -ClassName Win32_OperatingSystem; [pscustomobject]@{caption=[string]$os.Caption;version=[string]$os.Version} | ConvertTo-Json -Compress`

func init() {
	// Only this exact fixed script is trusted as collector-generated activity;
	// the marker alone must never suppress arbitrary PowerShell security events.
	agentactivity.RegisterPowerShellScript(windowsOSVersionScript)
}

// windowsOSVersion is best-effort inventory, not an enrollment prerequisite.
// Bound CIM to three seconds and the legacy fallback to two; blocked PowerShell,
// missing WMI, malformed output or oversized captions keep only the numeric build.
// The runner permits failure-path tests on non-Windows development machines.
func windowsOSVersion(run func(time.Duration, string, ...string) string) string {
	output := run(3*time.Second, "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", agentactivity.MarkPowerShellScript(windowsOSVersionScript))
	var info struct {
		Caption string `json:"caption"`
		Version string `json:"version"`
	}
	output = strings.TrimPrefix(strings.TrimSpace(output), "\ufeff")
	if utf8.ValidString(output) && json.Unmarshal([]byte(output), &info) == nil {
		caption, version := strings.TrimSpace(info.Caption), strings.TrimSpace(info.Version)
		if caption != "" && version != "" {
			if label := boundedWindowsOSVersion(caption + " (" + version + ")"); label != "" {
				return label
			}
		}
	}
	// /d disables CMD AutoRun hooks. The localized label uses the OEM code page,
	// not necessarily UTF-8; never forward those raw bytes to JSON serialization.
	return windowsCommandVersion(run(2*time.Second, "cmd", "/d", "/c", "ver"))
}

var windowsVerOutput = regexp.MustCompile(`(?i)^Microsoft Windows\s*\[[^0-9\[\]\r\n]*([0-9]+(?:\.[0-9]+){2,3})\]$`)

// windowsCommandVersion retains the complete ASCII build from cmd's known
// envelope across code pages, discarding only the localized "Version" label.
// This avoids guessing GBK/OEM encodings or silently losing the patch component.
// Unknown/truncated output remains absent, and build numbers never imply editions.
func windowsCommandVersion(output string) string {
	match := windowsVerOutput.FindStringSubmatch(strings.TrimSpace(output))
	if len(match) != 2 {
		return ""
	}
	return boundedWindowsOSVersion("Windows (" + match[1] + ")")
}

// The existing registration/heartbeat contract caps os_version at 128 bytes.
// Omit unusable optional metadata instead of rejecting the whole signed request
// or cutting a localized UTF-8 character in half. Reject already-replaced text
// too: UTF-8 validity alone cannot detect a JSON-escaped replacement character.
func boundedWindowsOSVersion(value string) string {
	value = strings.Join(strings.Fields(value), " ")
	if len(value) > 128 || !utf8.ValidString(value) || strings.ContainsRune(value, '\ufffd') {
		return ""
	}
	return value
}

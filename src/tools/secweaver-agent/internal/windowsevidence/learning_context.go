package windowsevidence

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	"secweaver-agent/pkg/behaviorlearning"
)

// learningObservation uses execution-time Sysmon evidence only. Querying live
// PIDs after a polling delay could associate an exited process with a reused PID.
// Security 4688 deliberately remains full-output: it has no image hash/GUID.
func learningObservation(e Event, started, now time.Time) behaviorlearning.Observation {
	raw, _ := json.Marshal(e)
	o := behaviorlearning.Observation{Raw: raw, EventID: e.EvidenceID, Reason: "windows_context_incomplete"}
	f := e.Fields
	o.At, _ = time.Parse(time.RFC3339Nano, e.Time)
	if strings.EqualFold(e.Provider, "Microsoft-Windows-Sysmon") {
		o.Instance = processInstance(e.HostName, f["ProcessGuid"])
		o.ParentInstance = processInstance(e.HostName, f["ParentProcessGuid"])
	}
	if e.WindowsEventID != "1" || !strings.EqualFold(e.Provider, "Microsoft-Windows-Sysmon") ||
		!strings.EqualFold(e.Channel, "Microsoft-Windows-Sysmon/Operational") {
		o.Reason = "windows_execution_identity_unavailable"
		return o
	}
	// Historical replay never trains or matches a current online baseline. Exact
	// commands are retained as one string; tokenizing Windows argv would be lossy.
	if o.At.Before(started) || o.At.After(now.Add(time.Minute)) || now.Sub(o.At) > 10*time.Minute {
		o.Reason = "historical_or_delayed_event"
		return o
	}
	if blockedWindows(e.Exe, f["OriginalFileName"], f["CommandLine"]) ||
		blockedWindows(e.ParentProcess, "", f["ParentCommandLine"]) {
		o.Reason = "always_emit_tool"
		return o
	}
	digest := sysmonSHA256(f["Hashes"])
	user, parentUser := strings.ToLower(f["User"]), strings.ToLower(f["ParentUser"])
	logon := strings.ToLower(f["LogonId"])
	if o.Instance == "" || o.ParentInstance == "" || o.Instance == o.ParentInstance || digest == "" ||
		e.WindowsRecordID == "" || e.HostName == "" || f["CommandLine"] == "" || f["CommandLine"] == "-" ||
		f["ParentCommandLine"] == "" || f["ParentCommandLine"] == "-" || f["TerminalSessionId"] != "0" ||
		!serviceImage(e.Exe) || !serviceImage(e.ParentProcess) || !absoluteWindowsPath(f["CurrentDirectory"]) ||
		user == "" || user != parentUser || !serviceToken(user, logon, f["IntegrityLevel"]) {
		return o
	}
	parent, _ := json.Marshal([]string{e.ParentProcess, f["ParentCommandLine"], parentUser})
	o.Context = behaviorlearning.Context{
		Service: string(parent), Parent: string(parent), Executable: e.Exe, Digest: digest,
		Args: []string{f["CommandLine"]}, CWD: f["CurrentDirectory"], Session: "service_noninteractive",
		Capability: "windows-sysmon-sha256-v1",
		Windows: &behaviorlearning.WindowsContext{User: user, ParentUser: parentUser,
			Integrity: f["IntegrityLevel"], LogonID: logon, SessionID: "0"},
	}
	o.Complete, o.Reason = true, ""
	return o
}

// processInstance uses GUIDs, never bare PIDs, across host reboots and PID reuse.
func processInstance(host, guid string) string {
	v := strings.ReplaceAll(strings.Trim(guid, "{}"), "-", "")
	b, err := hex.DecodeString(v)
	if err != nil || len(b) != 16 || strings.Trim(v, "0") == "" || host == "" {
		return ""
	}
	return strings.ToLower(host + ":" + guid)
}

func sysmonSHA256(hashes string) string {
	for _, field := range strings.Split(hashes, ",") {
		name, value, ok := strings.Cut(strings.TrimSpace(field), "=")
		if ok && strings.EqualFold(name, "SHA256") {
			b, err := hex.DecodeString(value)
			if err == nil && len(b) == 32 {
				return strings.ToLower(value)
			}
		}
	}
	return ""
}

// serviceToken excludes interactive/custom-domain tokens even when they run in
// session zero. Localization or incomplete identity fails open rather than guessing.
func serviceToken(user, logon, integrity string) bool {
	switch logon {
	case "0x3e7":
		return user == `nt authority\system` && strings.EqualFold(integrity, "System")
	case "0x3e4":
		return user == `nt authority\network service` && strings.EqualFold(integrity, "System")
	case "0x3e5":
		return user == `nt authority\local service` && strings.EqualFold(integrity, "System")
	}
	return false
}

func absoluteWindowsPath(path string) bool {
	return len(path) > 3 && ((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z')) && path[1:3] == `:\` && !strings.Contains(path[3:], ":") && !strings.Contains(path, `\..`)
}

// serviceImage narrows automatic admission; digest and exact context still bind
// every match. User-writable locations and UNC/ADS images stay full-output.
func serviceImage(path string) bool {
	if !absoluteWindowsPath(path) || !strings.HasSuffix(strings.ToLower(path), ".exe") {
		return false
	}
	suffix := strings.ToLower(path[3:])
	return strings.HasPrefix(suffix, `windows\system32\`) || strings.HasPrefix(suffix, `program files\`) || strings.HasPrefix(suffix, `program files (x86)\`)
}

// blockedWindows checks both the filename and Sysmon's original PE filename,
// plus exact command content. It is a conservative bypass, not malware detection.
func blockedWindows(image, original, command string) bool {
	for _, path := range []string{image, original} {
		name := strings.TrimSuffix(strings.ToLower(windowsBase(path)), ".exe")
		for _, blocked := range []string{"cmd", "powershell", "pwsh", "wscript", "cscript", "mshta", "rundll32", "regsvr32", "certutil", "bitsadmin", "msbuild", "installutil", "wmic", "reg", "schtasks", "sc", "net", "net1", "whoami", "curl", "wget", "ssh", "scp", "psexec", "python", "python3", "perl", "ruby", "node", "java", "javaw", "bash", "wsl", "dllhost", "forfiles", "msiexec"} {
			if name == blocked {
				return true
			}
		}
	}
	lower := strings.ToLower(command)
	for _, token := range []string{"http://", "https://", "ftp://", " -enc", " -encodedcommand", "javascript:", "vbscript:", ".ps1", ".bat", ".cmd", ".vbs", " -executionpolicy", " -nop", " -command", " /c ", " /k ", "|", ">", "<", "&"} {
		if strings.Contains(lower, token) {
			return true
		}
	}
	return false
}

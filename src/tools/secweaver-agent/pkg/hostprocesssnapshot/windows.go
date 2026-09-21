package hostprocesssnapshot

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"secweaver-agent/internal/agentactivity"
)

type windowsProcess struct {
	PID            int    `json:"pid"`
	PPID           int    `json:"ppid"`
	Name           string `json:"name"`
	ExecutablePath string `json:"exe"`
	CommandLine    string `json:"command_line"`
	CreationDate   string `json:"start_time"`
	WorkingSetSize int64  `json:"rss_bytes"`
	VirtualSize    int64  `json:"virtual_bytes"`
	ThreadCount    int    `json:"thread_count"`
	SessionID      int    `json:"session_id"`
	CPUTimeMS      int64  `json:"cpu_time_ms"`
	User           string `json:"user"`
}

const windowsProcessScript = `$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false); $owners=@{}; Get-Process -IncludeUserName -ErrorAction SilentlyContinue | ForEach-Object { $owners[[int]$_.Id]=$_.UserName }; @(Get-CimInstance Win32_Process | Where-Object { $_.ProcessId -ne $PID } | ForEach-Object { [pscustomobject]@{ pid=[int]$_.ProcessId; ppid=[int]$_.ParentProcessId; name=[string]$_.Name; exe=[string]$_.ExecutablePath; command_line=[string]$_.CommandLine; start_time=if ($_.CreationDate) {$_.CreationDate.ToUniversalTime().ToString('o')} else {''}; rss_bytes=[int64]$_.WorkingSetSize; virtual_bytes=[int64]$_.VirtualSize; thread_count=[int]$_.ThreadCount; session_id=[int]$_.SessionId; cpu_time_ms=[int64](($_.KernelModeTime + $_.UserModeTime) / 10000); user=[string]$owners[[int]$_.ProcessId] } }) | ConvertTo-Json -Compress -Depth 3`

func init() {
	// Registration is process-wide because the unified Event Log reader runs in
	// the same binary but must not import this collector package.
	agentactivity.RegisterPowerShellScript(windowsProcessScript)
}

func collectWindowsProcesses(ctx context.Context, now time.Time) ([]processInfo, error) {
	markedScript := agentactivity.MarkPowerShellScript(windowsProcessScript)
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", markedScript)
	body, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return nil, fmt.Errorf("PowerShell process query failed: %s", strings.TrimSpace(string(exitErr.Stderr)))
		}
		return nil, err
	}
	var rows []windowsProcess
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return rowsToProcessInfo(rows, now), nil
	}
	if trimmed[0] == '[' {
		if err := json.Unmarshal(trimmed, &rows); err != nil {
			return nil, fmt.Errorf("decode PowerShell process array: %w", err)
		}
	} else {
		var row windowsProcess
		if err := json.Unmarshal(trimmed, &row); err != nil {
			return nil, fmt.Errorf("decode PowerShell process object: %w", err)
		}
		rows = append(rows, row)
	}
	return rowsToProcessInfo(rows, now), nil
}

func rowsToProcessInfo(rows []windowsProcess, now time.Time) []processInfo {
	out := make([]processInfo, 0, len(rows))
	for _, row := range rows {
		process := processInfo{
			PID: row.PID, PPID: row.PPID, User: row.User, Process: row.Name, Comm: row.Name,
			Exe: row.ExecutablePath, CommandLine: row.CommandLine, StartTime: row.CreationDate,
			CPUTimeMS: row.CPUTimeMS, RSSBytes: row.WorkingSetSize, VirtualBytes: row.VirtualSize,
			ThreadCount: row.ThreadCount, SessionID: row.SessionID,
		}
		if started, err := time.Parse(time.RFC3339Nano, row.CreationDate); err == nil && now.After(started) {
			process.ElapsedSeconds = int64(now.Sub(started).Seconds())
		}
		process.IsAgent = strings.EqualFold(filepath.Base(process.Exe), "secweaver-agent.exe") || strings.EqualFold(process.Process, "secweaver-agent.exe")
		out = append(out, process)
	}
	return out
}

package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	agentoutput "secweaver-agent/pkg/output"
)

// doctorLog is a best-effort filesystem snapshot. Nullable current size and
// ScanComplete distinguish unavailable evidence from a genuinely empty log.
type doctorLog struct {
	Name string `json:"name"`
	Path string `json:"path"`
	agentoutput.RetentionLimits
	CurrentSizeBytes     *int64 `json:"current_size_bytes"`
	BackupCount          int    `json:"backup_count"`
	BackupSizeBytes      int64  `json:"backup_size_bytes"`
	TotalSizeBytes       int64  `json:"total_size_bytes"`
	LatestBackupPath     string `json:"latest_backup_path,omitempty"`
	LastRotationEstimate string `json:"last_rotation_estimate,omitempty"`
	RotationTimeSource   string `json:"rotation_time_source"`
	ScanComplete         bool   `json:"scan_complete"`
	InspectionError      string `json:"inspection_error,omitempty"`
}

// doctorInspectLogs shares the runtime inventory but never initializes writers.
// Limits describe the on-disk config: a running service may still need restart
// after an operator edits it, and file sizes may change during this snapshot.
func doctorInspectLogs(cfg agentConfig, configPath string, modules []runtimeModule, updater *scheduledUpdateConfig, add func(doctorLevel, string, string, string)) []doctorLog {
	operations, err := normalizeOperationsReportConfig(cfg.Operations)
	if err != nil {
		add(doctorError, "config/operations_report", "operations report settings are invalid", err.Error())
		return nil
	}
	outputs := configuredLogOutputs(modules, updater, &operations, configuredAlertOutput(cfg, configPath))
	logs := make([]doctorLog, 0, len(outputs))
	for _, item := range outputs {
		limits, err := agentoutput.EffectiveRetention(cfg.DiskBudget, len(outputs), item.MaxSizeBytes, item.MaxBackups)
		if err != nil {
			add(doctorError, "config/disk_budget", "output disk budget is invalid", err.Error())
			return nil
		}
		entry := inspectDoctorLog(item, limits)
		if !entry.ScanComplete {
			add(doctorWarn, "log-retention/"+item.Name, "log inventory is incomplete", item.Path+": "+entry.InspectionError)
		}
		logs = append(logs, entry)
	}
	return logs
}

const doctorLogDirectoryScanLimit = 16384

// inspectDoctorLog only reads metadata; it must not chmod, prune or create files.
// Directory traversal has bounded memory and work. Nonregular paths are never
// followed, and racing rotations produce partial evidence rather than failure
// of doctor itself. Backup mtime is explicitly an estimate, not rename time.
func inspectDoctorLog(item managedLogOutput, limits agentoutput.RetentionLimits) doctorLog {
	return inspectDoctorLogWithLimit(item, limits, doctorLogDirectoryScanLimit)
}

// inspectDoctorLogWithLimit allows small deterministic resource-bound fixtures;
// production callers always use the fixed limit through inspectDoctorLog.
func inspectDoctorLogWithLimit(item managedLogOutput, limits agentoutput.RetentionLimits, scanLimit int) doctorLog {
	entry := doctorLog{Name: item.Name, Path: item.Path, RetentionLimits: limits, ScanComplete: true, RotationTimeSource: "unknown"}
	fail := func(err error) {
		entry.ScanComplete = false
		if entry.InspectionError == "" {
			entry.InspectionError = err.Error()
		}
	}
	info, err := os.Lstat(item.Path)
	if err == nil && info.Mode().IsRegular() {
		size := info.Size()
		entry.CurrentSizeBytes = &size
		entry.TotalSizeBytes = size
	} else if err != nil && !os.IsNotExist(err) {
		fail(err)
	} else if err == nil {
		fail(fmt.Errorf("active log is not a regular file"))
	}
	// .1 is the writer's newest retained generation. Its mtime predates rename;
	// absence means unknown rotation history, not proof that rotation never ran.
	latest := item.Path + ".1"
	if info, err := os.Lstat(latest); err == nil && info.Mode().IsRegular() {
		entry.LatestBackupPath = latest
		entry.LastRotationEstimate = info.ModTime().UTC().Format(time.RFC3339Nano)
		entry.RotationTimeSource = "backup_mtime_estimate"
	}
	dir, err := os.Open(filepath.Dir(item.Path))
	if err != nil {
		if !os.IsNotExist(err) {
			fail(err)
		}
		return entry
	}
	defer dir.Close()
	prefix := filepath.Base(item.Path) + "."
	scanned := 0
	for {
		batch, readErr := dir.ReadDir(128)
		for _, child := range batch {
			if scanned >= scanLimit {
				fail(fmt.Errorf("directory scan limit reached (%d entries); counts and totals are partial", scanLimit))
				return entry
			}
			scanned++
			if !strings.HasPrefix(child.Name(), prefix) {
				continue
			}
			index, err := strconv.Atoi(strings.TrimPrefix(child.Name(), prefix))
			if err != nil || index < 1 {
				continue
			}
			// Lstat at inspection time, not DirEntry.Info: never follow a link
			// swapped in after enumeration, and tolerate concurrent renames.
			backup, err := os.Lstat(filepath.Join(filepath.Dir(item.Path), child.Name()))
			if os.IsNotExist(err) {
				continue
			}
			if err != nil {
				fail(err)
				continue
			}
			if !backup.Mode().IsRegular() {
				fail(fmt.Errorf("backup %s is not a regular file", child.Name()))
				continue
			}
			entry.BackupCount++
			entry.BackupSizeBytes += backup.Size()
			entry.TotalSizeBytes += backup.Size()
		}
		if readErr != nil {
			if readErr != io.EOF {
				fail(readErr)
			}
			return entry
		}
	}
}

// printDoctorLogs keeps retention visible even without -verbose. Bytes remain
// exact in text/JSON; unknown values must not look like zero-sized healthy logs.
func printDoctorLogs(out io.Writer, logs []doctorLog) {
	if len(logs) == 0 {
		return
	}
	fmt.Fprintln(out, "log retention (configured limits; filesystem snapshot; sizes in bytes):")
	for _, entry := range logs {
		size := "unknown/missing"
		if entry.CurrentSizeBytes != nil {
			size = strconv.FormatInt(*entry.CurrentSizeBytes, 10)
		}
		rotation := "unknown"
		if entry.LastRotationEstimate != "" {
			rotation = entry.LastRotationEstimate + " (backup-mtime estimate)"
		}
		fmt.Fprintf(out, "  %s: current=%s limit=%d backups=%d/%d total=%d budget=%d last_rotation=%s scan_complete=%t\n    %s\n",
			entry.Name, size, entry.MaxSizeBytes, entry.BackupCount, entry.MaxBackups, entry.TotalSizeBytes, entry.PerFileBudgetBytes, rotation, entry.ScanComplete, entry.Path)
	}
}

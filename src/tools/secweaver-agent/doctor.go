package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"time"

	"secweaver-agent/pkg/agentlicense"
	"secweaver-agent/pkg/layout"
)

type doctorLevel string

const (
	doctorOK    doctorLevel = "OK"
	doctorWarn  doctorLevel = "WARN"
	doctorError doctorLevel = "ERROR"
)

type doctorCheck struct {
	Level     doctorLevel `json:"level"`
	Component string      `json:"component"`
	Message   string      `json:"message"`
	Detail    string      `json:"detail,omitempty"`
}

type doctorReport struct {
	ConfigPath string        `json:"config_path"`
	Platform   string        `json:"platform"`
	Version    string        `json:"version"`
	Generated  string        `json:"generated_at"`
	Checks     []doctorCheck `json:"checks"`
}

func runDoctorCommand(args []string) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := defaultAgentConfigPath()
	verbose := false
	jsonOutput := false
	checkLicense := true
	fs.StringVar(&configPath, "config", configPath, "agent JSON config path")
	fs.BoolVar(&verbose, "verbose", false, "include OK checks in text output")
	fs.BoolVar(&jsonOutput, "json", false, "emit machine-readable JSON")
	fs.BoolVar(&checkLicense, "check-license", true, "check authorization service connectivity when license is enabled")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	report := collectDoctorReport(configPath, checkLicense)
	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			fmt.Fprintf(os.Stderr, "doctor json encode failed: %v\n", err)
			return 1
		}
	} else {
		printDoctorReport(os.Stdout, report, verbose)
	}
	if doctorHasErrors(report) {
		return 1
	}
	return 0
}

func collectDoctorReport(configPath string, checkLicense bool) doctorReport {
	report := doctorReport{
		ConfigPath: configPath,
		Platform:   runtime.GOOS + "_" + runtime.GOARCH,
		Version:    version,
		Generated:  time.Now().UTC().Format(time.RFC3339),
	}
	add := func(level doctorLevel, component, message, detail string) {
		report.Checks = append(report.Checks, doctorCheck{
			Level:     level,
			Component: component,
			Message:   message,
			Detail:    strings.TrimSpace(detail),
		})
	}

	cfg, modules, updater, configOK := doctorCheckConfig(configPath, add)
	if configOK {
		mode := cfg.DeploymentMode
		if mode == "" {
			mode = "unspecified (legacy/standalone)"
		}
		add(doctorOK, "deployment_mode", "Agent installation channel", mode)
		preflight := collectPreflightReport(configPath, modules, updater)
		for _, check := range preflight.Checks {
			add(doctorLevel(check.Level), "preflight/"+check.Component, check.Message, check.Detail)
		}
		if runtime.GOOS == "windows" {
			sysmon := false
			for _, check := range preflight.Checks {
				if check.Component == "windows-channel/Microsoft-Windows-Sysmon/Operational" && check.Level == preflightOK {
					sysmon = true
				}
			}
			doctorCheckWindowsLearning(cfg, modules, sysmon, add)
		}
		doctorCheckService(add)
		doctorCheckSLSIdentity(cfg, configPath, add)
		doctorCheckStatusFile(cfg, add)
		doctorCheckRecentLogs(modules, add)
		if checkLicense {
			doctorCheckLicenseConnectivity(cfg, add)
		}
	}

	sort.SliceStable(report.Checks, func(i, j int) bool {
		if report.Checks[i].Level != report.Checks[j].Level {
			return doctorRank(report.Checks[i].Level) > doctorRank(report.Checks[j].Level)
		}
		return report.Checks[i].Component < report.Checks[j].Component
	})
	return report
}

func doctorCheckConfig(configPath string, add func(doctorLevel, string, string, string)) (agentConfig, []runtimeModule, *scheduledUpdateConfig, bool) {
	cfg, err := loadConfig(configPath)
	if err != nil {
		add(doctorError, "config", "agent config cannot be loaded", fmt.Sprintf("%s: %v", configPath, err))
		return agentConfig{}, nil, nil, false
	}
	add(doctorOK, "config", "agent config loaded", configPath)
	modules, err := enabledModules(cfg)
	if err != nil {
		add(doctorError, "config/modules", "enabled modules are invalid", err.Error())
		return cfg, nil, nil, false
	}
	add(doctorOK, "config/modules", "enabled modules are valid", doctorModuleNames(modules))
	updater, err := scheduledUpdateFromConfig(cfg.Update)
	if err != nil {
		add(doctorError, "config/update", "update config is invalid", err.Error())
		return cfg, modules, nil, false
	}
	licenseCfg := cfg.License.Normalize()
	if err := licenseCfg.Validate(); err != nil {
		add(doctorError, "config/license", "license config is invalid", err.Error())
		return cfg, modules, updater, false
	}
	add(doctorOK, "config/license", "license config is valid", fmt.Sprintf("enabled=%v server=%s", licenseCfg.Enabled, licenseCfg.ServerURL))
	if _, err := scheduledRemoteConfigFromConfig(cfg.RemoteConfig, configPath, licenseCfg, cfg.EnterpriseID); err != nil {
		add(doctorError, "config/remote_config", "remote config settings are invalid", err.Error())
		return cfg, modules, updater, false
	}
	add(doctorOK, "config/remote_config", "remote config settings are valid", fmt.Sprintf("enabled=%v", cfg.RemoteConfig.Enabled))
	return cfg, modules, updater, true
}

func doctorCheckService(add func(doctorLevel, string, string, string)) {
	switch runtime.GOOS {
	case "linux":
		if _, err := exec.LookPath("systemctl"); err != nil {
			add(doctorWarn, "service", "systemctl not found", "cannot verify secweaver-agent.service")
			return
		}
		out, err := commandOutput(5*time.Second, "systemctl", "is-active", "secweaver-agent.service")
		state := strings.TrimSpace(string(out))
		if err == nil && state == "active" {
			add(doctorOK, "service", "secweaver-agent.service is active", state)
			return
		}
		add(doctorError, "service", "secweaver-agent.service is not active", stateOrError(state, err))
	case "windows":
		out, err := commandOutput(5*time.Second, "sc.exe", "query", layout.WindowsServiceName)
		text := strings.TrimSpace(string(out))
		if err == nil && strings.Contains(strings.ToUpper(text), "RUNNING") {
			add(doctorOK, "service", layout.WindowsServiceName+" Windows service is running", firstNonEmptyLine(text))
			return
		}
		add(doctorError, "service", layout.WindowsServiceName+" Windows service is not running", stateOrError(firstNonEmptyLine(text), err))
	default:
		add(doctorWarn, "service", "service check is unsupported on this platform", runtime.GOOS)
	}
}

func doctorCheckStatusFile(cfg agentConfig, add func(doctorLevel, string, string, string)) {
	path := strings.TrimSpace(cfg.StatusPath)
	if path == "" {
		path = defaultStatusPath()
	}
	data, err := os.ReadFile(path)
	if err != nil {
		add(doctorWarn, "status", "local Agent status file is not readable", fmt.Sprintf("%s: %v", path, err))
		return
	}
	var status agentStatusFile
	if err := json.Unmarshal(data, &status); err != nil {
		add(doctorWarn, "status", "local Agent status file is not valid JSON", fmt.Sprintf("%s: %v", path, err))
		return
	}
	add(doctorOK, "status", "local Agent status file is readable", fmt.Sprintf("%s modules=%d", path, len(status.Modules)))
	if strings.TrimSpace(status.License.LastError) != "" {
		add(doctorWarn, "status/license", "last license status contains an error", status.License.LastError)
	}
	moduleNames := make([]string, 0, len(status.Modules))
	for name := range status.Modules {
		moduleNames = append(moduleNames, name)
	}
	sort.Strings(moduleNames)
	for _, name := range moduleNames {
		health := status.Modules[name]
		detail := fmt.Sprintf("restarts=%d consecutive_failures=%d next_restart_at=%s circuit_open_until=%s last_error=%s",
			health.RestartCount, health.ConsecutiveFailures, health.NextRestartAt, health.CircuitOpenUntil, health.LastError)
		switch health.Status {
		case "error":
			add(doctorError, "status/module/"+name, "module is stopped with an error", detail)
		case "degraded":
			add(doctorWarn, "status/module/"+name, "module restart circuit is open", detail)
		case "restarting":
			add(doctorWarn, "status/module/"+name, "module is waiting to restart", detail)
		}
	}
	for name, diagnostic := range status.Diagnostics {
		level := doctorWarn
		if strings.EqualFold(diagnostic.Level, "error") {
			level = doctorError
		}
		add(level, "status/"+name, diagnostic.Message, fmt.Sprintf("updated_at=%s metrics=%v", diagnostic.UpdatedAt, diagnostic.Metrics))
	}
}

func doctorCheckLicenseConnectivity(cfg agentConfig, add func(doctorLevel, string, string, string)) {
	licenseCfg := cfg.License.Normalize()
	if !licenseCfg.Enabled {
		add(doctorOK, "license", "authorization service check skipped", "license.enabled=false")
		return
	}
	state, err := agentlicense.LoadState(licenseCfg.StatePath)
	if err != nil {
		add(doctorWarn, "license", "authorization state is not readable", fmt.Sprintf("%s: %v", licenseCfg.StatePath, err))
		return
	}
	if strings.TrimSpace(state.DeviceID) == "" {
		add(doctorWarn, "license", "authorization service check skipped because device_id is missing", "start secweaver-agent once to register this device")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := (agentlicense.Client{}).Heartbeat(ctx, licenseCfg, cfg.EnterpriseID, version, nil)
	if err != nil {
		var denied agentlicense.DeniedError
		if errors.As(err, &denied) {
			add(doctorError, "license", "authorization service denied this Agent", err.Error())
			return
		}
		add(doctorError, "license", "authorization service is not reachable or returned an error", err.Error())
		return
	}
	add(doctorOK, "license", "authorization service check succeeded", fmt.Sprintf("device_id=%s devices=%d/%d expires_at=%s", state.DeviceID, resp.UsedDevices, resp.MaxDevices, valueOrDash(resp.SubscriptionExpiresAt)))
}

func doctorCheckRecentLogs(modules []runtimeModule, add func(doctorLevel, string, string, string)) {
	paths := doctorOutputLogPaths(modules)
	if len(paths) == 0 {
		add(doctorWarn, "logs", "no file output paths could be derived from enabled modules", "check module args")
		return
	}
	for _, item := range paths {
		if item.Path == "-" {
			add(doctorOK, "logs/"+item.Module, "module outputs to stdout/stderr", "-")
			continue
		}
		info, err := os.Stat(item.Path)
		if err != nil {
			add(doctorWarn, "logs/"+item.Module, "output log is not readable", fmt.Sprintf("%s: %v", item.Path, err))
			continue
		}
		if info.IsDir() {
			add(doctorWarn, "logs/"+item.Module, "output log path is a directory", item.Path)
			continue
		}
		lines, err := readRecentLines(item.Path, 5, 64*1024)
		if err != nil {
			add(doctorWarn, "logs/"+item.Module, "failed to read recent output log lines", fmt.Sprintf("%s: %v", item.Path, err))
			continue
		}
		validJSON := 0
		for _, line := range lines {
			if json.Valid([]byte(line)) {
				validJSON++
			}
		}
		if len(lines) == 0 {
			add(doctorWarn, "logs/"+item.Module, "output log exists but has no recent lines", item.Path)
			continue
		}
		if validJSON == 0 {
			add(doctorWarn, "logs/"+item.Module, "recent output lines are not JSON", fmt.Sprintf("%s size=%d lines=%d", item.Path, info.Size(), len(lines)))
			continue
		}
		add(doctorOK, "logs/"+item.Module, "recent output log contains JSON events", fmt.Sprintf("%s size=%d recent_json_lines=%d/%d", item.Path, info.Size(), validJSON, len(lines)))
	}
}

type doctorOutputPath struct {
	Module string
	Path   string
}

func doctorOutputLogPaths(modules []runtimeModule) []doctorOutputPath {
	var out []doctorOutputPath
	seen := map[string]bool{}
	add := func(module, path string) {
		path = strings.TrimSpace(path)
		if path == "" {
			return
		}
		key := module + "\x00" + path
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, doctorOutputPath{Module: module, Path: path})
	}
	for _, module := range modules {
		if module.Spec.OutputPaths == nil {
			continue
		}
		for _, path := range module.Spec.OutputPaths(module.Config.Args) {
			add(module.Spec.Name, path)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Module != out[j].Module {
			return out[i].Module < out[j].Module
		}
		return out[i].Path < out[j].Path
	})
	return out
}

func defaultHostProcessSnapshotOutputLogPath() string {
	if runtime.GOOS == "windows" {
		return layout.WindowsLogs + `\host-process-snapshot.log`
	}
	return layout.LinuxLogs + "/host-process-snapshot.log"
}

func defaultHostProcessSnapshotStatePath() string {
	if runtime.GOOS == "windows" {
		return layout.WindowsData + `\host-process-snapshot-state.json`
	}
	return layout.LinuxData + "/host-process-snapshot-state.json"
}

func defaultHostStateSnapshotOutputLogPath() string {
	if runtime.GOOS == "windows" {
		return layout.WindowsLogs + `\host-state-snapshot.log`
	}
	return layout.LinuxLogs + "/host-state-snapshot.log"
}

func readRecentLines(path string, maxLines int, maxBytes int64) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	start := int64(0)
	if info.Size() > maxBytes {
		start = info.Size() - maxBytes
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return nil, err
	}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var lines []string
	skippedPartial := start == 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !skippedPartial {
			skippedPartial = true
			continue
		}
		if line != "" {
			lines = append(lines, line)
		}
		if len(lines) > maxLines {
			copy(lines, lines[len(lines)-maxLines:])
			lines = lines[:maxLines]
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return lines, nil
}

func printDoctorReport(out io.Writer, report doctorReport, verbose bool) {
	ok, warn, errCount := doctorCounts(report)
	fmt.Fprintf(out, "secweaver-agent doctor: platform=%s version=%s config=%s\n", report.Platform, report.Version, report.ConfigPath)
	for _, check := range report.Checks {
		if !verbose && check.Level == doctorOK {
			continue
		}
		fmt.Fprintf(out, "[%s] %s: %s", check.Level, check.Component, check.Message)
		if check.Detail != "" {
			fmt.Fprintf(out, " (%s)", check.Detail)
		}
		fmt.Fprintln(out)
	}
	fmt.Fprintf(out, "doctor summary: ok=%d warn=%d error=%d\n", ok, warn, errCount)
}

func doctorCounts(report doctorReport) (ok, warn, errCount int) {
	for _, check := range report.Checks {
		switch check.Level {
		case doctorOK:
			ok++
		case doctorWarn:
			warn++
		case doctorError:
			errCount++
		}
	}
	return ok, warn, errCount
}

func doctorHasErrors(report doctorReport) bool {
	_, _, errCount := doctorCounts(report)
	return errCount > 0
}

func doctorRank(level doctorLevel) int {
	switch level {
	case doctorError:
		return 3
	case doctorWarn:
		return 2
	case doctorOK:
		return 1
	default:
		return 0
	}
}

func doctorModuleNames(modules []runtimeModule) string {
	names := make([]string, 0, len(modules))
	for _, module := range modules {
		names = append(names, module.Spec.Name)
	}
	sort.Strings(names)
	return strings.Join(names, ",")
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func stateOrError(state string, err error) string {
	state = strings.TrimSpace(state)
	if err != nil {
		if state == "" {
			return err.Error()
		}
		return state + ": " + err.Error()
	}
	return state
}

func firstNonEmptyLine(text string) string {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			return line
		}
	}
	return ""
}

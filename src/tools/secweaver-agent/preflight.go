package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

type preflightLevel string

const (
	preflightOK    preflightLevel = "OK"
	preflightWarn  preflightLevel = "WARN"
	preflightError preflightLevel = "ERROR"
)

type preflightCheck struct {
	Level     preflightLevel
	Component string
	Message   string
	Detail    string
}

type preflightReport struct {
	ConfigPath string
	Platform   string
	Version    string
	Support    string
	Modules    []string
	Checks     []preflightCheck
}

func collectPreflightReport(configPath string, modules []runtimeModule, updater *scheduledUpdateConfig) preflightReport {
	report := preflightReport{
		ConfigPath: configPath,
		Platform:   runtime.GOOS + "_" + runtime.GOARCH,
		Version:    version,
		Support:    platformSupportLabel(),
	}
	for _, module := range modules {
		report.Modules = append(report.Modules, module.Spec.Name)
	}
	sort.Strings(report.Modules)

	add := func(level preflightLevel, component, message, detail string) {
		report.Checks = append(report.Checks, preflightCheck{
			Level:     level,
			Component: component,
			Message:   message,
			Detail:    detail,
		})
	}

	checkPlatformSupport(add)
	checkModulePlatforms(modules, add)
	switch runtime.GOOS {
	case "linux":
		checkLinuxRuntime(modules, add)
	case "windows":
		checkWindowsRuntime(modules, add)
	}
	checkScheduledUpdate(updater, add)
	return report
}

func platformSupportLabel() string {
	switch runtime.GOOS {
	case "linux":
		if runningInContainer() {
			return "supported: Linux container workload sensor"
		}
		return "supported: Linux systemd host"
	case "windows":
		return "supported: Windows service host"
	default:
		return "unsupported collection platform"
	}
}

func checkPlatformSupport(add func(preflightLevel, string, string, string)) {
	switch runtime.GOOS {
	case "linux":
		if runningInContainer() {
			add(preflightOK, "platform", "Linux container workload collection platform detected", "the container profile collects its own namespace; host audit and persistence coverage require a host-installed Agent")
			return
		}
		add(preflightOK, "platform", "Linux collection platform detected", "release installer expects a systemd host")
		if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" && runtime.GOARCH != "loong64" {
			add(preflightWarn, "platform", "Linux architecture is not in the packaged target list", "build-cross.sh currently packages linux/amd64, linux/arm64, and linux/loong64")
		}
	case "windows":
		add(preflightOK, "platform", "Windows collection platform detected", "Windows modules use wevtutil and the Windows Service Control Manager")
		if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
			add(preflightWarn, "platform", "Windows architecture is not in the packaged target list", "build-cross.sh currently packages windows/amd64 and windows/arm64")
		}
	default:
		add(preflightError, "platform", "current OS is not a supported collection platform", "official collection support is Linux systemd and Windows service hosts")
	}
}

func checkModulePlatforms(modules []runtimeModule, add func(preflightLevel, string, string, string)) {
	for _, module := range modules {
		platforms := module.Spec.Platforms
		if len(platforms) == 0 {
			add(preflightWarn, "module/"+module.Spec.Name, "module has no platform metadata", "add the module to modulePlatform for preflight checks")
			continue
		}
		if !moduleSupportsPlatform(module.Spec.Name, runtime.GOOS) {
			add(preflightError, "module/"+module.Spec.Name, "module is enabled for the wrong operating system", fmt.Sprintf("%s only runs on %s, current platform is %s", module.Spec.Name, modulePlatformLabel(module.Spec.Name), runtime.GOOS))
			continue
		}
		add(preflightOK, "module/"+module.Spec.Name, "module matches current operating system", modulePlatformLabel(module.Spec.Name))
	}
}

func checkLinuxRuntime(modules []runtimeModule, add func(preflightLevel, string, string, string)) {
	if !hasLinuxModule(modules) {
		return
	}
	if runningInContainer() {
		checkLinuxContainerRuntime(modules, add)
		return
	}
	checkLinuxSystemd(add)
	if os.Geteuid() != 0 {
		add(preflightWarn, "permission", "process is not running as root", "auditd, /proc process ownership, protected logs, and persistence paths normally require root")
	}
	if moduleEnabled(modules, "audit-port-execmon") {
		checkLinuxProcAndNetstat(add)
		checkLinuxEBPF(modules, add)
	}
	if moduleEnabled(modules, "audit-port-execmon") || moduleEnabled(modules, "host-persistence") {
		checkLinuxAudit(modules, add)
	}
	if moduleEnabled(modules, "syslog-risk-json") {
		checkLinuxSyslog(modules, add)
	}
	if moduleEnabled(modules, "host-persistence") {
		checkHostPersistenceConfig(modules, add)
	}
}

// checkLinuxContainerRuntime defines the supported Docker/Kubernetes boundary.
// A normal container only owns its namespaces, so accepting host audit or
// persistence modules would produce misleading host-security coverage. The
// supported profile deliberately limits collection to container-local process
// and state snapshots and makes incompatible selections visible to -strict.
func checkLinuxContainerRuntime(modules []runtimeModule, add func(preflightLevel, string, string, string)) {
	add(preflightOK, "container", "container workload profile is active", "runs without systemd, host PID/network namespaces, or Linux capabilities; persist /var/lib/secweaver-agent with a volume")
	if _, err := os.Stat("/proc/1/status"); err != nil {
		add(preflightError, "container/procfs", "/proc is not available in the container", "host-process-snapshot and host-state-snapshot require the container procfs")
	} else {
		add(preflightOK, "container/procfs", "container procfs is available", "process and socket snapshots are scoped to this container namespace")
	}
	for _, moduleName := range containerIncompatibleModules(modules) {
		add(preflightError, "container/module/"+moduleName, "module is not supported in the container workload profile", "install secweaver-agent on the Linux host for auditd-backed listener execution or host-persistence monitoring")
	}
	if moduleEnabled(modules, "syslog-risk-json") {
		checkLinuxSyslog(modules, add)
	}
}

// containerIncompatibleModules is intentionally narrow: syslog files may be
// explicitly bind-mounted by an application owner, while auditd rule control
// and host persistence watches are always host-security responsibilities.
func containerIncompatibleModules(modules []runtimeModule) []string {
	var incompatible []string
	for _, name := range []string{"audit-port-execmon", "host-persistence"} {
		if moduleEnabled(modules, name) {
			incompatible = append(incompatible, name)
		}
	}
	return incompatible
}

func checkLinuxEBPF(modules []runtimeModule, add func(preflightLevel, string, string, string)) {
	module, ok := runtimeModuleByName(modules, "audit-port-execmon")
	if !ok {
		return
	}
	backend := "auto"
	if configPath, found := stringFlag(module.Config.Args, "config"); found {
		if body, err := os.ReadFile(strings.TrimSpace(configPath)); err == nil {
			var cfg struct {
				Exec struct {
					Backend string `json:"process_tree_backend"`
				} `json:"exec"`
			}
			if json.Unmarshal(body, &cfg) == nil && strings.TrimSpace(cfg.Exec.Backend) != "" {
				backend = strings.ToLower(strings.TrimSpace(cfg.Exec.Backend))
			}
		}
	}
	if backend == "audit" || backend == "audit_pid" {
		add(preflightOK, "ebpf", "eBPF process tracking is disabled by configuration", "exec.process_tree_backend="+backend)
		return
	}
	level := preflightWarn
	if backend == "ebpf" {
		level = preflightError
	}
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		add(level, "ebpf", "architecture is not release-tested for eBPF process tracking", fmt.Sprintf("linux/%s will use audit fallback when backend=auto", runtime.GOARCH))
		return
	}
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		add(level, "ebpf/btf", "kernel BTF is unavailable", "/sys/kernel/btf/vmlinux is required for CO-RE; backend=auto falls back to audit")
		return
	}
	if !linuxTracepointExists("syscalls", "sys_enter_execve") {
		add(level, "ebpf/tracepoint", "execve tracepoint is unavailable", "syscalls/sys_enter_execve is required; backend=auto falls back to audit")
		return
	}
	if !linuxTracepointExists("syscalls", "sys_exit_execve") {
		add(level, "ebpf/tracepoint", "execve exit tracepoint is unavailable", "syscalls/sys_exit_execve is required to discard failed exec attempts; backend=auto falls back to audit")
		return
	}
	if !linuxTracepointExists("sched", "sched_process_exec") {
		add(level, "ebpf/tracepoint", "successful exec tracepoint is unavailable", "sched/sched_process_exec is required; backend=auto falls back to audit")
		return
	}
	add(preflightOK, "ebpf", "kernel exposes required eBPF CO-RE capabilities", fmt.Sprintf("backend=%s btf=/sys/kernel/btf/vmlinux", backend))
	if !linuxTracepointExists("syscalls", "sys_enter_execveat") || !linuxTracepointExists("syscalls", "sys_exit_execveat") {
		add(preflightWarn, "ebpf/execveat", "execveat tracepoint pair is unavailable", "execve remains monitored; execveat coverage is disabled")
	}
}

func linuxTracepointExists(group, name string) bool {
	for _, root := range []string{"/sys/kernel/tracing/events", "/sys/kernel/debug/tracing/events"} {
		if _, err := os.Stat(filepath.Join(root, group, name, "format")); err == nil {
			return true
		}
	}
	return false
}

func checkLinuxSystemd(add func(preflightLevel, string, string, string)) {
	if _, err := exec.LookPath("systemctl"); err != nil {
		add(preflightWarn, "systemd", "systemctl not found", "release install.sh supports systemd service installation by default")
		return
	}
	if linuxSystemdRunning() {
		add(preflightOK, "systemd", "systemd appears to be running", "systemd service installation is supported")
		return
	}
	add(preflightWarn, "systemd", "systemd does not appear to be PID 1", "direct module runs may work, but release service installation is unsupported unless REQUIRE_SYSTEMD=0 is used")
}

func linuxSystemdRunning() bool {
	if _, err := os.Stat("/run/systemd/system"); err == nil {
		return true
	}
	if data, err := os.ReadFile("/proc/1/comm"); err == nil && strings.TrimSpace(string(data)) == "systemd" {
		return true
	}
	if target, err := os.Readlink("/proc/1/exe"); err == nil && strings.HasSuffix(target, "/systemd") {
		return true
	}
	return false
}

func checkLinuxProcAndNetstat(add func(preflightLevel, string, string, string)) {
	if _, err := os.Stat("/proc/net/tcp"); err != nil {
		add(preflightError, "procfs", "/proc/net/tcp is unavailable", "audit-port-execmon cannot discover TCP listeners without host procfs")
	} else {
		add(preflightOK, "procfs", "/proc/net/tcp is available", "listener discovery can fall back to procfs")
	}
	if _, err := exec.LookPath("netstat"); err != nil {
		add(preflightWarn, "netstat", "netstat not found", "install.sh installs net-tools by default; procfs fallback still provides listener discovery")
	} else {
		add(preflightOK, "netstat", "netstat found", "listener discovery can use netstat -tlnp")
	}
}

func checkLinuxAudit(modules []runtimeModule, add func(preflightLevel, string, string, string)) {
	hardFail := moduleEnabled(modules, "audit-port-execmon")
	levelForAudit := preflightWarn
	if hardFail {
		levelForAudit = preflightError
	}
	if _, err := exec.LookPath("auditctl"); err != nil {
		add(levelForAudit, "auditd", "auditctl not found", "install auditd/audit and start auditd.service before enabling audit-based modules")
		return
	}
	add(preflightOK, "auditd", "auditctl found", "audit status will be queried with auditctl -s")

	out, err := commandOutput(2*time.Second, "auditctl", "-s")
	if err != nil {
		add(levelForAudit, "auditd", "auditctl -s failed", strings.TrimSpace(string(out)+" "+err.Error()))
	} else {
		status := parseKeyValueLines(string(out))
		add(preflightOK, "auditd", "auditctl -s succeeded", fmt.Sprintf("enabled=%s backlog=%s backlog_limit=%s lost=%s", preflightValueOrUnknown(status["enabled"]), preflightValueOrUnknown(status["backlog"]), preflightValueOrUnknown(status["backlog_limit"]), preflightValueOrUnknown(status["lost"])))
		switch status["enabled"] {
		case "0":
			add(levelForAudit, "auditd", "auditd is disabled", "start auditd.service before running audit-based modules")
		case "2":
			add(preflightWarn, "auditd", "auditd is immutable", "dynamic audit rules may fail until reboot or audit policy change")
		}
		if lost, _ := strconv.Atoi(status["lost"]); lost > 0 {
			add(preflightWarn, "auditd", "audit has already lost events", fmt.Sprintf("lost=%d; consider reducing scope or increasing backlog", lost))
		}
	}

	for _, path := range auditLogPathsFromModules(modules) {
		checkAuditLogPath(path, levelForAudit, add)
	}
}

func checkAuditLogPath(path string, level preflightLevel, add func(preflightLevel, string, string, string)) {
	path = strings.TrimSpace(path)
	if path == "" {
		path = defaultLinuxAuditLogPath
	}
	dir := filepath.Dir(path)
	info, err := os.Stat(dir)
	if err != nil {
		add(level, "audit-log", "audit log directory is not accessible", fmt.Sprintf("%s: %v", dir, err))
		return
	}
	if !info.IsDir() {
		add(level, "audit-log", "audit log parent is not a directory", dir)
		return
	}
	if _, err := os.Stat(path); err != nil {
		add(level, "audit-log", "audit log file is not currently visible", fmt.Sprintf("%s: %v; journald-only audit logging is not parsed yet", path, err))
		return
	}
	add(preflightOK, "audit-log", "audit log file is visible", path)
}

func checkLinuxSyslog(modules []runtimeModule, add func(preflightLevel, string, string, string)) {
	module, ok := runtimeModuleByName(modules, "syslog-risk-json")
	if !ok {
		return
	}
	secure := syslogRequestedPath(module.Config.Args, "secure", "auto")
	messages := syslogRequestedPath(module.Config.Args, "messages", "auto")
	checkSyslogSource("secure/auth", secure, []string{"/var/log/secure", "/var/log/auth.log"}, add)
	checkSyslogSource("messages/syslog", messages, []string{"/var/log/messages", "/var/log/syslog"}, add)
}

func syslogRequestedPath(args []string, name, defaultValue string) string {
	if value, ok := stringFlag(args, name); ok {
		return strings.TrimSpace(value)
	}
	return defaultValue
}

func checkSyslogSource(kind, requested string, candidates []string, add func(preflightLevel, string, string, string)) {
	component := "syslog/" + kind
	switch strings.TrimSpace(requested) {
	case "":
		add(preflightOK, component, "source is disabled by configuration", "empty path")
		return
	case "auto":
		for _, candidate := range candidates {
			if readableFile(candidate) {
				add(preflightOK, component, "auto-detected syslog source", candidate)
				return
			}
		}
		add(preflightWarn, component, "auto-detection found no traditional syslog file", fmt.Sprintf("candidates=%s; journald-only input is not supported yet", strings.Join(candidates, ",")))
	default:
		if readableFile(requested) {
			add(preflightOK, component, "configured syslog source is readable", requested)
			return
		}
		add(preflightWarn, component, "configured syslog source is not readable", requested)
	}
}

func checkHostPersistenceConfig(modules []runtimeModule, add func(preflightLevel, string, string, string)) {
	module, ok := runtimeModuleByName(modules, "host-persistence")
	if !ok {
		return
	}
	configPath, ok := stringFlag(module.Config.Args, "config")
	if !ok || strings.TrimSpace(configPath) == "" {
		add(preflightOK, "host-persistence/config", "using built-in host persistence defaults", "no -config path supplied")
		return
	}
	configPath = strings.TrimSpace(configPath)
	body, err := os.ReadFile(configPath)
	if err != nil {
		add(preflightWarn, "host-persistence/config", "host-persistence config is not readable", fmt.Sprintf("%s: %v", configPath, err))
		return
	}
	var cfg struct {
		Watch []struct {
			Path string `json:"path"`
		} `json:"watch"`
	}
	if err := json.Unmarshal(body, &cfg); err != nil {
		add(preflightWarn, "host-persistence/config", "host-persistence config is not valid JSON", fmt.Sprintf("%s: %v", configPath, err))
		return
	}
	if len(cfg.Watch) == 0 {
		add(preflightWarn, "host-persistence/config", "host-persistence watch list is empty", configPath)
		return
	}
	add(preflightOK, "host-persistence/config", "host-persistence config is readable", fmt.Sprintf("%s watch_targets=%d", configPath, len(cfg.Watch)))
}

func checkWindowsRuntime(modules []runtimeModule, add func(preflightLevel, string, string, string)) {
	if !hasWindowsModule(modules) {
		return
	}
	needsEventLog := moduleEnabled(modules, "windows-eventlog-risk-json") || moduleEnabled(modules, "windows-process-execmon")
	if needsEventLog {
		if _, err := exec.LookPath("wevtutil"); err != nil {
			add(preflightError, "wevtutil", "wevtutil not found", "Windows Event Log modules require wevtutil in PATH")
		} else {
			add(preflightOK, "wevtutil", "wevtutil found", "Windows Event Log channels can be queried")
			for _, channel := range windowsChannelsFromModules(modules) {
				checkWindowsChannel(channel, add)
			}
		}
		checkWindowsProcessCommandLinePolicy(add)
	}
	if moduleEnabled(modules, "host-persistence") {
		checkHostPersistenceConfig(modules, add)
	}
}

func checkWindowsChannel(channel string, add func(preflightLevel, string, string, string)) {
	channel = strings.TrimSpace(channel)
	if channel == "" {
		return
	}
	level := preflightWarn
	if channel == "Security" {
		level = preflightError
	}
	out, err := commandOutput(2*time.Second, "wevtutil", "gli", channel)
	if err != nil {
		add(level, "windows-channel/"+channel, "Windows Event Log channel is not queryable", strings.TrimSpace(string(out)+" "+err.Error()))
		return
	}
	add(preflightOK, "windows-channel/"+channel, "Windows Event Log channel is queryable", channel)
}

func checkWindowsProcessCommandLinePolicy(add func(preflightLevel, string, string, string)) {
	out, err := commandOutput(2*time.Second, "reg", "query", `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit`, "/v", "ProcessCreationIncludeCmdLine_Enabled")
	if err != nil {
		add(preflightWarn, "windows-audit-policy", "cannot confirm process command-line auditing policy", "enable Audit Process Creation and Include command line in process creation events for complete 4688 command lines")
		return
	}
	text := strings.ToLower(string(out))
	if strings.Contains(text, "0x1") || strings.Contains(text, " 1") || strings.Contains(text, "\t1") {
		add(preflightOK, "windows-audit-policy", "process command-line auditing appears enabled", "ProcessCreationIncludeCmdLine_Enabled=1")
		return
	}
	add(preflightWarn, "windows-audit-policy", "process command-line auditing may be disabled", "Security 4688 events may lack command_line unless Include command line is enabled")
}

func checkScheduledUpdate(updater *scheduledUpdateConfig, add func(preflightLevel, string, string, string)) {
	if updater == nil {
		add(preflightOK, "update", "scheduled update is disabled", "update.enabled=false; generic templates default to disabled. Managed installation enables updates when a real manifest URL is supplied; upgrades without one preserve the previous setting.")
		return
	}
	add(preflightOK, "update", "scheduled update is enabled", fmt.Sprintf("manifest=%s channel=%s interval=%s auto_install=%v", updater.Options.ManifestURL, updater.Options.Channel, updater.Interval, updater.AutoInstall))
	if strings.Contains(updater.Options.ManifestURL, "example.com") {
		add(preflightWarn, "update", "manifest_url still points to an example domain", "configure the internal update server manifest URL before enabling production auto-update")
	}
	if runtime.GOOS == "windows" && updater.AutoInstall {
		// This is the supported update lifecycle, not an observed failure or
		// pending restart. Runtime update status remains responsible for errors.
		add(preflightOK, "update/windows", "Windows automatic updates use process exit and service restart", "future update activation replaces files after exit; this check does not indicate a current failure or pending restart")
	}
	if updater.Options.StateDir != "" && !filepath.IsAbs(updater.Options.StateDir) {
		add(preflightWarn, "update/state", "update state_dir is not absolute", updater.Options.StateDir)
	}
}

func printPreflightReport(out io.Writer, report preflightReport, verbose bool) {
	ok, warn, errCount := preflightCounts(report)
	fmt.Fprintf(out, "secweaver-agent preflight: platform=%s version=%s support=%s config=%s\n", report.Platform, report.Version, report.Support, report.ConfigPath)
	if len(report.Modules) > 0 {
		fmt.Fprintf(out, "enabled modules: %s\n", strings.Join(report.Modules, ", "))
	}
	for _, check := range report.Checks {
		if !verbose && check.Level == preflightOK {
			continue
		}
		fmt.Fprintf(out, "[%s] %s: %s", check.Level, check.Component, check.Message)
		if strings.TrimSpace(check.Detail) != "" {
			fmt.Fprintf(out, " (%s)", strings.TrimSpace(check.Detail))
		}
		fmt.Fprintln(out)
	}
	fmt.Fprintf(out, "preflight summary: ok=%d warn=%d error=%d\n", ok, warn, errCount)
}

func preflightCounts(report preflightReport) (ok, warn, errCount int) {
	for _, check := range report.Checks {
		switch check.Level {
		case preflightOK:
			ok++
		case preflightWarn:
			warn++
		case preflightError:
			errCount++
		}
	}
	return ok, warn, errCount
}

func preflightHasErrors(report preflightReport) bool {
	_, _, errCount := preflightCounts(report)
	return errCount > 0
}

func hasLinuxModule(modules []runtimeModule) bool {
	for _, module := range modules {
		if moduleSupportsPlatform(module.Spec.Name, "linux") {
			return true
		}
	}
	return false
}

func hasWindowsModule(modules []runtimeModule) bool {
	for _, module := range modules {
		if moduleSupportsPlatform(module.Spec.Name, "windows") {
			return true
		}
	}
	return false
}

func moduleSupportsPlatform(name, goos string) bool {
	descriptor, ok := findModule(name)
	if !ok {
		return false
	}
	for _, platform := range descriptor.Platforms {
		if platform == goos {
			return true
		}
	}
	return false
}

func modulePlatformLabel(name string) string {
	descriptor, ok := findModule(name)
	if !ok {
		return "unknown"
	}
	platforms := descriptor.Platforms
	if len(platforms) == 0 {
		return "unknown"
	}
	return strings.Join(platforms, "/")
}

func moduleEnabled(modules []runtimeModule, name string) bool {
	_, ok := runtimeModuleByName(modules, name)
	return ok
}

func runtimeModuleByName(modules []runtimeModule, name string) (runtimeModule, bool) {
	for _, module := range modules {
		if module.Spec.Name == name {
			return module, true
		}
	}
	return runtimeModule{}, false
}

func auditLogPathsFromModules(modules []runtimeModule) []string {
	seen := map[string]bool{}
	var out []string
	add := func(path string) {
		path = strings.TrimSpace(path)
		if path == "" {
			path = defaultLinuxAuditLogPath
		}
		if !seen[path] {
			seen[path] = true
			out = append(out, path)
		}
	}
	for _, module := range modules {
		switch module.Spec.Name {
		case "audit-port-execmon":
			path := defaultLinuxAuditLogPath
			if value, ok := stringFlag(module.Config.Args, "audit-log"); ok {
				path = value
			}
			add(path)
		case "host-persistence":
			path := defaultLinuxAuditLogPath
			if configPath, ok := stringFlag(module.Config.Args, "config"); ok && strings.TrimSpace(configPath) != "" {
				if body, err := os.ReadFile(strings.TrimSpace(configPath)); err == nil {
					var cfg struct {
						Audit struct {
							AuditLog string `json:"audit_log,omitempty"`
						} `json:"audit,omitempty"`
					}
					if json.Unmarshal(body, &cfg) == nil && strings.TrimSpace(cfg.Audit.AuditLog) != "" {
						path = strings.TrimSpace(cfg.Audit.AuditLog)
					}
				}
			}
			if value, ok := stringFlag(module.Config.Args, "audit-log"); ok {
				path = value
			}
			add(path)
		}
	}
	sort.Strings(out)
	return out
}

func windowsChannelsFromModules(modules []runtimeModule) []string {
	seen := map[string]bool{}
	var out []string
	addCSV := func(csv string) {
		for _, item := range strings.Split(csv, ",") {
			item = strings.TrimSpace(item)
			if item != "" && !seen[item] {
				seen[item] = true
				out = append(out, item)
			}
		}
	}
	for _, module := range modules {
		switch module.Spec.Name {
		case "windows-eventlog-risk-json":
			csv := "Security,System,Microsoft-Windows-PowerShell/Operational"
			if value, ok := stringFlag(module.Config.Args, "channels"); ok && strings.TrimSpace(value) != "" {
				csv = value
			}
			addCSV(csv)
		case "windows-process-execmon":
			csv := "Security,Microsoft-Windows-Sysmon/Operational"
			if value, ok := stringFlag(module.Config.Args, "channels"); ok && strings.TrimSpace(value) != "" {
				csv = value
			}
			addCSV(csv)
		}
	}
	sort.Strings(out)
	return out
}

func commandOutput(timeout time.Duration, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return out, fmt.Errorf("%s timed out after %s", name, timeout)
	}
	return out, err
}

func parseKeyValueLines(text string) map[string]string {
	result := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			result[fields[0]] = fields[1]
		}
	}
	return result
}

func readableFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func preflightValueOrUnknown(value string) string {
	if strings.TrimSpace(value) == "" {
		return "unknown"
	}
	return value
}

func runningInContainer() bool {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	data, err := os.ReadFile("/proc/1/cgroup")
	if err != nil {
		return false
	}
	text := strings.ToLower(string(data))
	for _, marker := range []string{"docker", "kubepods", "containerd", "lxc", "libpod"} {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}

package auditportexecmon

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

func fileSize(path string) (int64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return -1, err
	}
	return info.Size(), nil
}

func requireAuditEnvironment(auditLog string) error {
	// Refuse to start before adding rules when auditctl, auditd, or the log
	// directory is unavailable. This keeps environment failures side-effect free.
	if _, err := exec.LookPath("auditctl"); err != nil {
		return fmt.Errorf("未找到 auditctl，请先安装 auditd：\n  Debian/Ubuntu: sudo apt-get install -y auditd && sudo systemctl enable --now auditd\n  RHEL/CentOS: sudo yum install -y audit && sudo systemctl enable --now auditd")
	}
	if err := requireAuditLogDir(auditLog); err != nil {
		return err
	}
	return requireAuditdRunning()
}

func requireAuditLogDir(auditLog string) error {
	logDir := filepath.Dir(auditLog)
	info, err := os.Stat(logDir)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("audit 日志目录不存在（%s）：通常表示 auditd 未安装或未启动\n请先安装并启动 auditd，例如：\n  Debian/Ubuntu: sudo apt-get install -y auditd && sudo systemctl enable --now auditd\n  RHEL/CentOS: sudo yum install -y audit && sudo systemctl enable --now auditd", logDir)
		}
		return fmt.Errorf("无法访问 audit 日志目录 %s：%w", logDir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("audit 日志路径 %s 不是目录", logDir)
	}
	return nil
}

func requireAuditdRunning() error {
	out, err := runAuditctlOutputWithTimeout(auditctlTimeout, "-s")
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("auditd 未运行或未就绪（auditctl -s 失败）：%s\n请先安装并启动 auditd，例如：sudo systemctl enable --now auditd", msg)
	}
	status := parseAuditStatus(string(out))
	switch status["enabled"] {
	case "0":
		return fmt.Errorf("auditd 已安装但未启用（enabled=0），请启动 auditd：sudo systemctl start auditd")
	case "":
		return fmt.Errorf("无法确认 auditd 状态，请检查 auditd 是否已安装并启动")
	}
	return nil
}

func resolveOutputLog(flagValue, configValue string) string {
	if flagValue != "" {
		return flagValue
	}
	if configValue != "" {
		return configValue
	}
	return defaultOutputLog
}

type auditPrecheck struct {
	Status      map[string]string
	RuleCount   int
	StatusError error
	ListError   error
}

func collectAuditPrecheck() auditPrecheck {
	// Status and rule listing are independent checks. Preserve both errors so an
	// operator can distinguish audit pressure from a listing compatibility issue.
	precheck := auditPrecheck{Status: map[string]string{}}
	if status, err := collectAuditStatus(); err != nil {
		precheck.StatusError = err
	} else {
		precheck.Status = status
	}
	if out, err := runAuditctlCommand(auditctlTimeout, "-l"); err != nil {
		precheck.ListError = err
	} else {
		precheck.RuleCount = countAuditRules(string(out))
	}
	return precheck
}

func collectAuditStatus() (map[string]string, error) {
	out, err := runAuditctlCommand(auditctlTimeout, "-s")
	if err != nil {
		return nil, err
	}
	return parseAuditStatus(string(out)), nil
}

func parseAuditStatus(text string) map[string]string {
	status := map[string]string{}
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 {
			status[fields[0]] = fields[1]
		}
	}
	return status
}

func countAuditRules(text string) int {
	count := 0
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "-a ") || strings.HasPrefix(line, "-w ") {
			count++
		}
	}
	return count
}

func printAuditPrecheckWarnings(precheck auditPrecheck, plannedRules int) {
	if precheck.StatusError != nil {
		fmt.Fprintf(os.Stderr, "audit status precheck failed: %v\n", precheck.StatusError)
	} else {
		fmt.Fprintf(os.Stderr, "audit status: enabled=%s backlog=%s backlog_limit=%s lost=%s existing_rules=%d planned_rules_estimate=%d\n", valueOrUnknown(precheck.Status["enabled"]), valueOrUnknown(precheck.Status["backlog"]), valueOrUnknown(precheck.Status["backlog_limit"]), valueOrUnknown(precheck.Status["lost"]), precheck.RuleCount, plannedRules)
		if precheck.Status["enabled"] == "2" {
			fmt.Fprintf(os.Stderr, "warning: auditd is immutable (enabled=2); dynamic audit rules may fail until reboot or audit config change\n")
		}
		if lost, _ := strconv.Atoi(precheck.Status["lost"]); lost > 0 {
			fmt.Fprintf(os.Stderr, "warning: audit has already lost %d events; consider increasing audit backlog or reducing monitored scope\n", lost)
		}
		if backlog, _ := strconv.Atoi(precheck.Status["backlog"]); backlog > 0 {
			if limit, _ := strconv.Atoi(precheck.Status["backlog_limit"]); limit > 0 && backlog*100/limit >= 80 {
				fmt.Fprintf(os.Stderr, "warning: audit backlog is high: %d/%d\n", backlog, limit)
			}
		}
	}
	if precheck.ListError != nil {
		fmt.Fprintf(os.Stderr, "audit rule count precheck failed: %v\n", precheck.ListError)
	}
	if precheck.RuleCount+plannedRules >= 500 || plannedRules >= 300 {
		fmt.Fprintf(os.Stderr, "warning: high audit rule volume: existing=%d planned_estimate=%d; consider -port, whitelist_ports, connect_listener_ports, file_listener_ports, or disabling monitor_file_ops\n", precheck.RuleCount, plannedRules)
	}
}

func valueOrUnknown(value string) string {
	if value == "" {
		return "unknown"
	}
	return value
}

func estimatePlannedAuditRules(listeners []listenerInfo, trackDescendants, monitorExec bool, execListenerPorts map[int]bool, monitorConnect bool, connectListenerPorts, skipConnectListenerPorts map[int]bool, skipConnectProcessNames map[string]bool, skipConnectExePatterns []*regexp.Regexp, monitorFileOps bool, fileListenerPorts map[int]bool, monitorSensitiveFileReads bool, sensitiveFilePaths []string, javaMonitorMode string) int {
	return estimatePlannedAuditRulesWithArches(listeners, trackDescendants, monitorExec, execListenerPorts, monitorConnect, connectListenerPorts, skipConnectListenerPorts, skipConnectProcessNames, skipConnectExePatterns, monitorFileOps, fileListenerPorts, monitorSensitiveFileReads, sensitiveFilePaths, auditArches(), javaMonitorMode)
}

func estimatePlannedAuditRulesWithArches(listeners []listenerInfo, trackDescendants, monitorExec bool, execListenerPorts map[int]bool, monitorConnect bool, connectListenerPorts, skipConnectListenerPorts map[int]bool, skipConnectProcessNames map[string]bool, skipConnectExePatterns []*regexp.Regexp, monitorFileOps bool, fileListenerPorts map[int]bool, monitorSensitiveFileReads bool, sensitiveFilePaths []string, arches []string, javaMonitorMode string) int {
	// This is a conservative warning estimate, not the enforcement point. The
	// hard limit is checked under monitor.mu using installed plus reserved rules.
	const pidFields = 2
	const execRuleGroups = 1
	const cloneRuleGroups = 1
	const connectRuleGroups = 1
	const fileRuleGroups = 1
	archCount := len(normalizeAuditArches(arches))
	exeSeen := map[string]bool{}
	pidSeen := map[int]bool{}
	total := 0
	for _, listener := range listeners {
		javaMode := normalizeJavaMonitorMode(javaMonitorMode)
		javaListener := isJavaListener(listener.Process, listener.MonitorExe)
		webGateway := isWebGatewayListener(listener)
		execSelected := monitorExec && portSelected(listener.Port, execListenerPorts)
		if listener.ExeOnly && listener.MonitorExe != "" && !(javaListener && javaMode == javaMonitorModePIDTree) {
			if exeSeen[listener.MonitorExe] {
				continue
			}
			exeSeen[listener.MonitorExe] = true
			if execSelected {
				total += archCount * execRuleGroups
			}
			if shouldMonitorListenerConnect(listener, monitorConnect, connectListenerPorts, skipConnectListenerPorts, skipConnectProcessNames, skipConnectExePatterns) {
				total += archCount * connectRuleGroups
			}
			if monitorFileOps && portSelected(listener.Port, fileListenerPorts) {
				total += archCount * fileRuleGroups
			}
			if !execSelected || !((javaListener && javaMode == javaMonitorModeHybrid || webGateway) && trackDescendants) {
				continue
			}
		}
		if listener.PID <= 1 || pidSeen[listener.PID] {
			continue
		}
		pidSeen[listener.PID] = true
		if execSelected {
			total += archCount * pidFields * execRuleGroups
			if trackDescendants {
				total += archCount * pidFields * cloneRuleGroups
			}
		}
		if shouldMonitorListenerConnect(listener, monitorConnect, connectListenerPorts, skipConnectListenerPorts, skipConnectProcessNames, skipConnectExePatterns) {
			total += archCount * pidFields * connectRuleGroups
		}
		if monitorFileOps && portSelected(listener.Port, fileListenerPorts) {
			total += archCount * pidFields * fileRuleGroups
		}
	}
	if monitorSensitiveFileReads {
		total += len(sensitiveFilePaths)
	}
	return total
}

func shouldMonitorListenerConnect(listener listenerInfo, monitorConnect bool, connectListenerPorts, skipConnectListenerPorts map[int]bool, skipConnectProcessNames map[string]bool, skipConnectExePatterns []*regexp.Regexp) bool {
	if !monitorConnect || !portSelected(listener.Port, connectListenerPorts) {
		return false
	}
	if len(skipConnectListenerPorts) > 0 && skipConnectListenerPorts[listener.Port] {
		return false
	}
	process := strings.ToLower(strings.TrimSpace(listener.Process))
	if process != "" && skipConnectProcessNames[process] {
		return false
	}
	base := strings.ToLower(filepath.Base(process))
	if base != "" && skipConnectProcessNames[base] {
		return false
	}
	exe := listener.MonitorExe
	for _, pattern := range skipConnectExePatterns {
		if pattern.MatchString(exe) || pattern.MatchString(listener.Process) {
			return false
		}
	}
	return true
}

func portSelected(port int, selected map[int]bool) bool {
	return len(selected) == 0 || selected[port]
}

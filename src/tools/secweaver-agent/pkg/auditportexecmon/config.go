package auditportexecmon

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type connectSettings struct {
	Monitor           *bool    `json:"monitor"`
	ListenerPorts     []int    `json:"listener_ports"`
	SkipProcessNames  []string `json:"skip_process_names"`
	SkipExePatterns   []string `json:"skip_exe_patterns"`
	SkipListenerPorts []int    `json:"skip_listener_ports"`
}

type execSettings struct {
	Monitor            *bool        `json:"monitor"`
	ListenerPorts      []int        `json:"listener_ports"`
	TrackDescendants   *bool        `json:"track_descendants"`
	JavaMonitorMode    string       `json:"java_monitor_mode"`
	ProcessTreeBackend string       `json:"process_tree_backend"`
	FallbackBackend    string       `json:"fallback_backend"`
	EBPF               ebpfSettings `json:"ebpf"`
}

type ebpfSettings struct {
	MaxTrackedProcesses   int `json:"max_tracked_processes"`
	PerfBufferBytesPerCPU int `json:"perf_buffer_bytes_per_cpu"`
}

type fileOpsSettings struct {
	Monitor       bool  `json:"monitor"`
	ListenerPorts []int `json:"listener_ports"`
}

type sensitiveFileReadsSettings struct {
	Monitor *bool     `json:"monitor"`
	Paths   *[]string `json:"paths"`
}

type auditSettings struct {
	Arches   []string              `json:"arches"`
	MaxRules int                   `json:"max_rules"`
	Pressure auditPressureSettings `json:"pressure"`
}

// auditPressureSettings is the on-disk representation. Zero values mean
// "use the release default" so older configuration files automatically gain
// staged pressure protection without migration.
type auditPressureSettings struct {
	Enabled                    *bool `json:"enabled,omitempty"`
	CheckIntervalSeconds       int   `json:"check_interval_seconds"`
	BacklogHighPercent         int   `json:"backlog_high_percent"`
	MediumBacklogPercent       int   `json:"medium_backlog_percent"`
	SevereBacklogPercent       int   `json:"severe_backlog_percent"`
	LostDelta                  int   `json:"lost_delta"`
	MediumLostDelta            int   `json:"medium_lost_delta"`
	SevereLostDelta            int   `json:"severe_lost_delta"`
	CooldownSeconds            int   `json:"cooldown_seconds"`
	LightRateLimitPerSecond    int   `json:"light_rate_limit_per_second"`
	MediumRateLimitPerSecond   int   `json:"medium_rate_limit_per_second"`
	RecoveryRateLimitPerSecond int   `json:"recovery_rate_limit_per_second"`
}

type config struct {
	WhitelistPorts        []int                      `json:"whitelist_ports"`
	Audit                 auditSettings              `json:"audit"`
	Exec                  execSettings               `json:"exec"`
	Connect               connectSettings            `json:"connect"`
	FileOps               fileOpsSettings            `json:"file_ops"`
	SensitiveFileReads    sensitiveFileReadsSettings `json:"sensitive_file_reads"`
	OutputLog             string                     `json:"output_log"`
	ListenerRescanSeconds int                        `json:"listener_rescan_seconds"`

	// 兼容旧版扁平字段；嵌套块优先。
	JavaMonitorMode           string   `json:"java_monitor_mode,omitempty"`
	MonitorConnect            *bool    `json:"monitor_connect,omitempty"`
	ConnectListenerPorts      []int    `json:"connect_listener_ports,omitempty"`
	SkipConnectProcessNames   []string `json:"skip_connect_process_names,omitempty"`
	SkipConnectExePatterns    []string `json:"skip_connect_exe_patterns,omitempty"`
	SkipConnectListenerPorts  []int    `json:"skip_connect_listener_ports,omitempty"`
	MonitorFileOps            *bool    `json:"monitor_file_ops,omitempty"`
	FileListenerPorts         []int    `json:"file_listener_ports,omitempty"`
	MonitorSensitiveFileReads *bool    `json:"monitor_sensitive_file_reads,omitempty"`
	SensitiveFilePaths        []string `json:"sensitive_file_paths,omitempty"`
	AuditArches               []string `json:"audit_arches,omitempty"`
}

var defaultSensitiveFilePaths = []string{"/etc/shadow"}
var emptySensitivePathFallback = []string{"/etc/shadow"}

func listenerRescanIntervalFromConfig(cfg config) time.Duration {
	if cfg.ListenerRescanSeconds <= 0 {
		return defaultListenerRescanInterval
	}
	return time.Duration(cfg.ListenerRescanSeconds) * time.Second
}

func configMonitorConnect(cfg config) bool {
	if cfg.Connect.Monitor != nil {
		return *cfg.Connect.Monitor
	}
	if cfg.MonitorConnect != nil {
		return *cfg.MonitorConnect
	}
	return false
}

func configMonitorExec(cfg config) bool {
	if cfg.Exec.Monitor != nil {
		return *cfg.Exec.Monitor
	}
	return true
}

func configTrackDescendants(cfg config) bool {
	if cfg.Exec.TrackDescendants != nil {
		return *cfg.Exec.TrackDescendants
	}
	return true
}

type processTreeRuntimeConfig struct {
	Backend               string
	FallbackBackend       string
	MaxTrackedProcesses   uint32
	PerfBufferBytesPerCPU int
}

func resolveProcessTreeConfig(cfg config) processTreeRuntimeConfig {
	backend := strings.ToLower(strings.TrimSpace(cfg.Exec.ProcessTreeBackend))
	if backend == "" {
		backend = processTreeBackendAuto
	}
	fallback := strings.ToLower(strings.TrimSpace(cfg.Exec.FallbackBackend))
	if fallback == "" {
		fallback = processTreeBackendAudit
	}
	maxTracked := cfg.Exec.EBPF.MaxTrackedProcesses
	if maxTracked <= 0 {
		maxTracked = defaultEBPFMaxTrackedProcesses
	}
	perfBufferBytes := cfg.Exec.EBPF.PerfBufferBytesPerCPU
	if perfBufferBytes <= 0 {
		perfBufferBytes = defaultEBPFPerfBufferBytes
	}
	return processTreeRuntimeConfig{
		Backend:               backend,
		FallbackBackend:       fallback,
		MaxTrackedProcesses:   uint32(maxTracked),
		PerfBufferBytesPerCPU: perfBufferBytes,
	}
}

func resolveJavaMonitorMode(cfg config) string {
	mode := strings.TrimSpace(cfg.Exec.JavaMonitorMode)
	if mode == "" {
		mode = strings.TrimSpace(cfg.JavaMonitorMode)
	}
	return normalizeJavaMonitorMode(mode)
}

func resolveAuditArches(cfg config) []string {
	if len(cfg.Audit.Arches) > 0 {
		return normalizeAuditArches(cfg.Audit.Arches)
	}
	if len(cfg.AuditArches) > 0 {
		return normalizeAuditArches(cfg.AuditArches)
	}
	return auditArches()
}

func resolveMaxAuditRules(cfg config) int {
	if cfg.Audit.MaxRules > 0 {
		return cfg.Audit.MaxRules
	}
	return defaultMaxAuditRules
}

type auditPressureRuntimeConfig struct {
	Enabled                    bool
	CheckInterval              time.Duration
	BacklogHighPercent         int
	MediumBacklogPercent       int
	SevereBacklogPercent       int
	LostDelta                  int
	MediumLostDelta            int
	SevereLostDelta            int
	Cooldown                   time.Duration
	LightRateLimitPerSecond    int
	MediumRateLimitPerSecond   int
	RecoveryRateLimitPerSecond int
}

// resolveAuditPressureConfig materializes all defaults before the state machine
// starts. Runtime pressure code therefore never has to reinterpret zero values.
func resolveAuditPressureConfig(cfg config) auditPressureRuntimeConfig {
	enabled := true
	if cfg.Audit.Pressure.Enabled != nil {
		enabled = *cfg.Audit.Pressure.Enabled
	}
	checkInterval := time.Duration(cfg.Audit.Pressure.CheckIntervalSeconds) * time.Second
	if checkInterval <= 0 {
		checkInterval = 30 * time.Second
	}
	backlogHighPercent := cfg.Audit.Pressure.BacklogHighPercent
	if backlogHighPercent <= 0 {
		backlogHighPercent = 80
	}
	mediumBacklogPercent := cfg.Audit.Pressure.MediumBacklogPercent
	if mediumBacklogPercent <= 0 {
		mediumBacklogPercent = 90
		if mediumBacklogPercent <= backlogHighPercent {
			mediumBacklogPercent = backlogHighPercent + 5
		}
	}
	severeBacklogPercent := cfg.Audit.Pressure.SevereBacklogPercent
	if severeBacklogPercent <= 0 {
		severeBacklogPercent = 95
		if severeBacklogPercent <= mediumBacklogPercent {
			severeBacklogPercent = mediumBacklogPercent + 5
		}
	}
	lostDelta := cfg.Audit.Pressure.LostDelta
	if lostDelta <= 0 {
		lostDelta = 1
	}
	mediumLostDelta := cfg.Audit.Pressure.MediumLostDelta
	if mediumLostDelta <= 0 {
		mediumLostDelta = 5
		if mediumLostDelta <= lostDelta {
			mediumLostDelta = lostDelta + 4
		}
	}
	severeLostDelta := cfg.Audit.Pressure.SevereLostDelta
	if severeLostDelta <= 0 {
		severeLostDelta = 20
		if severeLostDelta <= mediumLostDelta {
			severeLostDelta = mediumLostDelta + 15
		}
	}
	cooldown := time.Duration(cfg.Audit.Pressure.CooldownSeconds) * time.Second
	if cooldown <= 0 {
		cooldown = 2 * time.Minute
	}
	lightRate := cfg.Audit.Pressure.LightRateLimitPerSecond
	if lightRate <= 0 {
		lightRate = 10
	}
	mediumRate := cfg.Audit.Pressure.MediumRateLimitPerSecond
	if mediumRate <= 0 {
		mediumRate = 5
	}
	recoveryRate := cfg.Audit.Pressure.RecoveryRateLimitPerSecond
	if recoveryRate <= 0 {
		recoveryRate = 5
	}
	return auditPressureRuntimeConfig{
		Enabled:                    enabled,
		CheckInterval:              checkInterval,
		BacklogHighPercent:         backlogHighPercent,
		MediumBacklogPercent:       mediumBacklogPercent,
		SevereBacklogPercent:       severeBacklogPercent,
		LostDelta:                  lostDelta,
		MediumLostDelta:            mediumLostDelta,
		SevereLostDelta:            severeLostDelta,
		Cooldown:                   cooldown,
		LightRateLimitPerSecond:    lightRate,
		MediumRateLimitPerSecond:   mediumRate,
		RecoveryRateLimitPerSecond: recoveryRate,
	}
}

func flagChanged(name string) bool {
	changed := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			changed = true
		}
	})
	return changed
}

func configMonitorSensitiveFileReads(cfg config) bool {
	if cfg.SensitiveFileReads.Monitor != nil {
		return *cfg.SensitiveFileReads.Monitor
	}
	if cfg.MonitorSensitiveFileReads != nil {
		return *cfg.MonitorSensitiveFileReads
	}
	return true
}

func resolveSensitiveFilePaths(cfg config) []string {
	if cfg.SensitiveFileReads.Paths != nil {
		return normalizeSensitivePathList(*cfg.SensitiveFileReads.Paths)
	}
	if len(cfg.SensitiveFilePaths) > 0 {
		return normalizeSensitivePathList(cfg.SensitiveFilePaths)
	}
	out := make([]string, len(defaultSensitiveFilePaths))
	copy(out, defaultSensitiveFilePaths)
	return out
}

func normalizeSensitivePathList(paths []string) []string {
	out := make([]string, 0, len(paths))
	for _, path := range paths {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		out = append(out, filepath.Clean(path))
	}
	if len(out) == 0 {
		out = append(out, emptySensitivePathFallback...)
	}
	return out
}

func normalizeSensitivePath(path string) string {
	return filepath.Clean(strings.TrimSpace(path))
}

func isSensitiveFilePath(path string, sensitivePaths []string) bool {
	clean := normalizeSensitivePath(path)
	for _, candidate := range sensitivePaths {
		if clean == normalizeSensitivePath(candidate) {
			return true
		}
	}
	return false
}

func filterSensitivePaths(paths []string, sensitivePaths []string) []string {
	if len(paths) == 0 {
		return nil
	}
	out := make([]string, 0, len(paths))
	for _, path := range paths {
		if isSensitiveFilePath(path, sensitivePaths) {
			out = append(out, normalizeSensitivePath(path))
		}
	}
	return out
}

func normalizeJavaMonitorMode(mode string) string {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		return javaMonitorModeHybrid
	}
	return mode
}

func validJavaMonitorMode(mode string) bool {
	switch normalizeJavaMonitorMode(mode) {
	case javaMonitorModeExeOnly, javaMonitorModeHybrid, javaMonitorModePIDTree:
		return true
	default:
		return false
	}
}

func loadConfig(path string) (config, error) {
	// Fail before any auditctl side effect. Invalid thresholds can invert
	// degradation levels, while invalid paths or arches create partial coverage.
	// Legacy flat fields are normalized before semantic validation.
	if path == "" {
		return config{}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return config{}, err
	}
	var cfg config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return config{}, err
	}
	cfg.normalize()
	for _, port := range cfg.WhitelistPorts {
		if port <= 0 || port > 65535 {
			return config{}, fmt.Errorf("whitelist_ports 包含非法端口 %d", port)
		}
	}
	for _, port := range cfg.Connect.ListenerPorts {
		if port <= 0 || port > 65535 {
			return config{}, fmt.Errorf("connect.listener_ports 包含非法端口 %d", port)
		}
	}
	for _, port := range cfg.Exec.ListenerPorts {
		if port <= 0 || port > 65535 {
			return config{}, fmt.Errorf("exec.listener_ports 包含非法端口 %d", port)
		}
	}
	for _, port := range cfg.Connect.SkipListenerPorts {
		if port <= 0 || port > 65535 {
			return config{}, fmt.Errorf("connect.skip_listener_ports 包含非法端口 %d", port)
		}
	}
	if _, err := compileRegexps(cfg.Connect.SkipExePatterns); err != nil {
		return config{}, err
	}
	for _, port := range cfg.FileOps.ListenerPorts {
		if port <= 0 || port > 65535 {
			return config{}, fmt.Errorf("file_ops.listener_ports 包含非法端口 %d", port)
		}
	}
	for _, path := range resolveSensitiveFilePaths(cfg) {
		if !filepath.IsAbs(path) {
			return config{}, fmt.Errorf("sensitive_file_reads.paths 必须为绝对路径: %q", path)
		}
	}
	if cfg.ListenerRescanSeconds < 0 {
		return config{}, fmt.Errorf("listener_rescan_seconds 不能为负数")
	}
	if cfg.Audit.MaxRules < 0 {
		return config{}, fmt.Errorf("audit.max_rules 不能为负数")
	}
	processTree := resolveProcessTreeConfig(cfg)
	if processTree.Backend != processTreeBackendAuto && processTree.Backend != processTreeBackendEBPF && processTree.Backend != processTreeBackendAudit && processTree.Backend != processTreeBackendAuditPID {
		return config{}, fmt.Errorf("exec.process_tree_backend 只能是 %q、%q、%q 或 %q", processTreeBackendAuto, processTreeBackendEBPF, processTreeBackendAudit, processTreeBackendAuditPID)
	}
	if processTree.FallbackBackend != processTreeBackendAudit && processTree.FallbackBackend != processTreeBackendAuditPID {
		return config{}, fmt.Errorf("exec.fallback_backend 只能是 %q 或 %q", processTreeBackendAudit, processTreeBackendAuditPID)
	}
	if cfg.Exec.EBPF.MaxTrackedProcesses < 0 || cfg.Exec.EBPF.MaxTrackedProcesses > 1048576 {
		return config{}, fmt.Errorf("exec.ebpf.max_tracked_processes 必须在 1-1048576 范围内，0 表示使用默认值")
	}
	if cfg.Exec.EBPF.PerfBufferBytesPerCPU < 0 || cfg.Exec.EBPF.PerfBufferBytesPerCPU > 16<<20 {
		return config{}, fmt.Errorf("exec.ebpf.perf_buffer_bytes_per_cpu 必须在 1-16777216 范围内，0 表示使用默认值")
	}
	if cfg.Audit.Pressure.CheckIntervalSeconds < 0 {
		return config{}, fmt.Errorf("audit.pressure.check_interval_seconds 不能为负数")
	}
	if cfg.Audit.Pressure.BacklogHighPercent < 0 || cfg.Audit.Pressure.BacklogHighPercent > 100 {
		return config{}, fmt.Errorf("audit.pressure.backlog_high_percent 必须在 0-100 范围内")
	}
	if cfg.Audit.Pressure.MediumBacklogPercent < 0 || cfg.Audit.Pressure.MediumBacklogPercent > 100 {
		return config{}, fmt.Errorf("audit.pressure.medium_backlog_percent 必须在 0-100 范围内")
	}
	if cfg.Audit.Pressure.SevereBacklogPercent < 0 || cfg.Audit.Pressure.SevereBacklogPercent > 100 {
		return config{}, fmt.Errorf("audit.pressure.severe_backlog_percent 必须在 0-100 范围内")
	}
	if cfg.Audit.Pressure.LostDelta < 0 {
		return config{}, fmt.Errorf("audit.pressure.lost_delta 不能为负数")
	}
	if cfg.Audit.Pressure.MediumLostDelta < 0 || cfg.Audit.Pressure.SevereLostDelta < 0 {
		return config{}, fmt.Errorf("audit.pressure medium/severe lost_delta 不能为负数")
	}
	if cfg.Audit.Pressure.CooldownSeconds < 0 {
		return config{}, fmt.Errorf("audit.pressure.cooldown_seconds 不能为负数")
	}
	if cfg.Audit.Pressure.LightRateLimitPerSecond < 0 || cfg.Audit.Pressure.MediumRateLimitPerSecond < 0 || cfg.Audit.Pressure.RecoveryRateLimitPerSecond < 0 {
		return config{}, fmt.Errorf("audit.pressure rate_limit_per_second 不能为负数")
	}
	pressure := resolveAuditPressureConfig(cfg)
	if !(pressure.BacklogHighPercent < pressure.MediumBacklogPercent && pressure.MediumBacklogPercent < pressure.SevereBacklogPercent) {
		return config{}, fmt.Errorf("audit.pressure backlog 阈值必须满足 light < medium < severe")
	}
	if !(pressure.LostDelta < pressure.MediumLostDelta && pressure.MediumLostDelta < pressure.SevereLostDelta) {
		return config{}, fmt.Errorf("audit.pressure lost_delta 阈值必须满足 light < medium < severe")
	}
	for _, arch := range resolveAuditArches(cfg) {
		if !validAuditArch(arch) {
			return config{}, fmt.Errorf("audit.arches 只能包含 %q 或 %q: %q", "b64", "b32", arch)
		}
	}
	javaMode := resolveJavaMonitorMode(cfg)
	if !validJavaMonitorMode(javaMode) {
		return config{}, fmt.Errorf("exec.java_monitor_mode 只能是 %q、%q 或 %q", javaMonitorModeExeOnly, javaMonitorModeHybrid, javaMonitorModePIDTree)
	}
	cfg.Exec.JavaMonitorMode = javaMode
	return cfg, nil
}

func (c *config) normalize() {
	if c.Exec.JavaMonitorMode == "" && c.JavaMonitorMode != "" {
		c.Exec.JavaMonitorMode = c.JavaMonitorMode
	}
	if len(c.Audit.Arches) == 0 && len(c.AuditArches) > 0 {
		c.Audit.Arches = append([]string(nil), c.AuditArches...)
	}
	if c.Connect.Monitor == nil && c.MonitorConnect != nil {
		c.Connect.Monitor = c.MonitorConnect
	}
	if len(c.Connect.ListenerPorts) == 0 && len(c.ConnectListenerPorts) > 0 {
		c.Connect.ListenerPorts = append([]int(nil), c.ConnectListenerPorts...)
	}
	if len(c.Connect.SkipProcessNames) == 0 && len(c.SkipConnectProcessNames) > 0 {
		c.Connect.SkipProcessNames = append([]string(nil), c.SkipConnectProcessNames...)
	}
	if len(c.Connect.SkipExePatterns) == 0 && len(c.SkipConnectExePatterns) > 0 {
		c.Connect.SkipExePatterns = append([]string(nil), c.SkipConnectExePatterns...)
	}
	if len(c.Connect.SkipListenerPorts) == 0 && len(c.SkipConnectListenerPorts) > 0 {
		c.Connect.SkipListenerPorts = append([]int(nil), c.SkipConnectListenerPorts...)
	}
	if !c.FileOps.Monitor && c.MonitorFileOps != nil {
		c.FileOps.Monitor = *c.MonitorFileOps
	}
	if len(c.FileOps.ListenerPorts) == 0 && len(c.FileListenerPorts) > 0 {
		c.FileOps.ListenerPorts = append([]int(nil), c.FileListenerPorts...)
	}
	if c.SensitiveFileReads.Monitor == nil && c.MonitorSensitiveFileReads != nil {
		c.SensitiveFileReads.Monitor = c.MonitorSensitiveFileReads
	}
	if c.SensitiveFileReads.Paths == nil && len(c.SensitiveFilePaths) > 0 {
		paths := append([]string(nil), c.SensitiveFilePaths...)
		c.SensitiveFileReads.Paths = &paths
	}
}

func buildPortSet(ports []int) map[int]bool {
	set := map[int]bool{}
	for _, port := range ports {
		set[port] = true
	}
	return set
}

func buildStringSet(values []string) map[string]bool {
	set := map[string]bool{}
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value != "" {
			set[value] = true
		}
	}
	return set
}

func compileRegexps(patterns []string) ([]*regexp.Regexp, error) {
	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for _, pattern := range patterns {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("skip_connect_exe_patterns 包含非法正则 %q: %w", pattern, err)
		}
		compiled = append(compiled, re)
	}
	return compiled, nil
}

func formatPortSet(set map[int]bool) string {
	ports := make([]int, 0, len(set))
	for port := range set {
		ports = append(ports, port)
	}
	for i := 0; i < len(ports); i++ {
		for j := i + 1; j < len(ports); j++ {
			if ports[j] < ports[i] {
				ports[i], ports[j] = ports[j], ports[i]
			}
		}
	}
	parts := make([]string, 0, len(ports))
	for _, port := range ports {
		parts = append(parts, strconv.Itoa(port))
	}
	return strings.Join(parts, ",")
}

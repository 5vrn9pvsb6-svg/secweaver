package auditportexecmon

import (
	"os"
	"path/filepath"

	"testing"
)

// These tests cover monitor defaults, nested configuration, validation, and pressure-policy normalization.

func TestShouldMonitorListenerConnectSkipsGatewayProcessName(t *testing.T) {
	listener := listenerInfo{Process: "nginx", MonitorExe: "/usr/sbin/nginx", Port: 443}
	if shouldMonitorListenerConnect(listener, true, nil, nil, buildStringSet([]string{"nginx"}), nil) {
		t.Fatal("gateway process name should skip active connect monitoring")
	}
}

func TestShouldMonitorListenerConnectSkipsGatewayExePattern(t *testing.T) {
	patterns, err := compileRegexps([]string{`/usr/(sbin|local/sbin)/haproxy$`})
	if err != nil {
		t.Fatal(err)
	}
	listener := listenerInfo{Process: "haproxy", MonitorExe: "/usr/sbin/haproxy", Port: 443}
	if shouldMonitorListenerConnect(listener, true, nil, nil, nil, patterns) {
		t.Fatal("gateway exe pattern should skip active connect monitoring")
	}
}

func TestShouldMonitorListenerConnectSkipsGatewayPort(t *testing.T) {
	listener := listenerInfo{Process: "custom-gateway", MonitorExe: "/opt/gw/bin/gateway", Port: 443}
	if shouldMonitorListenerConnect(listener, true, nil, buildPortSet([]int{443}), nil, nil) {
		t.Fatal("gateway listener port should skip active connect monitoring")
	}
}

func TestShouldMonitorListenerConnectKeepsNonGatewayProcess(t *testing.T) {
	listener := listenerInfo{Process: "tomcat", MonitorExe: "/opt/tomcat/bin/java", Port: 8080}
	if !shouldMonitorListenerConnect(listener, true, buildPortSet([]int{8080}), buildPortSet([]int{443}), buildStringSet([]string{"nginx"}), nil) {
		t.Fatal("non-gateway listener should keep active connect monitoring")
	}
}

func TestLoadConfigValidatesSkipConnectFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	data := []byte(`{
		"skip_connect_process_names": ["nginx"],
		"skip_connect_exe_patterns": ["/usr/sbin/nginx$"],
		"skip_connect_listener_ports": [443],
		"java_monitor_mode": "hybrid"
	}`)
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if len(cfg.Connect.SkipProcessNames) != 1 || len(cfg.Connect.SkipExePatterns) != 1 || len(cfg.Connect.SkipListenerPorts) != 1 {
		t.Fatalf("skip connect config not loaded: %+v", cfg.Connect)
	}
	if cfg.JavaMonitorMode != javaMonitorModeHybrid {
		t.Fatalf("java monitor mode = %q, want %q", cfg.JavaMonitorMode, javaMonitorModeHybrid)
	}
}

func TestLoadConfigRejectsInvalidJavaMonitorMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"java_monitor_mode":"bad"}`), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path); err == nil {
		t.Fatal("expected invalid java_monitor_mode to fail")
	}
}

func TestLoadConfigAuditArches(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	data := []byte(`{"audit":{"arches":["b64","b32","b64"]}}`)
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	arches := resolveAuditArches(cfg)
	if len(arches) != 2 || arches[0] != "b64" || arches[1] != "b32" {
		t.Fatalf("audit arches = %#v, want [b64 b32]", arches)
	}
}

func TestResolveMaxAuditRulesDefaultAndConfig(t *testing.T) {
	cfg, err := loadConfig("")
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if got := resolveMaxAuditRules(cfg); got != defaultMaxAuditRules {
		t.Fatalf("default max audit rules = %d, want %d", got, defaultMaxAuditRules)
	}

	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"audit":{"max_rules":128}}`), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err = loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if got := resolveMaxAuditRules(cfg); got != 128 {
		t.Fatalf("configured max audit rules = %d, want 128", got)
	}
}

func TestResolveAuditPressureConfigDefaults(t *testing.T) {
	cfg := resolveAuditPressureConfig(config{})
	if cfg.BacklogHighPercent != 80 || cfg.MediumBacklogPercent != 90 || cfg.SevereBacklogPercent != 95 {
		t.Fatalf("backlog thresholds = %d/%d/%d", cfg.BacklogHighPercent, cfg.MediumBacklogPercent, cfg.SevereBacklogPercent)
	}
	if cfg.LostDelta != 1 || cfg.MediumLostDelta != 5 || cfg.SevereLostDelta != 20 {
		t.Fatalf("lost thresholds = %d/%d/%d", cfg.LostDelta, cfg.MediumLostDelta, cfg.SevereLostDelta)
	}
	if cfg.LightRateLimitPerSecond != 10 || cfg.MediumRateLimitPerSecond != 5 || cfg.RecoveryRateLimitPerSecond != 5 {
		t.Fatalf("rate limits = %d/%d/%d", cfg.LightRateLimitPerSecond, cfg.MediumRateLimitPerSecond, cfg.RecoveryRateLimitPerSecond)
	}
}

func TestLoadConfigRejectsUnorderedAuditPressureThresholds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	body := []byte(`{"audit":{"pressure":{"backlog_high_percent":80,"medium_backlog_percent":75,"severe_backlog_percent":95}}}`)
	if err := os.WriteFile(path, body, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path); err == nil {
		t.Fatal("unordered pressure thresholds should fail")
	}
}

func TestLegacyHighPressureThresholdRemainsValid(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"audit":{"pressure":{"backlog_high_percent":100}}}`), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	pressure := resolveAuditPressureConfig(cfg)
	if pressure.MediumBacklogPercent <= 100 || pressure.SevereBacklogPercent <= pressure.MediumBacklogPercent {
		t.Fatalf("derived thresholds should preserve legacy light-only behavior: %+v", pressure)
	}
}

func TestLoadConfigRejectsNegativeAuditMaxRules(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"audit":{"max_rules":-1}}`), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path); err == nil {
		t.Fatal("negative audit.max_rules should fail")
	}
}

func TestLoadConfigAcceptsExplicitLegacyAuditPIDBackend(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	body := []byte(`{"exec":{"process_tree_backend":"audit_pid","fallback_backend":"audit_pid"}}`)
	if err := os.WriteFile(path, body, 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	resolved := resolveProcessTreeConfig(cfg)
	if resolved.Backend != processTreeBackendAuditPID || resolved.FallbackBackend != processTreeBackendAuditPID {
		t.Fatalf("unexpected explicit legacy backend: %+v", resolved)
	}
}

func TestLoadConfigRejectsInvalidAuditArch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"audit":{"arches":["b128"]}}`), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path); err == nil {
		t.Fatal("invalid audit arch should fail")
	}
}

func TestJavaMonitorModeDefaultHybrid(t *testing.T) {
	if got := normalizeJavaMonitorMode(""); got != javaMonitorModeHybrid {
		t.Fatalf("default java monitor mode = %q, want %q", got, javaMonitorModeHybrid)
	}
	cfg, err := loadConfig("")
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if got := normalizeJavaMonitorMode(cfg.Exec.JavaMonitorMode); got != javaMonitorModeHybrid {
		t.Fatalf("default config java monitor mode = %q, want %q", got, javaMonitorModeHybrid)
	}
}

func TestDefaultMonitorExecEnabled(t *testing.T) {
	cfg, err := loadConfig("")
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if !configMonitorExec(cfg) {
		t.Fatal("exec.monitor should be enabled by default")
	}
	if !configTrackDescendants(cfg) {
		t.Fatal("exec.track_descendants should be enabled by default")
	}
}

func TestDefaultMonitorFileOpsDisabled(t *testing.T) {
	cfg, err := loadConfig("")
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.FileOps.Monitor {
		t.Fatal("file_ops.monitor should be disabled by default")
	}
}

func TestDefaultMonitorConnectDisabled(t *testing.T) {
	cfg, err := loadConfig("")
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if configMonitorConnect(cfg) {
		t.Fatal("connect.monitor should be disabled by default")
	}
}

func TestLoadConfigEnablesConnectExplicitly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	data := []byte(`{"connect":{"monitor":true}}`)
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if !configMonitorConnect(cfg) {
		t.Fatal("connect.monitor should be enabled when explicitly configured")
	}
}

func TestLoadConfigNestedBlocks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	data := []byte(`{
		"exec": {
			"monitor": true,
			"listener_ports": [8080],
			"track_descendants": false,
			"java_monitor_mode": "exe_only"
		},
		"connect": {
			"monitor": false,
			"listener_ports": [8080],
			"skip_process_names": ["java"]
		},
		"file_ops": {
			"monitor": true,
			"listener_ports": [443, 8443]
		},
		"sensitive_file_reads": {
			"monitor": false,
			"paths": ["/etc/passwd"]
		}
	}`)
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if configMonitorConnect(cfg) {
		t.Fatal("connect.monitor should be false")
	}
	if !configMonitorExec(cfg) {
		t.Fatal("exec.monitor should be true")
	}
	if configTrackDescendants(cfg) {
		t.Fatal("exec.track_descendants should be false")
	}
	if resolveJavaMonitorMode(cfg) != javaMonitorModeExeOnly {
		t.Fatalf("exec.java_monitor_mode = %q", resolveJavaMonitorMode(cfg))
	}
	if len(cfg.Exec.ListenerPorts) != 1 || cfg.Exec.ListenerPorts[0] != 8080 {
		t.Fatalf("exec.listener_ports = %#v", cfg.Exec.ListenerPorts)
	}
	if !cfg.FileOps.Monitor {
		t.Fatal("file_ops.monitor should be true")
	}
	if len(cfg.FileOps.ListenerPorts) != 2 {
		t.Fatalf("file_ops.listener_ports = %#v", cfg.FileOps.ListenerPorts)
	}
	if configMonitorSensitiveFileReads(cfg) {
		t.Fatal("sensitive_file_reads.monitor should be false")
	}
	if len(resolveSensitiveFilePaths(cfg)) != 1 || resolveSensitiveFilePaths(cfg)[0] != "/etc/passwd" {
		t.Fatalf("sensitive paths = %#v", resolveSensitiveFilePaths(cfg))
	}
}

func TestDefaultMonitorSensitiveFileReadsEnabled(t *testing.T) {
	cfg, err := loadConfig("")
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if !configMonitorSensitiveFileReads(cfg) {
		t.Fatal("monitor_sensitive_file_reads should be enabled by default")
	}
	paths := resolveSensitiveFilePaths(cfg)
	if len(paths) != 1 || paths[0] != "/etc/shadow" {
		t.Fatalf("unexpected default sensitive paths: %#v", paths)
	}
}

func TestEmptySensitiveFilePathsFallbackToShadow(t *testing.T) {
	for _, paths := range [][]string{nil, {}, {""}, {" ", ""}} {
		got := normalizeSensitivePathList(paths)
		if len(got) != 1 || got[0] != "/etc/shadow" {
			t.Fatalf("paths=%#v => %#v, want [/etc/shadow]", paths, got)
		}
	}
	cfg := config{SensitiveFileReads: sensitiveFileReadsSettings{Paths: ptrStrings([]string{})}}
	if got := resolveSensitiveFilePaths(cfg); len(got) != 1 || got[0] != "/etc/shadow" {
		t.Fatalf("empty config paths => %#v, want [/etc/shadow]", got)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	data := []byte(`{"sensitive_file_reads":{"paths":[]}}`)
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if got := resolveSensitiveFilePaths(loaded); len(got) != 1 || got[0] != "/etc/shadow" {
		t.Fatalf("loaded empty paths => %#v, want [/etc/shadow]", got)
	}
}

func ptrStrings(values []string) *[]string {
	out := append([]string(nil), values...)
	return &out
}

func TestEstimatePlannedAuditRulesSensitiveFileWatch(t *testing.T) {
	listeners := []listenerInfo{{PID: 100, Process: "nginx", Port: 443}}
	without := estimatePlannedAuditRules(listeners, true, true, map[int]bool{}, true, map[int]bool{}, nil, nil, nil, false, map[int]bool{}, false, nil, javaMonitorModeHybrid)
	with := estimatePlannedAuditRules(listeners, true, true, map[int]bool{}, true, map[int]bool{}, nil, nil, nil, false, map[int]bool{}, true, defaultSensitiveFilePaths, javaMonitorModeHybrid)
	if with <= without {
		t.Fatalf("sensitive file watch should increase planned rules: without=%d with=%d", without, with)
	}
	if with-without != len(defaultSensitiveFilePaths) {
		t.Fatalf("expected +%d watch rules, got delta=%d", len(defaultSensitiveFilePaths), with-without)
	}
}

func TestFilterSensitivePaths(t *testing.T) {
	paths := filterSensitivePaths([]string{"/etc/passwd", "/var/log/messages", "/etc/shadow"}, defaultSensitiveFilePaths)
	if len(paths) != 1 || paths[0] != "/etc/shadow" {
		t.Fatalf("unexpected filtered paths: %#v", paths)
	}
}

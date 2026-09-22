package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"secweaver-agent/pkg/agentlicense"
	"secweaver-agent/pkg/layout"
	agentoutput "secweaver-agent/pkg/output"
)

func runConfigCommand(args []string) int {
	if len(args) == 0 {
		printConfigUsage(os.Stderr)
		return 2
	}
	switch args[0] {
	case "set-enterprise-id":
		fs := flag.NewFlagSet("config set-enterprise-id", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		configPath := defaultAgentConfigPath()
		enterpriseID := ""
		fs.StringVar(&configPath, "config", configPath, "agent JSON config path")
		fs.StringVar(&enterpriseID, "enterprise-id", "", "platform-issued 16-character enterprise ID")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		normalized, err := setEnterpriseIDInConfig(configPath, enterpriseID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "set enterprise ID failed: %v\n", err)
			return 1
		}
		fmt.Fprintf(os.Stdout, "enterprise_id configured: %s (%s)\n", normalized, configPath)
		return 0
	case "set-license":
		fs := flag.NewFlagSet("config set-license", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		configPath := defaultAgentConfigPath()
		licenseCfg := agentlicense.Config{Enabled: true}
		failClosed := true
		outageGraceSeconds := 86400
		fs.StringVar(&configPath, "config", configPath, "agent JSON config path")
		fs.BoolVar(&licenseCfg.Enabled, "enabled", true, "enable managed device authorization and heartbeat")
		fs.StringVar(&licenseCfg.Protocol, "protocol", "legacy_v1", "authorization protocol: legacy_v1 or device_v2")
		fs.StringVar(&licenseCfg.ServerURL, "server-url", "", "SecWeaver managed control-plane URL")
		fs.StringVar(&licenseCfg.CAFile, "ca-file", "", "optional PEM CA file for the authorization server")
		fs.StringVar(&licenseCfg.EnrollmentID, "enrollment-id", "", "Data Cloud enrollment ID used for device registration")
		fs.StringVar(&licenseCfg.StatePath, "state-path", "", "local device registration state path")
		fs.StringVar(&licenseCfg.IdentityKeyPath, "identity-key-path", "", "local Ed25519 device private key path")
		fs.IntVar(&licenseCfg.CheckIntervalSeconds, "check-interval-seconds", 21600, "periodic authorization recheck interval; 0 disables periodic recheck")
		fs.IntVar(&licenseCfg.HeartbeatSeconds, "heartbeat-interval-seconds", 180, "device heartbeat interval")
		fs.IntVar(&outageGraceSeconds, "outage-grace-seconds", 86400, "cached authorization grace for transient control-plane outages; 0 disables")
		fs.BoolVar(&failClosed, "fail-closed", true, "stop agent when authorization check fails")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		licenseCfg.FailClosed = &failClosed
		licenseCfg.OutageGraceSeconds = &outageGraceSeconds
		if err := setLicenseInConfig(configPath, licenseCfg); err != nil {
			fmt.Fprintf(os.Stderr, "set license failed: %v\n", err)
			return 1
		}
		fmt.Fprintf(os.Stdout, "license configured: enabled=%v server=%s (%s)\n", licenseCfg.Enabled, licenseCfg.ServerURL, configPath)
		return 0
	case "set-update":
		fs := flag.NewFlagSet("config set-update", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		configPath := defaultAgentConfigPath()
		cfg := updateConfig{Enabled: true, Channel: "stable", IntervalSeconds: 21600, InitialDelaySeconds: 60, JitterSeconds: 300, RetryInitialSeconds: 60, RetryMaxSeconds: 3600, HealthTimeoutSeconds: 90, LockStaleSeconds: 3600, MaxBackups: 3, MinFreeSpaceMB: 256}
		autoInstall := true
		fs.StringVar(&configPath, "config", configPath, "agent JSON config path")
		fs.BoolVar(&cfg.Enabled, "enabled", true, "enable Agent updates")
		fs.StringVar(&cfg.ManifestURL, "manifest-url", "", "update manifest HTTPS URL")
		fs.StringVar(&cfg.CAFile, "ca-file", "", "optional PEM CA file for the update HTTPS endpoint")
		fs.StringVar(&cfg.PublicKey, "public-key", "", "optional trusted Ed25519 update public key in base64; enables signed-manifest verification")
		fs.StringVar(&cfg.DeviceID, "device-id", "", "immutable rollout device ID for standalone updates")
		fs.StringVar(&cfg.Channel, "channel", "stable", "update channel")
		fs.IntVar(&cfg.IntervalSeconds, "interval-seconds", 21600, "periodic update check interval")
		fs.IntVar(&cfg.InitialDelaySeconds, "initial-delay-seconds", 60, "initial update check delay")
		fs.IntVar(&cfg.JitterSeconds, "jitter-seconds", 300, "stable update check jitter")
		fs.IntVar(&cfg.RetryInitialSeconds, "retry-initial-seconds", 60, "initial retry delay after an update failure")
		fs.IntVar(&cfg.RetryMaxSeconds, "retry-max-seconds", 3600, "maximum retry delay after repeated update failures")
		fs.BoolVar(&autoInstall, "auto-install", true, "install an eligible update automatically")
		fs.BoolVar(&cfg.RequireServerPolicy, "require-server-policy", true, "require managed server heartbeat approval before installation")
		fs.IntVar(&cfg.HealthTimeoutSeconds, "health-timeout-seconds", 90, "new version health confirmation window")
		fs.IntVar(&cfg.LockStaleSeconds, "lock-stale-seconds", 3600, "remove an abandoned update lock after this age")
		fs.IntVar(&cfg.MaxBackups, "max-backups", 3, "maximum retained Agent binary backups")
		fs.IntVar(&cfg.MinFreeSpaceMB, "min-free-space-mb", 256, "free-space reserve required before update")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		cfg.AutoInstall = boolPointer(autoInstall)
		if err := setUpdateInConfig(configPath, cfg); err != nil {
			fmt.Fprintf(os.Stderr, "set update failed: %v\n", err)
			return 1
		}
		fmt.Fprintf(os.Stdout, "signed updates configured: enabled=%v channel=%s manifest=%s (%s)\n", cfg.Enabled, cfg.Channel, cfg.ManifestURL, configPath)
		return 0
	case "ensure-host-process-snapshot":
		fs := flag.NewFlagSet("config ensure-host-process-snapshot", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		configPath := defaultAgentConfigPath()
		fs.StringVar(&configPath, "config", configPath, "agent JSON config path")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		added, err := ensureHostProcessSnapshotInConfig(configPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ensure host process snapshot failed: %v\n", err)
			return 1
		}
		fmt.Fprintf(os.Stdout, "host-process-snapshot configured: added=%v (%s)\n", added, configPath)
		return 0
	case "ensure-host-state-snapshot":
		fs := flag.NewFlagSet("config ensure-host-state-snapshot", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		configPath := defaultAgentConfigPath()
		fs.StringVar(&configPath, "config", configPath, "agent JSON config path")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		added, err := ensureHostStateSnapshotInConfig(configPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ensure host state snapshot failed: %v\n", err)
			return 1
		}
		fmt.Fprintf(os.Stdout, "host-state-snapshot configured: added=%v (%s)\n", added, configPath)
		return 0
	case "optimize-collectors":
		fs := flag.NewFlagSet("config optimize-collectors", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		configPath := defaultAgentConfigPath()
		fs.StringVar(&configPath, "config", configPath, "agent JSON config path")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		changed, err := optimizeCollectorsInConfig(configPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "optimize collectors failed: %v\n", err)
			return 1
		}
		fmt.Fprintf(os.Stdout, "collector configuration optimized: changed=%v (%s)\n", changed, configPath)
		return 0
	case "migrate-layout":
		fs := flag.NewFlagSet("config migrate-layout", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		configPath := defaultAgentConfigPath()
		platform := runtimePlatform()
		fs.StringVar(&configPath, "config", configPath, "JSON configuration path")
		fs.StringVar(&platform, "platform", platform, "path platform: linux or windows")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		changed, err := migrateConfigLayout(configPath, platform)
		if err != nil {
			fmt.Fprintf(os.Stderr, "migrate config layout failed: %v\n", err)
			return 1
		}
		fmt.Fprintf(os.Stdout, "configuration layout migrated: changed=%v (%s)\n", changed, configPath)
		return 0
	case "help", "-h", "--help":
		printConfigUsage(os.Stdout)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown config command: %s\n", args[0])
		printConfigUsage(os.Stderr)
		return 2
	}
}

// migrateConfigLayout recursively updates known legacy SecWeaver-owned paths.
// Unknown strings are preserved so an installer cannot relocate custom inputs,
// external log files, or integration-specific output paths by accident.
func migrateConfigLayout(path, platform string) (bool, error) {
	platform = strings.ToLower(strings.TrimSpace(platform))
	if platform != "linux" && platform != "windows" {
		return false, fmt.Errorf("platform must be linux or windows")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	var payload any
	if err := json.Unmarshal(body, &payload); err != nil {
		return false, fmt.Errorf("parse config: %w", err)
	}
	changed := migrateConfigValue(payload, platform)
	if !changed {
		return false, nil
	}
	encoded, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return false, fmt.Errorf("encode config: %w", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	if err := writeFileAtomic(path, append(encoded, '\n'), info.Mode().Perm()); err != nil {
		return false, err
	}
	return true, nil
}

func migrateConfigValue(value any, platform string) bool {
	changed := false
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if text, ok := child.(string); ok {
				if migrated, pathChanged := layout.MigratePath(platform, text); pathChanged {
					typed[key] = migrated
					changed = true
				}
				continue
			}
			changed = migrateConfigValue(child, platform) || changed
		}
	case []any:
		for index, child := range typed {
			if text, ok := child.(string); ok {
				if migrated, pathChanged := layout.MigratePath(platform, text); pathChanged {
					typed[index] = migrated
					changed = true
				}
				continue
			}
			changed = migrateConfigValue(child, platform) || changed
		}
	}
	return changed
}

func runtimePlatform() string {
	if filepath.Separator == '\\' {
		return "windows"
	}
	return "linux"
}

func setEnterpriseIDInConfig(path, enterpriseID string) (string, error) {
	normalized, err := agentoutput.NormalizeEnterpriseID(enterpriseID)
	if err != nil {
		return "", fmt.Errorf("enterprise_id: %w", err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", fmt.Errorf("parse config: %w", err)
	}
	if payload == nil {
		return "", fmt.Errorf("config must be a JSON object")
	}
	encodedID, _ := json.Marshal(normalized)
	payload["enterprise_id"] = encodedID
	if err := validateAndWriteConfig(path, payload); err != nil {
		return "", err
	}
	return normalized, nil
}

func setLicenseInConfig(path string, licenseCfg agentlicense.Config) error {
	licenseCfg.ServerURL = strings.TrimSpace(licenseCfg.ServerURL)
	licenseCfg.CAFile = strings.TrimSpace(licenseCfg.CAFile)
	licenseCfg.Protocol = strings.TrimSpace(licenseCfg.Protocol)
	licenseCfg.EnrollmentID = strings.TrimSpace(licenseCfg.EnrollmentID)
	licenseCfg.StatePath = strings.TrimSpace(licenseCfg.StatePath)
	licenseCfg.IdentityKeyPath = strings.TrimSpace(licenseCfg.IdentityKeyPath)
	licenseCfg = licenseCfg.Normalize()
	if err := licenseCfg.Validate(); err != nil {
		return fmt.Errorf("license: %w", err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(body, &payload); err != nil {
		return fmt.Errorf("parse config: %w", err)
	}
	if payload == nil {
		return fmt.Errorf("config must be a JSON object")
	}
	encodedLicense, _ := json.Marshal(licenseCfg)
	payload["license"] = encodedLicense
	return validateAndWriteConfig(path, payload)
}

// setUpdateInConfig keeps signing opt-in: an omitted public key writes the
// HTTPS plus artifact-hash mode, while a supplied key is validated immediately.
func setUpdateInConfig(path string, cfg updateConfig) error {
	cfg.ManifestURL = strings.TrimSpace(cfg.ManifestURL)
	cfg.PublicKey = strings.TrimSpace(cfg.PublicKey)
	cfg.Channel = strings.TrimSpace(cfg.Channel)
	if cfg.Enabled {
		if !strings.HasPrefix(strings.ToLower(cfg.ManifestURL), "https://") {
			return fmt.Errorf("update manifest_url must use HTTPS")
		}
		if cfg.PublicKey != "" {
			if _, err := parseEd25519PublicKey(cfg.PublicKey); err != nil {
				return fmt.Errorf("update public_key: %w", err)
			}
		}
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(body, &payload); err != nil {
		return fmt.Errorf("parse config: %w", err)
	}
	if payload == nil {
		return fmt.Errorf("config must be a JSON object")
	}
	encodedUpdate, _ := json.Marshal(cfg)
	payload["update"] = encodedUpdate
	return validateAndWriteConfig(path, payload)
}

func ensureHostProcessSnapshotInConfig(path string) (bool, error) {
	return ensureModuleInConfig(path, "host-process-snapshot", moduleConfig{
		Enabled:             boolPointer(true),
		Restart:             "on_failure",
		RestartDelaySeconds: 5,
		Args: []string{
			"-interval", "10m",
			"-full-snapshot-interval", "24h",
			"-state", defaultHostProcessSnapshotStatePath(),
			"-collection-timeout", "45s",
			"-output", defaultHostProcessSnapshotOutputLogPath(),
		},
	})
}

func ensureHostStateSnapshotInConfig(path string) (bool, error) {
	return ensureModuleInConfig(path, "host-state-snapshot", moduleConfig{
		Enabled:             boolPointer(true),
		Restart:             "on_failure",
		RestartDelaySeconds: 5,
		Args: []string{
			"-socket-interval", "5m",
			"-identity-interval", "5m",
			"-service-interval", "5m",
			"-kernel-interval", "10m",
			"-full-snapshot-interval", "24h",
			"-max-fd-scan", "100000",
			"-output", defaultHostStateSnapshotOutputLogPath(),
		},
	})
}

func ensureModuleInConfig(path, moduleName string, module moduleConfig) (bool, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(body, &payload); err != nil {
		return false, fmt.Errorf("parse config: %w", err)
	}
	if payload == nil {
		return false, fmt.Errorf("config must be a JSON object")
	}
	modules := map[string]json.RawMessage{}
	if raw := payload["modules"]; len(raw) > 0 {
		if err := json.Unmarshal(raw, &modules); err != nil {
			return false, fmt.Errorf("parse modules: %w", err)
		}
	}
	for name := range modules {
		if normalizeModuleName(name) == normalizeModuleName(moduleName) {
			return false, nil
		}
	}
	encodedModule, err := json.Marshal(module)
	if err != nil {
		return false, err
	}
	modules[moduleName] = encodedModule
	encodedModules, err := json.Marshal(modules)
	if err != nil {
		return false, err
	}
	payload["modules"] = encodedModules
	if err := validateAndWriteConfig(path, payload); err != nil {
		return false, err
	}
	return true, nil
}

func optimizeCollectorsInConfig(path string) (bool, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(body, &payload); err != nil {
		return false, fmt.Errorf("parse config: %w", err)
	}
	modules := map[string]json.RawMessage{}
	if err := json.Unmarshal(payload["modules"], &modules); err != nil {
		return false, fmt.Errorf("parse modules: %w", err)
	}
	changed := false
	updateModule := func(normalized string, update func(*moduleConfig) bool) error {
		for name, raw := range modules {
			if normalizeModuleName(name) != normalized {
				continue
			}
			var cfg moduleConfig
			if err := json.Unmarshal(raw, &cfg); err != nil {
				return fmt.Errorf("parse module %s: %w", name, err)
			}
			if update(&cfg) {
				encoded, err := json.Marshal(cfg)
				if err != nil {
					return err
				}
				modules[name] = encoded
				changed = true
			}
			return nil
		}
		return nil
	}
	if err := updateModule("host-process-snapshot", func(cfg *moduleConfig) bool {
		changed := appendMissingFlag(&cfg.Args, "collection-timeout", "45s")
		changed = appendMissingFlag(&cfg.Args, "full-snapshot-interval", "24h") || changed
		changed = appendMissingFlag(&cfg.Args, "state", defaultHostProcessSnapshotStatePath()) || changed
		return changed
	}); err != nil {
		return false, err
	}
	if err := updateModule("host-state-snapshot", func(cfg *moduleConfig) bool {
		return appendMissingFlag(&cfg.Args, "max-fd-scan", "100000")
	}); err != nil {
		return false, err
	}
	riskEnabled := false
	if err := updateModule("windows-eventlog-risk-json", func(cfg *moduleConfig) bool {
		if cfg.Enabled != nil && !*cfg.Enabled {
			return false
		}
		riskEnabled = true
		moduleChanged := mergeCSVFlag(&cfg.Args, "channels", []string{"Security", "System", "Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-Sysmon/Operational"})
		if appendMissingFlag(&cfg.Args, "evidence-output", layout.WindowsLogs+`\windows-process-execmon.log`) {
			moduleChanged = true
		}
		return moduleChanged
	}); err != nil {
		return false, err
	}
	if riskEnabled {
		if err := updateModule("windows-process-execmon", func(cfg *moduleConfig) bool {
			if cfg.Enabled != nil && !*cfg.Enabled {
				return false
			}
			cfg.Enabled = boolPointer(false)
			return true
		}); err != nil {
			return false, err
		}
	}
	if !changed {
		return false, nil
	}
	encodedModules, err := json.Marshal(modules)
	if err != nil {
		return false, err
	}
	payload["modules"] = encodedModules
	if err := validateAndWriteConfig(path, payload); err != nil {
		return false, err
	}
	return true, nil
}

func appendMissingFlag(args *[]string, name, value string) bool {
	if _, ok := stringFlag(*args, name); ok {
		return false
	}
	*args = append(*args, "-"+name, value)
	return true
}

func mergeCSVFlag(args *[]string, name string, required []string) bool {
	current, ok := stringFlag(*args, name)
	if !ok {
		*args = append(*args, "-"+name, strings.Join(required, ","))
		return true
	}
	seen := map[string]bool{}
	var values []string
	for _, value := range append(strings.Split(current, ","), required...) {
		value = strings.TrimSpace(value)
		if value != "" && !seen[strings.ToLower(value)] {
			seen[strings.ToLower(value)] = true
			values = append(values, value)
		}
	}
	merged := strings.Join(values, ",")
	if merged == current {
		return false
	}
	for i := 0; i+1 < len(*args); i++ {
		if strings.TrimLeft((*args)[i], "-") == name {
			(*args)[i+1] = merged
			return true
		}
	}
	return false
}

func boolPointer(value bool) *bool {
	return &value
}

func validateAndWriteConfig(path string, payload map[string]json.RawMessage) error {
	encoded, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	encoded = append(encoded, '\n')
	var candidate agentConfig
	if err := decodeStrictJSON(encoded, &candidate); err != nil {
		return fmt.Errorf("validate config: %w", err)
	}
	if len(candidate.Modules) == 0 {
		return fmt.Errorf("validate config: modules is empty")
	}
	if _, err := enabledModules(candidate); err != nil {
		return fmt.Errorf("validate config: %w", err)
	}
	if _, err := scheduledUpdateFromConfig(candidate.Update); err != nil {
		return fmt.Errorf("validate config: update: %w", err)
	}
	licenseCfg := candidate.License.Normalize()
	if err := licenseCfg.Validate(); err != nil {
		return fmt.Errorf("validate config: license: %w", err)
	}
	if _, err := scheduledRemoteConfigFromConfig(candidate.RemoteConfig, path, licenseCfg, candidate.EnterpriseID); err != nil {
		return fmt.Errorf("validate config: remote_config: %w", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".secweaver-agent-config-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	committed := false
	defer func() {
		_ = tmp.Close()
		if !committed {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(info.Mode().Perm()); err != nil {
		return err
	}
	if _, err := tmp.Write(encoded); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	committed = true
	return nil
}

func printConfigUsage(out *os.File) {
	fmt.Fprintf(out, `Usage:
  secweaver-agent config set-enterprise-id -config <path> -enterprise-id <16-char-id>
  secweaver-agent config set-license -config <path> -protocol <legacy_v1|device_v2> -server-url <url> [-ca-file <path>] [-enrollment-id <id>]
  secweaver-agent config set-update -config <path> -manifest-url <https-url> [-public-key <base64>] [-ca-file <path>] [flags]
  secweaver-agent config ensure-host-process-snapshot -config <path>
  secweaver-agent config ensure-host-state-snapshot -config <path>
  secweaver-agent config optimize-collectors -config <path>
  secweaver-agent config migrate-layout -config <path> -platform <linux|windows>

`)
}

package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"secweaver-agent/internal/modulecontract"
	"secweaver-agent/pkg/agentlicense"
	"secweaver-agent/pkg/agentupdate"
	"secweaver-agent/pkg/metrics"
	agentoutput "secweaver-agent/pkg/output"
)

type moduleDescriptor = modulecontract.Descriptor

type moduleSpec = moduleDescriptor

type agentConfig struct {
	DeploymentMode string                       `json:"deployment_mode,omitempty"`
	EnterpriseID   string                       `json:"enterprise_id"`
	StatusPath     string                       `json:"status_path,omitempty"`
	Operations     operationsReportConfig       `json:"operations_report,omitempty"`
	License        agentlicense.Config          `json:"license,omitempty"`
	RemoteConfig   remoteConfigConfig           `json:"remote_config,omitempty"`
	Modules        map[string]moduleConfig      `json:"modules"`
	Update         updateConfig                 `json:"update,omitempty"`
	Metrics        metricsConfig                `json:"metrics,omitempty"`
	DiskBudget     agentoutput.DiskBudgetConfig `json:"disk_budget,omitempty"`
}

type operationsReportConfig struct {
	Enabled                 *bool  `json:"enabled,omitempty"`
	Output                  string `json:"output,omitempty"`
	SnapshotIntervalSeconds int    `json:"snapshot_interval_seconds,omitempty"`
	JitterSeconds           int    `json:"jitter_seconds,omitempty"`
	MaxSizeMB               int    `json:"max_size_mb,omitempty"`
	MaxBackups              int    `json:"max_backups,omitempty"`
	IncludeResourceUsage    *bool  `json:"include_resource_usage,omitempty"`
	IncludeShipperStatus    *bool  `json:"include_shipper_status,omitempty"`
}

type operationsReportRuntime struct {
	ConfigPath           string
	DeploymentMode       string
	Enabled              bool
	Output               string
	SnapshotInterval     time.Duration
	Jitter               time.Duration
	MaxSizeBytes         int64
	MaxBackups           int
	IncludeResourceUsage bool
	IncludeShipperStatus bool
}

type metricsConfig struct {
	Enabled       bool   `json:"enabled,omitempty"`
	ListenAddress string `json:"listen_address,omitempty"`
	Path          string `json:"path,omitempty"`
}

type remoteConfigConfig struct {
	Enabled             bool   `json:"enabled,omitempty"`
	URL                 string `json:"url,omitempty"`
	IntervalSeconds     int    `json:"interval_seconds,omitempty"`
	InitialDelaySeconds int    `json:"initial_delay_seconds,omitempty"`
	JitterSeconds       int    `json:"jitter_seconds,omitempty"`
	PublicKey           string `json:"public_key,omitempty"`
	RequireSignature    *bool  `json:"require_signature,omitempty"`
	AllowUnsigned       bool   `json:"allow_unsigned,omitempty"`
}

type moduleConfig struct {
	Enabled                *bool    `json:"enabled,omitempty"`
	Args                   []string `json:"args,omitempty"`
	Restart                string   `json:"restart,omitempty"`
	RestartDelaySeconds    int      `json:"restart_delay_seconds,omitempty"`
	RestartMaxDelaySeconds int      `json:"restart_max_delay_seconds,omitempty"`
	RestartFailureLimit    int      `json:"restart_failure_limit,omitempty"`
	RestartStableSeconds   int      `json:"restart_stable_seconds,omitempty"`
	RestartCircuitSeconds  int      `json:"restart_circuit_seconds,omitempty"`
}

type updateConfig struct {
	Enabled              bool              `json:"enabled,omitempty"`
	ManifestURL          string            `json:"manifest_url,omitempty"`
	CAFile               string            `json:"ca_file,omitempty"`
	Channel              string            `json:"channel,omitempty"`
	IntervalSeconds      int               `json:"interval_seconds,omitempty"`
	InitialDelaySeconds  int               `json:"initial_delay_seconds,omitempty"`
	JitterSeconds        int               `json:"jitter_seconds,omitempty"`
	RetryInitialSeconds  int               `json:"retry_initial_seconds,omitempty"`
	RetryMaxSeconds      int               `json:"retry_max_seconds,omitempty"`
	AutoInstall          *bool             `json:"auto_install,omitempty"`
	StateDir             string            `json:"state_dir,omitempty"`
	SelfPath             string            `json:"self_path,omitempty"`
	StatusOutput         string            `json:"status_output,omitempty"`
	DeviceID             string            `json:"device_id,omitempty"`
	HostID               string            `json:"host_id,omitempty"`
	PublicKey            string            `json:"public_key,omitempty"`
	TrustedPublicKeys    map[string]string `json:"trusted_public_keys,omitempty"`
	RevokedKeyIDs        []string          `json:"revoked_key_ids,omitempty"`
	AllowInsecureHTTP    bool              `json:"allow_insecure_http,omitempty"`
	AllowUnsignedLocal   bool              `json:"allow_unsigned_local,omitempty"` // Deprecated compatibility field.
	RequireServerPolicy  bool              `json:"require_server_policy,omitempty"`
	HealthTimeoutSeconds int               `json:"health_timeout_seconds,omitempty"`
	LockStaleSeconds     int               `json:"lock_stale_seconds,omitempty"`
	MaxBackups           int               `json:"max_backups,omitempty"`
	MinFreeSpaceMB       int               `json:"min_free_space_mb,omitempty"`
}

type runtimeModule struct {
	Spec         moduleDescriptor
	Config       moduleConfig
	EnterpriseID string
	HostName     string
	HostIP       string
}

type scheduledUpdateConfig struct {
	Options              agentupdate.Options
	Interval             time.Duration
	InitialDelay         time.Duration
	Jitter               time.Duration
	RetryInitial         time.Duration
	RetryMax             time.Duration
	AutoInstall          bool
	StatusOutput         string
	RequireServerPolicy  bool
	HealthTimeout        time.Duration
	HealthCheckPending   bool
	PolicyLeaseExpiresAt time.Time
}

type scheduledRemoteConfig struct {
	ConfigPath    string
	License       agentlicense.Config
	EnterpriseID  string
	URL           string
	Interval      time.Duration
	InitialDelay  time.Duration
	Jitter        time.Duration
	PublicKey     ed25519.PublicKey
	AllowUnsigned bool
}

func loadConfig(path string) (agentConfig, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return agentConfig{}, err
	}
	var cfg agentConfig
	if err := decodeStrictJSON(body, &cfg); err != nil {
		return agentConfig{}, err
	}
	if err := validateDeploymentMode(cfg.DeploymentMode); err != nil {
		return agentConfig{}, err
	}
	enterpriseID, err := agentoutput.NormalizeEnterpriseID(cfg.EnterpriseID)
	if err != nil {
		return agentConfig{}, fmt.Errorf("enterprise_id: %w", err)
	}
	cfg.EnterpriseID = enterpriseID
	if len(cfg.Modules) == 0 {
		return agentConfig{}, fmt.Errorf("modules is empty")
	}
	// Metrics configuration is validated during file loading so preflight and
	// service startup report the same deterministic error before binding ports.
	if _, err := metrics.NormalizeConfig(metrics.Config{
		Enabled:       cfg.Metrics.Enabled,
		ListenAddress: cfg.Metrics.ListenAddress,
		Path:          cfg.Metrics.Path,
	}); err != nil {
		return agentConfig{}, fmt.Errorf("metrics: %w", err)
	}
	normalizedBudget, err := agentoutput.NormalizeDiskBudgetConfig(cfg.DiskBudget)
	if err != nil {
		return agentConfig{}, fmt.Errorf("disk_budget: %w", err)
	}
	cfg.DiskBudget = normalizedBudget
	if _, err := normalizeOperationsReportConfig(cfg.Operations); err != nil {
		return agentConfig{}, fmt.Errorf("operations_report: %w", err)
	}
	return cfg, nil
}

// normalizeOperationsReportConfig applies one cross-platform production
// policy. Pointer booleans distinguish an omitted field, which enables the
// operational stream by default, from an explicit operator opt-out.
func normalizeOperationsReportConfig(config operationsReportConfig) (operationsReportRuntime, error) {
	runtimeConfig := operationsReportRuntime{
		Enabled:              true,
		Output:               defaultOperationsReportPath(),
		SnapshotInterval:     5 * time.Minute,
		Jitter:               time.Minute,
		MaxSizeBytes:         agentoutput.DefaultMaxSizeBytes,
		MaxBackups:           agentoutput.DefaultMaxBackups,
		IncludeResourceUsage: true,
		IncludeShipperStatus: true,
	}
	if config.Enabled != nil {
		runtimeConfig.Enabled = *config.Enabled
	}
	if strings.TrimSpace(config.Output) != "" {
		runtimeConfig.Output = strings.TrimSpace(config.Output)
	}
	if config.SnapshotIntervalSeconds < 0 || config.JitterSeconds < 0 || config.MaxSizeMB < 0 || config.MaxBackups < 0 {
		return operationsReportRuntime{}, fmt.Errorf("interval, jitter, max_size_mb, and max_backups must be >= 0")
	}
	if config.SnapshotIntervalSeconds > 0 {
		runtimeConfig.SnapshotInterval = time.Duration(config.SnapshotIntervalSeconds) * time.Second
	}
	if runtimeConfig.SnapshotInterval < time.Minute {
		return operationsReportRuntime{}, fmt.Errorf("snapshot_interval_seconds must be at least 60")
	}
	if config.JitterSeconds > 0 {
		runtimeConfig.Jitter = time.Duration(config.JitterSeconds) * time.Second
	}
	if runtimeConfig.Jitter > runtimeConfig.SnapshotInterval {
		return operationsReportRuntime{}, fmt.Errorf("jitter_seconds must not exceed snapshot_interval_seconds")
	}
	if config.MaxSizeMB > 0 {
		runtimeConfig.MaxSizeBytes = int64(config.MaxSizeMB) * 1024 * 1024
	}
	if config.MaxBackups > 0 {
		runtimeConfig.MaxBackups = config.MaxBackups
	}
	if config.IncludeResourceUsage != nil {
		runtimeConfig.IncludeResourceUsage = *config.IncludeResourceUsage
	}
	if config.IncludeShipperStatus != nil {
		runtimeConfig.IncludeShipperStatus = *config.IncludeShipperStatus
	}
	if runtimeConfig.Enabled && (runtimeConfig.Output == "" || runtimeConfig.Output == "-") {
		return operationsReportRuntime{}, fmt.Errorf("output must be a file path when enabled")
	}
	return runtimeConfig, nil
}

// configuredOutputFileCount returns the global retention divisor. Paths are
// deduplicated because two descriptors referring to one file must share one
// budget slot rather than accidentally receiving twice the host allocation.
func configuredOutputFileCount(modules []runtimeModule, updater *scheduledUpdateConfig, operations *operationsReportRuntime) int {
	paths := make(map[string]bool)
	for _, module := range modules {
		if module.Spec.OutputPaths == nil {
			continue
		}
		for _, path := range module.Spec.OutputPaths(module.Config.Args) {
			path = strings.TrimSpace(path)
			if path != "" && path != "-" {
				paths[path] = true
			}
		}
	}
	if updater != nil {
		if path := strings.TrimSpace(updater.StatusOutput); path != "" && path != "-" {
			paths[path] = true
		}
	}
	if operations != nil && operations.Enabled {
		if path := strings.TrimSpace(operations.Output); path != "" && path != "-" {
			paths[path] = true
		}
	}
	return len(paths)
}

func enabledModules(cfg agentConfig) ([]runtimeModule, error) {
	names := make([]string, 0, len(cfg.Modules))
	for name := range cfg.Modules {
		names = append(names, name)
	}
	sort.Strings(names)

	var modules []runtimeModule
	seenModules := make(map[string]string)
	for _, configuredName := range names {
		moduleCfg := cfg.Modules[configuredName]
		if moduleCfg.Enabled != nil && !*moduleCfg.Enabled {
			continue
		}
		spec, ok := findModule(configuredName)
		if !ok {
			return nil, fmt.Errorf("unknown module %q", configuredName)
		}
		if previous, exists := seenModules[spec.Name]; exists {
			return nil, fmt.Errorf("module %q is configured more than once via %q and %q", spec.Name, previous, configuredName)
		}
		seenModules[spec.Name] = configuredName
		if err := validateRestartPolicy(moduleCfg.Restart); err != nil {
			return nil, fmt.Errorf("module %s: %w", configuredName, err)
		}
		if moduleCfg.RestartDelaySeconds < 0 || moduleCfg.RestartMaxDelaySeconds < 0 || moduleCfg.RestartFailureLimit < 0 || moduleCfg.RestartStableSeconds < 0 || moduleCfg.RestartCircuitSeconds < 0 {
			return nil, fmt.Errorf("module %s: restart timing and failure values must be >= 0", configuredName)
		}
		if err := spec.ValidateArgs(moduleCfg.Args); err != nil {
			return nil, fmt.Errorf("module %s args: %w", configuredName, err)
		}
		modules = append(modules, runtimeModule{Spec: spec, Config: moduleCfg, EnterpriseID: cfg.EnterpriseID})
	}
	if len(modules) == 0 {
		return nil, fmt.Errorf("no enabled modules")
	}
	if err := validateWindowsReaderOwnership(modules); err != nil {
		return nil, err
	}
	return modules, nil
}

// validateWindowsReaderOwnership enforces one physical Windows Event Log
// reader for process evidence. Independent readers have separate cursors and
// can duplicate records, race output rotation, and double query load.
func validateWindowsReaderOwnership(modules []runtimeModule) error {
	var unified, standalone *runtimeModule
	for i := range modules {
		switch modules[i].Spec.Name {
		case "windows-eventlog-risk-json":
			unified = &modules[i]
		case "windows-process-execmon":
			standalone = &modules[i]
		}
	}
	if unified == nil || standalone == nil {
		return nil
	}
	if output, configured := modulecontract.StringFlag(unified.Config.Args, "evidence-output"); configured && strings.TrimSpace(output) == "" {
		return nil
	}
	return fmt.Errorf("modules windows-eventlog-risk-json and windows-process-execmon both own Windows process evidence; disable windows-process-execmon or set windows-eventlog-risk-json -evidence-output=\"\"")
}

func scheduledUpdateFromConfig(cfg updateConfig) (*scheduledUpdateConfig, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	manifestURL := strings.TrimSpace(cfg.ManifestURL)
	if manifestURL == "" {
		manifestURL = agentupdate.DefaultManifestURL()
	}
	if manifestURL == "" {
		return nil, fmt.Errorf("manifest_url is required when update.enabled=true")
	}
	channel := strings.TrimSpace(cfg.Channel)
	if channel == "" {
		channel = "stable"
	}
	if cfg.IntervalSeconds < 0 {
		return nil, fmt.Errorf("interval_seconds must be >= 0")
	}
	if cfg.InitialDelaySeconds < 0 {
		return nil, fmt.Errorf("initial_delay_seconds must be >= 0")
	}
	if cfg.JitterSeconds < 0 {
		return nil, fmt.Errorf("jitter_seconds must be >= 0")
	}
	if cfg.RetryInitialSeconds < 0 || cfg.RetryMaxSeconds < 0 {
		return nil, fmt.Errorf("retry_initial_seconds and retry_max_seconds must be >= 0")
	}
	if cfg.HealthTimeoutSeconds < 0 {
		return nil, fmt.Errorf("health_timeout_seconds must be >= 0")
	}
	if cfg.LockStaleSeconds < 0 || cfg.MaxBackups < 0 || cfg.MinFreeSpaceMB < 0 {
		return nil, fmt.Errorf("lock_stale_seconds, max_backups, and min_free_space_mb must be >= 0")
	}
	if strings.TrimSpace(cfg.DeviceID) != "" && strings.TrimSpace(cfg.HostID) != "" && strings.TrimSpace(cfg.DeviceID) != strings.TrimSpace(cfg.HostID) {
		return nil, fmt.Errorf("device_id conflicts with deprecated host_id")
	}
	interval := time.Duration(cfg.IntervalSeconds) * time.Second
	if interval == 0 {
		interval = 6 * time.Hour
	}
	initialDelay := time.Duration(cfg.InitialDelaySeconds) * time.Second
	jitter := time.Duration(cfg.JitterSeconds) * time.Second
	retryInitial := time.Duration(cfg.RetryInitialSeconds) * time.Second
	if retryInitial == 0 {
		retryInitial = time.Minute
	}
	retryMax := time.Duration(cfg.RetryMaxSeconds) * time.Second
	if retryMax == 0 {
		retryMax = time.Hour
	}
	if retryMax < retryInitial {
		return nil, fmt.Errorf("retry_max_seconds must be >= retry_initial_seconds")
	}
	healthTimeout := time.Duration(cfg.HealthTimeoutSeconds) * time.Second
	if healthTimeout == 0 {
		healthTimeout = 90 * time.Second
	}
	autoInstall := true
	if cfg.AutoInstall != nil {
		autoInstall = *cfg.AutoInstall
	}
	statusOutput := strings.TrimSpace(cfg.StatusOutput)
	if statusOutput == "" {
		statusOutput = "-"
	}
	var publicKey ed25519.PublicKey
	if strings.TrimSpace(cfg.PublicKey) != "" {
		key, err := parseEd25519PublicKey(cfg.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("public_key: %w", err)
		}
		publicKey = key
	}
	trustedPublicKeys := make(map[string]ed25519.PublicKey, len(cfg.TrustedPublicKeys))
	for keyID, encoded := range cfg.TrustedPublicKeys {
		key, err := parseEd25519PublicKey(encoded)
		if err != nil {
			return nil, fmt.Errorf("trusted_public_keys[%s]: %w", keyID, err)
		}
		if derived := agentupdate.PublicKeyID(key); keyID != derived {
			return nil, fmt.Errorf("trusted_public_keys key ID %q does not match derived ID %q", keyID, derived)
		}
		trustedPublicKeys[keyID] = key
	}
	opts := agentupdate.Options{
		ManifestURL:        manifestURL,
		CAFile:             strings.TrimSpace(cfg.CAFile),
		Channel:            channel,
		CurrentVersion:     version,
		StateDir:           cfg.StateDir,
		SelfPath:           cfg.SelfPath,
		DeviceID:           cfg.DeviceID,
		HostID:             cfg.HostID,
		PublicKey:          publicKey,
		TrustedPublicKeys:  trustedPublicKeys,
		RevokedKeyIDs:      append([]string(nil), cfg.RevokedKeyIDs...),
		AllowInsecureHTTP:  cfg.AllowInsecureHTTP,
		AllowUnsignedLocal: cfg.AllowUnsignedLocal,
		ServerManaged:      cfg.RequireServerPolicy,
		LockStaleAfter:     time.Duration(cfg.LockStaleSeconds) * time.Second,
		MaxBackups:         cfg.MaxBackups,
		MinFreeSpaceBytes:  uint64(cfg.MinFreeSpaceMB) * 1024 * 1024,
	}
	opts = normalizeUpdateOptions(opts)
	return &scheduledUpdateConfig{
		Options:             opts,
		Interval:            interval,
		InitialDelay:        initialDelay,
		Jitter:              jitter,
		RetryInitial:        retryInitial,
		RetryMax:            retryMax,
		AutoInstall:         autoInstall,
		StatusOutput:        statusOutput,
		RequireServerPolicy: cfg.RequireServerPolicy,
		HealthTimeout:       healthTimeout,
	}, nil
}

func scheduledRemoteConfigFromConfig(cfg remoteConfigConfig, configPath string, licenseCfg agentlicense.Config, enterpriseID string) (*scheduledRemoteConfig, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	if !licenseCfg.Enabled {
		return nil, fmt.Errorf("license.enabled must be true when remote_config.enabled=true")
	}
	if cfg.IntervalSeconds < 0 {
		return nil, fmt.Errorf("interval_seconds must be >= 0")
	}
	if cfg.InitialDelaySeconds < 0 {
		return nil, fmt.Errorf("initial_delay_seconds must be >= 0")
	}
	if cfg.JitterSeconds < 0 {
		return nil, fmt.Errorf("jitter_seconds must be >= 0")
	}
	interval := time.Duration(cfg.IntervalSeconds) * time.Second
	if interval == 0 {
		interval = 15 * time.Minute
	}
	initialDelay := time.Duration(cfg.InitialDelaySeconds) * time.Second
	jitter := time.Duration(cfg.JitterSeconds) * time.Second
	url := strings.TrimSpace(cfg.URL)
	if cfg.RequireSignature != nil && !*cfg.RequireSignature && !cfg.AllowUnsigned {
		return nil, fmt.Errorf("require_signature=false is no longer accepted; set allow_unsigned=true only in an isolated development environment")
	}
	if cfg.AllowUnsigned && cfg.RequireSignature != nil && *cfg.RequireSignature {
		return nil, fmt.Errorf("allow_unsigned=true conflicts with require_signature=true")
	}
	var publicKey ed25519.PublicKey
	if strings.TrimSpace(cfg.PublicKey) != "" {
		key, err := parseEd25519PublicKey(cfg.PublicKey)
		if err != nil {
			return nil, err
		}
		publicKey = key
	}
	if len(publicKey) == 0 && !cfg.AllowUnsigned {
		return nil, fmt.Errorf("public_key is required when remote_config.enabled=true")
	}
	if len(publicKey) > 0 && cfg.AllowUnsigned {
		return nil, fmt.Errorf("allow_unsigned=true cannot be combined with public_key")
	}
	return &scheduledRemoteConfig{
		ConfigPath:    configPath,
		License:       licenseCfg,
		EnterpriseID:  enterpriseID,
		URL:           url,
		Interval:      interval,
		InitialDelay:  initialDelay,
		Jitter:        jitter,
		PublicKey:     publicKey,
		AllowUnsigned: cfg.AllowUnsigned,
	}, nil
}

func parseEd25519PublicKey(value string) (ed25519.PublicKey, error) {
	value = strings.TrimSpace(value)
	if decoded, err := base64.StdEncoding.DecodeString(value); err == nil && len(decoded) == ed25519.PublicKeySize {
		return ed25519.PublicKey(decoded), nil
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public_key must be base64 or hex encoded Ed25519 public key")
	}
	return ed25519.PublicKey(decoded), nil
}

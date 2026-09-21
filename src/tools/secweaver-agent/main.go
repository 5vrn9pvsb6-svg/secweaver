package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"secweaver-agent/pkg/agentupdate"
	"secweaver-agent/pkg/layout"
	"secweaver-agent/pkg/metrics"
	agentoutput "secweaver-agent/pkg/output"
)

const defaultLinuxConfigPath = layout.LinuxEtc + "/config.json"
const defaultServiceRestartExitCode = 1
const configurationErrorExitCode = 78

// version is "development" for unversioned go run/go test builds. Release
// scripts inject the single VERSION file value through the linker.
var version = "development"

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		printUsage(os.Stderr)
		return 2
	}

	switch args[0] {
	case "run":
		return runAgentCommand(args[1:])
	case "service":
		return runServiceCommand(args[1:])
	case "preflight":
		return runPreflightCommand(args[1:])
	case "doctor":
		return runDoctorCommand(args[1:])
	case "collect-existing-logs":
		return runCollectExistingLogsCommand(args[1:])
	case "config":
		return runConfigCommand(args[1:])
	case "enroll":
		return runEnrollCommand(args[1:])
	case "audit-cleanup":
		return runAuditCleanupCommand(args[1:])
	case "module":
		return runModuleCommand(args[1:])
	case "update":
		return runUpdateCommand(args[1:])
	case "modules":
		printModules(os.Stdout)
		return 0
	case "version", "-version", "--version":
		printVersion(os.Stdout)
		return 0
	case "help", "-h", "--help":
		printUsage(os.Stdout)
		return 0
	default:
		if spec, ok := findModule(args[0]); ok {
			return spec.Run(args[1:])
		}
		fmt.Fprintf(os.Stderr, "unknown command or module: %s\n\n", args[0])
		printUsage(os.Stderr)
		return 2
	}
}

func runUpdateCommand(args []string) int {
	if len(args) == 0 {
		printUpdateUsage(os.Stderr)
		return 2
	}
	switch args[0] {
	case "check":
		return runUpdateAction("check", args[1:])
	case "install":
		return runUpdateAction("install", args[1:])
	case "rollback":
		return runUpdateAction("rollback", args[1:])
	case "help", "-h", "--help":
		printUpdateUsage(os.Stdout)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown update command: %s\n\n", args[0])
		printUpdateUsage(os.Stderr)
		return 2
	}
}

func runUpdateAction(action string, args []string) int {
	fs := flag.NewFlagSet("update "+action, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	manifestURL := ""
	caFile := ""
	channel := "stable"
	stateDir := agentupdate.DefaultStateDir()
	selfPath := ""
	deviceID := ""
	hostID := ""
	statusOutput := "-"
	publicKeyText := ""
	allowInsecureHTTP := false
	allowUnsignedLocal := false
	fs.StringVar(&manifestURL, "manifest-url", agentupdate.DefaultManifestURL(), "update manifest URL or local file path")
	fs.StringVar(&caFile, "ca-file", "", "optional PEM CA file for the update HTTPS endpoint")
	fs.StringVar(&channel, "channel", channel, "update channel")
	fs.StringVar(&stateDir, "state-dir", stateDir, "update state, backup, and lock directory")
	fs.StringVar(&selfPath, "self-path", "", "path to secweaver-agent binary; defaults to current executable")
	fs.StringVar(&deviceID, "device-id", "", "immutable rollout device identity")
	fs.StringVar(&hostID, "host-id", "", "deprecated alias for -device-id")
	fs.StringVar(&statusOutput, "status-output", statusOutput, "write update status JSON Lines to path; - means stderr")
	fs.StringVar(&publicKeyText, "public-key", "", "trusted Ed25519 public key in base64")
	fs.BoolVar(&allowInsecureHTTP, "allow-insecure-http", false, "development only: allow HTTP update URLs")
	fs.BoolVar(&allowUnsignedLocal, "allow-unsigned-local", false, "development only: allow an unsigned local manifest")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	var publicKey ed25519.PublicKey
	if strings.TrimSpace(publicKeyText) != "" {
		key, keyErr := parseEd25519PublicKey(publicKeyText)
		if keyErr != nil {
			fmt.Fprintf(os.Stderr, "invalid update public key: %v\n", keyErr)
			return 2
		}
		publicKey = key
	}
	opts := agentupdate.Options{
		ManifestURL:        manifestURL,
		CAFile:             caFile,
		Channel:            channel,
		CurrentVersion:     version,
		StateDir:           stateDir,
		SelfPath:           selfPath,
		DeviceID:           deviceID,
		HostID:             hostID,
		PublicKey:          publicKey,
		AllowInsecureHTTP:  allowInsecureHTTP,
		AllowUnsignedLocal: allowUnsignedLocal,
	}
	statusOut, closeStatus, err := agentupdate.OpenStatusOutput(statusOutput)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open status output failed: %v\n", err)
		return 1
	}
	defer closeStatus()

	var status agentupdate.Status
	switch action {
	case "check":
		status, err = agentupdate.Check(opts)
	case "install":
		status, err = agentupdate.Install(opts)
	case "rollback":
		status, err = agentupdate.Rollback(opts)
	}
	if writeErr := agentupdate.WriteStatus(statusOut, status); writeErr != nil {
		fmt.Fprintf(os.Stderr, "write update status failed: %v\n", writeErr)
		return 1
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "update %s failed: %v\n", action, err)
		return 1
	}
	return 0
}

func runAgentCommand(args []string) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := defaultAgentConfigPath()
	dryRun := false
	fs.StringVar(&configPath, "config", configPath, "agent JSON config path")
	fs.BoolVar(&dryRun, "dry-run", false, "validate config and print enabled modules without starting them")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	cfg, err := loadConfig(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load config failed: %v\n", err)
		return configurationErrorExitCode
	}
	modules, err := enabledModules(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config validation failed: %v\n", err)
		return configurationErrorExitCode
	}
	if runtime.GOOS == "linux" && runningInContainer() {
		if incompatible := containerIncompatibleModules(modules); len(incompatible) > 0 {
			// Fail before authorization or child startup. A container must never
			// partially start host-security modules and then appear healthy while
			// auditd rules or persistence watches are unavailable.
			fmt.Fprintf(os.Stderr, "config validation failed: container workload cannot enable %s; install the host Agent for host-security coverage\n", strings.Join(incompatible, ", "))
			return configurationErrorExitCode
		}
	}
	updateRuntime, err := scheduledUpdateFromConfig(cfg.Update)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config validation failed: update: %v\n", err)
		return configurationErrorExitCode
	}
	licenseRuntime := cfg.License.Normalize()
	if err := licenseRuntime.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "config validation failed: license: %v\n", err)
		return configurationErrorExitCode
	}
	if err := bindUpdateRuntimeToDevice(updateRuntime, licenseRuntime); err != nil {
		fmt.Fprintf(os.Stderr, "config validation failed: update: %v\n", err)
		return configurationErrorExitCode
	}
	remoteRuntime, err := scheduledRemoteConfigFromConfig(cfg.RemoteConfig, configPath, licenseRuntime, cfg.EnterpriseID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config validation failed: remote_config: %v\n", err)
		return configurationErrorExitCode
	}
	statusPath := strings.TrimSpace(cfg.StatusPath)
	if statusPath == "" {
		statusPath = defaultStatusPath()
	}
	operationsRuntime, err := normalizeOperationsReportConfig(cfg.Operations)
	if err != nil {
		fmt.Fprintf(os.Stderr, "configure operations report failed: %v\n", err)
		return configurationErrorExitCode
	}
	if dryRun {
		fmt.Fprintf(os.Stdout, "config ok: %s\n", configPath)
		fmt.Fprintf(os.Stdout, "- status path=%s\n", statusPath)
		for _, module := range modules {
			fmt.Fprintf(os.Stdout, "- %s args=%s restart=%s\n", module.Spec.Name, formatArgs(module.Config.Args), restartPolicy(module.Config.Restart))
		}
		if licenseRuntime.Enabled {
			fmt.Fprintf(os.Stdout, "- license enabled server=%s state=%s check_interval=%s heartbeat_interval=%s fail_closed=%v\n",
				licenseRuntime.ServerURL,
				licenseRuntime.StatePath,
				time.Duration(licenseRuntime.CheckIntervalSeconds)*time.Second,
				time.Duration(licenseRuntime.HeartbeatSeconds)*time.Second,
				licenseRuntime.FailClosedEnabled(),
			)
		}
		if updateRuntime != nil {
			mode := "check"
			if updateRuntime.AutoInstall {
				mode = "install"
			}
			fmt.Fprintf(os.Stdout, "- update %s manifest=%s channel=%s interval=%s device_id=%s\n",
				mode,
				updateRuntime.Options.ManifestURL,
				updateRuntime.Options.Channel,
				updateRuntime.Interval,
				updateRuntime.Options.DeviceID,
			)
		}
		if remoteRuntime != nil {
			fmt.Fprintf(os.Stdout, "- remote_config enabled url=%s interval=%s signed=%v\n",
				remoteRuntime.URL,
				remoteRuntime.Interval,
				!remoteRuntime.AllowUnsigned,
			)
		}
		fmt.Fprintf(os.Stdout, "- operations_report enabled=%v output=%s snapshot_interval=%s jitter=%s\n",
			operationsRuntime.Enabled, operationsRuntime.Output, operationsRuntime.SnapshotInterval, operationsRuntime.Jitter)
		printPreflightReport(os.Stdout, collectPreflightReport(configPath, modules, updateRuntime), true)
		return 0
	}
	if err := agentoutput.ApplyDiskBudgetEnvironment(cfg.DiskBudget, configuredOutputFileCount(modules, updateRuntime, &operationsRuntime)); err != nil {
		fmt.Fprintf(os.Stderr, "configure output disk budget failed: %v\n", err)
		return configurationErrorExitCode
	}
	if err := prepareUpdateActivation(updateRuntime); err != nil {
		if errors.Is(err, errRestartAfterUpdate) {
			fmt.Fprintf(os.Stderr, "%v; exiting so the service manager can activate the rollback\n", err)
			return serviceRestartExitCode()
		}
		fmt.Fprintf(os.Stderr, "update activation check failed: %v\n", err)
		return 1
	}

	statusTracker := newStatusTracker(statusPath, cfg.EnterpriseID, licenseRuntime, modules)
	statusTracker.write()
	statusTracker.startWriter()
	defer func() {
		if err := statusTracker.closeWriter(); err != nil {
			fmt.Fprintf(os.Stderr, "final status persistence failed: %v\n", err)
		}
	}()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// Construct the exporter before the initial authorization so the first check
	// contributes to counters. The socket is bound only after authorization passes.
	var metricsExporter *metrics.Exporter
	if cfg.Metrics.Enabled {
		metricsExporter = metrics.NewExporter(cfg.EnterpriseID, version)
		metricsExporter.SetHealthCheck(statusTracker.readiness)
	}
	if err := waitForInitialAgentLicense(ctx, licenseRuntime, cfg.EnterpriseID, statusTracker, metricsExporter, initialLicenseRetryDelay, maximumLicenseRetryDelay); err != nil {
		if errors.Is(err, context.Canceled) {
			return 0
		}
		fmt.Fprintf(os.Stderr, "license check failed: %v\n", err)
		return 1
	}

	// Metrics are optional: a bad observability endpoint must not disable host
	// collection, but a failed exporter is discarded to avoid useless updates.
	if metricsExporter != nil {
		metricsConfig := metrics.Config{
			Enabled:       cfg.Metrics.Enabled,
			ListenAddress: cfg.Metrics.ListenAddress,
			Path:          cfg.Metrics.Path,
		}
		metricsCtx, metricsCancel := context.WithCancel(ctx)
		defer metricsCancel()
		if err := metricsExporter.Start(metricsCtx, metricsConfig); err != nil {
			fmt.Fprintf(os.Stderr, "metrics exporter start warning: %v\n", err)
			metricsExporter = nil
		}
	}

	printPreflightReport(os.Stderr, collectPreflightReport(configPath, modules, updateRuntime), false)
	if err := runSupervisor(ctx, modules, updateRuntime, remoteRuntime, licenseRuntime, cfg.EnterpriseID, statusTracker, metricsExporter, &operationsRuntime); err != nil {
		if errors.Is(err, errRestartAfterUpdate) || errors.Is(err, errRemoteConfigApplied) {
			fmt.Fprintf(os.Stderr, "%v; exiting so the service manager can restart secweaver-agent\n", err)
			return serviceRestartExitCode()
		}
		fmt.Fprintf(os.Stderr, "agent stopped with error: %v\n", err)
		return 1
	}
	return 0
}

func serviceRestartExitCode() int {
	value := strings.TrimSpace(os.Getenv("SECWEAVER_AGENT_RESTART_EXIT_CODE"))
	if value == "" {
		return defaultServiceRestartExitCode
	}
	code, err := strconv.Atoi(value)
	if err != nil || code < 1 || code > 255 {
		return defaultServiceRestartExitCode
	}
	return code
}

func runPreflightCommand(args []string) int {
	fs := flag.NewFlagSet("preflight", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := defaultAgentConfigPath()
	strict := false
	verbose := true
	fs.StringVar(&configPath, "config", configPath, "agent JSON config path")
	fs.BoolVar(&strict, "strict", false, "return non-zero when preflight reports ERROR checks")
	fs.BoolVar(&verbose, "verbose", true, "include OK checks in the report")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := loadConfig(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load config failed: %v\n", err)
		return 1
	}
	modules, err := enabledModules(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config validation failed: %v\n", err)
		return 1
	}
	updateRuntime, err := scheduledUpdateFromConfig(cfg.Update)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config validation failed: update: %v\n", err)
		return 1
	}
	licenseRuntime := cfg.License.Normalize()
	if err := licenseRuntime.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "config validation failed: license: %v\n", err)
		return 1
	}
	if _, err := scheduledRemoteConfigFromConfig(cfg.RemoteConfig, configPath, licenseRuntime, cfg.EnterpriseID); err != nil {
		fmt.Fprintf(os.Stderr, "config validation failed: remote_config: %v\n", err)
		return 1
	}
	report := collectPreflightReport(configPath, modules, updateRuntime)
	printPreflightReport(os.Stdout, report, verbose)
	if strict && preflightHasErrors(report) {
		return 1
	}
	return 0
}

func defaultAgentConfigPath() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(layout.WindowsRootDir(), "etc", "config.json")
	}
	return defaultLinuxConfigPath
}

func runModuleCommand(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "missing module name")
		printModules(os.Stderr)
		return 2
	}
	spec, ok := findModule(args[0])
	if !ok {
		fmt.Fprintf(os.Stderr, "unknown module: %s\n", args[0])
		printModules(os.Stderr)
		return 2
	}
	return spec.Run(args[1:])
}

func printUsage(out *os.File) {
	fmt.Fprintf(out, `secweaver-agent %s

Usage:
	  secweaver-agent run -config %s
	  secweaver-agent service -config %s
	  secweaver-agent preflight -config %s
	  secweaver-agent doctor -config %s
	  %s
	  secweaver-agent config set-enterprise-id -config %s -enterprise-id <16-char-id>
	  secweaver-agent enroll -server-url <url> -enterprise-enrollment-token <token>
  secweaver-agent audit-cleanup
  secweaver-agent module <module-name> [module flags...]
  secweaver-agent <module-name> [module flags...]
  secweaver-agent update <check|install|rollback> [flags...]
  secweaver-agent modules
  secweaver-agent version

	`, version, defaultAgentConfigPath(), defaultAgentConfigPath(), defaultAgentConfigPath(), defaultAgentConfigPath(), collectExistingLogsUsageLine(), defaultAgentConfigPath())
	printModules(out)
}

func printUpdateUsage(out *os.File) {
	fmt.Fprintf(out, `Usage:
  secweaver-agent update check -manifest-url <url-or-path> [flags...]
  secweaver-agent update install -manifest-url <url-or-path> [flags...]
  secweaver-agent update rollback [flags...]

Flags:
  -manifest-url       update manifest URL or local file path; defaults to SECWEAVER_AGENT_UPDATE_MANIFEST_URL
  -channel            update channel (default stable)
  -state-dir          update state, backup, and lock directory
  -self-path          path to secweaver-agent binary; defaults to current executable
	  -device-id          immutable rollout device identity
	  -host-id            deprecated alias for -device-id
  -status-output      status JSON Lines path; - means stderr

`)
}

func printVersion(out *os.File) {
	fmt.Fprintf(out, "secweaver-agent %s\n", version)
	printModules(out)
}

func printModules(out *os.File) {
	names := make([]string, 0, len(moduleRegistry))
	for name := range moduleRegistry {
		names = append(names, name)
	}
	sort.Strings(names)
	fmt.Fprintln(out, "Built-in modules:")
	for _, name := range names {
		spec := moduleRegistry[name]
		fmt.Fprintf(out, "  - %s [%s]: %s\n", spec.Name, strings.Join(spec.Platforms, "/"), spec.Description)
	}
}

func formatArgs(args []string) string {
	if len(args) == 0 {
		return "[]"
	}
	body, err := json.Marshal(args)
	if err != nil {
		return strings.Join(args, " ")
	}
	return string(body)
}

func sleepContext(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

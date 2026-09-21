package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"
)

const defaultExistingLogsLookback = 180 * 24 * time.Hour

func runCollectExistingLogsCommand(args []string) int {
	fs := flag.NewFlagSet("collect-existing-logs", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := defaultAgentConfigPath()
	lookback := defaultExistingLogsLookback
	outputPath := ""
	minLevel := "medium"
	includeRaw := false
	securePath := ""
	messagesPath := ""
	channels := ""
	maxEvents := 1000
	failOnError := false
	fs.StringVar(&configPath, "config", configPath, "agent JSON config path; enterprise_id and module defaults are read from it")
	fs.DurationVar(&lookback, "lookback", defaultExistingLogsLookback, "existing-log lookback window; default 4320h (180 days)")
	fs.StringVar(&outputPath, "output", "", "override JSON Lines output path; empty uses module config/default")
	fs.StringVar(&minLevel, "min-level", minLevel, "minimum severity: info/low/medium/high/critical")
	fs.BoolVar(&includeRaw, "raw", false, "include raw log/event payload")
	fs.StringVar(&securePath, "secure", "", "Linux secure/auth log path override; auto means detect")
	fs.StringVar(&messagesPath, "messages", "", "Linux messages/syslog path override; auto means detect")
	fs.StringVar(&channels, "channels", "", "Windows Event Log channels override")
	fs.IntVar(&maxEvents, "max-events", maxEvents, "Windows maximum events queried from each channel per page")
	fs.BoolVar(&failOnError, "fail-on-error", false, "return non-zero on read/query errors")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if lookback <= 0 {
		fmt.Fprintln(os.Stderr, "-lookback must be positive")
		return 2
	}
	cfg, err := loadConfig(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load config failed: %v\n", err)
		return 1
	}
	if cfg.EnterpriseID != "" {
		_ = os.Setenv("SECWEAVER_ENTERPRISE_ID", cfg.EnterpriseID)
	}
	switch runtime.GOOS {
	case "windows":
		return runWindowsExistingLogCollection(cfg, lookback, outputPath, minLevel, includeRaw, channels, maxEvents, failOnError)
	case "linux":
		return runLinuxExistingLogCollection(cfg, lookback, outputPath, minLevel, includeRaw, securePath, messagesPath, failOnError)
	default:
		fmt.Fprintf(os.Stderr, "collect-existing-logs is only supported on Linux and Windows; current platform is %s\n", runtime.GOOS)
		return 1
	}
}

func runLinuxExistingLogCollection(cfg agentConfig, lookback time.Duration, outputPath, minLevel string, includeRaw bool, securePath, messagesPath string, failOnError bool) int {
	args := buildLinuxExistingLogArgs(cfg, lookback, outputPath, minLevel, includeRaw, securePath, messagesPath, failOnError)
	return syslogModule().Run(args)
}

func buildLinuxExistingLogArgs(cfg agentConfig, lookback time.Duration, outputPath, minLevel string, includeRaw bool, securePath, messagesPath string, failOnError bool) []string {
	args := moduleArgsFromConfig(cfg, "syslog-risk-json")
	args = append(args, "-backfill", "-lookback", lookback.String(), "-min-level", minLevel)
	if outputPath != "" {
		args = append(args, "-output", outputPath)
	}
	if securePath != "" {
		args = append(args, "-secure", securePath)
	}
	if messagesPath != "" {
		args = append(args, "-messages", messagesPath)
	}
	if includeRaw {
		args = append(args, "-raw")
	}
	if failOnError {
		args = append(args, "-fail-on-read-error")
	}
	return args
}

func runWindowsExistingLogCollection(cfg agentConfig, lookback time.Duration, outputPath, minLevel string, includeRaw bool, channels string, maxEvents int, failOnError bool) int {
	args := buildWindowsExistingLogArgs(cfg, lookback, outputPath, minLevel, includeRaw, channels, maxEvents, failOnError)
	return windowsEventLogRiskModule().Run(args)
}

func buildWindowsExistingLogArgs(cfg agentConfig, lookback time.Duration, outputPath, minLevel string, includeRaw bool, channels string, maxEvents int, failOnError bool) []string {
	args := moduleArgsFromConfig(cfg, "windows-eventlog-risk-json")
	args = append(args, "-once", "-lookback", lookback.String(), "-state-file", "", "-min-level", minLevel, "-max-events", fmt.Sprintf("%d", maxEvents))
	if outputPath != "" {
		args = append(args, "-output", outputPath)
	}
	if channels != "" {
		args = append(args, "-channels", channels)
	}
	if includeRaw {
		args = append(args, "-raw")
	}
	if failOnError {
		args = append(args, "-fail-on-query-error")
	}
	return args
}

func moduleArgsFromConfig(cfg agentConfig, name string) []string {
	for configuredName, moduleCfg := range cfg.Modules {
		if normalizeModuleName(configuredName) != name {
			continue
		}
		if moduleCfg.Enabled != nil && !*moduleCfg.Enabled {
			return nil
		}
		return append([]string(nil), moduleCfg.Args...)
	}
	return nil
}

func syslogModule() moduleSpec {
	spec, _ := findModule("syslog-risk-json")
	return spec
}

func windowsEventLogRiskModule() moduleSpec {
	spec, _ := findModule("windows-eventlog-risk-json")
	return spec
}

func collectExistingLogsUsageLine() string {
	return strings.TrimSpace("secweaver-agent collect-existing-logs -config " + defaultAgentConfigPath() + " [-lookback 4320h]")
}

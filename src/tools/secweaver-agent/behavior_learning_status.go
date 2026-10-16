package main

import (
	"strconv"
	"strings"
	"time"

	"secweaver-agent/internal/modulecontract"
	"secweaver-agent/internal/windowsevidence"
	"secweaver-agent/pkg/agentlicense"
	"secweaver-agent/pkg/auditportexecmon"
	"secweaver-agent/pkg/behaviorlearning"
	"secweaver-agent/pkg/layout"
	"secweaver-agent/pkg/windowseventlogriskjson"
)

// behaviorLearningStatus reads bounded local checkpoints, never native event
// sources. The top level remains the historical exec projection; independent
// leaves prevent an exec baseline from certifying file/network/risk filtering.
// Probe failures cannot interrupt evidence collection or license renewal.
func behaviorLearningStatus(modules []runtimeModule, health map[string]agentlicense.ModuleHealth, licenseCfg agentlicense.Config, enterpriseID string) *behaviorlearning.StatusSnapshot {
	streams := map[string]behaviorlearning.StatusSnapshot{}
	for _, kind := range []string{"exec", "file", "network", "risk"} {
		streams[kind] = behaviorlearning.StatusSnapshot{Mode: "disabled", Reason: "collector_disabled", FilteringReason: "collector_disabled"}
	}
	seen := map[string]bool{}
	for _, module := range modules {
		// First configured owner wins per stream, matching module ownership. The
		// unified Windows risk reader can delegate evidence while retaining risk.
		put := func(kind string, status behaviorlearning.StatusSnapshot, err error) {
			if !seen[kind] {
				streams[kind] = qualifyLearningRuntime(status, err, health[module.Spec.Name])
				seen[kind] = true
			}
		}
		switch module.Spec.Name {
		case "audit-port-execmon":
			configPath, _ := modulecontract.StringFlag(module.Config.Args, "config")
			outputPath, _ := modulecontract.StringFlag(module.Config.Args, "output-log")
			status, err := auditportexecmon.ReadLearningStatus(configPath, outputPath)
			put("exec", status, err)
			status, err = auditportexecmon.ReadFileLearningStatus(configPath, outputPath)
			put("file", status, err)
		case "windows-eventlog-risk-json", "windows-process-execmon":
			if module.Spec.Name == "windows-eventlog-risk-json" {
				status, err := readHeartbeatRiskLearning(module.Config.Args, licenseCfg, enterpriseID)
				put("risk", status, err)
			}
			cursor, _ := modulecontract.StringFlag(module.Config.Args, "state-file")
			eventPath, flag := layout.WindowsLogs+`\windows-process-execmon.log`, "output"
			if module.Spec.Name == "windows-eventlog-risk-json" {
				flag = "evidence-output"
			}
			if value, ok := modulecontract.StringFlag(module.Config.Args, flag); ok {
				eventPath = value
			}
			if strings.TrimSpace(eventPath) == "" {
				continue
			}
			status, err := windowsevidence.ReadLearningStatus(module.Config.Args, cursor, eventPath)
			put("exec", status, err)
			status, err = windowsevidence.ReadFileLearningStatus(module.Config.Args, cursor, eventPath)
			put("file", status, err)
			status, err = windowsevidence.ReadNetworkLearningStatus(module.Config.Args, cursor, eventPath)
			put("network", status, err)
		}
	}
	result := streams["exec"]
	result.Streams = streams
	return &result
}

// A prior process can leave a fresh summary. Qualify each stream against its
// actual collector start, without overwriting why the baseline itself is empty.
// Missing/failed probes cannot establish a prior runtime: keep their diagnosis
// rather than misleading operators into restarting an already running host.
func qualifyLearningRuntime(status behaviorlearning.StatusSnapshot, err error, health agentlicense.ModuleHealth) behaviorlearning.StatusSnapshot {
	if err != nil && status.Mode == "" {
		status = behaviorlearning.StatusSnapshot{Mode: "unknown", Reason: "status_unavailable", FilteringReason: "status_unavailable"}
	}
	if status.Enabled {
		started, startErr := time.Parse(time.RFC3339, health.LastStartAt)
		updated, updateErr := time.Parse(time.RFC3339, status.UpdatedAt)
		if health.Status != "running" {
			status.FilteringActive, status.FilteringReason = false, "collector_not_running"
		} else if updateErr != nil {
			status.FilteringActive = false
			if status.FilteringReason == "" {
				status.FilteringReason = "summary_unavailable"
			}
		} else if startErr != nil {
			status.FilteringActive, status.FilteringReason = false, "runtime_start_unknown"
		} else if updated.Before(started) {
			status.FilteringActive, status.FilteringReason = false, "awaiting_current_runtime"
		}
	}
	// The checkpoint may be intact while its sole owner is stopped/restarting.
	// Runtime qualification can only remove readiness, never create it.
	if status.FilteringReason != "active" && status.FilteringReason != "baseline_empty" {
		status.RelearningEligible = false
	}
	return status
}

// Risk has a separate identity-bound policy and local runtime file. Omitted
// flags mean disabled; they must not trigger checkpoint reads or new defaults.
func readHeartbeatRiskLearning(args []string, licenseCfg agentlicense.Config, enterpriseID string) (behaviorlearning.StatusSnapshot, error) {
	enabled, _, err := modulecontract.BoolFlag(args, "risk-behavior-learning")
	if err != nil {
		return behaviorlearning.StatusSnapshot{}, err
	}
	if !enabled {
		return behaviorlearning.Snapshot(behaviorlearning.Config{}, nil, nil, time.Now()), nil
	}
	shadow, _, err := modulecontract.BoolFlag(args, "risk-learning-shadow")
	if err != nil {
		return behaviorlearning.StatusSnapshot{}, err
	}
	options := windowseventlogriskjson.RiskLearningOptions{Enabled: enabled, Shadow: shadow, Duration: 24 * time.Hour}
	if v, ok := modulecontract.StringFlag(args, "risk-learning-duration"); ok {
		options.Duration, err = time.ParseDuration(v)
		if err != nil {
			return behaviorlearning.StatusSnapshot{}, err
		}
	}
	if v, ok := modulecontract.StringFlag(args, "risk-learning-generation"); ok {
		options.Generation, err = strconv.ParseUint(v, 10, 64)
		if err != nil {
			return behaviorlearning.StatusSnapshot{}, err
		}
	}
	options.StateDir, _ = modulecontract.StringFlag(args, "risk-learning-state-dir")
	cursor := layout.WindowsData + `\windows-eventlog-risk-json.cursor.json`
	if v, ok := modulecontract.StringFlag(args, "state-file"); ok {
		cursor = v
	}
	unknown := behaviorlearning.StatusSnapshot{Enabled: true, Mode: "unknown", Shadow: shadow, Reason: "identity_unavailable", FilteringReason: "identity_unavailable"}
	identity, err := agentlicense.LoadState(licenseCfg.Normalize().StatePath)
	if err != nil || !licenseCfg.Enabled || identity.DeviceID == "" || identity.EnterpriseID != enterpriseID || identity.RegisteredAt == "" {
		return unknown, err
	}
	return windowseventlogriskjson.ReadRiskLearningStatus(options, cursor, "", identity.DeviceID)
}

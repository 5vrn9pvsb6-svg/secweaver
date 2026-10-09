package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"secweaver-agent/internal/modulecontract"
	"secweaver-agent/internal/windowsevidence"
	"secweaver-agent/pkg/agentlicense"
	"secweaver-agent/pkg/layout"
	"secweaver-agent/pkg/windowseventlogriskjson"
)

// doctorCheckWindowsLearning reuses preflight's channel observation: repeated
// PowerShell probes create their own audit load. Configuration is not proof of
// filtering readiness; complete fields and the runtime baseline state remain
// necessary even when the native channel is accessible.
func doctorCheckWindowsLearning(cfg agentConfig, modules []runtimeModule, sysmon bool, add func(doctorLevel, string, string, string)) {
	if !cfg.License.Enabled {
		add(doctorWarn, "authorization", "Managed authorization is disabled", "Local collection/test configuration; this is not proof of SaaS registration")
	}
	for _, module := range modules {
		if module.Spec.Name != "windows-eventlog-risk-json" && module.Spec.Name != "windows-process-execmon" {
			continue
		}
		if module.Spec.Name == "windows-eventlog-risk-json" {
			doctorCheckWindowsRiskLearning(cfg, module.Config.Args, add)
		}
		enabled, _, err := modulecontract.BoolFlag(module.Config.Args, "behavior-learning")
		shadow, _, shadowErr := modulecontract.BoolFlag(module.Config.Args, "learning-shadow")
		if err != nil || shadowErr != nil {
			add(doctorError, "learning/config", "Invalid Windows learning flags", module.Spec.Name)
			continue
		}
		if !enabled {
			add(doctorWarn, "learning/config", "Windows behavior learning is disabled in the current configuration", "Upgrades preserve existing choices; explicitly rerun the installer with -LearningMode shadow or enable")
			continue
		}
		add(doctorOK, "learning/config", "Windows learning policy is enabled", fmt.Sprintf("module=%s shadow=%t; not proof of active suppression", module.Spec.Name, shadow))
		cursor, _ := modulecontract.StringFlag(module.Config.Args, "state-file")
		eventPath := layout.WindowsLogs + `\windows-process-execmon.log`
		outputFlag := "output"
		if module.Spec.Name == "windows-eventlog-risk-json" {
			outputFlag = "evidence-output"
		}
		if value, ok := modulecontract.StringFlag(module.Config.Args, outputFlag); ok {
			eventPath = value
		}
		// An empty evidence path transfers ownership to the other reader.
		if strings.TrimSpace(eventPath) != "" {
			execStatus, execErr := windowsevidence.ReadLearningStatus(module.Config.Args, cursor, eventPath)
			doctorReportStreamLearning("exec", execStatus, execErr, add)
			fileStatus, fileErr := windowsevidence.ReadFileLearningStatus(module.Config.Args, cursor, eventPath)
			doctorReportFileLearning(fileStatus, fileErr, add)
			networkStatus, networkErr := windowsevidence.ReadNetworkLearningStatus(module.Config.Args, cursor, eventPath)
			doctorReportStreamLearning("network", networkStatus, networkErr, add)
		}
		state, err := agentlicense.LoadState(cfg.License.Normalize().StatePath)
		if err != nil || state.DeviceID == "" || state.EnterpriseID != cfg.EnterpriseID || state.RegisteredAt == "" || !cfg.License.Enabled {
			add(doctorWarn, "learning/identity", "Registered device identity unavailable or does not match configuration", "Original events remain available; complete managed device registration before learning")
		}
		if !sysmon {
			add(doctorWarn, "learning/capability", "Sysmon is missing or inaccessible; file/network command correlation is unavailable", "Security 4688 with a complete command can learn when configured sources are healthy; a configured unavailable channel degrades evidence learning. Native PowerShell learning is independent of Sysmon")
		} else {
			add(doctorOK, "learning/capability", "Sysmon is accessible", "Exact tuples qualify after five events within one hour; incomplete context and protected risk alerts retain originals")
		}
	}
}

// doctorCheckWindowsRiskLearning reports authenticated risk baseline progress
// separately from exec. It reads bounded local state/tails, never queries Event
// Log or takes ownership of the live collector's baseline lock.
func doctorCheckWindowsRiskLearning(cfg agentConfig, args []string, add func(doctorLevel, string, string, string)) {
	enabled, _, err := modulecontract.BoolFlag(args, "risk-behavior-learning")
	shadow, _, shadowErr := modulecontract.BoolFlag(args, "risk-learning-shadow")
	o := windowseventlogriskjson.RiskLearningOptions{Enabled: enabled, Shadow: shadow, Duration: 24 * time.Hour}
	var durationErr error
	if value, ok := modulecontract.StringFlag(args, "risk-learning-duration"); ok {
		o.Duration, durationErr = time.ParseDuration(value)
	}
	if err != nil || shadowErr != nil || durationErr != nil {
		add(doctorError, "risk-learning/config", "Invalid Windows risk learning flags", "Check risk learning boolean flags and duration")
		return
	}
	if value, ok := modulecontract.StringFlag(args, "risk-learning-generation"); ok {
		o.Generation, err = strconv.ParseUint(value, 10, 64)
		if err != nil {
			add(doctorError, "risk-learning/config", "Invalid risk learning generation", "Use a nonnegative integer")
			return
		}
	}
	if !enabled {
		add(doctorWarn, "risk-learning/config", "Windows risk learning is disabled", "Original risk events retained; -LearningMode enable or shadow explicitly migrates the unified reader")
		return
	}
	o.StateDir, _ = modulecontract.StringFlag(args, "risk-learning-state-dir")
	cursor := layout.WindowsData + `\windows-eventlog-risk-json.cursor.json`
	if value, ok := modulecontract.StringFlag(args, "state-file"); ok {
		cursor = value
	}
	output := layout.WindowsLogs + `\windows-eventlog-risk-json.log`
	if value, ok := modulecontract.StringFlag(args, "output"); ok {
		output = value
	}
	add(doctorOK, "risk-learning/config", "Windows risk learning policy is enabled", fmt.Sprintf("shadow=%t; exact complete PowerShell script blocks; independent of Sysmon", shadow))
	identity, err := agentlicense.LoadState(cfg.License.Normalize().StatePath)
	if err != nil || !cfg.License.Enabled || identity.EnterpriseID != cfg.EnterpriseID || identity.RegisteredAt == "" {
		add(doctorWarn, "risk-learning/identity", "Registered risk learning identity unavailable", "Original risk events retained")
		return
	}
	status, err := windowseventlogriskjson.ReadRiskLearningStatus(o, cursor, output, identity.DeviceID)
	if err != nil {
		add(doctorWarn, "risk-learning/status", "Risk baseline is unavailable or invalid", err.Error())
		return
	}
	level := doctorOK
	if status.Mode == "unknown" || status.Mode == "degraded" {
		level = doctorWarn
	}
	add(level, "risk-learning/status", "Windows risk learning status", fmt.Sprintf("mode=%s started_at=%s remaining_seconds=%d filtering_active=%t baseline_entries=%d candidate_entries=%d updated_at=%s reason=%s",
		status.Mode, status.StartedAt, status.RemainingSeconds, status.FilteringActive, status.BaselineEntries, status.CandidateEntries, status.UpdatedAt, status.Reason))
}

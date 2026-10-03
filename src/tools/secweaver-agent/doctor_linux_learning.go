package main

import (
	"fmt"
	"strings"

	"secweaver-agent/internal/modulecontract"
	"secweaver-agent/pkg/auditportexecmon"
)

// doctorCheckLinuxLearning reports both policy and runtime progress. The policy
// warning is intentionally actionable: preserve is the safe upgrade default,
// while enable/shadow must be an operator decision.
func doctorCheckLinuxLearning(modules []runtimeModule, add func(doctorLevel, string, string, string)) {
	for _, module := range modules {
		if module.Spec.Name != "audit-port-execmon" {
			continue
		}
		configPath, ok := modulecontract.StringFlag(module.Config.Args, "config")
		if !ok {
			configPath = ""
		}
		outputPath, _ := modulecontract.StringFlag(module.Config.Args, "output-log")
		status, err := auditportexecmon.ReadLearningStatus(strings.TrimSpace(configPath), outputPath)
		if err != nil {
			add(doctorWarn, "learning/status", "Linux behavior learning state is unavailable or invalid", fmt.Sprintf("mode=%s; %v; original audit events remain available", status.Mode, err))
			return
		}
		if !status.Enabled {
			add(doctorWarn, "learning/config", "Linux behavior learning is disabled", "behavior learning: disabled; reason=config-disabled; rerun the installer with --learning-mode enable or shadow to opt in")
			return
		}
		add(doctorOK, "learning/config", "Linux behavior learning policy is enabled", fmt.Sprintf("mode=%s shadow=%t", status.Mode, status.Shadow))
		level := doctorOK
		if status.Mode == "unknown" || status.Mode == "degraded" || status.UpdatedAt == "" {
			level = doctorWarn
		}
		add(level, "learning/status", "Linux behavior learning status", fmt.Sprintf("mode=%s started_at=%s remaining_seconds=%d filtering_active=%t baseline_entries=%d updated_at=%s reason=%s", status.Mode, status.StartedAt, status.RemainingSeconds, status.FilteringActive, status.BaselineEntries, status.UpdatedAt, status.Reason))
		return
	}
	add(doctorWarn, "learning/config", "Linux behavior learning is unavailable because audit-port-execmon is disabled", "Enable the audit module before selecting --learning-mode enable or shadow")
}

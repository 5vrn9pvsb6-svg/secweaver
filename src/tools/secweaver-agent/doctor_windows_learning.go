package main

import (
	"fmt"

	"secweaver-agent/internal/modulecontract"
	"secweaver-agent/pkg/agentlicense"
)

// doctorCheckWindowsLearning reuses preflight's channel observation: repeated
// PowerShell probes create their own audit load. Configuration is not proof of
// filtering readiness; eligible GUID/hash/context and runtime baseline state
// remain necessary even with an accessible Sysmon channel.
func doctorCheckWindowsLearning(cfg agentConfig, modules []runtimeModule, sysmon bool, add func(doctorLevel, string, string, string)) {
	if !cfg.License.Enabled {
		add(doctorWarn, "authorization", "Managed authorization is disabled", "Local collection/test configuration; this is not proof of SaaS registration")
	}
	for _, module := range modules {
		if module.Spec.Name != "windows-eventlog-risk-json" && module.Spec.Name != "windows-process-execmon" {
			continue
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
		state, err := agentlicense.LoadState(cfg.License.Normalize().StatePath)
		if err != nil || state.DeviceID == "" || state.EnterpriseID != cfg.EnterpriseID || state.RegisteredAt == "" || !cfg.License.Enabled {
			add(doctorWarn, "learning/identity", "Registered device identity unavailable or does not match configuration", "Original events remain available; complete managed device registration before learning")
		}
		if !sysmon {
			add(doctorWarn, "learning/capability", "Sysmon is missing or inaccessible; Sysmon-based whitelist reduction is unavailable", "Security 4688 process events and risk events remain full-output; collection continues without eligible Sysmon GUID/SHA256 context")
		} else {
			add(doctorWarn, "learning/readiness", "Sysmon is accessible; baseline filtering is not certified by doctor", "Verify behavior-learning.log and eligible GUID/SHA256 context. Security 4688, risk events and incomplete context always retain originals")
		}
	}
}

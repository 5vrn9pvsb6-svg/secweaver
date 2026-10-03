package main

import (
	"strings"
	"time"

	"secweaver-agent/internal/modulecontract"
	"secweaver-agent/internal/windowsevidence"
	"secweaver-agent/pkg/agentlicense"
	"secweaver-agent/pkg/auditportexecmon"
	"secweaver-agent/pkg/behaviorlearning"
	"secweaver-agent/pkg/layout"
)

// behaviorLearningStatus reads local checkpoints only. A status read failure is
// logged in doctor, but heartbeat construction remains best effort so a damaged
// learning state cannot stop ordinary evidence collection or license renewal.
func behaviorLearningStatus(modules []runtimeModule, health map[string]agentlicense.ModuleHealth) *behaviorlearning.StatusSnapshot {
	for _, module := range modules {
		var status behaviorlearning.StatusSnapshot
		var err error
		switch module.Spec.Name {
		case "audit-port-execmon":
			configPath, _ := modulecontract.StringFlag(module.Config.Args, "config")
			outputPath, _ := modulecontract.StringFlag(module.Config.Args, "output-log")
			status, err = auditportexecmon.ReadLearningStatus(configPath, outputPath)
		case "windows-eventlog-risk-json", "windows-process-execmon":
			stateFile, _ := modulecontract.StringFlag(module.Config.Args, "state-file")
			eventPath := layout.WindowsLogs + `\windows-process-execmon.log`
			flag := "output"
			if module.Spec.Name == "windows-eventlog-risk-json" {
				flag = "evidence-output"
			}
			if value, ok := modulecontract.StringFlag(module.Config.Args, flag); ok {
				eventPath = value
			}
			// The unified reader can explicitly transfer evidence ownership to
			// the standalone reader. Skip it rather than report its risk sink.
			if strings.TrimSpace(eventPath) == "" {
				continue
			}
			status, err = windowsevidence.ReadLearningStatus(module.Config.Args, stateFile, eventPath)
		default:
			continue
		}
		if err != nil && status.Mode == "" {
			status = behaviorlearning.StatusSnapshot{Mode: "unknown", Reason: "config_invalid"}
		}
		// A previous process can leave a fresh summary behind. Require this
		// collector to be running and the observation to follow its last start.
		if status.FilteringActive {
			current := health[module.Spec.Name]
			started, startErr := time.Parse(time.RFC3339, current.LastStartAt)
			updated, updateErr := time.Parse(time.RFC3339, status.UpdatedAt)
			if current.Status != "running" || startErr != nil || updateErr != nil || updated.Before(started) {
				status.FilteringActive = false
			}
		}
		return &status
	}
	return &behaviorlearning.StatusSnapshot{Mode: "disabled", Reason: "collector_disabled"}
}

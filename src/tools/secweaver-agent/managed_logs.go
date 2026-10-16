package main

import (
	"path/filepath"
	"sort"
	"strings"

	agentoutput "secweaver-agent/pkg/output"
)

type managedLogOutput struct {
	Name         string
	Path         string
	MaxSizeBytes int64
	MaxBackups   int
}

// configuredAlertOutput reserves the device-v2 controller's slot before its
// identity is loaded. Temporary enrollment/state failures must not redistribute
// disk shares; legacy deployments never start this controller.
func configuredAlertOutput(cfg agentConfig, configPath string) string {
	if !cfg.License.DeviceAuthEnabled() {
		return ""
	}
	root := filepath.Dir(filepath.Dir(configPath))
	return cfg.CollectionRules.AlertOutputPath(filepath.Join(root, "logs"))
}

// configuredLogOutputs is the common inventory for runtime budget division and
// read-only diagnostics. Module writers use output defaults; only the operations
// writer has configurable log retention (update.max_backups is for binaries).
func configuredLogOutputs(modules []runtimeModule, updater *scheduledUpdateConfig, operations *operationsReportRuntime, alertPath string) []managedLogOutput {
	paths := make(map[string]managedLogOutput)
	add := func(name, path string, size int64, backups int) {
		path = strings.TrimSpace(path)
		if path == "" || path == "-" {
			return
		}
		if size == 0 {
			size = agentoutput.DefaultMaxSizeBytes
		}
		if backups == 0 {
			backups = agentoutput.DefaultMaxBackups
		}
		if previous, exists := paths[path]; exists {
			// Shared paths get one budget slot. Report the strictest writer limits
			// rather than claiming that a larger limit protects every writer.
			name = previous.Name + "," + name
			if previous.MaxSizeBytes < size {
				size = previous.MaxSizeBytes
			}
			if previous.MaxBackups < backups {
				backups = previous.MaxBackups
			}
		}
		paths[path] = managedLogOutput{name, path, size, backups}
	}
	for _, module := range modules {
		if module.Spec.OutputPaths != nil {
			for _, path := range module.Spec.OutputPaths(module.Config.Args) {
				add(module.Spec.Name, path, 0, 0)
			}
		}
	}
	if updater != nil {
		add("agent-update", updater.StatusOutput, 0, 0)
	}
	if operations != nil && operations.Enabled {
		add("agent-health", operations.Output, operations.MaxSizeBytes, operations.MaxBackups)
	}
	add("custom-risk-alert", alertPath, 0, 0)
	outputs := make([]managedLogOutput, 0, len(paths))
	for _, item := range paths {
		outputs = append(outputs, item)
	}
	sort.Slice(outputs, func(i, j int) bool { return outputs[i].Path < outputs[j].Path })
	return outputs
}

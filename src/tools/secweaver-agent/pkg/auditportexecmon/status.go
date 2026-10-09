package auditportexecmon

import (
	"fmt"
	"strings"
	"time"

	"secweaver-agent/pkg/behaviorlearning"
)

// ReadLearningStatus exposes the audit module's operational learning state to
// doctor and managed heartbeats without opening the audit reader or changing
// its rule ownership. It is deliberately read-only and failure tolerant at the
// caller so audit collection remains independent from status reporting.
func ReadLearningStatus(configPath, outputPath string) (behaviorlearning.StatusSnapshot, error) {
	return readLearningStatus(configPath, outputPath, false)
}

// ReadFileLearningStatus reads the independent five-field file baseline.
func ReadFileLearningStatus(configPath, outputPath string) (behaviorlearning.StatusSnapshot, error) {
	return readLearningStatus(configPath, outputPath, true)
}

func readLearningStatus(configPath, outputPath string, file bool) (behaviorlearning.StatusSnapshot, error) {
	cfg, err := loadConfig(configPath)
	if err != nil {
		return behaviorlearning.StatusSnapshot{Mode: "unknown", Reason: "config_unavailable"}, err
	}
	policy, err := behaviorlearning.DecodeExec(cfg.BehaviorLearning)
	if err != nil {
		return behaviorlearning.StatusSnapshot{Mode: "unknown", Reason: "config_invalid"}, fmt.Errorf("decode behavior_learning: %w", err)
	}
	if !policy.Enabled {
		return behaviorlearning.Snapshot(policy, nil, nil, time.Now()), nil
	}
	path := strings.TrimSpace(outputPath)
	if path == "" {
		path = resolveOutputLog("", cfg.OutputLog)
	}
	policy = learningPaths(policy, path)
	if file {
		policy = behaviorlearning.FilePolicy(policy, false)
	}
	return behaviorlearning.InspectStatus(policy)
}

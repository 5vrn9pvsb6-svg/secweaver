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
	cfg, err := loadConfig(configPath)
	if err != nil {
		return behaviorlearning.StatusSnapshot{Mode: "unknown", Reason: "config_unavailable"}, err
	}
	policy, err := behaviorlearning.Decode(cfg.BehaviorLearning)
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
	state, stateErr := behaviorlearning.Inspect(policy.StateDir, policy.StateMB)
	var latest *behaviorlearning.Summary
	if summary, summaryErr := behaviorlearning.ReadLatestSummary(policy.OutputLog); summaryErr == nil {
		latest = summary
	}
	if stateErr != nil {
		return behaviorlearning.Snapshot(policy, nil, latest, time.Now()), stateErr
	}
	return behaviorlearning.Snapshot(policy, state, latest, time.Now()), nil
}

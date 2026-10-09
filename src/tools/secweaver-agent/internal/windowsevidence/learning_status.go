package windowsevidence

import (
	"fmt"
	"strconv"
	"time"

	"secweaver-agent/internal/modulecontract"
	"secweaver-agent/pkg/behaviorlearning"
)

// ReadLearningStatus reconstructs the same bounded policy used by the Windows
// reader. It reads only the authenticated checkpoint and summary tail; no
// Event Log query is started merely to populate a device inventory heartbeat.
func ReadLearningStatus(args []string, stateFile, eventPath string) (behaviorlearning.StatusSnapshot, error) {
	return readLearningStatus(args, stateFile, eventPath, "exec")
}

// ReadFileLearningStatus inspects the independent Windows file baseline without
// querying Event Log or treating the exec baseline as proof of file filtering.
func ReadFileLearningStatus(args []string, stateFile, eventPath string) (behaviorlearning.StatusSnapshot, error) {
	return readLearningStatus(args, stateFile, eventPath, "file_op")
}

// ReadNetworkLearningStatus exposes the independently persisted connection
// baseline without opening another Event Log reader or taking its writer lock.
func ReadNetworkLearningStatus(args []string, stateFile, eventPath string) (behaviorlearning.StatusSnapshot, error) {
	return readLearningStatus(args, stateFile, eventPath, "active_connect")
}

func readLearningStatus(args []string, stateFile, eventPath string, kind string) (behaviorlearning.StatusSnapshot, error) {
	enabled, _, err := modulecontract.BoolFlag(args, "behavior-learning")
	if err != nil {
		return behaviorlearning.StatusSnapshot{}, err
	}
	shadow, _, err := modulecontract.BoolFlag(args, "learning-shadow")
	if err != nil {
		return behaviorlearning.StatusSnapshot{}, err
	}
	options := LearningOptions{Enabled: enabled, Shadow: shadow, EventTypes: "exec"}
	if value, ok := modulecontract.StringFlag(args, "learning-duration"); ok {
		duration, parseErr := time.ParseDuration(value)
		if parseErr != nil {
			return behaviorlearning.StatusSnapshot{}, fmt.Errorf("learning-duration: %w", parseErr)
		}
		options.Duration = duration
	}
	if value, ok := modulecontract.StringFlag(args, "learning-generation"); ok {
		generation, parseErr := strconv.ParseUint(value, 10, 64)
		if parseErr != nil {
			return behaviorlearning.StatusSnapshot{}, fmt.Errorf("learning-generation: %w", parseErr)
		}
		options.Generation = generation
	}
	if value, ok := modulecontract.StringFlag(args, "learning-event-types"); ok {
		options.EventTypes = value
	}
	if value, ok := modulecontract.StringFlag(args, "learning-file-roots"); ok {
		options.FileRoots = value
	}
	if !enabled {
		return behaviorlearning.Snapshot(behaviorlearning.Config{}, nil, nil, time.Now()), nil
	}
	options.StateDir, _ = modulecontract.StringFlag(args, "learning-state-dir")
	options.Output, _ = modulecontract.StringFlag(args, "learning-output")
	policy, err := options.policy(stateFile, eventPath)
	if err != nil {
		return behaviorlearning.StatusSnapshot{}, err
	}
	if kind == "file_op" {
		policy = behaviorlearning.FilePolicy(policy, true)
	} else if kind == "active_connect" {
		policy = behaviorlearning.NetworkPolicy(policy)
	}
	return behaviorlearning.InspectStatus(policy)
}

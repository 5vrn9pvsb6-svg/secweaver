package main

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"secweaver-agent/pkg/agentlicense"
)

// Serialize in-process config replacements. A signed full configuration remains
// authoritative; the next heartbeat merges the tenant's managed cadence fields.
var configMutationMu sync.Mutex

// Guarded by configMutationMu. A committed cadence change fences new update
// attempts until the service has reloaded; an upgrade already in progress wins.
var runtimeConfigRestartScheduled bool

// applyManagedRuntimePolicy merges only bounded cadence fields. Raw messages
// preserve unrelated integers and module options exactly; disabled/absent
// modules are never enabled. The supervisor drains children before restarting.
func applyManagedRuntimePolicy(configPath string, policy *agentlicense.RuntimePolicy, updater ...*scheduledUpdateConfig) (bool, error) {
	if policy == nil {
		return false, nil
	}
	if policy.HostProcessIntervalMinutes < 1 || policy.HostProcessIntervalMinutes > 1440 ||
		policy.HeartbeatIntervalMinutes < 1 || policy.HeartbeatIntervalMinutes > 60 || policy.Revision < 1 {
		return false, fmt.Errorf("invalid runtime policy: process range=1..1440m heartbeat range=1..60m revision>=1")
	}
	stateIntervals := make(map[string]time.Duration, 4)
	for flag, minutes := range map[string]*int{
		"socket-interval":   policy.HostSocketIntervalMinutes,
		"identity-interval": policy.HostIdentityIntervalMinutes,
		"service-interval":  policy.HostServiceIntervalMinutes,
		"kernel-interval":   policy.HostKernelContextIntervalMinutes,
	} {
		if minutes == nil {
			continue
		}
		if *minutes < 1 || *minutes > 1440 {
			return false, fmt.Errorf("invalid runtime policy: %s range=1..1440m", flag)
		}
		stateIntervals[flag] = time.Duration(*minutes) * time.Minute
	}
	// Validate the complete envelope before any mutation, including seconds and
	// hours. A bad additive setting must never partially rewrite valid timers.
	for _, setting := range []struct {
		name     string
		value    *int
		min, max int
	}{
		{"health_report_interval_minutes", policy.HealthReportIntervalMinutes, 1, 1440},
		{"host_persistence_interval_seconds", policy.HostPersistenceIntervalSeconds, 10, 3600},
		{"host_process_full_snapshot_hours", policy.HostProcessFullSnapshotHours, 1, 168},
		{"host_state_full_snapshot_hours", policy.HostStateFullSnapshotHours, 1, 168},
	} {
		if setting.value != nil && (*setting.value < setting.min || *setting.value > setting.max) {
			return false, fmt.Errorf("invalid runtime policy: %s range=%d..%d", setting.name, setting.min, setting.max)
		}
	}
	// Do not block heartbeat delivery behind a potentially slow upgrade download.
	// Retry at the next heartbeat; the updater owns the same mutation fence.
	if !configMutationMu.TryLock() {
		return false, nil
	}
	defer configMutationMu.Unlock()
	if len(updater) > 0 && !runtimePolicyRestartAllowed(updateHeartbeatReport(updater[0])) {
		return false, nil
	}
	body, err := os.ReadFile(configPath)
	if err != nil {
		return false, err
	}
	var document map[string]json.RawMessage
	if err = json.Unmarshal(body, &document); err != nil {
		return false, err
	}
	var license map[string]json.RawMessage
	if err = json.Unmarshal(document["license"], &license); err != nil || license == nil {
		return false, fmt.Errorf("runtime policy requires a license object")
	}
	var heartbeat int
	if raw := license["heartbeat_interval_seconds"]; len(raw) != 0 {
		if err = json.Unmarshal(raw, &heartbeat); err != nil {
			return false, err
		}
	}
	desired := policy.HeartbeatIntervalMinutes * 60
	changed := heartbeat != desired
	license["heartbeat_interval_seconds"], _ = json.Marshal(desired)
	document["license"], _ = json.Marshal(license)
	// Missing health configuration remains missing; disabled reporting stays
	// disabled. Only the snapshot timer changes, preserving paths and jitter.
	if policy.HealthReportIntervalMinutes != nil && len(document["operations_report"]) != 0 {
		var report map[string]json.RawMessage
		if err = json.Unmarshal(document["operations_report"], &report); err != nil || report == nil {
			return false, fmt.Errorf("invalid operations_report object")
		}
		var seconds int
		if value := report["snapshot_interval_seconds"]; len(value) != 0 {
			if err = json.Unmarshal(value, &seconds); err != nil {
				return false, err
			}
		}
		desiredSeconds := *policy.HealthReportIntervalMinutes * 60
		if seconds != desiredSeconds {
			report["snapshot_interval_seconds"], _ = json.Marshal(desiredSeconds)
			document["operations_report"], _ = json.Marshal(report)
			changed = true
		}
	}
	var modules map[string]json.RawMessage
	if err = json.Unmarshal(document["modules"], &modules); err != nil {
		return false, err
	}
	for name, raw := range modules {
		moduleName := normalizeModuleName(name)
		var intervals map[string]time.Duration
		switch moduleName {
		case "host-process-snapshot":
			intervals = map[string]time.Duration{"interval": time.Duration(policy.HostProcessIntervalMinutes) * time.Minute}
			if policy.HostProcessFullSnapshotHours != nil {
				intervals["full-snapshot-interval"] = time.Duration(*policy.HostProcessFullSnapshotHours) * time.Hour
			}
		case "host-state-snapshot":
			intervals = stateIntervals
			if policy.HostStateFullSnapshotHours != nil {
				intervals["full-snapshot-interval"] = time.Duration(*policy.HostStateFullSnapshotHours) * time.Hour
			}
		case "host-persistence":
			if policy.HostPersistenceIntervalSeconds != nil {
				// The explicit CLI timer overrides either platform's collector JSON
				// without rewriting watch lists, audit rules or persisted baselines.
				intervals = map[string]time.Duration{"poll-interval": time.Duration(*policy.HostPersistenceIntervalSeconds) * time.Second}
			}
		}
		if len(intervals) == 0 {
			continue
		}
		var module map[string]json.RawMessage
		if err = json.Unmarshal(raw, &module); err != nil || module == nil {
			return false, fmt.Errorf("invalid %s module", moduleName)
		}
		var args []string
		if raw := module["args"]; len(raw) != 0 {
			if err = json.Unmarshal(raw, &args); err != nil {
				return false, err
			}
		}
		updatedArgs, updated, err := runtimeCadenceArgs(args, moduleName, intervals)
		if err != nil {
			return false, err
		}
		if updated {
			module["args"], _ = json.Marshal(updatedArgs)
			modules[name], _ = json.Marshal(module)
			changed = true
		}
	}
	if !changed {
		return false, nil
	}
	document["modules"], _ = json.Marshal(modules)
	// Reuse the CLI's strict validation, fsync and atomic replacement, retaining
	// the original file permissions. Invalid local configuration stays intact.
	if err = validateAndWriteConfig(configPath, document); err != nil {
		return false, err
	}
	if len(updater) > 0 {
		runtimeConfigRestartScheduled = true
	}
	return true, nil
}

// runtimeCadenceArgs handles duplicate flags and every Go flag spelling without
// mistaking another option's value for a flag. Only managed durations change;
// stable ordering and equivalent spellings prevent heartbeat reload loops.
func runtimeCadenceArgs(args []string, moduleName string, desired map[string]time.Duration) ([]string, bool, error) {
	descriptor := moduleRegistry[moduleName]
	if err := descriptor.ValidateArgs(args); err != nil {
		return nil, false, err
	}
	out := append([]string(nil), args...)
	terminated := len(out) > 0 && out[len(out)-1] == "--"
	if terminated {
		out = out[:len(out)-1]
	}
	found := make(map[string]bool, len(desired))
	changed := false
	for i := 0; i < len(out); i++ {
		name, value, inline := strings.Cut(strings.TrimLeft(out[i], "-"), "=")
		duration, managed := desired[name]
		if !managed {
			// Follow the existing descriptor's value ownership, so a path named
			// '-interval' cannot be mistaken for another option.
			if descriptor.Flags[name] && !inline {
				i++
			}
			continue
		}
		found[name] = true
		if !inline {
			if i+1 == len(out) || strings.HasPrefix(out[i+1], "-") {
				return nil, false, fmt.Errorf("%s flag is missing a duration", name)
			}
			value = out[i+1]
		}
		current, err := time.ParseDuration(value)
		if err != nil {
			return nil, false, fmt.Errorf("invalid %s %s: %w", moduleName, name, err)
		}
		if current != duration {
			changed = true
			if inline {
				out[i] = strings.SplitN(out[i], "=", 2)[0] + "=" + duration.String()
			} else {
				out[i+1] = duration.String()
			}
		}
		if !inline {
			i++
		}
	}
	missing := make([]string, 0, len(desired))
	for name := range desired {
		if !found[name] {
			missing = append(missing, name)
		}
	}
	slices.Sort(missing)
	for _, name := range missing {
		out = append(out, "-"+name, desired[name].String())
		changed = true
	}
	if terminated {
		out = append(out, "--")
	}
	return out, changed, nil
}

// Defer a policy restart during upgrade probation or state-read failure. A
// later heartbeat retries after health confirmation without resetting learning.
func runtimePolicyRestartAllowed(report *agentlicense.UpdateReport) bool {
	return report == nil || (!report.HealthPending && report.Status != "state_read_failed")
}

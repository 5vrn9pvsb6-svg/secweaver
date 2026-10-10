package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"secweaver-agent/pkg/agentlicense"
)

// Serialize in-process config replacements. A signed full configuration remains
// authoritative; the next heartbeat merges the tenant's two cadence fields.
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
	var modules map[string]json.RawMessage
	if err = json.Unmarshal(document["modules"], &modules); err != nil {
		return false, err
	}
	for name, raw := range modules {
		if normalizeModuleName(name) != "host-process-snapshot" {
			continue
		}
		var module map[string]json.RawMessage
		if err = json.Unmarshal(raw, &module); err != nil || module == nil {
			return false, fmt.Errorf("invalid process module")
		}
		var args []string
		if raw := module["args"]; len(raw) != 0 {
			if err = json.Unmarshal(raw, &args); err != nil {
				return false, err
			}
		}
		updatedArgs, updated, err := runtimeIntervalArgs(args, time.Duration(policy.HostProcessIntervalMinutes)*time.Minute)
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

// runtimeIntervalArgs handles every Go flag spelling, including duplicate
// flags (the last one wins). Equivalent duration spellings do not cause churn.
func runtimeIntervalArgs(args []string, desired time.Duration) ([]string, bool, error) {
	descriptor := moduleRegistry["host-process-snapshot"]
	if err := descriptor.ValidateArgs(args); err != nil {
		return nil, false, err
	}
	out := append([]string(nil), args...)
	terminated := len(out) > 0 && out[len(out)-1] == "--"
	if terminated {
		out = out[:len(out)-1]
	}
	found, changed := false, false
	for i := 0; i < len(out); i++ {
		name, value, inline := strings.Cut(strings.TrimLeft(out[i], "-"), "=")
		if name != "interval" {
			// Follow the existing descriptor's value ownership, so a path named
			// '-interval' cannot be mistaken for another option.
			if descriptor.Flags[name] && !inline {
				i++
			}
			continue
		}
		found = true
		if !inline {
			if i+1 == len(out) || strings.HasPrefix(out[i+1], "-") {
				return nil, false, fmt.Errorf("interval flag is missing a duration")
			}
			value = out[i+1]
		}
		current, err := time.ParseDuration(value)
		if err != nil {
			return nil, false, fmt.Errorf("invalid process interval: %w", err)
		}
		if current != desired {
			changed = true
			if inline {
				out[i] = strings.SplitN(out[i], "=", 2)[0] + "=" + desired.String()
			} else {
				out[i+1] = desired.String()
			}
		}
		if !inline {
			i++
		}
	}
	if !found {
		out = append(out, "-interval", desired.String())
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

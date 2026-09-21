package hostprocesssnapshot

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

type persistedProcessState struct {
	Version          string                 `json:"version"`
	HostName         string                 `json:"host_name"`
	UpdatedAt        string                 `json:"updated_at"`
	Initialized      bool                   `json:"initialized"`
	LastFullSnapshot string                 `json:"last_full_snapshot,omitempty"`
	Processes        map[string]processInfo `json:"processes"`
}

// processIdentityKey intentionally requires both PID and kernel/process start
// time. A PID-only key would silently merge an exited process with a later PID
// reuse and produce incorrect change events during incident investigation.
func processIdentityKey(process processInfo) (string, bool) {
	start := strings.TrimSpace(process.StartTime)
	if process.PID <= 0 || start == "" {
		return "", false
	}
	return strconv.Itoa(process.PID) + "\x00" + start, true
}

func processEvents(current []processInfo, previous persistedProcessState, fullPeriod time.Duration, host, hostIP, snapshotID string, now time.Time, durationMS int64) ([]processEvent, persistedProcessState, bool, error) {
	currentMap := make(map[string]processInfo, len(current))
	for _, process := range current {
		if key, ok := processIdentityKey(process); ok {
			currentMap[key] = process
		}
	}
	// An initialized host cannot legitimately have zero observable processes
	// while this collector itself is running. Treat that result as incomplete so
	// a transient /proc/CIM failure cannot emit a host-wide set of false exits.
	if previous.Initialized && len(previous.Processes) > 0 && len(currentMap) == 0 {
		return nil, previous, true, fmt.Errorf("process collection contained no records with pid and start_time")
	}
	lastFull, _ := time.Parse(time.RFC3339Nano, previous.LastFullSnapshot)
	full := !previous.Initialized || lastFull.IsZero() || now.Sub(lastFull) >= fullPeriod
	next := persistedProcessState{
		Version: parserVersion, HostName: host, UpdatedAt: now.Format(time.RFC3339Nano),
		Initialized: true, LastFullSnapshot: previous.LastFullSnapshot, Processes: make(map[string]processInfo, len(currentMap)),
	}
	if full {
		events := make([]processEvent, 0, len(current))
		for _, process := range current {
			events = append(events, makeEvent(process, "process_snapshot", "observed", nil, nil, false, host, hostIP, snapshotID, now, len(current), durationMS))
		}
		for key, process := range currentMap {
			next.Processes[key] = process
		}
		next.LastFullSnapshot = now.Format(time.RFC3339Nano)
		return events, next, false, nil
	}

	keys := sortedProcessKeys(currentMap)
	events := make([]processEvent, 0)
	for _, key := range keys {
		process := currentMap[key]
		old, exists := previous.Processes[key]
		if !exists {
			events = append(events, makeEvent(process, "process_start", "started", nil, nil, true, host, hostIP, snapshotID, now, len(current), durationMS))
			next.Processes[key] = process
			continue
		}
		changes, oldValues := processChanges(old, process)
		if len(changes) > 0 {
			events = append(events, makeEvent(process, "process_change", "changed", changes, oldValues, true, host, hostIP, snapshotID, now, len(current), durationMS))
			next.Processes[key] = process
			continue
		}
		// Preserve the prior compact state when only volatile CPU/memory/runtime
		// counters changed, avoiding a state-file rewrite on every scan.
		next.Processes[key] = old
	}
	for _, key := range sortedProcessKeys(previous.Processes) {
		if _, exists := currentMap[key]; exists {
			continue
		}
		old := previous.Processes[key]
		events = append(events, makeEvent(old, "process_exit", "exited", nil, nil, true, host, hostIP, snapshotID, now, len(current), durationMS))
	}
	return events, next, true, nil
}

func processChanges(old, current processInfo) ([]string, map[string]any) {
	changes := make([]string, 0, 6)
	previous := make(map[string]any)
	add := func(name string, oldValue any) {
		changes = append(changes, name)
		previous[name] = oldValue
	}
	if old.PPID != current.PPID {
		add("ppid", optionalInt(old.PPID))
	}
	if old.UID != current.UID {
		add("uid", old.UID)
	}
	if old.User != current.User {
		add("user", old.User)
	}
	if old.Exe != current.Exe {
		add("exe", old.Exe)
	}
	if old.CommandHash != current.CommandHash {
		add("command_hash", old.CommandHash)
	}
	if old.Cgroup != current.Cgroup {
		add("cgroup", old.Cgroup)
	}
	if len(previous) == 0 {
		return nil, nil
	}
	return changes, previous
}

func processCommandHash(process processInfo) string {
	command := process.CommandLine
	if command == "" {
		command = strings.Join(process.Command, "\x00")
	}
	return stableID("command", command)
}

func sortedProcessKeys(processes map[string]processInfo) []string {
	keys := make([]string, 0, len(processes))
	for key := range processes {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		left, right := processes[keys[i]], processes[keys[j]]
		if left.PID != right.PID {
			return left.PID < right.PID
		}
		return left.StartTime < right.StartTime
	})
	return keys
}

func loadProcessState(path, host string) (persistedProcessState, error) {
	state := persistedProcessState{HostName: host, Processes: map[string]processInfo{}}
	if strings.TrimSpace(path) == "" {
		return state, nil
	}
	body, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return state, nil
	}
	if err != nil {
		return state, fmt.Errorf("read process snapshot state: %w", err)
	}
	if err := json.Unmarshal(body, &state); err != nil {
		corruptPath := path + ".corrupt-" + time.Now().UTC().Format("20060102T150405.000000000Z")
		if renameErr := os.Rename(path, corruptPath); renameErr != nil {
			return state, fmt.Errorf("parse process snapshot state: %w; quarantine failed: %v", err, renameErr)
		}
		fmt.Fprintf(os.Stderr, "WARN: quarantined corrupt process snapshot state: %s\n", corruptPath)
		return persistedProcessState{HostName: host, Processes: map[string]processInfo{}}, nil
	}
	if state.HostName != "" && state.HostName != host {
		fmt.Fprintf(os.Stderr, "WARN: process snapshot state belongs to host %q; rebuilding baseline for %q\n", state.HostName, host)
		return persistedProcessState{HostName: host, Processes: map[string]processInfo{}}, nil
	}
	if state.Processes == nil {
		state.Processes = map[string]processInfo{}
	}
	return state, nil
}

func saveProcessState(path string, state persistedProcessState) error {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	body, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".host-process-snapshot-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	committed := false
	defer func() {
		_ = tmp.Close()
		if !committed {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(0600); err != nil {
		return err
	}
	if _, err := tmp.Write(body); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := replaceProcessStateFile(tmpPath, path); err != nil {
		return err
	}
	committed = true
	return nil
}

func processStateEqual(left, right persistedProcessState) bool {
	if left.HostName != right.HostName || left.Initialized != right.Initialized || left.LastFullSnapshot != right.LastFullSnapshot || len(left.Processes) != len(right.Processes) {
		return false
	}
	for key, leftProcess := range left.Processes {
		rightProcess, ok := right.Processes[key]
		if !ok || leftProcess.CommandHash != rightProcess.CommandHash || leftProcess.Exe != rightProcess.Exe || leftProcess.UID != rightProcess.UID || leftProcess.User != rightProcess.User || leftProcess.Cgroup != rightProcess.Cgroup || leftProcess.PPID != rightProcess.PPID {
			return false
		}
	}
	return true
}

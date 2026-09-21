package hoststatesnapshot

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"

	"secweaver-agent/internal/modulecontrol"
	"secweaver-agent/pkg/layout"
	agentoutput "secweaver-agent/pkg/output"
)

const (
	parserVersion             = "0.3.0"
	defaultSocketInterval     = 5 * time.Minute
	defaultIdentityInterval   = 5 * time.Minute
	defaultServiceInterval    = 5 * time.Minute
	defaultKernelInterval     = 10 * time.Minute
	defaultFullSnapshotPeriod = 24 * time.Hour
	defaultCollectionTimeout  = 45 * time.Second
	defaultMaxFDScan          = 100000
	linuxDefaultOutput        = layout.LinuxLogs + "/host-state-snapshot.log"
	linuxDefaultState         = layout.LinuxData + "/host-state-snapshot-state.json"
	windowsDefaultOutput      = layout.WindowsLogs + `\host-state-snapshot.log`
	windowsDefaultState       = layout.WindowsData + `\host-state-snapshot-state.json`
)

var version = parserVersion

type entity struct {
	Key        string         `json:"key"`
	EntityType string         `json:"entity_type"`
	AssetType  string         `json:"asset_type"`
	Fields     map[string]any `json:"fields"`
}

type persistedCollection struct {
	Initialized      bool              `json:"initialized"`
	LastFullSnapshot string            `json:"last_full_snapshot,omitempty"`
	Entities         map[string]entity `json:"entities"`
}

type persistedState struct {
	Version     string                         `json:"version"`
	HostName    string                         `json:"host_name"`
	UpdatedAt   string                         `json:"updated_at"`
	Collections map[string]persistedCollection `json:"collections"`
}

type stats struct {
	CollectionsRun int `json:"collections_run"`
	EntitiesRead   int `json:"entities_read"`
	EventsWritten  int `json:"events_written"`
	CollectErrors  int `json:"collect_errors"`
}

type collectorSpec struct {
	Name         string
	Interval     time.Duration
	InitialDelay time.Duration
	Snapshot     bool
	Collect      func(context.Context, time.Time) ([]entity, error)
	nextRun      time.Time
}

type runConfig struct {
	OutputPath         string
	StatePath          string
	HostIP             string
	FullSnapshotPeriod time.Duration
	Once               bool
	Collectors         []collectorSpec
}

func Main(args []string) int {
	fs := flag.NewFlagSet("host-state-snapshot", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	outputPath := defaultOutputPath()
	statePath := defaultStatePath()
	hostIP := ""
	socketInterval := defaultSocketInterval
	identityInterval := defaultIdentityInterval
	serviceInterval := defaultServiceInterval
	kernelInterval := defaultKernelInterval
	fullSnapshotPeriod := defaultFullSnapshotPeriod
	maxFDScan := defaultMaxFDScan
	containerWorkload := false
	once := false
	showStats := false
	showVersion := false
	fs.StringVar(&outputPath, "output", outputPath, "JSON Lines output path; - for stdout")
	fs.StringVar(&statePath, "state", statePath, "persistent state path; empty disables state persistence")
	fs.StringVar(&hostIP, "host-ip", hostIP, "host IP to include; empty auto-detects the primary address")
	fs.DurationVar(&socketInterval, "socket-interval", socketInterval, "listening socket snapshot interval")
	fs.DurationVar(&identityInterval, "identity-interval", identityInterval, "login session and identity change scan interval")
	fs.DurationVar(&serviceInterval, "service-interval", serviceInterval, "service and scheduled-task change scan interval")
	fs.DurationVar(&kernelInterval, "kernel-interval", kernelInterval, "kernel module and container context scan interval")
	fs.DurationVar(&fullSnapshotPeriod, "full-snapshot-interval", fullSnapshotPeriod, "periodic full baseline interval for stateful collections")
	fs.IntVar(&maxFDScan, "max-fd-scan", maxFDScan, "maximum /proc file descriptors inspected per listening-socket collection")
	fs.BoolVar(&containerWorkload, "container-workload", containerWorkload, "collect only container-namespace state; omit host service/session and shadow inputs")
	fs.BoolVar(&once, "once", once, "run all state collectors once and exit")
	fs.BoolVar(&showStats, "stats", showStats, "print collection statistics to stderr on exit")
	fs.BoolVar(&showVersion, "version", showVersion, "print version and exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if showVersion {
		fmt.Fprintf(os.Stdout, "host-state-snapshot %s\n", version)
		return 0
	}
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		fmt.Fprintf(os.Stderr, "host-state-snapshot only runs on Linux or Windows; current platform is %s\n", runtime.GOOS)
		return 1
	}
	for name, interval := range map[string]time.Duration{
		"socket-interval": socketInterval, "identity-interval": identityInterval,
		"service-interval": serviceInterval, "kernel-interval": kernelInterval,
		"full-snapshot-interval": fullSnapshotPeriod,
	} {
		if interval <= 0 {
			fmt.Fprintf(os.Stderr, "-%s must be positive\n", name)
			return 2
		}
	}
	if strings.TrimSpace(hostIP) == "" {
		hostIP = primaryHostIP()
	}
	if maxFDScan <= 0 {
		fmt.Fprintln(os.Stderr, "-max-fd-scan must be positive")
		return 2
	}
	out, cleanup, err := agentoutput.OpenEventAppend(agentoutput.AppendOptions{
		Path: outputPath, Fallback: os.Stdout, Perm: agentoutput.DefaultFilePerm,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "open host state output: %v\n", err)
		return 1
	}
	defer cleanup()
	ctx, stop := modulecontrol.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	collectors := platformCollectors(socketInterval, identityInterval, serviceInterval, kernelInterval, maxFDScan, containerWorkload)
	st := &stats{}
	err = run(ctx, runConfig{
		OutputPath: outputPath, StatePath: statePath, HostIP: hostIP,
		FullSnapshotPeriod: fullSnapshotPeriod, Once: once, Collectors: collectors,
	}, out, st)
	if showStats {
		body, _ := json.Marshal(st)
		fmt.Fprintf(os.Stderr, "stats: %s\n", body)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "host-state-snapshot failed: %v\n", err)
		return 1
	}
	return 0
}

// platformCollectors keeps the container profile namespace-scoped. In
// particular, service state, login sessions, and /etc/shadow are host-facing
// sources whose absence in an unprivileged container must not turn into noisy
// collection failures or an empty host-service baseline.
func platformCollectors(socketInterval, identityInterval, serviceInterval, kernelInterval time.Duration, maxFDScan int, containerWorkload bool) []collectorSpec {
	collectors := []collectorSpec{
		{Name: "socket", Interval: socketInterval, Collect: func(ctx context.Context, now time.Time) ([]entity, error) {
			return collectSocketState(ctx, now, maxFDScan)
		}},
		{Name: "identity", Interval: identityInterval, InitialDelay: 15 * time.Second, Collect: func(ctx context.Context, now time.Time) ([]entity, error) {
			return collectIdentityState(ctx, now, containerWorkload)
		}},
		{Name: "kernel", Interval: kernelInterval, InitialDelay: 45 * time.Second, Collect: collectKernelContainerState},
	}
	if !containerWorkload {
		collectors = append(collectors, collectorSpec{Name: "service", Interval: serviceInterval, InitialDelay: 30 * time.Second, Collect: collectServiceState})
	}
	return collectors
}

func run(ctx context.Context, cfg runConfig, out io.Writer, st *stats) error {
	if len(cfg.Collectors) == 0 {
		return fmt.Errorf("at least one collector is required")
	}
	host, err := os.Hostname()
	if err != nil || strings.TrimSpace(host) == "" {
		host = "unknown"
	}
	host = strings.TrimSpace(host)
	state, err := loadState(cfg.StatePath)
	if err != nil {
		return err
	}
	if state.Collections == nil {
		state.Collections = map[string]persistedCollection{}
	}
	enc := json.NewEncoder(out)
	now := time.Now().UTC()
	for i := range cfg.Collectors {
		cfg.Collectors[i].nextRun = now
		if !cfg.Once {
			cfg.Collectors[i].nextRun = now.Add(cfg.Collectors[i].InitialDelay)
		}
	}
	for {
		now = time.Now().UTC()
		ranAny := false
		stateDirty := false
		for i := range cfg.Collectors {
			spec := &cfg.Collectors[i]
			if now.Before(spec.nextRun) {
				continue
			}
			ranAny = true
			collectCtx, cancelCollect := context.WithTimeout(ctx, defaultCollectionTimeout)
			entities, collectErr := spec.Collect(collectCtx, now)
			cancelCollect()
			st.CollectionsRun++
			if collectErr != nil {
				st.CollectErrors++
				if cfg.Once {
					return fmt.Errorf("collect %s: %w", spec.Name, collectErr)
				}
				fmt.Fprintf(os.Stderr, "WARN: host state %s collection failed: %v\n", spec.Name, collectErr)
			} else {
				st.EntitiesRead += len(entities)
				events, nextCollection := collectionEvents(spec.Name, entities, state.Collections[spec.Name], spec.Snapshot, cfg.FullSnapshotPeriod, host, cfg.HostIP, now)
				for _, event := range events {
					if err := enc.Encode(event); err != nil {
						return err
					}
					st.EventsWritten++
				}
				if !spec.Snapshot && !persistedCollectionEqual(state.Collections[spec.Name], nextCollection) {
					state.Collections[spec.Name] = nextCollection
					state.Version = parserVersion
					state.HostName = host
					state.UpdatedAt = now.Format(time.RFC3339Nano)
					stateDirty = true
				}
			}
			spec.nextRun = time.Now().UTC().Add(spec.Interval)
		}
		if stateDirty {
			if err := agentoutput.Checkpoint(out); err != nil {
				return fmt.Errorf("checkpoint host state output: %w", err)
			}
			if err := saveState(cfg.StatePath, state); err != nil {
				return err
			}
		}
		if cfg.Once {
			return nil
		}
		if !ranAny {
			next := cfg.Collectors[0].nextRun
			for i := 1; i < len(cfg.Collectors); i++ {
				if cfg.Collectors[i].nextRun.Before(next) {
					next = cfg.Collectors[i].nextRun
				}
			}
			wait := time.Until(next)
			if wait < 10*time.Millisecond {
				wait = 10 * time.Millisecond
			}
			timer := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil
			case <-timer.C:
			}
		}
	}
}

func collectionEvents(name string, current []entity, previous persistedCollection, snapshot bool, fullPeriod time.Duration, host, hostIP string, now time.Time) ([]map[string]any, persistedCollection) {
	currentMap := make(map[string]entity, len(current))
	for _, item := range current {
		if item.Key != "" {
			currentMap[item.Key] = item
		}
	}
	keys := make([]string, 0, len(currentMap))
	for key := range currentMap {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	current = current[:0]
	for _, key := range keys {
		current = append(current, currentMap[key])
	}
	snapshotID := stableID("host-state", host, name, now.Format(time.RFC3339Nano))
	if snapshot {
		events := make([]map[string]any, 0, len(current))
		for _, item := range current {
			events = append(events, eventForEntity(item, "observed", nil, host, hostIP, snapshotID, len(current), now))
		}
		return events, previous
	}
	lastFull, _ := time.Parse(time.RFC3339Nano, previous.LastFullSnapshot)
	full := !previous.Initialized || lastFull.IsZero() || now.Sub(lastFull) >= fullPeriod
	events := make([]map[string]any, 0)
	if full {
		for _, item := range current {
			events = append(events, eventForEntity(item, "observed", nil, host, hostIP, snapshotID, len(current), now))
		}
		previous.LastFullSnapshot = now.Format(time.RFC3339Nano)
	} else {
		for _, item := range current {
			old, ok := previous.Entities[item.Key]
			if !ok {
				events = append(events, eventForEntity(item, "created", nil, host, hostIP, snapshotID, len(current), now))
				continue
			}
			if entityDigest(old) != entityDigest(item) {
				events = append(events, eventForEntity(item, "modified", old.Fields, host, hostIP, snapshotID, len(current), now))
			}
		}
		deletedKeys := make([]string, 0)
		for key := range previous.Entities {
			if _, ok := currentMap[key]; !ok {
				deletedKeys = append(deletedKeys, key)
			}
		}
		sort.Strings(deletedKeys)
		for _, key := range deletedKeys {
			old := previous.Entities[key]
			events = append(events, eventForEntity(old, "deleted", old.Fields, host, hostIP, snapshotID, len(current), now))
		}
	}
	previous.Initialized = true
	previous.Entities = currentMap
	return events, previous
}

func persistedCollectionEqual(left, right persistedCollection) bool {
	if left.Initialized != right.Initialized || left.LastFullSnapshot != right.LastFullSnapshot || len(left.Entities) != len(right.Entities) {
		return false
	}
	for key, leftEntity := range left.Entities {
		rightEntity, ok := right.Entities[key]
		if !ok || entityDigest(leftEntity) != entityDigest(rightEntity) {
			return false
		}
	}
	return true
}

func eventForEntity(item entity, action string, previous map[string]any, host, hostIP, snapshotID string, count int, now time.Time) map[string]any {
	timestamp := now.Format(time.RFC3339Nano)
	eventType := eventTypeFor(item.EntityType, action)
	event := map[string]any{
		"evidence_id": stableID("host-state-event", snapshotID, item.Key, action, entityDigest(item)),
		"asset_type":  item.AssetType, "event_type": eventType, "entity_type": item.EntityType,
		"action": action, "time": timestamp, "timestamp": timestamp,
		"snapshot_id": snapshotID, "snapshot_entity_count": count,
		"host": host, "host_name": host, "os": runtime.GOOS, "arch": runtime.GOARCH,
		"entity_key": item.Key, "parser_version": parserVersion,
	}
	if hostIP != "" {
		event["host_ip"] = hostIP
	}
	for key, value := range item.Fields {
		event[key] = value
	}
	if previous != nil && (action == "modified" || action == "deleted") {
		event["previous"] = previous
	}
	return event
}

func eventTypeFor(entityType, action string) string {
	if action == "observed" {
		switch entityType {
		case "listening_socket":
			return "listening_socket_snapshot"
		case "login_session":
			return "login_session_snapshot"
		case "identity_account":
			return "identity_snapshot"
		case "service":
			return "service_snapshot"
		case "scheduled_task":
			return "scheduled_task_snapshot"
		case "kernel_module":
			return "kernel_module_snapshot"
		case "container_context":
			return "container_context_snapshot"
		default:
			return "host_context_snapshot"
		}
	}
	if entityType == "login_session" {
		if action == "created" {
			return "login_session_started"
		}
		if action == "deleted" {
			return "login_session_ended"
		}
	}
	switch entityType {
	case "identity_account":
		return "identity_change"
	case "service":
		return "service_change"
	case "scheduled_task":
		return "scheduled_task_change"
	case "kernel_module":
		return "kernel_module_change"
	case "container_context":
		return "container_context_change"
	case "listening_socket":
		return "listening_socket_change"
	default:
		return "host_context_change"
	}
}

func entityDigest(item entity) string {
	digestItem := item
	if item.EntityType == "container_context" {
		digestItem.Fields = cloneFields(item.Fields)
		delete(digestItem.Fields, "pids")
		delete(digestItem.Fields, "process_count")
	}
	body, _ := json.Marshal(digestItem)
	h := sha256.Sum256(body)
	return hex.EncodeToString(h[:])
}

func stableID(prefix string, values ...string) string {
	h := sha256.New()
	for _, value := range values {
		_, _ = io.WriteString(h, value)
		_, _ = io.WriteString(h, "\x00")
	}
	return prefix + "-" + hex.EncodeToString(h.Sum(nil)[:16])
}

func loadState(path string) (persistedState, error) {
	state := persistedState{Collections: map[string]persistedCollection{}}
	if strings.TrimSpace(path) == "" {
		return state, nil
	}
	body, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return state, nil
	}
	if err != nil {
		return state, fmt.Errorf("read host state snapshot: %w", err)
	}
	if err := json.Unmarshal(body, &state); err != nil {
		corruptPath := path + ".corrupt-" + time.Now().UTC().Format("20060102T150405.000000000Z")
		if renameErr := os.Rename(path, corruptPath); renameErr != nil {
			return state, fmt.Errorf("parse host state snapshot: %w; quarantine failed: %v", err, renameErr)
		}
		fmt.Fprintf(os.Stderr, "WARN: quarantined corrupt host state snapshot: %s\n", corruptPath)
		return state, nil
	}
	if state.Collections == nil {
		state.Collections = map[string]persistedCollection{}
	}
	return state, nil
}

func saveState(path string, state persistedState) error {
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
	tmp, err := os.CreateTemp(dir, ".host-state-snapshot-*.tmp")
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
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	committed = true
	return nil
}

func defaultOutputPath() string {
	if runtime.GOOS == "windows" {
		return windowsDefaultOutput
	}
	return linuxDefaultOutput
}

func defaultStatePath() string {
	if runtime.GOOS == "windows" {
		return windowsDefaultState
	}
	return linuxDefaultState
}

func primaryHostIP() string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	fallback := ""
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addresses, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, address := range addresses {
			ip, _, err := net.ParseCIDR(address.String())
			if err != nil || ip.IsLoopback() {
				continue
			}
			if ipv4 := ip.To4(); ipv4 != nil {
				return ipv4.String()
			}
			if fallback == "" {
				fallback = ip.String()
			}
		}
	}
	return fallback
}

package hostprocesssnapshot

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
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"secweaver-agent/internal/modulecontrol"
	"secweaver-agent/pkg/layout"
	agentoutput "secweaver-agent/pkg/output"
)

const (
	parserVersion             = "0.3.0"
	defaultInterval           = 10 * time.Minute
	defaultFullSnapshotPeriod = 24 * time.Hour
	defaultCollectionTimeout  = 45 * time.Second
	linuxDefaultLog           = layout.LinuxLogs + "/host-process-snapshot.log"
	linuxDefaultState         = layout.LinuxData + "/host-process-snapshot-state.json"
	windowsDefaultLog         = layout.WindowsLogs + `\host-process-snapshot.log`
	windowsDefaultState       = layout.WindowsData + `\host-process-snapshot-state.json`
)

var version = parserVersion

type processInfo struct {
	PID             int      `json:"pid"`
	PPID            int      `json:"ppid,omitempty"`
	UID             string   `json:"uid,omitempty"`
	User            string   `json:"user,omitempty"`
	Process         string   `json:"process,omitempty"`
	Comm            string   `json:"comm,omitempty"`
	Exe             string   `json:"exe,omitempty"`
	Command         []string `json:"command,omitempty"`
	CommandLine     string   `json:"command_line,omitempty"`
	CWD             string   `json:"cwd,omitempty"`
	State           string   `json:"state,omitempty"`
	StateName       string   `json:"state_name,omitempty"`
	StartTime       string   `json:"start_time,omitempty"`
	ElapsedSeconds  int64    `json:"elapsed_seconds,omitempty"`
	CPUTimeMS       int64    `json:"cpu_time_ms,omitempty"`
	RSSBytes        int64    `json:"rss_bytes,omitempty"`
	VirtualBytes    int64    `json:"virtual_bytes,omitempty"`
	ThreadCount     int      `json:"thread_count,omitempty"`
	SessionID       int      `json:"session_id,omitempty"`
	Cgroup          string   `json:"cgroup,omitempty"`
	CommandHash     string   `json:"command_hash,omitempty"`
	CommandRedacted bool     `json:"command_redacted,omitempty"`
	IsAgent         bool     `json:"is_secweaver_agent,omitempty"`
}

type processEvent struct {
	EvidenceID           string         `json:"evidence_id"`
	AssetType            string         `json:"asset_type"`
	EventType            string         `json:"event_type"`
	Action               string         `json:"action"`
	Time                 string         `json:"time"`
	Timestamp            string         `json:"timestamp"`
	SnapshotID           string         `json:"snapshot_id"`
	SnapshotProcessCount int            `json:"snapshot_process_count"`
	SnapshotDurationMS   int64          `json:"snapshot_duration_ms"`
	Host                 string         `json:"host"`
	HostName             string         `json:"host_name"`
	HostIP               string         `json:"host_ip,omitempty"`
	OS                   string         `json:"os"`
	Arch                 string         `json:"arch"`
	PID                  string         `json:"pid"`
	PPID                 string         `json:"ppid,omitempty"`
	UID                  string         `json:"uid,omitempty"`
	User                 string         `json:"user,omitempty"`
	Process              string         `json:"process,omitempty"`
	Comm                 string         `json:"comm,omitempty"`
	Exe                  string         `json:"exe,omitempty"`
	Command              []string       `json:"command,omitempty"`
	CommandLine          string         `json:"command_line,omitempty"`
	CWD                  string         `json:"cwd,omitempty"`
	State                string         `json:"state,omitempty"`
	StateName            string         `json:"state_name,omitempty"`
	StartTime            string         `json:"start_time,omitempty"`
	ElapsedSeconds       int64          `json:"elapsed_seconds,omitempty"`
	CPUTimeMS            int64          `json:"cpu_time_ms,omitempty"`
	RSSBytes             int64          `json:"rss_bytes,omitempty"`
	VirtualBytes         int64          `json:"virtual_bytes,omitempty"`
	ThreadCount          int            `json:"thread_count,omitempty"`
	SessionID            int            `json:"session_id,omitempty"`
	Cgroup               string         `json:"cgroup,omitempty"`
	CommandHash          string         `json:"command_hash,omitempty"`
	ChangeFields         []string       `json:"change_fields,omitempty"`
	Previous             map[string]any `json:"previous,omitempty"`
	CommandRedacted      bool           `json:"command_redacted,omitempty"`
	IsAgent              bool           `json:"is_secweaver_agent,omitempty"`
	ParserVersion        string         `json:"parser_version"`
}

type stats struct {
	Snapshots      int `json:"snapshots"`
	DeltaScans     int `json:"delta_scans"`
	ProcessStarts  int `json:"process_starts"`
	ProcessExits   int `json:"process_exits"`
	ProcessChanges int `json:"process_changes"`
	Untracked      int `json:"untracked_without_start_time"`
	ProcessesRead  int `json:"processes_read"`
	EventsWritten  int `json:"events_written"`
	ScanErrors     int `json:"scan_errors"`
}

type runConfig struct {
	OutputPath         string
	StatePath          string
	HostIP             string
	Interval           time.Duration
	FullSnapshotPeriod time.Duration
	CollectionTimeout  time.Duration
	Once               bool
	RedactSensitive    bool
	Collector          func(context.Context, time.Time) ([]processInfo, error)
}

func Main(args []string) int {
	fs := flag.NewFlagSet("host-process-snapshot", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	outputPath := defaultOutputPath()
	statePath := defaultStatePath()
	hostIP := ""
	interval := defaultInterval
	fullSnapshotPeriod := defaultFullSnapshotPeriod
	collectionTimeout := defaultCollectionTimeout
	once := false
	redactSensitive := true
	showStats := false
	showVersion := false
	fs.StringVar(&outputPath, "output", outputPath, "JSON Lines output path; - for stdout")
	fs.StringVar(&statePath, "state", statePath, "persistent process state path; empty keeps state in memory only")
	fs.StringVar(&hostIP, "host-ip", hostIP, "host IP to include; empty auto-detects the primary address")
	fs.DurationVar(&interval, "interval", interval, "process delta scan interval")
	fs.DurationVar(&fullSnapshotPeriod, "full-snapshot-interval", fullSnapshotPeriod, "periodic full process baseline interval")
	fs.DurationVar(&collectionTimeout, "collection-timeout", collectionTimeout, "maximum duration of one process inventory collection")
	fs.BoolVar(&once, "once", once, "collect one process snapshot and exit")
	fs.BoolVar(&redactSensitive, "redact-sensitive", redactSensitive, "redact common password/token command arguments")
	fs.BoolVar(&showStats, "stats", showStats, "print collection statistics to stderr on exit")
	fs.BoolVar(&showVersion, "version", showVersion, "print version and exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if showVersion {
		fmt.Fprintf(os.Stdout, "host-process-snapshot %s\n", version)
		return 0
	}
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		fmt.Fprintf(os.Stderr, "host-process-snapshot only runs on Linux or Windows; current platform is %s\n", runtime.GOOS)
		return 1
	}
	if interval <= 0 {
		fmt.Fprintln(os.Stderr, "-interval must be positive")
		return 2
	}
	if fullSnapshotPeriod <= 0 {
		fmt.Fprintln(os.Stderr, "-full-snapshot-interval must be positive")
		return 2
	}
	if collectionTimeout <= 0 {
		fmt.Fprintln(os.Stderr, "-collection-timeout must be positive")
		return 2
	}
	if strings.TrimSpace(hostIP) == "" {
		hostIP = primaryHostIP()
	}
	out, cleanup, err := agentoutput.OpenEventAppend(agentoutput.AppendOptions{
		Path: outputPath, Fallback: os.Stdout, Perm: agentoutput.DefaultFilePerm,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "open process snapshot output: %v\n", err)
		return 1
	}
	defer cleanup()
	ctx, stop := modulecontrol.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	collector := collectProcesses
	st := &stats{}
	err = run(ctx, runConfig{
		OutputPath: outputPath, StatePath: statePath, HostIP: hostIP, Interval: interval,
		FullSnapshotPeriod: fullSnapshotPeriod, CollectionTimeout: collectionTimeout, Once: once,
		RedactSensitive: redactSensitive, Collector: collector,
	}, out, st)
	if showStats {
		body, _ := json.Marshal(st)
		fmt.Fprintf(os.Stderr, "stats: %s\n", body)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "host-process-snapshot failed: %v\n", err)
		return 1
	}
	return 0
}

func run(ctx context.Context, cfg runConfig, out io.Writer, st *stats) error {
	if cfg.Collector == nil {
		return fmt.Errorf("process collector is required")
	}
	host, err := os.Hostname()
	if err != nil || strings.TrimSpace(host) == "" {
		host = "unknown"
	}
	host = strings.TrimSpace(host)
	state, err := loadProcessState(cfg.StatePath, host)
	if err != nil {
		return err
	}
	if cfg.Once {
		// A one-shot invocation is used for diagnostics and exports, so it must
		// always return a complete inventory instead of an empty unchanged delta.
		state = persistedProcessState{HostName: host, Processes: map[string]processInfo{}}
	}
	enc := json.NewEncoder(out)
	if cfg.CollectionTimeout <= 0 {
		cfg.CollectionTimeout = defaultCollectionTimeout
	}
	if cfg.FullSnapshotPeriod <= 0 {
		cfg.FullSnapshotPeriod = defaultFullSnapshotPeriod
	}
	for {
		started := time.Now().UTC()
		collectCtx, cancelCollect := context.WithTimeout(ctx, cfg.CollectionTimeout)
		processes, collectErr := cfg.Collector(collectCtx, started)
		cancelCollect()
		if collectErr != nil {
			st.ScanErrors++
			if cfg.Once {
				return collectErr
			}
			fmt.Fprintf(os.Stderr, "WARN: process snapshot failed: %v\n", collectErr)
		} else {
			sort.Slice(processes, func(i, j int) bool { return processes[i].PID < processes[j].PID })
			if cfg.RedactSensitive {
				for i := range processes {
					redactProcess(&processes[i])
				}
			}
			for i := range processes {
				processes[i].CommandHash = processCommandHash(processes[i])
			}
			duration := time.Since(started).Milliseconds()
			snapshotID := stableID("process-snapshot", host, started.Format(time.RFC3339Nano))
			events, nextState, delta, eventErr := processEvents(processes, state, cfg.FullSnapshotPeriod, host, cfg.HostIP, snapshotID, started, duration)
			if eventErr != nil {
				st.ScanErrors++
				if cfg.Once {
					return eventErr
				}
				fmt.Fprintf(os.Stderr, "WARN: process snapshot rejected incomplete collection: %v\n", eventErr)
				goto wait
			}
			for _, event := range events {
				if err := enc.Encode(event); err != nil {
					return err
				}
				st.EventsWritten++
			}
			if delta {
				st.DeltaScans++
			} else {
				st.Snapshots++
			}
			for _, event := range events {
				switch event.EventType {
				case "process_start":
					st.ProcessStarts++
				case "process_exit":
					st.ProcessExits++
				case "process_change":
					st.ProcessChanges++
				}
			}
			st.Untracked += len(processes) - len(nextState.Processes)
			st.ProcessesRead += len(processes)
			if !processStateEqual(state, nextState) {
				// State advances only after buffered output is durable, otherwise a crash
				// could permanently hide delta events that were never written.
				if err := agentoutput.Checkpoint(out); err != nil {
					return fmt.Errorf("checkpoint process output: %w", err)
				}
				if err := saveProcessState(cfg.StatePath, nextState); err != nil {
					return err
				}
				state = nextState
			}
		}
	wait:
		if cfg.Once {
			return nil
		}
		timer := time.NewTimer(cfg.Interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}

func makeEvent(p processInfo, eventType, action string, changeFields []string, previous map[string]any, includeCommand bool, host, hostIP, snapshotID string, now time.Time, count int, durationMS int64) processEvent {
	timestamp := now.Format(time.RFC3339Nano)
	event := processEvent{
		EvidenceID: stableID("host-process", snapshotID, eventType, strconv.Itoa(p.PID), p.StartTime),
		AssetType:  "host_process", EventType: eventType, Action: action, Time: timestamp, Timestamp: timestamp,
		SnapshotID: snapshotID, SnapshotProcessCount: count, SnapshotDurationMS: durationMS,
		Host: host, HostName: host, HostIP: hostIP, OS: runtime.GOOS, Arch: runtime.GOARCH,
		PID: strconv.Itoa(p.PID), PPID: optionalInt(p.PPID), UID: p.UID, User: p.User,
		Process: p.Process, Comm: p.Comm, Exe: p.Exe,
		CWD: p.CWD, State: p.State, StateName: p.StateName, StartTime: p.StartTime,
		ElapsedSeconds: p.ElapsedSeconds, CPUTimeMS: p.CPUTimeMS, RSSBytes: p.RSSBytes,
		VirtualBytes: p.VirtualBytes, ThreadCount: p.ThreadCount, SessionID: p.SessionID,
		Cgroup: p.Cgroup, CommandHash: p.CommandHash, ChangeFields: changeFields, Previous: previous,
		CommandRedacted: p.CommandRedacted, IsAgent: p.IsAgent,
		ParserVersion: parserVersion,
	}
	// Full baselines deliberately omit repeated command payloads. Delta events
	// retain the redacted command because starts/exits/changes are high-value.
	if includeCommand {
		event.Command = p.Command
		event.CommandLine = p.CommandLine
	}
	return event
}

func optionalInt(value int) string {
	if value <= 0 {
		return ""
	}
	return strconv.Itoa(value)
}

func stableID(prefix string, values ...string) string {
	h := sha256.New()
	for _, value := range values {
		_, _ = io.WriteString(h, value)
		_, _ = io.WriteString(h, "\x00")
	}
	return prefix + "-" + hex.EncodeToString(h.Sum(nil)[:16])
}

func defaultOutputPath() string {
	if runtime.GOOS == "windows" {
		return windowsDefaultLog
	}
	return linuxDefaultLog
}

func defaultStatePath() string {
	if runtime.GOOS == "windows" {
		return windowsDefaultState
	}
	return linuxDefaultState
}

func collectProcesses(ctx context.Context, now time.Time) ([]processInfo, error) {
	switch runtime.GOOS {
	case "linux":
		return collectLinuxProcesses(ctx, "/proc", now)
	case "windows":
		return collectWindowsProcesses(ctx, now)
	default:
		return nil, fmt.Errorf("unsupported platform %s", runtime.GOOS)
	}
}

var sensitiveAssignment = regexp.MustCompile(`(?i)(--?(?:password|passwd|token|api[_-]?key|secret|client[_-]?secret|access[_-]?key)(?:=|\s+))(\S+)`)
var sshpassPassword = regexp.MustCompile(`(?i)(\bsshpass\s+-p\s+)(\S+)`)
var urlPassword = regexp.MustCompile(`(?i)(://[^\s/:@]+:)([^\s/@]+)(@)`)
var bearerToken = regexp.MustCompile(`(?i)(authorization\s*:\s*bearer\s+)([^\s"']+)`)

func redactProcess(p *processInfo) {
	redactedLine := redactCommandLine(p.CommandLine)
	changed := redactedLine != p.CommandLine
	p.CommandLine = redactedLine
	if len(p.Command) > 0 {
		args := append([]string(nil), p.Command...)
		for i := range args {
			redacted := redactCommandLine(args[i])
			if redacted != args[i] {
				changed = true
			}
			args[i] = redacted
		}
		for i := 0; i+1 < len(args); i++ {
			arg := strings.ToLower(args[i])
			secretFlag := arg == "--password" || arg == "--passwd" || arg == "--token" || arg == "--api-key" || arg == "--secret" || arg == "--client-secret" || arg == "--access-key"
			sshpassFlag := filepath.Base(strings.ToLower(args[0])) == "sshpass" && arg == "-p"
			if secretFlag || sshpassFlag {
				args[i+1] = "[REDACTED]"
				changed = true
			}
		}
		p.Command = args
		p.CommandLine = joinCommand(args)
	}
	p.CommandRedacted = changed
}

func redactCommandLine(value string) string {
	value = sensitiveAssignment.ReplaceAllString(value, `${1}[REDACTED]`)
	value = sshpassPassword.ReplaceAllString(value, `${1}[REDACTED]`)
	value = urlPassword.ReplaceAllString(value, `${1}[REDACTED]${3}`)
	return bearerToken.ReplaceAllString(value, `${1}[REDACTED]`)
}

func joinCommand(args []string) string {
	quoted := make([]string, 0, len(args))
	for _, arg := range args {
		if arg == "" || strings.ContainsAny(arg, " \t\n\"'") {
			quoted = append(quoted, strconv.Quote(arg))
		} else {
			quoted = append(quoted, arg)
		}
	}
	return strings.Join(quoted, " ")
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

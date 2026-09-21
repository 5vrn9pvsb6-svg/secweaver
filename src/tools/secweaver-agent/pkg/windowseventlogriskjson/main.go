package windowseventlogriskjson

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"time"

	"secweaver-agent/internal/agentactivity"
	"secweaver-agent/internal/modulecontrol"
	"secweaver-agent/internal/windowsevidence"
	"secweaver-agent/pkg/layout"
	agentoutput "secweaver-agent/pkg/output"
	"secweaver-agent/pkg/windowseventlog"
)

const parserVersion = "0.3.0"

const defaultStateFile = layout.WindowsData + `\windows-eventlog-risk-json.cursor.json`

var version = parserVersion

var queryWindowsEventsAscending = windowseventlog.QueryAfterAscending

var severityRank = map[string]int{
	"info":     1,
	"low":      2,
	"medium":   3,
	"high":     4,
	"critical": 5,
}

type riskEvent struct {
	EvidenceID      string            `json:"evidence_id"`
	AssetType       string            `json:"asset_type"`
	Timestamp       string            `json:"timestamp"`
	Host            string            `json:"host"`
	HostName        string            `json:"host_name"`
	Channel         string            `json:"channel"`
	Provider        string            `json:"provider"`
	EventID         string            `json:"event_id"`
	WindowsRecordID string            `json:"windows_record_id,omitempty"`
	EventType       string            `json:"event_type"`
	Severity        string            `json:"severity"`
	RiskLevel       string            `json:"risk_level"`
	RuleID          string            `json:"rule_id"`
	RuleName        string            `json:"rule_name"`
	User            string            `json:"user,omitempty"`
	SrcIP           string            `json:"src_ip,omitempty"`
	LogonType       string            `json:"logon_type,omitempty"`
	Process         string            `json:"process,omitempty"`
	Command         string            `json:"command,omitempty"`
	Message         string            `json:"message"`
	RawXML          string            `json:"raw_xml,omitempty"`
	Fields          map[string]string `json:"fields,omitempty"`
	ParserVersion   string            `json:"parser_version"`
}

type stats struct {
	Queries         int `json:"queries"`
	QueryErrors     int `json:"query_errors"`
	EventsRead      int `json:"events_read"`
	EventsWritten   int `json:"events_written"`
	EvidenceWritten int `json:"evidence_written"`
	Suppressed      int `json:"suppressed"`
}

func Main(args []string) int {
	oldArgs := os.Args
	oldCommandLine := flag.CommandLine
	defer func() {
		os.Args = oldArgs
		flag.CommandLine = oldCommandLine
	}()
	os.Args = append([]string{"windows-eventlog-risk-json"}, args...)
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	var channelsCSV string
	var outputPath string
	var stateFile string
	var evidenceOutputPath string
	var lookback time.Duration
	var pollInterval time.Duration
	var maxEvents int
	var once bool
	var includeRaw bool
	var minLevel string
	var failOnQueryError bool
	var showStats bool
	var showVersion bool

	flag.StringVar(&channelsCSV, "channels", "Security,System,Microsoft-Windows-PowerShell/Operational,Microsoft-Windows-Sysmon/Operational", "comma-separated Windows Event Log channels")
	flag.StringVar(&outputPath, "output", layout.WindowsLogs+`\windows-eventlog-risk-json.log`, "JSON Lines output path; - for stdout")
	flag.StringVar(&evidenceOutputPath, "evidence-output", layout.WindowsLogs+`\windows-process-execmon.log`, "host exec/connect/file JSON Lines output; empty disables unified evidence output")
	flag.StringVar(&stateFile, "state-file", defaultStateFile, "persistent EventRecordID cursor state file; empty disables persistence")
	flag.DurationVar(&lookback, "lookback", 10*time.Minute, "event lookback window per poll")
	flag.DurationVar(&pollInterval, "poll-interval", 30*time.Second, "follow mode poll interval")
	flag.IntVar(&maxEvents, "max-events", 300, "maximum events queried from each channel per poll")
	flag.BoolVar(&once, "once", false, "process the current lookback window and exit")
	flag.BoolVar(&includeRaw, "raw", false, "include raw event XML")
	flag.StringVar(&minLevel, "min-level", "medium", "minimum severity: info/low/medium/high/critical")
	flag.BoolVar(&failOnQueryError, "fail-on-query-error", false, "return non-zero when a channel query fails")
	flag.BoolVar(&showStats, "stats", true, "write stats to stderr on exit")
	flag.BoolVar(&showVersion, "version", false, "print version and exit")
	flag.Parse()

	if showVersion {
		fmt.Fprintf(os.Stdout, "windows-eventlog-risk-json %s\n", version)
		return 0
	}
	if runtime.GOOS != "windows" {
		fatalf("windows-eventlog-risk-json only runs on Windows; current platform is %s", runtime.GOOS)
	}
	minLevel = strings.ToLower(strings.TrimSpace(minLevel))
	if _, ok := severityRank[minLevel]; !ok {
		fatalf("-min-level must be one of info/low/medium/high/critical")
	}
	channels := windowseventlog.SplitCSV(channelsCSV)
	if len(channels) == 0 {
		fatalf("no channels configured")
	}
	out, closeOut, err := openOutput(outputPath)
	if err != nil {
		fatalf("open output failed: %v", err)
	}
	defer closeOut()
	var evidenceOut io.Writer
	closeEvidence := func() {}
	if strings.TrimSpace(evidenceOutputPath) != "" {
		if strings.EqualFold(strings.TrimSpace(evidenceOutputPath), strings.TrimSpace(outputPath)) {
			fatalf("-evidence-output must differ from -output")
		}
		evidenceOut, closeEvidence, err = openOutput(evidenceOutputPath)
		if err != nil {
			fatalf("open evidence output failed: %v", err)
		}
	}
	defer closeEvidence()

	cfg := runConfig{
		Channels:         channels,
		StateFile:        stateFile,
		Lookback:         lookback,
		PollInterval:     pollInterval,
		MaxEvents:        maxEvents,
		Once:             once,
		IncludeRaw:       includeRaw,
		MinLevel:         minLevel,
		FailOnQueryError: failOnQueryError,
	}
	st := &stats{}
	ctx, stop := modulecontrol.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, cfg, out, evidenceOut, st); err != nil {
		fatalf("%v", err)
	}
	if showStats {
		b, _ := json.Marshal(st)
		fmt.Fprintf(os.Stderr, "stats: %s\n", b)
	}
	return 0
}

type runConfig struct {
	Channels         []string
	StateFile        string
	Lookback         time.Duration
	PollInterval     time.Duration
	MaxEvents        int
	Once             bool
	IncludeRaw       bool
	MinLevel         string
	FailOnQueryError bool
}

func run(ctx context.Context, cfg runConfig, out, evidenceOut io.Writer, st *stats) error {
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 30 * time.Second
	}
	cursors, err := windowseventlog.LoadCursorState(cfg.StateFile)
	if err != nil {
		return fmt.Errorf("load cursor state: %w", err)
	}
	seenWithoutRecordID := map[string]bool{}
	for {
		beforeCursors := windowseventlog.CloneCursors(cursors)
		if err := collectOnce(ctx, cfg, out, evidenceOut, st, cursors, seenWithoutRecordID); err != nil {
			return err
		}
		if !windowseventlog.CursorsEqual(beforeCursors, cursors) {
			if err := agentoutput.Checkpoint(out); err != nil {
				return fmt.Errorf("checkpoint Windows risk output: %w", err)
			}
			if evidenceOut != nil {
				if err := agentoutput.Checkpoint(evidenceOut); err != nil {
					return fmt.Errorf("checkpoint Windows evidence output: %w", err)
				}
			}
			if err := windowseventlog.SaveCursorState(cfg.StateFile, "windows-eventlog-risk-json", cursors); err != nil {
				return fmt.Errorf("save cursor state: %w", err)
			}
		}
		if cfg.Once {
			return nil
		}
		timer := time.NewTimer(cfg.PollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}

func collectOnce(ctx context.Context, cfg runConfig, out, evidenceOut io.Writer, st *stats, cursors map[string]uint64, seenWithoutRecordID map[string]bool) error {
	enc := json.NewEncoder(out)
	var evidenceEnc *json.Encoder
	if evidenceOut != nil {
		evidenceEnc = json.NewEncoder(evidenceOut)
	}
	pageSize := cfg.MaxEvents
	if pageSize <= 0 {
		pageSize = 200
	}
	for _, channel := range cfg.Channels {
		lookback := cfg.Lookback
		if cursors[channel] > 0 {
			lookback = 0
		}
		for {
			beforeCursor := cursors[channel]
			st.Queries++
			events, err := queryWindowsEventsAscending(ctx, channel, cursors[channel], lookback, cfg.MaxEvents)
			if err != nil {
				st.QueryErrors++
				if cfg.FailOnQueryError {
					return err
				}
				fmt.Fprintf(os.Stderr, "WARN: %v\n", err)
				break
			}
			for _, event := range events {
				recordID := event.RecordIDUint()
				if recordID > 0 {
					if recordID <= cursors[channel] {
						continue
					}
				} else {
					key := event.RecordKey()
					if seenWithoutRecordID[key] {
						continue
					}
					seenWithoutRecordID[key] = true
					if len(seenWithoutRecordID) > 10000 {
						clear(seenWithoutRecordID)
						seenWithoutRecordID[key] = true
					}
				}
				st.EventsRead++
				if isInternalPowerShellEvent(event) {
					st.Suppressed++
					if recordID > cursors[channel] {
						cursors[channel] = recordID
					}
					continue
				}
				if evidenceEnc != nil {
					written, err := windowsevidence.Write(evidenceEnc, event, cfg.IncludeRaw)
					if err != nil {
						return err
					}
					st.EvidenceWritten += written
				}
				for _, item := range classifyRiskEvent(event, cfg.IncludeRaw) {
					if severityRank[item.Severity] < severityRank[cfg.MinLevel] {
						st.Suppressed++
						continue
					}
					if err := enc.Encode(item); err != nil {
						return err
					}
					st.EventsWritten++
				}
				if recordID > cursors[channel] {
					cursors[channel] = recordID
				}
			}
			if len(events) < pageSize || cursors[channel] <= beforeCursor {
				break
			}
			lookback = 0
		}
	}
	return nil
}

func classifyRiskEvent(event windowseventlog.Event, includeRaw bool) []riskEvent {
	if isInternalPowerShellEvent(event) {
		return nil
	}
	fields := event.Fields()
	base := riskEvent{
		EvidenceID:      windowseventlog.EvidenceID("win-risk", event),
		AssetType:       "windows_event_log",
		Timestamp:       event.Timestamp(),
		Host:            event.System.Computer,
		HostName:        event.System.Computer,
		Channel:         event.System.Channel,
		Provider:        event.System.Provider,
		EventID:         event.System.EventID,
		WindowsRecordID: event.System.EventRecordID,
		ParserVersion:   parserVersion,
		Fields:          fields,
	}
	if includeRaw {
		base.RawXML = event.RawXML
	}

	user := firstNonEmpty(event.Field("TargetUserName"), event.Field("SubjectUserName"), event.Field("AccountName"), event.Field("MemberName"))
	srcIP := normalizeSourceIP(firstNonEmpty(event.Field("IpAddress"), event.Field("SourceAddress"), event.Field("ClientAddress")))
	logonType := event.Field("LogonType")
	process := firstNonEmpty(event.Field("ProcessName"), event.Field("NewProcessName"), event.Field("Image"), event.Field("ServiceFileName"))
	command := firstNonEmpty(event.Field("CommandLine"), event.Field("ScriptBlockText"), event.Field("ImagePath"))

	switch event.EventIDInt() {
	case 4624:
		return []riskEvent{finish(base, "windows_logon_success", "high", "WIN-AUTH-4624", "Windows logon success", user, srcIP, logonType, process, command)}
	case 4625:
		return []riskEvent{finish(base, "windows_logon_failed", "medium", "WIN-AUTH-4625", "Windows logon failed", user, srcIP, logonType, process, command)}
	case 4648:
		return []riskEvent{finish(base, "windows_explicit_credentials", "medium", "WIN-AUTH-4648", "Explicit credential logon", user, srcIP, logonType, process, command)}
	case 4672:
		return []riskEvent{finish(base, "windows_special_privileges", "high", "WIN-AUTH-4672", "Special privileges assigned", user, srcIP, logonType, process, command)}
	case 4720:
		return []riskEvent{finish(base, "windows_user_created", "high", "WIN-ACCOUNT-4720", "User account created", user, srcIP, logonType, process, command)}
	case 4726:
		return []riskEvent{finish(base, "windows_user_deleted", "medium", "WIN-ACCOUNT-4726", "User account deleted", user, srcIP, logonType, process, command)}
	case 4728, 4732:
		return []riskEvent{finish(base, "windows_group_member_added", "high", "WIN-ACCOUNT-GROUP-ADD", "Member added to security group", user, srcIP, logonType, process, command)}
	case 1102:
		return []riskEvent{finish(base, "windows_audit_log_cleared", "critical", "WIN-AUDIT-1102", "Windows audit log cleared", user, srcIP, logonType, process, command)}
	case 7045:
		return []riskEvent{finish(base, "windows_service_installed", "high", "WIN-SYSTEM-7045", "Windows service installed", user, srcIP, logonType, process, command)}
	case 4104:
		severity := "medium"
		if containsSuspiciousCommand(command) {
			severity = "high"
		}
		return []riskEvent{finish(base, "powershell_script_block", severity, "WIN-PS-4104", "PowerShell script block", user, srcIP, logonType, process, command)}
	case 4688:
		if containsSuspiciousCommand(command) || containsSuspiciousCommand(process) {
			return []riskEvent{finish(base, "windows_process_high_risk", "high", "WIN-PROC-4688", "High-risk process creation", user, srcIP, logonType, process, command)}
		}
	}
	return nil
}

func isInternalPowerShellEvent(event windowseventlog.Event) bool {
	internalScript := event.Field("ScriptBlockText")
	return agentactivity.IsInternalPowerShellScript(internalScript)
}

func finish(base riskEvent, eventType, severity, ruleID, ruleName, user, srcIP, logonType, process, command string) riskEvent {
	base.EventType = eventType
	base.Severity = severity
	base.RiskLevel = severity
	base.RuleID = ruleID
	base.RuleName = ruleName
	base.User = user
	base.SrcIP = srcIP
	base.LogonType = logonType
	base.Process = process
	base.Command = command
	base.Message = buildMessage(ruleName, user, srcIP, process, command)
	return base
}

func buildMessage(ruleName, user, srcIP, process, command string) string {
	parts := []string{ruleName}
	if user != "" {
		parts = append(parts, "user="+user)
	}
	if srcIP != "" {
		parts = append(parts, "src_ip="+srcIP)
	}
	if process != "" {
		parts = append(parts, "process="+process)
	}
	if command != "" {
		parts = append(parts, "command="+command)
	}
	return strings.Join(parts, " ")
}

func containsSuspiciousCommand(value string) bool {
	lower := strings.ToLower(value)
	for _, token := range []string{
		"-enc", "-encodedcommand", "downloadstring", "invoke-webrequest", " iwr ",
		"curl ", "wget ", "certutil", "bitsadmin", "rundll32", "regsvr32",
		"mimikatz", "add-mppreference", "set-mppreference", "net user",
		"net localgroup", "schtasks", "wmic", "frombase64string",
	} {
		if strings.Contains(lower, token) {
			return true
		}
	}
	return false
}

func normalizeSourceIP(value string) string {
	value = strings.TrimSpace(value)
	if value == "-" || value == "::1" || value == "127.0.0.1" {
		return ""
	}
	return value
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" && value != "-" {
			return value
		}
	}
	return ""
}

func openOutput(path string) (io.Writer, func(), error) {
	return agentoutput.OpenEventAppend(agentoutput.AppendOptions{
		Path:     path,
		Fallback: os.Stdout,
		Perm:     agentoutput.DefaultFilePerm,
	})
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

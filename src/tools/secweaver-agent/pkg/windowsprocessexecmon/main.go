package windowsprocessexecmon

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"time"

	"secweaver-agent/internal/modulecontrol"
	"secweaver-agent/internal/windowsevidence"
	"secweaver-agent/pkg/layout"
	agentoutput "secweaver-agent/pkg/output"
	"secweaver-agent/pkg/windowseventlog"
)

const (
	parserVersion                     = "0.3.0"
	defaultStateFile                  = layout.WindowsData + `\windows-process-execmon.cursor.json`
	defaultWindowsProcessPollInterval = 5 * time.Minute
)

var version = parserVersion

var queryWindowsEventsAscending = windowseventlog.QueryAfterAscending

type stats struct {
	Queries       int `json:"queries"`
	QueryErrors   int `json:"query_errors"`
	EventsRead    int `json:"events_read"`
	EventsWritten int `json:"events_written"`
	Suppressed    int `json:"suppressed"`
}

func Main(args []string) int {
	oldArgs := os.Args
	oldCommandLine := flag.CommandLine
	defer func() {
		os.Args = oldArgs
		flag.CommandLine = oldCommandLine
	}()
	os.Args = append([]string{"windows-process-execmon"}, args...)
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	var channelsCSV string
	var outputPath string
	var stateFile string
	var lookback time.Duration
	var pollInterval time.Duration
	var maxEvents int
	var once bool
	var includeRaw bool
	var failOnQueryError bool
	var showStats bool
	var showVersion bool
	var learning windowsevidence.LearningOptions
	learning.RegisterFlags(flag.CommandLine)

	flag.StringVar(&channelsCSV, "channels", "Security,Microsoft-Windows-Sysmon/Operational", "comma-separated Windows Event Log channels")
	flag.StringVar(&outputPath, "output", layout.WindowsLogs+`\windows-process-execmon.log`, "JSON Lines output path; - for stdout")
	flag.StringVar(&stateFile, "state-file", defaultStateFile, "persistent EventRecordID cursor state file; empty disables persistence")
	flag.DurationVar(&lookback, "lookback", 10*time.Minute, "event lookback window per poll")
	flag.DurationVar(&pollInterval, "poll-interval", defaultWindowsProcessPollInterval, "follow mode poll interval")
	flag.IntVar(&maxEvents, "max-events", 500, "maximum events queried from each channel per poll")
	flag.BoolVar(&once, "once", false, "process the current lookback window and exit")
	flag.BoolVar(&includeRaw, "raw", false, "include raw event XML")
	flag.BoolVar(&failOnQueryError, "fail-on-query-error", false, "return non-zero when a channel query fails")
	flag.BoolVar(&showStats, "stats", true, "write stats to stderr on exit")
	flag.BoolVar(&showVersion, "version", false, "print version and exit")
	flag.Parse()

	if showVersion {
		fmt.Fprintf(os.Stdout, "windows-process-execmon %s\n", version)
		return 0
	}
	if runtime.GOOS != "windows" {
		fatalf("windows-process-execmon only runs on Windows; current platform is %s", runtime.GOOS)
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

	cfg := runConfig{
		Learning: learning, OutputPath: outputPath,
		Channels:         channels,
		StateFile:        stateFile,
		Lookback:         lookback,
		PollInterval:     pollInterval,
		MaxEvents:        maxEvents,
		Once:             once,
		IncludeRaw:       includeRaw,
		FailOnQueryError: failOnQueryError,
	}
	st := &stats{}
	ctx, stop := modulecontrol.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, cfg, out, st); err != nil {
		fatalf("%v", err)
	}
	if showStats {
		b, _ := json.Marshal(st)
		fmt.Fprintf(os.Stderr, "stats: %s\n", b)
	}
	return 0
}

type runConfig struct {
	Learning         windowsevidence.LearningOptions
	OutputPath       string
	Channels         []string
	StateFile        string
	Lookback         time.Duration
	PollInterval     time.Duration
	MaxEvents        int
	Once             bool
	IncludeRaw       bool
	FailOnQueryError bool
}

// run owns the adapter and closes it on all exits before Main closes the sink.
func run(ctx context.Context, cfg runConfig, out io.Writer, st *stats) (runErr error) {
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 10 * time.Second
	}
	cursors, err := windowseventlog.LoadCursorState(cfg.StateFile)
	if err != nil {
		return fmt.Errorf("load cursor state: %w", err)
	}
	var closeLearning func() error
	out, closeLearning = windowsevidence.WrapLearning(out, cfg.Learning, cfg.StateFile, cfg.OutputPath, cfg.PollInterval)
	defer func() {
		if runErr != nil {
			windowsevidence.SourceFault(out, "windows_reader_failed")
		}
		if err := closeLearning(); runErr == nil {
			runErr = err
		}
	}()
	seenWithoutRecordID := map[string]bool{}
	for {
		beforeCursors := windowseventlog.CloneCursors(cursors)
		beforeErrors := st.QueryErrors
		if err := collectOnce(ctx, cfg, out, st, cursors, seenWithoutRecordID); err != nil {
			return err
		}
		windowsevidence.SourcePoll(out, st.QueryErrors == beforeErrors)
		if !windowseventlog.CursorsEqual(beforeCursors, cursors) {
			if err := agentoutput.Checkpoint(out); err != nil {
				return fmt.Errorf("checkpoint Windows evidence output: %w", err)
			}
			if err := windowseventlog.SaveCursorState(cfg.StateFile, "windows-process-execmon", cursors); err != nil {
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

func collectOnce(ctx context.Context, cfg runConfig, out io.Writer, st *stats, cursors map[string]uint64, seenWithoutRecordID map[string]bool) error {
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
				// Normal service stop cancels wevtutil; retain a clean learning state.
				if ctx.Err() != nil {
					return nil
				}
				st.QueryErrors++
				if ctx.Err() == nil {
					windowsevidence.SourceFault(out, "windows_source_query_failed")
				}
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
				if windowsevidence.IsAgentEvent(event) {
					st.Suppressed++
					if recordID > cursors[channel] {
						cursors[channel] = recordID
					}
					continue
				}
				written, err := windowsevidence.WriteSource(out, event, cfg.IncludeRaw)
				if err != nil {
					return err
				}
				st.EventsWritten += written
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

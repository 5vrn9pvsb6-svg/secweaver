package hostpersistence

import (
	"context"

	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"runtime"

	"syscall"
	"time"

	"secweaver-agent/internal/modulecontrol"
	agentoutput "secweaver-agent/pkg/output"
)

// This file owns CLI adaptation and process exit behavior; scanner lifecycle remains context-driven in runner.go.

func Main(args []string) int {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	os.Args = append([]string{"host-persistence"}, args...)

	fs := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	var configPath string
	var outputPath string
	var statePath string
	var hostIP string
	var pollInterval time.Duration
	var once bool
	var emitBaseline bool
	var includeHash bool
	var maxHashBytes int64
	var includeContentDiff bool
	var maxContentBytes int64
	var maxDiffLines int
	var auditEnabled bool
	var auditLog string
	var auditKey string
	var auditManageRules bool
	var showStats bool
	var showVersion bool

	fs.StringVar(&configPath, "config", "", "JSON config path")
	fs.StringVar(&outputPath, "output", defaultOutputLogPath(), "JSON Lines output path; - for stdout")
	fs.StringVar(&statePath, "state", defaultStatePath(), "snapshot state path; empty disables persistent state")
	fs.StringVar(&hostIP, "host-ip", "", "host IP to include; empty auto-detects the primary address")
	fs.DurationVar(&pollInterval, "poll-interval", defaultPollInterval, "scan interval in follow mode")
	fs.BoolVar(&once, "once", false, "scan once and exit")
	fs.BoolVar(&emitBaseline, "emit-baseline", false, "emit observed events for the initial baseline")
	fs.BoolVar(&includeHash, "hash", true, "include SHA256 for regular files up to max-hash-bytes")
	fs.Int64Var(&maxHashBytes, "max-hash-bytes", defaultMaxHashBytes, "maximum regular file size to hash")
	fs.BoolVar(&includeContentDiff, "content-diff", true, "include line diff for small text files")
	fs.Int64Var(&maxContentBytes, "max-content-bytes", defaultMaxContentBytes, "maximum regular text file size to keep for diff")
	fs.IntVar(&maxDiffLines, "max-diff-lines", defaultMaxDiffLines, "maximum content diff lines emitted per event")
	fs.BoolVar(&auditEnabled, "audit", true, "enrich actor/process from auditd")
	fs.StringVar(&auditLog, "audit-log", defaultAuditLogPath, "auditd log path for actor/process enrichment")
	fs.StringVar(&auditKey, "audit-key", defaultAuditKey, "auditd key for host-persistence watch rules")
	fs.BoolVar(&auditManageRules, "audit-manage-rules", true, "add/remove auditd watch rules for configured persistence paths")
	fs.BoolVar(&showStats, "stats", true, "write stats to stderr on exit")
	fs.BoolVar(&showVersion, "version", false, "print version and exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if showVersion {
		fmt.Fprintf(os.Stdout, "host-persistence %s\n", version)
		return 0
	}
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		fatalf("host-persistence only runs on Linux or Windows; current platform is %s", runtime.GOOS)
	}

	cfg, err := loadRuntimeConfig(configPath)
	if err != nil {
		fatalf("load config failed: %v", err)
	}
	if flagSetChanged(fs, "output") {
		cfg.OutputLog = outputPath
	}
	if flagSetChanged(fs, "state") {
		cfg.StatePath = statePath
	}
	if flagSetChanged(fs, "host-ip") {
		cfg.HostIP = hostIP
	}
	if flagSetChanged(fs, "poll-interval") {
		cfg.PollInterval = pollInterval
	}
	if flagSetChanged(fs, "emit-baseline") {
		cfg.EmitBaseline = emitBaseline
	}
	if flagSetChanged(fs, "hash") {
		cfg.IncludeHash = includeHash
	}
	if flagSetChanged(fs, "max-hash-bytes") {
		cfg.MaxHashBytes = maxHashBytes
	}
	if flagSetChanged(fs, "content-diff") {
		cfg.IncludeContentDiff = includeContentDiff
	}
	if flagSetChanged(fs, "max-content-bytes") {
		cfg.MaxContentBytes = maxContentBytes
	}
	if flagSetChanged(fs, "max-diff-lines") {
		cfg.MaxDiffLines = maxDiffLines
	}
	if flagSetChanged(fs, "audit") {
		cfg.Audit.Enabled = auditEnabled
	}
	if flagSetChanged(fs, "audit-log") {
		cfg.Audit.AuditLog = auditLog
	}
	if flagSetChanged(fs, "audit-key") {
		cfg.Audit.Key = auditKey
	}
	if flagSetChanged(fs, "audit-manage-rules") {
		cfg.Audit.ManageRules = auditManageRules
	}
	cfg.Once = once
	cfg.normalize()

	out, closeOut, err := openOutput(cfg.OutputLog)
	if err != nil {
		fatalf("open output failed: %v", err)
	}
	defer closeOut()

	ctx, stop := modulecontrol.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	st := &stats{}
	if err := run(ctx, cfg, out, st); err != nil {
		fatalf("%v", err)
	}
	if showStats {
		b, _ := json.Marshal(st)
		fmt.Fprintf(os.Stderr, "stats: %s\n", b)
	}
	return 0
}

func flagSetChanged(fs *flag.FlagSet, name string) bool {
	changed := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			changed = true
		}
	})
	return changed
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

package syslogriskjson

import (
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"secweaver-agent/internal/modulecontrol"
	"secweaver-agent/pkg/layout"
	agentoutput "secweaver-agent/pkg/output"
)

type syslogLine struct {
	TimestampText string
	Timestamp     time.Time
	HostName      string
	Program       string
	PID           string
	Message       string
	RawLine       string
	SourceFile    string
}

type riskEvent struct {
	Timestamp     string            `json:"timestamp"`
	HostName      string            `json:"host_name,omitempty"`
	HostIP        string            `json:"host_ip,omitempty"`
	SourceFile    string            `json:"source_file"`
	Program       string            `json:"program,omitempty"`
	PID           string            `json:"pid,omitempty"`
	EventType     string            `json:"event_type"`
	Severity      string            `json:"severity"`
	RiskLevel     string            `json:"risk_level"`
	RuleID        string            `json:"rule_id"`
	RuleName      string            `json:"rule_name"`
	User          string            `json:"user,omitempty"`
	SrcIP         string            `json:"src_ip,omitempty"`
	Port          string            `json:"port,omitempty"`
	Process       string            `json:"process,omitempty"`
	Command       string            `json:"command,omitempty"`
	Message       string            `json:"message"`
	RawLine       string            `json:"raw_line,omitempty"`
	Tags          []string          `json:"tags,omitempty"`
	Fields        map[string]string `json:"fields,omitempty"`
	EventID       string            `json:"event_id"`
	ParserVersion string            `json:"parser_version"`
	RulesVersion  string            `json:"rules_version,omitempty"`
}

type stats struct {
	Files      int `json:"files"`
	Lines      int `json:"lines"`
	Events     int `json:"events"`
	Secure     int `json:"secure_events"`
	Messages   int `json:"messages_events"`
	Unparsed   int `json:"unparsed_lines"`
	Suppressed int `json:"suppressed_lines"`
	ReadErrors int `json:"read_errors"`
}

const defaultBackfillLookback = 180 * 24 * time.Hour

type config struct {
	IncludeRaw   bool
	Year         int
	MinLevel     string
	RulesVersion string
	HostName     string
	HostIP       string
}

type logSource struct {
	Path string
	Kind string
}

var (
	authLogCandidates   = []string{"/var/log/secure", "/var/log/auth.log"}
	systemLogCandidates = []string{"/var/log/messages", "/var/log/syslog"}
)

type followOptions struct {
	PollInterval    time.Duration
	FailOnReadError bool
}

type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (w *lockedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.w.Write(p)
}

const parserVersion = "0.3.0"

var version = parserVersion

var (
	syslogPattern       = regexp.MustCompile(`^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<clock>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<program>[^:\[]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$`)
	ipv4Pattern         = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	invalidUserPattern  = regexp.MustCompile(`for invalid user\s+(\S+)`)
	userFromPattern     = regexp.MustCompile(`for\s+(\S+)\s+from`)
	fromIPv4Pattern     = regexp.MustCompile(`from\s+((?:\d{1,3}\.){3}\d{1,3})`)
	portPattern         = regexp.MustCompile(`port\s+(\d+)`)
	pamUserPattern      = regexp.MustCompile(`\buser=([^\s]+)`)
	pamRhostPattern     = regexp.MustCompile(`\brhost=([^\s]+)`)
	sessionUserPattern  = regexp.MustCompile(`session opened for user\s+(\S+)`)
	sudoUserPattern     = regexp.MustCompile(`^\s*([^\s:]+)\s*:`)
	sudoCommandPattern  = regexp.MustCompile(`COMMAND=(.*)$`)
	sudoPWDPattern      = regexp.MustCompile(`PWD=([^;]+)`)
	processPattern      = regexp.MustCompile(`(?:comm=|process\s+)("?[A-Za-z0-9_./-]+"?)`)
	processPIDPattern   = regexp.MustCompile(`\bpid\s*=?\s*(\d+)`)
	systemdUnitPattern  = regexp.MustCompile(`(?:Unit\s+|unit\s+)?([A-Za-z0-9_.@-]+\.service)`)
	accountNamePatterns = []*regexp.Regexp{
		regexp.MustCompile(`new user:\s+name=([^,\s]+)`),
		regexp.MustCompile(`user '([^']+)'`),
		regexp.MustCompile(`\bname=([^,\s]+)`),
	}
)

var severityRank = map[string]int{
	"info":     1,
	"low":      2,
	"medium":   3,
	"high":     4,
	"critical": 5,
}

func Main(args []string) int {
	return Run(args)
}

func hasLegacyUpdateFlag(args []string) bool {
	legacyFlags := map[string]struct{}{
		"update-check":         {},
		"update-now":           {},
		"rollback":             {},
		"update-url":           {},
		"update-channel":       {},
		"update-status-output": {},
		"state-dir":            {},
		"self-path":            {},
	}
	for _, arg := range args {
		if !strings.HasPrefix(arg, "-") {
			continue
		}
		name := strings.TrimLeft(arg, "-")
		if idx := strings.IndexByte(name, '='); idx >= 0 {
			name = name[:idx]
		}
		if _, ok := legacyFlags[name]; ok {
			return true
		}
	}
	return false
}

func Run(args []string) int {
	oldArgs := os.Args
	oldCommandLine := flag.CommandLine
	defer func() {
		os.Args = oldArgs
		flag.CommandLine = oldCommandLine
	}()
	commandName := "syslog-risk-json"
	os.Args = append([]string{commandName}, args...)
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	if hasLegacyUpdateFlag(args) {
		fatalf("secweaver-agent 内置 syslog-risk-json 模块不支持旧版模块自更新参数；请使用 secweaver-agent update check/install/rollback 更新统一 agent 二进制")
	}

	var securePath string
	var messagesPath string
	var outputPath string
	var includeRaw bool
	var year int
	var minLevel string
	var showStats bool
	var failOnReadError bool
	var once bool
	var backfill bool
	var lookback time.Duration
	var pollInterval time.Duration
	var showVersion bool
	var rulesFile string

	flag.StringVar(&securePath, "secure", "auto", "secure/auth 日志路径；auto 自动检测（secure/auth.log）；为空则跳过")
	flag.StringVar(&messagesPath, "messages", "auto", "messages/syslog 日志路径；auto 自动检测（messages/syslog）；为空则跳过")
	flag.StringVar(&outputPath, "output", layout.LinuxLogs+"/syslog-risk-json.log", "输出 JSON Lines 路径；- 表示 stdout")
	flag.BoolVar(&includeRaw, "raw", false, "输出 raw_line 原文")
	flag.IntVar(&year, "year", time.Now().Year(), "syslog 无年份时使用的年份")
	flag.StringVar(&minLevel, "min-level", "medium", "最小输出风险级别：info/low/medium/high/critical")
	flag.BoolVar(&showStats, "stats", true, "结束时向 stderr 输出统计信息")
	flag.BoolVar(&failOnReadError, "fail-on-read-error", false, "任一输入文件读取失败时返回非 0")
	flag.BoolVar(&once, "once", false, "只处理当前文件内容后退出；默认常驻监听新增内容")
	flag.BoolVar(&backfill, "backfill", false, "回溯分析已有日志和常见轮转文件后退出")
	flag.DurationVar(&lookback, "lookback", defaultBackfillLookback, "backfill 回溯窗口；默认 4320h（180 天）")
	flag.DurationVar(&pollInterval, "poll-interval", time.Second, "follow 模式下检查新增内容和日志轮转的间隔")
	flag.BoolVar(&showVersion, "version", false, "打印版本、规则版本、构建信息后退出")
	flag.StringVar(&rulesFile, "rules-file", "", "外部规则文件路径；当前最小实现仅加载校验并输出 rules_version")
	flag.Parse()

	rulesVersion, err := loadRulesVersion(rulesFile)
	if err != nil {
		fatalf("加载规则文件失败：%v", err)
	}
	if showVersion {
		printVersion(os.Stdout, rulesVersion)
		return 0
	}
	if runtime.GOOS != "linux" {
		fatalf("syslog-risk-json only runs on Linux; current platform is %s", runtime.GOOS)
	}

	identity, err := agentoutput.HostIdentityFromEnv()
	if err != nil {
		fatalf("探测主机身份失败：%v", err)
	}
	cfg := config{
		IncludeRaw: includeRaw, Year: year, MinLevel: strings.ToLower(minLevel), RulesVersion: rulesVersion,
		HostName: identity.HostName, HostIP: identity.HostIP,
	}
	if _, ok := severityRank[cfg.MinLevel]; !ok {
		fatalf("-min-level 不合法：%s", minLevel)
	}

	out, closeOut, err := openOutput(outputPath)
	if err != nil {
		fatalf("打开输出失败：%v", err)
	}
	defer closeOut()
	out = &lockedWriter{w: out}

	st := &stats{}
	paths, err := resolveLogSources(securePath, messagesPath)
	if err != nil {
		fatalf("%v", err)
	}
	for _, item := range paths {
		fmt.Fprintf(os.Stderr, "input log [%s]: %s\n", item.Kind, item.Path)
	}
	if backfill {
		since := time.Now().Add(-lookback)
		fmt.Fprintf(os.Stderr, "backfill existing syslog risk logs: lookback=%s since=%s\n", lookback, since.Format(time.RFC3339))
		for _, item := range paths {
			if strings.TrimSpace(item.Path) == "" {
				continue
			}
			if err := processBackfillSource(item, cfg, out, st, since, time.Now()); err != nil {
				st.ReadErrors++
				fmt.Fprintf(os.Stderr, "WARN: 回溯处理 %s 失败：%v\n", item.Path, err)
				if failOnReadError {
					os.Exit(1)
				}
			}
		}
	} else if once {
		for _, item := range paths {
			if strings.TrimSpace(item.Path) == "" {
				continue
			}
			if err := processFile(item.Path, item.Kind, cfg, out, st); err != nil {
				st.ReadErrors++
				fmt.Fprintf(os.Stderr, "WARN: 处理 %s 失败：%v\n", item.Path, err)
				if failOnReadError {
					os.Exit(1)
				}
			}
		}
	} else {
		ctx, stop := modulecontrol.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		if err := followFiles(ctx, paths, cfg, out, st, followOptions{PollInterval: pollInterval, FailOnReadError: failOnReadError}); err != nil {
			fatalf("follow 失败：%v", err)
		}
	}
	if showStats {
		b, _ := json.Marshal(st)
		fmt.Fprintf(os.Stderr, "stats: %s\n", b)
	}
	return 0
}

func resolveLogSources(securePath, messagesPath string) ([]logSource, error) {
	var sources []logSource
	var missing []string

	if strings.TrimSpace(securePath) != "" {
		path, ok := resolveLogPath(securePath, authLogCandidates)
		if !ok {
			missing = append(missing, describeMissingLog("secure/auth", securePath, authLogCandidates))
		} else {
			sources = append(sources, logSource{Path: path, Kind: "secure"})
		}
	}
	if strings.TrimSpace(messagesPath) != "" {
		path, ok := resolveLogPath(messagesPath, systemLogCandidates)
		if !ok {
			missing = append(missing, describeMissingLog("messages/syslog", messagesPath, systemLogCandidates))
		} else {
			sources = append(sources, logSource{Path: path, Kind: "messages"})
		}
	}

	sources = dedupeLogSources(sources)
	if len(missing) > 0 {
		return nil, fmt.Errorf("未找到所需的 syslog 输入文件：%s\n请确认 rsyslog/syslog-ng 已安装并生成日志，或通过 -secure / -messages 显式指定路径", strings.Join(missing, "；"))
	}
	if len(sources) == 0 {
		return nil, fmt.Errorf("未配置任何 syslog 输入；请至少指定 -secure 或 -messages")
	}
	return sources, nil
}

func describeMissingLog(kind, requested string, candidates []string) string {
	requested = strings.TrimSpace(requested)
	if requested == "" || requested == "auto" {
		return fmt.Sprintf("%s（候选：%s）", kind, strings.Join(candidates, "、"))
	}
	return fmt.Sprintf("%s（%s）", kind, requested)
}

func resolveLogPath(requested string, candidates []string) (string, bool) {
	requested = strings.TrimSpace(requested)
	if requested == "" {
		return "", false
	}
	if requested != "auto" {
		if logPathAccessible(requested) {
			return requested, true
		}
		if isKnownLogCandidate(requested, candidates) {
			if alt, ok := firstAccessibleLogPath(candidates, requested); ok {
				fmt.Fprintf(os.Stderr, "INFO: %s 不存在，改用 %s\n", requested, alt)
				return alt, true
			}
		}
		return "", false
	}
	if path, ok := firstAccessibleLogPath(candidates, ""); ok {
		return path, true
	}
	return "", false
}

func firstAccessibleLogPath(candidates []string, skip string) (string, bool) {
	for _, candidate := range candidates {
		if candidate == skip {
			continue
		}
		if logPathAccessible(candidate) {
			return candidate, true
		}
	}
	return "", false
}

func isKnownLogCandidate(requested string, candidates []string) bool {
	for _, candidate := range candidates {
		if requested == candidate {
			return true
		}
	}
	return false
}

func logPathAccessible(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir()
}

func dedupeLogSources(sources []logSource) []logSource {
	seen := map[string]bool{}
	out := make([]logSource, 0, len(sources))
	for _, source := range sources {
		if source.Path == "" || seen[source.Path] {
			continue
		}
		seen[source.Path] = true
		out = append(out, source)
	}
	return out
}

func openOutput(path string) (io.Writer, func(), error) {
	return agentoutput.OpenEventAppend(agentoutput.AppendOptions{
		Path:     path,
		Fallback: os.Stdout,
		Perm:     agentoutput.DefaultFilePerm,
	})
}

func processFile(path, kind string, cfg config, out io.Writer, st *stats) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return processReader(f, path, kind, cfg, out, st, time.Time{}, time.Now())
}

func processReader(r io.Reader, path, kind string, cfg config, out io.Writer, st *stats, since, referenceNow time.Time) error {
	st.Files++
	scanner := bufio.NewScanner(r)
	buf := make([]byte, 0, 1024*1024)
	scanner.Buffer(buf, 8*1024*1024)
	enc := json.NewEncoder(out)
	for scanner.Scan() {
		if err := processRawLineSince(scanner.Text(), path, kind, cfg, enc, st, since, referenceNow); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return nil
}

func processRawLine(raw, path, kind string, cfg config, enc *json.Encoder, st *stats) error {
	return processRawLineSince(raw, path, kind, cfg, enc, st, time.Time{}, time.Now())
}

func processRawLineSince(raw, path, kind string, cfg config, enc *json.Encoder, st *stats, since, referenceNow time.Time) error {
	st.Lines++
	line, ok := parseSyslogLine(raw, path, cfg.Year)
	if !ok {
		st.Unparsed++
		return nil
	}
	line = normalizeSyslogYear(line, referenceNow)
	if !since.IsZero() && !line.Timestamp.IsZero() && line.Timestamp.Before(since) {
		st.Suppressed++
		return nil
	}
	events := classifyLine(line, kind, cfg)
	if len(events) == 0 {
		st.Suppressed++
		return nil
	}
	for _, event := range events {
		if severityRank[event.Severity] < severityRank[cfg.MinLevel] {
			st.Suppressed++
			continue
		}
		if !cfg.IncludeRaw {
			event.RawLine = ""
		}
		if err := enc.Encode(event); err != nil {
			return err
		}
		st.Events++
		if kind == "secure" {
			st.Secure++
		} else {
			st.Messages++
		}
	}
	return nil
}

func processBackfillSource(source logSource, cfg config, out io.Writer, st *stats, since, referenceNow time.Time) error {
	paths, err := discoverBackfillFiles(source.Path, since)
	if err != nil {
		return err
	}
	for _, path := range paths {
		if err := processBackfillFile(path, source.Kind, cfg, out, st, since, referenceNow); err != nil {
			return err
		}
	}
	return nil
}

func discoverBackfillFiles(path string, since time.Time) ([]string, error) {
	candidates := []string{path}
	for _, pattern := range []string{path + ".*", path + "-*"} {
		matches, err := filepathGlob(pattern)
		if err != nil {
			return nil, err
		}
		candidates = append(candidates, matches...)
	}
	seen := map[string]bool{}
	var files []string
	for _, candidate := range candidates {
		if seen[candidate] {
			continue
		}
		seen[candidate] = true
		info, err := os.Stat(candidate)
		if err != nil || info.IsDir() {
			continue
		}
		if !since.IsZero() && info.ModTime().Before(since) {
			continue
		}
		files = append(files, candidate)
	}
	sort.Slice(files, func(i, j int) bool {
		left, _ := os.Stat(files[i])
		right, _ := os.Stat(files[j])
		if left != nil && right != nil && !left.ModTime().Equal(right.ModTime()) {
			return left.ModTime().Before(right.ModTime())
		}
		return files[i] < files[j]
	})
	return files, nil
}

var filepathGlob = filepath.Glob

func processBackfillFile(path, kind string, cfg config, out io.Writer, st *stats, since, referenceNow time.Time) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	var r io.Reader = f
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return err
		}
		defer gz.Close()
		r = gz
	}
	fmt.Fprintf(os.Stderr, "backfill input log [%s]: %s\n", kind, path)
	return processReader(r, path, kind, cfg, out, st, since, referenceNow)
}

func normalizeSyslogYear(line syslogLine, referenceNow time.Time) syslogLine {
	if line.Timestamp.IsZero() || referenceNow.IsZero() {
		return line
	}
	if line.Timestamp.After(referenceNow.Add(24 * time.Hour)) {
		line.Timestamp = line.Timestamp.AddDate(-1, 0, 0)
	}
	return line
}

func followFiles(ctx context.Context, sources []logSource, cfg config, out io.Writer, st *stats, opts followOptions) error {
	if opts.PollInterval <= 0 {
		opts.PollInterval = time.Second
	}
	active := make([]logSource, 0, len(sources))
	for _, source := range sources {
		if strings.TrimSpace(source.Path) != "" {
			active = append(active, source)
		}
	}
	if len(active) == 0 {
		<-ctx.Done()
		return nil
	}

	var wg sync.WaitGroup
	errCh := make(chan error, len(active))
	for _, source := range active {
		source := source
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := followFile(ctx, source.Path, source.Kind, cfg, out, st, opts); err != nil {
				errCh <- err
			}
		}()
	}
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-ctx.Done():
		<-done
		return nil
	case <-done:
		select {
		case err := <-errCh:
			return err
		default:
			return nil
		}
	}
}

func followFile(ctx context.Context, path, kind string, cfg config, out io.Writer, st *stats, opts followOptions) error {
	enc := json.NewEncoder(out)
	var f *os.File
	var reader *bufio.Reader
	openAtEnd := true
	for {
		if ctx.Err() != nil {
			if f != nil {
				_ = f.Close()
			}
			return nil
		}
		if f == nil {
			opened, err := os.Open(path)
			if err != nil {
				st.ReadErrors++
				fmt.Fprintf(os.Stderr, "WARN: 打开 %s 失败：%v\n", path, err)
				if opts.FailOnReadError {
					return err
				}
				if !sleepOrDone(ctx, opts.PollInterval) {
					return nil
				}
				continue
			}
			f = opened
			st.Files++
			if openAtEnd {
				_, _ = f.Seek(0, io.SeekEnd)
			} else {
				_, _ = f.Seek(0, io.SeekStart)
			}
			reader = bufio.NewReaderSize(f, 1024*1024)
			openAtEnd = false
		}

		raw, err := reader.ReadString('\n')
		if len(raw) > 0 {
			raw = strings.TrimRight(raw, "\r\n")
			if raw != "" {
				if err := processRawLine(raw, path, kind, cfg, enc, st); err != nil {
					_ = f.Close()
					return err
				}
			}
		}
		if err == nil {
			continue
		}
		if err != io.EOF {
			st.ReadErrors++
			fmt.Fprintf(os.Stderr, "WARN: 读取 %s 失败：%v\n", path, err)
			if opts.FailOnReadError {
				_ = f.Close()
				return err
			}
		}
		if rotated, truncated := fileRotatedOrTruncated(f, path); rotated || truncated {
			_ = f.Close()
			f = nil
			reader = nil
			openAtEnd = false
			continue
		}
		if !sleepOrDone(ctx, opts.PollInterval) {
			_ = f.Close()
			return nil
		}
	}
}

func fileRotatedOrTruncated(f *os.File, path string) (bool, bool) {
	current, currentErr := f.Stat()
	latest, latestErr := os.Stat(path)
	if currentErr != nil || latestErr != nil {
		return latestErr == nil, false
	}
	if !os.SameFile(current, latest) {
		return true, false
	}
	offset, err := f.Seek(0, io.SeekCurrent)
	if err != nil {
		return false, false
	}
	return false, latest.Size() < offset
}

func sleepOrDone(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func parseSyslogLine(raw, sourceFile string, year int) (syslogLine, bool) {
	matches := namedMatches(syslogPattern, raw)
	if matches == nil {
		return syslogLine{}, false
	}
	text := fmt.Sprintf("%d %s %s %s", year, matches["month"], strings.TrimSpace(matches["day"]), matches["clock"])
	ts, err := time.ParseInLocation("2006 Jan 2 15:04:05", text, time.Local)
	if err != nil {
		ts = time.Time{}
	}
	return syslogLine{
		TimestampText: fmt.Sprintf("%s %s %s", matches["month"], matches["day"], matches["clock"]),
		Timestamp:     ts,
		HostName:      matches["host"],
		Program:       matches["program"],
		PID:           matches["pid"],
		Message:       matches["message"],
		RawLine:       raw,
		SourceFile:    sourceFile,
	}, true
}

func classifyLine(line syslogLine, kind string, cfg config) []riskEvent {
	msg := line.Message
	lower := strings.ToLower(msg)
	program := strings.ToLower(line.Program)
	var events []riskEvent
	emit := func(eventType, severity, ruleID, ruleName string, fields map[string]string, tags ...string) {
		e := baseEvent(line, eventType, severity, ruleID, ruleName, fields, tags...)
		e.RulesVersion = cfg.RulesVersion
		events = append(events, e)
	}

	if kind == "secure" || program == "sshd" || strings.Contains(lower, "pam_unix") || strings.Contains(lower, "sudo") || strings.Contains(lower, "su:") {
		classifySecure(line, lower, emit)
	}
	if kind == "messages" || len(events) == 0 {
		classifyMessages(line, lower, emit)
	}
	for i := range events {
		if strings.TrimSpace(events[i].HostName) == "" {
			events[i].HostName = cfg.HostName
		}
		events[i].HostIP = cfg.HostIP
	}
	return events
}

func classifySecure(line syslogLine, lower string, emit func(string, string, string, string, map[string]string, ...string)) {
	msg := line.Message
	fields := map[string]string{}
	if strings.Contains(lower, "failed password") {
		fillUserAndIP(fields, msg)
		emit("ssh_login_failed", "medium", "secure_ssh_failed_password", "SSH failed password login", fields, "auth", "ssh", "bruteforce")
		return
	}
	if strings.Contains(lower, "invalid user") {
		fillUserAndIP(fields, msg)
		emit("ssh_invalid_user", "medium", "secure_ssh_invalid_user", "SSH invalid user attempt", fields, "auth", "ssh", "recon")
		return
	}
	if strings.Contains(lower, "maximum authentication attempts exceeded") {
		fillUserAndIP(fields, msg)
		emit("ssh_auth_attempts_exceeded", "high", "secure_ssh_max_auth_exceeded", "SSH maximum authentication attempts exceeded", fields, "auth", "ssh", "bruteforce")
		return
	}
	if strings.Contains(lower, "authentication failure") {
		fillPamUserAndIP(fields, msg)
		emit("auth_failure", "medium", "secure_pam_auth_failure", "PAM authentication failure", fields, "auth", "pam")
		return
	}
	if strings.Contains(lower, "accepted password") || strings.Contains(lower, "accepted publickey") {
		fillUserAndIP(fields, msg)
		severity := "high"
		rule := "secure_ssh_login_success"
		if fields["user"] == "root" {
			rule = "secure_ssh_root_login_success"
		}
		emit("ssh_login_success", severity, rule, "SSH successful login", fields, "auth", "ssh", "login_success")
		return
	}
	if strings.Contains(lower, "session opened for user root") {
		fillSessionUser(fields, msg)
		emit("root_session_opened", "high", "secure_root_session_opened", "Root session opened", fields, "auth", "privilege")
		return
	}
	if (strings.Contains(lower, "sudo:") || strings.EqualFold(line.Program, "sudo")) && strings.Contains(lower, "command=") {
		fillSudo(fields, msg)
		severity := "medium"
		if riskyCommand(fields["command"]) {
			severity = "high"
		}
		emit("sudo_command", severity, "secure_sudo_command", "Sudo command execution", fields, "sudo", "privilege")
		return
	}
	if strings.Contains(lower, "su:") && (strings.Contains(lower, "authentication failure") || strings.Contains(lower, "failed")) {
		fillPamUserAndIP(fields, msg)
		emit("su_failure", "medium", "secure_su_failure", "su authentication failure", fields, "auth", "privilege")
		return
	}
	if strings.Contains(lower, "useradd") || strings.Contains(lower, "new user") || strings.Contains(lower, "add user") {
		fillAccountChange(fields, msg)
		emit("account_created", "high", "secure_account_created", "Local account created", fields, "account", "persistence")
		return
	}
	if strings.Contains(lower, "usermod") || strings.Contains(lower, "groupadd") || strings.Contains(lower, "passwd") {
		fillAccountChange(fields, msg)
		emit("account_modified", "medium", "secure_account_modified", "Local account or password modified", fields, "account", "privilege")
		return
	}
}

func classifyMessages(line syslogLine, lower string, emit func(string, string, string, string, map[string]string, ...string)) {
	msg := line.Message
	fields := map[string]string{}
	if strings.Contains(lower, "segfault") || strings.Contains(lower, "general protection fault") {
		fillProcess(fields, msg)
		emit("process_crash", "medium", "messages_process_crash", "Process crash or segfault", fields, "stability", "exploit_signal")
		return
	}
	if strings.Contains(lower, "out of memory") || strings.Contains(lower, "oom-killer") || strings.Contains(lower, "killed process") {
		fillProcess(fields, msg)
		emit("oom_kill", "medium", "messages_oom_kill", "OOM killer event", fields, "availability", "dos_signal")
		return
	}
	if strings.Contains(lower, "kernel panic") || strings.Contains(lower, "panic") {
		emit("kernel_panic", "critical", "messages_kernel_panic", "Kernel panic", fields, "availability", "kernel")
		return
	}
	if strings.Contains(lower, "audit") && (strings.Contains(lower, "avc") || strings.Contains(lower, "denied")) {
		fillProcess(fields, msg)
		emit("security_policy_denied", "medium", "messages_security_policy_denied", "SELinux/AppArmor/audit policy denied", fields, "policy", "denied")
		return
	}
	if strings.Contains(lower, "iptables") || strings.Contains(lower, "firewalld") || strings.Contains(lower, "ufw") {
		fillFirstIP(fields, msg)
		emit("firewall_event", "medium", "messages_firewall_event", "Firewall security event", fields, "firewall", "network")
		return
	}
	if strings.Contains(lower, "possible syn flooding") || strings.Contains(lower, "martian source") || strings.Contains(lower, "promiscuous mode") {
		fillFirstIP(fields, msg)
		emit("network_anomaly", "high", "messages_network_anomaly", "Kernel network anomaly", fields, "network", "anomaly")
		return
	}
	if strings.Contains(lower, "usb") && (strings.Contains(lower, "new") || strings.Contains(lower, "attached")) {
		emit("device_attached", "high", "messages_usb_device_attached", "USB or device attached", fields, "device")
		return
	}
	if strings.Contains(lower, "cron") && (strings.Contains(lower, "wget") || strings.Contains(lower, "curl") || strings.Contains(lower, "bash -c") || strings.Contains(lower, "/tmp/")) {
		fields["command"] = msg
		emit("suspicious_cron_command", "high", "messages_suspicious_cron", "Suspicious cron command", fields, "cron", "persistence")
		return
	}
	if (strings.EqualFold(line.Program, "systemd") || strings.Contains(lower, "systemd")) && (strings.Contains(lower, "failed") || strings.Contains(lower, "failure")) {
		fillSystemdUnit(fields, msg)
		emit("service_failure", "high", "messages_service_failure", "Systemd service failure", fields, "service")
		return
	}
}

func baseEvent(line syslogLine, eventType, severity, ruleID, ruleName string, fields map[string]string, tags ...string) riskEvent {
	if fields == nil {
		fields = map[string]string{}
	}
	timestamp := line.Timestamp.Format(time.RFC3339)
	if line.Timestamp.IsZero() {
		timestamp = line.TimestampText
	}
	e := riskEvent{
		Timestamp:     timestamp,
		HostName:      line.HostName,
		SourceFile:    line.SourceFile,
		Program:       line.Program,
		PID:           line.PID,
		EventType:     eventType,
		Severity:      severity,
		RiskLevel:     severity,
		RuleID:        ruleID,
		RuleName:      ruleName,
		Message:       line.Message,
		RawLine:       line.RawLine,
		Tags:          uniqueSorted(tags),
		Fields:        fields,
		ParserVersion: parserVersion,
	}
	e.User = fields["user"]
	e.SrcIP = fields["src_ip"]
	e.Port = fields["port"]
	e.Process = fields["process"]
	e.Command = fields["command"]
	e.EventID = stableID(line.RawLine, eventType, ruleID)
	if len(e.Fields) == 0 {
		e.Fields = nil
	}
	return e
}

func fillUserAndIP(fields map[string]string, msg string) {
	if m := invalidUserPattern.FindStringSubmatch(msg); len(m) == 2 {
		fields["user"] = m[1]
	} else if m := userFromPattern.FindStringSubmatch(msg); len(m) == 2 {
		fields["user"] = m[1]
	}
	if m := fromIPv4Pattern.FindStringSubmatch(msg); len(m) == 2 {
		fields["src_ip"] = m[1]
	}
	if m := portPattern.FindStringSubmatch(msg); len(m) == 2 {
		fields["port"] = m[1]
	}
}

func fillPamUserAndIP(fields map[string]string, msg string) {
	if m := pamUserPattern.FindStringSubmatch(msg); len(m) == 2 {
		fields["user"] = m[1]
	}
	if m := pamRhostPattern.FindStringSubmatch(msg); len(m) == 2 && m[1] != "" {
		fields["src_ip"] = m[1]
	} else {
		fillFirstIP(fields, msg)
	}
}

func fillSessionUser(fields map[string]string, msg string) {
	if m := sessionUserPattern.FindStringSubmatch(msg); len(m) == 2 {
		fields["user"] = strings.TrimSuffix(m[1], ")")
	}
}

func fillSudo(fields map[string]string, msg string) {
	if m := sudoUserPattern.FindStringSubmatch(msg); len(m) == 2 {
		fields["user"] = m[1]
	}
	if m := sudoCommandPattern.FindStringSubmatch(msg); len(m) == 2 {
		fields["command"] = strings.TrimSpace(m[1])
	}
	if m := sudoPWDPattern.FindStringSubmatch(msg); len(m) == 2 {
		fields["cwd"] = strings.TrimSpace(m[1])
	}
}

func fillAccountChange(fields map[string]string, msg string) {
	for _, re := range accountNamePatterns {
		if m := re.FindStringSubmatch(msg); len(m) == 2 {
			fields["user"] = m[1]
			return
		}
	}
}

func fillProcess(fields map[string]string, msg string) {
	if m := processPattern.FindStringSubmatch(msg); len(m) == 2 {
		fields["process"] = strings.Trim(m[1], `"`)
	}
	if m := processPIDPattern.FindStringSubmatch(strings.ToLower(msg)); len(m) == 2 {
		fields["pid"] = m[1]
	}
}

func fillSystemdUnit(fields map[string]string, msg string) {
	if m := systemdUnitPattern.FindStringSubmatch(msg); len(m) == 2 {
		fields["unit"] = m[1]
	}
}

func fillFirstIP(fields map[string]string, msg string) {
	if m := ipv4Pattern.FindString(msg); m != "" {
		fields["src_ip"] = m
	}
}

func riskyCommand(command string) bool {
	lower := strings.ToLower(command)
	needles := []string{"/etc/sudoers", "useradd", "usermod", "passwd", "chmod 777", "chattr", "iptables", "firewall", "curl ", "wget ", "nc ", "ncat", "bash -c", "/tmp/", "crontab"}
	for _, n := range needles {
		if strings.Contains(lower, n) {
			return true
		}
	}
	return false
}

func namedMatches(re *regexp.Regexp, text string) map[string]string {
	match := re.FindStringSubmatch(text)
	if match == nil {
		return nil
	}
	out := map[string]string{}
	for i, name := range re.SubexpNames() {
		if i > 0 && name != "" {
			out[name] = match[i]
		}
	}
	return out
}

func uniqueSorted(values []string) []string {
	set := map[string]bool{}
	for _, v := range values {
		if v = strings.TrimSpace(v); v != "" {
			set[v] = true
		}
	}
	out := make([]string, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func stableID(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		_, _ = h.Write([]byte(p))
		_, _ = h.Write([]byte{0})
	}
	return "syslog-risk-" + hex.EncodeToString(h.Sum(nil))[:16]
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "ERROR: "+format+"\n", args...)
	os.Exit(2)
}

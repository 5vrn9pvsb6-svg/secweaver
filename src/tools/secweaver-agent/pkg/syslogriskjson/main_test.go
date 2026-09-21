package syslogriskjson

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"secweaver-agent/internal/testutil"
)

func TestResolveLogPathAutoUsesFirstExistingCandidate(t *testing.T) {
	dir := t.TempDir()
	authLog := filepath.Join(dir, "auth.log")
	if err := os.WriteFile(authLog, []byte("x\n"), 0644); err != nil {
		t.Fatal(err)
	}
	path, ok := resolveLogPath("auto", []string{filepath.Join(dir, "secure"), authLog})
	if !ok || path != authLog {
		t.Fatalf("resolveLogPath(auto) = (%q, %v), want (%q, true)", path, ok, authLog)
	}
}

func TestResolveLogPathFallsBackWhenDefaultMissing(t *testing.T) {
	dir := t.TempDir()
	authLog := filepath.Join(dir, "auth.log")
	if err := os.WriteFile(authLog, []byte("x\n"), 0644); err != nil {
		t.Fatal(err)
	}
	missingSecure := filepath.Join(dir, "secure")
	path, ok := resolveLogPath(missingSecure, []string{missingSecure, authLog})
	if !ok || path != authLog {
		t.Fatalf("resolveLogPath fallback = (%q, %v), want (%q, true)", path, ok, authLog)
	}
}

func TestResolveLogSourcesDedupesSamePath(t *testing.T) {
	dir := t.TempDir()
	syslog := filepath.Join(dir, "syslog")
	if err := os.WriteFile(syslog, []byte("x\n"), 0644); err != nil {
		t.Fatal(err)
	}
	sources, err := resolveLogSources(syslog, syslog)
	if err != nil {
		t.Fatalf("resolveLogSources: %v", err)
	}
	if len(sources) != 1 || sources[0].Path != syslog {
		t.Fatalf("deduped sources = %#v, want single %q", sources, syslog)
	}
}

func TestResolveLogPathAutoAcrossOSCandidates(t *testing.T) {
	dir := t.TempDir()
	authLog := filepath.Join(dir, "auth.log")
	syslog := filepath.Join(dir, "syslog")
	for _, path := range []string{authLog, syslog} {
		if err := os.WriteFile(path, []byte("x\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	authCandidates := []string{filepath.Join(dir, "secure"), authLog}
	systemCandidates := []string{filepath.Join(dir, "messages"), syslog}

	securePath, ok := resolveLogPath("auto", authCandidates)
	if !ok || securePath != authLog {
		t.Fatalf("auth auto = (%q, %v), want (%q, true)", securePath, ok, authLog)
	}
	messagesPath, ok := resolveLogPath("auto", systemCandidates)
	if !ok || messagesPath != syslog {
		t.Fatalf("system auto = (%q, %v), want (%q, true)", messagesPath, ok, syslog)
	}
}

func TestResolveLogPathDoesNotFallbackForCustomMissingPath(t *testing.T) {
	dir := t.TempDir()
	custom := filepath.Join(dir, "custom-auth.log")
	path, ok := resolveLogPath(custom, authLogCandidates)
	if ok || path != "" {
		t.Fatalf("custom missing path = (%q, %v), want (_, false)", path, ok)
	}
}

func TestResolveLogSourcesRequiresBothDefaultLogs(t *testing.T) {
	if _, err := resolveLogSources("auto", "auto"); err == nil {
		t.Fatal("expected error when both default log files are missing")
	}
}

func TestResolveLogSourcesAllowsSingleConfiguredLog(t *testing.T) {
	dir := t.TempDir()
	authLog := filepath.Join(dir, "auth.log")
	if err := os.WriteFile(authLog, []byte("x\n"), 0644); err != nil {
		t.Fatal(err)
	}
	sources, err := resolveLogSources(authLog, "")
	if err != nil {
		t.Fatalf("resolveLogSources: %v", err)
	}
	if len(sources) != 1 || sources[0].Path != authLog {
		t.Fatalf("sources = %#v, want single auth log", sources)
	}
}

func TestParseSecureFailedPassword(t *testing.T) {
	line, ok := parseSyslogLine(`Jun 30 13:01:02 host-1 sshd[1234]: Failed password for invalid user admin from 1.2.3.4 port 52222 ssh2`, "/var/log/secure", 2026)
	if !ok {
		t.Fatal("parse failed")
	}
	events := classifyLine(line, "secure", config{IncludeRaw: true, Year: 2026, MinLevel: "medium"})
	if len(events) != 1 {
		t.Fatalf("events len=%d", len(events))
	}
	e := events[0]
	if e.EventType != "ssh_login_failed" || e.SrcIP != "1.2.3.4" || e.User != "admin" || e.Severity != "medium" {
		t.Fatalf("unexpected event: %+v", e)
	}
}

func TestParseRootLoginHighRisk(t *testing.T) {
	line, ok := parseSyslogLine(`Jun 30 13:02:03 host-1 sshd[1235]: Accepted password for root from 5.6.7.8 port 60000 ssh2`, "/var/log/secure", 2026)
	if !ok {
		t.Fatal("parse failed")
	}
	events := classifyLine(line, "secure", config{IncludeRaw: false, Year: 2026, MinLevel: "medium"})
	if len(events) != 1 {
		t.Fatalf("events len=%d", len(events))
	}
	e := events[0]
	if e.EventType != "ssh_login_success" || e.User != "root" || e.Severity != "high" || e.RawLine != line.RawLine {
		t.Fatalf("unexpected event: %+v", e)
	}
}

func TestParseUserLoginHighRiskAndPassesMediumFilter(t *testing.T) {
	raw := `Jul 10 17:43:20 localhost sshd[15270]: Accepted password for devops from 192.0.2.91 port 59014 ssh2`
	line, ok := parseSyslogLine(raw, "/var/log/secure", 2026)
	if !ok {
		t.Fatal("parse failed")
	}
	events := classifyLine(line, "secure", config{IncludeRaw: false, Year: 2026, MinLevel: "medium"})
	if len(events) != 1 {
		t.Fatalf("events len=%d", len(events))
	}
	e := events[0]
	if e.EventType != "ssh_login_success" || e.User != "devops" || e.SrcIP != "192.0.2.91" || e.Severity != "high" || e.RuleID != "secure_ssh_login_success" {
		t.Fatalf("unexpected event: %+v", e)
	}

	var out bytes.Buffer
	st := &stats{}
	if err := processRawLine(raw, "/var/log/secure", "secure", config{IncludeRaw: false, Year: 2026, MinLevel: "medium"}, json.NewEncoder(&out), st); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"ssh_login_success"`) || !strings.Contains(out.String(), `"severity":"high"`) {
		t.Fatalf("expected medium filter to emit high-risk user login, got: %s", out.String())
	}
}

func TestSudoRiskCommand(t *testing.T) {
	line, ok := parseSyslogLine(`Jun 30 13:03:04 host-1 sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/sbin/useradd backdoor`, "/var/log/secure", 2026)
	if !ok {
		t.Fatal("parse failed")
	}
	events := classifyLine(line, "secure", config{IncludeRaw: false, Year: 2026, MinLevel: "medium"})
	if len(events) != 1 {
		t.Fatalf("events len=%d", len(events))
	}
	e := events[0]
	if e.EventType != "sudo_command" || e.Severity != "high" || !strings.Contains(e.Command, "useradd") {
		t.Fatalf("unexpected event: %+v", e)
	}
}

func TestMessagesNetworkAnomaly(t *testing.T) {
	line, ok := parseSyslogLine(`Jun 30 13:04:05 host-1 kernel: possible SYN flooding on port 80. Sending cookies.`, "/var/log/messages", 2026)
	if !ok {
		t.Fatal("parse failed")
	}
	events := classifyLine(line, "messages", config{IncludeRaw: false, Year: 2026, MinLevel: "medium"})
	if len(events) != 1 {
		t.Fatalf("events len=%d", len(events))
	}
	if events[0].EventType != "network_anomaly" || events[0].Severity != "high" {
		t.Fatalf("unexpected event: %+v", events[0])
	}
}

func TestMessagesDeviceAttachedHighRisk(t *testing.T) {
	raw := `Jun 30 13:04:06 host-1 kernel: usb 1-1: new high-speed USB device number 4 using xhci_hcd`
	line, ok := parseSyslogLine(raw, "/var/log/messages", 2026)
	if !ok {
		t.Fatal("parse failed")
	}
	events := classifyLine(line, "messages", config{IncludeRaw: false, Year: 2026, MinLevel: "medium"})
	if len(events) != 1 {
		t.Fatalf("events len=%d", len(events))
	}
	if events[0].EventType != "device_attached" || events[0].Severity != "high" {
		t.Fatalf("unexpected event: %+v", events[0])
	}

	var out bytes.Buffer
	st := &stats{}
	if err := processRawLine(raw, "/var/log/messages", "messages", config{IncludeRaw: false, Year: 2026, MinLevel: "medium"}, json.NewEncoder(&out), st); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"device_attached"`) || !strings.Contains(out.String(), `"severity":"high"`) {
		t.Fatalf("expected medium filter to emit high-risk device event, got: %s", out.String())
	}
}

func TestMessagesServiceFailureHighRisk(t *testing.T) {
	line, ok := parseSyslogLine(`Jun 30 13:04:07 host-1 systemd[1]: nginx.service: Failed with result 'exit-code'.`, "/var/log/messages", 2026)
	if !ok {
		t.Fatal("parse failed")
	}
	events := classifyLine(line, "messages", config{IncludeRaw: false, Year: 2026, MinLevel: "medium"})
	if len(events) != 1 {
		t.Fatalf("events len=%d", len(events))
	}
	if events[0].EventType != "service_failure" || events[0].Severity != "high" || events[0].Fields["unit"] != "nginx.service" {
		t.Fatalf("unexpected event: %+v", events[0])
	}
}

func TestEventJSONShape(t *testing.T) {
	line, ok := parseSyslogLine(`Jun 30 13:05:06 host-1 sshd[1236]: maximum authentication attempts exceeded for root from 1.1.1.1 port 3333 ssh2`, "/var/log/secure", 2026)
	if !ok {
		t.Fatal("parse failed")
	}
	events := classifyLine(line, "secure", config{
		IncludeRaw: true, Year: 2026, MinLevel: "medium",
		HostName: "host-test-01", HostIP: "192.0.2.10",
	})
	b, err := json.Marshal(events[0])
	if err != nil {
		t.Fatal(err)
	}
	var obj map[string]any
	if err := json.Unmarshal(b, &obj); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"timestamp", "host_name", "host_ip", "event_type", "severity", "rule_id", "event_id", "parser_version"} {
		if _, ok := obj[key]; !ok {
			t.Fatalf("missing key %s in %s", key, b)
		}
	}
}

func TestBackfillReadsRotatedGzipAndFiltersLookback(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secure")
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.Local)
	since := now.Add(-180 * 24 * time.Hour)
	if err := os.WriteFile(path, []byte("Jan 01 01:00:00 host-1 sshd[1]: Failed password for root from 9.9.9.9 port 1 ssh2\n"), 0644); err != nil {
		t.Fatal(err)
	}
	rotated := path + ".1.gz"
	f, err := os.Create(rotated)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	if _, err := gz.Write([]byte("Jul 10 17:43:20 host-1 sshd[15270]: Accepted password for devops from 192.0.2.91 port 59014 ssh2\n")); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	for _, item := range []string{path, rotated} {
		if err := os.Chtimes(item, now, now); err != nil {
			t.Fatal(err)
		}
	}

	var out bytes.Buffer
	st := &stats{}
	if err := processBackfillSource(logSource{Path: path, Kind: "secure"}, config{Year: 2026, MinLevel: "medium"}, &out, st, since, now); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if strings.Contains(got, "9.9.9.9") {
		t.Fatalf("old event should be filtered, got: %s", got)
	}
	if !strings.Contains(got, "ssh_login_success") || !strings.Contains(got, "192.0.2.91") {
		t.Fatalf("rotated gzip event missing, got: %s", got)
	}
}

func TestOpenOutputUsesRootOnlyPermissions(t *testing.T) {
	t.Setenv("SECWEAVER_ENTERPRISE_ID", "6X13NGV4G9CVK92E")
	t.Setenv("SECWEAVER_HOST_NAME", "host-test-01")
	t.Setenv("SECWEAVER_HOST_IP", "192.0.2.10")
	path := filepath.Join(t.TempDir(), "syslog-risk-json.log")
	_, closeOut, err := openOutput(path)
	if err != nil {
		t.Fatal(err)
	}
	closeOut()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Fatalf("output permission = %o, want 600", got)
	}
}

func TestOpenOutputInjectsRequiredHostEventFields(t *testing.T) {
	t.Setenv("SECWEAVER_ENTERPRISE_ID", "6X13NGV4G9CVK92E")
	t.Setenv("SECWEAVER_HOST_NAME", "host-test-01")
	t.Setenv("SECWEAVER_HOST_IP", "192.0.2.10")
	path := filepath.Join(t.TempDir(), "syslog-risk-json.log")
	out, closeOut, err := openOutput(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.NewEncoder(out).Encode(map[string]any{
		"event_type": "root_session_opened",
		"message":    "session opened",
	}); err != nil {
		t.Fatal(err)
	}
	closeOut()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var event map[string]any
	if err := json.Unmarshal(body, &event); err != nil {
		t.Fatal(err)
	}
	if event["enterprise_id"] != "6X13NGV4G9CVK92E" {
		t.Fatalf("enterprise ID missing from syslog output: %s", body)
	}
	if event["host_name"] != "host-test-01" || event["host_ip"] != "192.0.2.10" {
		t.Fatalf("host identity missing from syslog output: %s", body)
	}
}

func TestFollowFileStartsAtEndAndProcessesAppendedLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secure")
	if err := os.WriteFile(path, []byte("Jun 30 13:00:00 host-1 sshd[1]: Failed password for root from 9.9.9.9 port 1 ssh2\n"), 0644); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var out testutil.SyncBuffer
	st := &stats{}
	errCh := make(chan error, 1)
	go func() {
		errCh <- followFile(ctx, path, "secure", config{Year: 2026, MinLevel: "medium"}, &out, st, followOptions{PollInterval: 10 * time.Millisecond})
	}()

	time.Sleep(50 * time.Millisecond)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.WriteString("Jun 30 13:01:02 host-1 sshd[1234]: Failed password for invalid user admin from 1.2.3.4 port 52222 ssh2\n")
	_ = f.Close()
	if err != nil {
		t.Fatal(err)
	}

	deadline := time.After(time.Second)
	for !strings.Contains(out.String(), "ssh_login_failed") {
		select {
		case <-deadline:
			t.Fatalf("follow output did not include appended event: %s", out.String())
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
	cancel()
	if err := <-errCh; err != nil {
		t.Fatalf("followFile: %v", err)
	}
	if strings.Contains(out.String(), "9.9.9.9") {
		t.Fatalf("follow mode should start at end and skip existing content: %s", out.String())
	}
}

func TestFollowFileContinuesAfterRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secure")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", 4096)+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var out testutil.SyncBuffer
	st := &stats{}
	errCh := make(chan error, 1)
	go func() {
		errCh <- followFile(ctx, path, "secure", config{Year: 2026, MinLevel: "medium"}, &out, st, followOptions{PollInterval: 10 * time.Millisecond})
	}()

	time.Sleep(50 * time.Millisecond)
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, nil, 0644); err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Millisecond)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.WriteString("Jul  5 21:30:00 host-1 sshd[99]: Failed password for invalid user admin from 1.2.3.4 port 52222 ssh2\n")
	_ = f.Close()
	if err != nil {
		t.Fatal(err)
	}

	deadline := time.After(2 * time.Second)
	for !strings.Contains(out.String(), "ssh_login_failed") {
		select {
		case <-deadline:
			t.Fatalf("expected event after log rotation, got %s", out.String())
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
	cancel()
	if err := <-errCh; err != nil {
		t.Fatalf("followFile: %v", err)
	}
}

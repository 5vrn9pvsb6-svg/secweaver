package output

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"secweaver-agent/internal/testutil"
)

func setTestHostIdentity(t *testing.T) {
	t.Helper()
	t.Setenv(HostNameEnv, "host-test-01")
	t.Setenv(HostIPEnv, "192.0.2.10")
}

func TestNormalizeEnterpriseID(t *testing.T) {
	got, err := NormalizeEnterpriseID(" 6x13ngv4g9cvk92e ")
	if err != nil {
		t.Fatal(err)
	}
	if got != "6X13NGV4G9CVK92E" {
		t.Fatalf("enterprise ID = %q", got)
	}
	for _, invalid := range []string{"", "short", "6X13NGV4G9CVK92-", "6X13NGV4G9CVK92E0"} {
		if _, err := NormalizeEnterpriseID(invalid); err == nil {
			t.Fatalf("expected %q to be rejected", invalid)
		}
	}
}

func TestEnterpriseJSONLinesWriterInjectsEveryRecordAcrossWrites(t *testing.T) {
	setTestHostIdentity(t)
	var sink bytes.Buffer
	writer, err := NewEnterpriseJSONLinesWriter(&sink, "6X13NGV4G9CVK92E")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte(`{"event_type":"exec","record_id":9007199254740993`)); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("}\n{\"event_type\":\"connect\"}\n")); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(sink.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("lines = %q", sink.String())
	}
	for _, line := range lines {
		var record map[string]json.RawMessage
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatal(err)
		}
		if string(record["enterprise_id"]) != `"6X13NGV4G9CVK92E"` {
			t.Fatalf("record missing enterprise ID: %s", line)
		}
		if string(record["host_name"]) != `"host-test-01"` || string(record["host_ip"]) != `"192.0.2.10"` {
			t.Fatalf("record missing host identity: %s", line)
		}
	}
	if !strings.Contains(lines[0], `9007199254740993`) {
		t.Fatalf("large integer changed: %s", lines[0])
	}
}

func TestEnterpriseJSONLinesWriterOverridesUntrustedField(t *testing.T) {
	setTestHostIdentity(t)
	var sink bytes.Buffer
	writer, err := NewEnterpriseJSONLinesWriter(&sink, "6X13NGV4G9CVK92E")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("{\"enterprise_id\":\"ATTACKER00000000\",\"message\":\"ok\"}\n")); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sink.String(), "ATTACKER") || !strings.Contains(sink.String(), "6X13NGV4G9CVK92E") {
		t.Fatalf("enterprise field was not enforced: %s", sink.String())
	}
}

func TestEnterpriseJSONLinesWriterPreservesExplicitHostIdentity(t *testing.T) {
	setTestHostIdentity(t)
	var sink bytes.Buffer
	writer, err := NewEnterpriseJSONLinesWriter(&sink, "6X13NGV4G9CVK92E")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("{\"host_name\":\"module-host\",\"host_ip\":\"198.51.100.20\"}\n")); err != nil {
		t.Fatal(err)
	}
	var record map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(sink.Bytes()), &record); err != nil {
		t.Fatal(err)
	}
	if record["host_name"] != "module-host" || record["host_ip"] != "198.51.100.20" {
		t.Fatalf("explicit module host identity changed: %s", sink.String())
	}
}

func TestHostIdentityFromEnvValidatesAndNormalizes(t *testing.T) {
	setTestHostIdentity(t)
	identity, err := HostIdentityFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if identity.HostName != "host-test-01" || identity.HostIP != "192.0.2.10" {
		t.Fatalf("identity = %+v", identity)
	}
	t.Setenv(HostIPEnv, "127.0.0.1")
	if _, err := HostIdentityFromEnv(); err == nil || !strings.Contains(err.Error(), HostIPEnv) {
		t.Fatalf("loopback host IP should be rejected, got %v", err)
	}
}

func TestDetectPrimaryHostIPReturnsNonLoopbackAddress(t *testing.T) {
	hostIP, err := DetectPrimaryHostIP()
	if err != nil {
		t.Fatal(err)
	}
	ip := net.ParseIP(hostIP)
	if ip == nil || ip.IsLoopback() || !ip.IsGlobalUnicast() {
		t.Fatalf("auto-detected host IP is not usable: %q", hostIP)
	}
}

func TestOpenEventAppendRequiresEnterpriseID(t *testing.T) {
	t.Setenv(EnterpriseIDEnv, "")
	if _, _, err := OpenEventAppend(AppendOptions{Path: "-", Fallback: &bytes.Buffer{}}); err == nil {
		t.Fatal("expected missing enterprise ID error")
	}
}

func TestPeriodicFlushWriterFlushesOnInterval(t *testing.T) {
	var sink testutil.SyncBuffer
	writer := NewPeriodicFlushWriter(&sink, 1024, 10*time.Millisecond)
	if _, err := writer.Write([]byte("one\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if sink.Len() != 0 {
		t.Fatalf("writer should buffer before interval, got %q", sink.String())
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if sink.String() == "one\n" {
			_ = writer.Close()
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	_ = writer.Close()
	t.Fatalf("writer did not flush on interval, got %q", sink.String())
}

func TestPeriodicFlushWriterCloseFlushes(t *testing.T) {
	var sink bytes.Buffer
	writer := NewPeriodicFlushWriter(&sink, 1024, time.Hour)
	if _, err := writer.Write([]byte("one\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if got := sink.String(); got != "one\n" {
		t.Fatalf("flushed output = %q, want one line", got)
	}
}

func TestCheckpointFlushesAndSyncsDestination(t *testing.T) {
	setTestHostIdentity(t)
	sink := &syncTrackingWriter{}
	buffered := NewPeriodicFlushWriter(sink, 1024, -1)
	writer, err := NewEnterpriseJSONLinesWriter(buffered, "6X13NGV4G9CVK92E")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("{\"event_type\":\"exec\"}\n")); err != nil {
		t.Fatal(err)
	}
	if sink.Len() != 0 || sink.syncs != 0 {
		t.Fatalf("event should still be buffered: len=%d syncs=%d", sink.Len(), sink.syncs)
	}
	if err := Checkpoint(writer); err != nil {
		t.Fatal(err)
	}
	if sink.Len() == 0 || sink.syncs != 1 {
		t.Fatalf("checkpoint did not make output durable: len=%d syncs=%d", sink.Len(), sink.syncs)
	}
}

func TestPeriodicFlushWriterKeepsFlushError(t *testing.T) {
	errBoom := errors.New("boom")
	sink := &failingWriter{err: errBoom}
	writer := NewPeriodicFlushWriter(sink, 1024, -1)
	if _, err := writer.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Flush(); !errors.Is(err, errBoom) {
		t.Fatalf("flush err=%v want %v", err, errBoom)
	}
	if _, err := writer.Write([]byte("again")); !errors.Is(err, errBoom) {
		t.Fatalf("sticky write err=%v want %v", err, errBoom)
	}
	if err := writer.Close(); !errors.Is(err, errBoom) {
		t.Fatalf("close err=%v want %v", err, errBoom)
	}
}

type failingWriter struct {
	err error
}

func (w *failingWriter) Write(p []byte) (int, error) {
	return 0, w.err
}

type syncTrackingWriter struct {
	bytes.Buffer
	syncs int
}

func (w *syncTrackingWriter) Sync() error {
	w.syncs++
	return nil
}

func TestOpenAppendEnforcesPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.log")
	backup := path + ".1"
	if err := os.WriteFile(path, []byte("old\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(backup, []byte("older\n"), 0644); err != nil {
		t.Fatal(err)
	}
	// Omitting Perm exercises the secure default used by future callers.
	_, closeOut, err := OpenAppend(AppendOptions{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	closeOut()
	for _, checkedPath := range []string{path, backup} {
		info, err := os.Stat(checkedPath)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != DefaultFilePerm {
			t.Fatalf("permission for %s = %o, want %o", checkedPath, got, DefaultFilePerm)
		}
	}
}

func TestOpenAppendRejectsBroaderPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.log")
	if _, _, err := OpenAppend(AppendOptions{Path: path, Perm: 0644}); err == nil {
		t.Fatal("expected insecure log permissions to be rejected")
	}
}

func TestOpenAppendRejectsSymlinkBackup(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks requires privileges on many Windows hosts")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "events.log")
	target := filepath.Join(dir, "outside.log")
	if err := os.WriteFile(target, []byte("protected\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path+".1"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenAppend(AppendOptions{Path: path}); err == nil {
		t.Fatal("expected symlink backup to be rejected")
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0644 {
		t.Fatalf("symlink target permission = %o, want unchanged 0644", got)
	}
}

func TestOpenAppendRotatesBySizeAndKeepsBackups(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.log")
	out, closeOut, err := OpenAppend(AppendOptions{
		Path:          path,
		Perm:          0600,
		BufferSize:    1,
		FlushInterval: -1,
		MaxSizeBytes:  10,
		MaxBackups:    2,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{"11111\n", "22222\n", "33333\n", "44444\n"} {
		if _, err := out.Write([]byte(line)); err != nil {
			t.Fatalf("write %q: %v", line, err)
		}
	}
	closeOut()

	current, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	firstBackup, err := os.ReadFile(path + ".1")
	if err != nil {
		t.Fatal(err)
	}
	secondBackup, err := os.ReadFile(path + ".2")
	if err != nil {
		t.Fatal(err)
	}
	if string(current) != "44444\n" || string(firstBackup) != "33333\n" || string(secondBackup) != "22222\n" {
		t.Fatalf("unexpected rotation files: current=%q .1=%q .2=%q", current, firstBackup, secondBackup)
	}
	for _, checkedPath := range []string{path, path + ".1", path + ".2"} {
		info, err := os.Stat(checkedPath)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != DefaultFilePerm {
			t.Fatalf("rotated permission for %s = %o, want %o", checkedPath, got, DefaultFilePerm)
		}
	}
	if _, err := os.Stat(path + ".3"); !os.IsNotExist(err) {
		t.Fatalf("unexpected third backup stat err=%v", err)
	}
}

func TestDiskBudgetClampsTotalRetention(t *testing.T) {
	t.Setenv(diskBudgetEnabledEnv, "true")
	t.Setenv(diskBudgetPerFileBytesEnv, "12582912")
	t.Setenv(diskBudgetMinFreeBytesEnv, "0")
	t.Setenv(diskBudgetCheckIntervalEnv, "30")
	file, err := OpenRotatingFile(filepath.Join(t.TempDir(), "events.log"), DefaultFilePerm, DefaultMaxSizeBytes, DefaultMaxBackups)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if got := file.maxSizeBytes * int64(file.maxBackups+1); got > 12*1024*1024 {
		t.Fatalf("retention=%d exceeds assigned budget", got)
	}
	if file.maxSizeBytes < 1024*1024 {
		t.Fatalf("active file became impractically small: %d", file.maxSizeBytes)
	}
}

func TestDiskBudgetRemovesBackupsAboveReducedLimit(t *testing.T) {
	t.Setenv(diskBudgetEnabledEnv, "true")
	t.Setenv(diskBudgetPerFileBytesEnv, "2097152")
	t.Setenv(diskBudgetMinFreeBytesEnv, "0")
	t.Setenv(diskBudgetCheckIntervalEnv, "30")
	path := filepath.Join(t.TempDir(), "events.log")
	if err := os.WriteFile(path, make([]byte, 256*1024), DefaultFilePerm); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{".1", ".2", ".3"} {
		if err := os.WriteFile(path+suffix, make([]byte, 256*1024), DefaultFilePerm); err != nil {
			t.Fatal(err)
		}
	}
	file, err := OpenRotatingFile(path, DefaultFilePerm, DefaultMaxSizeBytes, DefaultMaxBackups)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if file.maxBackups != 1 {
		t.Fatalf("max backups=%d, want 1 under 2MB share", file.maxBackups)
	}
	for _, suffix := range []string{".2", ".3"} {
		if _, err := os.Stat(path + suffix); !os.IsNotExist(err) {
			t.Fatalf("backup %s above reduced limit remains: %v", suffix, err)
		}
	}
}

func TestDiskBudgetStopsSnapshotsBeforeRealtimeEvidence(t *testing.T) {
	original := availableDiskBytes
	t.Cleanup(func() { availableDiskBytes = original })
	availableDiskBytes = func(string) (uint64, error) { return 550, nil }
	t.Setenv(diskBudgetEnabledEnv, "true")
	t.Setenv(diskBudgetPerFileBytesEnv, "400")
	t.Setenv(diskBudgetMinFreeBytesEnv, "500")
	t.Setenv(diskBudgetCheckIntervalEnv, "30")

	t.Setenv(DiskPriorityEnv, DiskPriorityRealtime)
	realtime, err := OpenRotatingFile(filepath.Join(t.TempDir(), "realtime.log"), DefaultFilePerm, 100, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := realtime.Write([]byte("event\n")); err != nil {
		t.Fatalf("realtime evidence should retain the base reserve: %v", err)
	}
	_ = realtime.Close()

	t.Setenv(DiskPriorityEnv, DiskPrioritySnapshot)
	snapshot, err := OpenRotatingFile(filepath.Join(t.TempDir(), "snapshot.log"), DefaultFilePerm, 100, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	if _, err := snapshot.Write([]byte("snapshot\n")); err == nil || !strings.Contains(err.Error(), "disk reserve exhausted") {
		t.Fatalf("snapshot write below its early-stop reserve error=%v", err)
	}
}

func TestDiskBudgetPrunesOwnBackupsBeforeRefusingWrite(t *testing.T) {
	original := availableDiskBytes
	t.Cleanup(func() { availableDiskBytes = original })
	t.Setenv(diskBudgetEnabledEnv, "true")
	t.Setenv(diskBudgetPerFileBytesEnv, "10485760")
	t.Setenv(diskBudgetMinFreeBytesEnv, "500")
	t.Setenv(diskBudgetCheckIntervalEnv, "30")
	t.Setenv(DiskPriorityEnv, DiskPriorityRealtime)
	path := filepath.Join(t.TempDir(), "events.log")
	file, err := OpenRotatingFile(path, DefaultFilePerm, 1024, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := os.WriteFile(path+".2", []byte("old"), DefaultFilePerm); err != nil {
		t.Fatal(err)
	}
	availableDiskBytes = func(string) (uint64, error) {
		if _, err := os.Stat(path + ".2"); err == nil {
			return 100, nil
		}
		return 1000, nil
	}
	if _, err := file.Write([]byte("event\n")); err != nil {
		t.Fatalf("write did not recover after pruning backup: %v", err)
	}
	if _, err := os.Stat(path + ".2"); !os.IsNotExist(err) {
		t.Fatalf("old backup was not pruned: %v", err)
	}
}

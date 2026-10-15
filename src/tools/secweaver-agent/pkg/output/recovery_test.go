package output

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"secweaver-agent/internal/testutil"
)

// This uses the real rotating/buffered stack: a reserve refusal must not poison
// accepted bytes forever or require a collector/service restart after cleanup.
func TestBufferedOutputRecoversAfterDiskReserveFailure(t *testing.T) {
	t.Setenv(diskBudgetEnabledEnv, "true")
	t.Setenv(diskBudgetPerFileBytesEnv, "1048576")
	t.Setenv(diskBudgetMinFreeBytesEnv, "500")
	t.Setenv(diskBudgetCheckIntervalEnv, "30")
	t.Setenv(DiskPriorityEnv, DiskPriorityRealtime)
	available := uint64(0)
	prior := availableDiskBytes
	availableDiskBytes = func(string) (uint64, error) { return available, nil }
	t.Cleanup(func() { availableDiskBytes = prior })
	path := filepath.Join(t.TempDir(), "events.log")
	file, err := OpenRotatingFile(path, 0600, 1024, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	writer := NewPeriodicFlushWriter(file, 1024, -1)
	defer writer.Close()
	if _, err := writer.Write([]byte("{\"event\":1}\n")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Flush(); err == nil || !strings.Contains(err.Error(), "disk reserve exhausted") {
		t.Fatalf("expected reserve failure, got %v", err)
	}
	available = 10000000
	file.nextCheck = time.Time{}
	deadline := time.Now().Add(2 * time.Second)
	for {
		err = writer.Flush()
		if err == nil || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("freed disk did not recover buffered output: %v", err)
	}
	if _, err := writer.Write([]byte("{\"event\":2}\n")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Sync(); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "{\"event\":1}\n{\"event\":2}\n" {
		t.Fatalf("pending bytes lost or duplicated: %q", body)
	}
}

type reserveWriter struct {
	bytes.Buffer
	blocked bool
	calls   int
}

func (w *reserveWriter) Write(p []byte) (int, error) {
	w.calls++
	if w.blocked {
		return 0, ErrDiskReserve
	}
	return w.Buffer.Write(p)
}

// Virtual time verifies real I/O attempts, not just suppressed log lines. The
// retained buffer stays bounded and refused new bytes never enter the backlog.
func TestBufferedReserveBackoffIsBoundedAndPreservesOrder(t *testing.T) {
	sink := &reserveWriter{blocked: true}
	w := NewPeriodicFlushWriter(sink, 8, -1)
	now := time.Unix(1000, 0)
	w.now = func() time.Time { return now }
	if n, err := w.Write([]byte("first\n")); n != 6 || err != nil {
		t.Fatalf("write=%d,%v", n, err)
	}
	for i := 0; i < 300; i++ {
		if err := w.Flush(); !errors.Is(err, ErrDiskReserve) {
			t.Fatalf("failure lost at second %d: %v", i, err)
		}
		now = now.Add(time.Second)
	}
	if sink.calls != 10 || w.retryDelay != time.Minute {
		t.Fatalf("backoff calls=%d delay=%s", sink.calls, w.retryDelay)
	}
	if n, err := w.Write([]byte("refused\n")); n != 0 || !errors.Is(err, ErrDiskReserve) {
		t.Fatalf("backoff accepted new bytes: %d %v", n, err)
	}
	if len(w.buf) != 6 || cap(w.buf) != 8 {
		t.Fatalf("pending buffer changed: %q cap=%d", w.buf, cap(w.buf))
	}
	sink.blocked, now = false, w.retryAt
	if _, err := w.Write([]byte("second\n")); err != nil {
		t.Fatal(err)
	}
	if err := w.Sync(); err != nil {
		t.Fatal(err)
	}
	if sink.String() != "first\nsecond\n" || w.retryDelay != 0 || w.err != nil {
		t.Fatalf("recovery output=%q delay=%s err=%v", sink.String(), w.retryDelay, w.err)
	}
	// A second outage starts at one second, not the previous episode's cap.
	sink.blocked = true
	_, _ = w.Write([]byte("third\n"))
	if err := w.Flush(); !errors.Is(err, ErrDiskReserve) || w.retryDelay != time.Second {
		t.Fatalf("new episode delay=%s err=%v", w.retryDelay, err)
	}
}

func TestRefusedLargeWriteIsNotSilentlyReplayed(t *testing.T) {
	sink := &reserveWriter{blocked: true}
	w := NewPeriodicFlushWriter(sink, 8, -1)
	now := time.Unix(1000, 0)
	w.now = func() time.Time { return now }
	if n, err := w.Write([]byte("large refused record\n")); n != 0 || !errors.Is(err, ErrDiskReserve) {
		t.Fatalf("large write=%d,%v", n, err)
	}
	now, sink.blocked = w.retryAt, false
	if err := w.Flush(); !errors.Is(err, ErrDiskReserve) {
		t.Fatalf("empty flush falsely proved recovery: %v", err)
	}
	if _, err := w.Write([]byte("new\n")); err != nil {
		t.Fatal(err)
	}
	if err := w.Sync(); err != nil || sink.String() != "new\n" {
		t.Fatalf("output=%q err=%v", sink.String(), err)
	}
}

func TestSmallWriteAfterRefusalMustVerifyRealRecovery(t *testing.T) {
	sink := &reserveWriter{blocked: true}
	w := NewPeriodicFlushWriter(sink, 8, -1)
	now := time.Unix(1000, 0)
	w.now = func() time.Time { return now }
	if _, err := w.Write([]byte("large refused record\n")); !errors.Is(err, ErrDiskReserve) {
		t.Fatal(err)
	}
	now = w.retryAt
	if n, err := w.Write([]byte("small\n")); n != 0 || !errors.Is(err, ErrDiskReserve) || len(w.buf) != 0 {
		t.Fatalf("RAM acceptance falsely reported recovery: n=%d err=%v pending=%q", n, err, w.buf)
	}
	sink.blocked, now = false, w.retryAt
	if n, err := w.Write([]byte("small\n")); n != 6 || err != nil || sink.String() != "small\n" {
		t.Fatalf("actual recovery failed: n=%d err=%v output=%q", n, err, sink.String())
	}
}

type partialErrorWriter struct {
	bytes.Buffer
	err error
}

func (w *partialErrorWriter) Write(p []byte) (int, error) {
	if w.err != nil {
		n, _ := w.Buffer.Write(p[:2])
		return n, w.err
	}
	return w.Buffer.Write(p)
}

func TestAmbiguousPartialIOErrorRemainsSticky(t *testing.T) {
	boom := errors.New("filesystem I/O failure")
	sink := &partialErrorWriter{err: boom}
	w := NewPeriodicFlushWriter(sink, 8, -1)
	_, _ = w.Write([]byte("abcdef"))
	if err := w.Flush(); !errors.Is(err, boom) {
		t.Fatal(err)
	}
	sink.err = nil
	if err := w.Sync(); !errors.Is(err, boom) || sink.String() != "ab" || string(w.buf) != "cdef" {
		t.Fatalf("ambiguous error was retried: data=%q pending=%q err=%v", sink.String(), w.buf, err)
	}
}

func TestBufferedWriterMaintainsLargeWriteAndShortWriteSemantics(t *testing.T) {
	var sink bytes.Buffer
	w := NewPeriodicFlushWriter(&sink, 8, -1)
	for _, value := range []string{"one", "abcdefghijklmnop", "end"} {
		if n, err := w.Write([]byte(value)); n != len(value) || err != nil {
			t.Fatalf("write=%d,%v", n, err)
		}
	}
	if err := w.Flush(); err != nil || sink.String() != "oneabcdefghijklmnopend" {
		t.Fatalf("output=%q err=%v", sink.String(), err)
	}
	bad := NewPeriodicFlushWriter(zeroWriter{}, 8, -1)
	if _, err := bad.Write([]byte("oversized")); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("zero progress did not stop: %v", err)
	}
}

type zeroWriter struct{}

func (zeroWriter) Write([]byte) (int, error) { return 0, nil }

func TestDiskGuardProbeBackoffAndAutomaticRecovery(t *testing.T) {
	t.Setenv(diskBudgetEnabledEnv, "true")
	t.Setenv(diskBudgetPerFileBytesEnv, "1048576")
	t.Setenv(diskBudgetMinFreeBytesEnv, "500")
	t.Setenv(diskBudgetCheckIntervalEnv, "30")
	t.Setenv(DiskPriorityEnv, DiskPriorityRealtime)
	available, probes := uint64(0), 0
	prior := availableDiskBytes
	availableDiskBytes = func(string) (uint64, error) { probes++; return available, nil }
	t.Cleanup(func() { availableDiskBytes = prior })
	f, err := OpenRotatingFile(filepath.Join(t.TempDir(), "events.log"), 0600, 1024, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	// No backups exist; count initial probes separately from rechecks after
	// per-file numeric backup cleanup, which is bounded by maxBackups.
	f.maxBackups = 0
	now := time.Unix(1000, 0)
	f.now = func() time.Time { return now }
	for i := 0; i < 300; i++ {
		if _, err := f.Write([]byte("x")); !errors.Is(err, ErrDiskReserve) {
			t.Fatal(err)
		}
		now = now.Add(time.Second)
	}
	if probes != 10 || f.retryDelay != time.Minute {
		t.Fatalf("probes=%d delay=%s", probes, f.retryDelay)
	}
	available, now = 10000000, f.nextCheck
	if _, err := f.Write([]byte("recovered")); err != nil || f.retryDelay != 0 {
		t.Fatalf("guard recovery err=%v delay=%s", err, f.retryDelay)
	}
}

type asynchronousReserveWriter struct {
	blocked atomic.Bool
	data    testutil.SyncBuffer
}

func (w *asynchronousReserveWriter) Write(p []byte) (int, error) {
	if w.blocked.Load() {
		return 0, ErrDiskReserve
	}
	return w.data.Write(p)
}

// Recovery must not depend on a new event or manual Flush: quiet hosts still
// have accepted evidence owned by the real background flush worker.
func TestBackgroundFlushRecoversWithoutNewEvents(t *testing.T) {
	sink := &asynchronousReserveWriter{}
	sink.blocked.Store(true)
	w := NewPeriodicFlushWriter(sink, 1024, 10*time.Millisecond)
	defer w.Close()
	if _, err := w.Write([]byte("pending\n")); err != nil {
		t.Fatal(err)
	}
	if err := w.Flush(); !errors.Is(err, ErrDiskReserve) {
		t.Fatal(err)
	}
	sink.blocked.Store(false)
	deadline := time.Now().Add(3 * time.Second)
	for sink.data.String() != "pending\n" && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if sink.data.String() != "pending\n" {
		t.Fatalf("background flush did not recover: %q", sink.data.String())
	}
}

type syncFailureWriter struct {
	bytes.Buffer
	err error
}

func (w *syncFailureWriter) Sync() error { return w.err }

func TestDurabilityFailureStillBlocksSuccessfulCheckpoint(t *testing.T) {
	for _, boom := range []error{errors.New("fsync failure"), ErrDiskReserve} {
		sink := &syncFailureWriter{err: boom}
		w := NewPeriodicFlushWriter(sink, 8, -1)
		_, _ = w.Write([]byte("event\n"))
		if err := w.Sync(); !errors.Is(err, boom) {
			t.Fatal(err)
		}
		sink.err = nil
		w.retryAt = time.Time{}
		if err := w.Sync(); !errors.Is(err, boom) || w.retryable {
			t.Fatalf("ambiguous durability failure silently cleared: %v", err)
		}
	}
}

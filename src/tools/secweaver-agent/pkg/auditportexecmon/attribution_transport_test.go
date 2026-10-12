package auditportexecmon

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// A buffered channel owns output bytes, avoiding concurrent inspection of a
// bytes.Buffer while either real reader is still writing.
type snapshotEventWriter struct{ records chan []byte }

func (w *snapshotEventWriter) Write(p []byte) (int, error) {
	w.records <- append([]byte(nil), p...)
	return len(p), nil
}

// Exercise both real input transports across an actual inter-record pause. Only
// process identity is synthetic; admission, buffering, assembly and JSON output
// use production code. No auditctl, kernel attachment or network is involved.
func TestSnapshotTransportsRetainPrimaryAcrossExit(t *testing.T) {
	for _, transport := range []string{"stream", "file"} {
		t.Run(transport, func(t *testing.T) {
			var exited atomic.Bool
			stubAttributionStartTimes(t, func(pid int) uint64 {
				if exited.Load() {
					return 0
				}
				if pid == 900001 {
					return 100
				}
				return 200
			})
			m := newAttributionMonitor(processTreeBackendAudit)
			m.trackDescendants = false
			m.pidListener[910001] = m.listeners[0]
			m.processStartTimes[910001] = 200
			m.processParentPIDs[910001] = 900001
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			out := &snapshotEventWriter{records: make(chan []byte, 8)}
			done := make(chan error, 1)
			var input io.WriteCloser
			if transport == "stream" {
				reader, writer := io.Pipe()
				input = writer
				go func() {
					done <- followAuditStream(ctx, reader, m.execKey, m.connectKey, m.fileKey, m, hostIdentity{}, false, out, time.Hour)
				}()
			} else {
				path := filepath.Join(t.TempDir(), "audit.log")
				writer, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
				if err != nil {
					t.Fatal(err)
				}
				input = writer
				go func() {
					done <- followAuditLog(ctx, path, m.execKey, m.connectKey, m.fileKey, m, hostIdentity{}, true, 0, false, out, time.Hour)
				}()
			}
			defer func() {
				cancel()
				_ = input.Close()
				select {
				case <-done:
				case <-time.After(3 * time.Second):
					t.Error("reader did not stop")
				}
			}()
			line := snapshotPrimary(time.Now(), 71, 910001, 900001)
			if _, err := io.WriteString(input, line+"\n"); err != nil {
				t.Fatal(err)
			}
			// Wait for primary admission, not merely pipe consumption by the prefetcher.
			deadline := time.After(3 * time.Second)
			ticker := time.NewTicker(time.Millisecond)
			defer ticker.Stop()
		waitAdmission:
			for {
				select {
				case <-deadline:
					t.Fatal("primary was never admitted")
				case <-ticker.C:
					m.mu.Lock()
					admitted := m.attributionCounts["snapshot_saved"] > 0
					m.mu.Unlock()
					if admitted {
						break waitAdmission
					}
				}
			}
			exited.Store(true)
			msg := parseFields(line)["msg"]
			tails := `type=EXECVE msg=` + msg + ` argc=1 a0="helper"` + "\n" + `type=PROCTITLE msg=` + msg + ` proctitle=68656c706572` + "\n"
			if _, err := io.WriteString(input, tails); err != nil {
				t.Fatal(err)
			}
			select {
			case raw := <-out.records:
				var event auditEvent
				if err := json.Unmarshal(raw, &event); err != nil {
					t.Fatal(err)
				}
				if event.ListenerProcess != "mysqld" || event.AttributionStatus != "" || event.CommandLine != "helper" {
					t.Fatalf("lost admitted identity: %s", raw)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("accepted event vanished after process exit")
			}
		})
	}
}

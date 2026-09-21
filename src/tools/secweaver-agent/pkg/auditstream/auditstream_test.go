package auditstream

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestFollowFileReadsRecordsAlreadyPresentAfterRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	if err := os.WriteFile(path, []byte("old\n"), 0644); err != nil {
		t.Fatal(err)
	}
	startOffset, err := FileSize(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var mu sync.Mutex
	var lines []string
	done := make(chan error, 1)
	go func() {
		done <- FollowFile(ctx, path, false, startOffset, func(line string) {
			mu.Lock()
			lines = append(lines, line)
			mu.Unlock()
		}, 10*time.Millisecond)
	}()
	time.Sleep(30 * time.Millisecond)
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("during-rotation\n"), 0644); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		found := len(lines) > 0 && lines[len(lines)-1] == "during-rotation\n"
		mu.Unlock()
		if found {
			cancel()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	got := append([]string(nil), lines...)
	mu.Unlock()
	if len(got) != 1 || got[0] != "during-rotation\n" {
		t.Fatalf("rotation lines = %#v", got)
	}
	if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestFollowFileObserverReportsOpenAndFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	observed := make(chan error, 1)
	done := make(chan error, 1)
	go func() {
		done <- FollowFileWithObserver(ctx, path, false, 0, func(string) {}, 10*time.Millisecond, func(err error) {
			observed <- err
		})
	}()
	select {
	case err := <-observed:
		if err != nil {
			t.Fatalf("initial observer status = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("observer did not report successful open")
	}
	cancel()
	if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}

	missing := filepath.Join(t.TempDir(), "missing.log")
	var openErr error
	err := FollowFileWithObserver(context.Background(), missing, false, 0, func(string) {}, time.Millisecond, func(err error) {
		openErr = err
	})
	if err == nil || openErr == nil {
		t.Fatalf("missing file errors = return:%v observer:%v", err, openErr)
	}
}

func TestFollowFileObserverReportsMissingPathAndRecovery(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	observed := make(chan error, 4)
	done := make(chan error, 1)
	go func() {
		done <- FollowFileWithObserver(ctx, path, false, 0, func(string) {}, 10*time.Millisecond, func(err error) {
			observed <- err
		})
	}()
	if err := waitObservedStatus(t, observed); err != nil {
		t.Fatalf("initial status = %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := waitObservedStatus(t, observed); err == nil {
		t.Fatal("missing configured path did not report reader failure")
	}
	if err := os.WriteFile(path, []byte("recovered\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := waitObservedStatus(t, observed); err != nil {
		t.Fatalf("recovery status = %v", err)
	}
	cancel()
	if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func waitObservedStatus(t *testing.T, observed <-chan error) error {
	t.Helper()
	select {
	case err := <-observed:
		return err
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for audit file status")
		return nil
	}
}

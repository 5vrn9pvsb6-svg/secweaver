package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Exercise the real pipe writer: supervisor cancellation must not manufacture
// EOF while a child is still handling its stop request. Explicit reader shutdown
// must still close the pipe, so real disconnections remain observable.
func TestAuditSupervisorShutdownKeepsPipeUntilChildrenExit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	d := &auditDemux{
		key:         auditDemuxKey{Path: path},
		subscribers: map[string]*auditSubscriber{},
		moduleKeys:  map[string]map[string]bool{"test": {"test_key": true}},
		backlogs:    map[string]*auditLineRing{"test": {}},
		routes:      map[string]auditDemuxRoute{},
	}
	r := &auditDemuxRegistry{byModule: map[string]auditDemuxBinding{"test": {demux: d}}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stopReaders := r.startForSupervisor(ctx)
	defer stopReaders()
	reader, cleanup, err := d.subscribe(ctx, "test", map[string]bool{"test_key": true})
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	defer reader.Close()
	cancel()
	const line = "type=SYSCALL msg=audit(1.2:3): key=test_key\n"
	d.broadcast(line)
	result := make(chan error, 1)
	go func() {
		got := make([]byte, len(line))
		_, err := io.ReadFull(reader, got)
		if err == nil && string(got) != line {
			err = io.ErrUnexpectedEOF
		}
		result <- err
	}()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("pipe closed before child shutdown completed: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("audit pipe stopped delivering during child shutdown")
	}
	stopReaders()
	go func() {
		var b [1]byte
		_, err := reader.Read(b[:])
		result <- err
	}()
	select {
	case err := <-result:
		if err != io.EOF {
			t.Fatalf("reader shutdown error = %v, want EOF", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("audit pipe remained open after reader shutdown")
	}
}

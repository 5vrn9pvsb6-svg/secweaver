package hostpersistence

import (
	"bufio"
	"context"

	"errors"

	"io"
	"os"

	"strconv"
	"strings"

	"time"
)

// This file owns standalone and shared audit transports, rotation handling, record accumulation, and cancellation.

func followAuditLog(ctx context.Context, cfg auditRuntimeConfig, tracker *auditTracker) error {
	accs := map[string]*auditAccumulator{}
	flushTicker := time.NewTicker(auditFlushInterval)
	defer flushTicker.Stop()
	pollTicker := time.NewTicker(auditPollInterval)
	defer pollTicker.Stop()

	var file *os.File
	var reader *bufio.Reader
	openLog := func(afterRotation bool) error {
		f, err := os.Open(cfg.AuditLog)
		if err != nil {
			return err
		}
		if afterRotation {
			// A replacement audit.log is a new file and must be consumed from byte
			// zero; seeking to its end would lose records written during rotation.
			_, _ = f.Seek(0, io.SeekStart)
		} else if !cfg.FromStart {
			_, _ = f.Seek(0, io.SeekEnd)
		}
		if file != nil {
			_ = file.Close()
		}
		file = f
		reader = bufio.NewReader(f)
		return nil
	}
	if err := openLog(false); err != nil {
		return err
	}
	defer func() {
		if file != nil {
			_ = file.Close()
		}
	}()
	nextFlush := time.Now().Add(auditFlushInterval)
	flushPending := func(now time.Time) {
		// Flush on elapsed wall time as well as EOF. A continuously busy audit log
		// may never reach EOF, but completed multi-record events still need to be
		// made visible to the persistence scanner promptly.
		flushAuditAccumulators(accs, tracker, 0)
		pruneAuditAccumulators(accs, 10*time.Second)
		nextFlush = now.Add(auditFlushInterval)
	}

	for {
		line, err := reader.ReadString('\n')
		if len(line) > 0 {
			consumeAuditLine(accs, line, cfg.Key)
			if now := time.Now(); !now.Before(nextFlush) {
				flushPending(now)
			}
		}
		if err == nil {
			continue
		}
		if !errors.Is(err, io.EOF) {
			return err
		}
		if !auditLogSameFile(cfg.AuditLog, file) {
			for {
				if err := openLog(true); err == nil {
					break
				}
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-pollTicker.C:
				}
			}
			continue
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-flushTicker.C:
			flushPending(time.Now())
		case <-pollTicker.C:
		}
	}
}

func followAuditStream(ctx context.Context, r io.Reader, cfg auditRuntimeConfig, tracker *auditTracker) error {
	accs := map[string]*auditAccumulator{}
	flushTicker := time.NewTicker(auditFlushInterval)
	defer flushTicker.Stop()

	// Decouple potentially blocking pipe reads from accumulator expiry. The
	// bounded channel supplies backpressure instead of unbounded buffering.
	lines := make(chan string, 1024)
	errCh := make(chan error, 1)
	go readAuditStreamLines(ctx, r, lines, errCh)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case line, ok := <-lines:
			if !ok {
				select {
				case err := <-errCh:
					return err
				default:
					return nil
				}
			}
			consumeAuditLine(accs, line, cfg.Key)
		case <-flushTicker.C:
			flushAuditAccumulators(accs, tracker, 0)
			pruneAuditAccumulators(accs, 10*time.Second)
		}
	}
}

func readAuditStreamLines(ctx context.Context, r io.Reader, lines chan<- string, errCh chan<- error) {
	defer close(lines)
	reader := bufio.NewReader(r)
	for {
		line, err := reader.ReadString('\n')
		if len(line) > 0 {
			select {
			case lines <- line:
			case <-ctx.Done():
				return
			}
		}
		if err != nil {
			select {
			case errCh <- err:
			case <-ctx.Done():
			}
			return
		}
	}
}

func auditLogSameFile(path string, f *os.File) bool {
	pst, err1 := os.Stat(path)
	fst, err2 := f.Stat()
	if err1 != nil || err2 != nil {
		return true
	}
	return os.SameFile(pst, fst)
}

func consumeAuditLine(accs map[string]*auditAccumulator, line, key string) {
	line = strings.TrimSpace(line)
	if line == "" || !strings.Contains(line, "msg=audit(") {
		return
	}
	id := extractAuditMsgID(line)
	if id == "" {
		return
	}
	fields := parseAuditFields(line)
	recordType := fields["type"]
	acc := accs[id]
	if acc == nil {
		// The shared demux guarantees that the keyed SYSCALL record precedes its
		// unkeyed PATH/EXECVE companions. Refusing an unkeyed first record avoids
		// accidentally joining another module's event with the same parser state.
		_, hasKey := fields["key"]
		if !hasKey {
			return
		}
		acc = &auditAccumulator{
			id:        id,
			firstSeen: time.Now(),
			fields:    map[string]string{},
			argv:      map[int]string{},
			paths:     map[int]string{},
		}
		accs[id] = acc
	}
	acc.lastRecordAt = time.Now()
	for k, v := range fields {
		if _, exists := acc.fields[k]; !exists || k == "key" {
			acc.fields[k] = v
		}
	}
	if acc.fields["key"] != "" && acc.fields["key"] != key {
		delete(accs, id)
		return
	}
	if recordType == "PATH" {
		if name := fields["name"]; name != "" {
			item, _ := strconv.Atoi(fields["item"])
			acc.paths[item] = name
		}
	}
	if recordType == "EXECVE" {
		for k, v := range fields {
			if len(k) >= 2 && k[0] == 'a' {
				if idx, err := strconv.Atoi(k[1:]); err == nil {
					acc.argv[idx] = v
				}
			}
		}
	}
	if recordType == "PROCTITLE" {
		acc.proctitle = fields["proctitle"]
	}
}

func flushAuditAccumulators(accs map[string]*auditAccumulator, tracker *auditTracker, maxAge time.Duration) {
	now := time.Now()
	for id, acc := range accs {
		if maxAge > 0 && now.Sub(acc.firstSeen) < maxAge {
			continue
		}
		if now.Sub(acc.lastRecordAt) < auditFlushInterval {
			// auditd emits one logical event over several adjacent lines. A quiet
			// interval is the completion signal because there is no explicit trailer.
			continue
		}
		if acc.fields["key"] == "" || len(acc.paths) == 0 {
			if now.Sub(acc.firstSeen) > 5*time.Second {
				delete(accs, id)
			}
			continue
		}
		change := auditChangeFromAccumulator(acc)
		tracker.Add(change)
		delete(accs, id)
	}
}

func pruneAuditAccumulators(accs map[string]*auditAccumulator, maxAge time.Duration) {
	if maxAge <= 0 {
		return
	}
	now := time.Now()
	for id, acc := range accs {
		if now.Sub(acc.firstSeen) > maxAge {
			delete(accs, id)
		}
	}
}

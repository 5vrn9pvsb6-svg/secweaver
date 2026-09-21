package auditportexecmon

import (
	"bufio"
	"context"

	"errors"

	"io"

	"os"

	"strings"

	"time"
)

// This file owns audit log and shared-stream transport, including rotation-safe reopening and cancellation.

func followAuditLog(ctx context.Context, path, execKey, connectKey, fileKey string, monitor *processTreeMonitor, host hostIdentity, fromStart bool, startOffset int64, printRaw bool, out io.Writer, listenerRescanInterval time.Duration) error {
	accs := map[string]*auditAccumulator{}
	flushTicker := time.NewTicker(auditLogFlushInterval)
	defer flushTicker.Stop()
	nextFlush := time.Now().Add(auditLogFlushInterval)
	if listenerRescanInterval <= 0 {
		listenerRescanInterval = defaultListenerRescanInterval
	}
	rescanTicker := time.NewTicker(listenerRescanInterval)
	defer rescanTicker.Stop()
	pollTicker := time.NewTicker(auditLogReadPoll)
	defer pollTicker.Stop()

	var file *os.File
	var reader *bufio.Reader

	openLog := func(afterRotation bool) error {
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		if afterRotation {
			// The replacement may already contain events when rotation is noticed.
			// Starting at zero preserves those records; only the initial open uses
			// the captured startup offset to skip historical data.
			if _, err := f.Seek(0, io.SeekStart); err != nil {
				_ = f.Close()
				return err
			}
		} else if !fromStart {
			// 首次打开：从启动时记录的 offset 读（跳过历史）。
			if startOffset < 0 {
				if _, err := f.Seek(0, io.SeekEnd); err != nil {
					_ = f.Close()
					return err
				}
			} else if _, err := f.Seek(startOffset, io.SeekStart); err != nil {
				_ = f.Close()
				return err
			}
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

	flushPending := func(now time.Time) {
		emitReady(accs, execKey, connectKey, fileKey, monitor, host, printRaw, out, 0)
		pruneOld(accs, 10*time.Second)
		nextFlush = now.Add(auditLogFlushInterval)
	}
	maybeFlushPending := func() {
		now := time.Now()
		if now.Before(nextFlush) {
			return
		}
		flushPending(now)
	}

	processLine := func(line string) {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(line, "msg=audit(") {
			return
		}
		if shouldSkipBoundedAuditAuxiliary(accs, line, monitor) {
			return
		}
		fields := parseFields(line)
		monitor.observeAuditFields(fields)
		if monitor.shouldDropBoundedAuditPrimary(fields) {
			return
		}
		// Clone records drive process-tree expansion but are not user-facing exec
		// events. Skipping their accumulator avoids allocation on a high-rate path.
		if fields["key"] == monitor.cloneKey {
			return
		}
		id, _ := consumeAuditLineParsed(accs, line, fields, printRaw)
		if id != "" {
			emitOneReady(accs, id, execKey, connectKey, fileKey, monitor, host, printRaw, out)
		}
		maybeFlushPending()
	}

	for {
		line, err := reader.ReadString('\n')
		if len(line) > 0 {
			processLine(line)
		}
		if err == nil {
			continue
		}
		if !errors.Is(err, io.EOF) {
			return err
		}
		if !auditLogSameFile(path, file) {
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
		case <-rescanTicker.C:
			monitor.requestRescan()
		case <-pollTicker.C:
		}
	}
}

// followAuditStream consumes the inherited, already-routed audit pipe. A reader
// goroutine isolates blocking pipe reads from flush and rescan timers; any EOF or
// read error is returned so the supervisor restarts the module and reconnects it
// to the demux backlog.
func followAuditStream(ctx context.Context, r io.Reader, execKey, connectKey, fileKey string, monitor *processTreeMonitor, host hostIdentity, printRaw bool, out io.Writer, listenerRescanInterval time.Duration) error {
	accs := map[string]*auditAccumulator{}
	flushTicker := time.NewTicker(auditLogFlushInterval)
	defer flushTicker.Stop()
	nextFlush := time.Now().Add(auditLogFlushInterval)
	if listenerRescanInterval <= 0 {
		listenerRescanInterval = defaultListenerRescanInterval
	}
	rescanTicker := time.NewTicker(listenerRescanInterval)
	defer rescanTicker.Stop()

	lines := make(chan string, 1024)
	errCh := make(chan error, 1)
	go readAuditStreamLines(ctx, r, lines, errCh)

	flushPending := func(now time.Time) {
		emitReady(accs, execKey, connectKey, fileKey, monitor, host, printRaw, out, 0)
		pruneOld(accs, 10*time.Second)
		nextFlush = now.Add(auditLogFlushInterval)
	}
	maybeFlushPending := func() {
		now := time.Now()
		if now.Before(nextFlush) {
			return
		}
		flushPending(now)
	}
	processLine := func(line string) {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(line, "msg=audit(") {
			return
		}
		if shouldSkipBoundedAuditAuxiliary(accs, line, monitor) {
			return
		}
		fields := parseFields(line)
		monitor.observeAuditFields(fields)
		if monitor.shouldDropBoundedAuditPrimary(fields) {
			return
		}
		if fields["key"] == monitor.cloneKey {
			return
		}
		id, _ := consumeAuditLineParsed(accs, line, fields, printRaw)
		if id != "" {
			emitOneReady(accs, id, execKey, connectKey, fileKey, monitor, host, printRaw, out)
		}
		maybeFlushPending()
	}

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
			processLine(line)
		case <-flushTicker.C:
			flushPending(time.Now())
		case <-rescanTicker.C:
			monitor.requestRescan()
		}
	}
}

// shouldSkipBoundedAuditAuxiliary avoids full field parsing for EXECVE, PATH,
// CWD, and PROCTITLE records whose host-wide SYSCALL was already rejected. An
// accepted primary owns an accumulator by audit ID, so its auxiliaries remain
// available for normal command and path assembly.
func shouldSkipBoundedAuditAuxiliary(accs map[string]*auditAccumulator, line string, monitor *processTreeMonitor) bool {
	if !monitor.usesBoundedAudit() || strings.Contains(line, " key=") {
		return false
	}
	id := extractMsgID(line)
	if id == "" {
		return true
	}
	return accs[id] == nil
}

// readAuditStreamLines owns the buffered reader and closes lines exactly once.
// Both data and terminal errors are context-aware so shutdown cannot deadlock on
// a full consumer channel or an unread error channel.
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

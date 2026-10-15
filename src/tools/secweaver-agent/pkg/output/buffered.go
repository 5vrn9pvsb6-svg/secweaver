package output

import (
	"errors"
	"io"
	"sync"
	"time"

	"secweaver-agent/internal/errlog"
)

// PeriodicFlushWriter retains at most bufferSize accepted bytes. Unlike
// bufio.Writer's permanent error latch, a reserve refusal can be retried without
// discarding pending evidence. mu owns the buffer, retry state and destination.
type PeriodicFlushWriter struct {
	mu         sync.Mutex
	buf        []byte
	bufferSize int
	dest       io.Writer
	stop, done chan struct{}
	once       sync.Once
	err        error
	retryable  bool
	retryAt    time.Time
	retryDelay time.Duration
	now        func() time.Time
	reporter   *errlog.Reporter
}

// NewPeriodicFlushWriter creates a bounded buffer with optional background
// flushing. Rejected writes are not an unbounded in-memory spool or durable log.
func NewPeriodicFlushWriter(w io.Writer, bufferSize int, interval time.Duration) *PeriodicFlushWriter {
	if bufferSize <= 0 {
		bufferSize = DefaultBufferSize
	}
	operation := "buffered output"
	if f, ok := w.(*RotatingFile); ok {
		operation += " " + f.path
	}
	p := &PeriodicFlushWriter{buf: make([]byte, 0, bufferSize), bufferSize: bufferSize, dest: w, now: time.Now, reporter: errlog.New(operation)}
	if interval > 0 {
		p.stop, p.done = make(chan struct{}), make(chan struct{})
		go p.flushLoop(interval)
	}
	return p
}

// retryErrorLocked refuses new work during backoff. Unknown/partial filesystem
// failures remain sticky; only a guard refusal with known zero I/O is retryable.
func (w *PeriodicFlushWriter) retryErrorLocked() error {
	if w.err != nil && (!w.retryable || w.now().Before(w.retryAt)) {
		return w.err
	}
	return nil
}

// failedLocked preserves permanent I/O failures while scheduling retry-safe
// reserve refusals. The caller holds mu and has retained any pending suffix.
func (w *PeriodicFlushWriter) failedLocked(err error, retryable bool) error {
	w.err, w.retryable = err, retryable
	if retryable {
		w.retryDelay = diskRetryDelay(w.retryDelay)
		w.retryAt = w.now().Add(w.retryDelay)
	}
	w.reporter.Observe(err)
	return err
}

// recoveredLocked is called only after a real destination write succeeds.
func (w *PeriodicFlushWriter) recoveredLocked() {
	w.err, w.retryDelay, w.retryAt = nil, 0, time.Time{}
	w.retryable = false
	w.reporter.Observe(nil)
}

// flushLocked preserves the unwritten suffix even on partial I/O. A cached
// refusal with no pending data is not a successful probe or recovery signal.
func (w *PeriodicFlushWriter) flushLocked() error {
	if err := w.retryErrorLocked(); err != nil {
		return err
	}
	if len(w.buf) == 0 {
		return w.err
	}
	n, err := w.dest.Write(w.buf)
	if n < 0 || n > len(w.buf) {
		return w.failedLocked(io.ErrShortWrite, false)
	}
	if n > 0 {
		copy(w.buf, w.buf[n:])
		w.buf = w.buf[:len(w.buf)-n]
	}
	if err == nil && len(w.buf) > 0 {
		err = io.ErrShortWrite
	}
	if err != nil {
		return w.failedLocked(err, n == 0 && errors.Is(err, ErrDiskReserve))
	}
	w.recoveredLocked()
	return nil
}

// Write matches buffered io.Writer accounting: n includes bytes accepted into
// the bounded buffer, not just durable bytes. Large writes bypass the buffer;
// a refused large record remains the caller's responsibility and is not replayed.
func (w *PeriodicFlushWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.retryErrorLocked(); err != nil {
		return 0, err
	}
	accepted := 0
	for len(p) > 0 {
		if len(w.buf) == w.bufferSize || (w.err != nil && len(w.buf) > 0) {
			if err := w.flushLocked(); err != nil {
				return accepted, err
			}
		}
		// When a refused direct write left no pending bytes, probe with the
		// next real record even if small. RAM acceptance alone must not turn
		// a continuing disk refusal into a caller-visible success/recovery.
		if len(w.buf) == 0 && (len(p) > w.bufferSize || w.err != nil) {
			n, err := w.dest.Write(p)
			if n < 0 || n > len(p) {
				return accepted, w.failedLocked(io.ErrShortWrite, false)
			}
			accepted += n
			p = p[n:]
			if err == nil && n == 0 {
				err = io.ErrShortWrite
			}
			if err != nil {
				return accepted, w.failedLocked(err, n == 0 && errors.Is(err, ErrDiskReserve))
			}
			w.recoveredLocked()
			continue
		}
		n := min(len(p), w.bufferSize-len(w.buf))
		w.buf = append(w.buf, p[:n]...)
		p, accepted = p[n:], accepted+n
	}
	return accepted, nil
}

// Flush writes accepted bytes or returns the current failure during backoff.
func (w *PeriodicFlushWriter) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.flushLocked()
}

// Sync preserves the checkpoint contract: successful buffered acceptance or a
// retry delay is never reported as durable evidence or cursor advancement.
func (w *PeriodicFlushWriter) Sync() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.flushLocked(); err != nil {
		return err
	}
	if syncer, ok := w.dest.(interface{ Sync() error }); ok {
		if err := syncer.Sync(); err != nil {
			return w.failedLocked(err, false)
		}
	}
	return nil
}

// Close joins the flush worker before its final attempt. It does not override
// reserve protection or claim that pending bytes survived a failed shutdown.
func (w *PeriodicFlushWriter) Close() error {
	if w.stop != nil {
		w.once.Do(func() {
			close(w.stop)
			<-w.done
		})
	}
	return w.Flush()
}

func (w *PeriodicFlushWriter) flushLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	defer close(w.done)
	for {
		select {
		case <-ticker.C:
			_ = w.Flush() // failedLocked reports; callers still receive the error.
		case <-w.stop:
			return
		}
	}
}

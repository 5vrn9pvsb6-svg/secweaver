// Package errlog bounds recurring operational diagnostics independently of the
// evidence sink: a full evidence disk must not flood stderr/journald in turn.
package errlog

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// Reporter owns one operation's consecutive failure episode, not an unbounded
// map of error messages. Observe is safe across a writer's caller and flush loop.
type Reporter struct {
	mu         sync.Mutex
	operation  string
	out        io.Writer
	now        func() time.Time
	failed     bool
	started    time.Time
	nextLog    time.Time
	suppressed uint64
}

// New reports the first failure immediately, subsequent failures at most once
// per minute, and one recovery after the caller has verified success.
func New(operation string) *Reporter {
	return &Reporter{operation: operation, out: os.Stderr, now: time.Now}
}

// Observe never turns logging failure into evidence success. Callers must pass
// nil only after the failed operation actually succeeds, not while skipping it.
func (r *Reporter) Observe(err error) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	if err == nil {
		if r.failed {
			fmt.Fprintf(r.out, "%s recovered: duration=%s suppressed=%d\n", r.operation, now.Sub(r.started).Round(time.Second), r.suppressed)
		}
		r.failed, r.suppressed = false, 0
		return
	}
	if !r.failed {
		r.failed, r.started = true, now
	} else if now.Before(r.nextLog) {
		r.suppressed++
		return
	}
	fmt.Fprintf(r.out, "%s failed: %v (suppressed=%d)\n", r.operation, err, r.suppressed)
	r.nextLog, r.suppressed = now.Add(time.Minute), 0
}

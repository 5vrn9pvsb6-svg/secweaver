package errlog

import (
	"bytes"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestReporterBoundsRepeatedFailuresAndReportsRecovery(t *testing.T) {
	var out bytes.Buffer
	now := time.Unix(1000, 0)
	r := New("learning checkpoint")
	r.out, r.now = &out, func() time.Time { return now }
	for i := 0; i < 620; i++ {
		r.Observe(errors.New("disk reserve exhausted"))
		now = now.Add(500 * time.Millisecond)
	}
	if got := strings.Count(out.String(), "failed:"); got != 6 {
		t.Fatalf("620 failures produced %d diagnostics, want 6: %s", got, out.String())
	}
	r.Observe(nil)
	r.Observe(nil)
	if strings.Count(out.String(), "recovered:") != 1 || !strings.Contains(out.String(), "suppressed=19") {
		t.Fatalf("missing single recovery/count: %s", out.String())
	}
	r.Observe(errors.New("second episode"))
	if !strings.Contains(out.String(), "second episode") {
		t.Fatal("new failure episode was not reported immediately")
	}
}

// Caller and flush-loop failures can race; the reporter must still issue only
// one first diagnostic and retain an exact suppressed count without a map.
func TestReporterConcurrentFailures(t *testing.T) {
	var out bytes.Buffer
	r := New("output")
	r.out, r.now = &out, func() time.Time { return time.Unix(1000, 0) }
	var group sync.WaitGroup
	for i := 0; i < 100; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			r.Observe(errors.New("full"))
		}()
	}
	group.Wait()
	r.Observe(nil)
	if strings.Count(out.String(), "failed:") != 1 || !strings.Contains(out.String(), "suppressed=99") {
		t.Fatal(out.String())
	}
}

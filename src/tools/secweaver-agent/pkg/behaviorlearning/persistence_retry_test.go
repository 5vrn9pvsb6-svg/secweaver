package behaviorlearning

import (
	"errors"
	"testing"
	"time"
)

// Exercise actual Tick/Store/callback paths without sleeping. Persistence
// recovery must not silently promote a baseline across a known evidence gap.
func TestTickBacksOffPersistenceAndDoesNotRestoreBaselineTrust(t *testing.T) {
	f := newFixture(t)
	promote(t, f)
	f.now = f.now.Add(5 * time.Minute)
	attempts, blocked := 0, true
	original := f.e.summary
	f.e.summary = func(s Summary) error {
		attempts++
		if blocked {
			return errors.New("disk reserve exhausted")
		}
		return original(s)
	}
	before := f.e.state.OnlineSeconds
	for i := 0; i < 300; i++ {
		if err := f.e.Tick(); err == nil {
			t.Fatalf("failure hidden at tick %d", i)
		}
		f.now = f.now.Add(time.Second)
	}
	f.e.seen["expired"] = f.now.Add(-2 * time.Minute)
	f.e.evidence["expired"] = evidence{at: f.now.Add(-25 * time.Hour)}
	f.e.evidenceBytes += len("expired") + 512
	err := f.e.Tick()
	_, seen := f.e.seen["expired"]
	_, cached := f.e.evidence["expired"]
	if err == nil || seen || cached || f.e.evidenceBytes < 0 {
		t.Fatal("backoff skipped context reclamation or hid the failure")
	}
	if attempts != 10 || f.e.persistenceWait != time.Minute {
		t.Fatalf("attempts=%d delay=%s", attempts, f.e.persistenceWait)
	}
	if f.e.state.OnlineSeconds-before < 299 {
		t.Fatal("backoff stopped online accounting")
	}
	blocked, f.now = false, f.e.persistenceAt
	if err := f.e.Tick(); err != nil {
		t.Fatal(err)
	}
	if f.e.persistenceErr != nil || f.e.persistenceWait != 0 || f.e.state.Mode != "degraded" {
		t.Fatalf("bad recovery: err=%v delay=%s mode=%s", f.e.persistenceErr, f.e.persistenceWait, f.e.state.Mode)
	}
	if err := f.e.Process(observation(100)); err != nil || len(f.raw) != 1 {
		t.Fatalf("degraded baseline suppressed new evidence: err=%v raw=%d", err, len(f.raw))
	}
}

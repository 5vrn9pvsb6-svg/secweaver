package eventwhitelist

import (
	"encoding/json"
	"secweaver-agent/pkg/eventwhitelist/core"
	"sort"
	"time"
)

// LegacyPortsDigest binds explicit migration consent to one device's exact
// sorted port set. The on-disk legacy setting is retained for binary rollback.
func LegacyPortsDigest(ports []int) string {
	copy := append([]int{}, ports...)
	sort.Ints(copy)
	raw, _ := json.Marshal(copy)
	return core.Digest(raw)
}
func LegacyPortsMigrated(ports map[int]bool) bool {
	r := active.Load()
	if r == nil {
		return false
	}
	s := r.current.Load()
	if s == nil || !s.policy.Enabled || s.policy.Mode != "enforce" {
		return false
	}
	now := time.Now()
	end, _ := time.Parse(time.RFC3339, s.envelope.ExpiresAt)
	from, _ := time.Parse(time.RFC3339, s.policy.ValidFrom)
	if !now.Before(end) || !from.IsZero() && now.Before(from) {
		return false
	}
	values := []int{}
	for p, on := range ports {
		if on {
			values = append(values, p)
		}
	}
	return s.policy.LegacyPortMigrations[r.device] == LegacyPortsDigest(values)
}

// ListenerRevision identifies the exact generation whose root reconciliation
// is being acknowledged, preventing a concurrent publication's premature ack.
func ListenerRevision() int64 {
	if r := active.Load(); r != nil {
		if s := r.current.Load(); s != nil {
			return s.policy.Revision
		}
	}
	return 0
}
func ListenerApplied(revision int64, complete bool) {
	r := active.Load()
	if r == nil {
		return
	}
	s := r.current.Load()
	if s == nil || s.policy.Revision != revision {
		return
	}
	state := "pending_listener"
	if complete {
		state = "applied"
	}
	r.mu.Lock()
	if r.status.Revision == revision {
		r.status.State = state
	}
	r.mu.Unlock()
}

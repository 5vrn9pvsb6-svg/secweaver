package hostpersistence

import (
	"path/filepath"

	"time"
)

// This file owns the synchronized and bounded path-to-actor correlation cache shared by the scanner and audit reader.

func newAuditTracker(retention time.Duration, maxPerPath int) *auditTracker {
	if retention <= 0 {
		retention = auditRetention
	}
	if maxPerPath <= 0 {
		maxPerPath = 20
	}
	return &auditTracker{
		byPath:     map[string][]auditChange{},
		retention:  retention,
		maxPerPath: maxPerPath,
		// Cap both dimensions of the cache: noisy paths cannot retain unlimited
		// events, and an attacker cannot grow memory through arbitrary path names.
		maxPaths: 4096,
		fatalErr: make(chan error, 1),
	}
}

func (t *auditTracker) Add(change auditChange) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-t.retention)
	if t.lastPrune.IsZero() || now.Sub(t.lastPrune) >= time.Minute {
		// Amortize the full-map prune; per-path filtering below still enforces
		// retention for every path touched by the current event.
		t.pruneLocked(cutoff)
		t.lastPrune = now
	}
	for _, path := range change.Paths {
		path = filepath.Clean(path)
		if _, exists := t.byPath[path]; !exists && t.maxPaths > 0 && len(t.byPath) >= t.maxPaths {
			// Prefer bounded memory over preserving the least recently active path.
			t.evictOldestPathLocked()
		}
		items := append(t.byPath[path], change)
		filtered := items[:0]
		for _, item := range items {
			if item.Timestamp.After(cutoff) {
				filtered = append(filtered, item)
			}
		}
		if len(filtered) > t.maxPerPath {
			filtered = filtered[len(filtered)-t.maxPerPath:]
		}
		t.byPath[path] = filtered
	}
}

func (t *auditTracker) pruneLocked(cutoff time.Time) {
	for path, items := range t.byPath {
		kept := items[:0]
		for _, item := range items {
			if item.Timestamp.After(cutoff) {
				kept = append(kept, item)
			}
		}
		if len(kept) == 0 {
			delete(t.byPath, path)
			continue
		}
		t.byPath[path] = kept
	}
}

func (t *auditTracker) evictOldestPathLocked() {
	oldestPath := ""
	var oldest time.Time
	for path, items := range t.byPath {
		if len(items) == 0 {
			delete(t.byPath, path)
			return
		}
		candidate := items[len(items)-1].Timestamp
		if oldestPath == "" || candidate.Before(oldest) {
			oldestPath = path
			oldest = candidate
		}
	}
	if oldestPath != "" {
		delete(t.byPath, oldestPath)
	}
}

func (t *auditTracker) reportFatal(err error) {
	if t == nil || err == nil {
		return
	}
	select {
	case t.fatalErr <- err:
	default:
		// The first failure is sufficient to trigger restart. Never block the
		// failed reader while the supervisor is already handling another error.
	}
}

func (t *auditTracker) Errors() <-chan error {
	if t == nil {
		// A nil channel intentionally disables this select case when enrichment
		// is not configured.
		return nil
	}
	return t.fatalErr
}

func (t *auditTracker) RefreshWatches() {
	// The closure itself rate-limits kernel reconciliation to once per minute.
	// Calling this from every persistence scan is therefore inexpensive.
	if t != nil && t.refreshWatches != nil {
		t.refreshWatches()
	}
}

func (t *auditTracker) Find(path, eventTimestamp string) (auditChange, bool) {
	if t == nil {
		return auditChange{}, false
	}
	ts, _ := time.Parse(time.RFC3339, eventTimestamp)
	path = filepath.Clean(path)
	t.mu.Lock()
	defer t.mu.Unlock()
	items := t.byPath[path]
	if len(items) == 0 {
		return auditChange{}, false
	}
	bestIdx := -1
	bestDistance := time.Duration(1<<63 - 1)
	// Polling observes the resulting filesystem state after auditd records the
	// write, so timestamps will not be identical. Choose the nearest candidate,
	// but never cross the retention boundary into stale actor evidence.
	for i, item := range items {
		distance := time.Since(item.Timestamp)
		if !ts.IsZero() {
			distance = ts.Sub(item.Timestamp)
			if distance < 0 {
				distance = -distance
			}
		}
		if distance < bestDistance {
			bestDistance = distance
			bestIdx = i
		}
	}
	if bestIdx < 0 || bestDistance > t.retention {
		return auditChange{}, false
	}
	return items[bestIdx], true
}

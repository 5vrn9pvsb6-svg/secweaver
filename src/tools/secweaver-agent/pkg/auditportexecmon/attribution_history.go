package auditportexecmon

import (
	"container/list"
	"time"

	"secweaver-agent/pkg/processtracker"
)

const (
	attributionHistoryTTL = 30 * time.Second
	maxRootHistory        = 4096
	maxProcessHistory     = 16384
)

var readAttributionMonotonicNS = attributionMonotonicNS

// A monitor is scoped to one collector lifetime/host boot. No history is persisted
// or shared across restarts, so these identities cannot acquire another boot's PID.
type rootIdentity struct {
	pid   int
	start uint64
}
type rootHistoryEntry struct {
	closed            bool // observed root exit or removal from listener inventory
	key               rootIdentity
	listener          listenerInfo
	fromNS, retiredNS uint64
	retiredAt         time.Time
}
type processHistoryEntry struct {
	pid, parent   int
	start         uint64
	listener      listenerInfo
	from, through time.Time
}
type attributionHistory struct {
	roots        map[rootIdentity]*list.Element
	rootOrder    list.List
	processes    map[int]*list.Element
	processOrder list.List
}

// History methods require mu, except during unpublished constructor setup.
// LRU admission is O(1); hard caps bound memory even under PID churn. Lookup
// never renews evidence or installs rules. Eviction reduces coverage, never trust.
func (m *processTreeMonitor) rememberRootHistoryLocked(listener listenerInfo) {
	if listener.Historical || listener.PID <= 1 || listener.RootStartTime == 0 || listener.RootStartTime == unknownProcessStartTime || listener.AttributionUnknown || listener.Process == "" {
		return
	}
	h := &m.attributionHistory
	if h.roots == nil {
		h.roots = make(map[rootIdentity]*list.Element)
	}
	key := rootIdentity{listener.PID, listener.RootStartTime}
	if elem := h.roots[key]; elem != nil {
		entry := elem.Value.(*rootHistoryEntry)
		if entry.closed {
			return
		}
		// A fresh positive read of the SAME generation may resume verification.
		// A replacement generation has another key and cannot inherit this name.
		entry.retiredAt, entry.retiredNS = time.Time{}, 0
		h.rootOrder.MoveToBack(elem)
		return
	}
	if len(h.roots) >= maxRootHistory {
		elem := h.rootOrder.Front()
		delete(h.roots, elem.Value.(*rootHistoryEntry).key)
		h.rootOrder.Remove(elem)
		m.recordAttributionLocked("history_evicted")
	}
	h.roots[key] = h.rootOrder.PushBack(&rootHistoryEntry{key: key, listener: listener, fromNS: readAttributionMonotonicNS()})
}

// Explicit retirement cannot be undone by a readable zombie /proc entry. Only
// fresh listener discovery may start another collection interval for that root.
func (m *processTreeMonitor) closeRootHistoryLocked(listener listenerInfo, atNS uint64) {
	m.retireRootHistoryLocked(listener, atNS)
	if elem := m.attributionHistory.roots[rootIdentity{listener.PID, listener.RootStartTime}]; elem != nil {
		elem.Value.(*rootHistoryEntry).closed = true
	}
	// Exit runs concurrently with discovery/bootstrap. Change the membership
	// index, not the indexed listener slice; expiry must not resurrect a zombie.
	delete(m.activeListenerRoots, rootIdentity{listener.PID, listener.RootStartTime})
}

// BPF can prove a buffered root token without any active listener. Active-state
// mutation additionally needs a root still known to current tracking/discovery.
func (m *processTreeMonitor) knownEBPFRootLocked(listener listenerInfo) bool {
	if m.activeListenerRoots != nil {
		return m.activeListenerRoots[rootIdentity{listener.PID, listener.RootStartTime}]
	}
	if elem := m.attributionHistory.roots[rootIdentity{listener.PID, listener.RootStartTime}]; elem != nil {
		return !elem.Value.(*rootHistoryEntry).closed
	}
	for _, candidate := range m.listeners {
		if candidate.PID == listener.PID && candidate.RootStartTime == listener.RootStartTime {
			return true
		}
	}
	return false
}

func (m *processTreeMonitor) rootHistoryClosedLocked(listener listenerInfo) bool {
	if elem := m.attributionHistory.roots[rootIdentity{listener.PID, listener.RootStartTime}]; elem != nil {
		return elem.Value.(*rootHistoryEntry).closed
	}
	return false
}

// Discovery is the authority for a process that stops listening and later
// listens again. Discard the old interval rather than bridge an unmonitored gap.
func (m *processTreeMonitor) reopenDiscoveredRootLocked(listener listenerInfo) {
	key := rootIdentity{listener.PID, listener.RootStartTime}
	if m.activeListenerRoots != nil {
		m.activeListenerRoots[key] = true
	}
	if elem := m.attributionHistory.roots[key]; elem != nil && elem.Value.(*rootHistoryEntry).closed {
		delete(m.attributionHistory.roots, key)
		m.attributionHistory.rootOrder.Remove(elem)
	}
	m.rememberRootHistoryLocked(listener)
}

// Retirement is a first-observed upper bound, tightened by a captured root exit
// when available. Repeated failed reads cannot extend it. Rule removal leaves
// this bounded record available to queued exec events.
func (m *processTreeMonitor) retireRootHistoryLocked(listener listenerInfo, atNS uint64) {
	elem := m.attributionHistory.roots[rootIdentity{listener.PID, listener.RootStartTime}]
	if elem == nil {
		return
	}
	entry := elem.Value.(*rootHistoryEntry)
	if atNS == 0 {
		atNS = readAttributionMonotonicNS()
	}
	if entry.retiredAt.IsZero() {
		entry.retiredAt, entry.retiredNS = time.Now(), atNS
	} else if atNS != 0 && (entry.retiredNS == 0 || atNS < entry.retiredNS) {
		entry.retiredNS = atNS
	}
}

// Trust the captured BPF generation only if that exact root was verified here.
// Source time must be recent and within its collection interval. The returned
// owner is for output only, never for seeding PIDs or auxiliary audit rules.
func (m *processTreeMonitor) historicalEBPFListenerLocked(event processtracker.Event) (listenerInfo, bool) {
	elem := m.attributionHistory.roots[rootIdentity{int(event.RootPID), event.RootStartTime}]
	if elem == nil {
		m.recordAttributionLocked("history_missing")
		return listenerInfo{}, false
	}
	entry := elem.Value.(*rootHistoryEntry)
	if !entry.retiredAt.IsZero() && time.Since(entry.retiredAt) > attributionHistoryTTL {
		if entry.closed {
			delete(m.activeListenerRoots, entry.key)
		}
		delete(m.attributionHistory.roots, entry.key)
		m.attributionHistory.rootOrder.Remove(elem)
		m.recordAttributionLocked("history_expired")
		return listenerInfo{}, false
	}
	now := readAttributionMonotonicNS()
	if event.TimestampNS == 0 || entry.fromNS == 0 || now < event.TimestampNS ||
		now-event.TimestampNS > uint64(attributionHistoryTTL) || event.TimestampNS < entry.fromNS ||
		(entry.retiredNS != 0 && event.TimestampNS > entry.retiredNS) {
		m.recordAttributionLocked("history_time_rejected")
		return listenerInfo{}, false
	}
	m.recordAttributionLocked("root_history_used")
	owner := entry.listener
	owner.Historical = true
	return owner, true
}

// Store only a positively observed process lifetime and verified root. Audit
// lacks BPF's generation token: an event after the last live observation cannot
// be justified by a remembered PID. Do not stretch the old fork TTL indefinitely.
func (m *processTreeMonitor) rememberProcessHistoryLocked(pid, parent int, start uint64, listener listenerInfo, at time.Time) {
	if listener.Historical || pid <= 1 || start == 0 || start == unknownProcessStartTime || listener.AttributionUnknown || listener.RootStartTime == 0 {
		return
	}
	h := &m.attributionHistory
	if h.processes == nil {
		h.processes = make(map[int]*list.Element)
	}
	if elem := h.processes[pid]; elem != nil {
		entry := elem.Value.(*processHistoryEntry)
		if entry.start == start && entry.parent == parent && entry.listener.PID == listener.PID && entry.listener.RootStartTime == listener.RootStartTime && !at.Before(entry.through) {
			entry.through = at
			h.processOrder.MoveToBack(elem)
			return
		}
		delete(h.processes, pid)
		h.processOrder.Remove(elem)
	}
	if len(h.processes) >= maxProcessHistory {
		elem := h.processOrder.Front()
		delete(h.processes, elem.Value.(*processHistoryEntry).pid)
		h.processOrder.Remove(elem)
		m.recordAttributionLocked("history_evicted")
	}
	h.processes[pid] = h.processOrder.PushBack(&processHistoryEntry{pid: pid, parent: parent, start: start, listener: listener, from: at, through: at})
}

func (m *processTreeMonitor) invalidateProcessHistoryLocked(pid int) {
	if elem := m.attributionHistory.processes[pid]; elem != nil {
		delete(m.attributionHistory.processes, pid)
		m.attributionHistory.processOrder.Remove(elem)
	}
}

// Audit recovery requires the same recorded parent and a source time inside a
// previously verified interval. Thus old (>5s) process instances can retain
// queued events without claiming proof for unobserved lifetimes or bare PIDs.
func (m *processTreeMonitor) historicalAuditListenerLocked(pid, parent int, at time.Time) (listenerInfo, bool) {
	elem := m.attributionHistory.processes[pid]
	if elem == nil || at.IsZero() {
		return listenerInfo{}, false
	}
	entry := elem.Value.(*processHistoryEntry)
	if time.Since(entry.through) > attributionHistoryTTL {
		m.invalidateProcessHistoryLocked(pid)
		m.recordAttributionLocked("history_expired")
		return listenerInfo{}, false
	}
	if parent != entry.parent || at.Before(entry.from) || at.After(entry.through) {
		return listenerInfo{}, false
	}
	if current := readProcessStartTime(pid); current != 0 && current != entry.start {
		m.invalidateProcessHistoryLocked(pid)
		m.recordAttributionLocked("identity_conflict")
		return listenerInfo{}, false
	}
	m.recordAttributionLocked("process_history_used")
	owner := entry.listener
	owner.Historical = true
	return owner, true
}

// Idle retired entries are removed with periodic PID cleanup, never by scanning
// all history on each event. Live root entries remain subject to the hard cap.
func (m *processTreeMonitor) pruneAttributionHistoryLocked(now time.Time) {
	h := &m.attributionHistory
	for key, elem := range h.roots {
		entry := elem.Value.(*rootHistoryEntry)
		if !entry.retiredAt.IsZero() && now.Sub(entry.retiredAt) > attributionHistoryTTL {
			if entry.closed {
				delete(m.activeListenerRoots, entry.key)
			}
			delete(h.roots, key)
			h.rootOrder.Remove(elem)
		}
	}
	for pid, elem := range h.processes {
		if now.Sub(elem.Value.(*processHistoryEntry).through) > attributionHistoryTTL {
			m.invalidateProcessHistoryLocked(pid)
		}
	}
}

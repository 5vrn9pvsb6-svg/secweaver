package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"secweaver-agent/internal/modulecontract"
	"secweaver-agent/pkg/auditstream"
)

const (
	defaultLinuxAuditLogPath = "/var/log/audit/audit.log"
	auditDemuxFD             = 3
	auditDemuxBacklogLines   = 4096
	auditDemuxQueueLines     = 8192
	auditDemuxWriteFlush     = 250 * time.Millisecond
	auditDemuxRetryInitial   = 200 * time.Millisecond
	auditDemuxRetryMaximum   = 5 * time.Second
)

// auditStreamSpec is the part of a module configuration that changes audit-log
// transport semantics. Modules can share a reader only when Path and FromStart
// match; Keys affect routing but not how the file is opened.
type auditStreamSpec = modulecontract.AuditSubscription

// auditDemuxKey identifies one physical file-follow operation. Separating it
// from module keys prevents modules with different replay policies from being
// accidentally joined onto the same cursor.
type auditDemuxKey struct {
	Path      string
	FromStart bool
}

// auditDemuxRegistry maps a supervised module to the shared reader selected at
// startup. It is immutable after construction.
type auditDemuxRegistry struct {
	byModule map[string]auditDemuxBinding
}

type auditDemuxBinding struct {
	demux *auditDemux
	keys  map[string]bool
}

// auditDemux is the single-reader fan-out for one audit log.
//
// mu protects subscribers, moduleKeys, backlogs, routes, and subscriber drop
// counters. Pipe writes and diagnostic callbacks must never execute while mu is
// held: either operation may block on another subsystem and stall audit routing.
// Each backlog ring is accessed only under mu. Delivery is at-least-once across
// a subscriber restart, so a replay after an uncertain pipe flush may duplicate
// an audit ID but must not silently discard it.
type auditDemux struct {
	key auditDemuxKey

	once sync.Once
	mu   sync.Mutex

	subscribers map[string]*auditSubscriber
	moduleKeys  map[string]map[string]bool
	backlogs    map[string]*auditLineRing
	routes      map[string]auditDemuxRoute
	routeTicks  uint64
	linesRead   uint64
	retired     uint64
	overflows   map[string]uint64
	readerReady bool
	readerFails uint64
	onDrop      func(module string, drops uint64)
	onOverflow  func(auditOverflowNotice)
	overflowQ   chan auditOverflowNotice
	onReader    func(auditReaderNotice)
	readerQ     chan auditReaderNotice
}

// auditDemuxRoute remembers which module owns the auxiliary records of one
// audit event. Linux audit normally emits a keyed SYSCALL record first, followed
// by unkeyed EXECVE, PATH, CWD, or PROCTITLE records with the same audit ID.
type auditDemuxRoute struct {
	modules map[string]bool
	seenAt  time.Time
}

// auditLineRing is a fixed-capacity FIFO implemented as a circular buffer.
// Append is O(1); once full, the oldest undelivered line is overwritten so a
// disconnected module cannot grow the parent process without bound.
type auditLineRing struct {
	lines []string
	next  int
	full  bool
}

// auditSubscriber owns one parent-to-child pipe. The writer goroutine is the
// sole owner of writer; registration and closure of lines are serialized by
// auditDemux.mu to prevent send-on-closed-channel races.
type auditSubscriber struct {
	id     string
	module string
	keys   map[string]bool
	writer *os.File
	lines  chan string
	done   chan struct{}
	drops  uint64
}

type auditDropNotice struct {
	module string
	drops  uint64
}

var followAuditFile = auditstream.FollowFileWithObserver

// buildAuditDemuxRegistry groups modules by physical audit stream. A demux is
// created only when at least two modules can share it; a single consumer keeps
// the simpler standalone path inside that module.
func buildAuditDemuxRegistry(modules []runtimeModule, tracker *statusTracker) (*auditDemuxRegistry, error) {
	if runtime.GOOS != "linux" {
		return nil, nil
	}
	type groupMember struct {
		module string
		keys   []string
	}
	groups := map[auditDemuxKey][]groupMember{}
	for _, module := range modules {
		spec, ok, err := moduleAuditStreamSpec(module)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		key := auditDemuxKey{Path: spec.Path, FromStart: spec.FromStart}
		groups[key] = append(groups[key], groupMember{module: module.Spec.Name, keys: spec.Keys})
	}
	byModule := map[string]auditDemuxBinding{}
	for key, members := range groups {
		if len(members) < 2 {
			continue
		}
		demux := &auditDemux{
			key:         key,
			subscribers: map[string]*auditSubscriber{},
			moduleKeys:  map[string]map[string]bool{},
			backlogs:    map[string]*auditLineRing{},
			routes:      map[string]auditDemuxRoute{},
			overflows:   map[string]uint64{},
			overflowQ:   make(chan auditOverflowNotice, 1),
			readerQ:     make(chan auditReaderNotice, 1),
			onDrop: func(module string, drops uint64) {
				if tracker != nil {
					tracker.setDiagnostic("audit_demux/"+module, "warn", "audit demux subscriber queue dropped lines", map[string]uint64{"dropped_lines": drops})
				}
			},
			onOverflow: func(notice auditOverflowNotice) {
				if tracker != nil {
					message := fmt.Sprintf("audit demux backlog overflowed; evidence was overwritten: first_lost_audit_id=%s latest_audit_id=%s", valueOrUnknown(notice.lostAuditID), valueOrUnknown(notice.latestAuditID))
					tracker.setDiagnostic("audit_demux/"+notice.module, "error", message, map[string]uint64{"backlog_overflows": notice.total})
				}
			},
		}
		readerDiagnostic := "audit_demux/reader/" + key.Path
		if tracker != nil {
			tracker.setDiagnostic(readerDiagnostic, "error", "audit demux reader is starting", nil)
			demux.onReader = func(notice auditReaderNotice) {
				if notice.ready {
					tracker.clearDiagnostic(readerDiagnostic)
					return
				}
				tracker.setDiagnostic(readerDiagnostic, "error", fmt.Sprintf("audit demux reader unavailable: %v", notice.err), map[string]uint64{"reader_failures": notice.failures})
			}
		}
		moduleNames := make([]string, 0, len(members))
		for _, member := range members {
			moduleNames = append(moduleNames, member.module)
			keys := stringSet(member.keys)
			demux.moduleKeys[member.module] = keys
			demux.backlogs[member.module] = &auditLineRing{}
			byModule[member.module] = auditDemuxBinding{demux: demux, keys: keys}
		}
		fmt.Fprintf(os.Stderr, "audit demux enabled: path=%s from_start=%v subscribers=%s\n", key.Path, key.FromStart, strings.Join(moduleNames, ","))
	}
	if len(byModule) == 0 {
		return nil, nil
	}
	return &auditDemuxRegistry{byModule: byModule}, nil
}

// moduleAuditStreamSpec delegates private configuration to the module owner.
// The supervisor receives only transport settings and cannot drift when the
// child module adds flags or changes precedence.
func moduleAuditStreamSpec(module runtimeModule) (auditStreamSpec, bool, error) {
	if module.Spec.AuditSubscription == nil {
		return auditStreamSpec{}, false, nil
	}
	spec, ok, err := module.Spec.AuditSubscription(module.Config.Args)
	if err != nil {
		return auditStreamSpec{}, false, fmt.Errorf("module %s: %w", module.Spec.Name, err)
	}
	return spec, ok, nil
}

func stringSet(values []string) map[string]bool {
	out := make(map[string]bool, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			out[value] = true
		}
	}
	return out
}

// attach creates the inherited read end used by one child module. ExtraFiles
// places the first supplied file at descriptor 3, and EnvFD tells the child to
// consume that descriptor instead of opening audit.log itself.
func (r *auditDemuxRegistry) attach(ctx context.Context, module runtimeModule) (*os.File, []string, func(), error) {
	if r == nil {
		return nil, nil, func() {}, nil
	}
	binding, ok := r.byModule[module.Spec.Name]
	if !ok || binding.demux == nil {
		return nil, nil, func() {}, nil
	}
	reader, cleanup, err := binding.demux.subscribe(ctx, module.Spec.Name, binding.keys)
	if err != nil {
		return nil, nil, nil, err
	}
	env := []string{fmt.Sprintf("%s=%d", auditstream.EnvFD, auditDemuxFD)}
	return reader, env, cleanup, nil
}

// subscribe atomically transfers a module's pending ring into its new queue
// before publishing the subscriber. This ordering prevents live broadcasts
// from overtaking replayed lines during a module restart.
func (d *auditDemux) subscribe(ctx context.Context, moduleName string, keys map[string]bool) (*os.File, func(), error) {
	d.start(ctx)
	reader, writer, err := os.Pipe()
	if err != nil {
		return nil, nil, err
	}
	sub := &auditSubscriber{
		id:     fmt.Sprintf("%s-%d", moduleName, time.Now().UnixNano()),
		module: moduleName,
		keys:   keys,
		writer: writer,
		lines:  make(chan string, auditDemuxQueueLines),
		done:   make(chan struct{}),
	}
	d.mu.Lock()
	for _, line := range d.backlogSnapshotLocked(moduleName) {
		sub.lines <- line
	}
	if ring := d.backlogs[moduleName]; ring != nil {
		ring.Reset()
	}
	d.subscribers[sub.id] = sub
	d.mu.Unlock()
	go d.writeSubscriber(sub)
	cleanup := func() {
		d.mu.Lock()
		if _, ok := d.subscribers[sub.id]; ok {
			delete(d.subscribers, sub.id)
			close(sub.lines)
		}
		d.mu.Unlock()
		<-sub.done
	}
	return reader, cleanup, nil
}

// start binds the demux lifetime to the supervisor context exactly once, even
// when several modules subscribe concurrently during startup.
func (d *auditDemux) start(ctx context.Context) {
	d.once.Do(func() {
		if d.overflowQ != nil {
			go d.runOverflowReporter(ctx)
		}
		if d.readerQ != nil {
			go d.runReaderReporter(ctx)
		}
		go d.run(ctx)
	})
}

// run owns the physical audit-log follower. FollowFile handles normal rotation;
// this outer retry covers open/read failures and caps retry delay so a temporary
// auditd or filesystem problem does not permanently disable all consumers.
func (d *auditDemux) run(ctx context.Context) {
	defer d.closeSubscribers()
	startOffset := int64(-1)
	if !d.key.FromStart {
		if offset, err := auditstream.FileSize(d.key.Path); err == nil {
			startOffset = offset
		} else {
			fmt.Fprintf(os.Stderr, "audit demux capture offset failed: path=%s err=%v\n", d.key.Path, err)
		}
	}
	retryDelay := auditDemuxRetryInitial
	fromStart := d.key.FromStart
	for {
		delivered := false
		err := followAuditFile(ctx, d.key.Path, fromStart, startOffset, func(line string) {
			delivered = true
			d.broadcast(line)
		}, 200*time.Millisecond, d.observeReaderStatus)
		if ctx.Err() != nil {
			return
		}
		if delivered {
			// Rotation recovery stays inside FollowFile. A replacement after another
			// reader error starts at the current end to avoid replaying old records.
			fromStart = false
			startOffset = -1
			retryDelay = auditDemuxRetryInitial
		}
		fmt.Fprintf(os.Stderr, "audit demux reader failed; retrying: path=%s delay=%s err=%v\n", d.key.Path, retryDelay, err)
		timer := time.NewTimer(retryDelay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		if retryDelay < auditDemuxRetryMaximum {
			retryDelay *= 2
			if retryDelay > auditDemuxRetryMaximum {
				retryDelay = auditDemuxRetryMaximum
			}
		}
	}
}

// broadcast routes one raw line without blocking on child processes. If a
// module queue is full, that subscription is retired: closing the pipe makes
// the module fail and lets the supervisor reconnect it, while the failed line
// enters the module-specific backlog.
func (d *auditDemux) broadcast(line string) {
	if strings.TrimSpace(line) == "" {
		return
	}
	d.mu.Lock()
	d.linesRead++
	modules := d.routeModulesLocked(line)
	var notices []auditDropNotice
	var overflowNotices []auditOverflowNotice
	for module := range modules {
		delivered := false
		for _, sub := range d.subscribers {
			if sub.module != module {
				continue
			}
			select {
			case sub.lines <- line:
				delivered = true
			default:
				sub.drops++
				if sub.drops == 1 || sub.drops%1000 == 0 {
					notices = append(notices, auditDropNotice{module: sub.module, drops: sub.drops})
				}
				// A full queue means this pipe can no longer provide an ordered,
				// lossless stream. Retire it so the module observes EOF and its
				// supervisor reconnects; the failed line is retained below.
				delete(d.subscribers, sub.id)
				close(sub.lines)
				d.retired++
			}
		}
		if !delivered {
			if notice := d.appendBacklogLocked(module, line); notice != nil {
				overflowNotices = append(overflowNotices, *notice)
			}
		}
	}
	d.mu.Unlock()
	for _, notice := range notices {
		fmt.Fprintf(os.Stderr, "audit demux subscriber queue full; restarting subscriber and buffering line: module=%s drops=%d\n", notice.module, notice.drops)
		if d.onDrop != nil {
			d.onDrop(notice.module, notice.drops)
		}
	}
	d.reportOverflowNotices(overflowNotices)
}

// routeModulesLocked resolves keyed primary records directly and unkeyed
// auxiliary records through the audit-ID cache. It intentionally drops unknown
// IDs rather than broadcasting unrelated host audit traffic to every module.
// d.mu must be held by the caller.
func (d *auditDemux) routeModulesLocked(line string) map[string]bool {
	id, key := auditDemuxLineIDAndKey(line)
	now := time.Now()
	d.routeTicks++
	if d.routeTicks%1000 == 0 {
		d.pruneRoutesLocked(now)
	}
	if key != "" {
		modules := map[string]bool{}
		for module, keys := range d.moduleKeys {
			if keys[key] {
				modules[module] = true
			}
		}
		if id != "" && len(modules) > 0 {
			d.routes[id] = auditDemuxRoute{modules: modules, seenAt: now}
		}
		return modules
	}
	if id != "" {
		if route, ok := d.routes[id]; ok {
			route.seenAt = now
			d.routes[id] = route
			return route.modules
		}
	}
	// Audit SYSCALL records carry the key and precede their auxiliary records.
	// An unkeyed record without a known audit ID route is unrelated to our modules.
	return nil
}

func (d *auditDemux) backlogSnapshotLocked(module string) []string {
	if ring := d.backlogs[module]; ring != nil {
		return ring.Snapshot()
	}
	return nil
}

// Append retains a fixed number of lines and returns the overwritten value when
// capacity is exhausted. Returning the lost line lets callers preserve audit-ID
// context without making the ring own logging or metrics policy.
func (r *auditLineRing) Append(line string, capacity int) (overwritten string, overflow bool) {
	if capacity <= 0 {
		return line, true
	}
	if len(r.lines) < capacity {
		r.lines = append(r.lines, line)
		if len(r.lines) == capacity {
			r.next = 0
			r.full = true
		}
		return "", false
	}
	overwritten = r.lines[r.next]
	r.lines[r.next] = line
	r.next = (r.next + 1) % capacity
	r.full = true
	return overwritten, true
}

func (r *auditLineRing) Len() int {
	if r == nil {
		return 0
	}
	return len(r.lines)
}

// Snapshot returns lines in delivery order without exposing the ring's backing
// storage. Callers can therefore reset or append to the ring independently.
func (r *auditLineRing) Snapshot() []string {
	if r == nil || len(r.lines) == 0 {
		return nil
	}
	out := make([]string, 0, len(r.lines))
	if !r.full {
		return append(out, r.lines...)
	}
	out = append(out, r.lines[r.next:]...)
	out = append(out, r.lines[:r.next]...)
	return out
}

func (r *auditLineRing) Reset() {
	if r == nil {
		return
	}
	r.lines = r.lines[:0]
	r.next = 0
	r.full = false
}

func (d *auditDemux) pruneRoutesLocked(now time.Time) {
	for id, route := range d.routes {
		if now.Sub(route.seenAt) > 30*time.Second {
			delete(d.routes, id)
		}
	}
}

func auditDemuxLineIDAndKey(line string) (id, key string) {
	key = strings.TrimSpace(auditDemuxFieldValue(line, "key"))
	if key == "" || key == "(null)" {
		key = ""
	}
	return auditDemuxMsgID(line), key
}

func auditDemuxFieldValue(line, name string) string {
	// This parser is on the raw audit hot path. A small boundary-aware scanner
	// avoids regex allocation while still handling quoted and escaped values.
	target := name + "="
	offset := 0
	for offset < len(line) {
		idx := strings.Index(line[offset:], target)
		if idx < 0 {
			return ""
		}
		idx += offset
		if idx > 0 && !isAuditDemuxFieldBoundary(line[idx-1]) {
			offset = idx + 1
			continue
		}
		start := idx + len(target)
		if start >= len(line) {
			return ""
		}
		if line[start] != '"' {
			end := start
			for end < len(line) && !isAuditDemuxFieldBoundary(line[end]) {
				end++
			}
			return line[start:end]
		}
		end := start + 1
		escaped := false
		for end < len(line) {
			ch := line[end]
			if escaped {
				escaped = false
				end++
				continue
			}
			if ch == '\\' {
				escaped = true
				end++
				continue
			}
			if ch == '"' {
				return unquoteAuditDemuxField(line[start : end+1])
			}
			end++
		}
		return strings.Trim(line[start:], `"`)
	}
	return ""
}

func isAuditDemuxFieldBoundary(ch byte) bool {
	return ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r'
}

func auditDemuxMsgID(line string) string {
	// Accept both msg=audit(...) and msg="audit(...):" forms emitted by
	// different audit userspace versions, but reject unrelated "audit(" text.
	offset := 0
	for offset < len(line) {
		idx := strings.Index(line[offset:], "audit(")
		if idx < 0 {
			return ""
		}
		idx += offset
		if !auditDemuxLooksLikeMsgValue(line, idx) {
			offset = idx + len("audit(")
			continue
		}
		start := idx + len("audit(")
		colon := strings.IndexByte(line[start:], ':')
		if colon < 0 {
			return ""
		}
		idStart := start + colon + 1
		idEnd := idStart
		for idEnd < len(line) && line[idEnd] >= '0' && line[idEnd] <= '9' {
			idEnd++
		}
		if idEnd == idStart {
			return ""
		}
		return line[idStart:idEnd]
	}
	return ""
}

func auditDemuxLooksLikeMsgValue(line string, auditIdx int) bool {
	if auditIdx >= 4 && line[auditIdx-4:auditIdx] == "msg=" {
		return true
	}
	return auditIdx >= 5 && line[auditIdx-5:auditIdx] == `msg="`
}

func unquoteAuditDemuxField(value string) string {
	if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
		if unquoted, err := strconv.Unquote(value); err == nil {
			return unquoted
		}
		return strings.Trim(value, `"`)
	}
	return value
}

func (d *auditDemux) closeSubscribers() {
	d.mu.Lock()
	for id, sub := range d.subscribers {
		delete(d.subscribers, id)
		close(sub.lines)
	}
	d.mu.Unlock()
}

// writeSubscriber batches pipe writes to reduce syscall pressure. pending holds
// the lines whose delivery is not yet confirmed by a successful Flush; on a
// write failure they are replayed because duplicates are safer than evidence
// loss for audit data.
func (d *auditDemux) writeSubscriber(s *auditSubscriber) {
	defer close(s.done)
	defer func() { _ = s.writer.Close() }()
	writer := bufio.NewWriterSize(s.writer, 64*1024)
	ticker := time.NewTicker(auditDemuxWriteFlush)
	defer ticker.Stop()
	dirty := false
	var pending []string
	flush := func() bool {
		if !dirty {
			return true
		}
		if err := writer.Flush(); err != nil {
			d.replayFailedSubscriber(s, pending)
			return false
		}
		dirty = false
		pending = pending[:0]
		return true
	}
	for {
		select {
		case line, ok := <-s.lines:
			if !ok {
				_ = writer.Flush()
				return
			}
			if _, err := writer.WriteString(line); err != nil {
				d.replayFailedSubscriber(s, append(pending, line))
				return
			}
			if !strings.HasSuffix(line, "\n") {
				if err := writer.WriteByte('\n'); err != nil {
					d.replayFailedSubscriber(s, append(pending, line))
					return
				}
			}
			dirty = true
			pending = append(pending, line)
		case <-ticker.C:
			if !flush() {
				return
			}
		}
	}
}

// replayFailedSubscriber removes a broken pipe from live routing and moves both
// its uncertain flush batch and queued lines into the module ring. It does
// nothing after intentional cleanup, because a stopped module should not create
// replay work for a future configuration that may no longer enable it.
func (d *auditDemux) replayFailedSubscriber(s *auditSubscriber, pending []string) {
	d.mu.Lock()
	current, active := d.subscribers[s.id]
	if !active || current != s {
		d.mu.Unlock()
		return
	}
	delete(d.subscribers, s.id)
	d.retired++
	var notices []auditOverflowNotice
	for _, line := range pending {
		if notice := d.appendBacklogLocked(s.module, line); notice != nil {
			notices = append(notices, *notice)
		}
	}
	for {
		select {
		case line := <-s.lines:
			if notice := d.appendBacklogLocked(s.module, line); notice != nil {
				notices = append(notices, *notice)
			}
		default:
			d.mu.Unlock()
			d.reportOverflowNotices(notices)
			return
		}
	}
}

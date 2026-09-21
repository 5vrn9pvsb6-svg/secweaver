package main

import (
	"context"
	"fmt"
	"os"
	"strings"
)

// auditOverflowNotice is emitted only for the first and every thousandth
// overwrite. Counters remain exact, while status-file and stderr IO stay bounded
// during a prolonged child outage.
type auditOverflowNotice struct {
	module        string
	total         uint64
	lostAuditID   string
	latestAuditID string
}

// auditReaderNotice represents an availability transition, not every retry.
// failures therefore counts outages and remains stable during one retry loop.
type auditReaderNotice struct {
	ready    bool
	failures uint64
	err      error
}

// auditDemuxMetrics is a backend-neutral cumulative snapshot. The supervisor
// converts it to Prometheus types so audit transport does not depend on the
// selected observability implementation.
type auditDemuxMetrics struct {
	backlogLines       int
	subscribers        int
	retiredSubscribers uint64
	linesProcessed     uint64
	backlogOverflows   uint64
	readers            int
	readersReady       int
	readerFailures     uint64
}

// observeReaderStatus turns noisy rotation retries into availability
// transitions. It updates metrics synchronously, then coalesces slow status-file
// publication onto a one-slot worker queue.
func (d *auditDemux) observeReaderStatus(err error) {
	d.mu.Lock()
	notice := auditReaderNotice{ready: err == nil, err: err}
	changed := false
	if err == nil {
		if !d.readerReady {
			d.readerReady = true
			changed = true
		}
	} else if d.readerReady || d.readerFails == 0 {
		d.readerReady = false
		d.readerFails++
		notice.failures = d.readerFails
		changed = true
	}
	d.mu.Unlock()
	if !changed {
		return
	}
	if notice.ready {
		d.mu.Lock()
		notice.failures = d.readerFails
		d.mu.Unlock()
	}
	d.queueReaderNotice(notice)
}

// queueReaderNotice retains the newest transition when status persistence falls
// behind, ensuring recovery can supersede an older failure notice.
func (d *auditDemux) queueReaderNotice(notice auditReaderNotice) {
	if d.readerQ == nil {
		d.emitReaderNotice(notice)
		return
	}
	select {
	case d.readerQ <- notice:
	default:
		select {
		case <-d.readerQ:
		default:
		}
		select {
		case d.readerQ <- notice:
		default:
		}
	}
}

// runReaderReporter isolates status persistence from file opening and rotation.
func (d *auditDemux) runReaderReporter(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case notice := <-d.readerQ:
			d.emitReaderNotice(notice)
		}
	}
}

// emitReaderNotice runs only on the reader diagnostic worker or in tests without
// a queue, keeping the file observer itself free of status-file IO.
func (d *auditDemux) emitReaderNotice(notice auditReaderNotice) {
	if d.onReader != nil {
		d.onReader(notice)
	}
}

// appendBacklogLocked is the only overflow accounting boundary. d.mu must be
// held so the ring mutation and cumulative counter cannot disagree in metrics.
func (d *auditDemux) appendBacklogLocked(module, line string) *auditOverflowNotice {
	ring := d.backlogs[module]
	if ring == nil {
		ring = &auditLineRing{}
		d.backlogs[module] = ring
	}
	overwritten, overflow := ring.Append(line, auditDemuxBacklogLines)
	if !overflow {
		return nil
	}
	if d.overflows == nil {
		d.overflows = map[string]uint64{}
	}
	d.overflows[module]++
	total := d.overflows[module]
	if total != 1 && total%1000 != 0 {
		return nil
	}
	return &auditOverflowNotice{
		module:        module,
		total:         total,
		lostAuditID:   auditDemuxMsgID(overwritten),
		latestAuditID: auditDemuxMsgID(line),
	}
}

// reportOverflowNotices runs outside d.mu and coalesces onto one asynchronous
// slot. Exact counters remain in memory and Prometheus; replacing a pending
// notice only limits slow stderr/status-file IO during a sustained overload.
func (d *auditDemux) reportOverflowNotices(notices []auditOverflowNotice) {
	for _, notice := range notices {
		if d.overflowQ == nil {
			d.emitOverflowNotice(notice)
			continue
		}
		select {
		case d.overflowQ <- notice:
		default:
			select {
			case <-d.overflowQ:
			default:
			}
			select {
			case d.overflowQ <- notice:
			default:
			}
		}
	}
}

// runOverflowReporter is the sole owner of slow overflow diagnostics. It is
// intentionally independent from the subscriber writers and audit reader.
func (d *auditDemux) runOverflowReporter(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case notice := <-d.overflowQ:
			d.emitOverflowNotice(notice)
		}
	}
}

// emitOverflowNotice runs only on the diagnostic worker, except in focused tests
// that construct a demux without a queue.
func (d *auditDemux) emitOverflowNotice(notice auditOverflowNotice) {
	fmt.Fprintf(os.Stderr, "audit demux backlog overflow; evidence overwritten: module=%s total=%d first_lost_audit_id=%s latest_audit_id=%s\n", notice.module, notice.total, valueOrUnknown(notice.lostAuditID), valueOrUnknown(notice.latestAuditID))
	if d.onOverflow != nil {
		d.onOverflow(notice)
	}
}

func valueOrUnknown(value string) string {
	if value = strings.TrimSpace(value); value != "" {
		return value
	}
	return "unknown"
}

// metricsSnapshot takes a short lock and never performs file or pipe IO. The
// supervisor polls it outside the audit hot path and exports cumulative counters.
func (d *auditDemux) metricsSnapshot() auditDemuxMetrics {
	if d == nil {
		return auditDemuxMetrics{}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	snapshot := auditDemuxMetrics{
		subscribers:        len(d.subscribers),
		retiredSubscribers: d.retired,
		linesProcessed:     d.linesRead,
		readers:            1,
		readerFailures:     d.readerFails,
	}
	if d.readerReady {
		snapshot.readersReady = 1
	}
	for _, ring := range d.backlogs {
		snapshot.backlogLines += ring.Len()
	}
	for _, overflows := range d.overflows {
		snapshot.backlogOverflows += overflows
	}
	return snapshot
}

// metricsSnapshot deduplicates demux pointers because one physical reader is
// referenced once per subscribed module in byModule.
func (r *auditDemuxRegistry) metricsSnapshot() auditDemuxMetrics {
	var total auditDemuxMetrics
	if r == nil {
		return total
	}
	seen := map[*auditDemux]bool{}
	for _, binding := range r.byModule {
		if binding.demux == nil || seen[binding.demux] {
			continue
		}
		seen[binding.demux] = true
		snapshot := binding.demux.metricsSnapshot()
		total.backlogLines += snapshot.backlogLines
		total.subscribers += snapshot.subscribers
		total.retiredSubscribers += snapshot.retiredSubscribers
		total.linesProcessed += snapshot.linesProcessed
		total.backlogOverflows += snapshot.backlogOverflows
		total.readers += snapshot.readers
		total.readersReady += snapshot.readersReady
		total.readerFailures += snapshot.readerFailures
	}
	return total
}

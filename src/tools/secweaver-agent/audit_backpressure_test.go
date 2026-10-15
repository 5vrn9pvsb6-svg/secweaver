package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"reflect"
	"testing"
	"time"
)

func pressureDemux(queueSize int) (*auditDemux, *auditSubscriber) {
	sub := &auditSubscriber{id: "exec-1", module: "exec", lines: make(chan string, queueSize), done: make(chan struct{})}
	return &auditDemux{
		subscribers: map[string]*auditSubscriber{sub.id: sub},
		moduleKeys:  map[string]map[string]bool{"exec": {"exec-key": true}},
		backlogs:    map[string]*auditLineRing{"exec": {}},
		routes:      map[string]auditDemuxRoute{},
	}, sub
}

func pressureLine(id int) string {
	return fmt.Sprintf(`type=SYSCALL msg=audit(1.0:%d): key="exec-key"`, id)
}

// New live input must never overtake paused data, including across partial
// replay on a deliberately tiny queue.
func TestAuditDemuxPartialReplayPreservesOrder(t *testing.T) {
	d, sub := pressureDemux(1)
	for i := 1; i <= 3; i++ {
		d.broadcast(pressureLine(i))
	}
	pressure := d.metricsSnapshot()
	health := operationAudit(pressure)
	if pressure.queuedLines != 1 || pressure.queueCapacity != 1 || pressure.pausedSubscribers != 1 || health.QueuedLines != 1 || health.QueueCapacity != 1 || health.PausedSubscribers != 1 {
		t.Fatalf("internal pressure missing from metrics/health: %+v %+v", pressure, health)
	}
	d.resumeSubscriber(sub)
	if got := <-sub.lines; got != pressureLine(1) {
		t.Fatal(got)
	}
	d.resumeSubscriber(sub)
	d.broadcast(pressureLine(4))
	for i := 2; i <= 4; i++ {
		if got := <-sub.lines; got != pressureLine(i) {
			t.Fatalf("line %d = %s", i, got)
		}
		d.resumeSubscriber(sub)
	}
	if sub.paused || d.metricsSnapshot().backlogOverflows != 0 {
		t.Fatal("lossless replay remained paused or reported evidence loss")
	}
}

// A blocked status-file publisher must not stall audit routing. Recovery is a
// separate, current-state observation and cannot leave a stale pressure warning.
func TestAuditDemuxPressureReporterDoesNotBlockRoutingAndClears(t *testing.T) {
	d, sub := pressureDemux(1)
	d.pressureQ = make(chan auditPressureNotice, 1)
	ctx, cancel := context.WithCancel(context.Background())
	blocked, release, recovered, done := make(chan struct{}, 1), make(chan struct{}), make(chan struct{}, 1), make(chan struct{})
	d.onPressure = func(_ string, count uint64) {
		if count == 0 {
			recovered <- struct{}{}
			return
		}
		blocked <- struct{}{}
		select {
		case <-release:
		case <-ctx.Done():
		}
	}
	go func() {
		defer close(done)
		d.runPressureReporter(ctx)
	}()
	defer func() { cancel(); <-done }()
	d.broadcast(pressureLine(1))
	d.broadcast(pressureLine(2))
	select {
	case <-blocked:
	case <-time.After(time.Second):
		t.Fatal("pressure diagnostic did not start")
	}
	routed := make(chan struct{})
	go func() { d.broadcast(pressureLine(3)); close(routed) }()
	select {
	case <-routed:
	case <-time.After(time.Second):
		t.Fatal("status persistence stalled routing")
	}
	for i := 1; i <= 3; i++ {
		<-sub.lines
		d.resumeSubscriber(sub)
	}
	close(release)
	select {
	case <-recovered:
	case <-time.After(time.Second):
		t.Fatal("pressure warning was not cleared after replay")
	}
}

// A previous overflow suppresses the next diagnostic, not the next retirement.
func TestAuditDemuxRetiresOnRealLossWithoutDuplicateAppend(t *testing.T) {
	for _, previous := range []uint64{0, 1} {
		t.Run(fmt.Sprint(previous), func(t *testing.T) {
			d, sub := pressureDemux(1)
			d.overflows = map[string]uint64{"exec": previous}
			for i := 1; i <= auditDemuxBacklogLines+2; i++ {
				d.broadcast(pressureLine(i))
			}
			if d.retired != 1 || len(d.subscribers) != 0 || d.overflows["exec"] != previous+1 {
				t.Fatalf("wrong loss/retirement accounting: %+v", d.metricsSnapshot())
			}
			if got := <-sub.lines; got != pressureLine(1) {
				t.Fatal(got)
			}
			if _, ok := <-sub.lines; ok {
				t.Fatal("real evidence loss must close the child stream")
			}
			backlog := d.backlogs["exec"].Snapshot()
			if backlog[0] != pressureLine(3) || backlog[len(backlog)-1] != pressureLine(auditDemuxBacklogLines+2) {
				t.Fatal("overflow duplicated or reordered the failed line")
			}
		})
	}
}

func TestAuditDemuxBrokenPipeReplaysOlderQueueBeforePausedBacklog(t *testing.T) {
	d, sub := pressureDemux(1)
	d.broadcast(pressureLine(2))
	d.broadcast(pressureLine(3))
	d.replayFailedSubscriber(sub, []string{pressureLine(1)})
	if got := d.backlogs["exec"].Snapshot(); !reflect.DeepEqual(got, []string{pressureLine(1), pressureLine(2), pressureLine(3)}) {
		t.Fatalf("broken pipe replay order: %v", got)
	}
}

// Exercise the actual writer/timer, not only queue helpers. A bounded burst
// fits in queue+backlog and must drain through the same pipe without EOF/restart.
func TestAuditDemuxBurstDrainsThroughOriginalPipe(t *testing.T) {
	d, sub := pressureDemux(auditDemuxQueueLines)
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	sub.writer = writer
	const count = auditDemuxQueueLines + 64
	for i := 1; i <= count; i++ {
		d.broadcast(pressureLine(i))
	}
	go d.writeSubscriber(sub)
	defer func() {
		d.closeSubscribers()
		reader.Close() // Unblock a failed-test writer before joining it.
		<-sub.done
	}()
	result := make(chan error, 1)
	go func() {
		scanner := bufio.NewScanner(reader)
		for i := 1; i <= count; i++ {
			if !scanner.Scan() || scanner.Text() != pressureLine(i) {
				result <- fmt.Errorf("pipe line %d = %q err=%v", i, scanner.Text(), scanner.Err())
				return
			}
		}
		result <- nil
	}()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("paused subscriber did not recover")
	}
	if snapshot := d.metricsSnapshot(); snapshot.retiredSubscribers != 0 || snapshot.backlogOverflows != 0 || snapshot.backlogLines != 0 {
		t.Fatalf("lossless burst triggered restart/loss: %+v", snapshot)
	}
}

package auditportexecmon

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"secweaver-agent/pkg/processtracker"
)

// Exercise both output entry points: disabling learning or using its fallback
// paths must not allow events outside the listener contract onto disk.
func TestListenerRequiredBeforeOutputOrLearning(t *testing.T) {
	for _, eventType := range []string{"exec", "active_connect", "file_op"} {
		for _, tc := range []struct {
			name, listener, status string
		}{
			{"missing", "", ""},
			{"blank", " \t", ""},
			{"unknown", "", "unknown"},
			{"stale_label", "nginx", "unknown"},
		} {
			t.Run(eventType+"/"+tc.name, func(t *testing.T) {
				event := auditEvent{EventType: eventType, ListenerProcess: tc.listener, AttributionStatus: tc.status,
					CommandLine: "pgrep -fl unicorn", RawRecords: []string{"private raw audit detail"}}
				var disk bytes.Buffer
				if err := emitNormalizedEvent(&disk, event); err != nil {
					t.Fatal(err)
				}
				for _, closed := range []bool{false, true} {
					sink := &learningOutput{Writer: &disk, queue: make(chan auditEvent, 1), closed: closed}
					if err := sink.WriteEvent(event); err != nil {
						t.Fatal(err)
					}
					if len(sink.queue) != 0 {
						t.Fatal("unattributed event reached learning queue")
					}
				}
				if disk.Len() != 0 {
					t.Fatalf("unattributed event reached output: %s", disk.String())
				}
			})
		}
		t.Run(eventType+"/verified", func(t *testing.T) {
			event := auditEvent{EventType: eventType, ListenerProcess: "nginx", CommandLine: "worker"}
			var disk bytes.Buffer
			if err := emitNormalizedEvent(&disk, event); err != nil {
				t.Fatal(err)
			}
			var decoded auditEvent
			if err := json.Unmarshal(disk.Bytes(), &decoded); err != nil || decoded.ListenerProcess != "nginx" {
				t.Fatalf("verified event lost: %v %s", err, disk.String())
			}
			disk.Reset()
			sink := &learningOutput{Writer: &disk, queue: make(chan auditEvent, 1)}
			if err := emitNormalizedEvent(sink, event); err != nil {
				t.Fatal(err)
			}
			if eventType == "exec" {
				if len(sink.queue) != 1 || disk.Len() != 0 {
					t.Fatal("verified exec bypassed learning")
				}
			} else if disk.Len() == 0 {
				t.Fatal("verified non-learned event lost")
			}
		})
	}
}

// Replay actual audit assembly for every service stream, including raw detail
// mode and terminal partial-file flush, so no serializer-only test can mask an
// alternate output path. Verified controls also protect descendant coverage.
func TestAuditListenerRequiredAcrossStreams(t *testing.T) {
	for _, backend := range []string{processTreeBackendAudit, processTreeBackendAuditPID, processTreeBackendEBPF} {
		for _, key := range []string{"exec", "connect", "file", "sensitive"} {
			for _, verified := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/verified=%t", backend, key, verified), func(t *testing.T) {
					stubAttributionStartTimes(t, func(pid int) uint64 {
						if verified && pid == 900001 {
							return 100
						}
						return 0
					})
					m := newAttributionMonitor(backend)
					m.sensitiveFilePaths = defaultSensitiveFilePaths
					// Prevent auditctl calls: the synthetic parent establishes
					// ownership, while this fixture tests emission only.
					m.pidListener[900001] = listenerInfo{PID: 900001, RootStartTime: 100, Process: "mysqld", Port: 3306, ExeOnly: true}
					accs := map[string]*auditAccumulator{}
					consumeAuditLine(accs, fmt.Sprintf(`type=SYSCALL msg=audit(1791733161.591:123): items=1 syscall=2 pid=910001 ppid=900001 comm="worker" exe="/bin/worker" key="%s"`, key))
					consumeAuditLine(accs, `type=EXECVE msg=audit(1791733161.591:123): argc=1 a0="worker"`)
					consumeAuditLine(accs, `type=SOCKADDR msg=audit(1791733161.591:123): saddr=02001F90080808080000000000000000`)
					consumeAuditLine(accs, `type=PATH msg=audit(1791733161.591:123): item=0 name="/etc/shadow"`)
					// No PROCTITLE: also exercise terminal partial-file fallback.
					var out bytes.Buffer
					if key == "file" || key == "sensitive" {
						flushFileRecords(accs, "exec", "connect", "file", m, hostIdentity{}, true, &out)
					} else {
						emitReady(accs, "exec", "connect", "file", m, hostIdentity{}, true, &out, time.Nanosecond)
					}
					if len(accs) != 0 || (out.Len() > 0) != verified {
						t.Fatalf("scope/cleanup: verified=%v pending=%d output=%s", verified, len(accs), out.String())
					}
					if verified {
						var event auditEvent
						if err := json.Unmarshal(out.Bytes(), &event); err != nil || event.ListenerProcess != "mysqld" || len(event.RawRecords) == 0 {
							t.Fatalf("verified listener/raw detail lost: %v %s", err, out.String())
						}
					}
				})
			}
		}
	}
}

func TestEBPFMissingListenerDropsOutput(t *testing.T) {
	var out bytes.Buffer
	source := processtracker.Event{Type: processtracker.EventExec, PID: 910001, Args: []string{"worker"}}
	for _, listener := range []listenerInfo{{}, {Process: " \t"}, {Process: "nginx", AttributionUnknown: true}} {
		if err := emitEBPFExecEventWithContext(source, listener, "exec", hostIdentity{}, &out, processExecutionContext{}); err != nil {
			t.Fatal(err)
		}
	}
	if out.Len() != 0 {
		t.Fatalf("eBPF emitted unverified listener: %s", out.String())
	}
}

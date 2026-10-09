package auditportexecmon

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"secweaver-agent/pkg/behaviorlearning"
)

// Replay the failed PATH-search shape seen on CentOS: no EXECVE record, only a
// capped parent PROCTITLE. Distinct audit IDs train the four collected fields;
// different attempted paths and missing argv do not introduce extra match keys.
func TestLearningCountsFailedExecWithoutEXECVE(t *testing.T) {
	cfg, err := behaviorlearning.DecodeExec([]byte(`{"enabled":true}`))
	if err != nil {
		t.Fatal(err)
	}
	cfg.StateDir = t.TempDir()
	var originals []json.RawMessage
	var suppressed uint64
	engine, err := behaviorlearning.New(cfg, "test-device", func(raw json.RawMessage) error {
		originals = append(originals, append(json.RawMessage(nil), raw...))
		return nil
	}, func(summary behaviorlearning.Summary) error {
		suppressed += summary.Suppressed
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { engine.Close() })
	engine.Health(true, false)
	title := "/opt/jre/bin/java\x00-jar\x00" + strings.Repeat("x", 106)
	for i := 0; i < 6; i++ {
		msg := fmt.Sprintf("msg=audit(1791536160.026:%d):", 100+i)
		accs := map[string]*auditAccumulator{}
		id, _ := consumeAuditLine(accs, `type=SYSCALL `+msg+` syscall=59 success=no exit=-2 pid=123 exe="/opt/jre/bin/java" comm="java" key="exec"`)
		consumeAuditLine(accs, `type=PATH `+msg+fmt.Sprintf(` item=0 name="/missing-%d/sh"`, i))
		consumeAuditLine(accs, `type=PROCTITLE `+msg+fmt.Sprintf(" proctitle=%X", title))
		acc := accs[id]
		command := resolveAuditCommand(acc, "java")
		event := auditEvent{Time: time.Now(), EventType: "exec", AuditID: id, ListenerProcess: "java", PIDName: "java",
			Exe: acc.fields["exe"], Command: command, CommandLine: strings.Join(command, " "),
			Success: acc.fields["success"], Exit: acc.fields["exit"], Fields: acc.fields}
		observation := execLearningObservation(event, "audit", "test-boot")
		putAccumulator(acc)
		if observation.Complete || observation.Reason != "incomplete_or_truncated_command" {
			t.Fatal("source completeness must remain honest even when Linux permits learning")
		}
		if err := engine.Process(observation); err != nil {
			t.Fatal(err)
		}
	}
	if err := engine.Checkpoint(); err != nil {
		t.Fatal(err)
	}
	if len(originals) != 4 || suppressed != 2 {
		t.Fatalf("failed exec originals=%d suppressed=%d; want 4 and 2", len(originals), suppressed)
	}
	var first map[string]any
	if err := json.Unmarshal(originals[0], &first); err != nil {
		t.Fatal(err)
	}
	if first["decision_reason"] != "learning" || first["command_evidence_reason"] != "incomplete_or_truncated_command" || first["success"] != "no" {
		t.Fatalf("failed exec diagnostics changed: %s", originals[0])
	}
}

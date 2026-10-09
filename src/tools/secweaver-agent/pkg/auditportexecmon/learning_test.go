package auditportexecmon

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Summary registration must not depend on explicitly setting output_log; most
// installations rely on the default original output path.
func TestLearningOutputDescriptorIncludesSummary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"behavior_learning":{"enabled":true}}`), 0600); err != nil {
		t.Fatal(err)
	}
	paths := descriptorOutputPaths([]string{"-config", path})
	if len(paths) != 2 || filepath.Base(paths[1]) != "behavior-learning.log" {
		t.Fatalf("paths: %v", paths)
	}
	if err := os.WriteFile(path, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	if got := descriptorOutputPaths([]string{"-config", path}); len(got) != 1 {
		t.Fatalf("upgrade omission changed outputs: %v", got)
	}
}

// A truncated PROCTITLE used to override complete EXECVE and reject candidates.
// Hex literals, encoded arguments and empty args must retain exact boundaries.
func TestLearningUsesCompleteEXECVEBeforePROCTITLE(t *testing.T) {
	accs := map[string]*auditAccumulator{}
	id, _ := consumeAuditLine(accs, `type=SYSCALL msg=audit(1782320671.957:900): pid=999999 exe="/bin/bash" comm="bash" key="exec" a0=12345678`)
	consumeAuditLine(accs, `type=EXECVE msg=audit(1782320671.957:900): argc=5 a0="bash" a1="-c" a2=6563686F206869 a3="deadbeef12345678" a4=""`)
	consumeAuditLine(accs, `type=PROCTITLE msg=audit(1782320671.957:900): proctitle=62617368002d63006563`)
	acc := accs[id]
	defer putAccumulator(acc)
	want := []string{"bash", "-c", "echo hi", "deadbeef12345678", ""}
	if got := resolveAuditCommand(acc, "bash"); !reflect.DeepEqual(got, want) || !completeAuditArgv(acc) {
		t.Fatalf("full command=%q wanted=%q complete=%t", got, want, completeAuditArgv(acc))
	}
	event := auditEvent{EventType: "exec", AuditID: id, ListenerProcess: "java", PIDName: "bash", Exe: "/bin/bash",
		CommandLine: strings.Join(want, " "), PID: "999999", UID: "0", Success: "no", Fields: map[string]string{"learning_argv_complete": "yes"}}
	o := execLearningObservation(event, "audit", "test-boot")
	if !o.Complete || o.Context.Exec.CommandLine != event.CommandLine || o.Instance != "" || o.Context.Capability != "" {
		t.Fatal("adapter requires live /proc or changed exact fields")
	}
	event.CommandTruncated = true
	if execLearningObservation(event, "audit", "test-boot").Complete {
		t.Fatal("truncated command qualified")
	}
	delete(acc.argv, 2)
	if completeAuditArgv(acc) {
		t.Fatal("missing middle EXECVE argument considered complete")
	}
}

func TestInvalidLearningPolicyDoesNotBreakCollectorConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"behavior_learning":{"enabled":true,"misspelled":1}}`), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if sink, err := newLearningOutput(cfg, "/tmp/original.log", "audit", &out, nil); err == nil || sink != nil {
		t.Fatal("invalid learning policy accepted")
	}
	event := auditEvent{Time: time.Now(), EventType: "exec", Command: []string{"example"}}
	if err := emitNormalizedEvent(&out, event); err != nil {
		t.Fatal(err)
	}
	var decoded auditEvent
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.EventType != "exec" {
		t.Fatal("full-output fallback broken")
	}
}

func TestAuditLearningSourceIdentity(t *testing.T) {
	accs := map[string]*auditAccumulator{}
	id, _ := consumeAuditLine(accs, `type=SYSCALL msg=audit(1782320671.957:88920): pid=42 exe="/usr/bin/stat" key="exec"`)
	consumeAuditLine(accs, `type=PATH msg=audit(1782320671.957:88920): item=0 name="/usr/bin/stat" inode=1234 dev=08:02`)
	a := accs[id]
	defer putAccumulator(a)
	if a.fields["learning_source_time"] != "1782320671.957" || a.fields["learning_inode"] != "1234" || a.fields["learning_dev"] != "08:02" {
		t.Fatalf("identity: %v", a.fields)
	}
}

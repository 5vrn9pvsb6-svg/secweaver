package auditportexecmon

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
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

package auditportexecmon

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"secweaver-agent/pkg/behaviorlearning"
)

// Capture at the semantic output boundary, before the accumulator returns to
// its pool; JSON alone omits the adapter's private completeness metadata.
type fileEvidenceCapture struct {
	bytes.Buffer
	observation behaviorlearning.Observation
}

func (w *fileEvidenceCapture) WriteEvent(e auditEvent) error {
	w.observation = fileLearningObservation(e, "audit", "test-boot")
	return nil
}

func TestNativeFileEvidenceReachesSimpleAdapter(t *testing.T) {
	listener := listenerInfo{PID: 1234, Process: "nginx", Address: "0.0.0.0", Port: 443, MonitorExe: "/usr/sbin/nginx", ExeOnly: true}
	monitor := &processTreeMonitor{listeners: []listenerInfo{listener}, pidListener: map[int]listenerInfo{},
		monitored: map[int]bool{}, exeMonitored: map[string]bool{}, selfBranch: map[int]bool{},
		execKey: "exec", fileKey: "file", connectKey: "connect", sensitiveFileKey: "sensitive", cloneKey: "clone",
		trackDescendants: true, monitorSensitiveFileReads: true, sensitiveFilePaths: defaultSensitiveFilePaths}
	accs := map[string]*auditAccumulator{}
	for _, line := range []string{
		`type=SYSCALL msg=audit(1791388800.001:42): arch=c000003e syscall=2 items=1 pid=2345 ppid=1234 exe="/usr/sbin/nginx" comm="nginx" key="sensitive"`,
		`type=PATH msg=audit(1791388800.001:42): item=0 name="/etc/shadow"`,
		`type=PROCTITLE msg=audit(1791388800.001:42): proctitle="nginx  -g daemon off;"`,
	} {
		consumeAuditLine(accs, line)
	}
	var out fileEvidenceCapture
	emitReady(accs, "exec", "connect", "file", monitor, hostIdentity{HostName: "test-host"}, false, &out, 0)
	o := out.observation
	if !o.Complete || o.Context.File == nil || o.Context.File.ListenerProcess != "nginx" ||
		o.Context.File.CommandLine != "nginx  -g daemon off;" || len(o.Context.File.FilePaths) != 1 {
		t.Fatalf("native file adapter did not receive complete exact fields: %+v", o)
	}
}

// Native audit PATH/PROCTITLE assembly is tested without any current /proc PID,
// proving that file completeness does not depend on a still-running process.
func TestFileAuditCompletenessAndLiteralPaths(t *testing.T) {
	accs := map[string]*auditAccumulator{}
	id, _ := consumeAuditLine(accs, `type=SYSCALL msg=audit(1791388800.001:42): items=2 pid=999999 exe="/bin/cat" comm="cat" key="file"`)
	a := accs[id]
	defer putAccumulator(a)
	consumeAuditLine(accs, `type=PATH msg=audit(1791388800.001:42): item=0 name="/etc"`)
	consumeAuditLine(accs, `type=PROCTITLE msg=audit(1791388800.001:42): proctitle=636174002F6574632F736861646F77`)
	if completeFileEvidence(a) {
		t.Fatal("partial PATH group eligible")
	}
	consumeAuditLine(accs, `type=PATH msg=audit(1791388800.001:42): item=1 name=2F6574632F736861646F77`)
	if !completeFileEvidence(a) || a.paths[1] != "/etc/shadow" {
		t.Fatal("complete native evidence rejected or encoded path not decoded")
	}
	e := auditEvent{EventType: "file_op", AuditID: "42", PIDName: "cat", Exe: "/bin/cat", ListenerProcess: "nginx", CommandLine: "cat /etc/shadow", FilePaths: orderedPaths(a.paths), Fields: map[string]string{"learning_file_fields_complete": "yes"}}
	o := fileLearningObservation(e, "audit", "boot")
	if !o.Complete || o.Context.Exec != nil || len(o.Context.File.FilePaths) != 2 || o.Context.File.CommandLine != e.CommandLine {
		t.Fatal("five-field adapter lost exact context")
	}
	a.proctitle = hex.EncodeToString([]byte(strings.Repeat("x", 128)))
	if completeFileEvidence(a) {
		t.Fatal("capped title eligible")
	}
	a.proctitle = "ff"
	if completeFileEvidence(a) {
		t.Fatal("invalid UTF-8 title eligible")
	}
	delete(e.Fields, "learning_file_fields_complete")
	if fileLearningObservation(e, "audit", "boot").Complete {
		t.Fatal("missing command used comm/exe fallback to qualify")
	}
}

func TestQuotedAuditTitleAndHexLookingPath(t *testing.T) {
	title := parseFields(`type=PROCTITLE proctitle="/bin/worker"`)["proctitle"]
	if got := decodeProctitle(title); len(got) != 1 || got[0] != "/bin/worker" {
		t.Fatalf("quoted title not normalized: %q", got)
	}
	if path := parseFields(`type=PATH item=0 name="deadbeef"`)["name"]; path != "deadbeef" {
		t.Fatal("quoted hexadecimal filename was decoded")
	}
	a := &auditAccumulator{proctitle: hex.EncodeToString([]byte("worker\x00  exact command  \x00"))}
	if command := strings.Join(resolveFileCommand(a, "worker"), " "); command != "worker   exact command  " {
		t.Fatalf("file command whitespace folded: %q", command)
	}
}

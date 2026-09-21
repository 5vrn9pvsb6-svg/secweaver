package auditportexecmon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"strings"
	"testing"
	"time"

	"secweaver-agent/internal/testutil"
)

// These tests cover audit transport, event assembly, rotation, filtering, and self-maintenance suppression.

func TestBoundedAuditFiltersUnrelatedProcessesAndTracksCloneChild(t *testing.T) {
	listener := listenerInfo{PID: 900001, Process: "nginx", Port: 443}
	monitor := &processTreeMonitor{
		processBackend:    processTreeBackendAudit,
		listeners:         []listenerInfo{listener},
		pidListener:       map[int]listenerInfo{listener.PID: listener},
		monitored:         map[int]bool{listener.PID: true},
		processStartTimes: map[int]uint64{listener.PID: 1},
		processParentPIDs: map[int]int{},
		processObservedAt: map[int]time.Time{},
		pidTargets:        map[int]trackingTarget{},
		selfBranch:        map[int]bool{},
		execKey:           "tb_external_listener_exec",
		cloneKey:          "tb_external_listener_clone",
		trackDescendants:  true,
	}
	unrelated := map[string]string{
		"type": "SYSCALL", "key": monitor.execKey, "pid": "910001", "ppid": "1", "exe": "/usr/bin/id",
	}
	if !monitor.shouldDropBoundedAuditPrimary(unrelated) {
		t.Fatal("unrelated host-wide exec must be dropped before accumulation")
	}
	clone := map[string]string{
		"type": "SYSCALL", "key": monitor.cloneKey, "pid": "900001", "ppid": "1", "exit": "900002", "success": "yes",
	}
	monitor.observeAuditFields(clone)
	childExec := map[string]string{
		"type": "SYSCALL", "key": monitor.execKey, "pid": "900002", "ppid": "900001", "exe": "/usr/bin/sh",
	}
	if monitor.shouldDropBoundedAuditPrimary(childExec) {
		t.Fatal("successful clone child must inherit listener ownership")
	}
	if got, ok := monitor.matchListener(childExec); !ok || got.PID != listener.PID {
		t.Fatalf("child ownership=%+v ok=%v, want listener %+v", got, ok, listener)
	}
	secondClone := map[string]string{
		"type": "SYSCALL", "key": monitor.cloneKey, "pid": "900001", "ppid": "1", "exit": "900003", "success": "yes",
	}
	monitor.observeAuditFields(secondClone)
	reusedPIDExec := map[string]string{
		"type": "SYSCALL", "key": monitor.execKey, "pid": "900003", "ppid": "999999", "exe": "/usr/bin/id",
	}
	if !monitor.shouldDropBoundedAuditPrimary(reusedPIDExec) {
		t.Fatal("unknown-starttime child must not survive a parent mismatch after PID reuse")
	}
}

func TestBoundedAuditSkipsAuxiliaryRecordsWithoutAcceptedPrimary(t *testing.T) {
	monitor := &processTreeMonitor{processBackend: processTreeBackendAudit}
	accs := map[string]*auditAccumulator{}
	line := `type=EXECVE msg=audit(1782320671.957:88922): argc=1 a0="id"`
	if !shouldSkipBoundedAuditAuxiliary(accs, line, monitor) {
		t.Fatal("unrelated auxiliary record should skip full parsing")
	}
	accs["88922"] = &auditAccumulator{id: "88922"}
	if shouldSkipBoundedAuditAuxiliary(accs, line, monitor) {
		t.Fatal("accepted primary accumulator must retain its auxiliary records")
	}
}

func TestBoundedAuditRejectsReusedListenerRootPID(t *testing.T) {
	originalReadStartTime := readProcessStartTime
	defer func() { readProcessStartTime = originalReadStartTime }()
	readProcessStartTime = func(pid int) uint64 {
		if pid == 900001 {
			return 200
		}
		return 0
	}
	listener := listenerInfo{PID: 900001, Process: "nginx", Port: 443}
	monitor := &processTreeMonitor{
		processBackend:    processTreeBackendAudit,
		listeners:         []listenerInfo{listener},
		pidListener:       map[int]listenerInfo{listener.PID: listener},
		monitored:         map[int]bool{listener.PID: true},
		processStartTimes: map[int]uint64{listener.PID: 100},
		processParentPIDs: map[int]int{},
		processObservedAt: map[int]time.Time{},
		pidTargets:        map[int]trackingTarget{},
		selfBranch:        map[int]bool{},
		execKey:           "tb_external_listener_exec",
		cloneKey:          "tb_external_listener_clone",
	}
	fields := map[string]string{
		"type": "SYSCALL", "key": monitor.execKey, "pid": "900001", "ppid": "1", "exe": "/usr/bin/id",
	}
	if !monitor.shouldDropBoundedAuditPrimary(fields) {
		t.Fatal("reused listener root PID must not regain ownership from listener metadata")
	}
	if _, ok := monitor.pidListener[listener.PID]; ok {
		t.Fatal("reused PID ownership should be removed")
	}
}

func TestFollowAuditLogReadsFromCapturedStartOffset(t *testing.T) {
	logFile, err := os.CreateTemp(t.TempDir(), "audit.log")
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()
	if _, err := logFile.WriteString("old ignored line\n"); err != nil {
		t.Fatal(err)
	}
	startOffset, err := fileSize(logFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := logFile.WriteString(`type=SYSCALL msg=audit(1782320671.957:88922): arch=c000003e syscall=59 success=yes exit=0 ppid=125609 pid=126350 auid=1000 uid=1000 tty=pts0 comm="ps" exe="/usr/bin/ps" key="tb_external_listener_exec"` + "\n" +
		`type=EXECVE msg=audit(1782320671.957:88922): argc=2 a0="ps" a1="-ef335"` + "\n" +
		`type=PROCTITLE msg=audit(1782320671.957:88922): proctitle=7073002D6566333335` + "\n"); err != nil {
		t.Fatal(err)
	}
	monitor := &processTreeMonitor{
		pidListener:      map[int]listenerInfo{},
		monitored:        map[int]bool{},
		exeMonitored:     map[string]bool{},
		execKey:          "tb_external_listener_exec",
		connectKey:       "tb_external_listener_connect",
		fileKey:          "tb_external_listener_file",
		cloneKey:         "tb_external_listener_clone",
		selfBranch:       map[int]bool{},
		trackDescendants: true,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	var out bytes.Buffer
	err = followAuditLog(ctx, logFile.Name(), monitor.execKey, monitor.connectKey, monitor.fileKey, monitor, hostIdentity{HostName: "test-host", HostIP: "127.0.0.1"}, false, startOffset, false, &out, defaultListenerRescanInterval)
	if err != nil && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		t.Fatalf("followAuditLog: %v", err)
	}
	if !bytes.Contains(out.Bytes(), []byte(`"command_line":"ps -ef335"`)) {
		t.Fatalf("expected ps -ef335 output, got %s", out.String())
	}
}

func TestFollowAuditLogContinuesAfterRotation(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	if err := os.WriteFile(logPath, []byte(strings.Repeat("x", 4096)+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	startOffset, err := fileSize(logPath)
	if err != nil {
		t.Fatal(err)
	}
	monitor := &processTreeMonitor{
		pidListener:      map[int]listenerInfo{},
		monitored:        map[int]bool{},
		exeMonitored:     map[string]bool{},
		execKey:          "tb_external_listener_exec",
		connectKey:       "tb_external_listener_connect",
		fileKey:          "tb_external_listener_file",
		cloneKey:         "tb_external_listener_clone",
		selfBranch:       map[int]bool{},
		trackDescendants: true,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var out testutil.SyncBuffer
	done := make(chan error, 1)
	go func() {
		done <- followAuditLog(ctx, logPath, monitor.execKey, monitor.connectKey, monitor.fileKey, monitor, hostIdentity{HostName: "test-host", HostIP: "127.0.0.1"}, false, startOffset, false, &out, defaultListenerRescanInterval)
	}()
	time.Sleep(120 * time.Millisecond)
	rotatedPath := logPath + ".1"
	if err := os.Rename(logPath, rotatedPath); err != nil {
		t.Fatal(err)
	}
	newLine := `type=SYSCALL msg=audit(1782320671.957:88923): arch=c000003e syscall=59 success=yes exit=0 ppid=125609 pid=126351 auid=1000 uid=1000 tty=(none) comm="id" exe="/usr/bin/id" key="tb_external_listener_exec"` + "\n" +
		`type=EXECVE msg=audit(1782320671.957:88923): argc=1 a0="id"` + "\n" +
		`type=PROCTITLE msg=audit(1782320671.957:88923): proctitle=6964` + "\n"
	// Write before the follower notices rotation. Reopening at EOF would lose this event.
	if err := os.WriteFile(logPath, []byte(newLine), 0644); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if bytes.Contains(out.Bytes(), []byte(`"command_line":"id"`)) {
			cancel()
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !bytes.Contains(out.Bytes(), []byte(`"command_line":"id"`)) {
		t.Fatalf("expected id after audit.log rotation, got %s", out.String())
	}
	<-done
}

func TestFollowAuditLogReplaysRawAuditRecords(t *testing.T) {
	logFile, err := os.CreateTemp(t.TempDir(), "audit.log")
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()
	raw := "" +
		`type=SYSCALL msg=audit(1782320671.957:88920): arch=c000003e syscall=59 success=yes exit=0 a0=5d9634fde0f0 a1=5d9634fcc780 a2=5d963535fd50 a3=5d9634fcc780 items=2 ppid=125609 pid=126350 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=316 comm="ps" exe="/usr/bin/ps" subj=unconfined key="tb_external_listener_exec" ARCH=x86_64 SYSCALL=execve AUID="ks" UID="ks" GID="ks" EUID="ks" SUID="ks" FSUID="ks" EGID="ks" SGID="ks" FSGID="ks"` + "\n" +
		`type=EXECVE msg=audit(1782320671.957:88920): argc=2 a0="ps" a1="-ef334"` + "\n" +
		`type=CWD msg=audit(1782320671.957:88920): cwd="/home/ks"` + "\n" +
		`type=PATH msg=audit(1782320671.957:88920): item=0 name="/usr/bin/ps" inode=918726 dev=08:02 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0 OUID="root" OGID="root"` + "\n" +
		`type=PATH msg=audit(1782320671.957:88920): item=1 name="/lib64/ld-linux-x86-64.so.2" inode=928786 dev=08:02 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0 OUID="root" OGID="root"` + "\n" +
		`type=PROCTITLE msg=audit(1782320671.957:88920): proctitle=7073002D6566333334` + "\n"
	if _, err := logFile.WriteString(raw); err != nil {
		t.Fatal(err)
	}
	monitor := &processTreeMonitor{
		pidListener:      map[int]listenerInfo{},
		monitored:        map[int]bool{},
		exeMonitored:     map[string]bool{},
		execKey:          "tb_external_listener_exec",
		connectKey:       "tb_external_listener_connect",
		fileKey:          "tb_external_listener_file",
		cloneKey:         "tb_external_listener_clone",
		selfBranch:       map[int]bool{},
		trackDescendants: true,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	var out bytes.Buffer
	err = followAuditLog(ctx, logFile.Name(), monitor.execKey, monitor.connectKey, monitor.fileKey, monitor, hostIdentity{HostName: "test-host", HostIP: "127.0.0.1"}, true, -1, false, &out, defaultListenerRescanInterval)
	if err != nil && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		t.Fatalf("followAuditLog: %v", err)
	}
	if out.Len() == 0 {
		t.Fatal("expected replayed event output, got empty output")
	}
	var event auditEvent
	if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &event); err != nil {
		t.Fatalf("unmarshal output: %v\n%s", err, out.String())
	}
	if event.CommandLine != "ps -ef334" || event.CWD != "/home/ks" {
		t.Fatalf("event = command_line %q cwd %q, want ps -ef334 /home/ks", event.CommandLine, event.CWD)
	}
}

func TestEmitExecEventFromRawAuditRecords(t *testing.T) {
	monitor := &processTreeMonitor{
		pidListener:      map[int]listenerInfo{},
		monitored:        map[int]bool{},
		exeMonitored:     map[string]bool{},
		execKey:          "tb_external_listener_exec",
		connectKey:       "tb_external_listener_connect",
		fileKey:          "tb_external_listener_file",
		cloneKey:         "tb_external_listener_clone",
		selfBranch:       map[int]bool{},
		trackDescendants: true,
	}
	accs := map[string]*auditAccumulator{}
	lines := []string{
		`type=SYSCALL msg=audit(1782320671.957:88920): arch=c000003e syscall=59 success=yes exit=0 a0=5d9634fde0f0 a1=5d9634fcc780 a2=5d963535fd50 a3=5d9634fcc780 items=2 ppid=125609 pid=126350 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=316 comm="ps" exe="/usr/bin/ps" subj=unconfined key="tb_external_listener_exec" ARCH=x86_64 SYSCALL=execve AUID="ks" UID="ks" GID="ks" EUID="ks" SUID="ks" FSUID="ks" EGID="ks" SGID="ks" FSGID="ks"`,
		`type=EXECVE msg=audit(1782320671.957:88920): argc=2 a0="ps" a1="-ef334"`,
		`type=CWD msg=audit(1782320671.957:88920): cwd="/home/ks"`,
		`type=PATH msg=audit(1782320671.957:88920): item=0 name="/usr/bin/ps" inode=918726 dev=08:02 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0 OUID="root" OGID="root"`,
		`type=PROCTITLE msg=audit(1782320671.957:88920): proctitle=7073002D6566333334`,
	}
	var out bytes.Buffer
	for _, line := range lines {
		id, _ := consumeAuditLine(accs, line)
		if id != "" {
			emitOneReady(accs, id, monitor.execKey, monitor.connectKey, monitor.fileKey, monitor, hostIdentity{HostName: "test-host", HostIP: "127.0.0.1"}, false, &out)
		}
		emitReady(accs, monitor.execKey, monitor.connectKey, monitor.fileKey, monitor, hostIdentity{HostName: "test-host", HostIP: "127.0.0.1"}, false, &out, 0)
	}
	emitReady(accs, monitor.execKey, monitor.connectKey, monitor.fileKey, monitor, hostIdentity{HostName: "test-host", HostIP: "127.0.0.1"}, false, &out, execRecordSettleDelay)

	if out.Len() == 0 {
		t.Fatalf("expected event output, got empty output")
	}
	var event auditEvent
	if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &event); err != nil {
		t.Fatalf("unmarshal output: %v\n%s", err, out.String())
	}
	if event.EventType != "exec" {
		t.Fatalf("event_type = %q, want exec", event.EventType)
	}
	if event.AuditID != "88920" {
		t.Fatalf("audit_id = %q, want 88920", event.AuditID)
	}
	if event.PID != "126350" || event.PPID != "125609" {
		t.Fatalf("pid/ppid = %q/%q, want 126350/125609", event.PID, event.PPID)
	}
	if event.CommandLine != "ps -ef334" {
		t.Fatalf("command_line = %q, want ps -ef334", event.CommandLine)
	}
	if event.CWD != "/home/ks" {
		t.Fatalf("cwd = %q, want /home/ks", event.CWD)
	}
	if event.TTY != "pts0" || event.HasTTY == nil || !*event.HasTTY {
		t.Fatalf("tty/has_tty = %q/%v, want pts0/true", event.TTY, event.HasTTY)
	}
}

func TestParseTTYInfoPreservesUnknownState(t *testing.T) {
	if tty, hasTTY := parseTTYInfo(map[string]string{}); tty != "" || hasTTY != nil {
		t.Fatalf("missing tty = %q/%v, want unknown", tty, hasTTY)
	}
	if tty, hasTTY := parseTTYInfo(map[string]string{"tty": "(none)"}); tty != "(none)" || hasTTY == nil || *hasTTY {
		t.Fatalf("non-interactive tty = %q/%v, want false", tty, hasTTY)
	}
}

func TestExecEventSettlesAfterExecveWithoutProctitle(t *testing.T) {
	accs := map[string]*auditAccumulator{}
	_, _ = consumeAuditLine(accs, `type=SYSCALL msg=audit(1782320671.957:88921): arch=c000003e syscall=59 success=yes exit=0 ppid=1 pid=2 auid=1000 uid=1000 tty=pts0 comm="ps" exe="/usr/bin/ps" key="tb_external_listener_exec"`)
	_, _ = consumeAuditLine(accs, `type=EXECVE msg=audit(1782320671.957:88921): argc=2 a0="ps" a1="-ef334"`)
	acc := accs["88921"]
	if acc == nil {
		t.Fatal("expected accumulator")
	}
	if execCommandIncomplete(acc, acc.lastRecordAt.Add(time.Millisecond)) {
		t.Fatal("valid EXECVE argv should not be incomplete")
	}
}

func TestConsumeAuditLineParsedSkipsRawRecordsWhenRawDisabled(t *testing.T) {
	accs := map[string]*auditAccumulator{}
	line := `type=SYSCALL msg=audit(1782320671.957:88933): arch=c000003e syscall=59 success=yes exit=0 ppid=1 pid=2 auid=1000 uid=1000 comm="sh" exe="/usr/bin/sh" key="tb_external_listener_exec"`
	id, _ := consumeAuditLineParsed(accs, line, parseFields(line), false)
	if id != "88933" {
		t.Fatalf("id = %q, want 88933", id)
	}
	if accs[id] == nil {
		t.Fatal("expected accumulator")
	}
	if len(accs[id].records) != 0 {
		t.Fatalf("raw records should not be retained when raw output is disabled: %#v", accs[id].records)
	}
}

func TestIsLoopbackConnectAddress(t *testing.T) {
	loopbacks := []string{
		"127.0.0.1",
		"127.0.0.2",
		"::1",
		"::ffff:127.0.0.1",
	}
	for _, address := range loopbacks {
		if !isLoopbackConnectAddress(address) {
			t.Fatalf("expected %s to be loopback", address)
		}
	}
	for _, address := range []string{"", "10.0.0.1", "192.168.1.10", "8.8.8.8", "2001:4860:4860::8888"} {
		if isLoopbackConnectAddress(address) {
			t.Fatalf("expected %s to be non-loopback", address)
		}
	}
}

func TestEmitActiveConnectFiltersLoopbackAddress(t *testing.T) {
	monitor := &processTreeMonitor{
		pidListener:      map[int]listenerInfo{},
		monitored:        map[int]bool{},
		exeMonitored:     map[string]bool{},
		execKey:          "tb_external_listener_exec",
		connectKey:       "tb_external_listener_connect",
		fileKey:          "tb_external_listener_file",
		cloneKey:         "tb_external_listener_clone",
		selfBranch:       map[int]bool{},
		trackDescendants: true,
	}
	accs := map[string]*auditAccumulator{}
	lines := []string{
		`type=SYSCALL msg=audit(1782320671.957:88930): arch=c000003e syscall=42 success=yes exit=0 ppid=100 pid=200 auid=1000 uid=1000 comm="curl" exe="/usr/bin/curl" key="tb_external_listener_connect"`,
		`type=SOCKADDR msg=audit(1782320671.957:88930): saddr=02001F907F0000010000000000000000`,
	}
	for _, line := range lines {
		_, _ = consumeAuditLine(accs, line)
	}
	var out bytes.Buffer
	emitReady(accs, monitor.execKey, monitor.connectKey, monitor.fileKey, monitor, hostIdentity{HostName: "test-host", HostIP: "10.0.0.10"}, false, &out, 0)
	if out.Len() != 0 {
		t.Fatalf("loopback active_connect should be filtered, got %s", out.String())
	}
}

func TestEmitActiveConnectKeepsNonLoopbackAddress(t *testing.T) {
	monitor := &processTreeMonitor{
		pidListener:      map[int]listenerInfo{},
		monitored:        map[int]bool{},
		exeMonitored:     map[string]bool{},
		execKey:          "tb_external_listener_exec",
		connectKey:       "tb_external_listener_connect",
		fileKey:          "tb_external_listener_file",
		cloneKey:         "tb_external_listener_clone",
		selfBranch:       map[int]bool{},
		trackDescendants: true,
	}
	accs := map[string]*auditAccumulator{}
	lines := []string{
		`type=SYSCALL msg=audit(1782320671.957:88931): arch=c000003e syscall=42 success=yes exit=0 ppid=100 pid=200 auid=1000 uid=1000 comm="curl" exe="/usr/bin/curl" key="tb_external_listener_connect"`,
		`type=SOCKADDR msg=audit(1782320671.957:88931): saddr=02001F90080808080000000000000000`,
	}
	for _, line := range lines {
		_, _ = consumeAuditLine(accs, line)
	}
	var out bytes.Buffer
	emitReady(accs, monitor.execKey, monitor.connectKey, monitor.fileKey, monitor, hostIdentity{HostName: "test-host", HostIP: "10.0.0.10"}, false, &out, 0)
	if out.Len() == 0 {
		t.Fatal("non-loopback active_connect should be emitted")
	}
	var event auditEvent
	if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &event); err != nil {
		t.Fatalf("unmarshal active_connect output: %v\n%s", err, out.String())
	}
	if event.EventType != "active_connect" || event.ConnectAddress != "8.8.8.8" || event.ConnectPort != 8080 {
		t.Fatalf("unexpected active_connect event: %+v", event)
	}
}

func TestEmitActiveConnectFiltersNonIPFamily(t *testing.T) {
	monitor := &processTreeMonitor{
		pidListener:      map[int]listenerInfo{},
		monitored:        map[int]bool{},
		exeMonitored:     map[string]bool{},
		execKey:          "tb_external_listener_exec",
		connectKey:       "tb_external_listener_connect",
		fileKey:          "tb_external_listener_file",
		cloneKey:         "tb_external_listener_clone",
		selfBranch:       map[int]bool{},
		trackDescendants: true,
	}
	accs := map[string]*auditAccumulator{}
	lines := []string{
		`type=SYSCALL msg=audit(1782320671.957:88932): arch=c000003e syscall=42 success=yes exit=0 ppid=100 pid=200 auid=1000 uid=1000 comm="nscd" exe="/usr/sbin/nscd" key="tb_external_listener_connect"`,
		`type=SOCKADDR msg=audit(1782320671.957:88932): saddr=01002F7661722F72756E2F6E7363642F736F636B657400`,
	}
	for _, line := range lines {
		_, _ = consumeAuditLine(accs, line)
	}
	var out bytes.Buffer
	emitReady(accs, monitor.execKey, monitor.connectKey, monitor.fileKey, monitor, hostIdentity{HostName: "test-host", HostIP: "10.0.0.10"}, false, &out, 0)
	if out.Len() != 0 {
		t.Fatalf("non-IP active_connect should be filtered, got %s", out.String())
	}
}

func TestEmitDropsSelfAuditEvent(t *testing.T) {
	monitor := &processTreeMonitor{
		selfPID:          200,
		selfExe:          "/usr/local/bin/secweaver-agent",
		selfBranch:       map[int]bool{100: true, 200: true},
		pidListener:      map[int]listenerInfo{},
		monitored:        map[int]bool{},
		exeMonitored:     map[string]bool{},
		execKey:          "tb_external_listener_exec",
		connectKey:       "tb_external_listener_connect",
		fileKey:          "tb_external_listener_file",
		cloneKey:         "tb_external_listener_clone",
		monitorExec:      true,
		trackDescendants: true,
	}
	accs := map[string]*auditAccumulator{}
	lines := []string{
		`type=SYSCALL msg=audit(1782320671.957:88940): arch=c000003e syscall=59 success=yes exit=0 ppid=100 pid=300 auid=0 uid=0 tty=(none) comm="auditctl" exe="/usr/bin/auditctl" key="tb_external_listener_exec"`,
		`type=EXECVE msg=audit(1782320671.957:88940): argc=2 a0="auditctl" a1="-l"`,
		`type=PROCTITLE msg=audit(1782320671.957:88940): proctitle=617564697463746C002D6C`,
	}
	for _, line := range lines {
		_, _ = consumeAuditLine(accs, line)
	}
	var out bytes.Buffer
	emitReady(accs, monitor.execKey, monitor.connectKey, monitor.fileKey, monitor, hostIdentity{HostName: "test-host", HostIP: "127.0.0.1"}, false, &out, 0)
	if out.Len() != 0 {
		t.Fatalf("expected self audit event to be dropped, got: %s", out.String())
	}
}

func TestEmitDropsAuditctlRuleMaintenanceWithUnknownProcess(t *testing.T) {
	monitor := &processTreeMonitor{
		pidListener:      map[int]listenerInfo{},
		monitored:        map[int]bool{},
		exeMonitored:     map[string]bool{},
		execKey:          "tb_external_listener_exec",
		connectKey:       "tb_external_listener_connect",
		fileKey:          "tb_external_listener_file",
		cloneKey:         "tb_external_listener_clone",
		monitorExec:      true,
		trackDescendants: true,
	}
	accs := map[string]*auditAccumulator{}
	lines := []string{
		`type=SYSCALL msg=audit(1782320671.957:88941): arch=c000003e syscall=59 success=yes exit=0 pid=0 auid=4294967295 tty=(none) key="tb_external_listener_exec"`,
		`type=EXECVE msg=audit(1782320671.957:88941): argc=15 a0="auditctl" a1="-d" a2="always,exit" a3="-F" a4="arch" a5="b64" a6="-S" a7="execve" a8="-S" a9="execveat" a10="-F" a11="ppid" a12="3319400" a13="-k" a14="tb_external_listener_exec"`,
	}
	for _, line := range lines {
		_, _ = consumeAuditLine(accs, line)
	}
	var out bytes.Buffer
	emitReady(accs, monitor.execKey, monitor.connectKey, monitor.fileKey, monitor, hostIdentity{HostName: "test-host", HostIP: "127.0.0.1"}, false, &out, execRecordSettleDelay)
	if out.Len() != 0 {
		t.Fatalf("expected auditctl maintenance event to be dropped, got: %s", out.String())
	}
}

func TestEmitDropsAuditctlRuleMaintenanceWithProcessIdentity(t *testing.T) {
	monitor := &processTreeMonitor{
		pidListener:      map[int]listenerInfo{},
		monitored:        map[int]bool{},
		exeMonitored:     map[string]bool{},
		execKey:          "tb_external_listener_exec",
		connectKey:       "tb_external_listener_connect",
		fileKey:          "tb_external_listener_file",
		cloneKey:         "tb_external_listener_clone",
		monitorExec:      true,
		trackDescendants: true,
	}
	accs := map[string]*auditAccumulator{}
	lines := []string{
		`type=SYSCALL msg=audit(1782320671.957:88942): arch=c000003e syscall=59 success=yes exit=0 pid=501 ppid=500 auid=4294967295 tty=(none) comm="auditctl" exe="/usr/sbin/auditctl" key="tb_external_listener_exec"`,
		`type=EXECVE msg=audit(1782320671.957:88942): argc=15 a0="auditctl" a1="-d" a2="always,exit" a3="-F" a4="arch" a5="b64" a6="-S" a7="execve" a8="-S" a9="execveat" a10="-F" a11="pid" a12="3333630" a13="-k" a14="tb_external_listener_exec"`,
	}
	for _, line := range lines {
		_, _ = consumeAuditLine(accs, line)
	}
	var out bytes.Buffer
	emitReady(accs, monitor.execKey, monitor.connectKey, monitor.fileKey, monitor, hostIdentity{HostName: "test-host", HostIP: "127.0.0.1"}, false, &out, execRecordSettleDelay)
	if out.Len() != 0 {
		t.Fatalf("expected auditctl maintenance event with process identity to be dropped, got: %s", out.String())
	}
}

func TestSelfAuditctlMaintenanceDropsSecweaverRuleMutationWithProcessIdentity(t *testing.T) {
	fields := map[string]string{
		"pid":  "1234",
		"ppid": "100",
		"comm": "auditctl",
		"exe":  "/usr/sbin/auditctl",
		"key":  "tb_external_listener_exec",
	}
	command := []string{"auditctl", "-d", "always,exit", "-k", "tb_external_listener_exec"}
	if !isSelfAuditctlMaintenance(fields, command) {
		t.Fatal("expected secweaver auditctl rule delete to be dropped even with process identity")
	}
}

func TestSelfAuditctlMaintenanceKeepsAuditctlQueryWithProcessIdentity(t *testing.T) {
	fields := map[string]string{
		"pid":  "1234",
		"ppid": "100",
		"comm": "auditctl",
		"exe":  "/usr/sbin/auditctl",
		"key":  "tb_external_listener_exec",
	}
	command := []string{"auditctl", "-l"}
	if isSelfAuditctlMaintenance(fields, command) {
		t.Fatal("auditctl query with process identity should remain visible")
	}
}

func TestCommandReferencesSecweaverAuditKeyFromFieldSyntax(t *testing.T) {
	cases := [][]string{
		{"auditctl", "-d", "always,exit", "-F", "key=tb_external_listener_exec"},
		{"auditctl", "-d", "always,exit", "-F", "key", "tb_port_443_exec"},
	}
	for _, command := range cases {
		if !commandReferencesSecweaverAuditKey(command) {
			t.Fatalf("expected command to reference secweaver key: %#v", command)
		}
	}
}

func TestEmitSensitiveFileReadRequiresListenerMatch(t *testing.T) {
	gateway := listenerInfo{PID: 1234, Process: "nginx", Address: "0.0.0.0", Port: 443, MonitorExe: "/usr/sbin/nginx", ExeOnly: true}
	monitor := &processTreeMonitor{
		listeners:                 []listenerInfo{gateway},
		pidListener:               map[int]listenerInfo{},
		monitored:                 map[int]bool{},
		exeMonitored:              map[string]bool{},
		execKey:                   "tb_external_listener_exec",
		connectKey:                "tb_external_listener_connect",
		fileKey:                   "tb_external_listener_file",
		sensitiveFileKey:          "tb_external_listener_sensitive",
		cloneKey:                  "tb_external_listener_clone",
		selfBranch:                map[int]bool{},
		trackDescendants:          true,
		monitorSensitiveFileReads: true,
		sensitiveFilePaths:        defaultSensitiveFilePaths,
	}
	accs := map[string]*auditAccumulator{}
	lines := []string{
		`type=SYSCALL msg=audit(1782320671.957:88931): arch=c000003e syscall=2 success=yes exit=3 a0=7fff... a1=0 a2=0 ppid=1234 pid=2345 auid=4294967295 uid=33 gid=33 euid=33 suid=33 fsuid=33 egid=33 sgid=33 fsgid=33 tty=(none) ses=4294967295 comm="nginx" exe="/usr/sbin/nginx" key="tb_external_listener_sensitive"`,
		`type=PATH msg=audit(1782320671.957:88931): item=0 name="/etc/shadow" inode=123 mode=0100640 ouid=0 ogid=42 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0`,
	}
	for _, line := range lines {
		_, _ = consumeAuditLine(accs, line)
	}
	var out bytes.Buffer
	emitReady(accs, monitor.execKey, monitor.connectKey, monitor.fileKey, monitor, hostIdentity{HostName: "test-host", HostIP: "192.0.2.91"}, false, &out, 0)
	if out.Len() == 0 {
		t.Fatal("expected sensitive file read event to be emitted")
	}
	var event auditEvent
	if err := json.Unmarshal([]byte(strings.TrimSpace(out.String())), &event); err != nil {
		t.Fatalf("decode event: %v", err)
	}
	if event.EventType != "file_op" || event.FileAction != "read_sensitive_file" {
		t.Fatalf("unexpected event: type=%q action=%q", event.EventType, event.FileAction)
	}
	if len(event.FilePaths) != 1 || event.FilePaths[0] != "/etc/shadow" {
		t.Fatalf("unexpected file paths: %#v", event.FilePaths)
	}
	if event.ListenerPID != 1234 || event.ListenerPort != 443 {
		t.Fatalf("unexpected listener context: pid=%d port=%d", event.ListenerPID, event.ListenerPort)
	}
}

func TestEmitSensitiveFileReadDropsNonListenerProcess(t *testing.T) {
	gateway := listenerInfo{PID: 1234, Process: "nginx", Address: "0.0.0.0", Port: 443, MonitorExe: "/usr/sbin/nginx", ExeOnly: true}
	monitor := &processTreeMonitor{
		listeners:                 []listenerInfo{gateway},
		pidListener:               map[int]listenerInfo{},
		monitored:                 map[int]bool{},
		exeMonitored:              map[string]bool{},
		execKey:                   "tb_external_listener_exec",
		connectKey:                "tb_external_listener_connect",
		fileKey:                   "tb_external_listener_file",
		sensitiveFileKey:          "tb_external_listener_sensitive",
		cloneKey:                  "tb_external_listener_clone",
		selfBranch:                map[int]bool{},
		trackDescendants:          true,
		monitorSensitiveFileReads: true,
		sensitiveFilePaths:        defaultSensitiveFilePaths,
	}
	accs := map[string]*auditAccumulator{}
	lines := []string{
		`type=SYSCALL msg=audit(1782320671.958:88932): arch=c000003e syscall=2 success=yes exit=3 ppid=1 pid=9999 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none) ses=4294967295 comm="cat" exe="/usr/bin/cat" key="tb_external_listener_sensitive"`,
		`type=PATH msg=audit(1782320671.958:88932): item=0 name="/etc/shadow" inode=124 mode=0100640 ouid=0 ogid=42 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0`,
	}
	for _, line := range lines {
		_, _ = consumeAuditLine(accs, line)
	}
	var out bytes.Buffer
	emitReady(accs, monitor.execKey, monitor.connectKey, monitor.fileKey, monitor, hostIdentity{HostName: "test-host", HostIP: "192.0.2.91"}, false, &out, 0)
	if out.Len() != 0 {
		t.Fatalf("expected non-listener sensitive read to be dropped, got: %s", out.String())
	}
}

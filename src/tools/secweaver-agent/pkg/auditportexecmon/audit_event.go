package auditportexecmon

import (
	"encoding/json"

	"fmt"
	"io"
	"net"

	"strconv"
	"strings"

	"time"
)

// This file assembles parsed audit records into SecWeaver events and performs event-level classification.

func consumeAuditLine(accs map[string]*auditAccumulator, line string) (id string, ready bool) {
	return consumeAuditLineParsed(accs, line, parseFields(line), true)
}

// consumeAuditLineParsed joins one raw record into its audit-ID accumulator.
// A new accumulator is created only from a keyed primary record. Linux audit
// emits SYSCALL before its unkeyed auxiliary records; enforcing that assumption
// prevents unrelated host PATH/EXECVE traffic from filling this module's map.
func consumeAuditLineParsed(accs map[string]*auditAccumulator, line string, lineFields map[string]string, keepRaw bool) (id string, ready bool) {
	id = extractMsgID(line)
	if id == "" {
		return "", false
	}
	recordType := lineFields["type"]
	acc := accs[id]
	if acc == nil {
		_, hasKey := lineFields["key"]
		if !hasKey {
			return id, false
		}
		// P1 Optimization: Use object pool to reduce allocations
		acc = getAccumulator(id)
		accs[id] = acc
		recordAccumulatorCreated()
	}
	acc.lastRecordAt = time.Now()
	if keepRaw {
		acc.records = append(acc.records, line)
	}
	for k, v := range lineFields {
		if _, exists := acc.fields[k]; !exists || k == "key" {
			acc.fields[k] = v
		}
	}
	if recordType == "PROCTITLE" {
		acc.seenProctitle = true
		ready = true
		if pt := lineFields["proctitle"]; pt != "" {
			acc.proctitle = pt
		}
	}
	if recordType == "EXECVE" {
		acc.seenExecve = true
		ready = true
		for k, v := range lineFields {
			if len(k) >= 2 && k[0] == 'a' {
				if idx, err := strconv.Atoi(k[1:]); err == nil {
					acc.argv[idx] = v
				}
			}
		}
	}
	if recordType == "SYSCALL" {
		acc.seenSyscall = true
	}
	if recordType == "CWD" {
		if cwd := lineFields["cwd"]; cwd != "" {
			acc.cwd = cwd
		}
	}
	if recordType == "PATH" {
		if name := lineFields["name"]; name != "" {
			item, _ := strconv.Atoi(lineFields["item"])
			acc.paths[item] = name
		}
	}
	return id, ready
}

// emitReady performs age-based completion for records whose final auxiliary
// line is absent or delayed. Immediate completion is still attempted for each
// EXECVE/PROCTITLE record to minimize normal event latency.
func emitReady(accs map[string]*auditAccumulator, execKey, connectKey, fileKey string, monitor *processTreeMonitor, host hostIdentity, printRaw bool, out io.Writer, maxAge time.Duration) {
	now := time.Now()
	for id := range accs {
		emitOne(accs, id, execKey, connectKey, fileKey, monitor, host, printRaw, out, maxAge, now)
	}
}

func emitOneReady(accs map[string]*auditAccumulator, id, execKey, connectKey, fileKey string, monitor *processTreeMonitor, host hostIdentity, printRaw bool, out io.Writer) {
	emitOne(accs, id, execKey, connectKey, fileKey, monitor, host, printRaw, out, 0, time.Now())
}

func emitOne(accs map[string]*auditAccumulator, id, execKey, connectKey, fileKey string, monitor *processTreeMonitor, host hostIdentity, printRaw bool, out io.Writer, maxAge time.Duration, now time.Time) {
	// This is the semantic boundary between raw audit records and the stable JSON
	// asset contract. Filtering happens before serialization so maintenance noise,
	// loopback connects, and unrelated sensitive-file reads never reach disk.
	acc := accs[id]
	if acc == nil {
		return
	}
	if maxAge > 0 && now.Sub(acc.firstSeen) < maxAge {
		return
	}
	key := acc.fields["key"]
	eventType := ""
	isSensitiveRead := key == monitor.sensitiveFileKey
	if key == execKey {
		eventType = "exec"
	} else if key == connectKey {
		eventType = "active_connect"
	} else if key == fileKey || isSensitiveRead {
		eventType = "file_op"
	}
	if monitor.isSelfAuditFields(acc.fields) {
		delete(accs, id)
		putAccumulator(acc) // P1 Optimization: Return to pool
		recordAccumulatorCompleted()
		return
	}
	comm := normalizeComm(acc.fields["comm"], acc.fields["exe"])
	command := resolveCommand(acc.argv, acc.proctitle, acc.fields["exe"], comm)
	if isSelfAuditctlMaintenance(acc.fields, command) {
		delete(accs, id)
		putAccumulator(acc) // P1 Optimization: Return to pool
		recordAccumulatorCompleted()
		return
	}
	if eventType == "" || (eventType == "exec" && len(command) == 0) {
		if now.Sub(acc.firstSeen) > 5*time.Second {
			delete(accs, id)
			putAccumulator(acc) // P1 Optimization: Return to pool
			recordAccumulatorExpired()
		}
		return
	}
	if eventType == "exec" && execRecordPending(acc, now, maxAge) {
		return
	}
	if eventType == "active_connect" && acc.fields["saddr"] == "" && maxAge == 0 {
		return
	}
	if eventType == "file_op" && len(acc.paths) == 0 && maxAge == 0 {
		return
	}
	listener, listenerMatched := monitor.matchListener(acc.fields)
	if monitor.usesBoundedAudit() && !listenerMatched {
		delete(accs, id)
		putAccumulator(acc)
		recordAccumulatorCompleted()
		return
	}
	if isSensitiveRead {
		if !listenerMatched {
			delete(accs, id)
			putAccumulator(acc) // P1 Optimization: Return to pool
			recordAccumulatorCompleted()
			return
		}
		if len(filterSensitivePaths(orderedPaths(acc.paths), monitor.sensitiveFilePaths)) == 0 {
			delete(accs, id)
			putAccumulator(acc) // P1 Optimization: Return to pool
			recordAccumulatorCompleted()
			return
		}
	}
	tty, hasTTY := parseTTYInfo(acc.fields)
	pid, pidName := splitProcessFields(acc.fields["pid"], comm, acc.fields["exe"])
	ppid, ppidName := splitProcessFields(acc.fields["ppid"], "", "")
	event := auditEvent{
		Time:        now,
		HostName:    host.HostName,
		HostIP:      host.HostIP,
		EventType:   eventType,
		AuditID:     id,
		PID:         pid,
		PIDName:     pidName,
		PPID:        ppid,
		PPIDName:    ppidName,
		UID:         acc.fields["uid"],
		UIDName:     resolveAccountName(acc.fields["uid"]),
		AUID:        acc.fields["auid"],
		AUIDName:    resolveAccountName(acc.fields["auid"]),
		Comm:        comm,
		Exe:         acc.fields["exe"],
		CWD:         acc.cwd,
		Command:     command,
		CommandLine: strings.Join(command, " "),
		Success:     acc.fields["success"],
		Exit:        acc.fields["exit"],
		Key:         acc.fields["key"],
		TTY:         tty,
		HasTTY:      hasTTY,
		Fields:      acc.fields,
	}
	if listenerMatched {
		event.ListenerPID = listener.PID
		event.ListenerProcess = listener.Process
		event.ListenerAddress = listener.Address
		event.ListenerPort = listener.Port
		if eventType == "exec" {
			pid, _ := strconv.Atoi(acc.fields["pid"])
			ppid, _ := strconv.Atoi(acc.fields["ppid"])
			if target, ok := monitor.resolveTrackingTarget(pid, ppid, acc.fields["exe"]); ok && target.ExpandDescendants {
				monitor.trackProcessChain(pid, ppid, target.Gateway)
			}
		}
	}
	if eventType == "active_connect" {
		family, address, port := parseSockaddr(acc.fields)
		if family != "ipv4" && family != "ipv6" {
			delete(accs, id)
			putAccumulator(acc) // P1 Optimization: Return to pool
			recordAccumulatorCompleted()
			return
		}
		if isLoopbackConnectAddress(address) {
			delete(accs, id)
			putAccumulator(acc) // P1 Optimization: Return to pool
			recordAccumulatorCompleted()
			return
		}
		event.ConnectFamily = family
		event.ConnectAddress = address
		event.ConnectPort = port
	}
	if eventType == "file_op" {
		if isSensitiveRead {
			event.FilePaths = filterSensitivePaths(orderedPaths(acc.paths), monitor.sensitiveFilePaths)
			event.FileAction = "read_sensitive_file"
		} else {
			event.FileAction = classifyFileAction(acc.fields)
			event.FilePaths = orderedPaths(acc.paths)
		}
	}
	if printRaw {
		event.RawRecords = acc.records
	}
	b, _ := json.Marshal(event)
	fmt.Fprintln(out, string(b))
	delete(accs, id)
	putAccumulator(acc) // P1 Optimization: Return to pool
	recordAccumulatorCompleted()
	recordEventProcessed()
}

// parseTTYInfo preserves the distinction between a known non-interactive audit
// record and a record that did not contain TTY evidence. Returning nil for the
// latter prevents missing data from becoming a false non-interactive signal.
func parseTTYInfo(fields map[string]string) (tty string, hasTTY *bool) {
	tty = strings.TrimSpace(fields["tty"])
	if tty == "" {
		return "", nil
	}
	normalized := strings.Trim(strings.ToLower(tty), "()")
	observed := true
	if normalized == "" || normalized == "none" || normalized == "0" {
		observed = false
	}
	return tty, &observed
}

func classifyFileAction(fields map[string]string) string {
	syscallNum, _ := strconv.Atoi(fields["syscall"])
	switch syscallNum {
	case 2:
		return "open_maybe_create"
	case 85:
		return "create_file"
	case 257, 437:
		return "openat_maybe_create"
	case 82, 264, 316:
		return "rename"
	case 83, 258:
		return "create_dir"
	case 84:
		return "delete_dir"
	case 86, 265, 88, 266:
		return "create_link"
	case 87, 263:
		return "delete_file"
	case 133, 259:
		return "create_node"
	default:
		if syscallNum > 0 {
			return fmt.Sprintf("syscall_%d", syscallNum)
		}
		return "file_op"
	}
}

func orderedPaths(paths map[int]string) []string {
	if len(paths) == 0 {
		return nil
	}
	max := 0
	for i := range paths {
		if i > max {
			max = i
		}
	}
	out := make([]string, 0, len(paths))
	for i := 0; i <= max; i++ {
		if v, ok := paths[i]; ok {
			out = append(out, v)
		}
	}
	return out
}

func parseSockaddr(fields map[string]string) (string, string, int) {
	// audit saddr stores sa_family in host byte order and port in network byte
	// order. IPv6 addresses begin after family, port, flowinfo, matching
	// sockaddr_in6 layout.
	saddr := fields["saddr"]
	if saddr == "" {
		return "", "", 0
	}
	decoded, err := hexStringToBytes(saddr)
	if err != nil || len(decoded) < 4 {
		return "raw", saddr, 0
	}
	family := int(decoded[0]) | int(decoded[1])<<8
	switch family {
	case 2:
		if len(decoded) < 8 {
			return "ipv4", "", 0
		}
		port := int(decoded[2])<<8 | int(decoded[3])
		addr := net.IPv4(decoded[4], decoded[5], decoded[6], decoded[7]).String()
		return "ipv4", addr, port
	case 10:
		if len(decoded) < 28 {
			return "ipv6", "", 0
		}
		port := int(decoded[2])<<8 | int(decoded[3])
		addr := net.IP(decoded[8:24]).String()
		return "ipv6", addr, port
	default:
		return fmt.Sprintf("family_%d", family), saddr, 0
	}
}

func isLoopbackConnectAddress(address string) bool {
	ip := net.ParseIP(strings.TrimSpace(address))
	if ip == nil {
		return false
	}
	return ip.IsLoopback()
}

func hexStringToBytes(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("odd hex length")
	}
	out := make([]byte, len(s)/2)
	for i := 0; i < len(out); i++ {
		b, err := strconv.ParseUint(s[i*2:i*2+2], 16, 8)
		if err != nil {
			return nil, err
		}
		out[i] = byte(b)
	}
	return out, nil
}

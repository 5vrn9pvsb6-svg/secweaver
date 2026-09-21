package hostpersistence

import (
	"encoding/hex"

	"os/user"
	"path/filepath"

	"sort"
	"strconv"
	"strings"

	"time"
)

// This file converts accumulated audit records into actor evidence and enriches persistence events without changing scanner ownership.

func auditChangeFromAccumulator(acc *auditAccumulator) auditChange {
	uid := acc.fields["uid"]
	auid := acc.fields["auid"]
	paths := make([]string, 0, len(acc.paths))
	for _, path := range acc.paths {
		if path != "" {
			paths = append(paths, filepath.Clean(path))
		}
	}
	sort.Strings(paths)
	// Store ingestion time rather than parsing the textual audit timestamp. The
	// tracker correlates against a near-real-time polling observation and uses a
	// generous bounded window, avoiding timezone/clock-format dependencies.
	return auditChange{
		Timestamp: time.Now(),
		AuditID:   acc.id,
		UID:       uid,
		UIDName:   lookupUserName(uid),
		AUID:      auid,
		AUIDName:  lookupUserName(auid),
		PID:       acc.fields["pid"],
		PPID:      acc.fields["ppid"],
		Process:   normalizeProcessName(acc.fields["comm"], acc.fields["exe"]),
		Exe:       acc.fields["exe"],
		Command:   resolveAuditCommand(acc.argv, acc.proctitle, acc.fields["exe"], acc.fields["comm"]),
		Syscall:   acc.fields["syscall"],
		Paths:     paths,
	}
}

func enrichWithAudit(event *persistenceEvent, change auditChange) {
	event.User = firstNonEmpty(change.AUIDName, change.UIDName)
	event.UID = change.UID
	event.AUID = change.AUID
	event.AUIDName = change.AUIDName
	event.PID = change.PID
	event.PPID = change.PPID
	event.Process = change.Process
	event.Exe = change.Exe
	event.Command = change.Command
	event.AuditID = change.AuditID
	event.AuditSyscall = change.Syscall
	event.ActorSource = "auditd"
}

func extractAuditMsgID(line string) string {
	m := auditMsgIDPattern.FindStringSubmatch(line)
	if len(m) == 2 {
		return m[1]
	}
	return ""
}

func parseAuditFields(line string) map[string]string {
	fields := map[string]string{}
	for _, m := range auditFieldPattern.FindAllStringSubmatch(line, -1) {
		if len(m) != 3 {
			continue
		}
		fields[m[1]] = unquoteAuditValue(m[2])
	}
	return fields
}

func unquoteAuditValue(value string) string {
	if strings.HasPrefix(value, `"`) && strings.HasSuffix(value, `"`) {
		if unquoted, err := strconv.Unquote(value); err == nil {
			return unquoted
		}
		return strings.Trim(value, `"`)
	}
	return value
}

func resolveAuditCommand(argv map[int]string, proctitle, exe, comm string) string {
	// EXECVE argv is the most faithful command representation. PROCTITLE is the
	// fallback for syscall families or audit configurations without EXECVE data.
	if len(argv) > 0 {
		keys := make([]int, 0, len(argv))
		for k := range argv {
			keys = append(keys, k)
		}
		sort.Ints(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, argv[k])
		}
		return strings.Join(parts, " ")
	}
	if decoded := decodeAuditProctitle(proctitle); decoded != "" {
		return decoded
	}
	return firstNonEmpty(exe, comm)
}

func decodeAuditProctitle(value string) string {
	if value == "" {
		return ""
	}
	raw, err := hex.DecodeString(value)
	if err != nil {
		return ""
	}
	for i, b := range raw {
		if b == 0 {
			raw[i] = ' '
		}
	}
	return strings.TrimSpace(string(raw))
}

func normalizeProcessName(comm, exe string) string {
	if strings.TrimSpace(comm) != "" {
		return strings.TrimSpace(comm)
	}
	if strings.TrimSpace(exe) != "" {
		return filepath.Base(exe)
	}
	return ""
}

func lookupUserName(id string) string {
	id = strings.TrimSpace(id)
	if id == "" || id == "4294967295" || id == "-1" {
		return ""
	}
	if cached, ok := userNameCache.Load(id); ok {
		return cached.(string)
	}
	// NSS lookups may consult LDAP/SSSD and are expensive on the audit hot path;
	// cache both successful and empty results for the process lifetime.
	name := ""
	if u, err := user.LookupId(id); err == nil {
		name = u.Username
	}
	userNameCache.Store(id, name)
	return name
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

package auditportexecmon

import "strconv"

// procNetSocketInode uses the fixed Linux TCP table column. Transport statistics
// follow inode and vary in number, so indexing backwards can lose every owner.
func procNetSocketInode(fields []string) string {
	if len(fields) < 10 {
		return ""
	}
	inode, err := strconv.ParseUint(fields[9], 10, 64)
	if err != nil || inode == 0 {
		return ""
	}
	return strconv.FormatUint(inode, 10)
}

// verifiedListenerDescendant bounds companion registration to one live root.
// Recheck after walking /proc: a numeric root PID can be reused during the walk.
func verifiedListenerDescendant(listener listenerInfo, pid int) bool {
	if pid <= 1 || listener.PID <= 1 || listener.RootStartTime == 0 ||
		readProcessStartTime(listener.PID) != listener.RootStartTime {
		return false
	}
	childStart := readProcessStartTime(pid)
	if childStart == 0 {
		return false
	}
	seen := map[int]bool{}
	for current, depth := pid, 0; current > 1 && depth < 64; current, depth = readProcessParentPID(current), depth+1 {
		if seen[current] {
			return false
		}
		seen[current] = true
		if current == listener.PID {
			return readProcessStartTime(pid) == childStart && readProcessStartTime(listener.PID) == listener.RootStartTime
		}
	}
	return false
}

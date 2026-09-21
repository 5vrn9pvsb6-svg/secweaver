package hostprocesssnapshot

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	clockTicksOnce sync.Once
	clockTicks     int64 = 100
)

func collectLinuxProcesses(ctx context.Context, procRoot string, now time.Time) ([]processInfo, error) {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil, err
	}
	bootTime := linuxBootTime(procRoot)
	ticks := linuxClockTicks()
	userNames := linuxUserNames("/etc/passwd")
	processes := make([]processInfo, 0, len(entries)/4)
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 || !entry.IsDir() {
			continue
		}
		process, err := readLinuxProcess(procRoot, pid, bootTime, ticks, now, userNames)
		if err != nil {
			// Processes commonly exit between directory enumeration and file reads.
			continue
		}
		processes = append(processes, process)
	}
	return processes, nil
}

func readLinuxProcess(procRoot string, pid int, bootTime time.Time, ticks int64, now time.Time, userNames map[string]string) (processInfo, error) {
	base := filepath.Join(procRoot, strconv.Itoa(pid))
	statusBody, err := os.ReadFile(filepath.Join(base, "status"))
	if err != nil {
		return processInfo{}, err
	}
	fields := parseLinuxStatus(string(statusBody))
	process := processInfo{
		PID: pid, PPID: parseInt(fields["PPid"]), UID: firstField(fields["Uid"]),
		Process: fields["Name"], Comm: fields["Name"], StateName: fields["State"],
		ThreadCount: parseInt(fields["Threads"]), RSSBytes: parseKB(fields["VmRSS"]),
		VirtualBytes: parseKB(fields["VmSize"]),
	}
	if process.UID != "" {
		if cached, ok := userNames[process.UID]; ok {
			process.User = cached
		}
	}
	if exe, err := os.Readlink(filepath.Join(base, "exe")); err == nil {
		process.Exe = strings.TrimSuffix(exe, " (deleted)")
	}
	if cwd, err := os.Readlink(filepath.Join(base, "cwd")); err == nil {
		process.CWD = cwd
	}
	if body, err := os.ReadFile(filepath.Join(base, "cmdline")); err == nil {
		process.Command = splitNullArgs(body)
		process.CommandLine = joinCommand(process.Command)
	}
	if process.CommandLine == "" {
		process.CommandLine = process.Process
	}
	if process.Exe == "" && len(process.Command) > 0 {
		process.Exe = process.Command[0]
	}
	if statBody, err := os.ReadFile(filepath.Join(base, "stat")); err == nil {
		applyLinuxStat(&process, string(statBody), bootTime, ticks, now)
	}
	if cgroup, err := os.ReadFile(filepath.Join(base, "cgroup")); err == nil {
		process.Cgroup = compactCgroup(string(cgroup))
	}
	process.IsAgent = filepath.Base(process.Exe) == "secweaver-agent" || process.Process == "secweaver-agent"
	return process, nil
}

func linuxUserNames(path string) map[string]string {
	out := map[string]string{}
	body, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(body), "\n") {
		parts := strings.Split(line, ":")
		if len(parts) >= 3 && parts[0] != "" && parts[2] != "" {
			out[parts[2]] = parts[0]
		}
	}
	return out
}

func parseLinuxStatus(body string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(body, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if ok {
			out[strings.TrimSpace(key)] = strings.TrimSpace(value)
		}
	}
	return out
}

func applyLinuxStat(process *processInfo, body string, bootTime time.Time, ticks int64, now time.Time) {
	closeParen := strings.LastIndex(body, ")")
	if closeParen < 0 || closeParen+2 >= len(body) {
		return
	}
	values := strings.Fields(body[closeParen+2:])
	if len(values) < 22 {
		return
	}
	process.State = values[0]
	process.PPID = parseInt(values[1])
	process.CPUTimeMS = (parseInt64(values[11]) + parseInt64(values[12])) * 1000 / ticks
	if process.ThreadCount == 0 {
		process.ThreadCount = parseInt(values[17])
	}
	startTicks := parseInt64(values[19])
	if !bootTime.IsZero() && startTicks > 0 {
		started := bootTime.Add(time.Duration(startTicks) * time.Second / time.Duration(ticks)).UTC()
		process.StartTime = started.Format(time.RFC3339Nano)
		if now.After(started) {
			process.ElapsedSeconds = int64(now.Sub(started).Seconds())
		}
	}
	if process.VirtualBytes == 0 {
		process.VirtualBytes = parseInt64(values[20])
	}
	if process.RSSBytes == 0 {
		process.RSSBytes = parseInt64(values[21]) * int64(os.Getpagesize())
	}
}

func linuxBootTime(procRoot string) time.Time {
	body, err := os.ReadFile(filepath.Join(procRoot, "stat"))
	if err != nil {
		return time.Time{}
	}
	for _, line := range strings.Split(string(body), "\n") {
		if strings.HasPrefix(line, "btime ") {
			seconds := parseInt64(strings.TrimSpace(strings.TrimPrefix(line, "btime ")))
			if seconds > 0 {
				return time.Unix(seconds, 0).UTC()
			}
		}
	}
	return time.Time{}
}

func linuxClockTicks() int64 {
	clockTicksOnce.Do(func() {
		body, err := exec.Command("getconf", "CLK_TCK").Output()
		if err == nil {
			if value := parseInt64(strings.TrimSpace(string(body))); value > 0 {
				clockTicks = value
			}
		}
	})
	return clockTicks
}

func splitNullArgs(body []byte) []string {
	parts := strings.Split(strings.TrimRight(string(body), "\x00"), "\x00")
	if len(parts) == 1 && parts[0] == "" {
		return nil
	}
	return parts
}

func compactCgroup(body string) string {
	var paths []string
	seen := map[string]bool{}
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 3)
		if len(parts) == 3 && !seen[parts[2]] {
			seen[parts[2]] = true
			paths = append(paths, parts[2])
		}
	}
	return strings.Join(paths, ",")
}

func firstField(value string) string {
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

func parseKB(value string) int64 {
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return 0
	}
	return parseInt64(fields[0]) * 1024
}

func parseInt(value string) int {
	parsed, _ := strconv.Atoi(strings.TrimSpace(value))
	return parsed
}

func parseInt64(value string) int64 {
	parsed, _ := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	return parsed
}

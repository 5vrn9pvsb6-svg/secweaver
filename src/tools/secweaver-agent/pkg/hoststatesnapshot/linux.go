package hoststatesnapshot

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type socketOwner struct {
	PID     int
	Process string
}

func collectLinuxSockets(ctx context.Context, procRoot string, _ time.Time, maxFDScan int) ([]entity, error) {
	userCache := linuxUIDNames("/etc/passwd")
	var socketRows []map[string]any
	targetInodes := map[string]bool{}
	for _, spec := range []struct {
		path     string
		protocol string
		ipv6     bool
		udp      bool
	}{
		{filepath.Join(procRoot, "net/tcp"), "tcp", false, false},
		{filepath.Join(procRoot, "net/tcp6"), "tcp6", true, false},
		{filepath.Join(procRoot, "net/udp"), "udp", false, true},
		{filepath.Join(procRoot, "net/udp6"), "udp6", true, true},
	} {
		rows, err := parseProcNetFile(spec.path, spec.protocol, spec.ipv6, spec.udp)
		if err != nil && !os.IsNotExist(err) {
			return nil, err
		}
		for _, row := range rows {
			socketRows = append(socketRows, row)
			targetInodes[fmt.Sprint(row["socket_inode"])] = true
		}
	}
	owners, err := linuxSocketOwners(ctx, procRoot, targetInodes, maxFDScan)
	if err != nil {
		return nil, err
	}
	var entities []entity
	for _, row := range socketRows {
		uid := fmt.Sprint(row["uid"])
		username := userCache[uid]
		if username != "" {
			row["user"] = username
		}
		inode := fmt.Sprint(row["socket_inode"])
		fields := cloneFields(row)
		matchedOwners := owners[inode]
		sort.Slice(matchedOwners, func(i, j int) bool { return matchedOwners[i].PID < matchedOwners[j].PID })
		if len(matchedOwners) > 0 {
			pids := make([]string, 0, len(matchedOwners))
			processes := make([]string, 0, len(matchedOwners))
			for _, owner := range matchedOwners {
				pids = append(pids, strconv.Itoa(owner.PID))
				processes = append(processes, owner.Process)
			}
			fields["pid"] = pids[0]
			fields["process"] = processes[0]
			fields["pids"] = pids
			fields["processes"] = processes
		}
		key := fmt.Sprintf("%s|%v|%v|%s", fields["protocol"], fields["listen_address"], fields["listen_port"], inode)
		entities = append(entities, entity{Key: key, EntityType: "listening_socket", AssetType: "host_socket", Fields: fields})
	}
	return entities, nil
}

func linuxUIDNames(path string) map[string]string {
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

func parseProcNetFile(path, protocol string, ipv6, udp bool) ([]map[string]any, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var rows []map[string]any
	scanner := bufio.NewScanner(f)
	first := true
	for scanner.Scan() {
		if first {
			first = false
			continue
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			continue
		}
		state := strings.ToUpper(fields[3])
		if !udp && state != "0A" {
			continue
		}
		address, port, ok := decodeProcEndpoint(fields[1], ipv6)
		if !ok || port == 0 {
			continue
		}
		if udp {
			remoteAddress, remotePort, _ := decodeProcEndpoint(fields[2], ipv6)
			if remotePort != 0 || (remoteAddress != "" && remoteAddress != "0.0.0.0" && remoteAddress != "::") {
				continue
			}
		}
		rows = append(rows, map[string]any{
			"protocol": protocol, "listen_address": address, "listen_port": port,
			"socket_state": state, "uid": fields[7], "socket_inode": fields[9],
		})
	}
	return rows, scanner.Err()
}

func decodeProcEndpoint(value string, ipv6 bool) (string, int, bool) {
	addressHex, portHex, ok := strings.Cut(value, ":")
	if !ok {
		return "", 0, false
	}
	port64, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return "", 0, false
	}
	addressBytes, err := hex.DecodeString(addressHex)
	if err != nil {
		return "", 0, false
	}
	if !ipv6 && len(addressBytes) == 4 {
		addressBytes[0], addressBytes[3] = addressBytes[3], addressBytes[0]
		addressBytes[1], addressBytes[2] = addressBytes[2], addressBytes[1]
	} else if ipv6 && len(addressBytes) == 16 {
		for i := 0; i < 16; i += 4 {
			addressBytes[i], addressBytes[i+3] = addressBytes[i+3], addressBytes[i]
			addressBytes[i+1], addressBytes[i+2] = addressBytes[i+2], addressBytes[i+1]
		}
	} else {
		return "", 0, false
	}
	return net.IP(addressBytes).String(), int(port64), true
}

func linuxSocketOwners(ctx context.Context, procRoot string, targetInodes map[string]bool, maxFDScan int) (map[string][]socketOwner, error) {
	out := map[string][]socketOwner{}
	if len(targetInodes) == 0 {
		return out, nil
	}
	seen := map[string]bool{}
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 || !entry.IsDir() {
			continue
		}
		fds, err := os.ReadDir(filepath.Join(procRoot, entry.Name(), "fd"))
		if err != nil {
			continue
		}
		owner := socketOwner{PID: pid}
		for _, fd := range fds {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			maxFDScan--
			if maxFDScan < 0 {
				return nil, fmt.Errorf("listening socket owner scan exceeded max-fd-scan budget")
			}
			target, err := os.Readlink(filepath.Join(procRoot, entry.Name(), "fd", fd.Name()))
			if err != nil || !strings.HasPrefix(target, "socket:[") || !strings.HasSuffix(target, "]") {
				continue
			}
			inode := strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")
			if !targetInodes[inode] {
				continue
			}
			if owner.Process == "" {
				commBody, _ := os.ReadFile(filepath.Join(procRoot, entry.Name(), "comm"))
				owner.Process = strings.TrimSpace(string(commBody))
			}
			ownerKey := inode + "|" + strconv.Itoa(pid)
			if seen[ownerKey] {
				continue
			}
			seen[ownerKey] = true
			out[inode] = append(out[inode], owner)
		}
	}
	return out, nil
}

func collectLinuxIdentity(ctx context.Context, root string, _ time.Time) ([]entity, error) {
	passwdBody, err := os.ReadFile(rooted(root, "/etc/passwd"))
	if err != nil {
		return nil, err
	}
	groupBody, err := os.ReadFile(rooted(root, "/etc/group"))
	if err != nil {
		return nil, err
	}
	shadowBody, err := os.ReadFile(rooted(root, "/etc/shadow"))
	if err != nil {
		return nil, err
	}
	groups := parseLinuxGroups(string(groupBody))
	shadow := parseLinuxShadow(string(shadowBody))
	entities := parseLinuxPasswd(string(passwdBody), groups, shadow)
	if root == "/" {
		sessions, err := linuxLoginSessions(ctx)
		if err != nil {
			return nil, err
		}
		entities = append(entities, sessions...)
	}
	return entities, nil
}

// collectLinuxContainerIdentity intentionally avoids /etc/shadow and `who`.
// A regular Docker workload cannot read those host-oriented inputs, but its
// public account/group database is still useful for process attribution. The
// same entity shape is retained with an empty password-state map so downstream
// schemas do not need a separate container-only identity contract.
func collectLinuxContainerIdentity(root string, _ time.Time) ([]entity, error) {
	passwdBody, err := os.ReadFile(rooted(root, "/etc/passwd"))
	if err != nil {
		return nil, err
	}
	groupBody, err := os.ReadFile(rooted(root, "/etc/group"))
	if err != nil {
		return nil, err
	}
	return parseLinuxPasswd(string(passwdBody), parseLinuxGroups(string(groupBody)), nil), nil
}

func parseLinuxPasswd(body string, groups map[string][]string, shadow map[string]map[string]any) []entity {
	var entities []entity
	for _, line := range strings.Split(body, "\n") {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) < 7 {
			continue
		}
		uid, _ := strconv.Atoi(parts[2])
		userGroups := append([]string(nil), groups[parts[0]]...)
		sort.Strings(userGroups)
		fields := map[string]any{
			"user": parts[0], "uid": parts[2], "gid": parts[3], "gecos": parts[4],
			"home": parts[5], "shell": parts[6], "groups": userGroups,
			"system_account": uid != 0 && uid < 1000,
		}
		for key, value := range shadow[parts[0]] {
			fields[key] = value
		}
		entities = append(entities, entity{Key: "account:" + parts[0], EntityType: "identity_account", AssetType: "host_identity", Fields: fields})
	}
	return entities
}

func parseLinuxGroups(body string) map[string][]string {
	out := map[string][]string{}
	for _, line := range strings.Split(body, "\n") {
		parts := strings.Split(line, ":")
		if len(parts) < 4 {
			continue
		}
		for _, member := range strings.Split(parts[3], ",") {
			member = strings.TrimSpace(member)
			if member != "" {
				out[member] = append(out[member], parts[0])
			}
		}
	}
	return out
}

func parseLinuxShadow(body string) map[string]map[string]any {
	out := map[string]map[string]any{}
	for _, line := range strings.Split(body, "\n") {
		parts := strings.Split(line, ":")
		if len(parts) < 2 || parts[0] == "" {
			continue
		}
		password := parts[1]
		out[parts[0]] = map[string]any{
			"password_locked":  strings.HasPrefix(password, "!") || strings.HasPrefix(password, "*"),
			"password_present": password != "" && password != "!" && password != "*" && password != "!!",
		}
		if len(parts) > 2 && parts[2] != "" {
			out[parts[0]]["password_last_change_days"] = parts[2]
		}
	}
	return out
}

func linuxLoginSessions(ctx context.Context) ([]entity, error) {
	body, err := exec.CommandContext(ctx, "who").Output()
	if err != nil {
		return nil, err
	}
	var entities []entity
	for _, line := range strings.Split(string(body), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		source := ""
		if len(fields) > 4 {
			source = strings.Trim(fields[len(fields)-1], "()")
		}
		loginTime := fields[2] + " " + fields[3]
		key := strings.Join([]string{"session", fields[0], fields[1], loginTime, source}, "|")
		entities = append(entities, entity{Key: key, EntityType: "login_session", AssetType: "host_identity", Fields: map[string]any{
			"user": fields[0], "tty": fields[1], "login_time_text": loginTime, "source": source,
		}})
	}
	return entities, nil
}

func collectLinuxServices(ctx context.Context, root string, _ time.Time) ([]entity, error) {
	var entities []entity
	if root == "/" {
		serviceFiles, err := systemctlUnitFiles(ctx, "service")
		if err != nil {
			return nil, err
		}
		runtimeStates, err := systemctlServiceStates(ctx)
		if err != nil {
			return nil, err
		}
		for name, fields := range serviceFiles {
			for key, value := range runtimeStates[name] {
				fields[key] = value
			}
			fields["service_name"] = name
			if path, info := systemdUnitFile(name); path != "" && info != nil {
				fields["unit_path"] = path
				fields["unit_size"] = info.Size()
				fields["unit_mod_time"] = info.ModTime().UTC().Format(time.RFC3339Nano)
			}
			entities = append(entities, entity{Key: "service:" + name, EntityType: "service", AssetType: "host_service", Fields: fields})
		}
		timers, err := systemctlUnitFiles(ctx, "timer")
		if err != nil {
			return nil, err
		}
		for name, fields := range timers {
			fields["task_name"] = name
			fields["task_type"] = "systemd_timer"
			entities = append(entities, entity{Key: "timer:" + name, EntityType: "scheduled_task", AssetType: "host_service", Fields: fields})
		}
	}
	cronEntities, err := linuxCronEntities(root)
	if err != nil {
		return nil, err
	}
	entities = append(entities, cronEntities...)
	return entities, nil
}

func systemdUnitFile(name string) (string, os.FileInfo) {
	for _, dir := range []string{"/etc/systemd/system", "/run/systemd/system", "/usr/local/lib/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system"} {
		path := filepath.Join(dir, name)
		info, err := os.Stat(path)
		if err == nil && !info.IsDir() {
			return path, info
		}
	}
	return "", nil
}

func systemctlUnitFiles(ctx context.Context, unitType string) (map[string]map[string]any, error) {
	body, err := exec.CommandContext(ctx, "systemctl", "list-unit-files", "--type="+unitType, "--no-legend", "--no-pager", "--plain").Output()
	if err != nil {
		return nil, err
	}
	out := map[string]map[string]any{}
	for _, line := range strings.Split(string(body), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		item := map[string]any{"unit_file_state": fields[1]}
		if len(fields) > 2 {
			item["preset"] = fields[2]
		}
		out[fields[0]] = item
	}
	return out, nil
}

func systemctlServiceStates(ctx context.Context) (map[string]map[string]any, error) {
	body, err := exec.CommandContext(ctx, "systemctl", "list-units", "--type=service", "--all", "--no-legend", "--no-pager", "--plain").Output()
	if err != nil {
		return nil, err
	}
	out := map[string]map[string]any{}
	for _, line := range strings.Split(string(body), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		item := map[string]any{"load_state": fields[1], "active_state": fields[2], "sub_state": fields[3]}
		if len(fields) > 4 {
			item["description"] = strings.Join(fields[4:], " ")
		}
		out[fields[0]] = item
	}
	return out, nil
}

func linuxCronEntities(root string) ([]entity, error) {
	paths := []string{"/etc/crontab", "/etc/cron.d", "/var/spool/cron", "/var/spool/cron/crontabs"}
	var entities []entity
	seen := map[string]bool{}
	for _, configured := range paths {
		path := rooted(root, configured)
		info, err := os.Stat(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		var files []string
		if info.IsDir() {
			entries, err := os.ReadDir(path)
			if err != nil {
				return nil, err
			}
			for _, entry := range entries {
				if !entry.IsDir() {
					files = append(files, filepath.Join(path, entry.Name()))
				}
			}
		} else {
			files = append(files, path)
		}
		for _, file := range files {
			if seen[file] {
				continue
			}
			seen[file] = true
			info, err := os.Stat(file)
			if err != nil {
				if os.IsNotExist(err) {
					continue
				}
				return nil, err
			}
			body, err := os.ReadFile(file)
			if err != nil {
				return nil, err
			}
			if len(body) > 1024*1024 {
				body = body[:1024*1024]
			}
			digest := sha256.Sum256(body)
			displayPath := file
			if root != "/" {
				displayPath = "/" + strings.TrimPrefix(strings.TrimPrefix(file, root), string(filepath.Separator))
			}
			entities = append(entities, entity{Key: "cron:" + displayPath, EntityType: "scheduled_task", AssetType: "host_service", Fields: map[string]any{
				"task_name": filepath.Base(file), "task_type": "cron", "path": displayPath,
				"size": info.Size(), "mod_time": info.ModTime().UTC().Format(time.RFC3339Nano), "hash": hex.EncodeToString(digest[:]),
			}})
		}
	}
	return entities, nil
}

var containerIDPattern = regexp.MustCompile(`(?i)(?:docker-|cri-containerd-)?([a-f0-9]{12,64})(?:\.scope)?`)

func collectLinuxKernelContainers(procRoot string, _ time.Time) ([]entity, error) {
	var entities []entity
	moduleBody, err := os.ReadFile(filepath.Join(procRoot, "modules"))
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	for _, line := range strings.Split(string(moduleBody), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		entities = append(entities, entity{Key: "module:" + fields[0], EntityType: "kernel_module", AssetType: "host_kernel_context", Fields: map[string]any{
			"module_name": fields[0], "module_size": parseInt64(fields[1]), "module_instances": parseInt(fields[2]),
			"module_dependencies": strings.TrimSuffix(fields[3], ","), "module_state": fields[4],
		}})
	}
	summary := map[string]any{}
	for key, path := range map[string]string{
		"kernel_release": "sys/kernel/osrelease", "boot_id": "sys/kernel/random/boot_id", "kernel_cmdline": "cmdline",
	} {
		if body, err := os.ReadFile(filepath.Join(procRoot, path)); err == nil {
			summary[key] = strings.TrimSpace(string(body))
		}
	}
	for _, namespace := range []string{"pid", "mnt", "net", "user", "uts", "ipc"} {
		if target, err := os.Readlink(filepath.Join(procRoot, "1/ns", namespace)); err == nil {
			summary["init_"+namespace+"_namespace"] = target
		}
	}
	if len(summary) > 0 {
		entities = append(entities, entity{Key: "kernel:summary", EntityType: "kernel_context", AssetType: "host_kernel_context", Fields: summary})
	}
	entities = append(entities, linuxContainerEntities(procRoot)...)
	return entities, nil
}

// linuxContainerEntities counts unique processes, not cgroup controller entries.
// A PID can repeat across cgroup v1 controllers or nested paths for one container.
// Deduplicate before counting and bounding the deterministic evidence list.
func linuxContainerEntities(procRoot string) []entity {
	type containerInfo struct {
		paths map[string]bool
		pids  map[int]bool
	}
	containers := map[string]*containerInfo{}
	entries, _ := os.ReadDir(procRoot)
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 || !entry.IsDir() {
			continue
		}
		body, err := os.ReadFile(filepath.Join(procRoot, entry.Name(), "cgroup"))
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(body), "\n") {
			parts := strings.SplitN(line, ":", 3)
			if len(parts) != 3 {
				continue
			}
			matches := containerIDPattern.FindAllStringSubmatch(parts[2], -1)
			for _, match := range matches {
				id := strings.ToLower(match[1])
				if len(id) < 12 || allZero(id) {
					continue
				}
				info := containers[id]
				if info == nil {
					info = &containerInfo{paths: map[string]bool{}, pids: map[int]bool{}}
					containers[id] = info
				}
				info.paths[parts[2]] = true
				info.pids[pid] = true
			}
		}
	}
	var entities []entity
	for id, info := range containers {
		pids := make([]int, 0, len(info.pids))
		for pid := range info.pids {
			pids = append(pids, pid)
		}
		sort.Ints(pids)
		paths := make([]string, 0, len(info.paths))
		for path := range info.paths {
			paths = append(paths, path)
		}
		sort.Strings(paths)
		if len(pids) > 100 {
			pids = pids[:100]
		}
		entities = append(entities, entity{Key: "container:" + id, EntityType: "container_context", AssetType: "host_kernel_context", Fields: map[string]any{
			"container_id": id, "process_count": len(info.pids), "pids": pids, "cgroup_paths": paths,
		}})
	}
	return entities
}

func rooted(root, path string) string {
	if root == "/" {
		return path
	}
	return filepath.Join(root, strings.TrimPrefix(path, "/"))
}

func cloneFields(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func parseInt(value string) int {
	parsed, _ := strconv.Atoi(strings.TrimSpace(value))
	return parsed
}

func parseInt64(value string) int64 {
	parsed, _ := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	return parsed
}

func allZero(value string) bool {
	return strings.Trim(value, "0") == ""
}

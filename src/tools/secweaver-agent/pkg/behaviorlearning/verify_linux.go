//go:build linux

package behaviorlearning

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Execution is a kernel-derived exec, before best-effort /proc enrichment.
type Execution struct {
	PID, PPID, RootPID              int
	Exe                             string
	Args                            []string
	UID, GID, EUID, EGID, AUID, CWD string
	Address                         string
	Port                            int
	Success                         bool
	Truncated                       bool
	HasTTY                          *bool
	Backend                         string
	Inode, Device, SourceTime       string
	StartBootNS                     uint64
}

type fileIdentity struct {
	Dev, Ino     uint64
	Size         int64
	Mtime, Ctime unix.Timespec
}
type verifiedFile struct {
	identity fileIdentity
	digest   string
	checked  time.Time
}
type processView struct {
	PID, PPID                      int
	Start                          string
	Exe, Digest, CWD, AUID, Cgroup string
	Args                           []string
	UID, EUID, GID, EGID           string
	TTY                            string
}

// Verifier is owned by one background worker; its bounded digest cache never
// stores argv. File metadata is checked on every lookup and hashes expire.
type Verifier struct {
	files map[string]verifiedFile
	boot  string
}

// NewVerifier binds instance identities to this kernel boot.
func NewVerifier() (*Verifier, error) {
	b, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return nil, err
	}
	return &Verifier{files: map[string]verifiedFile{}, boot: strings.TrimSpace(string(b))}, nil
}

// Verify rejects exited, raced, writable or unresolvable instances. Reads stay
// off the source reader. Exact kernel argv/credentials must agree with /proc.
func (v *Verifier) Verify(in Execution) (Context, string, string, string) {
	if !in.Success || in.Truncated || in.HasTTY == nil || *in.HasTTY {
		return Context{}, "", "", "failed_truncated_or_interactive"
	}
	if blocked(in.Exe, in.Args) {
		return Context{}, "", "", "always_emit_tool"
	}
	// Both backends require execution-time credentials and image identity.
	if in.EUID == "" || in.EGID == "" || in.GID == "" || in.Inode == "" {
		return Context{}, "", "", "backend_identity_incomplete"
	}
	child, err := v.readProcess(in.PID)
	if err != nil {
		return Context{}, "", "", "unverified_process"
	}
	if err := verifyAuditInstance(in, child); err != nil {
		return Context{}, "", "", "kernel_instance_unverified"
	}
	if child.PPID != in.PPID || child.Exe != in.Exe || !equalArgs(child.Args, in.Args) ||
		child.UID != in.UID || child.AUID != in.AUID || child.CWD != in.CWD ||
		(in.GID != "" && child.GID != in.GID) || (in.EUID != "" && child.EUID != in.EUID) || (in.EGID != "" && child.EGID != in.EGID) {
		return Context{}, "", "", "process_context_changed"
	}

	if child.UID != child.EUID || child.GID != child.EGID || child.TTY != "0" ||
		(child.AUID != "4294967295" && child.AUID != "-1") {
		return Context{}, "", "", "identity_or_session"
	}
	parent, err := v.readProcess(in.PPID)
	if err != nil {
		return Context{}, "", "", "unverified_parent"
	}
	// Only a direct, stable service parent is initially eligible. Deeper ancestry
	// remains collected until lifecycle-bound ancestor execution evidence exists.
	if parent.PID != in.RootPID {
		return Context{}, "", "", "deep_ancestry_unverified"
	}
	if parent.Cgroup != child.Cgroup {
		return Context{}, "", "", "workload_context_changed"
	}
	if parent.Cgroup == "" || parent.Cgroup == "0::/" || !strings.Contains(parent.Cgroup, ".service") {
		return Context{}, "", "", "service_identity_incomplete"
	}
	childAgain, err := readSmall(fmt.Sprintf("/proc/%d/stat", in.PID), 8192)
	if err != nil || procStart(string(childAgain)) != child.Start {
		return Context{}, "", "", "process_instance_changed"
	}
	stableParent := parent
	stableParent.PID = 0
	stableParent.PPID = 0
	stableParent.Start = ""
	parentJSON, _ := json.Marshal(stableParent)
	serviceJSON, _ := json.Marshal(struct {
		Parent  processView
		Address string
		Port    int
	}{stableParent, in.Address, in.Port})
	ctx := Context{Service: string(serviceJSON), Parent: string(parentJSON), Executable: child.Exe, Digest: child.Digest, Args: child.Args, CWD: child.CWD, UID: child.UID, EUID: child.EUID, GID: child.GID, EGID: child.EGID, AUID: child.AUID, Session: "service_noninteractive", Capability: "linux-" + in.Backend + "-verified-direct-v1"}
	return ctx, v.instance(child), v.instance(parent), ""
}

// instance includes an execution digest; identical same-PID re-execs cannot
// inherit a new cache allowance because Engine refuses conflicting event IDs.
// ParentInstance resolves only a live, verified image for ancestor replay.
// A vanished or changed parent yields no key rather than a guessed PID link.
func (v *Verifier) ParentInstance(pid int) string {
	p, err := v.readProcess(pid)
	if err != nil {
		return ""
	}
	return v.instance(p)
}

func (v *Verifier) instance(p processView) string {
	b, _ := json.Marshal(struct {
		Exe, Digest string
		Args        []string
	}{p.Exe, p.Digest, p.Args})
	h := sha256.Sum256(b)
	return fmt.Sprintf("%s:%d:%s:%x", v.boot, p.PID, p.Start, h)
}

func (v *Verifier) readProcess(pid int) (processView, error) {
	p := processView{PID: pid}
	if pid <= 1 {
		return p, fmt.Errorf("invalid process")
	}
	base := fmt.Sprintf("/proc/%d", pid)
	stat, err := readSmall(base+"/stat", 8192)
	if err != nil {
		return p, err
	}
	p.Start = procStart(string(stat))
	end := strings.LastIndex(string(stat), ")")
	if end < 0 || p.Start == "" {
		return p, fmt.Errorf("invalid stat")
	}
	fields := strings.Fields(string(stat)[end+1:])
	if len(fields) < 20 {
		return p, fmt.Errorf("short stat")
	}
	p.PPID, _ = strconv.Atoi(fields[1])
	p.TTY = fields[4]
	p.Exe, err = os.Readlink(base + "/exe")
	if err != nil {
		return p, err
	}
	p.Digest, err = v.digest(base+"/exe", p.Exe)
	if err != nil {
		return p, err
	}
	cmd, err := readSmall(base+"/cmdline", 32768)
	if err != nil || len(cmd) == 0 || cmd[len(cmd)-1] != 0 {
		return p, fmt.Errorf("invalid argv")
	}
	for _, a := range bytes.Split(cmd[:len(cmd)-1], []byte{0}) {
		p.Args = append(p.Args, string(a))
	}
	status, err := readSmall(base+"/status", 16384)
	if err != nil {
		return p, err
	}
	for _, line := range strings.Split(string(status), "\n") {
		f := strings.Fields(line)
		if len(f) == 5 && f[0] == "Uid:" {
			p.UID = f[1]
			p.EUID = f[2]
			if f[3] != f[1] || f[4] != f[1] {
				return p, fmt.Errorf("saved/fs uid differs")
			}
		}
		if len(f) == 5 && f[0] == "Gid:" {
			p.GID = f[1]
			p.EGID = f[2]
			if f[3] != f[1] || f[4] != f[1] {
				return p, fmt.Errorf("saved/fs gid differs")
			}
		}
		if len(f) == 2 && f[0] == "CapEff:" && strings.Trim(f[1], "0") != "" {
			return p, fmt.Errorf("capability-bearing execution")
		}
	}
	p.CWD, err = os.Readlink(base + "/cwd")
	if err != nil {
		return p, err
	}
	auid, err := readSmall(base+"/loginuid", 32)
	if err != nil {
		return p, err
	}
	p.AUID = strings.TrimSpace(string(auid))
	cg, err := readSmall(base+"/cgroup", 8192)
	if err != nil {
		return p, err
	}
	p.Cgroup = strings.TrimSpace(string(cg))
	after, err := readSmall(base+"/stat", 8192)
	if err != nil || procStart(string(after)) != p.Start {
		return p, fmt.Errorf("process changed")
	}
	exe, err := os.Readlink(base + "/exe")
	if err != nil || exe != p.Exe {
		return p, fmt.Errorf("exec changed")
	}
	afterCmd, err := readSmall(base+"/cmdline", 32768)
	if err != nil || !bytes.Equal(cmd, afterCmd) {
		return p, fmt.Errorf("argv changed")
	}
	return p, nil
}

// digest opens the running executable, validates ELF and root-controlled
// ancestors, and compares fstat before/after hashing. No path-only hash is used.
func (v *Verifier) digest(procPath, exe string) (string, error) {
	if !filepath.IsAbs(exe) || strings.Contains(exe, " (deleted)") || strings.HasPrefix(exe, "/memfd:") {
		return "", fmt.Errorf("untrusted image")
	}
	if err := controlledPath(exe); err != nil {
		return "", err
	}
	f, err := os.Open(procPath)
	if err != nil {
		return "", err
	}
	defer f.Close()
	var st unix.Stat_t
	if err = unix.Fstat(int(f.Fd()), &st); err != nil {
		return "", err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != 0 || st.Mode&0022 != 0 || st.Size > 64<<20 || st.Size < 4 {
		return "", fmt.Errorf("uncontrolled executable")
	}
	id := fileIdentity{uint64(st.Dev), st.Ino, st.Size, st.Mtim, st.Ctim}
	if c, ok := v.files[exe]; ok && c.identity == id && time.Since(c.checked) < time.Minute {
		return c.digest, nil
	}
	var magic [4]byte
	if _, err = io.ReadFull(f, magic[:]); err != nil || string(magic[:]) != "\x7fELF" {
		return "", fmt.Errorf("scripts are always emitted")
	}
	hash := sha256.New()
	hash.Write(magic[:])
	if _, err = io.Copy(hash, io.LimitReader(f, (64<<20)+1)); err != nil {
		return "", err
	}
	var after unix.Stat_t
	if err = unix.Fstat(int(f.Fd()), &after); err != nil {
		return "", err
	}
	if id != (fileIdentity{uint64(after.Dev), after.Ino, after.Size, after.Mtim, after.Ctim}) {
		return "", fmt.Errorf("executable changed")
	}
	digest := hex.EncodeToString(hash.Sum(nil))
	if len(v.files) >= 256 {
		v.files = map[string]verifiedFile{}
	}
	v.files[exe] = verifiedFile{id, digest, time.Now()}
	return digest, nil
}

// controlledPath rejects any group/world-writable or non-root-owned ancestor.
// Symlinks are resolved before checks, while the image itself is hashed by FD.
func controlledPath(path string) error {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return err
	}
	for p := resolved; ; p = filepath.Dir(p) {
		st, err := os.Stat(p)
		if err != nil {
			return err
		}
		var u unix.Stat_t
		if err = unix.Stat(p, &u); err != nil {
			return err
		}
		if u.Uid != 0 || st.Mode().Perm()&0022 != 0 {
			return fmt.Errorf("writable image path")
		}
		if p == "/" {
			return nil
		}
	}
}

func readSmall(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if int64(len(b)) > max {
		return nil, fmt.Errorf("proc field too long")
	}
	return b, err
}
func procStart(stat string) string {
	end := strings.LastIndex(stat, ")")
	if end < 0 {
		return ""
	}
	f := strings.Fields(stat[end+1:])
	if len(f) < 20 {
		return ""
	}
	return f[19]
}
func equalArgs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// blocked is deliberately conservative. Unknown executable renaming is not
// claimed as complete detection; ELF/path integrity checks remain mandatory.
func blocked(exe string, args []string) bool {
	name := strings.ToLower(filepath.Base(exe))
	for _, n := range []string{"sh", "bash", "dash", "zsh", "busybox", "python", "perl", "ruby", "php", "node", "java", "curl", "wget", "ssh", "scp", "sftp", "nc", "ncat", "socat", "sudo", "su", "env", "xargs", "find", "awk", "sed", "gdb", "strace", "dd", "rm", "chmod", "chown", "mount", "systemctl", "crontab", "openssl", "base64"} {
		if name == n || strings.HasPrefix(name, n+".") || ((n == "python" || n == "php") && strings.HasPrefix(name, n)) {
			return true
		}
	}
	for _, a := range args {
		// Generic evaluation syntax remains visible even when an interpreter
		// has a vendor-specific executable name.
		if a == "-c" || a == "-e" || a == "--eval" || strings.Contains(a, "$(") || strings.Contains(a, "`") {
			return true
		}
		lower := strings.ToLower(a)
		for _, s := range []string{"/etc/shadow", "authorized_keys", "/etc/cron", "/etc/sudoers", "/tmp/", "/dev/shm/", "memfd:", "-exec"} {
			if strings.Contains(lower, s) {
				return true
			}
		}
	}
	return false
}

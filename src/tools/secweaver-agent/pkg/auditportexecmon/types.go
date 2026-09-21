package auditportexecmon

import (
	"regexp"
	"sync"
	"time"

	"secweaver-agent/pkg/layout"
)

type listenerInfo struct {
	PID        int    `json:"pid"`
	Process    string `json:"process"`
	Address    string `json:"address"`
	Port       int    `json:"port"`
	MonitorExe string `json:"-"`
	ExeOnly    bool   `json:"-"` // nginx/java/php-fpm 等：仅用 -F exe= 规则
	Raw        string `json:"raw"`
}

// auditEvent is the normalized JSON contract emitted by this module. Fields
// contains parser-only data and is deliberately excluded from serialization;
// downstream assets consume the stable top-level fields instead.
type auditEvent struct {
	Time             time.Time `json:"time"`
	HostName         string    `json:"host_name"`
	HostIP           string    `json:"host_ip"`
	EventType        string    `json:"event_type"`
	AuditID          string    `json:"audit_id"`
	PID              string    `json:"pid,omitempty"`
	PIDName          string    `json:"pid_name,omitempty"`
	PPID             string    `json:"ppid,omitempty"`
	PPIDName         string    `json:"ppid_name,omitempty"`
	UID              string    `json:"uid,omitempty"`
	UIDName          string    `json:"uid_name,omitempty"`
	AUID             string    `json:"auid,omitempty"`
	AUIDName         string    `json:"auid_name,omitempty"`
	Comm             string    `json:"comm,omitempty"`
	Exe              string    `json:"exe,omitempty"`
	CWD              string    `json:"cwd,omitempty"`
	Command          []string  `json:"command,omitempty"`
	CommandLine      string    `json:"command_line,omitempty"`
	CommandTruncated bool      `json:"command_truncated,omitempty"`
	Success          string    `json:"success,omitempty"`
	Exit             string    `json:"exit,omitempty"`
	Key              string    `json:"key,omitempty"`
	TTY              string    `json:"tty,omitempty"`
	// HasTTY is tri-state: nil means the collector could not observe session TTY
	// state. Unknown must be omitted because downstream analysis treats false as
	// positive evidence of a non-interactive WebShell/RCE-style execution.
	HasTTY          *bool             `json:"has_tty,omitempty"`
	RawRecords      []string          `json:"raw_records,omitempty"`
	ListenerPID     int               `json:"listener_pid,omitempty"`
	ListenerProcess string            `json:"listener_process,omitempty"`
	ListenerAddress string            `json:"listener_address,omitempty"`
	ListenerPort    int               `json:"listener_port,omitempty"`
	ConnectFamily   string            `json:"connect_family,omitempty"`
	ConnectAddress  string            `json:"connect_address,omitempty"`
	ConnectPort     int               `json:"connect_port,omitempty"`
	FileAction      string            `json:"file_action,omitempty"`
	FilePaths       []string          `json:"file_paths,omitempty"`
	Fields          map[string]string `json:"-"`
}

type hostIdentity struct {
	HostName string
	HostIP   string
}

// auditAccumulator joins the multiple Linux audit records that describe one
// syscall. The audit ID is the transaction key: SYSCALL contributes identity,
// EXECVE contributes argv, and PATH/CWD/PROCTITLE contribute context.
type auditAccumulator struct {
	id            string
	firstSeen     time.Time
	lastRecordAt  time.Time
	records       []string
	fields        map[string]string
	argv          map[int]string
	paths         map[int]string
	proctitle     string
	cwd           string
	seenSyscall   bool
	seenExecve    bool
	seenProctitle bool
}

// Timing and capacity defaults are intentionally conservative. Settle delay
// allows auxiliary records to arrive after SYSCALL, while the short flush/read
// poll keeps event latency low without busy-waiting on audit.log.
const defaultOutputLog = layout.LinuxLogs + "/audit-port-execmon.log"
const defaultListenerRescanInterval = 5 * time.Minute
const defaultMaxAuditRules = 1024
const auditctlTimeout = 3 * time.Second
const javaMonitorModeExeOnly = "exe_only"
const javaMonitorModeHybrid = "hybrid"
const javaMonitorModePIDTree = "pid_tree"
const processTreeBackendAuto = "auto"
const processTreeBackendEBPF = "ebpf"

// processTreeBackendAudit uses a bounded set of host-wide syscall rules and
// performs listener-tree attribution in userspace. The fixed rule count keeps
// old kernels without BTF from degrading audit_filter_syscall as process churns.
const processTreeBackendAudit = "audit"

// processTreeBackendAuditPID preserves the historical PID/PPID-rule backend for
// explicit compatibility only. It is never selected by the default auto mode.
const processTreeBackendAuditPID = "audit_pid"
const defaultEBPFMaxTrackedProcesses = 131072
const defaultEBPFPerfBufferBytes = 256 << 10
const toolAuditRuleKeyPrefix = "tb_"
const execRecordSettleDelay = 150 * time.Millisecond
const auditLogFlushInterval = 100 * time.Millisecond
const auditLogReadPoll = 100 * time.Millisecond

var (
	msgIDPattern      = regexp.MustCompile(`msg=audit\([^:]+:([0-9]+)\)`)
	fieldPattern      = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]*)=("(?:\\.|[^"])*"|[^\s]+)`)
	execArgPattern    = regexp.MustCompile(`\ba([0-9]+)=("(?:\\.|[^"])*"|[^\s]+)`)
	pointerArgPattern = regexp.MustCompile(`^[0-9a-fA-F]{8,}$`)
	accountNameCache  sync.Map
	// unsupportedAuditSyscalls caches kernel/userspace capability failures by
	// arch and syscall. Without this cache every new PID would repeat the same
	// failing auditctl probe and amplify pressure on auditd.
	unsupportedAuditSyscalls sync.Map
	// Tests replace this function to inject auditctl failures. Production always
	// uses the timeout-bounded implementation below.
	runAuditctlCommand = runAuditctlOutputWithTimeout
)

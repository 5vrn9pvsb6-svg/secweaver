package hostpersistence

import (
	"time"

	"secweaver-agent/pkg/layout"
)

// This file defines the persistence scanner data contract, bounded defaults, and platform target catalogs shared across the module.

const parserVersion = "0.3.0"

const (
	defaultLinuxOutputLog   = layout.LinuxLogs + "/host-persistence.log"
	defaultLinuxStatePath   = layout.LinuxData + "/host-persistence-state.json"
	defaultWindowsOutputLog = layout.WindowsLogs + `\host-persistence.log`
	defaultWindowsStatePath = layout.WindowsData + `\host-persistence-state.json`
	defaultPollInterval     = 30 * time.Second
	defaultMaxHashBytes     = int64(1024 * 1024)
	defaultMaxContentBytes  = int64(64 * 1024)
	defaultMaxDiffLines     = 200
	defaultPersistenceEvt   = "persistence_change"
)

var version = parserVersion

type watchTarget struct {
	Path            string `json:"path"`
	Category        string `json:"category"`
	PersistenceType string `json:"persistence_type"`
	Recursive       bool   `json:"recursive"`
	MaxDepth        int    `json:"max_depth,omitempty"`
}

type config struct {
	OutputLog           string        `json:"output_log"`
	StatePath           string        `json:"state_path"`
	PollIntervalSeconds int           `json:"poll_interval_seconds"`
	HostIP              string        `json:"host_ip,omitempty"`
	IncludeHash         *bool         `json:"include_hash,omitempty"`
	MaxHashBytes        int64         `json:"max_hash_bytes,omitempty"`
	IncludeContentDiff  *bool         `json:"include_content_diff,omitempty"`
	MaxContentBytes     int64         `json:"max_content_bytes,omitempty"`
	MaxDiffLines        int           `json:"max_diff_lines,omitempty"`
	EmitBaseline        bool          `json:"emit_baseline,omitempty"`
	Audit               auditSettings `json:"audit,omitempty"`
	Watch               []watchTarget `json:"watch"`
}

type runtimeConfig struct {
	OutputLog          string
	StatePath          string
	PollInterval       time.Duration
	HostIP             string
	IncludeHash        bool
	MaxHashBytes       int64
	IncludeContentDiff bool
	MaxContentBytes    int64
	MaxDiffLines       int
	EmitBaseline       bool
	Audit              auditRuntimeConfig
	Watch              []watchTarget
	Once               bool
}

type fileState struct {
	Path             string `json:"path"`
	Category         string `json:"category"`
	PersistenceType  string `json:"persistence_type"`
	FileType         string `json:"file_type"`
	Mode             string `json:"mode"`
	Size             int64  `json:"size"`
	ModTime          string `json:"mod_time"`
	Hash             string `json:"hash,omitempty"`
	ContentCaptured  bool   `json:"content_captured,omitempty"`
	Content          string `json:"content,omitempty"`
	ContentTruncated bool   `json:"content_truncated,omitempty"`
	SymlinkTarget    string `json:"symlink_target,omitempty"`
}

type persistedState struct {
	Version   string               `json:"version"`
	HostName  string               `json:"host_name"`
	UpdatedAt string               `json:"updated_at"`
	Files     map[string]fileState `json:"files"`
}

type persistenceEvent struct {
	EvidenceID           string            `json:"evidence_id"`
	AssetType            string            `json:"asset_type"`
	Time                 string            `json:"time"`
	Timestamp            string            `json:"timestamp"`
	Host                 string            `json:"host"`
	HostName             string            `json:"host_name"`
	HostIP               string            `json:"host_ip,omitempty"`
	EventType            string            `json:"event_type"`
	Action               string            `json:"action"`
	Category             string            `json:"category"`
	PersistenceType      string            `json:"persistence_type"`
	Path                 string            `json:"path"`
	FileType             string            `json:"file_type,omitempty"`
	Mode                 string            `json:"mode,omitempty"`
	Size                 int64             `json:"size,omitempty"`
	ModTime              string            `json:"mod_time,omitempty"`
	Hash                 string            `json:"hash,omitempty"`
	PreviousHash         string            `json:"previous_hash,omitempty"`
	PreviousMode         string            `json:"previous_mode,omitempty"`
	PreviousSize         int64             `json:"previous_size,omitempty"`
	PreviousModTime      string            `json:"previous_mod_time,omitempty"`
	SymlinkTarget        string            `json:"symlink_target,omitempty"`
	User                 string            `json:"user,omitempty"`
	UID                  string            `json:"uid,omitempty"`
	AUID                 string            `json:"auid,omitempty"`
	AUIDName             string            `json:"auid_name,omitempty"`
	PID                  string            `json:"pid,omitempty"`
	PPID                 string            `json:"ppid,omitempty"`
	Process              string            `json:"process,omitempty"`
	Exe                  string            `json:"exe,omitempty"`
	Command              string            `json:"command,omitempty"`
	AuditID              string            `json:"audit_id,omitempty"`
	AuditSyscall         string            `json:"audit_syscall,omitempty"`
	ActorSource          string            `json:"actor_source,omitempty"`
	ContentDiff          string            `json:"content_diff,omitempty"`
	ContentDiffTruncated bool              `json:"content_diff_truncated,omitempty"`
	Message              string            `json:"message"`
	Fields               map[string]string `json:"fields,omitempty"`
	ParserVersion        string            `json:"parser_version"`
}

type stats struct {
	Scans         int `json:"scans"`
	FilesTracked  int `json:"files_tracked"`
	EventsWritten int `json:"events_written"`
	ScanErrors    int `json:"scan_errors"`
}

var defaultLinuxWatchTargets = []watchTarget{
	{Path: "/etc/crontab", Category: "scheduled_task", PersistenceType: "cron"},
	{Path: "/etc/cron.d", Category: "scheduled_task", PersistenceType: "cron", Recursive: true, MaxDepth: 3},
	{Path: "/etc/cron.daily", Category: "scheduled_task", PersistenceType: "cron", Recursive: true, MaxDepth: 2},
	{Path: "/etc/cron.hourly", Category: "scheduled_task", PersistenceType: "cron", Recursive: true, MaxDepth: 2},
	{Path: "/etc/cron.weekly", Category: "scheduled_task", PersistenceType: "cron", Recursive: true, MaxDepth: 2},
	{Path: "/etc/cron.monthly", Category: "scheduled_task", PersistenceType: "cron", Recursive: true, MaxDepth: 2},
	{Path: "/var/spool/cron", Category: "scheduled_task", PersistenceType: "cron", Recursive: true, MaxDepth: 3},
	{Path: "/var/spool/cron/crontabs", Category: "scheduled_task", PersistenceType: "cron", Recursive: true, MaxDepth: 3},
	{Path: "/etc/systemd/system", Category: "service_autostart", PersistenceType: "systemd", Recursive: true, MaxDepth: 4},
	{Path: "/etc/init.d", Category: "service_autostart", PersistenceType: "sysvinit", Recursive: true, MaxDepth: 2},
	{Path: "/etc/rc.local", Category: "service_autostart", PersistenceType: "rc_local"},
	{Path: "/etc/sudoers", Category: "privilege_escalation", PersistenceType: "sudoers"},
	{Path: "/etc/sudoers.d", Category: "privilege_escalation", PersistenceType: "sudoers", Recursive: true, MaxDepth: 2},
	{Path: "/root/.ssh/authorized_keys", Category: "account_access", PersistenceType: "ssh_authorized_keys"},
	{Path: "/home/*/.ssh/authorized_keys", Category: "account_access", PersistenceType: "ssh_authorized_keys"},
	{Path: "/etc/profile", Category: "shell_startup", PersistenceType: "shell_profile"},
	{Path: "/etc/profile.d", Category: "shell_startup", PersistenceType: "shell_profile", Recursive: true, MaxDepth: 2},
	{Path: "/etc/bashrc", Category: "shell_startup", PersistenceType: "shell_profile"},
	{Path: "/etc/bash.bashrc", Category: "shell_startup", PersistenceType: "shell_profile"},
	{Path: "/root/.bashrc", Category: "shell_startup", PersistenceType: "shell_profile"},
	{Path: "/root/.profile", Category: "shell_startup", PersistenceType: "shell_profile"},
	{Path: "/home/*/.bashrc", Category: "shell_startup", PersistenceType: "shell_profile"},
	{Path: "/home/*/.profile", Category: "shell_startup", PersistenceType: "shell_profile"},
	{Path: "/etc/ld.so.preload", Category: "library_hijack", PersistenceType: "ld_preload"},
	{Path: "/etc/modules-load.d", Category: "kernel_module", PersistenceType: "kernel_module", Recursive: true, MaxDepth: 2},
	{Path: "/etc/modprobe.d", Category: "kernel_module", PersistenceType: "kernel_module", Recursive: true, MaxDepth: 2},
}

var defaultWindowsWatchTargets = []watchTarget{
	{Path: `C:\Windows\System32\Tasks`, Category: "scheduled_task", PersistenceType: "windows_scheduled_task", Recursive: true, MaxDepth: 6},
	{Path: `C:\Windows\Tasks`, Category: "scheduled_task", PersistenceType: "windows_scheduled_task", Recursive: true, MaxDepth: 3},
	{Path: `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp`, Category: "startup_folder", PersistenceType: "startup_folder", Recursive: true, MaxDepth: 3},
	{Path: `C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`, Category: "startup_folder", PersistenceType: "startup_folder", Recursive: true, MaxDepth: 3},
	{Path: `C:\Windows\System32\GroupPolicy\Machine\Scripts`, Category: "logon_script", PersistenceType: "group_policy_script", Recursive: true, MaxDepth: 5},
	{Path: `C:\Windows\System32\GroupPolicy\User\Scripts`, Category: "logon_script", PersistenceType: "group_policy_script", Recursive: true, MaxDepth: 5},
	{Path: `C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1`, Category: "shell_startup", PersistenceType: "powershell_profile"},
	{Path: `C:\Users\*\Documents\WindowsPowerShell\profile.ps1`, Category: "shell_startup", PersistenceType: "powershell_profile"},
	{Path: `C:\Users\*\Documents\PowerShell\profile.ps1`, Category: "shell_startup", PersistenceType: "powershell_profile"},
}

package hostpersistence

import (
	"regexp"

	"strings"
	"sync"
	"time"
)

// This file defines optional Linux audit enrichment settings, bounded correlation state, and accumulator ownership invariants.

const (
	defaultAuditLogPath = "/var/log/audit/audit.log"
	defaultAuditKey     = "tb_host_persistence"
	defaultAuditPerm    = "wa"
	auditFlushInterval  = 250 * time.Millisecond
	auditPollInterval   = 200 * time.Millisecond
	auditRetention      = 10 * time.Minute
	auditctlTimeout     = 3 * time.Second
	auditWatchReconcile = time.Minute
)

// auditSettings controls the optional Linux auditd enrichment path. File
// polling remains the source of persistence changes; auditd contributes actor
// identity and process context when a matching record is available.
type auditSettings struct {
	Enabled     *bool  `json:"enabled,omitempty"`
	AuditLog    string `json:"audit_log,omitempty"`
	Key         string `json:"key,omitempty"`
	Perm        string `json:"perm,omitempty"`
	ManageRules *bool  `json:"manage_rules,omitempty"`
	FollowLog   *bool  `json:"follow_log,omitempty"`
	FailOnError bool   `json:"fail_on_error,omitempty"`
	FromStart   bool   `json:"from_start,omitempty"`
}

type auditRuntimeConfig struct {
	Enabled     bool
	AuditLog    string
	Key         string
	Perm        string
	ManageRules bool
	FollowLog   bool
	FailOnError bool
	FromStart   bool
}

// auditChange is the compact actor evidence retained for one or more PATH
// records belonging to the same audit event.
type auditChange struct {
	Timestamp time.Time
	AuditID   string
	UID       string
	UIDName   string
	AUID      string
	AUIDName  string
	PID       string
	PPID      string
	Process   string
	Exe       string
	Command   string
	Syscall   string
	Paths     []string
}

// auditTracker is a bounded, path-indexed correlation cache. The persistence
// scanner and audit reader run independently, so all cache access is protected
// by mu and old evidence is discarded before it can be attributed to a later
// unrelated file change.
type auditTracker struct {
	mu             sync.Mutex
	byPath         map[string][]auditChange
	retention      time.Duration
	maxPerPath     int
	maxPaths       int
	lastPrune      time.Time
	fatalErr       chan error
	refreshWatches func()
}

// auditAccumulator joins the SYSCALL, PATH, EXECVE, and PROCTITLE records that
// auditd emits as separate lines under one audit message ID.
type auditAccumulator struct {
	id           string
	firstSeen    time.Time
	lastRecordAt time.Time
	fields       map[string]string
	argv         map[int]string
	paths        map[int]string
	proctitle    string
}

var (
	auditMsgIDPattern  = regexp.MustCompile(`msg=audit\([^:]+:([0-9]+)\)`)
	auditFieldPattern  = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]*)=("(?:\\.|[^"])*"|[^\s]+)`)
	userNameCache      sync.Map
	runAuditctlCommand = runAuditctlOutputWithTimeout
)

func mergeAuditConfig(base auditRuntimeConfig, raw auditSettings) auditRuntimeConfig {
	if raw.Enabled != nil {
		base.Enabled = *raw.Enabled
	}
	if strings.TrimSpace(raw.AuditLog) != "" {
		base.AuditLog = strings.TrimSpace(raw.AuditLog)
	}
	if strings.TrimSpace(raw.Key) != "" {
		base.Key = strings.TrimSpace(raw.Key)
	}
	if strings.TrimSpace(raw.Perm) != "" {
		base.Perm = strings.TrimSpace(raw.Perm)
	}
	if raw.ManageRules != nil {
		base.ManageRules = *raw.ManageRules
	}
	if raw.FollowLog != nil {
		base.FollowLog = *raw.FollowLog
	}
	base.FailOnError = raw.FailOnError
	base.FromStart = raw.FromStart
	base.normalize()
	return base
}

func (cfg *auditRuntimeConfig) normalize() {
	if strings.TrimSpace(cfg.AuditLog) == "" {
		cfg.AuditLog = defaultAuditLogPath
	}
	if strings.TrimSpace(cfg.Key) == "" {
		cfg.Key = defaultAuditKey
	}
	if strings.TrimSpace(cfg.Perm) == "" {
		cfg.Perm = defaultAuditPerm
	}
}

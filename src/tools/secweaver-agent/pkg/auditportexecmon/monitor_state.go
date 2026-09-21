package auditportexecmon

import (
	"os"
	"regexp"

	"sync"

	"time"

	"secweaver-agent/pkg/processtracker"
)

// This file owns the monitor state model and constructor. Runtime workers and kernel rule mutations live in focused sibling files.

type trackingTarget struct {
	Gateway           listenerInfo
	ExpandDescendants bool
	Source            string
}

// ruleExpansion is the worker's unit of rule lifecycle work. StartTime binds a
// numeric PID to one process lifetime. Remove, Replace, and CloneOnly alter the
// normal full-expansion path and are mutually exclusive in produced jobs.
type ruleExpansion struct {
	PID       int
	Listener  listenerInfo
	CloneOnly bool
	Replace   bool
	Remove    bool
	StartTime uint64
}

type ruleExpansionStats struct {
	Enqueued        uint64
	Deduped         uint64
	QueueFull       uint64
	Expanded        uint64
	Failed          uint64
	RuleLimitSkips  uint64
	Pending         int
	QueueDepth      int
	CurrentRules    int
	ReservedRules   int
	MaxAuditRules   int
	PressureLevel   string
	PressurePaused  uint64
	PressureEvents  uint64
	RecoveryActive  bool
	RecoveryPending int
}

var isProcessAlive = procAlive
var readProcessStartTime = readProcStartTime

// processTreeMonitor owns the complete in-memory model of audit coverage.
//
// Mutable maps, queues, rule ledgers, reservations, and pressure state are
// protected by mu. The ruleExpansion* and pressure* counters documented as
// statistics use atomics and may be read without mu. auditctl calls never run
// while mu is held; they can take seconds, and holding the lock would block the
// audit reader from matching and enqueueing new processes.
type processTreeMonitor struct {
	mu sync.Mutex

	// Agent identity and listener ownership. selfBranch prevents the supervisor,
	// this module, and their auditctl maintenance children from monitoring itself.
	selfPID        int
	selfExe        string
	selfBranch     map[int]bool
	portFilter     int
	whitelistPorts map[int]bool
	listeners      []listenerInfo
	pidListener    map[int]listenerInfo
	processTracker processtracker.Tracker
	processBackend string

	// Coverage ledger. monitored is a reservation as well as a state flag;
	// processStartTimes prevents PID reuse, while rules/watchRules are the exact
	// kernel objects this process remains responsible for deleting.
	monitored             map[int]bool
	processStartTimes     map[int]uint64
	processParentPIDs     map[int]int
	processObservedAt     map[int]time.Time
	pendingRuleExpansion  map[int]bool
	pendingPIDRuleCleanup map[int]bool
	pendingExeRuleCleanup map[string]bool
	exeMonitored          map[string]bool
	rules                 []auditRule
	watchRules            []auditWatchRule
	reservedAuditRules    int
	maxAuditRules         int
	ruleLimitReached      bool

	// Cleanup failure tracking to prevent memory leaks from perpetually failing deletions
	pidCleanupFailureCount map[int]int       // Track retry count per PID
	pidCleanupFirstFailed  map[int]time.Time // Track when cleanup first failed
	exeCleanupFailureCount map[string]int
	exeCleanupFirstFailed  map[string]time.Time

	// Immutable policy and audit keys resolved from configuration at startup.
	execKey                   string
	connectKey                string
	fileKey                   string
	sensitiveFileKey          string
	cloneKey                  string
	trackDescendants          bool
	monitorExec               bool
	execListenerPorts         map[int]bool
	monitorConnect            bool
	monitorFileOps            bool
	monitorSensitiveFileReads bool
	sensitiveFilePaths        []string
	connectListenerPorts      map[int]bool
	skipConnectListenerPorts  map[int]bool
	skipConnectProcessNames   map[string]bool
	skipConnectExePatterns    []*regexp.Regexp
	fileListenerPorts         map[int]bool
	auditArches               []string
	javaMonitorMode           string

	// Companion backends are separate process trees (for example php-fpm behind
	// nginx) whose events are attributed to the gateway listener.
	companionLogged map[string]bool
	pidTargets      map[int]trackingTarget
	exeTargets      map[string]trackingTarget

	// One worker serializes dynamic rule mutations and slow reconciliation away
	// from the audit reader. rescanQueue has capacity one to coalesce timer bursts.
	ruleExpansionQueue chan ruleExpansion
	rescanQueue        chan struct{}
	ruleExpansionStop  chan struct{}
	ruleExpansionDone  chan struct{}

	// High-frequency counters are atomic to avoid taking mu on the event path.
	ruleExpansionEnqueued    uint64
	ruleExpansionDeduped     uint64
	ruleExpansionQueueFull   uint64
	ruleExpansionExpanded    uint64
	ruleExpansionFailed      uint64
	ruleExpansionRuleLimited uint64

	// Pressure state owns both deferred full expansions and clone-only coverage
	// suppressed at medium pressure. Recovery drains these maps gradually.
	pressureDegradedUntil    time.Time
	pressureLevel            auditPressureLevel
	pressureReason           string
	pressureConfig           auditPressureRuntimeConfig
	pressureRecovering       bool
	pressureRecoveryScanning bool
	pressureRecoveryBlocked  bool
	deferredRuleExpansion    map[int]ruleExpansion
	suppressedCloneRules     map[int]ruleExpansion
	lastRuleExpansionAt      time.Time
	pressurePausedExpansions uint64
	pressureTransitions      uint64
}

func (m *processTreeMonitor) setProcessTracker(backend string, tracker processtracker.Tracker) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.processBackend = backend
	m.processTracker = tracker
}

func (m *processTreeMonitor) usesEBPF() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.processBackend == processTreeBackendEBPF && m.processTracker != nil
}

// usesBoundedAudit reports whether host-wide fixed syscall rules feed the
// userspace process-tree map. This backend must never enqueue PID rule changes.
func (m *processTreeMonitor) usesBoundedAudit() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.processBackend == processTreeBackendAudit
}

// usesDynamicPIDRules isolates the legacy backend whose kernel rule count grows
// with process lifetimes. Empty is retained for focused unit tests that build a
// monitor directly without running backend selection.
func (m *processTreeMonitor) usesDynamicPIDRules() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.processBackend == "" || m.processBackend == processTreeBackendAuditPID
}

func newProcessTreeMonitor(listeners []listenerInfo, portFilter int, whitelistPorts map[int]bool, execKey, connectKey, fileKey, sensitiveFileKey, cloneKey string, trackDescendants, monitorExec bool, execListenerPorts map[int]bool, monitorConnect bool, connectListenerPorts, skipConnectListenerPorts map[int]bool, skipConnectProcessNames map[string]bool, skipConnectExePatterns []*regexp.Regexp, monitorFileOps bool, fileListenerPorts map[int]bool, monitorSensitiveFileReads bool, sensitiveFilePaths []string, auditArches []string, javaMonitorMode string) *processTreeMonitor {
	selfExe, _ := os.Executable()
	selfPID := os.Getpid()
	return &processTreeMonitor{
		selfPID:                   selfPID,
		selfExe:                   selfExe,
		selfBranch:                collectSelfBranchPIDs(selfPID, selfExe),
		portFilter:                portFilter,
		whitelistPorts:            whitelistPorts,
		listeners:                 listeners,
		pidListener:               map[int]listenerInfo{},
		monitored:                 map[int]bool{},
		processStartTimes:         map[int]uint64{},
		processParentPIDs:         map[int]int{},
		processObservedAt:         map[int]time.Time{},
		pendingRuleExpansion:      map[int]bool{},
		pendingPIDRuleCleanup:     map[int]bool{},
		pendingExeRuleCleanup:     map[string]bool{},
		exeMonitored:              map[string]bool{},
		pidCleanupFailureCount:    map[int]int{},
		pidCleanupFirstFailed:     map[int]time.Time{},
		exeCleanupFailureCount:    map[string]int{},
		exeCleanupFirstFailed:     map[string]time.Time{},
		execKey:                   execKey,
		connectKey:                connectKey,
		fileKey:                   fileKey,
		sensitiveFileKey:          sensitiveFileKey,
		cloneKey:                  cloneKey,
		trackDescendants:          trackDescendants,
		monitorExec:               monitorExec,
		execListenerPorts:         execListenerPorts,
		monitorConnect:            monitorConnect,
		monitorFileOps:            monitorFileOps,
		monitorSensitiveFileReads: monitorSensitiveFileReads,
		sensitiveFilePaths:        append([]string(nil), sensitiveFilePaths...),
		connectListenerPorts:      connectListenerPorts,
		skipConnectListenerPorts:  skipConnectListenerPorts,
		skipConnectProcessNames:   skipConnectProcessNames,
		skipConnectExePatterns:    skipConnectExePatterns,
		fileListenerPorts:         fileListenerPorts,
		auditArches:               normalizeAuditArches(auditArches),
		javaMonitorMode:           normalizeJavaMonitorMode(javaMonitorMode),
		companionLogged:           map[string]bool{},
		pidTargets:                map[int]trackingTarget{},
		exeTargets:                map[string]trackingTarget{},
		deferredRuleExpansion:     map[int]ruleExpansion{},
		suppressedCloneRules:      map[int]ruleExpansion{},
	}
}

// startRuleExpansionWorker creates the only dynamic rule mutation worker. Clone
// events can arrive in bursts, so producers use a large bounded queue and never
// invoke auditctl synchronously from the audit-read hot path.

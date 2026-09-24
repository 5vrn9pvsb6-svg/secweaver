package auditportexecmon

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"secweaver-agent/internal/modulecontrol"
	"secweaver-agent/pkg/auditstream"
)

// Release builds replace this value from the root VERSION file. Keeping the
// development fallback prevents a module-specific version from drifting.
var version = "development"

func Main(args []string) int {
	// Lifecycle order is deliberate: validate, discover roots, remove stale
	// rules, capture the log cursor, install initial rules, start workers, then
	// consume events. Deferred cleanup runs after workers stop, so no background
	// auditctl command can recreate a rule during shutdown.
	oldArgs := os.Args
	oldCommandLine := flag.CommandLine
	defer func() {
		os.Args = oldArgs
		flag.CommandLine = oldCommandLine
	}()
	os.Args = append([]string{"audit-port-execmon"}, args...)
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	var showVersion bool
	var learningStatus bool
	var configPath string
	var port int
	var auditLog string
	var key string
	var includePPID bool
	var keepRule bool
	var fromStart bool
	var printRaw bool
	var dryRun bool
	var outputLog string

	flag.BoolVar(&showVersion, "version", false, "输出版本号并退出")
	flag.BoolVar(&learningStatus, "learning-status", false, "读取行为学习状态及名单，不修改运行状态")
	flag.StringVar(&configPath, "config", "", "可选：JSON 配置文件路径，支持端口白名单、connect、文件创建删除监控")
	flag.IntVar(&port, "port", 0, "可选：只监控指定对外监听端口；不指定则监控所有对外监听端口")
	flag.StringVar(&auditLog, "audit-log", "/var/log/audit/audit.log", "auditd 日志路径")
	flag.StringVar(&outputLog, "output-log", "", fmt.Sprintf("事件 JSON 输出路径（默认 %s）；- 表示 stdout", defaultOutputLog))
	flag.StringVar(&key, "key", "", "auditd 规则 key，默认自动生成")
	flag.BoolVar(&includePPID, "include-ppid", true, "跟踪监听进程 fork 出的子进程树（含现有与后续 fork 的子进程/孙进程）")
	flag.BoolVar(&keepRule, "keep-rule", false, "退出时保留 auditd 规则")
	flag.BoolVar(&fromStart, "from-start", false, "从 audit.log 文件开头读取；默认只看启动后的新增记录")
	flag.BoolVar(&printRaw, "raw", false, "输出事件时包含原始 audit 记录")
	flag.BoolVar(&dryRun, "dry-run", false, "只发现监听进程、预检查 audit 状态并估算规则数量，不添加 auditd 规则、不读取日志")
	flag.Parse()
	if showVersion {
		fmt.Println(version)
		return 0
	}
	if learningStatus {
		return printLearningStatus(configPath, outputLog)
	}
	if runtime.GOOS != "linux" {
		fatalf("audit-port-execmon only runs on Linux; current platform is %s", runtime.GOOS)
	}

	if port < 0 || port > 65535 {
		fatalf("-port 必须在 1-65535 范围内；不指定或指定 0 表示监控所有对外监听端口")
	}
	if os.Geteuid() != 0 {
		usage := filepath.Base(os.Args[0])
		if port > 0 {
			fatalf("需要 root 权限运行：sudo %s -port %d", usage, port)
		}
		fatalf("需要 root 权限运行：sudo %s", usage)
	}
	if err := requireAuditEnvironment(auditLog); err != nil {
		fatalf("%v", err)
	}

	cfg, err := loadConfig(configPath)
	if err != nil {
		fatalf("读取配置失败：%v", err)
	}
	if !flagChanged("include-ppid") && cfg.Exec.TrackDescendants != nil {
		includePPID = *cfg.Exec.TrackDescendants
	}
	eventLogPath := resolveOutputLog(outputLog, cfg.OutputLog)
	var eventOut io.Writer = io.Discard
	closeEventOut := func() {}
	if !dryRun {
		var err error
		eventOut, closeEventOut, err = openOutputLog(eventLogPath)
		if err != nil {
			fatalf("打开事件输出日志失败：%v", err)
		}
	}
	defer closeEventOut()

	whitelistPorts := buildPortSet(cfg.WhitelistPorts)
	connectListenerPorts := buildPortSet(cfg.Connect.ListenerPorts)
	skipConnectListenerPorts := buildPortSet(cfg.Connect.SkipListenerPorts)
	skipConnectProcessNames := buildStringSet(cfg.Connect.SkipProcessNames)
	skipConnectExePatterns, err := compileRegexps(cfg.Connect.SkipExePatterns)
	if err != nil {
		fatalf("读取配置失败：%v", err)
	}
	execListenerPorts := buildPortSet(cfg.Exec.ListenerPorts)
	fileListenerPorts := buildPortSet(cfg.FileOps.ListenerPorts)
	monitorConnect := configMonitorConnect(cfg)
	monitorExec := configMonitorExec(cfg)
	monitorSensitiveFileReads := configMonitorSensitiveFileReads(cfg)
	sensitiveFilePaths := resolveSensitiveFilePaths(cfg)
	monitorFileOps := cfg.FileOps.Monitor
	auditArches := resolveAuditArches(cfg)
	maxAuditRules := resolveMaxAuditRules(cfg)
	auditPressure := resolveAuditPressureConfig(cfg)
	processTreeConfig := resolveProcessTreeConfig(cfg)
	javaMonitorMode := resolveJavaMonitorMode(cfg)
	selfExe, _ := os.Executable()
	selfPID := os.Getpid()
	selfBranch := collectSelfBranchPIDs(selfPID, selfExe)

	listeners, err := findExternalListeners(port, whitelistPorts)
	if err != nil {
		fatalf("定位对外监听端口进程失败：%v", err)
	}
	listeners, skippedSelfListeners := filterSelfListeners(listeners, selfPID, selfExe, selfBranch)
	if len(listeners) == 0 {
		if skippedSelfListeners > 0 {
			fatalf("定位对外监听端口进程失败：只发现 secweaver-agent 自身监听，已排除；没有其他需要监控的对外监听端口")
		}
		fatalf("定位对外监听端口进程失败：没有找到需要监控的对外监听端口")
	}
	if key == "" {
		if port > 0 {
			key = fmt.Sprintf("tb_port_%d", port)
		} else {
			key = "tb_external_listener"
		}
	}
	execKey := key + "_exec"
	connectKey := key + "_connect"
	fileKey := key + "_file"
	sensitiveFileKey := key + "_sensitive"
	cloneKey := key + "_clone"

	signalCtx, stop := modulecontrol.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancelRun := context.WithCancel(signalCtx)
	defer cancelRun()
	processBackend, processTracker, processBackendReason, err := startConfiguredProcessTracker(ctx, processTreeConfig, monitorExec, !dryRun)
	if err != nil {
		fatalf("启动进程树监控后端失败：%v", err)
	}
	if processTracker != nil {
		defer processTracker.Close()
	}
	// The bounded audit backend never mutates PID rules, while eBPF needs them
	// only for explicitly enabled connect/file collection. Pressure polling is
	// disabled when no dynamic audit rule path exists.
	if processBackend == processTreeBackendAudit || (processBackend == processTreeBackendEBPF && !monitorConnect && !monitorFileOps) {
		auditPressure.Enabled = false
	}

	host := resolveHostIdentity()
	fmt.Fprintf(os.Stderr, "host: name=%s ip=%s\n", host.HostName, host.HostIP)
	fmt.Fprintf(os.Stderr, "event output log: %s\n", eventLogPath)
	fmt.Fprintf(os.Stderr, "monitor external listening processes: count=%d\n", len(listeners))
	fmt.Fprintf(os.Stderr, "process tree backend: %s (%s)\n", processBackend, processBackendReason)
	if skippedSelfListeners > 0 {
		fmt.Fprintf(os.Stderr, "excluded secweaver-agent family listeners: %d\n", skippedSelfListeners)
	}
	if len(whitelistPorts) > 0 {
		fmt.Fprintf(os.Stderr, "whitelist ports: %s\n", formatPortSet(whitelistPorts))
	}
	for _, listener := range listeners {
		if listener.ExeOnly && listener.MonitorExe != "" {
			fmt.Fprintf(os.Stderr, "- exe-only=%s process=%s address=%s port=%d (listener pid=%d)\n", listener.MonitorExe, listener.Process, listener.Address, listener.Port, listener.PID)
		} else if listener.MonitorExe != "" {
			fmt.Fprintf(os.Stderr, "- exe=%s process=%s address=%s port=%d (pid-tree)\n", listener.MonitorExe, listener.Process, listener.Address, listener.Port)
		} else {
			fmt.Fprintf(os.Stderr, "- pid-tree pid=%d process=%s address=%s port=%d\n", listener.PID, listener.Process, listener.Address, listener.Port)
		}
	}
	fmt.Fprintf(os.Stderr, "audit arches: %s\n", strings.Join(auditArches, ","))
	if maxAuditRules > 0 {
		if processBackend == processTreeBackendAudit {
			fmt.Fprintf(os.Stderr, "audit max rules: %d (bounded global rules and watches)\n", maxAuditRules)
		} else {
			fmt.Fprintf(os.Stderr, "audit max rules: %d (dynamic pid expansion degrades beyond this limit)\n", maxAuditRules)
		}
	}
	if auditPressure.Enabled {
		fmt.Fprintf(os.Stderr, "audit pressure adaptive mode: interval=%s backlog=%d/%d/%d%% lost_delta=%d/%d/%d rate_limit=%d/%d recovery=%d cooldown=%s\n",
			auditPressure.CheckInterval,
			auditPressure.BacklogHighPercent, auditPressure.MediumBacklogPercent, auditPressure.SevereBacklogPercent,
			auditPressure.LostDelta, auditPressure.MediumLostDelta, auditPressure.SevereLostDelta,
			auditPressure.LightRateLimitPerSecond, auditPressure.MediumRateLimitPerSecond, auditPressure.RecoveryRateLimitPerSecond,
			auditPressure.Cooldown,
		)
	}
	if monitorExec {
		if len(execListenerPorts) > 0 {
			fmt.Fprintf(os.Stderr, "monitor command exec for listener ports: %s\n", formatPortSet(execListenerPorts))
		} else {
			fmt.Fprintf(os.Stderr, "monitor command exec for all selected listeners\n")
		}
		if processBackend == processTreeBackendEBPF {
			fmt.Fprintf(os.Stderr, "eBPF exec tracking: max_tracked_processes=%d perf_buffer_bytes_per_cpu=%d\n", processTreeConfig.MaxTrackedProcesses, processTreeConfig.PerfBufferBytesPerCPU)
		} else if processBackend == processTreeBackendAudit {
			fmt.Fprintf(os.Stderr, "bounded audit exec tracking: fixed host-wide rules with userspace listener-tree filtering\n")
		} else {
			fmt.Fprintf(os.Stderr, "audit exec key: %s\n", execKey)
		}
	}
	if includePPID && monitorExec && (processBackend == processTreeBackendAudit || processBackend == processTreeBackendAuditPID) {
		fmt.Fprintf(os.Stderr, "audit clone key: %s (track fork descendants)\n", cloneKey)
	}
	if monitorConnect {
		if len(connectListenerPorts) > 0 {
			fmt.Fprintf(os.Stderr, "monitor active connect for listener ports: %s\n", formatPortSet(connectListenerPorts))
		} else {
			fmt.Fprintf(os.Stderr, "monitor active connect for all selected listeners\n")
		}
		fmt.Fprintf(os.Stderr, "audit connect key: %s\n", connectKey)
	}
	if monitorFileOps {
		if len(fileListenerPorts) > 0 {
			fmt.Fprintf(os.Stderr, "monitor file create/delete for listener ports: %s\n", formatPortSet(fileListenerPorts))
		} else {
			fmt.Fprintf(os.Stderr, "monitor file create/delete for all selected listeners\n")
		}
		fmt.Fprintf(os.Stderr, "audit file key: %s\n", fileKey)
	}
	if monitorSensitiveFileReads {
		fmt.Fprintf(os.Stderr, "monitor sensitive file reads for listener processes: %s\n", strings.Join(sensitiveFilePaths, ", "))
		fmt.Fprintf(os.Stderr, "audit sensitive file key: %s\n", sensitiveFileKey)
	}

	monitor := newProcessTreeMonitor(listeners, port, whitelistPorts, execKey, connectKey, fileKey, sensitiveFileKey, cloneKey, includePPID, monitorExec, execListenerPorts, monitorConnect, connectListenerPorts, skipConnectListenerPorts, skipConnectProcessNames, skipConnectExePatterns, monitorFileOps, fileListenerPorts, monitorSensitiveFileReads, sensitiveFilePaths, auditArches, javaMonitorMode)
	monitor.setProcessTracker(processBackend, processTracker)
	monitor.setMaxAuditRules(maxAuditRules)
	monitor.configureAuditPressure(auditPressure)
	listenerRescanInterval := listenerRescanIntervalFromConfig(cfg)
	fmt.Fprintf(os.Stderr, "listener rescan interval: %s\n", listenerRescanInterval)
	estimateTrackDescendants := includePPID
	estimateMonitorExec := monitorExec
	if processBackend == processTreeBackendEBPF || processBackend == processTreeBackendAudit {
		estimateTrackDescendants = false
		estimateMonitorExec = false
	}
	plannedRules := estimatePlannedAuditRulesWithArches(listeners, estimateTrackDescendants, estimateMonitorExec, execListenerPorts, monitorConnect, connectListenerPorts, skipConnectListenerPorts, skipConnectProcessNames, skipConnectExePatterns, monitorFileOps, fileListenerPorts, monitorSensitiveFileReads, sensitiveFilePaths, auditArches, javaMonitorMode)
	if processBackend == processTreeBackendAudit {
		plannedRules = estimateBoundedAuditRuleCount(monitorExec, includePPID, monitorConnect, monitorFileOps, monitorSensitiveFileReads, sensitiveFilePaths, auditArches)
	}
	if maxAuditRules > 0 && plannedRules > maxAuditRules {
		if processBackend == processTreeBackendAudit {
			fmt.Fprintf(os.Stderr, "WARN: bounded audit rules estimate %d exceeds audit.max_rules=%d; startup will reject incomplete fixed coverage\n", plannedRules, maxAuditRules)
		} else {
			fmt.Fprintf(os.Stderr, "WARN: planned initial audit rules estimate %d exceeds audit.max_rules=%d; later PID expansion will degrade when the rule budget is exhausted\n", plannedRules, maxAuditRules)
		}
	}
	if dryRun {
		fmt.Fprintf(os.Stderr, "dry-run: no audit rules will be added and audit log will not be followed\n")
		printAuditPrecheckWarnings(collectAuditPrecheck(), plannedRules)
		return 0
	}
	removed, err := cleanupStaleToolAuditRules(execKey, connectKey, fileKey, sensitiveFileKey, cloneKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cleanup stale audit rules failed: %v\n", err)
	} else if removed > 0 {
		fmt.Fprintf(os.Stderr, "removed %d stale audit rules from previous runs\n", removed)
	}
	printAuditPrecheckWarnings(collectAuditPrecheck(), plannedRules)
	sharedAuditStream, usingSharedAuditStream, err := auditstream.ReaderFromEnv()
	if err != nil {
		fatalf("打开共享 audit 输入失败：%v", err)
	}
	if usingSharedAuditStream {
		defer sharedAuditStream.Close()
		fmt.Fprintf(os.Stderr, "audit log input: shared secweaver-agent demux\n")
	}
	startOffset := int64(-1)
	if !usingSharedAuditStream && !fromStart {
		if offset, err := fileSize(auditLog); err == nil {
			startOffset = offset
		} else {
			fmt.Fprintf(os.Stderr, "capture audit log offset failed: %v\n", err)
		}
	}
	if !keepRule {
		defer func() {
			if removed, err := monitor.cleanupSessionRules(); err != nil {
				fmt.Fprintf(os.Stderr, "cleanup audit rules failed: %v\n", err)
			} else if removed > 0 {
				fmt.Fprintf(os.Stderr, "removed %d audit rules on exit\n", removed)
			}
		}()
	}
	if err := monitor.bootstrapInitialContext(ctx); err != nil {
		return failf("添加 auditd 规则失败：%v", err)
	}
	fmt.Fprintf(os.Stderr, "audit rules added: %d\n", len(monitor.rulesSnapshot())+len(monitor.watchRulesSnapshot()))
	if includePPID {
		fmt.Fprintf(os.Stderr, "tracked process count: %d (exclude agent family branch_pids=%d self pid=%d)\n", monitor.trackedCount(), monitor.selfBranchCount(), os.Getpid())
	}
	monitor.startRuleExpansionWorker()
	defer func() {
		monitor.stopRuleExpansionWorker()
		monitor.logRuleExpansionStats()
	}()
	stopPressureMonitor := startAuditPressureMonitor(ctx, monitor, auditPressure)
	defer stopPressureMonitor()

	// Learning health is sampled off the reader, independently of optional
	// audit pressure adaptation. Missing samples never advance learning.
	lastLearningLost := -1
	lastTrackerLost := uint64(0)
	learningHealth := func() (bool, bool) {
		if processTracker != nil {
			lost := processTracker.LostSamples()
			changed := lost != lastTrackerLost
			lastTrackerLost = lost
			return true, changed
		}
		status, err := collectAuditStatus()
		if err != nil {
			return false, false
		}
		lost, err := strconv.Atoi(status["lost"])
		if err != nil || lost < 0 || (status["enabled"] != "1" && status["enabled"] != "2") {
			return false, false
		}
		changed := lastLearningLost >= 0 && lost != lastLearningLost
		lastLearningLost = lost
		return true, changed
	}
	if !fromStart {
		learning, learningErr := newLearningOutput(cfg, eventLogPath, processBackend, eventOut, learningHealth)
		if learningErr != nil {
			fmt.Fprintf(os.Stderr, "behavior learning disabled; keeping original output: %v\n", learningErr)
		} else if learning != nil {
			eventOut = learning
			defer learning.Close()
		}
	}

	trackerResult := make(chan error, 1)
	if processTracker != nil {
		go func() {
			trackerErr := followProcessTracker(ctx, processTracker, monitor, host, eventOut)
			trackerResult <- trackerErr
			if trackerErr != nil && !errors.Is(trackerErr, context.Canceled) {
				cancelRun()
			}
		}()
	}

	if usingSharedAuditStream {
		err = followAuditStream(ctx, sharedAuditStream, execKey, connectKey, fileKey, monitor, host, printRaw, eventOut, listenerRescanInterval)
	} else {
		err = followAuditLog(ctx, auditLog, execKey, connectKey, fileKey, monitor, host, fromStart, startOffset, printRaw, eventOut, listenerRescanInterval)
	}
	if processTracker != nil {
		// Join producers before draining learning and closing its output sinks.
		cancelRun()
		trackerErr := <-trackerResult
		if trackerErr != nil && !errors.Is(trackerErr, context.Canceled) {
			learningFault(eventOut, "ebpf_reader_failed")
			return failf("读取 eBPF 进程事件失败：%v", trackerErr)
		}
	}
	if err != nil && !errors.Is(err, context.Canceled) {
		learningFault(eventOut, "audit_reader_failed")
		return failf("读取 audit 日志失败：%v", err)
	}
	return 0
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func failf(format string, args ...any) int {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	return 1
}

//go:build windows

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"secweaver-agent/pkg/metrics"
	agentoutput "secweaver-agent/pkg/output"
)

const windowsServiceName = "SecWeaverAgent"

const (
	serviceWin32OwnProcess = 0x00000010

	serviceStopped      = 0x00000001
	serviceStartPending = 0x00000002
	serviceStopPending  = 0x00000003
	serviceRunning      = 0x00000004

	serviceAcceptStop     = 0x00000001
	serviceAcceptShutdown = 0x00000004

	serviceControlStop        = 0x00000001
	serviceControlInterrogate = 0x00000004
	serviceControlShutdown    = 0x00000005

	serviceNoError                                    = 0
	errorFailedServiceControllerConnect syscall.Errno = 1063
)

type serviceTableEntry struct {
	serviceName *uint16
	serviceProc uintptr
}

type serviceStatus struct {
	serviceType             uint32
	currentState            uint32
	controlsAccepted        uint32
	win32ExitCode           uint32
	serviceSpecificExitCode uint32
	checkPoint              uint32
	waitHint                uint32
}

var (
	advapi32                         = syscall.NewLazyDLL("advapi32.dll")
	procStartServiceCtrlDispatcherW  = advapi32.NewProc("StartServiceCtrlDispatcherW")
	procRegisterServiceCtrlHandlerEx = advapi32.NewProc("RegisterServiceCtrlHandlerExW")
	procSetServiceStatus             = advapi32.NewProc("SetServiceStatus")

	// syscall.NewCallback requires a uintptr-sized return value for callbacks
	// even when the native SCM entry point ignores it. Keep ABI adapters here so
	// every command, including config subcommands, can initialize on Windows.
	serviceMainCallback = syscall.NewCallback(windowsServiceMainCallback)
	serviceCtrlCallback = syscall.NewCallback(windowsServiceCtrlHandlerCallback)

	serviceConfigPath string
	serviceHandle     uintptr
	serviceCancel     context.CancelFunc
	serviceMu         sync.Mutex
	serviceCheckPoint uint32
)

func runServiceCommand(args []string) int {
	fs := flag.NewFlagSet("service", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := defaultAgentConfigPath()
	fs.StringVar(&configPath, "config", configPath, "agent JSON config path")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if err := runWindowsService(configPath); err != nil {
		fmt.Fprintf(os.Stderr, "service failed: %v\n", err)
		return 1
	}
	return 0
}

func runWindowsService(configPath string) error {
	serviceConfigPath = configPath
	name, err := syscall.UTF16PtrFromString(windowsServiceName)
	if err != nil {
		return err
	}
	entries := []serviceTableEntry{
		{serviceName: name, serviceProc: serviceMainCallback},
		{},
	}
	r1, _, callErr := procStartServiceCtrlDispatcherW.Call(uintptr(unsafe.Pointer(&entries[0])))
	if r1 != 0 {
		return nil
	}
	if errno, ok := callErr.(syscall.Errno); ok && errno == errorFailedServiceControllerConnect {
		return runWindowsServiceConsole(configPath)
	}
	if callErr != syscall.Errno(0) {
		return callErr
	}
	return syscall.GetLastError()
}

func runWindowsServiceConsole(configPath string) error {
	serviceLogf("service command started outside SCM; running in console mode config=%s", configPath)
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	return runWindowsServiceSupervisor(ctx, configPath)
}

// windowsServiceMainCallback adapts the Windows SCM callback ABI to the
// strongly typed service implementation. The return value is required by Go's
// callback trampoline and is ignored by StartServiceCtrlDispatcherW.
func windowsServiceMainCallback(argc, argv uintptr) uintptr {
	windowsServiceMain(uint32(argc), argv)
	return 0
}

func windowsServiceMain(argc uint32, argv uintptr) {
	_ = argc
	_ = argv
	handle, err := registerServiceCtrlHandler()
	if err != nil {
		serviceLogf("register service control handler failed: %v", err)
		return
	}
	serviceMu.Lock()
	serviceHandle = handle
	serviceCheckPoint = 1
	serviceMu.Unlock()
	setWindowsServiceStatus(serviceStartPending, 0, 1, 30000)

	serviceLogf("service starting config=%s", serviceConfigPath)

	ctx, cancel := context.WithCancel(context.Background())
	serviceMu.Lock()
	serviceCancel = cancel
	serviceMu.Unlock()
	defer cancel()

	setWindowsServiceStatus(serviceRunning, serviceAcceptStop|serviceAcceptShutdown, 0, 0)
	err = runWindowsServiceSupervisor(ctx, serviceConfigPath)
	exitCode := uint32(0)
	if err != nil && !errors.Is(err, context.Canceled) {
		exitCode = 1
		serviceLogf("service stopped with error: %v", err)
	} else {
		serviceLogf("service stopped")
	}
	setWindowsServiceStatus(serviceStopped, 0, exitCode, 0)
}

func registerServiceCtrlHandler() (uintptr, error) {
	name, err := syscall.UTF16PtrFromString(windowsServiceName)
	if err != nil {
		return 0, err
	}
	r1, _, callErr := procRegisterServiceCtrlHandlerEx.Call(
		uintptr(unsafe.Pointer(name)),
		serviceCtrlCallback,
		0,
	)
	if r1 == 0 {
		if callErr != syscall.Errno(0) {
			return 0, callErr
		}
		return 0, syscall.GetLastError()
	}
	return r1, nil
}

func windowsServiceCtrlHandler(control uint32, eventType uint32, eventData uintptr, context uintptr) uintptr {
	_ = eventType
	_ = eventData
	_ = context
	switch control {
	case serviceControlStop, serviceControlShutdown:
		setWindowsServiceStatus(serviceStopPending, 0, 1, 30000)
		serviceMu.Lock()
		cancel := serviceCancel
		serviceMu.Unlock()
		if cancel != nil {
			cancel()
		}
		return serviceNoError
	case serviceControlInterrogate:
		return serviceNoError
	default:
		return serviceNoError
	}
}

// windowsServiceCtrlHandlerCallback keeps all callback parameters uintptr-sized
// at the syscall boundary, preventing architecture-specific callback layout
// assumptions on Windows amd64 and arm64.
func windowsServiceCtrlHandlerCallback(control, eventType, eventData, context uintptr) uintptr {
	return windowsServiceCtrlHandler(uint32(control), uint32(eventType), eventData, context)
}

func setWindowsServiceStatus(state, accepted, exitCode, waitHint uint32) {
	serviceMu.Lock()
	handle := serviceHandle
	checkPoint := serviceCheckPoint
	if state == serviceStartPending || state == serviceStopPending {
		serviceCheckPoint++
		checkPoint = serviceCheckPoint
	} else {
		checkPoint = 0
	}
	serviceMu.Unlock()
	if handle == 0 {
		return
	}
	status := serviceStatus{
		serviceType:      serviceWin32OwnProcess,
		currentState:     state,
		controlsAccepted: accepted,
		win32ExitCode:    exitCode,
		checkPoint:       checkPoint,
		waitHint:         waitHint,
	}
	_, _, _ = procSetServiceStatus.Call(handle, uintptr(unsafe.Pointer(&status)))
}

func runWindowsServiceSupervisor(ctx context.Context, configPath string) error {
	cfg, err := loadConfig(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	modules, err := enabledModules(cfg)
	if err != nil {
		return fmt.Errorf("config validation: %w", err)
	}
	updateRuntime, err := scheduledUpdateFromConfig(cfg.Update)
	if err != nil {
		return fmt.Errorf("config validation: update: %w", err)
	}
	licenseRuntime := cfg.License.Normalize()
	if err := licenseRuntime.Validate(); err != nil {
		return fmt.Errorf("config validation: license: %w", err)
	}
	if err := bindUpdateRuntimeToDevice(updateRuntime, licenseRuntime); err != nil {
		return fmt.Errorf("config validation: update: %w", err)
	}
	remoteRuntime, err := scheduledRemoteConfigFromConfig(cfg.RemoteConfig, configPath, licenseRuntime, cfg.EnterpriseID)
	if err != nil {
		return fmt.Errorf("config validation: remote_config: %w", err)
	}
	statusPath := strings.TrimSpace(cfg.StatusPath)
	if statusPath == "" {
		statusPath = defaultStatusPath()
	}
	if err := prepareUpdateActivation(updateRuntime); err != nil {
		return err
	}
	operationsRuntime, err := normalizeOperationsReportConfig(cfg.Operations)
	if err != nil {
		return fmt.Errorf("configure operations report: %w", err)
	}
	if err := agentoutput.ApplyDiskBudgetEnvironment(cfg.DiskBudget, configuredOutputFileCount(modules, updateRuntime, &operationsRuntime)); err != nil {
		return fmt.Errorf("configure output disk budget: %w", err)
	}
	statusTracker := newStatusTracker(statusPath, cfg.EnterpriseID, licenseRuntime, modules)
	statusTracker.write()
	statusTracker.startWriter()
	defer func() {
		if err := statusTracker.closeWriter(); err != nil {
			serviceLogf("final status persistence failed: %v", err)
		}
	}()
	// Build metrics before authorization so the initial check is included in the
	// same counters as scheduled checks; bind only after authorization succeeds.
	var metricsExporter *metrics.Exporter
	if cfg.Metrics.Enabled {
		metricsExporter = metrics.NewExporter(cfg.EnterpriseID, version)
		metricsExporter.SetHealthCheck(statusTracker.readiness)
	}
	if err := waitForInitialAgentLicense(ctx, licenseRuntime, cfg.EnterpriseID, statusTracker, metricsExporter, initialLicenseRetryDelay, maximumLicenseRetryDelay); err != nil {
		return fmt.Errorf("license check: %w", err)
	}
	// Keep the Windows SCM path equivalent to the unified run path: metrics must
	// start before supervision so module status and restart updates are exported
	// in both service and console modes.
	if metricsExporter != nil {
		metricsConfig := metrics.Config{
			Enabled:       cfg.Metrics.Enabled,
			ListenAddress: cfg.Metrics.ListenAddress,
			Path:          cfg.Metrics.Path,
		}
		metricsCtx, metricsCancel := context.WithCancel(ctx)
		defer metricsCancel()
		if err := metricsExporter.Start(metricsCtx, metricsConfig); err != nil {
			serviceLogf("metrics exporter start warning: %v", err)
			metricsExporter = nil
		}
	}
	printPreflightReport(os.Stderr, collectPreflightReport(configPath, modules, updateRuntime), false)
	return runSupervisor(ctx, modules, updateRuntime, remoteRuntime, licenseRuntime, cfg.EnterpriseID, statusTracker, metricsExporter, &operationsRuntime)
}

func serviceLogf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "%s ", time.Now().Format(time.RFC3339))
	fmt.Fprintf(os.Stderr, format, args...)
	fmt.Fprintln(os.Stderr)
}

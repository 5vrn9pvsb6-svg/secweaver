package auditportexecmon

import (
	"testing"

	"go.uber.org/goleak"
)

// P1-5: Goroutine leak detection tests
// This ensures all goroutines are properly cleaned up

func TestMain(m *testing.M) {
	// Enable goleak for all tests in this package
	goleak.VerifyTestMain(m,
		// Ignore known background goroutines from dependencies
		goleak.IgnoreTopFunction("internal/poll.runtime_pollWait"),
		goleak.IgnoreTopFunction("go.opencensus.io/stats/view.(*worker).start"),
	)
}

func TestNoGoroutineLeakInMonitor(t *testing.T) {
	defer goleak.VerifyNone(t)

	// Test basic monitor lifecycle
	listeners := []listenerInfo{
		{Process: "test", Port: 9000, PID: 1000},
	}

	monitor := newProcessTreeMonitor(
		listeners,
		0,                        // portFilter
		nil,                      // whitelistPorts
		"test-exec",              // execKey
		"test-connect",           // connectKey
		"test-file",              // fileKey
		"test-sensitive",         // sensitiveFileKey
		"test-clone",             // cloneKey
		true,                     // trackDescendants
		true,                     // monitorExec
		map[int]bool{9000: true}, // execListenerPorts
		false,                    // monitorConnect
		nil,                      // connectListenerPorts
		nil,                      // skipConnectListenerPorts
		nil,                      // skipConnectProcessNames
		nil,                      // skipConnectExePatterns
		false,                    // monitorFileOps
		nil,                      // fileListenerPorts
		false,                    // monitorSensitiveFileReads
		nil,                      // sensitiveFilePaths
		[]string{"b64"},          // auditArches
		"default",                // javaMonitorMode
	)

	// Start worker
	monitor.startRuleExpansionWorker()

	// Stop worker
	monitor.stopRuleExpansionWorker()

	// No goroutines should leak
}

func TestNoGoroutineLeakInRuleExpansion(t *testing.T) {
	defer goleak.VerifyNone(t)

	listeners := []listenerInfo{
		{Process: "nginx", Port: 80, PID: 2000},
	}

	monitor := newProcessTreeMonitor(
		listeners,
		0,
		nil,
		"exec-key",
		"connect-key",
		"file-key",
		"sensitive-key",
		"clone-key",
		true,
		true,
		map[int]bool{80: true},
		false,
		nil,
		nil,
		nil,
		nil,
		false,
		nil,
		false,
		nil,
		[]string{"b64"},
		"default",
	)

	// Start and immediately stop - should not leak
	monitor.startRuleExpansionWorker()
	monitor.stopRuleExpansionWorker()
}

package hoststatesnapshot

import (
	"context"
	"fmt"
	"runtime"
	"time"
)

func collectSocketState(ctx context.Context, now time.Time, maxFDScan int) ([]entity, error) {
	if runtime.GOOS == "windows" {
		return collectWindowsSockets(ctx, now)
	}
	if runtime.GOOS == "linux" {
		return collectLinuxSockets(ctx, "/proc", now, maxFDScan)
	}
	return nil, fmt.Errorf("unsupported platform %s", runtime.GOOS)
}

func collectIdentityState(ctx context.Context, now time.Time, containerWorkload bool) ([]entity, error) {
	if runtime.GOOS == "windows" {
		return collectWindowsIdentity(ctx, now)
	}
	if runtime.GOOS == "linux" {
		if containerWorkload {
			return collectLinuxContainerIdentity("/", now)
		}
		return collectLinuxIdentity(ctx, "/", now)
	}
	return nil, fmt.Errorf("unsupported platform %s", runtime.GOOS)
}

func collectServiceState(ctx context.Context, now time.Time) ([]entity, error) {
	if runtime.GOOS == "windows" {
		return collectWindowsServices(ctx, now)
	}
	if runtime.GOOS == "linux" {
		return collectLinuxServices(ctx, "/", now)
	}
	return nil, fmt.Errorf("unsupported platform %s", runtime.GOOS)
}

func collectKernelContainerState(ctx context.Context, now time.Time) ([]entity, error) {
	if runtime.GOOS == "windows" {
		return collectWindowsKernel(ctx, now)
	}
	if runtime.GOOS == "linux" {
		return collectLinuxKernelContainers("/proc", now)
	}
	return nil, fmt.Errorf("unsupported platform %s", runtime.GOOS)
}

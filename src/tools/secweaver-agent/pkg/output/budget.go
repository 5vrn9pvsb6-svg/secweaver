package output

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultDiskBudgetTotalMB      = 2048
	defaultDiskBudgetMinFreeMB    = 512
	defaultDiskBudgetCheckSeconds = 30

	diskBudgetEnabledEnv       = "SECWEAVER_OUTPUT_BUDGET_ENABLED"
	diskBudgetPerFileBytesEnv  = "SECWEAVER_OUTPUT_BUDGET_PER_FILE_BYTES"
	diskBudgetMinFreeBytesEnv  = "SECWEAVER_OUTPUT_MIN_FREE_BYTES"
	diskBudgetCheckIntervalEnv = "SECWEAVER_OUTPUT_BUDGET_CHECK_INTERVAL_SECONDS"
	DiskPriorityEnv            = "SECWEAVER_OUTPUT_PRIORITY"

	DiskPriorityRealtime = "realtime"
	DiskPriorityStandard = "standard"
	DiskPrioritySnapshot = "snapshot"
)

// DiskBudgetConfig is the host-wide retention and reserve contract. The parent
// divides MaxTotalMB across declared file outputs, while every child enforces
// its assigned share and the common filesystem reserve independently.
type DiskBudgetConfig struct {
	Enabled              *bool `json:"enabled,omitempty"`
	MaxTotalMB           int   `json:"max_total_mb,omitempty"`
	MinFreeMB            int   `json:"min_free_mb,omitempty"`
	CheckIntervalSeconds int   `json:"check_interval_seconds,omitempty"`
}

func (c DiskBudgetConfig) EnabledValue() bool {
	return c.Enabled == nil || *c.Enabled
}

// NormalizeDiskBudgetConfig applies conservative defaults and rejects values
// that could disable retention accidentally through integer underflow.
func NormalizeDiskBudgetConfig(c DiskBudgetConfig) (DiskBudgetConfig, error) {
	if c.MaxTotalMB < 0 || c.MinFreeMB < 0 || c.CheckIntervalSeconds < 0 {
		return DiskBudgetConfig{}, fmt.Errorf("max_total_mb, min_free_mb, and check_interval_seconds must be >= 0")
	}
	if c.MaxTotalMB == 0 {
		c.MaxTotalMB = defaultDiskBudgetTotalMB
	}
	if c.MinFreeMB == 0 {
		c.MinFreeMB = defaultDiskBudgetMinFreeMB
	}
	if c.CheckIntervalSeconds == 0 {
		c.CheckIntervalSeconds = defaultDiskBudgetCheckSeconds
	}
	if c.EnabledValue() && c.MaxTotalMB < 64 {
		return DiskBudgetConfig{}, fmt.Errorf("max_total_mb must be at least 64 when disk budget is enabled")
	}
	return c, nil
}

// ApplyDiskBudgetEnvironment publishes one normalized policy before child
// processes start. Environment transport keeps every independently supervised
// collector on the same budget without duplicating module-specific flags.
func ApplyDiskBudgetEnvironment(c DiskBudgetConfig, outputFiles int) error {
	normalized, err := NormalizeDiskBudgetConfig(c)
	if err != nil {
		return err
	}
	if outputFiles <= 0 {
		outputFiles = 1
	}
	values := map[string]string{
		diskBudgetEnabledEnv:       strconv.FormatBool(normalized.EnabledValue()),
		diskBudgetPerFileBytesEnv:  strconv.FormatInt(int64(normalized.MaxTotalMB)*1024*1024/int64(outputFiles), 10),
		diskBudgetMinFreeBytesEnv:  strconv.FormatInt(int64(normalized.MinFreeMB)*1024*1024, 10),
		diskBudgetCheckIntervalEnv: strconv.Itoa(normalized.CheckIntervalSeconds),
		DiskPriorityEnv:            DiskPriorityStandard,
	}
	for key, value := range values {
		if err := os.Setenv(key, value); err != nil {
			return fmt.Errorf("set %s: %w", key, err)
		}
	}
	return nil
}

type diskBudgetPolicy struct {
	enabled       bool
	perFileBytes  int64
	minFreeBytes  uint64
	checkInterval time.Duration
	priority      string
}

// diskBudgetPolicyFromEnv treats malformed supervised environment as a startup
// error instead of silently running without the configured host protection.
func diskBudgetPolicyFromEnv() (diskBudgetPolicy, error) {
	enabledValue := strings.TrimSpace(os.Getenv(diskBudgetEnabledEnv))
	if enabledValue == "" {
		return diskBudgetPolicy{}, nil
	}
	enabled, err := strconv.ParseBool(enabledValue)
	if err != nil {
		return diskBudgetPolicy{}, fmt.Errorf("invalid %s: %w", diskBudgetEnabledEnv, err)
	}
	policy := diskBudgetPolicy{enabled: enabled, priority: normalizeDiskPriority(os.Getenv(DiskPriorityEnv))}
	if !enabled {
		return policy, nil
	}
	perFile, err := strconv.ParseInt(strings.TrimSpace(os.Getenv(diskBudgetPerFileBytesEnv)), 10, 64)
	if err != nil || perFile <= 0 {
		return diskBudgetPolicy{}, fmt.Errorf("invalid %s", diskBudgetPerFileBytesEnv)
	}
	minFree, err := strconv.ParseUint(strings.TrimSpace(os.Getenv(diskBudgetMinFreeBytesEnv)), 10, 64)
	if err != nil {
		return diskBudgetPolicy{}, fmt.Errorf("invalid %s", diskBudgetMinFreeBytesEnv)
	}
	seconds, err := strconv.Atoi(strings.TrimSpace(os.Getenv(diskBudgetCheckIntervalEnv)))
	if err != nil || seconds <= 0 {
		return diskBudgetPolicy{}, fmt.Errorf("invalid %s", diskBudgetCheckIntervalEnv)
	}
	policy.perFileBytes = perFile
	policy.minFreeBytes = minFree
	policy.checkInterval = time.Duration(seconds) * time.Second
	return policy, nil
}

func normalizeDiskPriority(priority string) string {
	switch strings.ToLower(strings.TrimSpace(priority)) {
	case DiskPriorityRealtime:
		return DiskPriorityRealtime
	case DiskPrioritySnapshot:
		return DiskPrioritySnapshot
	default:
		return DiskPriorityStandard
	}
}

// retentionWithinBudget clamps both dimensions of numeric rotation. Small
// budgets reduce backup count before allowing an impractically tiny active file.
func retentionWithinBudget(maxSize int64, maxBackups int, budget int64) (int64, int) {
	if budget <= 0 || maxSize <= 0 {
		return maxSize, maxBackups
	}
	const minimumUsefulFile = int64(1024 * 1024)
	maximumSlots := int(budget / minimumUsefulFile)
	if maximumSlots < 1 {
		maximumSlots = 1
	}
	if maxBackups+1 > maximumSlots {
		maxBackups = maximumSlots - 1
	}
	perSlot := budget / int64(maxBackups+1)
	if maxSize > perSlot {
		maxSize = perSlot
	}
	return maxSize, maxBackups
}

func (p diskBudgetPolicy) requiredFreeBytes() uint64 {
	extra := uint64(0)
	switch p.priority {
	case DiskPrioritySnapshot:
		extra = uint64(p.perFileBytes / 4)
	case DiskPriorityStandard:
		extra = uint64(p.perFileBytes / 10)
	}
	return p.minFreeBytes + extra
}

package output

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEffectiveRetentionMatchesWriter(t *testing.T) {
	disabled := false
	for _, tc := range []struct {
		name    string
		config  DiskBudgetConfig
		files   int
		size    int64
		backups int
	}{
		{name: "defaults", files: 9},
		{name: "disabled", config: DiskBudgetConfig{Enabled: &disabled}, files: 9},
		{name: "small share", config: DiskBudgetConfig{MaxTotalMB: 64}, files: 64},
		{name: "custom limits", files: 9, size: 2 << 20, backups: 2},
		{name: "no files"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, key := range []string{diskBudgetEnabledEnv, diskBudgetPerFileBytesEnv, diskBudgetMinFreeBytesEnv, diskBudgetCheckIntervalEnv, DiskPriorityEnv} {
				t.Setenv(key, os.Getenv(key))
			}
			// Diagnostics must ignore stale/inherited writer environment and must
			// not mutate it while resolving the policy from the current config.
			t.Setenv(diskBudgetEnabledEnv, "malformed")
			limits, err := EffectiveRetention(tc.config, tc.files, tc.size, tc.backups)
			if err != nil {
				t.Fatal(err)
			}
			if os.Getenv(diskBudgetEnabledEnv) != "malformed" {
				t.Fatal("diagnostics changed writer environment")
			}
			if err := ApplyDiskBudgetEnvironment(tc.config, tc.files); err != nil {
				t.Fatal(err)
			}
			writer, err := OpenRotatingFile(filepath.Join(t.TempDir(), "events.log"), DefaultFilePerm, tc.size, tc.backups)
			if err != nil {
				t.Fatal(err)
			}
			defer writer.Close()
			if writer.maxSizeBytes != limits.MaxSizeBytes || writer.maxBackups != limits.MaxBackups {
				t.Fatalf("writer %d/%d != diagnostics %+v", writer.maxSizeBytes, writer.maxBackups, limits)
			}
			if tc.config.EnabledValue() {
				if limits.MaxSizeBytes*int64(limits.MaxBackups+1) > limits.PerFileBudgetBytes {
					t.Fatalf("limits exceed per-file budget: %+v", limits)
				}
			} else if limits.PerFileBudgetBytes != 0 {
				t.Fatalf("disabled budget still reserves bytes: %+v", limits)
			}
		})
	}
}

func TestEffectiveRetentionRejectsInvalidBudget(t *testing.T) {
	if _, err := EffectiveRetention(DiskBudgetConfig{MaxTotalMB: 1}, 9, 0, 0); err == nil {
		t.Fatal("invalid budget accepted")
	}
}

package auditportexecmon

import (
	"testing"
)

// 真实的 audit 日志样本
var testAuditLines = []string{
	// SYSCALL record with many fields
	`type=SYSCALL msg=audit(1234567890.123:456): arch=c000003e syscall=59 success=yes exit=0 a0=7fff12345678 a1=7fff56781234 a2=7fff9abcdef0 a3=8 items=2 ppid=1000 pid=1001 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 comm="bash" exe="/bin/bash" key="test_key"`,

	// EXECVE record with arguments
	`type=EXECVE msg=audit(1234567890.123:456): argc=3 a0="/bin/sh" a1="-c" a2="echo hello world"`,

	// PATH record with quoted paths
	`type=PATH msg=audit(1234567890.123:456): item=0 name="/usr/bin/bash" inode=123456 dev=08:01 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL`,

	// Record with escaped quotes
	`type=PROCTITLE msg=audit(1234567890.123:456): proctitle="/bin/bash" -c "echo \"hello world\""`,

	// Connect record
	`type=SOCKADDR msg=audit(1234567890.123:456): saddr=02001F9001020304000000000000000000000000`,
}

// BenchmarkParseFieldsFast tests the optimized state-machine parser
func BenchmarkParseFieldsFast(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		for _, line := range testAuditLines {
			_ = parseFieldsFast(line)
		}
	}
}

// BenchmarkParseFieldsRegex tests the original regex-based parser
func BenchmarkParseFieldsRegex(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		for _, line := range testAuditLines {
			_ = parseFieldsRegex(line)
		}
	}
}

// BenchmarkParseFieldsFastSingleLine tests single line parsing
func BenchmarkParseFieldsFastSingleLine(b *testing.B) {
	line := testAuditLines[0]
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = parseFieldsFast(line)
	}
}

// BenchmarkParseFieldsRegexSingleLine tests single line parsing with regex
func BenchmarkParseFieldsRegexSingleLine(b *testing.B) {
	line := testAuditLines[0]
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = parseFieldsRegex(line)
	}
}

// BenchmarkReadProcStartTime tests the cached /proc read
func BenchmarkReadProcStartTime(b *testing.B) {
	pid := 1 // init process, always exists
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = readProcStartTime(pid)
	}
}

// BenchmarkReadProcStartTimeCacheMiss simulates cache misses
func BenchmarkReadProcStartTimeCacheMiss(b *testing.B) {
	// Use different PIDs to force cache misses
	pids := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		pid := pids[i%len(pids)]
		_ = readProcStartTime(pid)
	}
}

// TestParseFieldsCompatibility ensures new parser produces same results as original
func TestParseFieldsCompatibility(t *testing.T) {
	for i, line := range testAuditLines {
		fast := parseFieldsFast(line)
		regex := parseFieldsRegex(line)

		// Compare field counts
		if len(fast) != len(regex) {
			t.Errorf("Line %d: field count mismatch: fast=%d, regex=%d", i, len(fast), len(regex))
			t.Logf("Fast fields: %v", fast)
			t.Logf("Regex fields: %v", regex)
			continue
		}

		// Compare each field
		for key, regexValue := range regex {
			fastValue, ok := fast[key]
			if !ok {
				t.Errorf("Line %d: missing key %q in fast parser", i, key)
				continue
			}
			if fastValue != regexValue {
				t.Errorf("Line %d: value mismatch for key %q: fast=%q, regex=%q", i, key, fastValue, regexValue)
			}
		}
	}
}

// TestParseFieldsEdgeCases tests boundary conditions
func TestParseFieldsEdgeCases(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  map[string]string
	}{
		{
			name:  "empty line",
			input: "",
			want:  map[string]string{},
		},
		{
			name:  "no equals",
			input: "type SYSCALL msg audit",
			want:  map[string]string{},
		},
		{
			name:  "single field",
			input: "key=value",
			want:  map[string]string{"key": "value"},
		},
		{
			name:  "quoted value",
			input: `key="quoted value"`,
			want:  map[string]string{"key": "quoted value"},
		},
		{
			name:  "escaped quote",
			input: `key="escaped\"quote"`,
			want:  map[string]string{"key": `escaped"quote`},
		},
		{
			name:  "multiple spaces",
			input: "key1=value1    key2=value2",
			want:  map[string]string{"key1": "value1", "key2": "value2"},
		},
		{
			name:  "execve args",
			input: `a0="/bin/sh" a1="-c" a2="echo test"`,
			want:  map[string]string{"a0": "/bin/sh", "a1": "-c", "a2": "echo test"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseFieldsFast(tt.input)

			if len(got) != len(tt.want) {
				t.Errorf("field count mismatch: got %d, want %d", len(got), len(tt.want))
				t.Logf("got: %v", got)
				t.Logf("want: %v", tt.want)
				return
			}

			for key, wantValue := range tt.want {
				gotValue, ok := got[key]
				if !ok {
					t.Errorf("missing key %q", key)
					continue
				}
				if gotValue != wantValue {
					t.Errorf("value mismatch for key %q: got %q, want %q", key, gotValue, wantValue)
				}
			}
		})
	}
}

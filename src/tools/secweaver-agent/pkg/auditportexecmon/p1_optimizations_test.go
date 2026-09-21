package auditportexecmon

import (
	"sync"
	"testing"
	"time"
)

// TestObjectPool tests the audit accumulator object pool
func TestObjectPool(t *testing.T) {
	// Test basic get/put cycle
	t.Run("BasicGetPut", func(t *testing.T) {
		acc := getAccumulator("test-id-1")
		if acc == nil {
			t.Fatal("getAccumulator returned nil")
		}
		if acc.id != "test-id-1" {
			t.Errorf("Expected id 'test-id-1', got '%s'", acc.id)
		}
		if len(acc.fields) != 0 {
			t.Errorf("Expected empty fields map, got %d entries", len(acc.fields))
		}

		// Add some data
		acc.fields["key1"] = "value1"
		acc.argv[0] = "arg0"
		acc.paths[1] = "/path/1"
		acc.proctitle = "test"
		acc.seenSyscall = true

		// Return to pool
		putAccumulator(acc)

		// Get another accumulator - should be clean
		acc2 := getAccumulator("test-id-2")
		if acc2 == nil {
			t.Fatal("getAccumulator returned nil on second call")
		}
		if len(acc2.fields) != 0 {
			t.Errorf("Accumulator not cleaned: fields has %d entries", len(acc2.fields))
		}
		if len(acc2.argv) != 0 {
			t.Errorf("Accumulator not cleaned: argv has %d entries", len(acc2.argv))
		}
		if len(acc2.paths) != 0 {
			t.Errorf("Accumulator not cleaned: paths has %d entries", len(acc2.paths))
		}
		if acc2.proctitle != "" {
			t.Errorf("Accumulator not cleaned: proctitle is '%s'", acc2.proctitle)
		}
		if acc2.seenSyscall {
			t.Error("Accumulator not cleaned: seenSyscall is true")
		}

		putAccumulator(acc2)
	})

	// Test concurrent access
	t.Run("ConcurrentAccess", func(t *testing.T) {
		var wg sync.WaitGroup
		numGoroutines := 100

		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()

				acc := getAccumulator("concurrent-test")
				if acc == nil {
					t.Errorf("getAccumulator returned nil in goroutine %d", id)
					return
				}

				// Simulate usage
				acc.fields["test"] = "value"
				acc.argv[0] = "arg"
				time.Sleep(time.Millisecond)

				putAccumulator(acc)
			}(i)
		}

		wg.Wait()
	})

	// Test nil handling
	t.Run("NilHandling", func(t *testing.T) {
		// Should not panic
		putAccumulator(nil)
	})

	// Test map clearing
	t.Run("MapClearing", func(t *testing.T) {
		acc := getAccumulator("clearing-test")

		// Fill maps with data
		for i := 0; i < 50; i++ {
			acc.fields[string(rune(i))] = "value"
			acc.argv[i] = "arg"
			acc.paths[i] = "/path"
		}

		initialFieldsLen := len(acc.fields)
		initialArgvLen := len(acc.argv)
		initialPathsLen := len(acc.paths)

		if initialFieldsLen != 50 {
			t.Errorf("Expected 50 fields, got %d", initialFieldsLen)
		}

		putAccumulator(acc)

		// Get another accumulator - should be clean
		acc2 := getAccumulator("clearing-test-2")

		// Maps should be cleared
		if len(acc2.fields) != 0 {
			t.Error("Fields map not cleared")
		}
		if len(acc2.argv) != 0 {
			t.Error("Argv map not cleared")
		}
		if len(acc2.paths) != 0 {
			t.Error("Paths map not cleared")
		}

		t.Logf("Initial lengths: fields=%d, argv=%d, paths=%d",
			initialFieldsLen, initialArgvLen, initialPathsLen)
		t.Logf("After reuse: field entries=%d, argv entries=%d, path entries=%d",
			len(acc2.fields), len(acc2.argv), len(acc2.paths))

		putAccumulator(acc2)
	})
}
func BenchmarkObjectPool(b *testing.B) {
	b.Run("GetPut", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			acc := getAccumulator("bench-id")
			acc.fields["test"] = "value"
			putAccumulator(acc)
		}
	})

	b.Run("Parallel", func(b *testing.B) {
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				acc := getAccumulator("bench-id")
				acc.fields["test"] = "value"
				acc.argv[0] = "arg"
				putAccumulator(acc)
			}
		})
	})

	b.Run("WithoutPool", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			// Simulate allocation without pool
			acc := &auditAccumulator{
				id:        "bench-id",
				firstSeen: time.Now(),
				fields:    make(map[string]string, 32),
				argv:      make(map[int]string, 16),
				paths:     make(map[int]string, 8),
			}
			acc.fields["test"] = "value"
			_ = acc
		}
	})
}

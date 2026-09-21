package auditportexecmon

import (
	"sync"
	"time"
)

// This file owns pooled multi-record audit accumulators and their bounded reuse lifecycle.
// P1 Optimization: Object pool for auditAccumulator to reduce allocations
var auditAccumulatorPool = sync.Pool{
	New: func() interface{} {
		return &auditAccumulator{
			fields: make(map[string]string, 32),
			argv:   make(map[int]string, 16),
			paths:  make(map[int]string, 8),
		}
	},
}

// getAccumulator retrieves an accumulator from the pool and initializes it
func getAccumulator(id string) *auditAccumulator {
	// P0-3: Safe type assertion with defensive programming
	accInterface := auditAccumulatorPool.Get()
	acc, ok := accInterface.(*auditAccumulator)
	if !ok || acc == nil {
		// Fallback: create new accumulator if pool returns wrong type
		acc = &auditAccumulator{
			fields: make(map[string]string, 32),
			argv:   make(map[int]string, 16),
			paths:  make(map[int]string, 8),
		}
	}
	acc.id = id
	acc.firstSeen = time.Now()
	acc.lastRecordAt = time.Now()
	acc.seenSyscall = false
	acc.seenExecve = false
	acc.seenProctitle = false
	acc.proctitle = ""
	acc.cwd = ""
	acc.records = nil
	return acc
}

// putAccumulator returns an accumulator to the pool after clearing its data
func putAccumulator(acc *auditAccumulator) {
	if acc == nil {
		return
	}
	// Clear maps but retain capacity
	for k := range acc.fields {
		delete(acc.fields, k)
	}
	for k := range acc.argv {
		delete(acc.argv, k)
	}
	for k := range acc.paths {
		delete(acc.paths, k)
	}
	if acc.records != nil {
		acc.records = acc.records[:0]
	}
	auditAccumulatorPool.Put(acc)
}

// followAuditLog is the standalone transport: it owns audit.log directly,
// assembles multi-record events, and schedules reconciliation without blocking
// line reads. In supervised mode followAuditStream provides the same parser over
// the parent's demultiplexed pipe.

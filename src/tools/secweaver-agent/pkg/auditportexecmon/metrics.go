package auditportexecmon

import "sync/atomic"

// auditParserMetricsSnapshot contains only counters instrumented on production
// parser paths. Rule expansion and pressure metrics live on processTreeMonitor,
// whose lifecycle and ownership differ from the audit stream parser.
type auditParserMetricsSnapshot struct {
	EventsProcessed       uint64
	AccumulatorsCreated   uint64
	AccumulatorsCompleted uint64
	AccumulatorsExpired   uint64
}

var auditParserMetrics struct {
	eventsProcessed       atomic.Uint64
	accumulatorsCreated   atomic.Uint64
	accumulatorsCompleted atomic.Uint64
	accumulatorsExpired   atomic.Uint64
}

func recordEventProcessed()       { auditParserMetrics.eventsProcessed.Add(1) }
func recordAccumulatorCreated()   { auditParserMetrics.accumulatorsCreated.Add(1) }
func recordAccumulatorCompleted() { auditParserMetrics.accumulatorsCompleted.Add(1) }
func recordAccumulatorExpired()   { auditParserMetrics.accumulatorsExpired.Add(1) }

// auditParserMetricsSnapshotNow returns a coherent-enough operational snapshot.
// Counters are monotonic and independent, so exact cross-counter simultaneity is
// unnecessary and avoiding a lock keeps audit ingestion free of contention.
func auditParserMetricsSnapshotNow() auditParserMetricsSnapshot {
	return auditParserMetricsSnapshot{
		EventsProcessed:       auditParserMetrics.eventsProcessed.Load(),
		AccumulatorsCreated:   auditParserMetrics.accumulatorsCreated.Load(),
		AccumulatorsCompleted: auditParserMetrics.accumulatorsCompleted.Load(),
		AccumulatorsExpired:   auditParserMetrics.accumulatorsExpired.Load(),
	}
}

package auditportexecmon

import "testing"

func TestAuditParserMetricsRecordOnlyProductionCounters(t *testing.T) {
	before := auditParserMetricsSnapshotNow()
	recordAccumulatorCreated()
	recordAccumulatorCompleted()
	recordAccumulatorExpired()
	recordEventProcessed()
	after := auditParserMetricsSnapshotNow()
	if after.AccumulatorsCreated-before.AccumulatorsCreated != 1 ||
		after.AccumulatorsCompleted-before.AccumulatorsCompleted != 1 ||
		after.AccumulatorsExpired-before.AccumulatorsExpired != 1 ||
		after.EventsProcessed-before.EventsProcessed != 1 {
		t.Fatalf("unexpected metric delta: before=%+v after=%+v", before, after)
	}
}

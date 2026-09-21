package metrics

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	dto "github.com/prometheus/client_model/go"
)

func TestNormalizeConfigAppliesSafeDefaults(t *testing.T) {
	got, err := NormalizeConfig(Config{Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if got.ListenAddress != "127.0.0.1:9100" || got.Path != "/metrics" {
		t.Fatalf("normalized config = %+v", got)
	}
}

func TestNormalizeConfigRejectsHealthConflictAndMuxWildcard(t *testing.T) {
	for _, path := range []string{"/health", "/live", "/metrics/{tenant}"} {
		_, err := NormalizeConfig(Config{Enabled: true, ListenAddress: "127.0.0.1:9100", Path: path})
		if err == nil {
			t.Fatalf("expected path %q to be rejected", path)
		}
	}
}

func TestHealthEndpointSeparatesLivenessFromReadiness(t *testing.T) {
	exporter := NewExporter("6X13NGV4G9CVK92E", "test")
	handler := exporter.handler("/metrics")

	live := httptest.NewRecorder()
	handler.ServeHTTP(live, httptest.NewRequest(http.MethodGet, "/live", nil))
	if live.Code != http.StatusOK {
		t.Fatalf("live status = %d", live.Code)
	}

	unconfigured := httptest.NewRecorder()
	handler.ServeHTTP(unconfigured, httptest.NewRequest(http.MethodGet, "/health", nil))
	if unconfigured.Code != http.StatusServiceUnavailable {
		t.Fatalf("unconfigured health status = %d", unconfigured.Code)
	}

	exporter.SetHealthCheck(func() (bool, string) { return false, "module audit is restarting" })
	notReady := httptest.NewRecorder()
	handler.ServeHTTP(notReady, httptest.NewRequest(http.MethodGet, "/health", nil))
	if notReady.Code != http.StatusServiceUnavailable || !strings.Contains(notReady.Body.String(), "audit is restarting") {
		t.Fatalf("not-ready response = %d %q", notReady.Code, notReady.Body.String())
	}

	exporter.SetHealthCheck(func() (bool, string) { return true, "" })
	ready := httptest.NewRecorder()
	handler.ServeHTTP(ready, httptest.NewRequest(http.MethodGet, "/health", nil))
	if ready.Code != http.StatusOK {
		t.Fatalf("ready status = %d body=%q", ready.Code, ready.Body.String())
	}
}

func TestAuditMetricsUseCumulativeSnapshotDeltas(t *testing.T) {
	exporter := NewExporter("6X13NGV4G9CVK92E", "test")
	exporter.UpdateAuditMetrics(AuditMetrics{BacklogLines: 4, Subscribers: 2, LinesProcessed: 10, RetiredSubscribers: 1, BacklogOverflows: 2, Readers: 1, ReadersReady: 0, ReaderFailures: 1})
	exporter.UpdateAuditMetrics(AuditMetrics{BacklogLines: 1, Subscribers: 1, LinesProcessed: 15, RetiredSubscribers: 3, BacklogOverflows: 5, Readers: 1, ReadersReady: 1, ReaderFailures: 2})

	if got := exportedMetricValue(t, exporter.auditLinesProcessed); got != 15 {
		t.Fatalf("processed counter = %v, want 15", got)
	}
	if got := exportedMetricValue(t, exporter.auditRetiredSubscribers); got != 3 {
		t.Fatalf("retired counter = %v, want 3", got)
	}
	if got := exportedMetricValue(t, exporter.auditBacklogOverflows); got != 5 {
		t.Fatalf("overflow counter = %v, want 5", got)
	}
	if got := exportedMetricValue(t, exporter.auditBacklog); got != 1 {
		t.Fatalf("backlog gauge = %v, want 1", got)
	}
	if got := exportedMetricValue(t, exporter.auditReadersReady); got != 1 {
		t.Fatalf("ready readers gauge = %v, want 1", got)
	}
	if got := exportedMetricValue(t, exporter.auditReaderFailures); got != 2 {
		t.Fatalf("reader failures counter = %v, want 2", got)
	}

	// A source reset starts a new cumulative epoch instead of subtracting.
	exporter.UpdateAuditMetrics(AuditMetrics{LinesProcessed: 2, RetiredSubscribers: 1, BacklogOverflows: 1, ReaderFailures: 1})
	if got := exportedMetricValue(t, exporter.auditLinesProcessed); got != 17 {
		t.Fatalf("processed counter after reset = %v, want 17", got)
	}
	if got := exportedMetricValue(t, exporter.auditBacklogOverflows); got != 6 {
		t.Fatalf("overflow counter after reset = %v, want 6", got)
	}
	if got := exportedMetricValue(t, exporter.auditReaderFailures); got != 3 {
		t.Fatalf("reader failures after reset = %v, want 3", got)
	}
}

func exportedMetricValue(t *testing.T, metric interface{ Write(*dto.Metric) error }) float64 {
	t.Helper()
	var value dto.Metric
	if err := metric.Write(&value); err != nil {
		t.Fatal(err)
	}
	if value.Counter != nil {
		return value.Counter.GetValue()
	}
	if value.Gauge != nil {
		return value.Gauge.GetValue()
	}
	t.Fatal("metric has neither counter nor gauge value")
	return 0
}

func TestStartReturnsPortBindingFailure(t *testing.T) {
	originalListen := listen
	defer func() { listen = originalListen }()
	listen = func(network, address string) (net.Listener, error) {
		return nil, errors.New("forced bind failure")
	}

	exporter := NewExporter("6X13NGV4G9CVK92E", "test")
	err := exporter.Start(context.Background(), Config{
		Enabled:       true,
		ListenAddress: "127.0.0.1:9100",
		Path:          "/metrics",
	})
	if err == nil || !strings.Contains(err.Error(), "listen for metrics") {
		t.Fatalf("binding error = %v", err)
	}
}

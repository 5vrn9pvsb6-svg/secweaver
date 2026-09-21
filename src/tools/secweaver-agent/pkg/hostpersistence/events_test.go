package hostpersistence

import (
	"strings"
	"testing"
	"time"
)

// These tests cover persistence state transitions, evidence fields, diffs, and actor enrichment.

func TestDiffStatesCreatesModifiesDeletes(t *testing.T) {
	prev := map[string]fileState{
		"/etc/cron.d/a": {
			Path:            "/etc/cron.d/a",
			Category:        "scheduled_task",
			PersistenceType: "cron",
			FileType:        "file",
			Mode:            "-rw-r--r--",
			Size:            10,
			ModTime:         "2026-07-09T00:00:00Z",
			Hash:            "old",
		},
		"/etc/cron.d/deleted": {
			Path:            "/etc/cron.d/deleted",
			Category:        "scheduled_task",
			PersistenceType: "cron",
			FileType:        "file",
			Mode:            "-rw-r--r--",
			Size:            8,
			ModTime:         "2026-07-09T00:00:00Z",
			Hash:            "gone",
		},
	}
	cur := map[string]fileState{
		"/etc/cron.d/a": {
			Path:            "/etc/cron.d/a",
			Category:        "scheduled_task",
			PersistenceType: "cron",
			FileType:        "file",
			Mode:            "-rw-r--r--",
			Size:            11,
			ModTime:         "2026-07-09T00:01:00Z",
			Hash:            "new",
		},
		"/etc/cron.d/created": {
			Path:            "/etc/cron.d/created",
			Category:        "scheduled_task",
			PersistenceType: "cron",
			FileType:        "file",
			Mode:            "-rw-r--r--",
			Size:            9,
			ModTime:         "2026-07-09T00:01:00Z",
			Hash:            "created",
		},
	}
	events := diffStates(prev, cur, false, "host-01", "10.0.0.1", time.Date(2026, 7, 9, 0, 2, 0, 0, time.UTC), runtimeConfig{MaxDiffLines: defaultMaxDiffLines}, nil)
	if len(events) != 3 {
		t.Fatalf("events len = %d, want 3: %+v", len(events), events)
	}
	actions := map[string]bool{}
	for _, event := range events {
		actions[event.Action] = true
		if event.AssetType != "host_persistence" || event.EventType != "persistence_change" || event.Host != "host-01" {
			t.Fatalf("unexpected event: %+v", event)
		}
		if event.HostIP != "10.0.0.1" {
			t.Fatalf("host_ip = %q, want 10.0.0.1", event.HostIP)
		}
	}
	for _, action := range []string{"created", "modified", "deleted"} {
		if !actions[action] {
			t.Fatalf("missing action %s in %+v", action, events)
		}
	}
}

func TestRuntimeConfigNormalizesHostIP(t *testing.T) {
	cfg := runtimeConfig{HostIP: " 10.0.0.9 "}
	cfg.normalize()
	if cfg.HostIP != "10.0.0.9" {
		t.Fatalf("host_ip = %q, want 10.0.0.9", cfg.HostIP)
	}

	originalDetect := detectPrimaryHostIP
	detectPrimaryHostIP = func() string { return "192.0.2.10" }
	defer func() { detectPrimaryHostIP = originalDetect }()
	auto := runtimeConfig{}
	auto.normalize()
	if auto.HostIP != "192.0.2.10" {
		t.Fatalf("auto-detected host_ip = %q, want 192.0.2.10", auto.HostIP)
	}
}

func TestDiffStatesIncludesContentDiff(t *testing.T) {
	prev := map[string]fileState{
		"/etc/cron.d/job": {
			Path:            "/etc/cron.d/job",
			Category:        "scheduled_task",
			PersistenceType: "cron",
			FileType:        "file",
			Mode:            "-rw-r--r--",
			Size:            20,
			ModTime:         "2026-07-09T00:00:00Z",
			Hash:            "old",
			ContentCaptured: true,
			Content:         "* * * * * root true\n",
		},
	}
	cur := map[string]fileState{
		"/etc/cron.d/job": {
			Path:            "/etc/cron.d/job",
			Category:        "scheduled_task",
			PersistenceType: "cron",
			FileType:        "file",
			Mode:            "-rw-r--r--",
			Size:            18,
			ModTime:         "2026-07-09T00:01:00Z",
			Hash:            "new",
			ContentCaptured: true,
			Content:         "* * * * * root id\n",
		},
	}
	events := diffStates(prev, cur, false, "host-01", "", time.Date(2026, 7, 9, 0, 2, 0, 0, time.UTC), runtimeConfig{MaxDiffLines: defaultMaxDiffLines}, nil)
	if len(events) != 1 {
		t.Fatalf("events len = %d, want 1", len(events))
	}
	if !strings.Contains(events[0].ContentDiff, "-* * * * * root true") || !strings.Contains(events[0].ContentDiff, "+* * * * * root id") {
		t.Fatalf("content diff missing expected lines: %q", events[0].ContentDiff)
	}
}

func TestDiffStatesEnrichesAuditActor(t *testing.T) {
	tracker := newAuditTracker(time.Minute, 10)
	now := time.Now().UTC()
	tracker.Add(auditChange{
		Timestamp: now.Add(-time.Second),
		AuditID:   "88922",
		UID:       "0",
		UIDName:   "root",
		AUID:      "1000",
		AUIDName:  "alice",
		PID:       "1234",
		PPID:      "1",
		Process:   "bash",
		Exe:       "/usr/bin/bash",
		Command:   "bash -c echo bad >> /etc/cron.d/job",
		Syscall:   "257",
		Paths:     []string{"/etc/cron.d/job"},
	})
	prev := map[string]fileState{
		"/etc/cron.d/job": {Path: "/etc/cron.d/job", Category: "scheduled_task", PersistenceType: "cron", Hash: "old", ModTime: "old"},
	}
	cur := map[string]fileState{
		"/etc/cron.d/job": {Path: "/etc/cron.d/job", Category: "scheduled_task", PersistenceType: "cron", Hash: "new", ModTime: "new"},
	}
	events := diffStates(prev, cur, false, "host-01", "", now, runtimeConfig{MaxDiffLines: defaultMaxDiffLines}, tracker)
	if len(events) != 1 {
		t.Fatalf("events len = %d, want 1", len(events))
	}
	got := events[0]
	if got.User != "alice" || got.Process != "bash" || got.Command == "" || got.AuditID != "88922" || got.ActorSource != "auditd" {
		t.Fatalf("unexpected audit enrichment: %+v", got)
	}
}

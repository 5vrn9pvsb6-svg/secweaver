package hostpersistence

import (
	"bytes"
	"context"
	"encoding/json"

	"os"
	"path/filepath"

	"testing"
)

// These tests cover baseline persistence and suppression of the initial event flood.

func TestRunUsesStateFileWithoutInitialFlood(t *testing.T) {
	root := t.TempDir()
	watched := filepath.Join(root, "cron.d")
	if err := os.MkdirAll(watched, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(watched, "job")
	if err := os.WriteFile(path, []byte("* * * * * root true\n"), 0644); err != nil {
		t.Fatal(err)
	}
	cfg := runtimeConfig{
		StatePath:          filepath.Join(root, "state.json"),
		IncludeHash:        true,
		MaxHashBytes:       defaultMaxHashBytes,
		IncludeContentDiff: true,
		MaxContentBytes:    defaultMaxContentBytes,
		MaxDiffLines:       defaultMaxDiffLines,
		Once:               true,
		Watch: []watchTarget{{
			Path:            watched,
			Category:        "scheduled_task",
			PersistenceType: "cron",
			Recursive:       true,
		}},
	}
	var first bytes.Buffer
	if err := run(context.Background(), cfg, &first, &stats{}); err != nil {
		t.Fatal(err)
	}
	if first.Len() != 0 {
		t.Fatalf("initial run should not emit baseline, got %q", first.String())
	}
	if err := os.WriteFile(path, []byte("* * * * * root id\n"), 0644); err != nil {
		t.Fatal(err)
	}
	var second bytes.Buffer
	if err := run(context.Background(), cfg, &second, &stats{}); err != nil {
		t.Fatal(err)
	}
	var event persistenceEvent
	if err := json.Unmarshal(bytes.TrimSpace(second.Bytes()), &event); err != nil {
		t.Fatalf("decode event failed: %v; output=%q", err, second.String())
	}
	if event.Action != "modified" || event.Path != path || event.PersistenceType != "cron" {
		t.Fatalf("unexpected event: %+v", event)
	}
}

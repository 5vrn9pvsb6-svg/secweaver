package hostpersistence

import (
	"os"
	"path/filepath"

	"testing"
	"time"
)

// These tests cover glob expansion and metadata-based content reuse in the polling scanner.

func TestScanTargetsSupportsGlob(t *testing.T) {
	root := t.TempDir()
	sshDir := filepath.Join(root, "home", "alice", ".ssh")
	if err := os.MkdirAll(sshDir, 0755); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(sshDir, "authorized_keys")
	if err := os.WriteFile(keyPath, []byte("ssh-rsa AAAA\n"), 0644); err != nil {
		t.Fatal(err)
	}
	cfg := runtimeConfig{
		IncludeHash:  true,
		MaxHashBytes: defaultMaxHashBytes,
		Watch: []watchTarget{{
			Path:            filepath.Join(root, "home", "*", ".ssh", "authorized_keys"),
			Category:        "account_access",
			PersistenceType: "ssh_authorized_keys",
		}},
	}
	got, errs := scanTargets(cfg)
	if errs != 0 {
		t.Fatalf("scan errors = %d", errs)
	}
	item, ok := got[keyPath]
	if !ok {
		t.Fatalf("missing scanned key path; got keys %#v", got)
	}
	if item.Hash == "" || item.Category != "account_access" || item.PersistenceType != "ssh_authorized_keys" {
		t.Fatalf("unexpected item: %+v", item)
	}
}

func TestScanTargetsReusesPreviousContentWhenMetadataUnchanged(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "job")
	body := []byte("* * * * * root true\n")
	if err := os.WriteFile(path, body, 0644); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg := runtimeConfig{
		IncludeHash:        true,
		MaxHashBytes:       defaultMaxHashBytes,
		IncludeContentDiff: true,
		MaxContentBytes:    defaultMaxContentBytes,
		Watch: []watchTarget{{
			Path:            path,
			Category:        "scheduled_task",
			PersistenceType: "cron",
		}},
	}
	previous := map[string]fileState{
		path: {
			Path:             path,
			Category:         "scheduled_task",
			PersistenceType:  "cron",
			FileType:         "file",
			Mode:             info.Mode().String(),
			Size:             info.Size(),
			ModTime:          info.ModTime().UTC().Format(time.RFC3339Nano),
			Hash:             "cached-hash",
			ContentCaptured:  true,
			Content:          "cached-content",
			ContentTruncated: false,
		},
	}
	got, errs := scanTargetsWithPrevious(cfg, previous)
	if errs != 0 {
		t.Fatalf("scan errors = %d", errs)
	}
	item := got[path]
	if item.Hash != "cached-hash" || item.Content != "cached-content" {
		t.Fatalf("expected cached hash/content, got %+v", item)
	}
}

package hostpersistence

import (
	"encoding/json"

	"fmt"

	"os"

	"path/filepath"

	"strings"

	"time"
)

// This file owns baseline recovery and atomic state replacement so crashes cannot expose partially written persistence state.

func loadState(path string) (map[string]fileState, bool, error) {
	path = strings.TrimSpace(path)
	if path == "" || path == "-" {
		return nil, false, nil
	}
	body, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("read state %s: %w", path, err)
	}
	var state persistedState
	if err := json.Unmarshal(body, &state); err != nil {
		corruptPath := path + ".corrupt-" + time.Now().UTC().Format("20060102T150405.000000000Z")
		if renameErr := os.Rename(path, corruptPath); renameErr != nil {
			return nil, false, fmt.Errorf("parse state %s: %w; quarantine failed: %v", path, err, renameErr)
		}
		fmt.Fprintf(os.Stderr, "WARN: quarantined corrupt host persistence state: %s\n", corruptPath)
		return nil, false, nil
	}
	if state.Files == nil {
		state.Files = map[string]fileState{}
	}
	return state.Files, true, nil
}

func saveState(path, host string, files map[string]fileState, now time.Time) error {
	path = strings.TrimSpace(path)
	if path == "" || path == "-" {
		return nil
	}
	state := persistedState{
		Version:   "1",
		HostName:  host,
		UpdatedAt: now.UTC().Format(time.RFC3339),
		Files:     files,
	}
	body, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".host-persistence-state-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return nil
}

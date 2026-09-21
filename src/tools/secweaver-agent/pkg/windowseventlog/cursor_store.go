package windowseventlog

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type CursorState struct {
	SchemaVersion string            `json:"schema_version"`
	Module        string            `json:"module"`
	Cursors       map[string]uint64 `json:"cursors"`
}

func LoadCursorState(path string) (map[string]uint64, error) {
	if path == "" {
		return map[string]uint64{}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return map[string]uint64{}, nil
		}
		return nil, err
	}
	var state CursorState
	if err := json.Unmarshal(data, &state); err != nil {
		corruptPath := path + ".corrupt-" + time.Now().UTC().Format("20060102T150405.000000000Z")
		if renameErr := os.Rename(path, corruptPath); renameErr != nil {
			return nil, fmt.Errorf("parse cursor state: %w; quarantine failed: %v", err, renameErr)
		}
		fmt.Fprintf(os.Stderr, "WARN: quarantined corrupt Windows EventRecordID cursor: %s\n", corruptPath)
		return map[string]uint64{}, nil
	}
	if state.Cursors == nil {
		return map[string]uint64{}, nil
	}
	return state.Cursors, nil
}

func SaveCursorState(path, module string, cursors map[string]uint64) error {
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	state := CursorState{
		SchemaVersion: "1",
		Module:        module,
		Cursors:       map[string]uint64{},
	}
	for channel, cursor := range cursors {
		if cursor > 0 {
			state.Cursors[channel] = cursor
		}
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		if removeErr := os.Remove(path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return err
		}
		return os.Rename(tmpName, path)
	}
	return nil
}

func CloneCursors(cursors map[string]uint64) map[string]uint64 {
	out := make(map[string]uint64, len(cursors))
	for channel, cursor := range cursors {
		out[channel] = cursor
	}
	return out
}

func CursorsEqual(left, right map[string]uint64) bool {
	if len(left) != len(right) {
		return false
	}
	for channel, cursor := range left {
		if right[channel] != cursor {
			return false
		}
	}
	return true
}

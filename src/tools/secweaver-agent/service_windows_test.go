//go:build windows

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// SCM stderr is not available to an operator after startup exits; the latest
// failure must survive while repeated failures cannot grow an unbounded log.
func TestWindowsServiceFailureRecord(t *testing.T) {
	config := filepath.Join(t.TempDir(), "config.json")
	writeWindowsServiceFailure(config, errors.New(strings.Repeat("x", 20000)))
	body, err := os.ReadFile(config + ".service-error.txt")
	if err != nil || len(body) != 16384 {
		t.Fatalf("failure record length=%d err=%v", len(body), err)
	}
	writeWindowsServiceFailure(config, errors.New("invalid configuration"))
	body, err = os.ReadFile(config + ".service-error.txt")
	if err != nil || !strings.Contains(string(body), "invalid configuration") || len(body) > 100 {
		t.Fatalf("failure was not replaced: %q err=%v", body, err)
	}
}

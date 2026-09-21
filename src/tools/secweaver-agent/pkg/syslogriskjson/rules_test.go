package syslogriskjson

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadRulesVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.json")
	body := `{"schema_version":"1","rules_version":"20260701.1","rules":[]}`
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := loadRulesVersion(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != "20260701.1" {
		t.Fatalf("rules version=%q", got)
	}
}

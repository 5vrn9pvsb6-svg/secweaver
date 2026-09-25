package main

import (
	"os"
	"strings"
	"testing"

	"secweaver-agent/pkg/layout"
)

// PowerShell cannot import a Go constant. Guard the cross-language default so
// packaging cannot silently drift from doctor and the SCM dispatcher again.
func TestWindowsInstallerServiceIdentity(t *testing.T) {
	body, err := os.ReadFile("packaging/windows/install-service.ps1")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `[string]$ServiceName = "`+layout.WindowsServiceName+`"`) {
		t.Fatal("Windows installer service name differs from SCM/doctor")
	}
}

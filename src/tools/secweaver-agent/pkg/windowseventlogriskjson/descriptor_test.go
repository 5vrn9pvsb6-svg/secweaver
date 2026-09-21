package windowseventlogriskjson

import (
	"testing"

	"secweaver-agent/pkg/layout"
)

func TestDescriptorReportsUnifiedReaderOutputs(t *testing.T) {
	paths := Descriptor().OutputPaths(nil)
	if len(paths) != 2 || paths[0] != layout.WindowsLogs+`\windows-eventlog-risk-json.log` || paths[1] != layout.WindowsLogs+`\windows-process-execmon.log` {
		t.Fatalf("unexpected default outputs: %v", paths)
	}
	paths = Descriptor().OutputPaths([]string{"-output", `D:\risk.log`, "-evidence-output="})
	if len(paths) != 1 || paths[0] != `D:\risk.log` {
		t.Fatalf("explicit standalone ownership should suppress evidence output: %v", paths)
	}
}

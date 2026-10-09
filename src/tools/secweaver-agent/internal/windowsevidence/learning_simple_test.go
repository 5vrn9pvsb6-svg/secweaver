package windowsevidence

import (
	"bytes"
	"fmt"
	"testing"

	"secweaver-agent/pkg/windowseventlog"
)

// Native-shaped records go through Classify, the synchronous writer, durable
// admission and source dedup. Counts assert actual JSONL writes, not mock calls.
func TestWindowsExecAndConnectSimpleEndToEnd(t *testing.T) {
	for _, kind := range []string{"sysmon-exec", "security-exec", "connect"} {
		t.Run(kind, func(t *testing.T) {
			var out bytes.Buffer
			w, _ := fileLearningFixture(t, &out)
			w.engine.Health(true, false)
			w.networkEngine.Health(true, false)
			command := "powershell -File repeated.ps1"
			if kind == "connect" {
				if _, err := WriteSource(w, fileSysmonEvent(1, 1, fileTestGUID, command), false); err != nil {
					t.Fatal(err)
				}
			}
			for i := 0; i < 7; i++ {
				e := fileSysmonEvent(1, i+10, fileTestGUID, command)
				if kind == "security-exec" {
					e.System.EventID, e.System.Provider, e.System.Channel = "4688", "Microsoft-Windows-Security-Auditing", "Security"
					e.EventData = append(e.EventData, windowseventlog.DataField{Name: "NewProcessName", Value: `C:\Users\Alice\powershell.exe`})
				} else if kind == "connect" {
					e.System.EventID = "3"
					for name, value := range map[string]string{"Initiated": "true", "Protocol": "tcp", "DestinationIp": "8.8.8.8", "DestinationPort": "22", "SourcePort": fmt.Sprint(50000 + i)} {
						e.EventData = append(e.EventData, windowseventlog.DataField{Name: name, Value: value})
					}
				}
				want := 1
				if i >= 4 {
					want = 0
				}
				if n, err := WriteSource(w, e, false); err != nil || n != want {
					t.Fatalf("event %d wrote %d want %d: %v", i, n, want, err)
				}
				if n, err := WriteSource(w, e, false); err != nil || n != 0 {
					t.Fatalf("retry counted: %d %v", n, err)
				}
			}
			if err := w.Sync(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

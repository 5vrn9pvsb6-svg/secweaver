package windowseventlogriskjson

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestScriptCompactionRetainsEvidenceAndSeverity(t *testing.T) {
	script := strings.Repeat("Write-Output 'sample'; ", 1000) + "powershell -EncodedCommand SQBFAFgA"
	event := mustParseOne(t, `<Event><System><Provider Name="Microsoft-Windows-PowerShell"/><EventID>4104</EventID></System><EventData><Data Name="ScriptBlockText">`+script+`</Data><Data Name="ScriptBlockId">fragment-id</Data><Data Name="MessageNumber">2</Data><Data Name="MessageTotal">3</Data><Data Name="CommandLine">different launcher</Data></EventData></Event>`)
	got := classifyRiskEvent(event, true)[0]
	if got.Command != script || got.ScriptBytes != len(script) || got.ScriptSHA256 != fmt.Sprintf("%x", sha256.Sum256([]byte(script))) || got.Severity != "high" || got.RawXML != event.RawXML {
		t.Fatal("compaction changed security evidence or classification")
	}
	if got.Fields["ScriptBlockText"] != "" || strings.Contains(got.Message, script) || got.Fields["CommandLine"] != "different launcher" || got.Fields["MessageNumber"] != "2" || got.Fields["MessageTotal"] != "3" {
		t.Fatal("duplicate retained or fragment/launcher information lost")
	}
	// Compare normal JSONL (raw XML is explicitly optional) against the former
	// three-copy shape, using identical event content rather than a size guess.
	got.RawXML = ""
	compact, _ := json.Marshal(got)
	legacy := got
	legacy.Fields = event.Fields()
	legacy.Message = buildMessage(got.RuleName, "", "", "", script)
	large, _ := json.Marshal(legacy)
	if len(compact)*100/len(large) > 45 {
		t.Fatalf("expected substantial byte reduction: compact=%d legacy=%d", len(compact), len(large))
	}
	if event.Field("ScriptBlockText") != script {
		t.Fatal("source event mutated")
	}
}

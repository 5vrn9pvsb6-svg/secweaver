package agentactivity

import "testing"

func TestPowerShellAllowlistRequiresExactRegisteredScript(t *testing.T) {
	script := "Get-CimInstance Win32_Process | ConvertTo-Json"
	RegisterPowerShellScript(script)
	marked := MarkPowerShellScript(script)
	if !IsInternalPowerShellScript(marked) {
		t.Fatal("registered collector script was not recognized")
	}
	if IsInternalPowerShellScript(marked + "; Invoke-Expression 'malicious'") {
		t.Fatal("modified collector script must not bypass risk classification")
	}
	if IsInternalPowerShellScript(powerShellMarker + "Get-Process") {
		t.Fatal("marker alone must not bypass risk classification")
	}
}

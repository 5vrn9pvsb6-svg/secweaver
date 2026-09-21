//go:build windows

package agentupdate

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

func verifyWindowsAuthenticode(ctx context.Context, path string, allowed []string) error {
	script := `$signature = Get-AuthenticodeSignature -LiteralPath $args[0]
if ($signature.Status -ne 'Valid' -or $null -eq $signature.SignerCertificate) { exit 10 }
$sha = [System.Security.Cryptography.SHA256]::Create()
try { $value = [BitConverter]::ToString($sha.ComputeHash($signature.SignerCertificate.RawData)).Replace('-', '').ToLowerInvariant() }
finally { $sha.Dispose() }
[Console]::Out.Write($value)`
	command := exec.CommandContext(
		ctx,
		"powershell.exe",
		"-NoProfile",
		"-NonInteractive",
		"-ExecutionPolicy", "Bypass",
		"-Command", script,
		path,
	)
	output, err := command.Output()
	if err != nil {
		return fmt.Errorf("verify Windows Authenticode signature: %w", err)
	}
	actual := normalizePublisherThumbprint(string(output))
	for _, expected := range allowed {
		if actual == normalizePublisherThumbprint(expected) {
			return nil
		}
	}
	return fmt.Errorf("Windows Authenticode publisher SHA-256 %q is not allowed", actual)
}

func normalizePublisherThumbprint(value string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(value), ":", ""))
}

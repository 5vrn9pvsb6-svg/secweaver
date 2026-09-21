// Package agentactivity owns the exact allowlist used to suppress collector-
// generated activity from Windows risk output.
package agentactivity

import (
	"crypto/sha256"
	"strings"
	"sync"
)

const powerShellMarker = "$swMarker='SECWEAVER_INTERNAL_QUERY'; "

var powerShellScripts = struct {
	sync.RWMutex
	hashes map[[sha256.Size]byte]struct{}
}{hashes: make(map[[sha256.Size]byte]struct{})}

// RegisterPowerShellScript adds one fixed collector script to the process-wide
// allowlist. Registration occurs from collector init functions before module
// execution; the lock also keeps tests and future dynamic collectors race-free.
func RegisterPowerShellScript(script string) {
	marked := MarkPowerShellScript(script)
	hash := sha256.Sum256([]byte(marked))
	powerShellScripts.Lock()
	powerShellScripts.hashes[hash] = struct{}{}
	powerShellScripts.Unlock()
}

// MarkPowerShellScript adds the stable marker captured by Event ID 4104. The
// full marked script, rather than the marker alone, is allowlisted so an
// attacker cannot append commands and evade risk classification.
func MarkPowerShellScript(script string) string {
	return powerShellMarker + strings.TrimSpace(script)
}

// IsInternalPowerShellScript accepts only an exact registered script. Hashes
// bound memory to a fixed size even though inventory scripts can be large.
func IsInternalPowerShellScript(script string) bool {
	hash := sha256.Sum256([]byte(strings.TrimSpace(script)))
	powerShellScripts.RLock()
	_, ok := powerShellScripts.hashes[hash]
	powerShellScripts.RUnlock()
	return ok
}

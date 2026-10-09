package behaviorlearning

import (
	"encoding/hex"
	"net/netip"
	"path/filepath"
	"unicode/utf8"
)

const simpleWindowsExecStrategy = "windows_exec_four_fields_v1"
const simpleNetworkStrategy = "windows_connect_seven_fields_v1"
const simpleScriptStrategy = "windows_script_exact_v1"

// WindowsExecPolicy replaces legacy service-token admission in the existing
// state directory. New authentic policies migrate once; disabled stays disabled.
func WindowsExecPolicy(base Config) Config {
	base.simpleExec, base.simpleKind, base.fileWindows = true, "exec", true
	return base
}

// NetworkPolicy isolates connection counters from exec/file counters. It does
// not enable a stream that the installer or administrator left out of scope.
func NetworkPolicy(base Config) Config {
	base.Enabled = base.Enabled && includesEvent(base, "active_connect")
	base.simpleExec, base.simpleFile, base.fileWindows = true, false, true
	base.simpleKind = "active_connect"
	base.StateDir = filepath.Join(base.StateDir, "network-operations")
	base.EventTypes, base.FileRoots = []string{"active_connect"}, nil
	return base
}

// ScriptPolicy applies the common counter to complete native PowerShell blocks.
// Fragment assembly and protected-alert classification remain adapter concerns.
func ScriptPolicy(base Config) Config {
	base.simpleExec, base.simpleKind = true, "powershell_script_block"
	return base
}

func includesEvent(c Config, kind string) bool {
	for _, configured := range c.EventTypes {
		if configured == kind {
			return true
		}
	}
	return false
}

// simpleStrategyKnown is shared with journal compaction; unknown state never
// gains the right to discard admission records merely by naming a strategy.
func simpleStrategyKnown(strategy string) bool {
	switch strategy {
	case simpleExecStrategy, simpleWindowsExecStrategy, simpleLinuxFileStrategy,
		simpleWindowsFileStrategy, simpleNetworkStrategy, simpleScriptStrategy:
		return true
	}
	return false
}

// simpleScriptTuple permits an empty native Path (inline/generated scripts),
// but requires the complete script digest and origin. No CDXML class list,
// service account, path prefix or rate heuristic participates in admission.
func simpleScriptTuple(c Context) (any, bool) {
	r := c.Risk
	if r == nil || c.Exec != nil || c.File != nil || c.Network != nil || c.Windows != nil || c.Operation != nil {
		return nil, false
	}
	digest, err := hex.DecodeString(r.ScriptSHA256)
	if err != nil || len(digest) != 32 || r.Provider == "" || r.Channel == "" || r.UserSID == "" {
		return nil, false
	}
	// A fixed array explicitly excludes the obsolete module-class heuristic.
	tuple := [5]string{r.Provider, r.Channel, r.UserSID, r.Path, r.ScriptSHA256}
	size := 0
	for _, value := range tuple {
		if !utf8.ValidString(value) {
			return nil, false
		}
		size += len(value)
	}
	return tuple, size <= 32768
}

// validNetworkTarget checks completeness only. Public targets and management
// ports follow the same exact-match rule; no subnet or port-list whitelist exists.
func validNetworkTarget(n *NetworkFields) bool {
	if n == nil || n.Port < 1 || n.Port > 65535 || (n.Protocol != "tcp" && n.Protocol != "udp") {
		return false
	}
	address, err := netip.ParseAddr(n.Address)
	return err == nil && address.Zone() == "" && !address.IsUnspecified() && !address.IsMulticast()
}

//go:build linux && (amd64 || arm64)

package ebpf

import "secweaver-agent/pkg/processtracker"

const (
	parentPIDValid     = 1
	parentCommValid    = 2
	parentStartValid   = 4
	parentExeValid     = 8
	parentExeTruncated = 16
)

// decodeParentIdentity honors per-field evidence flags so reused scratch-map
// bytes can never become historical parent evidence. A corrupt path offset or
// conflicting status is treated as unavailable, not used to slice wire bytes.
func decodeParentIdentity(raw processLifecycleProcessEvent) *processtracker.ParentIdentity {
	if raw.Type != processtracker.EventExec || raw.ParentFlags&parentPIDValid == 0 || raw.Ppid == 0 {
		return nil
	}
	parent := &processtracker.ParentIdentity{ExeStatus: "unavailable"}
	if raw.ParentFlags&parentCommValid != 0 {
		parent.Comm = parentCString(raw.ParentComm[:])
	}
	if raw.ParentFlags&parentStartValid != 0 {
		parent.StartBootNS = raw.ParentStartBoottimeNs
	}
	if raw.ParentFlags&parentExeTruncated != 0 {
		parent.ExeStatus = "truncated"
	} else if raw.ParentFlags&parentExeValid != 0 && raw.ParentExeOffset < uint32(len(raw.ParentExe)) {
		// Do not TrimSpace paths: leading/trailing spaces are legal filename bytes.
		path := raw.ParentExe[raw.ParentExeOffset:]
		value := parentCString(path)
		if len(value) > 1 && value[0] == '/' && path[len(path)-1] == 0 {
			parent.Exe, parent.ExeStatus = value, "captured"
		}
	}
	return parent
}

// Kernel comm and executable paths may legally contain spaces. Strip only the
// C terminator; whitespace normalization would change captured identity bytes.
func parentCString(value []int8) string {
	buffer := make([]byte, 0, len(value))
	for _, character := range value {
		if character == 0 {
			break
		}
		buffer = append(buffer, byte(character))
	}
	return string(buffer)
}

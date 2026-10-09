package behaviorlearning

import (
	"path/filepath"
	"unicode/utf8"
)

const simpleLinuxFileStrategy = "linux_file_five_fields_v1"
const simpleWindowsFileStrategy = "windows_file_five_fields_v1"

// FilePolicy creates a separate baseline without changing the parent policy's
// hash or progress. Explicit event scope is respected; Linux omitted scope also
// covers file operations. Windows installation flags remain authoritative.
// The adapter must resolve the parent's absolute state path before calling.
func FilePolicy(base Config, windows bool) Config {
	enabled := !windows && !base.eventTypesExplicit
	for _, kind := range base.EventTypes {
		enabled = enabled || kind == "file_op"
	}
	base.Enabled = base.Enabled && enabled
	base.simpleExec, base.simpleFile, base.fileWindows = true, true, windows
	base.simpleKind = "file_op"
	base.StateDir = filepath.Join(base.StateDir, "file-operations")
	base.EventTypes, base.FileRoots = []string{"file_op"}, nil
	return base
}

func (c Config) simpleStrategy() string {
	if c.simpleKind == "active_connect" {
		return simpleNetworkStrategy
	}
	if c.simpleKind == "powershell_script_block" {
		return simpleScriptStrategy
	}
	if c.simpleFile {
		if c.fileWindows {
			return simpleWindowsFileStrategy
		}
		return simpleLinuxFileStrategy
	}
	if c.fileWindows {
		return simpleWindowsExecStrategy
	}
	return simpleExecStrategy
}

func (c Config) simpleEventType() string {
	if c.simpleKind != "" {
		return c.simpleKind
	}
	if c.simpleFile {
		return "file_op"
	}
	return "exec"
}

// simpleTuple never folds case/whitespace, sorts paths or adds action/identity
// gates. Array order is significant. Windows alone permits an empty listener,
// and rejects a nonempty one rather than inventing a root-process attribution.
func (c Config) simpleTuple(context Context) (any, bool) {
	if c.simpleKind == "powershell_script_block" {
		return simpleScriptTuple(context)
	}
	fields := context.Exec
	if context.Windows != nil || context.Operation != nil || context.Risk != nil {
		return nil, false
	}
	var tuple any = fields
	size := 0
	if c.simpleKind == "active_connect" {
		if context.Exec != nil || context.File != nil || !validNetworkTarget(context.Network) {
			return nil, false
		}
		fields, tuple = &context.Network.ExecFields, context.Network
		size += len(context.Network.Protocol) + len(context.Network.Address) + 8
	} else if context.Network != nil {
		return nil, false
	} else if c.simpleFile {
		if context.File == nil || context.Exec != nil || len(context.File.FilePaths) == 0 || len(context.File.FilePaths) > 64 {
			return nil, false
		}
		fields, tuple = &context.File.ExecFields, context.File
		for _, path := range context.File.FilePaths {
			if path == "" || !utf8.ValidString(path) {
				return nil, false
			}
			size += len(path)
		}
	} else if context.File != nil {
		return nil, false
	}
	if fields == nil || fields.PIDName == "" || fields.Exe == "" || fields.CommandLine == "" {
		return nil, false
	}
	if c.fileWindows {
		if fields.ListenerProcess != "" {
			return nil, false
		}
	} else if fields.ListenerProcess == "" {
		return nil, false
	}
	for _, value := range []string{fields.ListenerProcess, fields.PIDName, fields.Exe, fields.CommandLine} {
		// JSON replaces invalid UTF-8, which could otherwise merge distinct bytes.
		if !utf8.ValidString(value) {
			return nil, false
		}
		size += len(value)
	}
	return tuple, size <= 32768
}

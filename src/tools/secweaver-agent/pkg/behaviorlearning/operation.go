package behaviorlearning

import (
	"net/netip"
	"path"
	"strings"
)

// SourceEventType gives old exec-only entries their original semantics without
// changing their stored fingerprints or requiring a format migration.
func (c Context) SourceEventType() string {
	if c.Operation != nil {
		return c.Operation.EventType
	}
	return "exec"
}

// operationReason enforces policy again at the engine boundary. Event-specific
// adapters prove process identity; neither config nor frequent repetition can
// whitelist authentication, persistence, destructive operations or remote admin.
func (e *Engine) operationReason(c Context) string {
	kind := c.SourceEventType()
	enabled := false
	for _, configured := range e.cfg.EventTypes {
		if configured == kind {
			enabled = true
		}
	}
	if !enabled {
		return "event_type_not_enabled"
	}
	op := c.Operation
	if op == nil {
		return ""
	}
	if c.Windows == nil {
		return "operation_adapter_unverified"
	}
	switch kind {
	case "active_connect":
		if op.Action != "connect" || (op.Protocol != "tcp" && op.Protocol != "udp") || op.Port <= 0 || op.Port > 65535 {
			return "network_context_incomplete"
		}
		address, err := netip.ParseAddr(op.Address)
		if err != nil || !address.IsPrivate() || address.Zone() != "" {
			return "public_or_special_destination"
		}
		source, err := netip.ParseAddr(op.SourceAddress)
		if err != nil || !source.IsValid() || source.IsUnspecified() || source.IsMulticast() || source.Zone() != "" {
			return "network_source_incomplete"
		}
		// Authentication, remote management, SMB/RPC and common administration
		// ports stay visible even for otherwise stable internal service traffic.
		switch op.Port {
		case 22, 23, 53, 88, 111, 135, 137, 138, 139, 389, 445, 464, 636, 2049, 2375, 2376, 3389, 5985, 5986:
			return "sensitive_destination_port"
		}
		return ""
	case "file_op":
		if op.Action != "create" {
			return "sensitive_or_ambiguous_file_action"
		}
		if !ordinaryLogPath(op.Path) {
			return "sensitive_or_unqualified_file"
		}
		candidate := canonicalPath(op.Path)
		for _, root := range e.cfg.FileRoots {
			if strings.HasPrefix(candidate, strings.TrimSuffix(canonicalPath(root), "/")+"/") {
				return ""
			}
		}
		return "file_outside_learning_roots"
	default:
		return "protected_event_type"
	}
}

// canonicalPath only normalizes separators/case for Windows. It never expands
// variables, resolves patterns or folds dot segments into a more permissive path.
func canonicalPath(value string) string {
	if len(value) > 2 && value[1] == ':' {
		return strings.ToLower(strings.ReplaceAll(value, `\`, "/"))
	}
	return value
}

func validFileRoot(value string) bool {
	v := canonicalPath(value)
	if len(v) > 4096 || strings.ContainsAny(v, "*?\x00") || strings.Contains(v, "/../") || strings.HasSuffix(v, "/..") || strings.Contains(v, "/./") || strings.HasSuffix(v, "/.") {
		return false
	}
	if len(v) > 3 && v[1:3] == ":/" && v[0] >= 'a' && v[0] <= 'z' {
		return !strings.Contains(v[3:], ":") && strings.Trim(v[3:], "/") != ""
	}
	return strings.HasPrefix(v, "/") && !strings.HasPrefix(v, "//") && len(strings.Trim(v, "/")) > 0
}

// ordinaryLogPath excludes executable/config/credential/persistence locations;
// .log plus an explicit root is intentionally narrower than all file writes.
func ordinaryLogPath(value string) bool {
	if !validFileRoot(value) {
		return false
	}
	v := canonicalPath(value)
	if !strings.HasSuffix(v, ".log") {
		return false
	}
	for _, segment := range strings.Split(v, "/") {
		switch strings.ToLower(segment) {
		case "windows", "system32", "syswow64", "startup", "start menu", "tasks", "microsoft", "ssh", ".ssh", "credentials", "vault", "secrets", "etc", "proc", "sys", "dev", "audit":
			return false
		}
	}
	name := strings.ToLower(path.Base(v))
	for _, prefix := range []string{"security", "audit", "auth", "secure", "secweaver", "behavior-learning"} {
		if strings.HasPrefix(name, prefix) {
			return false
		}
	}
	return true
}

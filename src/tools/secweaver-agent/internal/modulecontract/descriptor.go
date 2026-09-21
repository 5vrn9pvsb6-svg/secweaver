// Package modulecontract defines the process-level contract between the Agent
// supervisor and built-in collector modules. Collector-private configuration is
// resolved by the collector package and returned as narrow supervisor capabilities.
package modulecontract

import (
	"fmt"
	"strconv"
	"strings"
)

// AuditSubscription describes one module's effective audit transport needs.
// Modules sharing Path and FromStart may use one parent reader; Keys only
// control event routing after the physical stream has been opened.
type AuditSubscription struct {
	Path      string
	FromStart bool
	Keys      []string
}

// Descriptor is the single supervisor-facing definition of a built-in module.
// OutputPaths and AuditSubscription receive raw module arguments so precedence
// and private config parsing remain owned by the module package.
type Descriptor struct {
	Name                  string
	Description           string
	Platforms             []string
	Flags                 map[string]bool
	OutputPaths           func(args []string) []string
	AuditSubscription     func(args []string) (AuditSubscription, bool, error)
	UpgradeOutputRequired bool
	Run                   func([]string) int
}

// Flags builds an immutable-by-convention flag contract. A true value means
// that the option consumes the following command-line argument.
func Flags(valueFlags, boolFlags []string) map[string]bool {
	flags := make(map[string]bool, len(valueFlags)+len(boolFlags))
	for _, name := range valueFlags {
		flags[name] = true
	}
	for _, name := range boolFlags {
		flags[name] = false
	}
	return flags
}

// ValidateArgs rejects unknown and positional module arguments before a child
// process starts, producing deterministic errors for local and remote configs.
func (d Descriptor) ValidateArgs(args []string) error {
	for index := 0; index < len(args); index++ {
		argument := strings.TrimSpace(args[index])
		if argument == "" {
			return fmt.Errorf("argument %d is empty", index+1)
		}
		if argument == "--" {
			if index != len(args)-1 {
				return fmt.Errorf("positional arguments are not supported: %q", args[index+1])
			}
			return nil
		}
		if !strings.HasPrefix(argument, "-") {
			return fmt.Errorf("unexpected positional argument %q", argument)
		}
		nameValue := strings.TrimLeft(argument, "-")
		name, _, hasInlineValue := strings.Cut(nameValue, "=")
		requiresValue, ok := d.Flags[name]
		if !ok {
			return fmt.Errorf("unknown flag -%s", name)
		}
		if !requiresValue || hasInlineValue {
			continue
		}
		if index+1 >= len(args) {
			return fmt.Errorf("flag -%s requires a value", name)
		}
		index++
	}
	return nil
}

// FlagOutputPaths resolves a conventional single output flag without exposing
// that parsing policy to the supervisor.
func FlagOutputPaths(defaultPath, flagName string) func([]string) []string {
	return func(args []string) []string {
		path := defaultPath
		if value, ok := StringFlag(args, flagName); ok {
			path = value
		}
		return []string{path}
	}
}

// StringFlag resolves -name value, --name value, and inline assignment forms.
func StringFlag(args []string, name string) (string, bool) {
	short := "-" + name
	long := "--" + name
	for i := 0; i < len(args); i++ {
		arg := args[i]
		for _, prefix := range []string{short + "=", long + "="} {
			if strings.HasPrefix(arg, prefix) {
				return strings.TrimSpace(strings.TrimPrefix(arg, prefix)), true
			}
		}
		if arg == short || arg == long {
			if i+1 < len(args) {
				return args[i+1], true
			}
			return "", true
		}
	}
	return "", false
}

// BoolFlag resolves Go flag-compatible boolean forms while distinguishing an
// omitted flag from an explicit false value.
func BoolFlag(args []string, name string) (bool, bool, error) {
	short := "-" + name
	long := "--" + name
	for i := 0; i < len(args); i++ {
		arg := args[i]
		for _, prefix := range []string{short + "=", long + "="} {
			if strings.HasPrefix(arg, prefix) {
				value := strings.TrimSpace(strings.TrimPrefix(arg, prefix))
				parsed, err := strconv.ParseBool(value)
				if err != nil {
					return false, true, fmt.Errorf("invalid %s value %q", name, value)
				}
				return parsed, true, nil
			}
		}
		if arg == short || arg == long {
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				parsed, err := strconv.ParseBool(strings.TrimSpace(args[i+1]))
				if err != nil {
					return false, true, fmt.Errorf("invalid %s value %q", name, args[i+1])
				}
				return parsed, true, nil
			}
			return true, true, nil
		}
	}
	return false, false, nil
}

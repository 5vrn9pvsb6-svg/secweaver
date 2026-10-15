package main

import (
	"context"
	"fmt"
	"runtime"
	"strings"

	"secweaver-agent/pkg/auditportexecmon"
)

var resolveLinuxCollectionProfile = auditportexecmon.ResolveCollectionProfile

// prepareLinuxCollectionModules freezes one transport choice for the entire
// supervisor run. Runtime-only flag overrides avoid rewriting custom configs
// or learning baselines during binary-only automatic upgrades. The copied
// slices prevent doctor/preflight from mutating the caller's configuration.
func prepareLinuxCollectionModules(ctx context.Context, modules []runtimeModule, verifyAttach bool) ([]runtimeModule, auditportexecmon.CollectionProfile, error) {
	if runtime.GOOS != "linux" || runningInContainer() {
		return modules, auditportexecmon.CollectionProfile{}, nil
	}
	module, ok := runtimeModuleByName(modules, "audit-port-execmon")
	if !ok {
		return modules, auditportexecmon.CollectionProfile{}, nil
	}
	profile, err := resolveLinuxCollectionProfile(ctx, module.Config.Args, verifyAttach)
	if err != nil {
		return modules, profile, fmt.Errorf("Linux evidence collection preflight: %w", err)
	}
	return modulesForCollectionProfile(modules, profile), profile, nil
}

// modulesForCollectionProfile applies one run's transport boundary without
// altering user files or the slices kept by configuration/status callers.
func modulesForCollectionProfile(modules []runtimeModule, profile auditportexecmon.CollectionProfile) []runtimeModule {
	prepared := append([]runtimeModule(nil), modules...)
	for i := range prepared {
		switch prepared[i].Spec.Name {
		case "audit-port-execmon":
			prepared[i].Config.Args = overrideModuleFlag(prepared[i], "collection-mode", profile.Mode)
		case "host-persistence":
			if profile.Mode == configAuditModeEBPFOnly {
				prepared[i].Config.Args = overrideModuleFlag(prepared[i], "audit", "false")
			}
		}
	}
	return prepared
}

// overrideModuleFlag removes all previous spellings while following descriptor
// value ownership; a value that happens to look like a flag remains data.
// The final inline spelling also works for Go boolean flags and before '--'.
func overrideModuleFlag(module runtimeModule, target, value string) []string {
	args := module.Config.Args
	out := make([]string, 0, len(args)+1)
	for i := 0; i < len(args); i++ {
		if args[i] == "--" {
			out = append(out, "-"+target+"="+value)
			return append(out, args[i:]...)
		}
		name, _, inline := strings.Cut(strings.TrimLeft(args[i], "-"), "=")
		if name == target {
			if module.Spec.Flags[name] && !inline {
				i++
			}
			continue
		}
		out = append(out, args[i])
		if module.Spec.Flags[name] && !inline && i+1 < len(args) {
			i++
			out = append(out, args[i])
		}
	}
	return append(out, "-"+target+"="+value)
}

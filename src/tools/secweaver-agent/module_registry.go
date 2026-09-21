package main

import (
	"fmt"
	"strings"

	"secweaver-agent/pkg/auditportexecmon"
	"secweaver-agent/pkg/hostpersistence"
	"secweaver-agent/pkg/hostprocesssnapshot"
	"secweaver-agent/pkg/hoststatesnapshot"
	"secweaver-agent/pkg/syslogriskjson"
	"secweaver-agent/pkg/windowseventlogriskjson"
	"secweaver-agent/pkg/windowsprocessexecmon"
)

var moduleRegistry = buildModuleRegistry(
	auditportexecmon.Descriptor(),
	syslogriskjson.Descriptor(),
	hostpersistence.Descriptor(),
	hostprocesssnapshot.Descriptor(),
	hoststatesnapshot.Descriptor(),
	windowseventlogriskjson.Descriptor(),
	windowsprocessexecmon.Descriptor(),
)

// buildModuleRegistry makes duplicate descriptor names a startup-time coding
// failure rather than silently allowing the last module to win.
func buildModuleRegistry(descriptors ...moduleDescriptor) map[string]moduleDescriptor {
	registry := make(map[string]moduleDescriptor, len(descriptors))
	for _, descriptor := range descriptors {
		name := normalizeModuleName(descriptor.Name)
		if name == "" {
			panic("module descriptor has an empty name")
		}
		if _, exists := registry[name]; exists {
			panic(fmt.Sprintf("duplicate module descriptor %q", name))
		}
		registry[name] = descriptor
	}
	return registry
}

func findModule(name string) (moduleSpec, bool) {
	spec, ok := moduleRegistry[normalizeModuleName(name)]
	return spec, ok
}

func normalizeModuleName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	name = strings.ReplaceAll(name, "_", "-")
	return name
}

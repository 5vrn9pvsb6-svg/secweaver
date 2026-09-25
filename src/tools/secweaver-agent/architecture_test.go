package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"secweaver-agent/pkg/agentlicense"
)

func TestAgentConfigSchemaIsValidJSON(t *testing.T) {
	body, err := os.ReadFile("config.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(body, &schema); err != nil {
		t.Fatalf("invalid config schema: %v", err)
	}
	if schema["$schema"] == "" || schema["type"] != "object" {
		t.Fatalf("unexpected schema header: %+v", schema)
	}
}

func TestAgentConfigSchemaTopLevelPropertiesMatchRuntime(t *testing.T) {
	body, err := os.ReadFile("config.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(body, &schema); err != nil {
		t.Fatal(err)
	}
	// Keep this list next to the runtime contract. A new top-level field must be
	// added to both the strict Go decoder and the published JSON Schema.
	want := []string{"deployment_mode", "disk_budget", "enterprise_id", "license", "metrics", "modules", "operations_report", "remote_config", "status_path", "update"}
	if len(schema.Properties) != len(want) {
		t.Fatalf("schema top-level properties=%v want=%v", schema.Properties, want)
	}
	for _, name := range want {
		if _, ok := schema.Properties[name]; !ok {
			t.Fatalf("schema is missing runtime property %q", name)
		}
	}
}

func TestPackagedConfigExamplesUseStrictRuntimeFields(t *testing.T) {
	for _, path := range []string{"config.example.json", "config.windows.example.json", "config.production.example.json"} {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		var cfg agentConfig
		if err := decodeStrictJSON(body, &cfg); err != nil {
			t.Fatalf("strict decode %s: %v", path, err)
		}
	}
}

func TestProductionExamplePassesRuntimeValidationAfterEnrollmentSubstitution(t *testing.T) {
	body, err := os.ReadFile("config.production.example.json")
	if err != nil {
		t.Fatal(err)
	}
	body = []byte(strings.Replace(string(body), "REPLACE_WITH_16_CHAR_ID", "6X13NGV4G9CVK92E", 1))
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := enabledModules(cfg); err != nil {
		t.Fatal(err)
	}
	if err := cfg.License.Validate(); err != nil {
		t.Fatalf("license config: %v", err)
	}
	if _, err := scheduledUpdateFromConfig(cfg.Update); err != nil {
		t.Fatalf("update config: %v", err)
	}
}

func TestReleaseVersionHasOneDefaultSource(t *testing.T) {
	body, err := os.ReadFile("VERSION")
	if err != nil {
		t.Fatal(err)
	}
	version := strings.TrimSpace(string(body))
	if !regexp.MustCompile(`^\d+\.\d+\.\d+([.-][A-Za-z0-9][A-Za-z0-9.-]*)?$`).MatchString(version) {
		t.Fatalf("invalid VERSION value %q", version)
	}

	// Release scripts may accept an explicit override, but their default must
	// always come from VERSION instead of another hard-coded release number.
	for _, path := range []string{"scripts/build-cross.sh", "scripts/package-release.sh"} {
		script, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(script), `"${ROOT_DIR}/VERSION"`) {
			t.Fatalf("%s does not read the canonical VERSION file", path)
		}
		if !strings.Contains(string(script), `scripts/verify-release-version.sh`) {
			t.Fatalf("%s does not enforce release-version immutability", path)
		}
	}
	makefile, err := os.ReadFile("Makefile")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(makefile), "VERSION_FILE := VERSION") {
		t.Fatal("Makefile does not use the canonical VERSION file")
	}
	if !strings.Contains(string(makefile), "-X secweaver-agent/pkg/auditportexecmon.version=$(VERSION)") {
		t.Fatal("audit-port-execmon release version is not injected from VERSION")
	}
}

func TestReleaseVersionGateRejectsEnvironmentOnlyVersioning(t *testing.T) {
	body, err := os.ReadFile("scripts/verify-release-version.sh")
	if err != nil {
		t.Fatal(err)
	}
	// A package name supplied only through VERSION would not be represented in
	// source history, so the gate must compare it with the canonical file.
	for _, contract := range []string{"requested VERSION", "diff --name-only", "status --porcelain"} {
		if !strings.Contains(string(body), contract) {
			t.Fatalf("release version gate does not enforce %q", contract)
		}
	}
}

func TestSignedCrossBuildDefaultsToDigestSignatures(t *testing.T) {
	body, err := os.ReadFile("scripts/build-cross.sh")
	if err != nil {
		t.Fatal(err)
	}
	// When signing is enabled, builds must not silently fall back to signing
	// arbitrarily large artifact bodies; the legacy mode is an explicit override.
	if !strings.Contains(string(body), `UPDATE_ARTIFACT_SIGNATURE_FORMAT:-ed25519-sha256`) {
		t.Fatal("cross-build does not default to ed25519-sha256 artifact signatures")
	}
}

func TestLinuxServiceContainsHostResourceEnvelope(t *testing.T) {
	body, err := os.ReadFile("packaging/secweaver-agent.service")
	if err != nil {
		t.Fatal(err)
	}
	unit := string(body)
	for _, directive := range []string{
		"StartLimitInterval=0",
		"RestartPreventExitStatus=78",
		"CPUQuota=50%",
		"MemoryLimit=512M",
		"TasksMax=128",
		"LimitNOFILE=8192",
		"IOSchedulingPriority=6",
		"OOMScoreAdjust=500",
	} {
		if !strings.Contains(unit, directive) {
			t.Fatalf("systemd resource envelope missing %q", directive)
		}
	}
}

func TestWindowsInstallerEnablesProcessCreationAuditBeforeStoppingService(t *testing.T) {
	body, err := os.ReadFile("packaging/windows/install-service.ps1")
	if err != nil {
		t.Fatal(err)
	}
	script := string(body)
	for _, contract := range []string{
		`{0CCE922B-69AE-11D9-BED3-505054503030}`,
		`/success:enable`,
		`ProcessCreationIncludeCmdLine_Enabled`,
		`Enable-ProcessCreationAudit`,
	} {
		if !strings.Contains(script, contract) {
			t.Fatalf("Windows process audit installer contract missing %q", contract)
		}
	}
	// Audit configuration runs before the existing service is stopped. If a
	// domain policy or permission blocks the change, the prior Agent stays live.
	enable := strings.LastIndex(script, "\nEnable-ProcessCreationAudit\n")
	stop := strings.Index(script, "\n$existing = Get-Service")
	if enable < 0 || stop < 0 || enable > stop {
		t.Fatal("Windows installer must configure process auditing before stopping the existing service")
	}
}

func TestLinuxInstallerPersistsBootstrapCABeforeConfigValidation(t *testing.T) {
	body, err := os.ReadFile("packaging/install.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := string(body)
	persist := strings.Index(script, "\npersist_bootstrap_ca\n")
	configure := strings.Index(script, ` config set-enterprise-id`)
	if persist < 0 || configure < 0 || persist > configure {
		t.Fatal("Linux installer must persist the bootstrap CA before validating or updating Agent config")
	}
	// Both paths are intentional: shipper/ca.crt is current, while older Agent
	// configurations can still validate etc/shipper/ca.crt during an upgrade.
	for _, contract := range []string{
		`PERSISTENT_CA_FILE="${SHIPPER_DIR}/ca.crt"`,
		`LEGACY_PERSISTENT_CA_FILE="${CONFIG_DIR}/shipper/ca.crt"`,
		`UPDATE_CA_FILE="${PERSISTENT_CA_FILE}"`,
	} {
		if !strings.Contains(script, contract) {
			t.Fatalf("Linux installer bootstrap CA contract missing %q", contract)
		}
	}
	if !strings.Contains(script, `install -m 0755 "${ROOT_DIR}/uninstall.sh" "${BIN_DIR}/uninstall.sh"`) {
		t.Fatal("Linux installer must install the canonical uninstaller below the product root")
	}
}

func TestLinuxInstallerUpgradeMakesBootstrapCAAvailableToExistingConfig(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash is required for the Linux installer regression test")
	}
	root := t.TempDir()
	packageRoot := filepath.Join(root, "package")
	installRoot := filepath.Join(root, "installed")
	for _, directory := range []string{"bin", "etc/secweaver-agent", "libexec", "systemd"} {
		if err := os.MkdirAll(filepath.Join(packageRoot, directory), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	installer, err := os.ReadFile("packaging/install.sh")
	if err != nil {
		t.Fatal(err)
	}
	installerPath := filepath.Join(packageRoot, "install.sh")
	if err := os.WriteFile(installerPath, installer, 0o755); err != nil {
		t.Fatal(err)
	}
	// The release archive keeps uninstall.sh beside install.sh as its bootstrap
	// input; the installer must copy it into the installed bin directory.
	if err := os.WriteFile(filepath.Join(packageRoot, "uninstall.sh"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	// The fake binary makes the first config mutation fail unless both current
	// and historical CA paths have already been populated by the installer.
	fakeAgent := `#!/usr/bin/env bash
set -euo pipefail
if [[ "$*" == "config set-enterprise-id"* ]]; then
  cmp -s "${EXPECTED_BOOTSTRAP_CA}" "${EXPECTED_CURRENT_CA}"
  cmp -s "${EXPECTED_BOOTSTRAP_CA}" "${EXPECTED_LEGACY_CA}"
fi
`
	if err := os.WriteFile(filepath.Join(packageRoot, "bin", "secweaver-agent"), []byte(fakeAgent), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, file := range []string{"config.example.json", "audit-port-execmon.example.json", "host-persistence.example.json"} {
		if err := os.WriteFile(filepath.Join(packageRoot, "etc/secweaver-agent", file), []byte("{}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(packageRoot, "libexec", "secweaver-agent-launch"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(packageRoot, "systemd", "secweaver-agent.service"), []byte("[Service]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	configDir := filepath.Join(installRoot, "etc")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	// Keep an existing config in place while the fake binary models the strict CA
	// validation performed before config mutations in the field upgrade path.
	if err := os.WriteFile(filepath.Join(configDir, "config.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bootstrapCA := filepath.Join(root, "bootstrap-ca.crt")
	if err := os.WriteFile(bootstrapCA, []byte("test enrollment CA\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	shipperDir := filepath.Join(installRoot, "shipper")
	command := exec.Command("bash", installerPath, "--enterprise-id", "ABCD1234EFGH5678")
	command.Env = append(os.Environ(),
		"INSTALL_ROOT="+installRoot,
		"BIN_DIR="+filepath.Join(installRoot, "bin"),
		"CONFIG_DIR="+configDir,
		"STATE_DIR="+filepath.Join(installRoot, "data"),
		"LOG_DIR="+filepath.Join(installRoot, "logs"),
		"SHIPPER_DIR="+shipperDir,
		"COMMAND_LINK="+filepath.Join(root, "command", "secweaver-agent"),
		"SYSTEMD_DIR="+filepath.Join(root, "systemd"),
		"INSTALL_DEPS=0",
		"REQUIRE_SYSTEMD=0",
		"SECWEAVER_BOOTSTRAP_CA_FILE="+bootstrapCA,
		"EXPECTED_BOOTSTRAP_CA="+bootstrapCA,
		"EXPECTED_CURRENT_CA="+filepath.Join(shipperDir, "ca.crt"),
		"EXPECTED_LEGACY_CA="+filepath.Join(configDir, "shipper", "ca.crt"),
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("installer regression scenario failed: %v\n%s", err, output)
	}
	if info, err := os.Stat(filepath.Join(installRoot, "bin", "uninstall.sh")); err != nil {
		t.Fatalf("canonical uninstaller was not installed: %v", err)
	} else if info.Mode().Perm() != 0o755 {
		t.Fatalf("canonical uninstaller mode = %o, want 755", info.Mode().Perm())
	}
}

func TestContainerReleaseArtifactsUseNamespaceScopedDefaults(t *testing.T) {
	for _, path := range []string{
		"packaging/container/Dockerfile",
		"packaging/container/docker-compose.yaml",
		"packaging/container/config.container.example.json",
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("container release artifact %s is missing: %v", path, err)
		}
	}
	compose, err := os.ReadFile("packaging/container/docker-compose.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"\n    privileged:", "\n    pid: host", "\n    network_mode: host"} {
		if strings.Contains(string(compose), forbidden) {
			t.Fatalf("container workload compose must not request host privileges: %q", forbidden)
		}
	}
	if !strings.Contains(string(compose), "cap_drop:") || !strings.Contains(string(compose), "- ALL") || !strings.Contains(string(compose), "read_only: true") {
		t.Fatal("container workload compose must retain its reduced-privilege filesystem and capability profile")
	}

	body, err := os.ReadFile("packaging/container/config.container.example.json")
	if err != nil {
		t.Fatal(err)
	}
	var cfg agentConfig
	if err := json.Unmarshal(body, &cfg); err != nil {
		t.Fatalf("container example is not JSON: %v", err)
	}
	for _, name := range []string{"audit-port-execmon", "host-persistence", "syslog-risk-json"} {
		module, ok := cfg.Modules[name]
		if !ok || module.Enabled == nil || *module.Enabled {
			t.Fatalf("container example must disable host-only module %s", name)
		}
	}
	for _, name := range []string{"host-process-snapshot", "host-state-snapshot"} {
		module, ok := cfg.Modules[name]
		if !ok || module.Enabled == nil || !*module.Enabled {
			t.Fatalf("container example must enable namespace-scoped module %s", name)
		}
	}
}

func TestContainerIncompatibleModulesAreLimitedToHostSecurityCollectors(t *testing.T) {
	modules := []runtimeModule{
		{Spec: moduleRegistry["audit-port-execmon"]},
		{Spec: moduleRegistry["host-persistence"]},
		{Spec: moduleRegistry["host-process-snapshot"]},
	}
	got := strings.Join(containerIncompatibleModules(modules), ",")
	if got != "audit-port-execmon,host-persistence" {
		t.Fatalf("container-incompatible modules = %q", got)
	}
}

func TestEnabledModulesRejectsUnknownModuleFlag(t *testing.T) {
	enabled := true
	_, err := enabledModules(agentConfig{
		EnterpriseID: "6X13NGV4G9CVK92E",
		Modules: map[string]moduleConfig{
			"syslog-risk-json": {Enabled: &enabled, Args: []string{"-ouptut", "/tmp/events.log"}},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "unknown flag -ouptut") {
		t.Fatalf("expected actionable module flag error, got %v", err)
	}
}

func TestRemoteConfigRequiresSignatureByDefault(t *testing.T) {
	_, err := scheduledRemoteConfigFromConfig(
		remoteConfigConfig{Enabled: true},
		filepath.Join(t.TempDir(), "config.json"),
		agentlicense.Config{Enabled: true},
		"6X13NGV4G9CVK92E",
	)
	if err == nil || !strings.Contains(err.Error(), "public_key is required") {
		t.Fatalf("expected missing remote config public key error, got %v", err)
	}
}

func TestRemoteConfigUnsignedModeMustBeExplicit(t *testing.T) {
	cfg, err := scheduledRemoteConfigFromConfig(
		remoteConfigConfig{Enabled: true, AllowUnsigned: true},
		filepath.Join(t.TempDir(), "config.json"),
		agentlicense.Config{Enabled: true},
		"6X13NGV4G9CVK92E",
	)
	if err != nil {
		t.Fatal(err)
	}
	if cfg == nil || !cfg.AllowUnsigned {
		t.Fatalf("unsigned development mode not preserved: %+v", cfg)
	}
}

func TestModuleRestartDefaultsAndBackoffCap(t *testing.T) {
	policy := normalizeModuleRestartConfig(moduleConfig{})
	if policy.BaseDelay != 3*time.Second || policy.MaxDelay != 5*time.Minute || policy.FailureLimit != 8 || policy.CircuitDuration != 15*time.Minute {
		t.Fatalf("unexpected restart defaults: %+v", policy)
	}
	module := runtimeModule{Spec: moduleRegistry["syslog-risk-json"], EnterpriseID: "6X13NGV4G9CVK92E"}
	first := moduleRestartBackoff(policy.BaseDelay, policy.MaxDelay, 1, module)
	if first < policy.BaseDelay || first > policy.BaseDelay+policy.BaseDelay/5 {
		t.Fatalf("first restart delay out of range: %s", first)
	}
	if capped := moduleRestartBackoff(policy.BaseDelay, policy.MaxDelay, 20, module); capped != policy.MaxDelay {
		t.Fatalf("restart delay=%s want cap=%s", capped, policy.MaxDelay)
	}
}

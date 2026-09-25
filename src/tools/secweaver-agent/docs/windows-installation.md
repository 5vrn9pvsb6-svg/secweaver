# Windows service and Data Cloud delivery (0.3.58)

0.3.58 separates installation results: green OK for verified steps, cyan INFO for
normal behavior/configuration, yellow WARN for limited or unverified capabilities,
and red ERROR for failures. Windows update exit/replacement and service restart
semantics are INFO, not a current failure or pending restart; preflight/doctor no
longer count this mechanism as a warning. Successful installation does not print
a startup error path. Failure diagnostics use only a current detail file up to 16 KiB.

Learning summaries reuse preflight without another channel query. Missing or
inaccessible Sysmon explicitly means Sysmon-based whitelist reduction is unavailable;
Security 4688 process events and risk events retain originals and collection continues.
An accessible Sysmon channel does not prove a completed baseline or active filtering.
Cloud receipt retains a PENDING VERIFICATION warning: the installer does not query
SLS/ES, so this means neither confirmed upload failure nor verified receipt. Verify
installation output, doctor results and a recent event for this host in the cloud.

0.3.57 fixes InvokeMethodOnNull when RuntimeInformation.OSArchitecture is unavailable
in a Windows PowerShell 5.1 session. Both Bootstrap and Logtail checks now prefer
PROCESSOR_ARCHITEW6432 over PROCESSOR_ARCHITECTURE for native x64/ARM64 and WOW64
OS detection. Missing or unsupported values fail explicitly with stage=platform
check=os-architecture rather than guessing an archive. Managed Windows Logtail
remains x64-only. Download the updated installer; uninstalling an existing Agent
is unnecessary. Verify platform checks through the public installer and run doctor
for service readiness; verify cloud receipt separately.

Version 0.3.56 packages the launcher with native CRLF and a pre-parsed command
block. It exits the dedicated CMD process because EXIT /B tries to return to the
deleted batch file. Use cmd /d /c from CMD/SSH to keep the interactive session open.

## Windows Uninstall

Starting with 0.3.54, installation persists uninstall.cmd, uninstall-service.ps1 and
uninstall-layout.json beside the binary. From an administrator CMD or SSH terminal:

```cmd
cmd.exe /d /c "C:\ProgramData\SecWeaver\Agent\bin\uninstall.cmd" -Purge
```

In PowerShell, `& 'C:\ProgramData\SecWeaver\Agent\bin\uninstall.cmd' -Purge`
also works because PowerShell creates the CMD child. No network/download is needed.
Without flags only the Agent service is removed; binaries and data remain.
`-Purge` removes Agent services/processes and its installation tree, plus the host-wide
LogtailDaemon/LogtailWorker services, known collector processes, standard Alibaba/Logtail
directories under Program Files, and C:\LogtailData. All local logs, credentials/identity,
learning state, update state and collector checkpoints are deleted. `-KeepLogtail` with
`-Purge` retains the shared collector. Existing `-RemoveFiles` and `-RemoveConfig` remain
Agent-only options. `-Json` emits one JSON result; exit 0 means verification passed,
exit 1 means incomplete/rejected cleanup. Cloud data and device records are not removed.
Filebeat, Sysmon, Windows Event Logs and audit policy are not changed.

Supports Windows PowerShell 5.1+ on supported Windows Agent hosts, standard Logtail
1.6.1.0 service/layout, and custom Agent roots with bin/etc beneath the root. Installed
layout metadata preserves a custom service name. External InstallDir/ConfigDir removal,
custom Logtail layouts, foreign service executable paths and junctions/symlinks fail
before cleanup; inspect them separately. The uninstaller serializes with installers,
waits at most 30 seconds per service phase and 10 seconds per owned process, then verifies
services and requested directories are absent. Close Services consoles if SCM deletion
is pending and retry. A partial filesystem failure may require inspecting leftover files;
unknown directories without an Agent binary/config are never blindly removed.

Run integration/windows-install/uninstall.ps1 on an administrator Windows test host:
it uses temporary fixtures for self-deletion/JSON/idempotence and mocked collector paths
for purge, retention and preflight rejection. It does not uninstall a live Agent/Logtail.
Release acceptance must also exercise the packaged entry on Windows PowerShell 5.1,
using a temporary Agent root and -KeepLogtail before testing live removal. Existing
0.3.53 installs do not gain this entry until upgraded to 0.3.54 or later.

Version 0.3.53 fixes PowerShell 5.1 Bootstrap cleanup: removing the enrollment
token must not re-trigger its format validator or turn a completed installation
into a failure. Both successful and failed installation cleanup are tested.

Version 0.3.52 accepts both the native Windows Logtail 1.6.1.0 `metrics` cache and
the legacy `log_config` envelope. Readiness still requires all eight signed routes,
with no overlapping inputs or different destinations. Both namespaces are checked
together; receipt in SLS must still be verified independently.

## 0.3.51 migration and acceptance output

Both Bootstrap and install-service.ps1 accept `-LearningMode preserve|enable|shadow|disable`.
The default preserves existing choices; fresh installations retain template defaults.
Enable explicitly permits eligible matching, shadow learns while retaining all originals,
and disable turns learning off. Only the enabled event owner is changed; duration, scope,
generation and state survive, and no second reader is started. Prefer shadow for migration.
An enabled flag does not certify suppression: enrolled identity and eligible Sysmon
GUID/SHA256/context are required. Security 4688, risk alerts and incomplete context remain
full-output. Doctor distinguishes these conditions.

Installation uses green `[OK]`, yellow `[WARN]` and red `[ERROR]` stages for collection,
authorization, learning, shipper configuration and cloud acceptance. One
`run -dry-run -strict-preflight` validates configuration and platform errors without duplicate
OS probes; ordinary dry-run is unchanged. Cloud delivery stays UNVERIFIED until a server-side
query proves receipt. Local test installation with authorization disabled never claims SaaS
registration. PowerShell 5.1 scripts can use
`powershell.exe -NoProfile -ExecutionPolicy Bypass -File ...`; this does not change machine policy.
The installer pipes enrollment credentials to `-enterprise-enrollment-token-stdin`,
keeping them out of the child process's 4688 command line. The CLI retains its
legacy argument option; managed installation no longer uses it. Avoid recording
credential input in transcripts or embedding it in publicly readable scripts.

## PowerShell risk record contract

Agent 0.3.51 uses Windows risk parser_version 0.3.1. A complete 4104 script fragment is retained
in `command`, with UTF-8 `script_bytes` and exact-content `script_sha256`. Message contains a
summary; byte-identical ScriptBlockText/CommandLine copies are removed from fields. Different
content, ScriptBlockId, MessageNumber and MessageTotal survive. No fragment merging, risk
downgrade or PowerShell/CIM keyword suppression occurs. Explicit raw_xml output still contains
the original XML. Custom queries must read command rather than rely on message or
fields.ScriptBlockText for full scripts; historical data remains readable. Public asset
templates select all fields and required fields remain. Optional indexes can expose the hash.

## Regression fixes from the 0.3.22 report

0.3.49 completes the following installer behavior; an existing 0.3.22 installation
does not acquire these fixes until a new immutable package and Bootstrap are published.

| Report | Current behavior / verification |
| --- | --- |
| Null Bootstrap response | Reject null/empty/HTML/JSON version pointers; accept bounded text/UTF-8 bytes with one LF/CRLF. Empty/malformed sidecars fail before extraction. |
| Created service stops | Require Running plus fresh module/authorization readiness for ten observations within 90 seconds. Before activation, failures restore prior files and SCM command/start mode and restart a previously running service; fresh failed services are deleted. |
| Doctor service name | SCM and doctor share the default `SecWeaverAgent` identity; the installer uses the same name. Custom service names still require explicit SCM inspection. |
| Unclear errors | Bootstrap emits stage, check, sanitized request URL, HTTP status and advice. Enrollment 401 explains credential replacement; 404 explains route configuration; an invalid HTTP-200 body is a response error. Tokens, userinfo, URL queries and server bodies are not printed. |
| Update mismatch | See the explicit defaults below; installation verifies persisted flags before SCM starts. |

Installer rollback is separate from automatic-update rollback. It snapshots only
the binary, Agent/module configuration, shipper intent marker and rollback command.
It preserves device keys/registration, cursors, evidence, audit policy and shared
Logtail. A successful cloud enrollment cannot be undone locally. Failures keep
private `data/install-rollback-*` snapshots for investigation; remove them only
after recovery is verified. Success removes its snapshot. Startup failure reports
SCM numeric exit codes, matching recent SCM events and the bounded private error
record. It does not write Agent events to the Windows System/Application log.
If rollback fails, output says so and provides the backup path; it never reports
installation success. After readiness is accepted, recovery-policy setup failure
retains the activated service and reports the failed stage instead of rewinding it.
`-NoStart` remains intentional staging and never claims runtime acceptance.

## Automatic update defaults

| Entry | Result |
| --- | --- |
| Generic Windows JSON template, no manifest supplied | `update.enabled=false`; there is no usable universal update origin. |
| Published SaaS Bootstrap | Requires a real embedded HTTPS manifest and passes it to installation; persists `enabled=true`, `auto_install=true`. |
| Direct package installer / ES enrollment with `UpdateManifestUrl` | Enables updates using the enrolled immutable device ID; managed installation fails if persisted flags disagree. |
| Upgrade without `UpdateManifestUrl` | Preserves existing settings; does not silently enable or disable updates. |

Enabled scheduling defaults to a six-hour check, initial delay/jitter, and server
policy approval. It does not mean immediate fleet-wide installation; manifest
eligibility, policy and rollout still apply. A supplied public key requires
signature verification; otherwise HTTPS and artifact integrity checks apply.
Doctor reports the actual configuration. Disabled scheduling is not a service-name
failure. To enable it, use the published managed installer or supply a real manifest
and device identity; never merely flip the template flag with its example URL.

Regression checks: `integration/windows-install/contracts.ps1` and `failures.ps1`
run without administrator rights; the latter mocks network/SCM while exercising
real file rollback. Windows CI runs both on PowerShell 5.1. Real SCM startup and
cloud-delivery acceptance remain required on the target Windows host.

The Windows installer now validates configuration/preflight, derives the update device ID
from the same persisted enrollment as the enterprise ID, and requires the SCM service plus
fresh authorized module status to stay ready for ten observations (90-second deadline).
A created service, a transient `Running` state, and an HTTP 200 query are not acceptance.
`doctor` now queries `SecWeaverAgent`, rather than the unrelated `secweaver-agent` name.
SCM failures overwrite one bounded (16 KiB) `<config-path>.service-error.txt`; successful
entry clears the old file. Inspect it before restarting again. It is protected by the
configuration directory ACL and is not collected as event JSONL.

## Prerequisites and limits

Use elevated Windows PowerShell 5.1+ on Windows 10 or Windows Server 2016/2019/2022/2025
amd64, with Security 4688 audit permissions and access to the release, authorization and
SLS endpoints. These are implementation targets; native SCM and cloud acceptance must
still be run for the target environment before release. Domain policy can override local
audit policy. Sysmon remains required for network/file evidence; 4688 suffices for exec.
The Agent still builds for ARM64, but managed Logtail installation rejects ARM64 before
enrollment. Use `-SkipLogtail` only with an independently verified external shipper.
No native ARM64 Logtail support or Windows 7/Server 2008 support is claimed here.

The default official Logtail amd64 archive is `win/win64/1.6.1.0/logtail_installer.zip`,
SHA-256 `58f4edc8d41250f05ca87e4130e52bfbc139e3c6b27e48aa60b2c86d4516ac4d`.
The installer downloads over HTTPS (120 seconds, redirects disabled), verifies SHA-256
before extraction/execution, runs the packaged `logtail_installer.exe install <region>`
from its extraction directory (600-second limit), then checks `LogtailDaemon` and
`ilogtail_worker`. It reuses an existing daemon and rejects legacy `LogtailWorker`
installations requiring an explicit upgrade. Installation is serialized for up to 120
seconds; retries preserve Agent enrollment/key and existing Logtail accounts/group lines.
It restarts the host-wide Logtail service, briefly affecting other sources using it.
`-NoStart` leaves both services stopped, including a daemon started by the vendor installer.
`-SkipLogtail` skips installation only; it does not stop or uninstall an existing shipper.

See the vendor [installation reference](https://www.alibabacloud.com/help/en/sls/install-run-upgrade-and-uninstall-logtail)
and [machine group setup](https://www.alibabacloud.com/help/doc-detail/2861803.html).
Windows uses `C:\LogtailData\users\<AliUid>` and `C:\LogtailData\user_defined_id` regardless
of the Agent root. Existing shared group identities are retained; administrators must
remove obsolete identities explicitly. Default Agent uninstall retains Logtail.
From 0.3.54, explicit `-Purge` also removes standard-layout Logtail; add `-KeepLogtail`
when it is shared. Older versions need the official vendor uninstall procedure.

## Installation and publication

```powershell
$Collection = [Convert]::ToBase64String([IO.File]::ReadAllBytes('C:\Staging\windows-collection.signed.json'))
.\install-service.ps1 `
  -EnterpriseEnrollmentToken 'swenr_TOKEN_ID.SECRET' `
  -LicenseServerUrl 'https://agent-gateway.id-net.cn:30443' `
  -LogtailAliUid '1234567890123456' `
  -LogtailMachineGroup 'YOUR_WINDOWS_ONLY_GROUP' `
  -LogtailRegion 'cn-hangzhou-internet' `
  -LogtailCollectionEnvelope $Collection `
  -LogtailCollectionPublicKey 'BASE64_ED25519_PUBLIC_KEY'
```

Direct packages require the SLS account UID, Windows-only group identifier and signed collection plan.
`-LogtailPackageUrl` and `-LogtailPackageSha256` may point to a reviewed HTTPS mirror with
the same package layout. Custom `-InstallRoot`, `-InstallDir` and `-ConfigDir` rewrite
product-owned default JSON paths without modifying unrelated paths or adding a UTF-8 BOM.
A custom `-ServiceName` is passed to the binary using `service -name`; the standard doctor
service check still targets the default name, so inspect custom services explicitly.

Publication embeds `BOOTSTRAP_LOGTAIL_ALIUID`, `BOOTSTRAP_LOGTAIL_REGION`, and
`BOOTSTRAP_WINDOWS_LOGTAIL_MACHINE_GROUP` in `install.ps1`. The latter defaults to
`<BOOTSTRAP_ENROLLMENT_ID>-windows` and must differ from the Linux identifier.
Before promotion, provision a **Windows** SLS machine group with that custom identifier
and bind Windows file rules. The installer writes the identity and starts the collector;
it does not hold cloud administration credentials or create cloud collection rules.
The generated one-click command then needs only the enrollment token. Missing embedded
identity fails before host changes. Publish new immutable archives for the current canonical `VERSION` and matching
Bootstrap; replacing only the outer Bootstrap cannot fix an old archive installer.

Configure JSON-line collection for the following files under
`C:\ProgramData\SecWeaver\Agent\logs` (substitute a custom root if used). Preserve parsed
enterprise/host identity and event fields. Include numeric rotation suffixes without
also reading the same files through a second rule; use the deployed Logtail version's
rotation handling. Paths and Windows machine group OS must not reuse Linux rules.

| File | Destination / selection |
| --- | --- |
| `windows-process-execmon.log` | host evidence; preserve/filter `asset_type` for exec/connect/file operations |
| `windows-eventlog-risk-json.log` | Windows risk events |
| `host-persistence.log` | host persistence |
| `host-process-snapshot.log` | host process inventory |
| `host-state-snapshot.log` | host state inventory |
| `behavior-learning.log` | behavior summaries |
| `secweaver-agent-health.log` | Agent operations health |
| `secweaver-agent-update.log` | Agent update events |

## Acceptance and recovery

```powershell
$Root = "$env:ProgramData\SecWeaver\Agent"
Get-Service SecWeaverAgent, LogtailDaemon
Get-Process logtail_daemon, ilogtail_worker
Get-Content "$Root\etc\config.json.service-error.txt" -ErrorAction SilentlyContinue
& "$Root\bin\secweaver-agent.exe" doctor -config "$Root\etc\config.json" -json
$Marker = 'secweaver-win-accept-' + [Guid]::NewGuid().ToString('N')
cmd.exe /c "echo $Marker"
Select-String -LiteralPath "$Root\logs\windows-process-execmon.log" -SimpleMatch $Marker
```

Wait for the configured Event Log poll interval before inspecting local evidence. Query
Data Cloud/SLS for this enterprise, this host, the marker and a recent timestamp window.
Require at least one matching **new** host-exec row and check machine-group heartbeat and
rule binding. HTTP 200 with zero matching rows remains a failed ingestion acceptance.
Doctor/health check signed routing, delivered native JSON rules, identity, service and worker; `cloud_delivery=unverified` remains
until independently checked server-side. If the service stops, preserve the failure file,
run `run -config <path> -dry-run`/`preflight -strict`, and correct the reported config,
authorization or audit issue; preserve `data/license-state.json` and `device-ed25519.key`.

Run `powershell -NoProfile -File integration/windows-install/contracts.ps1` for isolated
PowerShell regression tests and `make check` for Go, race and cross-build checks. Native
Windows SCM upgrade tests remain in `integration/service-upgrade/windows-scm.ps1`.
These automated checks do not replace the real-machine marker and cloud query above.

## Windows SLS Collection Readiness

Agent 0.3.50 closes identity-only installation acceptance. The Data Cloud operator
provisions the eight native JSON inputs above and signs a version-one manifest
containing aliuid, machine_group, project, region, log_path and routes
(file, logstore, config_name). The SecWeaver Server operator utility
`go run ./internal/windowsdelivery` provides read-only verification, explicit
`-apply` for absent resources, signing after read-back and a separate cloud marker
receipt check. Its bilingual `docs/windows-sls-collection` guide and
`config/windows-collection.example.json` are maintained in that private repository.
No SLS management credentials are put on customer hosts.

Publisher variables `BOOTSTRAP_WINDOWS_COLLECTION_FILE` (absolute signed-envelope
path) and `BOOTSTRAP_WINDOWS_COLLECTION_PUBLIC_KEY` (base64 Ed25519 public key)
are mandatory for managed Bootstrap publication. They are separate from the update
signing key. The publisher validates identity/region/signature; Bootstrap embeds
both, without an extra download endpoint. Direct archive installation passes
`-LogtailCollectionEnvelope` (base64 envelope) and `-LogtailCollectionPublicKey`.
An invalid/missing plan fails before audit policy, enrollment or service mutation.
Custom roots require a separately provisioned plan; changing paths locally cannot
change cloud rules. Explicitly customized module outputs must align with that plan.

After starting Logtail, installation waits about 120 seconds for the running
worker's `user_log_config.json`. Go parses the native `log_config` map and verifies
the separate `log_path` and `file_pattern`, JSON parser, Project, Logstore, absence
of filters/plugins and overlapping file rules. The supported pattern is the exact
filename plus `*`, covering the product's numeric rotations. Unsupported formats
fail, instead of accepting filenames found in arbitrary strings. The installer
does not write this SLS-owned cache. Failure rolls back Agent pre-activation files
and service; shared Logtail and device identity remain for correction/retry.

The envelope and pinned key persist in the actual config directory as
`windows-collection.json`/`.pub`. Doctor and health use them to check the exact
account/group and cache; `contract_missing`, `identity_missing` and
`collection_rules_missing` are errors, with `config_path` and `missing_paths`
details. Legacy installations need these files through managed reinstall; raw
binary auto-upgrade does not provision SLS. Cache reads are limited to 4 MiB,
manifest reads to 64 KiB and process probes to ten seconds, cached for a minute
by the health reporter. `-NoStart` defers rule delivery; `-SkipLogtail` explicitly
delegates shipping and does not certify it. ARM64 managed Logtail is not supported.

Local readiness never certifies cloud delivery. The operator's `-verify-host-ip`,
`-enterprise-id` and `-marker` check requires a recent machine heartbeat and a
complete nonempty SLS query of a newly generated benign command. It emits a
timestamped receipt; zero rows or query failure remain unverified. Run that test
on a real Windows x64 host before production promotion. Unit tests and cross-builds
do not replace this acceptance.

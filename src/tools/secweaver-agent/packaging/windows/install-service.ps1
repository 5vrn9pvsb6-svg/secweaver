[CmdletBinding()]
param(
  [ValidateSet("", "sls_saas", "es_private")]
  [string]$DeploymentMode = "",
  [ValidateSet('preserve', 'enable', 'shadow', 'disable')]
  [string]$LearningMode = 'preserve',
  [ValidatePattern('^[A-Za-z0-9]{16}$')]
  [string]$EnterpriseId = "",
  [string]$EnterpriseEnrollmentToken = "",
  [string]$InstallRoot = "$env:ProgramData\SecWeaver\Agent",
  [string]$InstallDir = "",
  [string]$ConfigDir = "",
  [ValidatePattern('^[A-Za-z0-9_.-]{1,128}$')]
  [string]$ServiceName = "SecWeaverAgent",
  [string]$DisplayName = "SecWeaver Agent",
  [string]$LicenseServerUrl = "",
  [string]$LicenseEnrollmentId = "",
  [int]$LicenseCheckIntervalSeconds = 21600,
  [int]$LicenseHeartbeatIntervalSeconds = 180,
  [ValidateRange(0, 604800)]
  [int]$LicenseOutageGraceSeconds = 86400,
  [string]$UpdateManifestUrl = "",
  [string]$UpdatePublicKey = "",
  [string]$UpdateDeviceId = "",
  [string]$UpdateCAFile = "",
  [ValidateSet("true", "false")]
  [string]$UpdateRequireServerPolicy = "true",
  [string]$LogtailAliUid = "",
  [string]$LogtailMachineGroup = "",
  [string]$LogtailCollectionEnvelope = "",
  [string]$LogtailCollectionPublicKey = "",
  [string]$LogtailRegion = "cn-hangzhou-internet",
  [string]$LogtailPackageUrl = "https://logtail-release.oss-cn-hangzhou.aliyuncs.com/win/win64/1.6.1.0/logtail_installer.zip",
  [string]$LogtailPackageSha256 = "58f4edc8d41250f05ca87e4130e52bfbc139e3c6b27e48aa60b2c86d4516ac4d",
  [switch]$SkipLogtail,
  [switch]$NoStart
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "windows-install-common.ps1")

function Assert-Administrator {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($identity)
  $adminRole = [Security.Principal.WindowsBuiltInRole]::Administrator
  if (-not $principal.IsInRole($adminRole)) {
    throw "Please run this script from an elevated PowerShell session."
  }
}

function Enable-ProcessCreationAudit {
  # Use the stable subcategory GUID instead of its localized display name so
  # the installer behaves identically on English, Chinese, and vendor Windows.
  $ProcessCreationSubcategory = "{0CCE922B-69AE-11D9-BED3-505054503030}"
  $AuditPol = Join-Path $env:SystemRoot "System32\auditpol.exe"
  if (-not (Test-Path -LiteralPath $AuditPol -PathType Leaf)) {
    throw "Windows audit policy utility not found: $AuditPol"
  }

  # Success auditing generates Security 4688. Do not alter failure auditing,
  # which remains owned by the local or domain security baseline.
  & $AuditPol /set "/subcategory:$ProcessCreationSubcategory" /success:enable | Out-Null
  if ($LASTEXITCODE -ne 0) {
    throw "Failed to enable Audit Process Creation success events (auditpol exit $LASTEXITCODE)."
  }

  # Event 4688 omits command-line arguments unless this separate ADMX-backed
  # policy is enabled. Arguments are stored as plaintext in the Security log;
  # access therefore remains restricted to Windows security-log readers.
  $AuditRegistryPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
  New-Item -Path $AuditRegistryPath -Force | Out-Null
  New-ItemProperty `
    -Path $AuditRegistryPath `
    -Name "ProcessCreationIncludeCmdLine_Enabled" `
    -PropertyType DWord `
    -Value 1 `
    -Force | Out-Null
  $ConfiguredValue = (Get-ItemProperty `
    -Path $AuditRegistryPath `
    -Name "ProcessCreationIncludeCmdLine_Enabled").ProcessCreationIncludeCmdLine_Enabled
  if ($ConfiguredValue -ne 1) {
    throw "Failed to enable command-line data in Windows process creation events."
  }
  Write-InstallResult 'OK' 'audit-policy' 'Security 4688 and command-line auditing enabled'
}

Assert-Administrator

$PackageRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$BinarySource = Join-Path $PackageRoot "bin\secweaver-agent.exe"
$ConfigSource = Join-Path $PackageRoot "etc\secweaver-agent\config.windows.example.json"
$HostPersistenceSource = Join-Path $PackageRoot "etc\secweaver-agent\host-persistence.windows.example.json"
$InstallDir = if ($InstallDir) { $InstallDir } else { Join-Path $InstallRoot "bin" }
$ConfigDir = if ($ConfigDir) { $ConfigDir } else { Join-Path $InstallRoot "etc" }
$DataDir = Join-Path $InstallRoot "data"
$LogsDir = Join-Path $InstallRoot "logs"
$ShipperDir = Join-Path $InstallRoot "shipper"
$BinaryDest = Join-Path $InstallDir "secweaver-agent.exe"
$ConfigPath = Join-Path $ConfigDir "config.json"
$HostPersistencePath = Join-Path $ConfigDir "host-persistence.json"
$LicenseStatePath = Join-Path $DataDir "license-state.json"
$IdentityKeyPath = Join-Path $DataDir "device-ed25519.key"
$UpdateStateDir = Join-Path $DataDir "update"
$RollbackScript = Join-Path $DataDir "rollback-agent.cmd"

if (-not (Test-Path $BinarySource)) {
  throw "Missing package binary: $BinarySource"
}
if (-not (Test-Path $ConfigSource)) {
  throw "Missing package config: $ConfigSource"
}
if (-not (Test-Path $HostPersistenceSource)) {
  throw "Missing host-persistence config: $HostPersistenceSource"
}
if ($EnterpriseEnrollmentToken -and $EnterpriseId) {
  throw "EnterpriseEnrollmentToken and EnterpriseId are mutually exclusive."
}
if (-not $EnterpriseEnrollmentToken -and -not $EnterpriseId) {
  throw "EnterpriseEnrollmentToken is required for a new installation. EnterpriseId is legacy migration only."
}

# Reject cross-channel upgrades before touching audit policy or the service.
$ModeConfig = $ConfigPath
if (-not (Test-Path $ModeConfig) -and (Test-Path "$env:ProgramData\SecWeaver\config.json")) {
  $ModeConfig = "$env:ProgramData\SecWeaver\config.json"
}
$DeploymentModeArgs = @()
if ($DeploymentMode) { $DeploymentModeArgs = @("-mode", $DeploymentMode) }
$ResolvedMode = & $BinarySource config set-deployment-mode -config $ModeConfig @DeploymentModeArgs -check-only
if ($LASTEXITCODE -ne 0) { throw "Agent deployment mode check failed." }
# An omitted flag preserves an existing ES installation. Only new, otherwise
# unspecified installations follow the Windows installer's SaaS default.
if ($ResolvedMode -eq "es_private") {
  $SkipLogtail = $true
} elseif ($ResolvedMode -eq "unspecified" -and -not $SkipLogtail) {
  $ResolvedMode = "sls_saas"
}
if ($ResolvedMode -ne "unspecified") { $DeploymentModeArgs = @("-mode", $ResolvedMode) }
if (-not $SkipLogtail) {
  Assert-LogtailParameters $LogtailAliUid $LogtailMachineGroup $LogtailRegion $LogtailPackageUrl $LogtailPackageSha256
  # Validate the operator-signed contract before audit policy, enrollment or
  # service changes. Custom roots require a matching operator-provisioned plan.
  if (-not $LogtailCollectionEnvelope -or $LogtailCollectionEnvelope.Length -gt 90000) { throw 'Missing or oversized signed Windows Logtail collection plan.' }
  $PlanTemp = [IO.Path]::GetTempFileName()
  try {
    [IO.File]::WriteAllBytes($PlanTemp, [Convert]::FromBase64String($LogtailCollectionEnvelope))
    & $BinarySource logtail-check -manifest $PlanTemp -public-key $LogtailCollectionPublicKey -log-path $LogsDir -aliuid $LogtailAliUid -machine-group $LogtailMachineGroup -region ($LogtailRegion -replace '-internet$', '')
    if ($LASTEXITCODE -ne 0) { throw 'Signed Windows collection plan validation failed; contact the Data Cloud operator.' }
  } finally { Remove-Item -LiteralPath $PlanTemp -Force -ErrorAction SilentlyContinue }
}

# Configure the event source before stopping an existing service. A policy
# failure aborts the upgrade while the currently installed Agent keeps running.
Enable-ProcessCreationAudit

# ProgramData is used for the single-root layout because the service must update
# state and binaries. Remove inherited write access so only SYSTEM and local
# Administrators can alter executable or configuration files.
New-Item -ItemType Directory -Force $InstallRoot, $InstallDir, $ConfigDir, $DataDir, $LogsDir, $ShipperDir | Out-Null
& icacls.exe $InstallRoot /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) {
  throw "Failed to apply the restricted ACL to $InstallRoot"
}

$InstallMutex = New-Object Threading.Mutex($false, 'Global\SecWeaverAgentInstall')
$InstallLocked = $false
$InstallSnapshot = $null
$InstallStartedAt = [DateTime]::UtcNow
$InstallStage = 'snapshot'
$InstallCommitted = $false
$InstallSucceeded = $false
try {
try { $InstallLocked = $InstallMutex.WaitOne([TimeSpan]::FromSeconds(120)) }
catch [Threading.AbandonedMutexException] { $InstallLocked = $true }
if (-not $InstallLocked) { throw 'Timed out waiting for another Agent installation.' }
$InstallSnapshot = New-AgentInstallSnapshot $ServiceName @($BinaryDest, (Join-Path $InstallDir 'uninstall.cmd'), (Join-Path $InstallDir 'uninstall-service.ps1'), (Join-Path $InstallDir 'uninstall-layout.json'), $ConfigPath, $HostPersistencePath, $RollbackScript, (Join-Path $ConfigDir 'shipper-kind'), (Join-Path $ConfigDir 'windows-collection.json'), (Join-Path $ConfigDir 'windows-collection.pub')) $DataDir
$InstallStage = 'configure-agent'
$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing -and $existing.Status -ne "Stopped") {
  Stop-Service -Name $ServiceName -Force
  $existing.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(30))
}

if (-not (Test-Path $ConfigPath)) {
  $LegacyConfigPath = "$env:ProgramData\SecWeaver\config.json"
  if (Test-Path $LegacyConfigPath) {
    Copy-Item $LegacyConfigPath $ConfigPath
    & $BinarySource config migrate-layout -platform windows -config $ConfigPath
    if ($LASTEXITCODE -ne 0) { throw "Failed to migrate legacy Agent configuration." }
  } else {
    Copy-Item $ConfigSource $ConfigPath
  }
}
& $BinarySource config set-deployment-mode -config $ConfigPath @DeploymentModeArgs
if ($LASTEXITCODE -ne 0) { throw "Failed to persist Agent deployment mode." }
if (-not (Test-Path $HostPersistencePath)) {
  $LegacyHostPersistencePath = "$env:ProgramData\SecWeaver\host-persistence.json"
  if (Test-Path $LegacyHostPersistencePath) {
    Copy-Item $LegacyHostPersistencePath $HostPersistencePath
    & $BinarySource config migrate-layout -platform windows -config $HostPersistencePath
    if ($LASTEXITCODE -ne 0) { throw "Failed to migrate legacy host-persistence configuration." }
  } else {
    Copy-Item $HostPersistenceSource $HostPersistencePath
  }
}

# Preserve registration identity and cursors during an in-place layout upgrade.
# Files are copied, not moved, so the previous service command remains rollback-capable.
@(
  "license-state.json", "device-ed25519.key", "status.json",
  "host-persistence-state.json", "host-process-snapshot-state.json",
  "host-state-snapshot-state.json", "windows-eventlog-risk-json.cursor.json",
  "windows-process-execmon.cursor.json"
) | ForEach-Object {
  $LegacyState = Join-Path "$env:ProgramData\SecWeaver" $_
  $NewState = Join-Path $DataDir $_
  if ((Test-Path $LegacyState) -and -not (Test-Path $NewState)) {
    Copy-Item $LegacyState $NewState
  }
}

if ($EnterpriseEnrollmentToken) {
  $InstallStage = 'device-enrollment'
  if (-not $LicenseServerUrl) {
    throw "LicenseServerUrl is required with EnterpriseEnrollmentToken."
  }
  # 4688 auditing is already enabled: pipe the credential so the child process
  # command line never contains it. No transcript is started by this installer.
  $EnrollmentOutput = $EnterpriseEnrollmentToken | & $BinarySource enroll `
    -server-url $LicenseServerUrl `
    -enterprise-enrollment-token-stdin `
    -state-path $LicenseStatePath `
    -identity-key-path $IdentityKeyPath `
    -output installer
  if ($LASTEXITCODE -ne 0) {
    throw "Failed to enroll this Windows device with SecWeaver Data Cloud."
  }
  # One durable enrollment supplies both tenant and rollout identity. Reject
  # unexpected output instead of silently using a hostname or a stale ID.
  $Identity = ConvertFrom-InstallerIdentity $EnrollmentOutput $UpdateDeviceId
  $NormalizedEnterpriseId = $Identity.EnterpriseId
  $UpdateDeviceId = $Identity.DeviceId
} else {
  if ($LicenseServerUrl -and -not $LicenseEnrollmentId) {
    throw "LicenseEnrollmentId is required when LicenseServerUrl is supplied."
  }
  $NormalizedEnterpriseId = $EnterpriseId.ToUpperInvariant()
}

& $BinarySource config set-enterprise-id `
  -config $ConfigPath `
  -enterprise-id $NormalizedEnterpriseId
if ($LASTEXITCODE -ne 0) {
  throw "Failed to configure enterprise_id in $ConfigPath"
}

& $BinarySource config ensure-host-process-snapshot -config $ConfigPath
if ($LASTEXITCODE -ne 0) {
  throw "Failed to configure host-process-snapshot in $ConfigPath"
}

& $BinarySource config ensure-host-state-snapshot -config $ConfigPath
if ($LASTEXITCODE -ne 0) {
  throw "Failed to configure host-state-snapshot in $ConfigPath"
}

& $BinarySource config optimize-collectors -config $ConfigPath
if ($LASTEXITCODE -ne 0) {
  throw "Failed to optimize collector configuration in $ConfigPath"
}

if ($EnterpriseEnrollmentToken) {
  & $BinarySource config set-license `
    -config $ConfigPath `
    -protocol device_v2 `
    -server-url $LicenseServerUrl `
    -state-path $LicenseStatePath `
    -identity-key-path $IdentityKeyPath `
    -check-interval-seconds $LicenseCheckIntervalSeconds `
    -heartbeat-interval-seconds $LicenseHeartbeatIntervalSeconds `
    -outage-grace-seconds $LicenseOutageGraceSeconds `
    -fail-closed true
  if ($LASTEXITCODE -ne 0) {
    throw "Failed to configure device_v2 authorization in $ConfigPath"
  }
} elseif ($LicenseServerUrl) {
  & $BinarySource config set-license `
    -config $ConfigPath `
    -server-url $LicenseServerUrl `
    -enrollment-id $LicenseEnrollmentId `
    -check-interval-seconds $LicenseCheckIntervalSeconds `
    -heartbeat-interval-seconds $LicenseHeartbeatIntervalSeconds `
    -outage-grace-seconds $LicenseOutageGraceSeconds `
    -fail-closed true
  if ($LASTEXITCODE -ne 0) {
    throw "Failed to configure license in $ConfigPath"
  }
}

$InstallStage = 'configure-updates'
if ($UpdatePublicKey -and -not $UpdateManifestUrl) {
  throw "UpdateManifestUrl is required when UpdatePublicKey is set."
}
if ($UpdateManifestUrl) {
  if ($UpdateManifestUrl -notmatch '^https://') {
    throw "UpdateManifestUrl must use HTTPS."
  }
  if ($UpdatePublicKey -and $UpdatePublicKey -notmatch '^[A-Za-z0-9+/]{43}=$') {
    throw "UpdatePublicKey must be a base64 Ed25519 public key."
  }
  if (-not $UpdateDeviceId) {
    throw "UpdateDeviceId is required when updates are enabled."
  }
  $UpdateArgs = @(
    "config", "set-update",
    "-config", $ConfigPath,
    "-manifest-url", $UpdateManifestUrl,
    "-device-id", $UpdateDeviceId,
    "-channel", "stable",
    "-auto-install", "true",
    "-require-server-policy", $UpdateRequireServerPolicy,
    "-health-timeout-seconds", "90"
  )
  if ($UpdatePublicKey) {
    $UpdateArgs += @("-public-key", $UpdatePublicKey)
  }
  if ($UpdateCAFile) {
    $UpdateArgs += @("-ca-file", $UpdateCAFile)
  }
  & $BinarySource @UpdateArgs
  if ($LASTEXITCODE -ne 0) {
    throw "Failed to configure Agent updates in $ConfigPath"
  }
}

Update-WindowsLayout $ConfigPath $InstallRoot $InstallDir $ConfigDir
Update-WindowsLayout $HostPersistencePath $InstallRoot $InstallDir $ConfigDir
Set-WindowsLearningMode $ConfigPath $LearningMode
Confirm-WindowsUpdateConfiguration $ConfigPath ([bool]$UpdateManifestUrl)

# Validate exactly the configuration that SCM will load, including enrollment
# and update identity. A created service alone is never an installation success.
# dry-run already performs and displays preflight. Keep its fatal-error check;
# a second preflight duplicated all output and repeated expensive OS queries.
$Validation = @(& $BinarySource run -config $ConfigPath -dry-run -strict-preflight)
$ValidationExit = $LASTEXITCODE
$Validation | Where-Object { $_ -match '^\[(WARN|ERROR)\]' } | ForEach-Object {
  Write-Host $_ -ForegroundColor $(if ($_ -match '^\[ERROR\]') { 'Red' } else { 'Yellow' })
}
if ($ValidationExit -ne 0) { throw "Agent configuration/preflight validation failed: $ConfigPath (exit $ValidationExit)" }
Write-InstallResult 'OK' 'configuration' 'Agent configuration and preflight validated'

if (-not $SkipLogtail) {
  $InstallStage = 'install-logtail'
  # Persist intent before download so interrupted setup is visible to doctor.
  Set-Content -LiteralPath (Join-Path $ConfigDir "shipper-kind") -Value "logtail" -Encoding Ascii
  $CollectionPath = Join-Path $ConfigDir 'windows-collection.json'
  [IO.File]::WriteAllBytes($CollectionPath, [Convert]::FromBase64String($LogtailCollectionEnvelope))
  [IO.File]::WriteAllText((Join-Path $ConfigDir 'windows-collection.pub'), $LogtailCollectionPublicKey, [Text.Encoding]::ASCII)
  Install-WindowsLogtail $LogtailAliUid $LogtailMachineGroup $LogtailRegion $LogtailPackageUrl $LogtailPackageSha256 -NoStart:$NoStart
  if (-not $NoStart) {
    $DeliveredConfig = Wait-WindowsLogtailCollection $BinarySource $CollectionPath $LogtailCollectionPublicKey
    Write-InstallResult 'OK' 'shipper' "Logtail runtime and delivered rules verified: $DeliveredConfig"
  } else {
    Write-Warning "NoStart requested: Windows Logtail collection-rule delivery is deferred until the collector is started."
  }
} else {
  Write-InstallResult 'WARN' 'shipper' 'Managed Logtail skipped; external delivery has not been verified'
}

$InstallStage = 'install-service'
Copy-Item -Force $BinarySource $BinaryDest
# Keep the offline uninstall entry with the installed binary, not in Bootstrap's
# temporary extraction directory. Rollback restores the prior entry as well.
Copy-Item -LiteralPath (Join-Path $PackageRoot 'uninstall-service.ps1') -Destination (Join-Path $InstallDir 'uninstall-service.ps1') -Force
Copy-Item -LiteralPath (Join-Path $PackageRoot 'uninstall.cmd') -Destination (Join-Path $InstallDir 'uninstall.cmd') -Force
$UninstallLayout = @{install_root=$InstallRoot;install_dir=$InstallDir;config_dir=$ConfigDir;service_name=$ServiceName} | ConvertTo-Json
[IO.File]::WriteAllText((Join-Path $InstallDir 'uninstall-layout.json'), $UninstallLayout, (New-Object Text.UTF8Encoding($false)))

$RollbackBody = @"
@echo off
setlocal
set "STATE=$UpdateStateDir"
set "AGENT=$BinaryDest"
if not exist "%STATE%\health.pending" goto restart
if not exist "%STATE%\previous.bin" exit /b 2
copy /Y "%STATE%\previous.bin" "%AGENT%.rollback" >NUL || exit /b 3
set "ROLLBACK=%AGENT%.rollback"
powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "[IO.File]::Replace(`$env:ROLLBACK, `$env:AGENT, `$null, `$true)" >NUL 2>NUL || exit /b 4
del /Q "%STATE%\health.pending" "%STATE%\activation.attempted" >NUL 2>NUL
:restart
sc.exe start "$ServiceName" >NUL 2>NUL
exit /b 0
"@
Set-Content -Path $RollbackScript -Value $RollbackBody -Encoding Ascii

$BinaryPath = "`"$BinaryDest`" service -name $ServiceName -config `"$ConfigPath`""
if ($existing) {
  & sc.exe config $ServiceName binPath= $BinaryPath start= auto | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "Failed to configure service $ServiceName" }
} else {
  New-Service `
    -Name $ServiceName `
    -BinaryPathName $BinaryPath `
    -DisplayName $DisplayName `
    -StartupType Automatic `
    -Description "SecWeaver host-side collection agent" | Out-Null
}

if (-not $NoStart) {
  $InstallStage = 'service-readiness'
  $StartedAt = [DateTime]::UtcNow
  Start-Service -Name $ServiceName
  Wait-AgentReady $ServiceName $ConfigPath $StartedAt
  Write-InstallResult 'OK' 'collection' 'Agent service and enabled modules verified running'
} else {
  Write-Warning "NoStart requested: services are installed but not started; runtime and cloud delivery are unverified."
}

# Readiness is the activation boundary. Keep prior recovery settings untouched
# on startup failure; configure future automatic-update recovery only afterwards.
$InstallCommitted = $true
$InstallStage = 'service-recovery'
$RollbackCommand = "`"$env:ComSpec`" /d /s /c `"`"$RollbackScript`"`""
& sc.exe failure $ServiceName reset= 86400 actions= restart/10000/restart/10000/run/1000 command= $RollbackCommand | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Failed to configure recovery for $ServiceName; the activated service is retained." }
& sc.exe failureflag $ServiceName 1 | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Failed to enable recovery for $ServiceName; the activated service is retained." }

Write-Host "Installed service: $ServiceName"
Write-Host "Installation root: $InstallRoot"
Write-Host "Binary: $BinaryDest"
Write-Host "Config: $ConfigPath"
Write-Host "Host persistence config: $HostPersistencePath"
Write-Host "State: $DataDir"
Write-Host "Logs: $LogsDir"
Write-Host "Uninstall: cmd.exe /d /c `"$InstallDir\uninstall.cmd`" ; add -Purge for full local cleanup"
if ($EnterpriseEnrollmentToken) {
  Write-InstallResult 'OK' 'enrollment' 'device_v2 registration configured'
} else {
  $FinalConfig = Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
  if ($FinalConfig.license.enabled) { Write-InstallResult 'OK' 'authorization' 'Existing managed authorization retained' }
  else { Write-InstallResult 'WARN' 'authorization' 'Authorization disabled; this is a local/test installation, not SaaS registration' }
}
Write-WindowsLearningSummary $ConfigPath $Validation
Write-InstallResult 'WARN' 'cloud-delivery' 'PENDING VERIFICATION: this installer does not query SLS/ES. Verify a recent event for this host in the cloud; local service/rule checks alone do not prove receipt. This is not a confirmed upload failure.'
$EnterpriseEnrollmentToken = ""
$InstallSucceeded = $true
} catch {
  $Failure = Protect-InstallerMessage $_.Exception.Message $EnterpriseEnrollmentToken
  # Diagnostic permissions/failures must never bypass rollback of the service.
  $Diagnostics = 'SCM diagnostics unavailable'
  try { $Diagnostics = Protect-InstallerMessage (Get-AgentStartupFailure $ServiceName $ConfigPath $InstallStartedAt) $EnterpriseEnrollmentToken } catch { }
  $RollbackResult = 'not started'
  if ($InstallSnapshot -and -not $InstallCommitted) {
    try { Restore-AgentInstallSnapshot $InstallSnapshot; $RollbackResult = 'completed' }
    catch { $RollbackResult = 'failed: ' + (Protect-InstallerMessage $_.Exception.Message $EnterpriseEnrollmentToken) }
  } elseif ($InstallCommitted) { $RollbackResult = 'activation already accepted; current service retained' }
  $BackupPath = if ($InstallSnapshot) { $InstallSnapshot.Directory } else { 'none' }
  Write-InstallResult 'ERROR' $InstallStage ("Installation failed; rollback=$RollbackResult")
  throw "stage=${InstallStage}: $Failure`n$Diagnostics`nrollback=$RollbackResult backup=$BackupPath. Device identity, cursors, evidence and shared Logtail are retained."
} finally {
  $EnterpriseEnrollmentToken = ''
  if ($InstallLocked) { $InstallMutex.ReleaseMutex() }
  $InstallMutex.Dispose()
  # Successful installs do not accumulate rollback copies; failures preserve
  # their private snapshot for investigation, including rollback failures.
  if ($InstallSucceeded -and $InstallSnapshot) {
    Remove-Item -LiteralPath $InstallSnapshot.Directory -Recurse -Force -ErrorAction SilentlyContinue
  }
}

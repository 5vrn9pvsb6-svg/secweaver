[CmdletBinding()]
param(
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
  [switch]$NoStart
)

$ErrorActionPreference = "Stop"

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
  Write-Host "Windows process creation auditing enabled: Security 4688 with command line"
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
  if (-not $LicenseServerUrl) {
    throw "LicenseServerUrl is required with EnterpriseEnrollmentToken."
  }
  $EnrollmentOutput = & $BinarySource enroll `
    -server-url $LicenseServerUrl `
    -enterprise-enrollment-token $EnterpriseEnrollmentToken `
    -state-path $LicenseStatePath `
    -identity-key-path $IdentityKeyPath
  if ($LASTEXITCODE -ne 0) {
    throw "Failed to enroll this Windows device with SecWeaver Data Cloud."
  }
  $NormalizedEnterpriseId = ($EnrollmentOutput | Select-Object -Last 1).Trim().ToUpperInvariant()
  if ($NormalizedEnterpriseId -notmatch '^[A-Za-z0-9]{16}$') {
    throw "Enrollment returned an invalid enterprise_id."
  }
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

Copy-Item -Force $BinarySource $BinaryDest

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

$BinaryPath = "`"$BinaryDest`" service -config `"$ConfigPath`""
if ($existing) {
  & sc.exe config $ServiceName binPath= $BinaryPath start= auto | Out-Null
  & sc.exe description $ServiceName "SecWeaver host-side collection agent" | Out-Null
} else {
  New-Service `
    -Name $ServiceName `
    -BinaryPathName $BinaryPath `
    -DisplayName $DisplayName `
    -StartupType Automatic `
    -Description "SecWeaver host-side collection agent" | Out-Null
}

$RollbackCommand = "`"$env:ComSpec`" /d /s /c `"`"$RollbackScript`"`""
& sc.exe failure $ServiceName reset= 86400 actions= restart/10000/restart/10000/run/1000 command= $RollbackCommand | Out-Null
& sc.exe failureflag $ServiceName 1 | Out-Null

if (-not $NoStart) {
  Start-Service -Name $ServiceName
}

Write-Host "Installed service: $ServiceName"
Write-Host "Installation root: $InstallRoot"
Write-Host "Binary: $BinaryDest"
Write-Host "Config: $ConfigPath"
Write-Host "Host persistence config: $HostPersistencePath"
Write-Host "State: $DataDir"
Write-Host "Logs: $LogsDir"
if ($EnterpriseEnrollmentToken) {
  Write-Host "Authorization: device_v2"
} else {
  Write-Host "Authorization: legacy_v1 migration"
}
$EnterpriseEnrollmentToken = ""
Write-Host "Service wrapper log: none; inspect Windows service status/Event Viewer and module JSONL outputs"

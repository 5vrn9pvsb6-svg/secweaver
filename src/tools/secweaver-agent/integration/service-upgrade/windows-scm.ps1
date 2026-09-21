[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw "Run this integration test from an elevated PowerShell session."
}

$ServiceName = "SecWeaverAgentUpgradeIntegration"
$AgentRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$Root = Join-Path $env:TEMP ("secweaver-agent-upgrade-" + [Guid]::NewGuid().ToString("N"))
$ArtifactDir = Join-Path $Root "artifacts"
$StateDir = Join-Path $Root "state"
$Binary = Join-Path $Root "secweaver-agent.exe"
$ConfigPath = Join-Path $Root "config.json"
$RollbackScript = Join-Path $Root "rollback-agent.cmd"

function Invoke-Go {
  param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)
  & go @Arguments
  if ($LASTEXITCODE -ne 0) {
    throw "go $($Arguments -join ' ') failed with exit code $LASTEXITCODE"
  }
}

function Remove-TestService {
  $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
  if ($service) {
    if ($service.Status -ne "Stopped") {
      Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
      $service.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(20))
    }
    & sc.exe delete $ServiceName | Out-Null
  }
}

function Write-SignedManifest {
  param(
    [Parameter(Mandatory = $true)][string]$Version,
    [Parameter(Mandatory = $true)][string]$TargetName
  )
  $UnsignedManifest = @{
    schema_version = "1"
    app = "secweaver-agent"
    channel = "stable"
    latest = @{ version = $Version }
    binaries = @{
      ("windows_" + $Arch) = @{ url = $TargetName; sha256 = "pending" }
    }
  }
  $UnsignedPath = Join-Path $Root "unsigned-manifest.json"
  [IO.File]::WriteAllText(
    $UnsignedPath,
    ($UnsignedManifest | ConvertTo-Json -Depth 8),
    (New-Object Text.UTF8Encoding($false))
  )
  Push-Location $AgentRoot
  try {
    Invoke-Go run ./cmd/update-sign `
      -manifest $UnsignedPath `
      -artifact-dir $ArtifactDir `
      -private-key-file (Join-Path $Root "update-signing.key") `
      -out (Join-Path $ArtifactDir "update-manifest.json")
  } finally {
    Pop-Location
  }
}

try {
  Remove-TestService
  New-Item -ItemType Directory -Force $ArtifactDir, $StateDir | Out-Null
  Push-Location $AgentRoot
  try {
    Invoke-Go build -trimpath -ldflags "-X main.version=0.3.0" -o $Binary .
    $Arch = (& go env GOARCH).Trim()
    $GoodTargetName = "secweaver-agent_0.3.1_windows_$Arch.exe"
    $GoodTargetBinary = Join-Path $ArtifactDir $GoodTargetName
    $FailedTargetName = "secweaver-agent_0.3.2_windows_$Arch.exe"
    $FailedTargetBinary = Join-Path $ArtifactDir $FailedTargetName
    Invoke-Go build -trimpath -ldflags "-X main.version=0.3.1" -o $GoodTargetBinary .
    Invoke-Go build -trimpath -tags integrationhealthfail -ldflags "-X main.version=0.3.2" -o $FailedTargetBinary .
    Invoke-Go run ./cmd/update-sign -generate-key (Join-Path $Root "update-signing.key")
  } finally {
    Pop-Location
  }
  Write-SignedManifest -Version "0.3.1" -TargetName $GoodTargetName

  $PublicKey = (Get-Content -Raw (Join-Path $Root "update-signing.key.pub")).Trim()
  $Config = @{
    enterprise_id = "TESTUPGRADE00001"
    status_path = (Join-Path $Root "status.json")
    license = @{ enabled = $false }
    update = @{
      enabled = $true
      manifest_url = (Join-Path $ArtifactDir "update-manifest.json")
      channel = "stable"
      interval_seconds = 3600
      initial_delay_seconds = 1
      retry_initial_seconds = 1
      retry_max_seconds = 5
      auto_install = $true
      state_dir = $StateDir
      self_path = $Binary
      status_output = (Join-Path $Root "update-status.jsonl")
      device_id = "integration-windows-device"
      public_key = $PublicKey
      require_server_policy = $false
      health_timeout_seconds = 5
      lock_stale_seconds = 60
      max_backups = 2
      min_free_space_mb = 1
    }
    modules = @{
      "host-process-snapshot" = @{
        enabled = $true
        restart = "on_failure"
        args = @("-interval", "30s", "-output", (Join-Path $Root "host-process.jsonl"))
      }
    }
  }
  [IO.File]::WriteAllText(
    $ConfigPath,
    ($Config | ConvertTo-Json -Depth 10),
    (New-Object Text.UTF8Encoding($false))
  )

  $RollbackBody = @"
@echo off
setlocal
set "STATE=$StateDir"
set "AGENT=$Binary"
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

  $BinaryPath = "`"$Binary`" service -config `"$ConfigPath`""
  New-Service -Name $ServiceName -BinaryPathName $BinaryPath -StartupType Manual `
    -DisplayName "SecWeaver Agent upgrade integration test" | Out-Null
  $RollbackCommand = "`"$env:ComSpec`" /d /s /c `"`"$RollbackScript`"`""
  & sc.exe failure $ServiceName reset= 86400 actions= restart/1000/restart/1000/run/1000 command= $RollbackCommand | Out-Null
  & sc.exe failureflag $ServiceName 1 | Out-Null
  Start-Service -Name $ServiceName

  $Deadline = [DateTime]::UtcNow.AddMinutes(3)
  $Healthy = $false
  while ([DateTime]::UtcNow -lt $Deadline) {
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ((Test-Path (Join-Path $StateDir "state.json")) -and $service -and $service.Status -eq "Running") {
      $state = Get-Content -Raw (Join-Path $StateDir "state.json") | ConvertFrom-Json
      $versionOutput = (& $Binary version 2>$null) -join "`n"
      if ($state.last_update_status -eq "healthy" -and $versionOutput -match "secweaver-agent 0\.3\.1") {
        Write-Host "PASS: Windows SCM activated N and confirmed service health"
        $Healthy = $true
        break
      }
    }
    Start-Sleep -Seconds 1
  }
  if (-not $Healthy) {
    & sc.exe query $ServiceName
    if (Test-Path (Join-Path $StateDir "state.json")) {
      Get-Content -Raw (Join-Path $StateDir "state.json") | Write-Host
    }
    throw "Windows SCM service did not complete the healthy upgrade"
  }

  Write-SignedManifest -Version "0.3.2" -TargetName $FailedTargetName
  Restart-Service -Name $ServiceName -Force

  $Deadline = [DateTime]::UtcNow.AddMinutes(3)
  while ([DateTime]::UtcNow -lt $Deadline) {
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ((Test-Path (Join-Path $StateDir "state.json")) -and $service -and $service.Status -eq "Running") {
      $state = Get-Content -Raw (Join-Path $StateDir "state.json") | ConvertFrom-Json
      $versionOutput = (& $Binary version 2>$null) -join "`n"
      if ($state.last_update_status -in @("rolled_back", "rollback_scheduled") -and $versionOutput -match "secweaver-agent 0\.3\.1") {
        Stop-Service -Name $ServiceName -Force
        Write-Host "PASS: Windows SCM restored N after N+1 failed its health check"
        exit 0
      }
    }
    Start-Sleep -Seconds 1
  }
  & sc.exe query $ServiceName
  if (Test-Path (Join-Path $StateDir "state.json")) {
    Get-Content -Raw (Join-Path $StateDir "state.json") | Write-Host
  }
  throw "Windows SCM service did not complete automatic rollback"
} finally {
  Remove-TestService
  if ($env:KEEP_INTEGRATION_ARTIFACTS -ne "1") {
    Remove-Item -Recurse -Force $Root -ErrorAction SilentlyContinue
  } else {
    Write-Host "kept integration artifacts: $Root"
  }
}

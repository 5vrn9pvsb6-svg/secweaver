# Shared installer operations are dot-sourced without side effects so regression
# fixtures can exercise failure paths without touching SCM, audit policy or SLS.
function Write-InstallResult([ValidateSet('OK','INFO','WARN','ERROR')][string]$Level, [string]$Stage, [string]$Message) {
  # Use PowerShell's host coloring, not ANSI escapes that pollute redirected logs.
  $Color = switch ($Level) { 'OK' {'Green'} 'INFO' {'Cyan'} 'WARN' {'Yellow'} 'ERROR' {'Red'} }
  Write-Host "[$Level] ${Stage}: $Message" -ForegroundColor $Color
}

function Get-WindowsLearningOwner($Config) {
  # The shared event reader owns evidence when enabled. Never activate a second
  # reader during policy migration; it would duplicate logs and race on cursors.
  foreach ($Name in @('windows-eventlog-risk-json','windows-process-execmon')) {
    $Module = $Config.modules.$Name
    if ($Module -and $Module.enabled -ne $false) { return $Module }
  }
  return $null
}

function Get-WindowsBooleanFlag([string[]]$Arguments, [string]$Name) {
  # Go's bool flags accept a bare switch or an =value suffix. Last occurrence
  # wins. Invalid spelling must not silently turn a user choice into a default.
  $Value = $false
  foreach ($Arg in $Arguments) {
    if ($Arg -ceq "-$Name" -or $Arg -ceq "--$Name") { $Value = $true }
    elseif ($Arg.StartsWith("-$Name=", [StringComparison]::Ordinal) -or $Arg.StartsWith("--$Name=", [StringComparison]::Ordinal)) {
      $Literal = $Arg.Substring($Arg.IndexOf('=')+1)
      switch -CaseSensitive ($Literal) {
        {$_ -cin @('1','t','T','TRUE','true','True')} { $Value=$true }
        {$_ -cin @('0','f','F','FALSE','false','False')} { $Value=$false }
        default { throw "Invalid $Name boolean flag" }
      }
    }
  }
  return $Value
}

function Set-WindowsLearningMode([string]$ConfigPath, [ValidateSet('preserve','enable','shadow','disable')][string]$Mode) {
  # Explicit choices apply only to the current reader. Preserve never rewrites
  # an existing false flag or resets a learned baseline/generation. Enrollment
  # and Sysmon prerequisites are diagnosed separately, never assumed here.
  if ($Mode -eq 'preserve') { return }
  $Config = Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
  $Module = Get-WindowsLearningOwner $Config
  if (-not $Module) { throw 'No enabled Windows event reader for LearningMode' }
  $Module.args = @($Module.args | Where-Object { $_ -cnotmatch '^--?(behavior-learning|learning-shadow)(=|$)' })
  $Module.args += @('-behavior-learning=' + $(if ($Mode -eq 'disable') {'false'} else {'true'}))
  $Module.args += @('-learning-shadow=' + $(if ($Mode -eq 'shadow') {'true'} else {'false'}))
  [IO.File]::WriteAllText($ConfigPath, ($Config | ConvertTo-Json -Depth 100), (New-Object Text.UTF8Encoding($false)))
}

function Write-WindowsLearningSummary([string]$ConfigPath, [string[]]$PreflightLines = @()) {
  $Config = Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
  $Module = Get-WindowsLearningOwner $Config
  if (-not $Module) { return }
  if (-not (Get-WindowsBooleanFlag $Module.args 'behavior-learning')) {
    Write-InstallResult 'WARN' 'learning' 'Disabled in existing configuration; use -LearningMode shadow or enable for an explicit migration'
    return
  }
  $Shadow = Get-WindowsBooleanFlag $Module.args 'learning-shadow'
  Write-InstallResult 'OK' 'learning-policy' "Enabled; shadow=$Shadow; existing duration, scope and baseline are preserved"
  # Reuse the completed preflight probe, not another expensive Event Log query.
  # An accessible channel proves neither eligible events nor a learned baseline;
  # absent/unknown evidence must never be reported as active suppression.
  $Channel = 'windows-channel/Microsoft-Windows-Sysmon/Operational:'
  if (@($PreflightLines | Where-Object { ([string]$_).StartsWith('[OK] ' + $Channel) }).Count) {
    Write-InstallResult 'INFO' 'learning-readiness' 'Sysmon channel available; baseline filtering still requires registered identity, eligible GUID/SHA256 context and a completed baseline. Security 4688, risk events and incomplete context retain originals.'
  } elseif (@($PreflightLines | Where-Object { $_ -match '^\[(WARN|ERROR)\] windows-channel/Microsoft-Windows-Sysmon/Operational:' }).Count) {
    Write-InstallResult 'WARN' 'learning-readiness' 'Sysmon is missing or its channel is inaccessible: Sysmon-based whitelist reduction is unavailable. Security 4688 process events and risk events remain full-output; collection continues.'
  } else {
    Write-InstallResult 'WARN' 'learning-readiness' 'Sysmon capability was not verified; run doctor. Without eligible GUID/SHA256 context, events retain originals; enabled policy alone does not prove whitelist reduction.'
  }
}

function Protect-InstallerMessage([string]$Message, [string]$Token = '') {
  if ($Token) { $Message = $Message.Replace($Token, '[REDACTED]') }
  $Message = $Message -replace 'swenr_[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', '[REDACTED]'
  $Message = $Message -replace '(https?://)[^/@\s]+@', '$1'
  $Message = $Message -replace '(https?://[^\s?]+)\?[^\s]+', '$1?[REDACTED]'
  if ($Message.Length -gt 8192) { $Message = $Message.Substring(0, 8192) }
  return $Message
}

function New-AgentInstallSnapshot([string]$Name, [string[]]$Paths, [string]$BackupRoot) {
  # The installer mutex owns this transaction. Backup only files this installer
  # edits; never rewind device keys, registration, cursors, evidence or shared Logtail.
  $Snapshot = @{Name=$Name; Files=@(); Service=$null; Running=$false; Directory=''}
  $Service = Get-Service -Name $Name -ErrorAction SilentlyContinue
  if ($Service) {
    $Scm = Get-CimInstance Win32_Service -Filter "Name='$Name'" -ErrorAction Stop
    if (-not $Scm -or -not $Scm.PathName) { throw 'Cannot snapshot existing SCM configuration; installation aborted.' }
    $Start = switch ($Scm.StartMode) { 'Auto' {'auto'} 'Manual' {'demand'} 'Disabled' {'disabled'} default { throw 'Unsupported existing SCM start mode.' } }
    $Registry = Get-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\$Name" -ErrorAction Stop
    if ($Start -eq 'auto' -and $Registry.DelayedAutoStart -eq 1) { $Start = 'delayed-auto' }
    $Snapshot.Service = @{Path=$Scm.PathName; Start=$Start}
    $Snapshot.Running = $Service.Status -eq 'Running'
  }
  $Snapshot.Directory = Join-Path $BackupRoot ('install-rollback-' + [Guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Path $Snapshot.Directory -ErrorAction Stop | Out-Null
  foreach ($Path in @($Paths | Select-Object -Unique)) {
    $Backup = Join-Path $Snapshot.Directory ([string]$Snapshot.Files.Count)
    $Exists = Test-Path -LiteralPath $Path -PathType Leaf
    if ($Exists) { Copy-Item -LiteralPath $Path -Destination $Backup -ErrorAction Stop }
    $Snapshot.Files += @{Path=$Path; Backup=$Backup; Existed=$Exists}
  }
  return $Snapshot
}

function Restore-AgentInstallSnapshot($Snapshot) {
  # Disable starts before replacing files, then restore exactly the previous
  # command/start mode. Recovery policy is not changed until readiness succeeds.
  $Service = Get-Service -Name $Snapshot.Name -ErrorAction SilentlyContinue
  if ($Service) {
    & sc.exe config $Snapshot.Name start= disabled | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot disable the failed service for rollback.' }
    if ($Service.Status -ne 'Stopped') {
      Stop-Service -Name $Snapshot.Name -Force -ErrorAction Stop
      $Service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    }
  }
  foreach ($File in $Snapshot.Files) {
    if ($File.Existed) { Copy-Item -LiteralPath $File.Backup -Destination $File.Path -Force -ErrorAction Stop }
    elseif (Test-Path -LiteralPath $File.Path) { Remove-Item -LiteralPath $File.Path -Force -ErrorAction Stop }
  }
  if ($Snapshot.Service) {
    & sc.exe config $Snapshot.Name binPath= $Snapshot.Service.Path start= $Snapshot.Service.Start | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot restore the previous SCM configuration.' }
    if ($Snapshot.Running) {
      Start-Service -Name $Snapshot.Name -ErrorAction Stop
      Wait-ServiceRunning $Snapshot.Name
    }
  } elseif ($Service) {
    & sc.exe delete $Snapshot.Name | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot remove the newly created failed service.' }
  }
}

function Get-AgentStartupFailure([string]$Name, [string]$ConfigPath, [DateTime]$Since) {
  # Bound diagnostics and select only this service's SCM events. SCM numeric
  # codes work across Windows locales; private Agent detail complements them.
  $Details = @("service=$Name")
  try {
    $Scm = Get-CimInstance Win32_Service -Filter "Name='$Name'" -ErrorAction Stop
    if ($Scm) { $Details += "SCM state=$($Scm.State) exit_code=$($Scm.ExitCode) service_exit_code=$($Scm.ServiceSpecificExitCode)" }
  } catch { $Details += 'SCM status unavailable' }
  try {
    $Events = Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Service Control Manager'; StartTime=$Since} -MaxEvents 32 -ErrorAction Stop
    $Events | Where-Object { $_.Message -match [regex]::Escape($Name) } | Select-Object -First 3 | ForEach-Object {
      $Details += "SCM event=$($_.Id): $($_.Message)"
    }
  } catch { }
  $DetailPath = "$ConfigPath.service-error.txt"
  if (Test-Path -LiteralPath $DetailPath -PathType Leaf) {
    # Only a current failure may advertise its detail file. Stale error files
    # from an older run must not make a later installation look unsuccessful.
    $DetailFile = Get-Item -LiteralPath $DetailPath
    if ($DetailFile.Length -le 16384 -and $DetailFile.LastWriteTimeUtc -ge $Since.ToUniversalTime()) {
      $Details += "Startup failure detail: $DetailPath"
      $Details += Get-Content -Raw -LiteralPath $DetailPath
    }
  }
  return Protect-InstallerMessage ($Details -join "`n")
}

function Confirm-WindowsUpdateConfiguration([string]$ConfigPath, [bool]$ExpectedEnabled) {
  # Validate what SCM will actually read, not just the set-update command exit.
  # Generic packages deliberately remain offline-capable until a real manifest
  # is supplied; an upgrade without this option preserves the previous choice.
  $Config = Get-Content -Raw -LiteralPath $ConfigPath | ConvertFrom-Json
  if ($ExpectedEnabled -and ($Config.update.enabled -ne $true -or $Config.update.auto_install -ne $true)) {
    throw 'stage=configure-updates: managed installation expected update.enabled=true and auto_install=true; inspect the persisted configuration.'
  }
  if ($Config.update.enabled) {
    Write-InstallResult 'INFO' 'updates' "Enabled; interval=$($Config.update.interval_seconds)s; server_policy=$($Config.update.require_server_policy); staged/gray rollout remains server-controlled."
    if ($Config.update.auto_install) {
      # This describes a future update lifecycle, not a pending restart detected
      # on this host. Actual update failures remain reported by runtime/doctor.
      Write-InstallResult 'INFO' 'update/windows' 'Future automatic updates replace files after Agent exit and use service restart to activate. This notice does not mean an update failed or a restart is pending now.'
    }
  } else {
    Write-InstallResult 'INFO' 'updates' 'Disabled in the current configuration. Generic templates default to disabled; supply UpdateManifestUrl to enable managed updates.'
  }
}

function ConvertFrom-InstallerIdentity($Output, [string]$RequestedDeviceId) {
  $Text = (@($Output) -join "`n").TrimEnd("`r", "`n")
  if ($Text -cnotmatch '^([A-Z0-9]{16})\t(swd_[a-z2-7]{52})$') {
    throw "Enrollment returned an invalid installer identity."
  }
  $Identity = @{ EnterpriseId = $Matches[1]; DeviceId = $Matches[2] }
  if ($RequestedDeviceId -and $RequestedDeviceId -cne $Identity.DeviceId) {
    throw "UpdateDeviceId does not match the enrolled device identity."
  }
  return $Identity
}

function Update-WindowsLayout([string]$Path, [string]$Root, [string]$Bin, [string]$Etc) {
  # Rewrite only product-owned default paths, including flags nested in arrays.
  # Custom inputs outside the default root survive upgrades. Explicit UTF-8
  # without BOM is required by the Go JSON decoder on Windows PowerShell 5.1.
  $Prefixes = [ordered]@{
    'C:\ProgramData\SecWeaver\Agent\bin' = $Bin
    'C:\ProgramData\SecWeaver\Agent\etc' = $Etc
    'C:\ProgramData\SecWeaver\Agent' = $Root
  }
  function Convert-LayoutValue($Value) {
    if ($Value -is [string]) {
      foreach ($Old in $Prefixes.Keys) {
        if ($Value.Equals($Old, [StringComparison]::OrdinalIgnoreCase)) { return $Prefixes[$Old] }
        if ($Value.StartsWith($Old + '\', [StringComparison]::OrdinalIgnoreCase)) {
          return $Prefixes[$Old].TrimEnd('\') + $Value.Substring($Old.Length)
        }
      }
      return $Value
    }
    if ($Value -is [System.Management.Automation.PSCustomObject]) {
      foreach ($Property in $Value.PSObject.Properties) { $Property.Value = Convert-LayoutValue $Property.Value }
    } elseif ($Value -is [array]) {
      # Unary comma preserves empty and one-item arrays through the PS pipeline.
      return ,@($Value | ForEach-Object { Convert-LayoutValue $_ })
    }
    return $Value
  }
  $Config = Convert-LayoutValue (Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json)
  # Event readers otherwise keep a compiled C:\ProgramData cursor default even
  # when every explicit output path has moved. Preserve intentional overrides.
  foreach ($Name in @('windows-eventlog-risk-json', 'windows-process-execmon')) {
    $Module = $Config.modules.$Name
    if ($Module -and -not @($Module.args | Where-Object { $_ -match '^--?state-file(=|$)' }).Count) {
      $Module.args = @($Module.args) + @('-state-file', ($Root.TrimEnd('\') + '\data\' + $Name + '.cursor.json'))
    }
  }
  [IO.File]::WriteAllText($Path, ($Config | ConvertTo-Json -Depth 100), (New-Object Text.UTF8Encoding($false)))
}

function Get-AgentArchitecture {
  # Windows PowerShell 5.1 can resolve RuntimeInformation without a usable
  # OSArchitecture property. Native Windows variables avoid that .NET dependency.
  # WOW64 must take precedence: the current shell can be x86 on x64/ARM64.
  # Keep this standalone Bootstrap copy identical to windows-install-common.ps1;
  # the regression suite checks both because no package exists at this stage.
  $architecture = [string]$env:PROCESSOR_ARCHITEW6432
  if ([string]::IsNullOrWhiteSpace($architecture)) {
    $architecture = [string]$env:PROCESSOR_ARCHITECTURE
  }
  switch ($architecture.Trim().ToUpperInvariant()) {
    'AMD64' { return 'amd64' }
    'ARM64' { return 'arm64' }
    default {
      throw 'stage=platform check=os-architecture: missing or unsupported Windows architecture; Windows x64 or ARM64 is required. Check PROCESSOR_ARCHITECTURE and PROCESSOR_ARCHITEW6432 in this PowerShell session.'
    }
  }
}

function Assert-LogtailParameters([string]$AliUid, [string]$MachineGroup, [string]$Region, [string]$Url, [string]$Sha256) {
  if ((Get-AgentArchitecture) -ne 'amd64') {
    throw "Managed Windows Logtail supports amd64 only; use -SkipLogtail with a separately verified shipper."
  }
  if ($AliUid -notmatch '^[0-9]{6,32}$' -or $MachineGroup -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._:-]{1,127}$') {
    throw "LogtailAliUid and a Windows-only LogtailMachineGroup are required; -SkipLogtail is for external delivery."
  }
  if ($Region -cnotmatch '^[a-z0-9][a-z0-9-]{1,31}$' -or $Sha256 -notmatch '^[a-fA-F0-9]{64}$') {
    throw "Invalid Logtail region or pinned package SHA-256."
  }
  $Parsed = $null
  if (-not [Uri]::TryCreate($Url, [UriKind]::Absolute, [ref]$Parsed) -or $Parsed.Scheme -ne 'https' -or $Parsed.UserInfo -or $Parsed.Fragment) {
    throw "LogtailPackageUrl must use HTTPS without embedded credentials or a fragment."
  }
}

function Wait-ServiceRunning([string]$Name) {
  # Start-Service may return at RUNNING immediately before a startup failure.
  # Require ten consecutive running observations; never accept a recovery loop.
  for ($i = 0; $i -lt 10; $i++) {
    $Service = Get-Service -Name $Name -ErrorAction Stop
    if ($Service.Status -ne 'Running') { throw "$Name is $($Service.Status), expected Running." }
    Start-Sleep -Seconds 1
  }
}

function Wait-AgentReady([string]$Name, [string]$ConfigPath, [DateTime]$StartedAt) {
  # Bound startup and require a fresh status from this start, authorized modules
  # and no error diagnostics. A previous run's status must not pass acceptance.
  $Config = Get-Content -Raw -LiteralPath $ConfigPath | ConvertFrom-Json
  $StatusPath = $Config.status_path
  $Deadline = [DateTime]::UtcNow.AddSeconds(90)
  $Stable = 0
  do {
    $Service = Get-Service -Name $Name -ErrorAction Stop
    if ($Service.Status -ne 'Running') {
      throw "$Name is $($Service.Status). Inspect $ConfigPath.service-error.txt and run the Agent doctor command."
    }
    $Ready = $false
    if (Test-Path -LiteralPath $StatusPath) {
      try {
        $Status = Get-Content -Raw -LiteralPath $StatusPath | ConvertFrom-Json
        # PS 7 may decode ISO timestamps as DateTime; PS 5.1 leaves strings.
        # Preserve Kind instead of formatting UTC back through local culture.
        $StatusTime = if ($Status.time -is [DateTime]) { $Status.time } else {
          [DateTime]::Parse($Status.time, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind)
        }
        $Ready = ($StatusTime.ToUniversalTime() -ge $StartedAt.AddSeconds(-1))
        foreach ($Module in $Config.modules.PSObject.Properties) {
          if ($Module.Value.enabled -ne $false) {
            $Health = $Status.modules.($Module.Name)
            if (-not $Health -or $Health.status -ne 'running' -or $Health.pid -le 0 -or $Health.last_error) { $Ready = $false }
          }
        }
        if ($Config.license.enabled -and (-not $Status.license.last_check_at -or $Status.license.last_error)) { $Ready = $false }
        if ($Status.persistence.last_error) { $Ready = $false }
        foreach ($Diagnostic in $Status.diagnostics.PSObject.Properties) {
          if ($Diagnostic.Value.level -eq 'error') { $Ready = $false }
        }
      } catch { $Ready = $false }
    }
    if ($Ready) { $Stable++ } else { $Stable = 0 }
    if ($Stable -ge 10) { return }
    Start-Sleep -Seconds 1
  } while ([DateTime]::UtcNow -lt $Deadline)
  throw "Agent readiness timed out; inspect $StatusPath and $ConfigPath.service-error.txt. Cloud delivery is unverified."
}

function Install-WindowsLogtail([string]$AliUid, [string]$MachineGroup, [string]$Region, [string]$Url, [string]$Sha256, [switch]$NoStart) {
  # Logtail is host-wide: serialize our installers and preserve existing account
  # and group entries. Do not overwrite/reinstall a collector used by other apps.
  $Mutex = New-Object Threading.Mutex($false, 'Global\SecWeaverLogtailInstall')
  $Acquired = $false
  $Temp = $null
  try {
    try { $Acquired = $Mutex.WaitOne([TimeSpan]::FromSeconds(120)) }
    catch [Threading.AbandonedMutexException] { $Acquired = $true }
    if (-not $Acquired) { throw 'Timed out waiting for the Windows Logtail installer lock.' }
    $Service = Get-Service -Name LogtailDaemon -ErrorAction SilentlyContinue
    if (-not $Service) {
      if (Get-Service -Name LogtailWorker -ErrorAction SilentlyContinue) {
        throw 'Legacy LogtailWorker exists; upgrade it explicitly before managed installation.'
      }
      $Temp = Join-Path ([IO.Path]::GetTempPath()) ('secweaver-logtail-' + [Guid]::NewGuid().ToString('N'))
      New-Item -ItemType Directory -Path $Temp | Out-Null
      $Zip = Join-Path $Temp 'logtail.zip'
      [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
      Invoke-WebRequest -UseBasicParsing -Uri $Url -OutFile $Zip -TimeoutSec 120 -MaximumRedirection 0
      if ((Get-FileHash -LiteralPath $Zip -Algorithm SHA256).Hash -ine $Sha256) { throw 'Windows Logtail package SHA-256 mismatch.' }
      Expand-Archive -LiteralPath $Zip -DestinationPath $Temp
      $Installer = Join-Path $Temp 'logtail_installer.exe'
      if (-not (Test-Path -LiteralPath $Installer -PathType Leaf)) { throw 'Missing logtail_installer.exe in verified package.' }
      # The official pinned package includes binaries and region config. Its
      # relative file lookups require the extraction directory as the cwd.
      $Process = Start-Process -FilePath $Installer -ArgumentList @('install', $Region) -WorkingDirectory $Temp -PassThru
      if (-not $Process.WaitForExit(600000)) {
        & taskkill.exe /PID $Process.Id /T /F | Out-Null
        throw 'Windows Logtail installation exceeded 600 seconds; inspect LogtailDaemon before retry.'
      }
      if ($Process.ExitCode -ne 0) { throw "Windows Logtail installer failed: $($Process.ExitCode)" }
      $Service = Get-Service -Name LogtailDaemon -ErrorAction Stop
    }
    # The vendor owns C:\LogtailData even when the Agent uses a custom root.
    # ASCII identity files avoid UTF-16/BOM corruption on PowerShell 5.1.
    $Data = 'C:\LogtailData'
    $Users = Join-Path $Data 'users'
    New-Item -ItemType Directory -Force $Users | Out-Null
    $Account = Join-Path $Users $AliUid
    if (-not (Test-Path -LiteralPath $Account)) { [IO.File]::WriteAllText($Account, '') }
    $GroupFile = Join-Path $Data 'user_defined_id'
    $Groups = @()
    if (Test-Path -LiteralPath $GroupFile) { $Groups = @(Get-Content -LiteralPath $GroupFile | Where-Object { $_.Trim() }) }
    if ($Groups -notcontains $MachineGroup) { $Groups += $MachineGroup }
    [IO.File]::WriteAllLines($GroupFile, [string[]]$Groups, [Text.Encoding]::ASCII)
    Set-Service -Name LogtailDaemon -StartupType Automatic
    # Vendor install starts its own service. NoStart must also stop that service;
    # otherwise installation would collect even when the caller requested staging.
    if ($Service.Status -ne 'Stopped') {
      Stop-Service -Name LogtailDaemon -Force
      $Service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    }
    if (-not $NoStart) {
      Start-Service -Name LogtailDaemon
      Wait-ServiceRunning 'LogtailDaemon'
      if (-not (Get-Process -Name ilogtail_worker -ErrorAction SilentlyContinue)) { throw 'Logtail service is running but its collection worker is missing.' }
    }
  } finally {
    if ($Temp -and (Test-Path -LiteralPath $Temp)) { Remove-Item -LiteralPath $Temp -Recurse -Force -ErrorAction SilentlyContinue }
    if ($Acquired) { $Mutex.ReleaseMutex() }
    $Mutex.Dispose()
  }
}

function Wait-WindowsLogtailCollection([string]$Binary, [string]$Manifest, [string]$PublicKey, [int]$TimeoutSeconds = 120) {
  # Resolve the active worker's directory rather than accepting a stale cache
  # from another installation. Go owns bounded JSON parsing/signature and route
  # validation, shared with doctor. Never modify the vendor's cloud-owned cache.
  $Deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
  $Detail = 'waiting for Logtail worker/config'
  do {
    $Workers = @(Get-CimInstance Win32_Process -Filter "Name='ilogtail_worker.exe'" -OperationTimeoutSec 5 -ErrorAction Stop)
    if ($Workers.Count -eq 1 -and $Workers[0].ExecutablePath) {
      $Candidate = Join-Path (Split-Path -Parent $Workers[0].ExecutablePath) 'user_log_config.json'
      $Detail = (& $Binary logtail-check -manifest $Manifest -public-key $PublicKey -cache $Candidate) -join "`n"
      if ($LASTEXITCODE -eq 0) { return $Candidate }
    }
    if ([DateTime]::UtcNow -ge $Deadline) { break }
    Start-Sleep -Seconds 5
  } while ($true)
  throw "stage=logtail-collection: $Detail. Bind the signed Windows collection plan to its SLS machine group; verify regional connectivity and retry. Cloud delivery is unverified."
}

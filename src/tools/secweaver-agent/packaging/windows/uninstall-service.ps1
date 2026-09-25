[CmdletBinding()]
param(
  [string]$InstallRoot = '',
  [ValidatePattern('^[A-Za-z0-9_.-]{1,128}$')]
  [string]$ServiceName = 'SecWeaverAgent',
  [switch]$RemoveFiles,
  [switch]$RemoveConfig,
  [switch]$Purge,
  [switch]$KeepLogtail,
  [switch]$Json
)

$ErrorActionPreference = 'Stop'

function Get-UninstallRoot([string]$Path) {
  # Resolve locally, never allow a drive root or a shared OS/product parent.
  # Purge deletes this entire tree; containment checks precede service mutation.
  if ($Path -notmatch '^[A-Za-z]:[\\/]') { throw 'InstallRoot must be an absolute local Windows path.' }
  $Full = [IO.Path]::GetFullPath($Path).TrimEnd('\','/')
  foreach ($Protected in @([IO.Path]::GetPathRoot($Full), $env:SystemRoot, $env:ProgramData, $env:ProgramFiles, ${env:ProgramFiles(x86)}, (Join-Path $env:ProgramData 'SecWeaver'))) {
    if (-not $Protected) { continue }
    $Protected = $Protected.TrimEnd('\','/')
    if ($Full.Equals($Protected, [StringComparison]::OrdinalIgnoreCase) -or $Protected.StartsWith($Full+'\', [StringComparison]::OrdinalIgnoreCase)) {
      throw 'Refusing to remove a system directory or shared parent.'
    }
  }
  return $Full
}

function Assert-UninstallTree([string]$Path) {
  # Windows PowerShell 5.1 recursion may follow junctions. Walk one level at a
  # time and reject reparse points, including ancestors, before deleting anything.
  $Parent = $Path
  while ($Parent) {
    if (Test-Path -LiteralPath $Parent) {
      if ((Get-Item -LiteralPath $Parent -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Reparse point requires manual review: $Parent" }
    }
    $Parent = Split-Path -Parent $Parent
  }
  if (-not (Test-Path -LiteralPath $Path)) { return }
  $Pending = New-Object 'Collections.Generic.Stack[string]'
  $Pending.Push($Path)
  while ($Pending.Count) {
    foreach ($Item in Get-ChildItem -LiteralPath $Pending.Pop() -Force) {
      if ($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Reparse point requires manual review: $($Item.FullName)" }
      if ($Item.PSIsContainer) { $Pending.Push($Item.FullName) }
    }
  }
}

function Get-UninstallService([string]$Name) {
  # Names come from a validated parameter or fixed Logtail names, not config SQL.
  return Get-CimInstance Win32_Service -Filter "Name='$Name'" -OperationTimeoutSec 5 -ErrorAction Stop
}

function Get-LogtailUninstallLayout {
  # Fixed vendor directories only; never derive deletion targets from a cloud
  # rule, user-defined group identifier, or an arbitrary service command line.
  $Roots = @((Join-Path $env:ProgramFiles 'Alibaba\Logtail'))
  if (${env:ProgramFiles(x86)}) { $Roots += (Join-Path ${env:ProgramFiles(x86)} 'Alibaba\Logtail') }
  return @{Roots=$Roots;Data='C:\LogtailData'}
}

function Assert-ServiceExecutable($Service, [string[]]$Allowed) {
  if (-not $Service) { return }
  $Command = [string]$Service.PathName
  $Match = [regex]::Match($Command, '^\s*(?:"([^"\r\n]+)"|(.+?\.exe))(?=\s|$)', 'IgnoreCase')
  if (-not $Match.Success) { throw "Unrecognized executable for service $($Service.Name)" }
  $Exe = if ($Match.Groups[1].Success) { $Match.Groups[1].Value } else { $Match.Groups[2].Value }
  if ($Allowed -notcontains $Exe) { throw "Service $($Service.Name) uses a different installation path; no files were removed." }
}

function Remove-UninstallService([string]$Name) {
  if (-not (Get-UninstallService $Name)) { return }
  # Disable future starts before stopping. Dispose the SCM handle before delete,
  # otherwise our own handle can leave the service marked-for-deletion forever.
  Set-Service -Name $Name -StartupType Disabled
  $Service = Get-Service -Name $Name -ErrorAction Stop
  try {
    if ($Service.Status -ne 'Stopped') { Stop-Service -Name $Name -Force; $Service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30)) }
  } finally { $Service.Dispose() }
  & sc.exe delete $Name | Out-Null
  if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 1060) { throw "SCM delete failed for $Name (exit $LASTEXITCODE)." }
  $Deadline = [DateTime]::UtcNow.AddSeconds(30)
  while (Get-UninstallService $Name) {
    if ([DateTime]::UtcNow -ge $Deadline) { throw "Service deletion pending: $Name. Close Services/SCM tools and retry." }
    Start-Sleep -Milliseconds 250
  }
}

function Stop-UninstallProcesses([string[]]$Executables) {
  # Kill only exact, prevalidated executable paths. Keep a Process handle and
  # verify creation time so a recycled PID cannot target an unrelated process.
  foreach ($Item in @(Get-CimInstance Win32_Process -Filter "Name='secweaver-agent.exe' OR Name='ilogtail_worker.exe' OR Name='logtail_daemon.exe'" -OperationTimeoutSec 5)) {
    if ($Executables -notcontains $Item.ExecutablePath) { continue }
    $Process = Get-Process -Id $Item.ProcessId -ErrorAction SilentlyContinue
    if (-not $Process) { continue }
    try {
      if ([math]::Abs(($Process.StartTime.ToUniversalTime() - $Item.CreationDate.ToUniversalTime()).TotalSeconds) -gt 0.01) { throw 'Process identity changed; retry uninstall.' }
      if ($Executables -notcontains $Process.MainModule.FileName) { throw 'Process executable changed; retry uninstall.' }
      $Process.Kill()
      if (-not $Process.WaitForExit(10000)) { throw "Process did not exit: $($Item.ProcessId)" }
    } finally { $Process.Dispose() }
  }
}

function Invoke-AgentUninstall {
  $Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  if (-not (New-Object Security.Principal.WindowsPrincipal($Identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run uninstall from an administrator terminal.' }
  $Root = $InstallRoot
  $Layout = $null
  $LayoutPath = Join-Path $PSScriptRoot 'uninstall-layout.json'
  if (Test-Path -LiteralPath $LayoutPath) {
    if ((Get-Item -LiteralPath $LayoutPath).Length -gt 65536) { throw 'Invalid uninstall layout.' }
    $Layout = Get-Content -LiteralPath $LayoutPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($Root -and ((Get-UninstallRoot $Root) -ine (Get-UninstallRoot $Layout.install_root))) { throw 'InstallRoot does not match this installed uninstall entry.' }
    if (-not $Root) { $Root = [string]$Layout.install_root }
    if (-not $script:PSBoundParameters.ContainsKey('ServiceName')) { $ServiceName = [string]$Layout.service_name }
    if ($ServiceName -notmatch '^[A-Za-z0-9_.-]{1,128}$') { throw 'Invalid installed service name.' }
    if (($Purge -or $RemoveFiles -or $RemoveConfig) -and (($Layout.install_dir -ine (Join-Path $Root 'bin')) -or ($Layout.config_dir -ine (Join-Path $Root 'etc')))) { throw 'External InstallDir/ConfigDir requires explicit operator cleanup; uninstall without removal flags first.' }
  }
  if (-not $Root) {
    $Root = if ((Split-Path -Leaf $PSScriptRoot) -eq 'bin') { Split-Path -Parent $PSScriptRoot } else { Join-Path $env:ProgramData 'SecWeaver\Agent' }
  }
  $Root = Get-UninstallRoot $Root
  $DeleteRoot = $Purge -or $RemoveConfig
  $DeleteLogtail = $Purge -and -not $KeepLogtail
  $AgentExe = Join-Path $Root 'bin\secweaver-agent.exe'
  if ($Layout) { $AgentExe = Join-Path $Layout.install_dir 'secweaver-agent.exe' }
  $Executables = @($AgentExe)
  $Services = @($ServiceName)
  $Paths = @()
  if ($DeleteRoot) { $Paths += $Root }
  elseif ($RemoveFiles) { $Paths += (Join-Path $Root 'bin') }
  if ($DeleteLogtail) {
    # Explicit Purge includes the host-wide collector, not merely one group ID.
    # Only standard vendor layouts are supported; custom services fail preflight.
    $LogtailLayout = Get-LogtailUninstallLayout
    $LogtailRoots = $LogtailLayout.Roots
    foreach ($Path in $LogtailRoots) {
      $Executables += (Join-Path $Path 'logtail_daemon.exe'), (Join-Path $Path 'ilogtail_worker.exe')
    }
    $Services += 'LogtailDaemon','LogtailWorker'
    $Paths += $LogtailRoots + @($LogtailLayout.Data)
  }
  $Locks = @()
  try {
    # Match installer lock order: Agent, then Logtail. Abandoned ownership means
    # the prior process exited; all file/service checks still run from scratch.
    $Names = @('Global\SecWeaverAgentInstall')
    if ($DeleteLogtail) { $Names += 'Global\SecWeaverLogtailInstall' }
    foreach ($Name in $Names) {
      $Mutex = New-Object Threading.Mutex($false, $Name)
      $Locked = $false
      try { $Locked = $Mutex.WaitOne([TimeSpan]::FromSeconds(30)) } catch [Threading.AbandonedMutexException] { $Locked = $true }
      if (-not $Locked) { $Mutex.Dispose(); throw 'Another install/uninstall is active; retry later.' }
      $Locks += $Mutex
    }
    Assert-ServiceExecutable (Get-UninstallService $ServiceName) @($AgentExe)
    foreach ($Name in @($Services | Where-Object { $_ -ne $ServiceName })) {
      Assert-ServiceExecutable (Get-UninstallService $Name) @($Executables | Where-Object { $_ -ne $AgentExe })
    }
    # Missing installations are idempotent; an existing unrelated directory is
    # never accepted as an Agent root merely because a caller supplied its path.
    if ((Test-Path -LiteralPath $Root) -and -not (Test-Path -LiteralPath $AgentExe) -and -not (Test-Path -LiteralPath (Join-Path $Root 'etc\config.json'))) { throw 'InstallRoot has no Agent binary/config; inspect the directory before removal.' }
    foreach ($Path in $Paths) { Assert-UninstallTree $Path }
    foreach ($Name in $Services) { Remove-UninstallService $Name }
    Stop-UninstallProcesses $Executables
    foreach ($Path in $Paths) {
      if (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Recurse -Force }
    }
    foreach ($Name in $Services) { if (Get-UninstallService $Name) { throw "Service remains: $Name" } }
    foreach ($Path in $Paths) { if (Test-Path -LiteralPath $Path) { throw "Directory remains: $Path" } }
    return @{ok=$true;purge=[bool]$Purge;logtail_removed=[bool]$DeleteLogtail;removed_services=$Services;removed_paths=$Paths;cloud_data_removed=$false}
  } finally {
    [array]::Reverse($Locks)
    foreach ($Mutex in $Locks) { $Mutex.ReleaseMutex(); $Mutex.Dispose() }
  }
}

# Capture the whole body before execution: Purge can remove this script and its
# launcher while it is running. JSON mode writes exactly one result and exit code.
& {
  try {
    $Result = Invoke-AgentUninstall
    if ($Json) { $Result | ConvertTo-Json -Depth 5 -Compress }
    else { Write-Host '[OK] Agent uninstall verified.' -ForegroundColor Green; if ($Result.logtail_removed) { Write-Host '[OK] Logtail services, files and identities removed.' -ForegroundColor Green } }
    exit 0
  } catch {
    if ($Json) { @{ok=$false;error=$_.Exception.Message} | ConvertTo-Json -Compress }
    else { Write-Host ('[ERROR] ' + $_.Exception.Message) -ForegroundColor Red }
    exit 1
  }
}

#Requires -Version 5.1
[CmdletBinding()]
param(
  [string]$InstallRoot = "$env:ProgramData\SecWeaver\Agent",
  [string]$ConfigPath = "",
  [string]$BinaryPath = "",
  [string]$ServiceName = "SecWeaverAgent",
  [string]$ProfilePath = (Join-Path $PSScriptRoot 'saas-0.3.83.json'),
  [ValidateRange(30, 600)][int]$HealthTimeoutSeconds = 180,
  [switch]$Apply
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-Field($Object, [string]$Name, $Default = $null) {
  # Legacy configurations omit newer fields. StrictMode must not turn a missing
  # optional member into the null-method errors seen in old bootstraps.
  if ($null -ne $Object -and $null -ne $Object.PSObject.Properties[$Name]) {
    $Value = $Object.$Name
    if ($null -ne $Value -and -not ($Value -is [string] -and [string]::IsNullOrWhiteSpace($Value))) { return $Value }
  }
  return $Default
}

function Set-Field($Object, [string]$Name, $Value) {
  $Object | Add-Member -NotePropertyName $Name -NotePropertyValue $Value -Force
}

function Assert-RegularFile([string]$Path) {
  $Item = Get-Item -LiteralPath $Path
  if ($Item.PSIsContainer -or ($Item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw "Expected a non-reparse regular file: $Path" }
}

function Read-Object([string]$Path) {
  Assert-RegularFile $Path
  if ((Get-Item -LiteralPath $Path).Length -gt 4MB) { throw "JSON exceeds 4 MiB: $Path" }
  $Result = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
  if ($null -eq $Result -or $Result -isnot [PSCustomObject]) { throw "Expected JSON object: $Path" }
  return $Result
}

function New-PrivateDirectory([string]$Path) {
  # Backups contain registration credentials. Use SID-based ACLs on every locale,
  # granting only Administrators and SYSTEM, including inherited child files.
  New-Item -ItemType Directory -Path $Path -Force | Out-Null
  $Acl = New-Object Security.AccessControl.DirectorySecurity
  $Acl.SetAccessRuleProtection($true, $false)
  foreach ($Sid in @('S-1-5-32-544', 'S-1-5-18')) {
    $Identity = New-Object Security.Principal.SecurityIdentifier($Sid)
    $Rule = New-Object Security.AccessControl.FileSystemAccessRule($Identity, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    $Acl.AddAccessRule($Rule)
  }
  Set-Acl -LiteralPath $Path -AclObject $Acl
}

function Get-SHA256([string]$Path) { return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }

function Invoke-Native([string]$Program, [string[]]$Arguments, [string]$Work) {
  # Quote native argv explicitly for Windows PowerShell 5.1 and bound execution.
  # Retain failure output only in the protected work directory, never in UI JSON.
  $Quoted = @($Arguments | ForEach-Object {
    if ($_ -match '"') { throw 'Unexpected quote in native argument' }
    '"' + ($_ -replace '(\\+)$', '$1$1') + '"'
  }) -join ' '
  $Stdout = Join-Path $Work ('native-' + [Guid]::NewGuid().ToString('N') + '.out')
  $Stderr = $Stdout + '.err'
  $Process = Start-Process -FilePath $Program -ArgumentList $Quoted -PassThru -WindowStyle Hidden -RedirectStandardOutput $Stdout -RedirectStandardError $Stderr
  # PowerShell 5.1 may otherwise lose the handle/ExitCode of a short-lived
  # process returned by Start-Process. Cache it before waiting for termination.
  $null = $Process.Handle
  if (-not $Process.WaitForExit(60000)) { $Process.Kill(); throw "Native command timed out; diagnostics: $Work" }
  $Process.WaitForExit()
  if ($Process.ExitCode -ne 0) { throw "Native command failed (exit $($Process.ExitCode)); diagnostics: $Work" }
  return (Get-Content -Raw -LiteralPath $Stdout)
}

function Get-PinnedFile([string]$Url, [string]$Destination, [string]$Origin, [long]$Limit) {
  $Uri = [Uri]$Url
  if ($Uri.Scheme -ne 'https' -or $Uri.Authority -ne ([Uri]$Origin).Authority -or $Uri.UserInfo -or $Uri.Query -or $Uri.Fragment) { throw 'Recovery URL must use the trusted HTTPS origin' }
  # Keep Windows certificate validation enabled. Redirects cannot change the
  # trust origin; limit both response size and the total/read duration.
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  $Request = [Net.HttpWebRequest]::Create($Uri)
  $Request.AllowAutoRedirect = $false
  $Request.Timeout = 30000
  $Request.ReadWriteTimeout = 30000
  $Response = $Request.GetResponse()
  try {
    if ([int]$Response.StatusCode -ne 200 -or $Response.ContentLength -gt $Limit) { throw 'Expected bounded HTTP 200 response' }
    $InputStream = $Response.GetResponseStream()
    $OutputStream = [IO.File]::Create($Destination)
    try {
      $Buffer = New-Object byte[] 65536
      $Total = 0L
      $Deadline = [DateTime]::UtcNow.AddSeconds(180)
      while (($Count = $InputStream.Read($Buffer, 0, $Buffer.Length)) -gt 0) {
        $Total += $Count
        if ($Total -gt $Limit -or [DateTime]::UtcNow -gt $Deadline) { throw 'Download exceeded size/time limit' }
        $OutputStream.Write($Buffer, 0, $Count)
      }
      $OutputStream.Flush($true)
    } finally { $OutputStream.Dispose(); $InputStream.Dispose() }
  } finally { $Response.Close() }
}

function Assert-NoPendingUpdate([string]$StateDir) {
  foreach ($Name in @('update.lock', 'health.pending', 'activation.attempted')) {
    if (Test-Path -LiteralPath (Join-Path $StateDir $Name)) { throw "Existing update transaction: $Name" }
  }
  $StatePath = Join-Path $StateDir 'state.json'
  if ((Test-Path -LiteralPath $StatePath) -and (Get-Field (Read-Object $StatePath) 'health_pending' $false)) { throw 'Existing update is awaiting health confirmation' }
}

function Copy-Atomic([string]$Source, [string]$Destination) {
  # Same-directory replacement preserves the destination ACL. SCM must release
  # the executable first; no scheduled deletion or deferred destructive action.
  $Temporary = $Destination + '.recovery-' + [Guid]::NewGuid().ToString('N')
  $Previous = $Temporary + '.old'
  try {
    [IO.File]::Copy($Source, $Temporary)
    Set-Acl -LiteralPath $Temporary -AclObject (Get-Acl -LiteralPath $Destination)
    # PowerShell 5.1 marshals a null string argument as an empty path, which
    # File.Replace rejects. Use a real same-volume backup and remove on success.
    [IO.File]::Replace($Temporary, $Destination, $Previous, $true)
    Remove-Item -LiteralPath $Previous -Force
  } finally { if (Test-Path -LiteralPath $Temporary) { Remove-Item -LiteralPath $Temporary -Force } }
}

function Stop-AgentService([string]$Name) {
  Stop-Service -Name $Name -ErrorAction Stop
  (Get-Service -Name $Name).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(90))
}

function Wait-AgentHealth([string]$Path, [string]$DeviceId, [string]$Version, [DateTime]$Started, [int]$Seconds) {
  $Deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
  $StableSince = $null
  while ([DateTime]::UtcNow -lt $Deadline) {
    try {
      $Health = Read-Object $Path
      $Modules = @( (Get-Field $Health 'modules' ([PSCustomObject]@{})).PSObject.Properties )
      $Healthy = (Get-Service -Name $ServiceName).Status -eq 'Running' -and
        (Get-Item -LiteralPath $Path).LastWriteTimeUtc -ge $Started -and
        (Get-Field $Health 'device_id') -eq $DeviceId -and [version]$Health.agent_version -ge [version]$Version -and
        $Modules.Count -gt 0 -and @($Modules | Where-Object { $_.Value.status -ne 'running' }).Count -eq 0
      if ($Healthy) {
        if ($null -eq $StableSince) { $StableSince = [DateTime]::UtcNow }
        if (([DateTime]::UtcNow - $StableSince).TotalSeconds -ge 15) { return $Health.agent_version }
      } else { $StableSince = $null }
    } catch { $StableSince = $null }
    Start-Sleep -Seconds 2
  }
  throw 'No fresh matching device/version/module health before timeout'
}

# Keep precheck, commit and recovery in one owner. Only config/binary are replaced;
# live identity/learning/replay state remains owned by the existing Agent.
function Invoke-SaasMigration {
  $Principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
  if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run in Administrator PowerShell 5.1+' }
  if ($ServiceName -notmatch '^[A-Za-z0-9_.@-]+$') { throw 'Invalid service name' }
  if (-not $ConfigPath) { $ConfigPath = Join-Path $InstallRoot 'etc\config.json' }
  if (-not $BinaryPath) { $BinaryPath = Join-Path $InstallRoot 'bin\secweaver-agent.exe' }
  Assert-RegularFile $BinaryPath
  $Drive = New-Object IO.DriveInfo([IO.Path]::GetPathRoot($BinaryPath))
  if ($Drive.AvailableFreeSpace -lt 256MB) { throw 'Recovery requires at least 256 MiB free space' }
  $Profile = Read-Object $ProfilePath
  if ($Profile.schema_version -ne 1) { throw 'Unsupported recovery profile' }
  if ($Profile.version -notmatch '^\d+\.\d+\.\d+$' -or [version]$Profile.version -lt [version]'0.3.83') { throw 'Recovery target must be 0.3.83 or later; downgrade is not authorized' }
  $ScheduledUri = [Uri]$Profile.scheduled_manifest_url
  if ($ScheduledUri.Scheme -ne 'https' -or $ScheduledUri.Authority -ne ([Uri]$Profile.server_url).Authority -or $ScheduledUri.UserInfo -or $ScheduledUri.Query -or $ScheduledUri.Fragment) { throw 'Scheduled update URL must use the trusted HTTPS origin' }
  $Config = Read-Object $ConfigPath
  $OriginalConfigHash = Get-SHA256 $ConfigPath
  $OriginalBinaryHash = Get-SHA256 $BinaryPath
  if ((Get-Field $Config 'deployment_mode') -eq 'es_private' -or $Config.license.server_url.TrimEnd('/') -ne $Profile.server_url) { throw 'Not the SaaS server in the trusted profile; private ES requires its own CA' }
  $Work = Join-Path $env:TEMP ('secweaver-recovery-' + [Guid]::NewGuid().ToString('N'))
  New-PrivateDirectory $Work
  $Lock = $null
  $Succeeded = $false
  try {
    # FileShare.None serializes recovery processes; never delete the updater's
    # own lock, rollback markers or replay state to force a migration through.
    $Lock = [IO.File]::Open((Join-Path $InstallRoot 'data\.saas-recovery.lock'), 'OpenOrCreate', 'ReadWrite', 'None')
    $CurrentText = Invoke-Native $BinaryPath @('version') $Work
    if ($CurrentText -notmatch '\b(0\.3\.[0-9]+)\b') { throw 'Unrecognized installed version' }
    $Current = $Matches[1]
    if ($Current -notin @('0.3.45', '0.3.64', $Profile.version)) { throw "Unexpected installed version: $Current" }
    $StatePath = Get-Field $Config.license 'state_path' (Join-Path $InstallRoot 'data\license-state.json')
    $KeyPath = Get-Field $Config.license 'identity_key_path' (Join-Path (Split-Path $StatePath) 'device-ed25519.key')
    Assert-RegularFile $KeyPath
    $IdentityHash = Get-SHA256 $KeyPath
    $DeviceId = (Read-Object $StatePath).device_id
    if ($DeviceId -cnotmatch '^swd_[a-z2-7]{52}$') { throw 'Existing device_v2 identity is required; do not re-enroll' }
    if (-not (Get-Field $Config 'update')) { Set-Field $Config 'update' ([PSCustomObject]@{}) }
    $StateDir = Get-Field $Config.update 'state_dir' (Join-Path $InstallRoot 'data\update')
    Assert-NoPendingUpdate $StateDir
    $CA = Get-Field $Config.update 'ca_file' ''
    if ($CA) {
      $Known = @('C:\ProgramData\SecWeaver\Agent\shipper\ca.crt', 'C:\ProgramData\SecWeaver\Agent\etc\shipper\ca.crt')
      if ([IO.Path]::GetFullPath($CA) -notin $Known -or (Test-Path -LiteralPath $CA)) { throw 'Custom/existing CA requires operator review; it was not removed' }
      $Config.update.PSObject.Properties.Remove('ca_file')
    }
    $PublicBytes = [Convert]::FromBase64String($Profile.public_key)
    $SHA = [Security.Cryptography.SHA256]::Create()
    try { $Derived = 'ed25519-' + ([BitConverter]::ToString($SHA.ComputeHash($PublicBytes)).Replace('-', '').ToLowerInvariant().Substring(0, 16)) } finally { $SHA.Dispose() }
    if ($PublicBytes.Length -ne 32 -or $Derived -ne $Profile.key_id) { throw 'Invalid trusted profile key' }
    if ($Profile.key_id -in @(Get-Field $Config.update 'revoked_key_ids' @())) { throw 'Profile key is revoked locally' }
    $PreviousKey = Get-Field $Config.update 'public_key' ''
    if ($PreviousKey -and $PreviousKey -ne $Profile.public_key) { throw 'Different existing public key requires operator review' }
    Set-Field $Config.update 'public_key' $Profile.public_key
    Set-Field $Config.update 'manifest_url' $Profile.scheduled_manifest_url
    Set-Field $Config.update 'require_server_policy' $true
    $Service = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
    if ($null -eq $Service -or $Service.PathName.IndexOf($BinaryPath, [StringComparison]::OrdinalIgnoreCase) -lt 0 -or $Service.PathName.IndexOf($ConfigPath, [StringComparison]::OrdinalIgnoreCase) -lt 0) { throw 'SCM paths do not match ConfigPath/BinaryPath' }
    if ((Get-Service -Name $ServiceName).Status -ne 'Running') { throw 'Existing service must be Running before migration' }
    $ManifestFile = Join-Path $Work 'manifest.json'
    Get-PinnedFile $Profile.manifest_url $ManifestFile $Profile.server_url 4MB
    if ((Get-SHA256 $ManifestFile) -ne $Profile.manifest_sha256) { throw 'Pinned manifest SHA-256 mismatch' }
    $Envelope = Read-Object $ManifestFile
    $Manifest = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Envelope.payload)) | ConvertFrom-Json
    if ($Manifest.latest.version -ne $Profile.version -or $Envelope.key_id -ne $Profile.key_id) { throw 'Pinned version/signer mismatch' }
    $Candidate = $BinaryPath
    if ($Current -ne $Profile.version) {
      $Arch = [Environment]::GetEnvironmentVariable('PROCESSOR_ARCHITEW6432')
      if (-not $Arch) { $Arch = [Environment]::GetEnvironmentVariable('PROCESSOR_ARCHITECTURE') }
      if ($Arch -notin @('AMD64', 'ARM64')) { throw 'Only Windows x64/ARM64 are supported' }
      $Artifact = $Manifest.binaries.('windows_' + $Arch.ToLowerInvariant())
      $Candidate = Join-Path $Work 'secweaver-agent.exe'
      Get-PinnedFile ([Uri]::new([Uri]$Profile.manifest_url, $Artifact.url).AbsoluteUri) $Candidate $Profile.server_url 64MB
      if ((Get-SHA256 $Candidate) -ne $Artifact.sha256 -or (Get-Item -LiteralPath $Candidate).Length -ne $Artifact.size) { throw 'Pinned binary hash/size mismatch; refusing execution' }
      if ((Invoke-Native $Candidate @('version') $Work) -notmatch ('(?m)^secweaver-agent ' + [regex]::Escape($Profile.version) + '\s')) { throw 'Candidate version mismatch' }
    }
    $CheckState = Join-Path $Work 'check-state'
    New-PrivateDirectory $CheckState
    foreach ($Name in @('state.json', 'trusted-update-keys.json')) {
      $Source = Join-Path $StateDir $Name
      if (Test-Path -LiteralPath $Source) { Assert-RegularFile $Source; Copy-Item -LiteralPath $Source -Destination (Join-Path $CheckState $Name) }
    }
    $CheckOutput = Join-Path $Work 'check.json'
    Invoke-Native $Candidate @('update', 'check', '-manifest-url', $Profile.manifest_url, '-public-key', $Profile.public_key, '-device-id', $DeviceId, '-state-dir', $CheckState, '-status-output', $CheckOutput) $Work | Out-Null
    $Check = Read-Object $CheckOutput
    if ($Check.status -notin @('update_available', 'up_to_date') -or $Check.latest_version -ne $Profile.version) { throw 'Signed check did not approve the migration target' }
    $Staged = Join-Path $Work 'config.json'
    [IO.File]::WriteAllText($Staged, ($Config | ConvertTo-Json -Depth 100), (New-Object Text.UTF8Encoding($false)))
    Invoke-Native $Candidate @('run', '-config', $Staged, '-dry-run') $Work | Out-Null
    if (-not $Apply) {
      $Succeeded = $true
      return @{status='checked'; current=$Current; target=$Profile.version; device_id=$DeviceId; apply_required=$true}
    }
    $Backup = Join-Path $InstallRoot ('data\recovery\' + [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss') + '-' + [Guid]::NewGuid().ToString('N'))
    New-PrivateDirectory $Backup
    Copy-Item -LiteralPath $ConfigPath -Destination (Join-Path $Backup 'config.json')
    Copy-Item -LiteralPath $BinaryPath -Destination (Join-Path $Backup 'secweaver-agent.exe')
    $Mutated = $false
    $ExpectedHash = $OriginalBinaryHash
    try {
      Stop-AgentService $ServiceName
      Assert-NoPendingUpdate $StateDir
      if ((Get-SHA256 $ConfigPath) -ne $OriginalConfigHash -or (Get-SHA256 $BinaryPath) -ne $OriginalBinaryHash -or (Get-SHA256 $KeyPath) -ne $IdentityHash -or (Read-Object $StatePath).device_id -ne $DeviceId) { throw 'Configuration/binary/identity changed during precheck' }
      $Mutated = $true
      Copy-Atomic $Staged $ConfigPath
      if ($Candidate -ne $BinaryPath) { Copy-Atomic $Candidate $BinaryPath; $ExpectedHash = Get-SHA256 $Candidate }
      $Started = [DateTime]::UtcNow
      Start-Service -Name $ServiceName
      $StatusPath = Get-Field $Config 'status_path' (Join-Path $InstallRoot 'data\status.json')
      $Installed = Wait-AgentHealth $StatusPath $DeviceId $Profile.version $Started $HealthTimeoutSeconds
      if ((Get-SHA256 $KeyPath) -ne $IdentityHash -or (Read-Object $StatePath).device_id -ne $DeviceId) { throw 'Device identity changed after restart' }
    } catch {
      $Failure = $_.Exception.Message
      if ($Mutated) {
        try { Assert-NoPendingUpdate $StateDir; if ((Get-SHA256 $BinaryPath) -ne $ExpectedHash) { throw 'Binary changed' } }
        catch { throw "Concurrent update detected; no rollback attempted. Backup: $Backup" }
      }
      try {
        Stop-AgentService $ServiceName
        if ($Mutated) { Copy-Atomic (Join-Path $Backup 'config.json') $ConfigPath; Copy-Atomic (Join-Path $Backup 'secweaver-agent.exe') $BinaryPath }
        Start-Service -Name $ServiceName
      } catch { throw "Migration failed: $Failure; restoration failed: $($_.Exception.Message); backup: $Backup" }
      throw "Migration failed: $Failure; restoration attempted. Backup: $Backup"
    }
    $Succeeded = $true
    return @{status='recovered'; current=$Current; installed=$Installed; device_id=$DeviceId; backup=$Backup}
  } finally {
    if ($null -ne $Lock) { $Lock.Dispose() }
    if ($Succeeded) { Remove-Item -LiteralPath $Work -Recurse -Force }
    else { Write-Warning "Protected recovery diagnostics retained: $Work" }
  }
}

# Dot-sourcing loads only helpers for isolated regression tests, never a service
# operation. Normal invocation returns one machine-readable result or exit 1.
if ($MyInvocation.InvocationName -ne '.') {
  try { Invoke-SaasMigration | ConvertTo-Json -Depth 8 }
  catch { @{status='failed'; reason=$_.Exception.Message} | ConvertTo-Json; exit 1 }
}

#Requires -Version 5.1
param([string]$RecoveryScript, [string]$OldAgentBinary, [string]$ProfilePath)
$ErrorActionPreference = 'Stop'
. $RecoveryScript
$FixtureRoot = Join-Path $env:TEMP ('secweaver-migration-fixture-' + [Guid]::NewGuid().ToString('N'))
New-PrivateDirectory $FixtureRoot
try {
  $InstallRoot = $FixtureRoot
  $ConfigPath = Join-Path $FixtureRoot 'etc\config.json'
  $BinaryPath = Join-Path $FixtureRoot 'bin\secweaver-agent.exe'
  foreach ($Name in @('etc', 'bin', 'data', 'data\update')) { New-Item -ItemType Directory -Path (Join-Path $FixtureRoot $Name) -Force | Out-Null }
  Copy-Item -LiteralPath $OldAgentBinary -Destination $BinaryPath
  $Device = 'swd_' + ('a' * 52)
  $IdentityPath = Join-Path $FixtureRoot 'data\license-state.json'
  $KeyPath = Join-Path $FixtureRoot 'data\device-ed25519.key'
  [IO.File]::WriteAllText($IdentityPath, ('{"device_id":"' + $Device + '"}'))
  [IO.File]::WriteAllText($KeyPath, 'synthetic identity key')
  $Baseline = Join-Path $FixtureRoot 'data\learning.json'
  [IO.File]::WriteAllText($Baseline, 'synthetic baseline')
  $OriginalIdentityHash = Get-SHA256 $IdentityPath
  $Profile = Read-Object $ProfilePath
  $Config = @{enterprise_id='TESTENTERPRISE01'; deployment_mode='sls_saas';
    license=@{enabled=$true; server_url=$Profile.server_url; protocol='device_v2'; state_path=$IdentityPath; identity_key_path=$KeyPath};
    modules=@{'host-process-snapshot'=@{enabled=$true}};
    update=@{enabled=$true; auto_install=$true; require_server_policy=$true; state_dir=(Join-Path $FixtureRoot 'data\update')}}
  [IO.File]::WriteAllText($ConfigPath, ($Config | ConvertTo-Json -Depth 10), (New-Object Text.UTF8Encoding($false)))
  $ServiceName = 'SecWeaverRecoveryFixtureOnly'
  $Apply = $true
  $script:Starts = 0
  $script:Stops = 0
  $script:FailHealth = $false
  # The transaction executes real old/new binaries and real file replacements.
  # Only SCM/health boundaries are fixtures; installed Agent/shipper stay running.
  function Get-CimInstance { param($ClassName, $Filter); return [PSCustomObject]@{PathName=('"' + $BinaryPath + '" service -config "' + $ConfigPath + '"')} }
  function Get-Service { param($Name); return [PSCustomObject]@{Status='Running'} }
  function Start-Service { param($Name); $script:Starts++ }
  function Stop-AgentService { param($Name); $script:Stops++ }
  function Wait-AgentHealth {
    param($Path, $DeviceId, $Version, $Started, $Seconds)
    if ($script:FailHealth) { throw 'synthetic unhealthy modules' }
    $Text = Invoke-Native $BinaryPath @('version') $FixtureRoot
    if ($Text -notmatch ('(?m)^secweaver-agent ' + [regex]::Escape($Version) + '\s')) { throw 'Installed binary has wrong version' }
    return $Version
  }
  $Result = Invoke-SaasMigration
  if ($Result.status -ne 'recovered' -or $Result.installed -ne '0.3.83') { throw 'Migration did not recover' }
  if ((Get-SHA256 $IdentityPath) -ne $OriginalIdentityHash -or [IO.File]::ReadAllText($Baseline) -ne 'synthetic baseline') { throw 'Identity/baseline changed' }
  $Saved = Read-Object $ConfigPath
  if ($Saved.update.public_key -ne $Profile.public_key -or -not $Saved.update.require_server_policy) { throw 'Trust was not saved' }
  # Restore the fixture's old input and force health failure to exercise rollback.
  Copy-Item -LiteralPath $OldAgentBinary -Destination $BinaryPath -Force
  [IO.File]::WriteAllText($ConfigPath, ($Config | ConvertTo-Json -Depth 10), (New-Object Text.UTF8Encoding($false)))
  $BeforeConfig = Get-SHA256 $ConfigPath
  $BeforeBinary = Get-SHA256 $BinaryPath
  $script:FailHealth = $true
  $Failed = $false
  try { Invoke-SaasMigration | Out-Null } catch {
    if ($_.Exception.Message -notlike '*restoration attempted*') { throw }
    $Failed = $true
  }
  if (-not $Failed -or (Get-SHA256 $ConfigPath) -ne $BeforeConfig -or (Get-SHA256 $BinaryPath) -ne $BeforeBinary) { throw 'Rollback did not restore exact bytes' }
  if ($script:Starts -lt 3 -or $script:Stops -lt 3) { throw 'Service boundary recovery was not exercised' }
  "PASS: source=$($Result.current), target=$($Result.installed); real binaries, pinned download/signature, identity preservation and exact rollback; SCM is a fixture"
} finally { Remove-Item -LiteralPath $FixtureRoot -Recurse -Force }

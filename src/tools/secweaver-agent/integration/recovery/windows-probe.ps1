#Requires -Version 5.1
param([string]$RecoveryScript, [string]$AgentBinary, [string]$ProfilePath)
$ErrorActionPreference = 'Stop'
. $RecoveryScript
$Profile = Read-Object $ProfilePath
$Work = Join-Path $env:TEMP ('secweaver-recovery-probe-' + [Guid]::NewGuid().ToString('N'))
New-PrivateDirectory $Work
try {
  # Exercise real 5.1 argument marshalling, UTF-8 serialization, filesystem
  # replacement and the published TLS/Ed25519 chain without operating SCM.
  $ConfigPath = Join-Path $Work 'config with spaces.json'
  $Config = @{enterprise_id='TESTENTERPRISE01'; modules=@{'host-process-snapshot'=@{enabled=$true}};
    update=@{enabled=$false; ca_file=(Join-Path $Work 'missing.crt'); state_dir=(Join-Path $Work 'state')}}
  [IO.File]::WriteAllText($ConfigPath, ($Config | ConvertTo-Json -Depth 10), (New-Object Text.UTF8Encoding($false)))
  $Before = Get-SHA256 $ConfigPath
  $Rejected = $false
  try { Invoke-Native $AgentBinary @('config', 'set-update', '-config', $ConfigPath, '-manifest-url', $Profile.scheduled_manifest_url, '-auto-install', 'true', '-public-key', $Profile.public_key) $Work | Out-Null }
  catch { $Rejected = $true }
  if (-not $Rejected -or (Get-SHA256 $ConfigPath) -ne $Before) { throw 'Broken boolean argv must fail without writing' }
  Invoke-Native $AgentBinary @('config', 'set-update', '-config', $ConfigPath, '-manifest-url', $Profile.scheduled_manifest_url,
    '-auto-install=true', '-require-server-policy=true', '-public-key', $Profile.public_key, '-use-system-ca') $Work | Out-Null
  $After = Read-Object $ConfigPath
  if ($After.update.public_key -ne $Profile.public_key -or (Get-Field $After.update 'ca_file')) { throw 'Trust was not persisted' }
  $Manifest = Join-Path $Work 'manifest.json'
  Get-PinnedFile $Profile.manifest_url $Manifest $Profile.server_url 4MB
  if ((Get-SHA256 $Manifest) -ne $Profile.manifest_sha256) { throw 'Published manifest pin mismatch' }
  $Check = Join-Path $Work 'check.json'
  $DowngradeRejected = $false
  try {
    Invoke-Native $AgentBinary @('update', 'check', '-manifest-url', $Profile.manifest_url, '-public-key', $Profile.public_key,
      '-device-id', ('swd_' + ('a' * 52)),
      '-state-dir', (Join-Path $Work 'check-state'), '-status-output', $Check) $Work | Out-Null
  } catch { $DowngradeRejected = $true }
  $Verified = Read-Object $Check
  # 0.3.84 must authenticate 0.3.83 and then refuse the unsigned downgrade.
  if (-not $DowngradeRejected -or $Verified.reason -ne 'rollback_not_authorized' -or $Verified.signer_key_id -ne $Profile.key_id -or $Verified.latest_version -ne $Profile.version) { throw 'Signature/downgrade check failed' }
  $Replacement = Join-Path $Work 'replacement.json'
  [IO.File]::WriteAllText($Replacement, '{"value":"new"}')
  Copy-Atomic $Replacement $ConfigPath
  if ((Read-Object $ConfigPath).value -ne 'new') { throw 'Atomic replacement failed' }
  $Acl = Get-Acl $Work
  if (-not $Acl.AreAccessRulesProtected) { throw 'Recovery ACL inherited broad permissions' }
  'PASS: PowerShell 5.1 native argv, trust write, HTTPS/hash/Ed25519, ACL and atomic replacement; no SCM changes'
} finally { Remove-Item -LiteralPath $Work -Recurse -Force }

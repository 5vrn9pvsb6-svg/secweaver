# No administrator access or host changes: run the actual parser/download,
# snapshot and rollback code with fake network/SCM boundaries and private files.
$ErrorActionPreference = 'Stop'
$AgentRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$WindowsDir = Join-Path $AgentRoot 'packaging/windows'
. (Join-Path $WindowsDir 'windows-install-common.ps1')
function Assert-True($Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
function Expect-Failure([scriptblock]$Action, [string]$Pattern) {
  $Message = ''
  try { & $Action | Out-Null } catch { $Message = $_.Exception.Message }
  Assert-True ($Message -match $Pattern) "Missing expected failure $Pattern; got $Message"
  return $Message
}
# Load only functions, never the Bootstrap's administrator/download entry body.
$Tokens = $null; $Errors = $null
$Ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $WindowsDir 'bootstrap-install.ps1'), [ref]$Tokens, [ref]$Errors)
Assert-True (-not $Errors) 'Bootstrap syntax errors'
# The Bootstrap cannot load package helpers before selecting/downloading a ZIP.
# Enforce parity and test native/WOW64 cases without depending on host .NET types.
$CommonArchitecture = (Get-Command Get-AgentArchitecture).ScriptBlock.ToString().Trim()
# Import definitions into this script scope, without running the entry body.
foreach ($Definition in $Ast.FindAll({param($Node) $Node -is [Management.Automation.Language.FunctionDefinitionAst]}, $false)) {
  . ([scriptblock]::Create($Definition.Extent.Text))
}
Assert-True ((Get-Command Get-AgentArchitecture).ScriptBlock.ToString().Trim() -eq $CommonArchitecture) 'Architecture detectors diverged'
$SavedArchitecture = $env:PROCESSOR_ARCHITECTURE
$SavedNativeArchitecture = $env:PROCESSOR_ARCHITEW6432
try {
  foreach ($Case in @(
    @('AMD64', '', 'amd64'), @('ARM64', '', 'arm64'),
    @('x86', 'AMD64', 'amd64'), @('x86', 'ARM64', 'arm64'),
    @('AMD64', 'ARM64', 'arm64'), @(' amd64 ', '', 'amd64')
  )) {
    $env:PROCESSOR_ARCHITECTURE = $Case[0]
    $env:PROCESSOR_ARCHITEW6432 = $Case[1]
    Assert-True ((Get-AgentArchitecture) -eq $Case[2]) 'Incorrect native/WOW64 architecture'
  }
  foreach ($Unknown in @('', 'x86', 'IA64')) {
    $env:PROCESSOR_ARCHITECTURE = $Unknown
    $env:PROCESSOR_ARCHITEW6432 = ''
    Expect-Failure { Get-AgentArchitecture } 'stage=platform check=os-architecture' | Out-Null
  }
  $env:PROCESSOR_ARCHITECTURE = 'AMD64'
  $env:PROCESSOR_ARCHITEW6432 = 'UNKNOWN'
  Expect-Failure { Get-AgentArchitecture } 'check=os-architecture' | Out-Null
  $env:PROCESSOR_ARCHITEW6432 = ''
  Assert-LogtailParameters '123456789' 'windows-group' 'cn-hangzhou-internet' 'https://example.invalid/logtail.zip' ('a' * 64)
  $env:PROCESSOR_ARCHITECTURE = 'ARM64'
  Expect-Failure { Assert-LogtailParameters '123456789' 'windows-group' 'cn-hangzhou-internet' 'https://example.invalid/logtail.zip' ('a' * 64) } 'supports amd64 only' | Out-Null
} finally {
  $env:PROCESSOR_ARCHITECTURE = $SavedArchitecture
  $env:PROCESSOR_ARCHITEW6432 = $SavedNativeArchitecture
}
function Invoke-WebRequest {
  param([switch]$UseBasicParsing, $Uri, $OutFile, $TimeoutSec, $MaximumRedirection, $ErrorAction)
  if ($script:HttpStatus) {
    $Failure = New-Object Exception 'server echoed swenr_example.secret'
    $Failure | Add-Member -NotePropertyName Response -NotePropertyValue @{StatusCode=$script:HttpStatus}
    throw $Failure
  }
  return $script:Response
}
$Url = 'https://user:password@example.invalid/releases/latest-version.txt?token=secret'
foreach ($Response in @($null, @{Content=$null}, @{Content=''}, @{Content='  '})) {
  $script:Response = $Response
  $script:HttpStatus = 0
  $Message = Expect-Failure { Invoke-BootstrapDownload 'agent-version' $Url } 'check=response-body'
  Assert-True ($Message -notmatch 'password|token=|swenr_') 'Credential leaked in empty-response error'
}
foreach ($Code in @(401, 404)) {
  $script:HttpStatus = $Code
  $Message = Expect-Failure { Invoke-BootstrapDownload 'agent-version' $Url } "HTTP=$Code"
  Assert-True ($Message -notmatch 'password|token=|swenr_') 'Credential leaked in HTTP error'
}
$script:HttpStatus = 0
$script:Response = @{Content=[Text.Encoding]::UTF8.GetBytes("0.3.49`r`n")}
$Value = Invoke-BootstrapDownload 'agent-version' $Url
Assert-True ((ConvertFrom-AgentVersionPointer $Value $Url) -eq '0.3.49') 'CRLF/byte response rejected'
foreach ($Value in @('', '<html>login</html>', '{"version":"0.3.49"}', "0.3.49`n0.3.48", ('x' * 67))) {
  Expect-Failure { ConvertFrom-AgentVersionPointer $Value $Url } 'check=version-pointer' | Out-Null
}

$Temp = Join-Path ([IO.Path]::GetTempPath()) ('secweaver-failure-contract-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $Temp | Out-Null
try {
  # Execute the real Bootstrap parameter validation and finally block without
  # its download/SCM body. Cleanup must preserve success and the original error.
  $OuterTry = @($Ast.EndBlock.Statements | Where-Object { $_ -is [Management.Automation.Language.TryStatementAst] })[-1]
  $CleanupTest = [scriptblock]::Create($Ast.ParamBlock.Extent.Text + "`n" + @'
$tempRoot = $InstallRoot
$installArgs = @{EnterpriseEnrollmentToken=$EnterpriseEnrollmentToken}
try { if ($NoStart) { throw 'original-install-failure' } } finally
'@ + $OuterTry.Finally.Extent.Text + @'

if (Get-Variable -Name EnterpriseEnrollmentToken -Scope Local -ErrorAction SilentlyContinue) { throw 'token reference retained' }
if ($installArgs.ContainsKey('EnterpriseEnrollmentToken')) { throw 'argument token retained' }
'@)
  $CleanupDir = Join-Path $Temp 'bootstrap-cleanup'
  $FakeToken = 'swenr_aaaaaaaa.' + ('a' * 40)
  New-Item -ItemType Directory -Path $CleanupDir | Out-Null
  & $CleanupTest -EnterpriseEnrollmentToken $FakeToken -InstallRoot $CleanupDir
  Assert-True (-not (Test-Path $CleanupDir)) 'Bootstrap temporary directory retained'
  New-Item -ItemType Directory -Path $CleanupDir | Out-Null
  Expect-Failure { & $CleanupTest -EnterpriseEnrollmentToken $FakeToken -InstallRoot $CleanupDir -NoStart } 'original-install-failure' | Out-Null
  Assert-True (-not (Test-Path $CleanupDir)) 'Failed Bootstrap temporary directory retained'

  $Checksum = Join-Path $Temp 'empty.sha256'
  [IO.File]::WriteAllText($Checksum, '')
  Expect-Failure { Get-ExpectedHash $Checksum } 'check=sha256' | Out-Null
  [IO.File]::WriteAllText($Checksum, (('A' * 64) + '  agent.zip'))
  Assert-True ((Get-ExpectedHash $Checksum) -eq ('a' * 64)) 'Valid sidecar was not parsed'
  $Config = Join-Path $Temp 'config.json'
  [IO.File]::WriteAllText($Config, '{"update":{"enabled":false}}')
  Expect-Failure { Confirm-WindowsUpdateConfiguration $Config $true } 'expected update.enabled=true' | Out-Null
  Confirm-WindowsUpdateConfiguration $Config $false
  [IO.File]::WriteAllText($Config, '{"update":{"enabled":true,"auto_install":true,"interval_seconds":21600,"require_server_policy":true}}')
  Confirm-WindowsUpdateConfiguration $Config $true

  # Exercise user-visible results with known/unknown channel evidence. Reading a
  # channel must never certify filtering, and normal update behavior is not WARN.
  $LearningConfig = Join-Path $Temp 'learning-summary.json'
  [IO.File]::WriteAllText($LearningConfig, '{"modules":{"windows-eventlog-risk-json":{"enabled":true,"args":["-behavior-learning=true","-learning-shadow=false"]}}}')
  $Missing = (Write-WindowsLearningSummary $LearningConfig @('[WARN] windows-channel/Microsoft-Windows-Sysmon/Operational: unavailable') 6>&1 | Out-String)
  Assert-True ($Missing -match '\[WARN\] learning-readiness: Sysmon is missing or its channel is inaccessible' -and $Missing -match 'remain full-output; collection continues') 'Missing Sysmon consequence hidden'
  $Available = (Write-WindowsLearningSummary $LearningConfig @('[OK] windows-channel/Microsoft-Windows-Sysmon/Operational: available') 6>&1 | Out-String)
  Assert-True ($Available -match '\[INFO\] learning-readiness: Sysmon channel available' -and $Available -match 'completed baseline' -and $Available -notmatch '\[WARN\]') 'Available Sysmon misclassified or filtering certified'
  $Unknown = (Write-WindowsLearningSummary $LearningConfig @($null) 6>&1 | Out-String)
  Assert-True ($Unknown -match '\[WARN\].*capability was not verified') 'Unknown channel capability treated as ready'
  $UpdateSummary = (Confirm-WindowsUpdateConfiguration $Config $true 6>&1 | Out-String)
  Assert-True ($UpdateSummary -match '\[INFO\] update/windows:' -and $UpdateSummary -notmatch '\[WARN\]' -and $UpdateSummary -match 'does not mean an update failed') 'Normal update mechanism reported as failure'

  # Stale detail files must not explain a new failure. Keep the bounded, fresh
  # file path in failure diagnostics so real startup errors remain actionable.
  $Since = [DateTime]::UtcNow.AddSeconds(-2)
  $DetailPath = "$LearningConfig.service-error.txt"
  [IO.File]::WriteAllText($DetailPath, 'current-failure-marker')
  $Fresh = Get-AgentStartupFailure 'SecWeaverDiagnosticFixture' $LearningConfig $Since
  Assert-True ($Fresh -match 'Startup failure detail:' -and $Fresh -match 'current-failure-marker') 'Current failure detail missing'
  (Get-Item $DetailPath).LastWriteTimeUtc = $Since.AddMinutes(-1)
  $Stale = Get-AgentStartupFailure 'SecWeaverDiagnosticFixture' $LearningConfig $Since
  Assert-True ($Stale -notmatch 'Startup failure detail:|current-failure-marker') 'Stale startup failure reported'
  [IO.File]::WriteAllText($DetailPath, ('x' * 16385))
  $Oversized = Get-AgentStartupFailure 'SecWeaverDiagnosticFixture' $LearningConfig $Since
  Assert-True ($Oversized -notmatch 'Startup failure detail:') 'Unbounded startup detail read'

  $script:HasService = $true; $script:ServiceState = 'Running'; $script:Calls = @()
  function Get-Service {
    param($Name, $ErrorAction)
    if (-not $script:HasService) { return $null }
    $Result = [pscustomobject]@{Status=$script:ServiceState}
    $Result | Add-Member -MemberType ScriptMethod -Name WaitForStatus -Value { param($State,$Timeout) }
    return $Result
  }
  function Get-CimInstance { param($ClassName,$Filter,$ErrorAction) return @{PathName='old-agent service -config old.json';StartMode='Auto'} }
  function Get-ItemProperty { param($LiteralPath,$ErrorAction) return @{DelayedAutoStart=1} }
  function Stop-Service { param($Name,[switch]$Force,$ErrorAction) $script:ServiceState='Stopped' }
  function Start-Service { param($Name,$ErrorAction) $script:ServiceState='Running' }
  function Start-Sleep { param($Seconds) }
  function sc.exe { $script:Calls += ($args -join ' '); $global:LASTEXITCODE=0 }
  $Binary = Join-Path $Temp 'agent.exe'
  $NewFile = Join-Path $Temp 'new.conf'
  [IO.File]::WriteAllText($Binary, 'old-binary')
  $Snapshot = New-AgentInstallSnapshot 'SecWeaverAgent' @($Binary,$Config,$NewFile) $Temp
  [IO.File]::WriteAllText($Binary, 'new-binary')
  [IO.File]::WriteAllText($Config, 'broken-config')
  [IO.File]::WriteAllText($NewFile, 'new')
  Restore-AgentInstallSnapshot $Snapshot
  Assert-True ((Get-Content -Raw $Binary) -eq 'old-binary') 'Previous binary not restored'
  Assert-True ((Get-Content -Raw $Config) -match 'update') 'Previous config not restored'
  Assert-True (-not (Test-Path $NewFile)) 'New file retained on rollback'
  Assert-True ($script:ServiceState -eq 'Running') 'Previous service not restarted'
  Assert-True (@($script:Calls | Where-Object { $_ -match 'binPath= old-agent service -config old.json start= delayed-auto' }).Count -eq 1) 'SCM command/start mode not restored'

  # A previously stopped service must remain stopped, and rollback errors must
  # surface instead of being mistaken for a recovered installation.
  $script:ServiceState = 'Stopped'
  $Stopped = New-AgentInstallSnapshot 'SecWeaverAgent' @($Binary) $Temp
  Restore-AgentInstallSnapshot $Stopped
  Assert-True ($script:ServiceState -eq 'Stopped') 'Rollback started an originally stopped service'
  function sc.exe { $global:LASTEXITCODE=5 }
  Expect-Failure { Restore-AgentInstallSnapshot $Stopped } 'Cannot disable' | Out-Null
  function sc.exe { $script:Calls += ($args -join ' '); $global:LASTEXITCODE=0 }

  $script:HasService=$false
  $Fresh = New-AgentInstallSnapshot 'SecWeaverAgent' @($NewFile) $Temp
  [IO.File]::WriteAllText($NewFile, 'new')
  $script:HasService=$true
  Restore-AgentInstallSnapshot $Fresh
  Assert-True ($script:Calls[-1] -eq 'delete SecWeaverAgent') 'Fresh failed service not removed'
  Assert-True (-not (Test-Path $NewFile)) 'Fresh failed file not removed'
  Assert-True ((Protect-InstallerMessage 'token=swenr_example.secret') -notmatch 'swenr_') 'Failure redaction lost'
} finally {
  Remove-Item -LiteralPath $Temp -Recurse -Force
}
Write-Output 'PASS: Bootstrap null/HTTP/version/sidecar validation, update expectations and installer rollback'

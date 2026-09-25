# Runs without administrator access, downloads, SCM mutations or SLS credentials.
$ErrorActionPreference = 'Stop'
$AgentRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$WindowsDir = Join-Path $AgentRoot 'packaging/windows'
Get-ChildItem -LiteralPath $WindowsDir -Filter '*.ps1' | ForEach-Object {
  $Tokens = $null; $Errors = $null
  [void][Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$Tokens, [ref]$Errors)
  if ($Errors) { throw ($Errors | Out-String) }
}
. (Join-Path $WindowsDir 'windows-install-common.ps1')
function Assert-True($Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
function Assert-Fails([scriptblock]$Action) {
  $Failed = $false
  try { & $Action } catch { $Failed = $true }
  Assert-True $Failed 'Expected failure was accepted'
}
$DeviceId = 'swd_' + ('a' * 52)
$Identity = ConvertFrom-InstallerIdentity "ABCDEFGHIJKLMNOP`t$DeviceId" ''
Assert-True ($Identity.DeviceId -eq $DeviceId) 'Enrollment identity lost'
Assert-Fails { ConvertFrom-InstallerIdentity "ABCDEFGHIJKLMNOP`t$DeviceId" 'swd_conflicting' }
Assert-Fails { ConvertFrom-InstallerIdentity @('noise', "ABCDEFGHIJKLMNOP`t$DeviceId") '' }
Assert-Fails { ConvertFrom-InstallerIdentity 'ABCDEFGHIJKLMNOP' '' }
$Temp = Join-Path ([IO.Path]::GetTempPath()) ('secweaver-windows-contract-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $Temp | Out-Null
try {
  $ConfigPath = Join-Path $Temp 'config.json'
  Copy-Item (Join-Path $AgentRoot 'config.windows.example.json') $ConfigPath
  Update-WindowsLayout $ConfigPath 'D:\SecWeaver' 'D:\SecWeaver\bin' 'D:\Config'
  $Config = Get-Content -Raw $ConfigPath | ConvertFrom-Json
  Assert-True ($Config.status_path -eq 'D:\SecWeaver\data\status.json') 'Custom root ignored'
  Assert-True ($Config.modules.'host-persistence'.args[1] -eq 'D:\Config\host-persistence.json') 'Custom config root ignored'
  Assert-True ($Config.modules.'audit-port-execmon'.args -is [array]) 'Empty flag array corrupted'
  Assert-True ($Config.modules.'windows-eventlog-risk-json'.args[-1] -eq 'D:\SecWeaver\data\windows-eventlog-risk-json.cursor.json') 'Implicit cursor root ignored'
  Assert-True ([IO.File]::ReadAllBytes($ConfigPath)[0] -eq 123) 'JSON contains a UTF-8 BOM'

  # Migration must preserve explicit opt-out by default, change only the owning
  # reader and retain custom duration/generation instead of starting a new day.
  $Config.modules.'windows-eventlog-risk-json'.args += @('-behavior-learning=false','-learning-duration','48h','-learning-generation','7')
  [IO.File]::WriteAllText($ConfigPath, ($Config|ConvertTo-Json -Depth 100))
  $Before = [IO.File]::ReadAllText($ConfigPath)
  Set-WindowsLearningMode $ConfigPath 'preserve'
  Assert-True ([IO.File]::ReadAllText($ConfigPath) -ceq $Before) 'Preserve rewrote a user policy'
  Set-WindowsLearningMode $ConfigPath 'shadow'
  $Migrated = Get-Content $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
  $ArgsAfter = $Migrated.modules.'windows-eventlog-risk-json'.args
  Assert-True (Get-WindowsBooleanFlag $ArgsAfter 'behavior-learning') 'Shadow did not enable learning'
  Assert-True (Get-WindowsBooleanFlag $ArgsAfter 'learning-shadow') 'Shadow discarded originals'
  Assert-True ($ArgsAfter -contains '48h' -and $ArgsAfter -contains '7') 'Migration reset baseline scope or clock'
  Assert-True ($Migrated.modules.'windows-process-execmon'.enabled -eq $false) 'Migration started duplicate event reader'
  Set-WindowsLearningMode $ConfigPath 'disable'
  $Migrated = Get-Content $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
  Assert-True (-not (Get-WindowsBooleanFlag $Migrated.modules.'windows-eventlog-risk-json'.args 'behavior-learning')) 'Disable ignored'
  Assert-Fails { Get-WindowsBooleanFlag @('-behavior-learning=not-a-bool') 'behavior-learning' }
  Assert-True ([IO.File]::ReadAllBytes($ConfigPath)[0] -eq 123) 'Migration wrote a BOM'

  # Mock only OS observations and delays, exercising real readiness predicates.
  function Start-Sleep { param($Seconds) }
  $script:Reads = 0
  $script:FailAfter = 20
  function Get-Service {
    param($Name, $ErrorAction)
    $script:Reads++
    if ($script:Reads -gt $script:FailAfter) { return @{Status='Stopped'} }
    return @{Status='Running'}
  }
  $StatusPath = Join-Path $Temp 'status.json'
  $Config = @{status_path=$StatusPath; license=@{enabled=$true}; modules=@{sensor=@{enabled=$true}}}
  $Config | ConvertTo-Json -Depth 10 | Set-Content $ConfigPath
  $Now = [DateTime]::UtcNow
  $Status = @{time=$Now.ToString('o');license=@{last_check_at=$Now.ToString('o')};modules=@{sensor=@{status='running';pid=123}}}
  $Status | ConvertTo-Json -Depth 10 | Set-Content $StatusPath
  Wait-AgentReady 'SecWeaverAgent' $ConfigPath $Now
  Assert-True ($script:Reads -eq 10) 'Did not require stable readiness'
  $script:Reads = 0
  $Status.time = $Now.AddHours(-1).ToString('o')
  $Status | ConvertTo-Json -Depth 10 | Set-Content $StatusPath
  Assert-Fails { Wait-AgentReady 'SecWeaverAgent' $ConfigPath $Now }
  $script:Reads = 0
  $Status.time = $Now.ToString('o'); $Status.license.last_error = 'authorization denied'
  $Status | ConvertTo-Json -Depth 10 | Set-Content $StatusPath
  Assert-Fails { Wait-AgentReady 'SecWeaverAgent' $ConfigPath $Now }
  $script:Reads = 0; $script:FailAfter = 1
  Assert-Fails { Wait-ServiceRunning 'SecWeaverAgent' }
  # A corrupt download must fail before extracting or executing vendor code.
  function Get-Service { param($Name, $ErrorAction) return $null }
  # Use a switch matching the production cmdlet's calling convention.
  function Invoke-WebRequest { param([switch]$UseBasicParsing, $Uri, $OutFile, $TimeoutSec, $MaximumRedirection) [IO.File]::WriteAllText($OutFile, 'tampered') }
  $script:Executed = $false
  function Start-Process { $script:Executed = $true; throw 'Vendor execution is forbidden in fixture' }
  $Mismatch = $false
  try { Install-WindowsLogtail '123456' 'test-windows' 'cn-hangzhou-internet' 'https://example.invalid/collector.zip' ('0' * 64) }
  catch { $Mismatch = $_.Exception.Message -like '*SHA-256 mismatch*' }
  Assert-True $Mismatch 'Corrupt archive did not report checksum failure'
  Assert-True (-not $script:Executed) 'Unverified vendor installer executed'
  # Readiness uses the active worker's cache and the shared Go validator, not
  # a stale default-directory file. Zero timeout exercises failure without sleeps.
  $script:WorkerPath = Join-Path $Temp 'ilogtail_worker.exe'
  function Get-CimInstance { param($ClassName,$Filter,$OperationTimeoutSec,$ErrorAction) return @{ExecutablePath=$script:WorkerPath} }
  $script:RuleExit = 0
  function Test-CollectionBinary {
    Assert-True ($args[0] -eq 'logtail-check') 'Wrong collection verifier'
    Assert-True ($args -contains (Join-Path $Temp 'user_log_config.json')) 'Did not select active worker cache'
    $global:LASTEXITCODE = $script:RuleExit
    return '{"cloud_delivery":"unverified"}'
  }
  $Cache = Wait-WindowsLogtailCollection 'Test-CollectionBinary' 'signed.json' 'public-key' 0
  Assert-True ($Cache -eq (Join-Path $Temp 'user_log_config.json')) 'Wrong delivered config path'
  $script:RuleExit = 1
  Assert-Fails { Wait-WindowsLogtailCollection 'Test-CollectionBinary' 'signed.json' 'public-key' 0 }
  function Get-CimInstance { param($ClassName,$Filter,$OperationTimeoutSec,$ErrorAction) return @() }
  Assert-Fails { Wait-WindowsLogtailCollection 'Test-CollectionBinary' 'signed.json' 'public-key' 0 }
  Write-Host 'PASS: Windows syntax, enrollment, layout, readiness and shipper checksum contracts' 
} finally { Remove-Item -LiteralPath $Temp -Recurse -Force }

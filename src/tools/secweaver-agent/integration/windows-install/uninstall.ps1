# Native Windows tests delete only fresh temporary fixture directories. SCM is
# mocked for collector cleanup; installed services and real Logtail are untouched.
$ErrorActionPreference='Stop'
$AgentRoot=(Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$Source=Join-Path $AgentRoot 'packaging\windows\uninstall-service.ps1'
$Tokens=$null; $Errors=$null
$Ast=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$Tokens,[ref]$Errors)
if($Errors){throw ($Errors|Out-String)}
if($env:OS -ne 'Windows_NT'){Write-Output 'SKIP: native uninstall tests require Windows';exit 0}
foreach($Definition in $Ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst]},$false)) {
  . ([scriptblock]::Create($Definition.Extent.Text))
}
function Assert-True($Condition,[string]$Message){if(-not $Condition){throw $Message}}
function Expect-Failure([scriptblock]$Body){$Failed=$false;try{& $Body|Out-Null}catch{$Failed=$true};Assert-True $Failed 'Expected failure was accepted'}
$Temp=Join-Path $env:TEMP ('secweaver-uninstall-test-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory $Temp|Out-Null
try {
  foreach($Unsafe in @('C:\',$env:ProgramData,$env:SystemRoot,(Join-Path $env:ProgramData 'SecWeaver'))){Expect-Failure {Get-UninstallRoot $Unsafe}}
  Assert-ServiceExecutable ([pscustomobject]@{Name='test';PathName='"C:\Agent\agent.exe" service'}) @('C:\Agent\agent.exe')
  Expect-Failure {Assert-ServiceExecutable ([pscustomobject]@{Name='test';PathName='"C:\Other\agent.exe" service'}) @('C:\Agent\agent.exe')}

  # Test the installed CMD entry deleting its own script/launcher, JSON output,
  # exit code propagation and a second invocation against an already absent root.
  $Fixture=Join-Path $Temp 'self-removal'
  New-Item -ItemType Directory (Join-Path $Fixture 'bin'),(Join-Path $Fixture 'etc')|Out-Null
  [IO.File]::WriteAllText((Join-Path $Fixture 'bin\secweaver-agent.exe'),'fixture only')
  Copy-Item $Source (Join-Path $Fixture 'bin\uninstall-service.ps1')
  # Match release packaging even when Git checks the source out with LF.
  $Launcher=[IO.File]::ReadAllText((Join-Path $AgentRoot 'packaging\windows\uninstall.cmd')).Replace("`r`n","`n").Replace("`n","`r`n")
  [IO.File]::WriteAllText((Join-Path $Fixture 'bin\uninstall.cmd'),$Launcher,[Text.Encoding]::ASCII)
  $Name='SecWeaverUninstallTest'+[guid]::NewGuid().ToString('N')
  $Result=& (Join-Path $Fixture 'bin\uninstall.cmd') -ServiceName $Name -Purge -KeepLogtail -Json
  Assert-True ($LASTEXITCODE -eq 0) "Self-removal failed: $Result"
  Assert-True (($Result|ConvertFrom-Json).ok -and -not (Test-Path $Fixture)) 'Self-removal did not delete all fixtures'
  $Result=& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $Source -InstallRoot $Fixture -ServiceName $Name -Purge -KeepLogtail -Json
  Assert-True ($LASTEXITCODE -eq 0 -and ($Result|ConvertFrom-Json).ok) 'Repeated cleanup was not idempotent'
  $Result=& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $Source -InstallRoot $env:ProgramData -ServiceName $Name -Purge -KeepLogtail -Json
  Assert-True ($LASTEXITCODE -eq 1 -and -not ($Result|ConvertFrom-Json).ok) 'Unsafe root/JSON failure status lost'

  # Redirect the entire Logtail layout into the private fixture. No native
  # collector service or real C:\LogtailData is changed by these tests.
  function Get-LogtailUninstallLayout {return @{Roots=@((Join-Path $Temp 'vendor'));Data=(Join-Path $Temp 'vendor-data')}}
  function Get-UninstallService($Name){return $script:Services[$Name]}
  function Remove-UninstallService($Name){$script:Stopped+= $Name; $script:Services.Remove($Name)}
  function Stop-UninstallProcesses($Executables){$script:KilledPaths=$Executables}
  $ServiceName=$Name; $RemoveFiles=$false; $RemoveConfig=$false; $KeepLogtail=$false
  foreach($Scenario in @('default','purge','keep','wrong-service','junction')) {
    $InstallRoot=Join-Path $Temp $Scenario
    $Vendor=Join-Path $Temp 'vendor';$Data=Join-Path $Temp 'vendor-data'
    New-Item -ItemType Directory -Force (Join-Path $InstallRoot 'bin'),(Join-Path $InstallRoot 'etc'),$Vendor,$Data|Out-Null
    [IO.File]::WriteAllText((Join-Path $InstallRoot 'bin\secweaver-agent.exe'),'fixture only')
    [IO.File]::WriteAllText((Join-Path $Data 'user_defined_id'),'test')
    $script:Services=@{}
    $script:Services[$Name]=[pscustomobject]@{Name=$Name;PathName=('"'+(Join-Path $InstallRoot 'bin\secweaver-agent.exe')+'" service')}
    $script:Services.LogtailDaemon=[pscustomobject]@{Name='LogtailDaemon';PathName=('"'+(Join-Path $Vendor 'logtail_daemon.exe')+'"')}
    $script:Stopped=@();$Purge=$Scenario -ne 'default';$KeepLogtail=$Scenario -eq 'keep'
    if($Scenario -eq 'wrong-service'){$script:Services.LogtailDaemon.PathName='"C:\Foreign\logtail_daemon.exe"'}
    if($Scenario -eq 'junction') {New-Item -ItemType Junction -Path (Join-Path $InstallRoot 'outside') -Target $Data|Out-Null}
    if($Scenario -in @('wrong-service','junction')) {
      Expect-Failure {Invoke-AgentUninstall}
      Assert-True ($script:Stopped.Count -eq 0 -and (Test-Path $Data)) 'Unsafe preflight changed services/files'
      if($Scenario -eq 'junction'){[IO.Directory]::Delete((Join-Path $InstallRoot 'outside'))}
      continue
    }
    $Result=Invoke-AgentUninstall
    Assert-True $Result.ok 'Cleanup failed'
    Assert-True ((Test-Path $InstallRoot) -eq (-not $Purge)) 'Agent files retention incorrect'
    Assert-True ((Test-Path $Data) -eq (-not $Purge -or $KeepLogtail)) 'Logtail retention incorrect'
  }
  Write-Output 'PASS: native self-removal, JSON/exit status, idempotence, purge/keep, foreign service and junction preflight'
} finally {Remove-Item -LiteralPath $Temp -Recurse -Force}

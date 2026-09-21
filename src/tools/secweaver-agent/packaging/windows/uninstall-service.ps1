[CmdletBinding()]
param(
  [string]$InstallRoot = "$env:ProgramData\SecWeaver\Agent",
  [string]$ServiceName = "SecWeaverAgent",
  [switch]$RemoveFiles,
  [switch]$RemoveConfig
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

Assert-Administrator

$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
  if ($existing.Status -ne "Stopped") {
    Stop-Service -Name $ServiceName -Force
    $existing.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(30))
  }
  & sc.exe delete $ServiceName | Out-Null
  Write-Host "Deleted service: $ServiceName"
}

if ($RemoveFiles -and (Test-Path (Join-Path $InstallRoot "bin"))) {
  Remove-Item -Recurse -Force (Join-Path $InstallRoot "bin")
  Write-Host "Removed executable directory under: $InstallRoot"
}

if ($RemoveConfig -and (Test-Path $InstallRoot)) {
  Remove-Item -Recurse -Force $InstallRoot
  Write-Host "Removed installation root: $InstallRoot"
}

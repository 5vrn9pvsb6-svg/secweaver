[CmdletBinding()]
param(
  [string]$Python = "",
  [string]$VenvDir = ".venv",
  [string]$ReportDir = "examples/reports"
)

$ErrorActionPreference = "Stop"

function Resolve-PythonInvocation {
  # Prefer the Windows Python Launcher because it selects the newest Python 3
  # without depending on the Microsoft Store alias named python.exe.
  if ($Python) {
    if (Test-Path -LiteralPath $Python -PathType Leaf) {
      return [PSCustomObject]@{ Command = (Resolve-Path -LiteralPath $Python).Path; Prefix = @() }
    }
    $Configured = Get-Command $Python -CommandType Application -ErrorAction SilentlyContinue
    if (-not $Configured) {
      throw "Python interpreter '$Python' was not found."
    }
    return [PSCustomObject]@{ Command = $Configured.Source; Prefix = @() }
  }

  $Launcher = Get-Command "py.exe" -CommandType Application -ErrorAction SilentlyContinue
  if ($Launcher) {
    return [PSCustomObject]@{ Command = $Launcher.Source; Prefix = @("-3") }
  }
  foreach ($Name in @("python.exe", "python3.exe")) {
    $Candidate = Get-Command $Name -CommandType Application -ErrorAction SilentlyContinue
    if ($Candidate) {
      return [PSCustomObject]@{ Command = $Candidate.Source; Prefix = @() }
    }
  }
  throw "Python 3.10 or newer was not found. Install Python with the py launcher and retry."
}

$RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$OriginalLocation = Get-Location
try {
  Set-Location -LiteralPath $RepoRoot
  $Invocation = Resolve-PythonInvocation
  # Pass every value as a native argument so repository paths containing spaces
  # or non-ASCII characters never pass through string evaluation.
  $Arguments = @($Invocation.Prefix) + @(
    "src/scripts/quickstart.py",
    "--venv-dir", $VenvDir,
    "--report-dir", $ReportDir
  )
  & $Invocation.Command @Arguments
  $ExitCode = $LASTEXITCODE
} finally {
  Set-Location -LiteralPath $OriginalLocation
}

if ($ExitCode -ne 0) {
  exit $ExitCode
}

[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [ValidatePattern('^swenr_[a-z2-7]+\.[A-Za-z0-9_-]{40,128}$')]
  [string]$EnterpriseEnrollmentToken,
  [string]$Version = "",
  [string]$InstallRoot = "$env:ProgramData\SecWeaver\Agent",
  [switch]$NoStart
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# SECWEAVER_WINDOWS_BOOTSTRAP_EMBEDDED_CONFIG_BEGIN
$EmbeddedReleaseBaseUrl = "https://YOUR_DATA_CLOUD_HOST/secweaver-agent/releases"
$EmbeddedLicenseServerUrl = "https://agent-gateway.id-net.cn:30443"
$EmbeddedUpdateManifestUrl = "https://YOUR_DATA_CLOUD_HOST/secweaver-agent/updates/stable/update-manifest.json"
$EmbeddedUpdatePublicKey = ""
# SECWEAVER_WINDOWS_BOOTSTRAP_EMBEDDED_CONFIG_END

function Assert-Administrator {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($identity)
  if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Please run this script from an elevated PowerShell session."
  }
}

function Get-AgentArchitecture {
  $architecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLowerInvariant()
  switch ($architecture) {
    "x64" { return "amd64" }
    "arm64" { return "arm64" }
    default { throw "Unsupported Windows architecture: $architecture" }
  }
}

function Get-ExpectedHash([string]$ChecksumPath) {
  $firstLine = (Get-Content -LiteralPath $ChecksumPath -TotalCount 1).Trim()
  if ($firstLine -notmatch '^([0-9A-Fa-f]{64})(?:\s+.+)?$') {
    throw "Invalid SHA-256 sidecar: $ChecksumPath"
  }
  return $Matches[1].ToLowerInvariant()
}

Assert-Administrator
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

if ($EmbeddedReleaseBaseUrl -notmatch '^https://' -or $EmbeddedReleaseBaseUrl -match 'YOUR_DATA_CLOUD_HOST') {
  throw "The Windows Bootstrap has not been published with a valid HTTPS release origin."
}
if ($EmbeddedLicenseServerUrl -notmatch '^https://') {
  throw "The Windows Bootstrap has no valid HTTPS authorization origin."
}
if ($EmbeddedUpdateManifestUrl -notmatch '^https://' -or $EmbeddedUpdateManifestUrl -match 'YOUR_DATA_CLOUD_HOST') {
  throw "The Windows Bootstrap has no valid update manifest URL."
}
if ($EmbeddedUpdatePublicKey -and $EmbeddedUpdatePublicKey -notmatch '^[A-Za-z0-9+/]{43}=$') {
  throw "The Windows Bootstrap has an invalid Ed25519 update public key."
}
# Resolve once before changing the host, without an embedded-version fallback.
# Initial trust and unsigned updates use HTTPS + SHA-256. When an update public
# key is embedded, the installed Agent also requires manifest signatures.
if (-not $Version) {
  $response = Invoke-WebRequest -UseBasicParsing -Uri "$($EmbeddedReleaseBaseUrl.TrimEnd('/'))/latest-version.txt" -MaximumRedirection 0 -TimeoutSec 30
  if ($response.Content.Length -gt 65) { throw "Release version pointer exceeds 65 bytes." }
  $Version = $response.Content.TrimEnd("`n")
}
if ($Version.Length -gt 64 -or $Version -cnotmatch '^[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9.-]+)?$' -or $Version.Contains("`n")) {
  throw "Invalid Agent version."
}

$architecture = Get-AgentArchitecture
$packageName = "secweaver-agent_${Version}_windows_${architecture}"
$packageUrl = "$($EmbeddedReleaseBaseUrl.TrimEnd('/'))/$Version/$packageName.zip"
$checksumUrl = "$packageUrl.sha256"
$tempRoot = Join-Path ([IO.Path]::GetTempPath()) ("secweaver-agent-" + [Guid]::NewGuid().ToString("N"))
$archivePath = Join-Path $tempRoot "$packageName.zip"
$checksumPath = "$archivePath.sha256"

try {
  New-Item -ItemType Directory -Force $tempRoot | Out-Null
  Write-Host "[secweaver-agent bootstrap] Downloading $packageUrl"
  Invoke-WebRequest -UseBasicParsing -Uri $packageUrl -OutFile $archivePath
  Invoke-WebRequest -UseBasicParsing -Uri $checksumUrl -OutFile $checksumPath

  $expectedHash = Get-ExpectedHash $checksumPath
  $actualHash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($actualHash -ne $expectedHash) {
    throw "Agent package SHA-256 mismatch."
  }

  Expand-Archive -LiteralPath $archivePath -DestinationPath $tempRoot -Force
  $packageRoot = Join-Path $tempRoot $packageName
  $installer = Join-Path $packageRoot "install-service.ps1"
  if (-not (Test-Path -LiteralPath $installer -PathType Leaf)) {
    throw "Agent package does not contain install-service.ps1."
  }

  $installArgs = @{
    EnterpriseEnrollmentToken = $EnterpriseEnrollmentToken
    LicenseServerUrl = $EmbeddedLicenseServerUrl
    InstallRoot = $InstallRoot
    UpdateManifestUrl = $EmbeddedUpdateManifestUrl
    NoStart = $NoStart
  }
  if ($EmbeddedUpdatePublicKey) {
    $installArgs.UpdatePublicKey = $EmbeddedUpdatePublicKey
  }
  & $installer @installArgs
  if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) {
    throw "Windows Agent installer failed with exit code $LASTEXITCODE."
  }
  Write-Host "[secweaver-agent bootstrap] Installation completed."
} finally {
  $EnterpriseEnrollmentToken = ""
  if (Test-Path -LiteralPath $tempRoot) {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
  }
}

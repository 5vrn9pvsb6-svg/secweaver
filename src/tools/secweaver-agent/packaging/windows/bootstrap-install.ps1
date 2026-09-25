[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [ValidatePattern('^swenr_[a-z2-7]+\.[A-Za-z0-9_-]{40,128}$')]
  [string]$EnterpriseEnrollmentToken,
  [string]$Version = "",
  [string]$InstallRoot = "$env:ProgramData\SecWeaver\Agent",
  [ValidateSet('preserve', 'enable', 'shadow', 'disable')]
  [string]$LearningMode = 'preserve',
  [switch]$SkipLogtail,
  [switch]$NoStart
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# SECWEAVER_WINDOWS_BOOTSTRAP_EMBEDDED_CONFIG_BEGIN
$EmbeddedReleaseBaseUrl = "https://YOUR_DATA_CLOUD_HOST/secweaver-agent/releases"
$EmbeddedLicenseServerUrl = "https://agent-gateway.id-net.cn:30443"
$EmbeddedUpdateManifestUrl = "https://YOUR_DATA_CLOUD_HOST/secweaver-agent/updates/stable/update-manifest.json"
$EmbeddedUpdatePublicKey = ""
$EmbeddedLogtailAliUid = ""
$EmbeddedLogtailMachineGroup = ""
$EmbeddedLogtailRegion = "cn-hangzhou-internet"
$EmbeddedWindowsCollectionEnvelope = ""
$EmbeddedWindowsCollectionPublicKey = ""
# SECWEAVER_WINDOWS_BOOTSTRAP_EMBEDDED_CONFIG_END

function Assert-Administrator {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($identity)
  if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Please run this script from an elevated PowerShell session."
  }
}

function Get-AgentArchitecture {
  # Windows PowerShell 5.1 can resolve RuntimeInformation without a usable
  # OSArchitecture property. Native Windows variables avoid that .NET dependency.
  # WOW64 must take precedence: the current shell can be x86 on x64/ARM64.
  # Keep this standalone Bootstrap copy identical to windows-install-common.ps1;
  # the regression suite checks both because no package exists at this stage.
  $architecture = [string]$env:PROCESSOR_ARCHITEW6432
  if ([string]::IsNullOrWhiteSpace($architecture)) {
    $architecture = [string]$env:PROCESSOR_ARCHITECTURE
  }
  switch ($architecture.Trim().ToUpperInvariant()) {
    'AMD64' { return 'amd64' }
    'ARM64' { return 'arm64' }
    default {
      throw 'stage=platform check=os-architecture: missing or unsupported Windows architecture; Windows x64 or ARM64 is required. Check PROCESSOR_ARCHITECTURE and PROCESSOR_ARCHITEW6432 in this PowerShell session.'
    }
  }
}

function Get-ExpectedHash([string]$ChecksumPath) {
  # Empty files yield $null in Windows PowerShell, not an empty string.
  $lines = @(Get-Content -LiteralPath $ChecksumPath -TotalCount 1)
  $firstLine = ''
  if ($lines.Count -gt 0 -and $null -ne $lines[0]) { $firstLine = ([string]$lines[0]).Trim() }
  if ($firstLine -notmatch '^([0-9A-Fa-f]{64})(?:\s+.+)?$') {
    throw "stage=checksum-validation check=sha256: empty or malformed checksum file; republish the release sidecar."
  }
  # Do not depend on $Matches from a negative match; PowerShell scopes can
  # retain a previous match from URL redaction or caller validation.
  return $firstLine.Substring(0, 64).ToLowerInvariant()
}

function Get-BootstrapSafeUrl([string]$Url) {
  # Never expose userinfo, query credentials or enrollment tokens in diagnostics.
  $parsed = $null
  if (-not [Uri]::TryCreate($Url, [UriKind]::Absolute, [ref]$parsed)) { return '<invalid-url>' }
  $safe = $parsed.GetLeftPart([UriPartial]::Authority) + $parsed.AbsolutePath
  $safe = $safe -replace '://[^/@]+@', '://'
  return ($safe -replace 'swenr_[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', '[REDACTED]')
}

function Invoke-BootstrapDownload([string]$Stage, [string]$Url, [string]$OutFile = '') {
  # Keep vendor/server bodies out of errors: they can echo credentials or HTML.
  # Bounded requests and disabled redirects make each failed stage actionable.
  $safe = Get-BootstrapSafeUrl $Url
  $request = @{UseBasicParsing=$true; Uri=$Url; MaximumRedirection=0; TimeoutSec=120; ErrorAction='Stop'}
  if ($OutFile) { $request.OutFile = $OutFile }
  try {
    $response = Invoke-WebRequest @request
  } catch {
    $status = 'unavailable'
    if ($_.Exception.Response -and $_.Exception.Response.StatusCode) { $status = [string][int]$_.Exception.Response.StatusCode }
    $advice = 'Check DNS, connectivity, TLS trust and the release origin; do not disable certificate verification.'
    if ($status -eq '401' -or $status -eq '403') { $advice = 'Check gateway download access; release downloads must not require an enrollment token.' }
    if ($status -eq '404') { $advice = 'Check the published version, platform archive and sidecar at this URL.' }
    throw "stage=$Stage check=download url=$safe HTTP=$status; $advice"
  }
  if ($OutFile) {
    if (-not (Test-Path -LiteralPath $OutFile -PathType Leaf) -or (Get-Item -LiteralPath $OutFile).Length -eq 0) {
      throw "stage=$Stage check=response-body url=$safe HTTP=200: empty download; republish the artifact."
    }
    return
  }
  if ($null -eq $response -or $null -eq $response.Content) {
    throw "stage=$Stage check=response-body url=$safe HTTP=200: missing response content; check the gateway/release origin."
  }
  $content = $response.Content
  if ($content -is [byte[]]) { $content = [Text.Encoding]::UTF8.GetString($content) }
  if ($content -isnot [string] -or [string]::IsNullOrWhiteSpace($content)) {
    throw "stage=$Stage check=response-body url=$safe HTTP=200: empty or non-text response; check the release origin."
  }
  return $content
}

function ConvertFrom-AgentVersionPointer([string]$Content, [string]$Url) {
  $safe = Get-BootstrapSafeUrl $Url
  if ([string]::IsNullOrWhiteSpace($Content) -or $Content.Length -gt 66) {
    throw "stage=agent-version check=version-pointer url=$safe HTTP=200: empty or oversized version pointer."
  }
  # Accept one conventional LF/CRLF terminator, but never HTML, JSON or multiline data.
  $value = $Content -replace '\r?\n$', ''
  if ($value.Length -gt 64 -or $value -cnotmatch '^[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9.-]+)?$' -or $value.Contains("`n") -or $value.Contains("`r")) {
    throw "stage=agent-version check=version-pointer url=$safe HTTP=200: expected a semantic version, not an API/HTML response."
  }
  return $value
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
  $versionUrl = "$($EmbeddedReleaseBaseUrl.TrimEnd('/'))/latest-version.txt"
  $Version = ConvertFrom-AgentVersionPointer (Invoke-BootstrapDownload 'agent-version' $versionUrl) $versionUrl
}
if ($Version.Length -gt 64 -or $Version -cnotmatch '^[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9.-]+)?$' -or $Version.Contains("`n")) {
  throw "Invalid Agent version."
}

$architecture = Get-AgentArchitecture
if (-not $SkipLogtail -and $architecture -ne "amd64") {
  throw "Managed Windows Logtail supports amd64 only; use -SkipLogtail with a separately verified ARM64 shipper."
}
if (-not $SkipLogtail -and (-not $EmbeddedLogtailAliUid -or -not $EmbeddedLogtailMachineGroup)) {
  throw "Bootstrap must publish a Windows Logtail account and Windows-only machine group."
}
if (-not $SkipLogtail -and (-not $EmbeddedWindowsCollectionEnvelope -or -not $EmbeddedWindowsCollectionPublicKey)) {
  throw 'Bootstrap has no signed Windows collection plan; ask the Data Cloud operator to provision and publish Windows SLS rules.'
}
$packageName = "secweaver-agent_${Version}_windows_${architecture}"
$packageUrl = "$($EmbeddedReleaseBaseUrl.TrimEnd('/'))/$Version/$packageName.zip"
$checksumUrl = "$packageUrl.sha256"
$tempRoot = Join-Path ([IO.Path]::GetTempPath()) ("secweaver-agent-" + [Guid]::NewGuid().ToString("N"))
$archivePath = Join-Path $tempRoot "$packageName.zip"
$checksumPath = "$archivePath.sha256"

try {
  New-Item -ItemType Directory -Force $tempRoot | Out-Null
  Write-Host "[secweaver-agent bootstrap] Downloading $(Get-BootstrapSafeUrl $packageUrl)"
  Invoke-BootstrapDownload 'agent-package' $packageUrl $archivePath
  Invoke-BootstrapDownload 'agent-checksum' $checksumUrl $checksumPath

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
    DeploymentMode = "sls_saas"
    EnterpriseEnrollmentToken = $EnterpriseEnrollmentToken
    LicenseServerUrl = $EmbeddedLicenseServerUrl
    InstallRoot = $InstallRoot
    LearningMode = $LearningMode
    UpdateManifestUrl = $EmbeddedUpdateManifestUrl
    NoStart = $NoStart
    SkipLogtail = $SkipLogtail
    LogtailAliUid = $EmbeddedLogtailAliUid
    LogtailMachineGroup = $EmbeddedLogtailMachineGroup
    LogtailRegion = $EmbeddedLogtailRegion
    LogtailCollectionEnvelope = $EmbeddedWindowsCollectionEnvelope
    LogtailCollectionPublicKey = $EmbeddedWindowsCollectionPublicKey
  }
  if ($EmbeddedUpdatePublicKey) {
    $installArgs.UpdatePublicKey = $EmbeddedUpdatePublicKey
  }
  & $installer @installArgs
  if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) {
    throw "Windows Agent installer failed with exit code $LASTEXITCODE."
  }
  Write-Host '[OK] Windows installation completed; see the separate collection, shipper and cloud-delivery results above.' -ForegroundColor Green
} finally {
  # Assignment re-runs ValidatePattern, so an empty string masks successful
  # installation (or the original failure) on Windows PowerShell 5.1. Remove
  # both references instead; never emit the token in cleanup diagnostics.
  if ($installArgs) { $installArgs.Remove('EnterpriseEnrollmentToken') }
  Remove-Variable -Name EnterpriseEnrollmentToken -ErrorAction SilentlyContinue
  if (Test-Path -LiteralPath $tempRoot) {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
  }
}

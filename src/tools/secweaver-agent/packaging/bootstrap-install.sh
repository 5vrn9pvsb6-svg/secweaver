#!/usr/bin/env bash
set -euo pipefail

# Non-interactive root shells on minimal Linux systems may omit /usr/local/bin.
# The package installer places secweaver-agent there, so normalize PATH before
# post-install verification and service setup.
export PATH="${PATH:-/usr/bin:/bin}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/sbin"

APP_NAME="secweaver-agent"
VERSION=""

# WEB Shield SecWeaver Data Cloud deployment checklist for operators:
#
# This file is a Bootstrap template. Do not publish it with the default
# YOUR_DATA_CLOUD_HOST placeholders. Generate the public installer through
# scripts/package-release.sh and set these release-time variables:
#
#   BOOTSTRAP_RELEASE_BASE_URL
#     HTTPS root that serves versioned secweaver-agent packages, for example:
#     https://updates.example.com/secweaver-agent/releases
#
#   BOOTSTRAP_LOGTAIL_INSTALL_URL
#     HTTPS URL of the pinned Logtail/LoongCollector installer mirrored by
#     WEB Shield SecWeaver Data Cloud.
#
#   BOOTSTRAP_LOGTAIL_INSTALL_SHA256
#     SHA-256 of the mirrored Logtail installer. Keep this pinned; the
#     Bootstrap refuses to install an unpinned Logtail package.
#
#   BOOTSTRAP_LOGTAIL_ALIUID
#     Alibaba Cloud UID of the managed SLS account that receives customer
#     logs. The Bootstrap writes /etc/ilogtail/users/<aliuid>.
#
#   BOOTSTRAP_LOGTAIL_REGION
#     Vendor region/network selector; default cn-hangzhou-internet. A bare
#     cn-hangzhou explicitly selects intranet. No automatic network fallback.
#
#   BOOTSTRAP_LICENSE_SERVER_URL
#     Shared Data Cloud authorization origin, normally the SLS Proxy origin.
#
#   BOOTSTRAP_UPDATE_MANIFEST_URL / optional UPDATE_SIGNING_PRIVATE_KEY_FILE
#     Update endpoint and optional offline signing key. package-release.sh embeds
#     the derived public key when signing is enabled; the private key is never published.
#
#   BOOTSTRAP_ENROLLMENT_ID
#     Shared Alibaba Cloud custom-identifier machine-group admission value.
#
# WEB Shield SecWeaver Data Cloud generates install commands with one secret
# per-enterprise value:
#
#   SECWEAVER_AGENT_BOOTSTRAP_URL
#   SECWEAVER_ENTERPRISE_ENROLLMENT_TOKEN
#
# Server-side SLS work is still required: create/bind the custom-identifier
# machine group for the enrollment_id, attach Logtail collection configs for
# /opt/secweaver-agent/logs/audit-port-execmon.log,
# /opt/secweaver-agent/logs/syslog-risk-json.log, host-persistence.log,
# host-process-snapshot.log, host-state-snapshot.log, secweaver-agent-health.log, and
# activate the tenant DataAsset package.

# SECWEAVER_BOOTSTRAP_EMBEDDED_CONFIG_BEGIN
EMBEDDED_RELEASE_BASE_URL="${SECWEAVER_AGENT_EMBEDDED_RELEASE_BASE_URL:-https://YOUR_DATA_CLOUD_HOST/secweaver-agent/releases}"
EMBEDDED_LICENSE_SERVER_URL="${SECWEAVER_LICENSE_EMBEDDED_SERVER_URL:-https://agent-gateway.id-net.cn:30443}"
EMBEDDED_ENROLLMENT_ID="${SECWEAVER_LOGTAIL_EMBEDDED_ENROLLMENT_ID:-}"
EMBEDDED_LOGTAIL_INSTALL_URL="${SECWEAVER_LOGTAIL_EMBEDDED_INSTALL_URL:-https://YOUR_DATA_CLOUD_HOST/logtail/install.sh}"
EMBEDDED_LOGTAIL_INSTALL_SHA256="${SECWEAVER_LOGTAIL_EMBEDDED_INSTALL_SHA256:-}"
EMBEDDED_LOGTAIL_ALIUID="${SECWEAVER_LOGTAIL_EMBEDDED_ALIUID:-}"
EMBEDDED_LOGTAIL_REGION="${SECWEAVER_LOGTAIL_EMBEDDED_REGION:-cn-hangzhou-internet}"
EMBEDDED_UPDATE_MANIFEST_URL="${SECWEAVER_AGENT_EMBEDDED_UPDATE_MANIFEST_URL:-https://YOUR_DATA_CLOUD_HOST/secweaver-agent/updates/stable/update-manifest.json}"
EMBEDDED_UPDATE_PUBLIC_KEY="${SECWEAVER_AGENT_EMBEDDED_UPDATE_PUBLIC_KEY:-}"
# SECWEAVER_BOOTSTRAP_EMBEDDED_CONFIG_END
RELEASE_BASE_URL="${EMBEDDED_RELEASE_BASE_URL}"
LICENSE_SERVER_URL="${EMBEDDED_LICENSE_SERVER_URL}"
ENROLLMENT_ID="${EMBEDDED_ENROLLMENT_ID}"
LOGTAIL_INSTALL_URL="${EMBEDDED_LOGTAIL_INSTALL_URL}"
LOGTAIL_INSTALL_SHA256="${EMBEDDED_LOGTAIL_INSTALL_SHA256}"
LOGTAIL_ALIUID="${EMBEDDED_LOGTAIL_ALIUID}"
LOGTAIL_REGION="${EMBEDDED_LOGTAIL_REGION}"
UPDATE_MANIFEST_URL="${EMBEDDED_UPDATE_MANIFEST_URL}"
UPDATE_PUBLIC_KEY="${EMBEDDED_UPDATE_PUBLIC_KEY}"
LOGTAIL_CONFIG_DIR="${SECWEAVER_LOGTAIL_CONFIG_DIR:-/etc/ilogtail}"
ENTERPRISE_ID=""
ENTERPRISE_ENROLLMENT_TOKEN=""
LICENSE_CHECK_INTERVAL_SECONDS="21600"
LICENSE_HEARTBEAT_INTERVAL_SECONDS="180"
LICENSE_OUTAGE_GRACE_SECONDS="86400"
ALLOW_HTTP=0
START_SERVICE=1
CONFIGURE_LOGTAIL=1
TEMP_DIR=""
NO_COLOR="${NO_COLOR:-}"
INSTALL_LOG=""
STEP_NUMBER=0
STEP_TITLE=""
STEP_STARTED=0
UI_OWNER="${BASHPID:-$$}"
FALLBACK_REPORTED=0
# stderr stays a terminal when curl supplies stdin. Never emit ANSI escapes to
# redirected logs/automation; the original descriptor is only for concise UI.
exec 3>&2

usage() {
  cat <<'EOF'
Usage: curl -fsSL <bootstrap-url> | sudo bash -s -- [options]

Required:
  --enterprise-enrollment-token TOKEN
                           Reusable enterprise-scoped installation credential

Options:
  --enterprise-id ID       Legacy v1 enterprise ID; migration use only
  --version VERSION        Explicitly pin an immutable version for testing
  --enrollment-id ID       Override the embedded machine admission identifier
  --license-server-url URL Override the embedded authorization origin
  --release-base-url URL   Override the embedded release root for self-hosting/testing
  --logtail-install-url URL
                           Override the embedded Logtail installer URL
  --logtail-install-sha256 SHA256
                           Override the embedded Logtail installer checksum
  --logtail-aliuid UID     Override the embedded managed SLS account UID
  --logtail-region REGION  Vendor region/network selector (default: cn-hangzhou-internet)
                           Bare cn-hangzhou explicitly selects intranet; no fallback
  --license-check-interval-seconds N
                           Periodic authorization recheck interval (default: 21600)
  --license-heartbeat-interval-seconds N
                           Device heartbeat interval (default: 180)
  --license-outage-grace-seconds N
                           Cached authorization grace for transient outages (default: 86400)
  --skip-logtail           Install only secweaver-agent; do not configure log upload
  --allow-http             Allow HTTP release URLs for local testing only
  --no-start               Install and preflight without enabling the service
  --no-color               Disable terminal colors (also honors NO_COLOR)
  -h, --help               Show this help

Operator deployment note:
  Publish this Bootstrap only after scripts/package-release.sh has embedded
  real BOOTSTRAP_RELEASE_BASE_URL, BOOTSTRAP_LOGTAIL_INSTALL_URL,
  BOOTSTRAP_LOGTAIL_INSTALL_SHA256, BOOTSTRAP_LOGTAIL_ALIUID, and
  BOOTSTRAP_LOGTAIL_REGION, BOOTSTRAP_LICENSE_SERVER_URL, and
  BOOTSTRAP_ENROLLMENT_ID values, plus the update manifest and optional public
  key generated when UPDATE_SIGNING_PRIVATE_KEY_FILE is set. The UI command contains only an enterprise
  enrollment token. The server resolves enterprise_id from that token; the
  client does not declare its own tenant. Shared values must not be
  placeholders. SecWeaver AK/SK stay on WEB Shield/SecWeaver Data Cloud and
  must never be placed on customer hosts.
EOF
}

log() {
  echo "[secweaver-agent bootstrap] $*"
}

fatal() {
  if [[ -z "${INSTALL_LOG}" ]]; then
    status_line FAIL "$*"
  else
    echo "[secweaver-agent bootstrap] ERROR: $*" >&2
  fi
  exit 1
}

# Presentation is independent of command execution. Commands remain at top
# level under errexit: wrapping shell functions in `if` would disable failures
# inside those functions and could incorrectly print a successful step.
status_line() {
  local level="$1" color="" reset=""
  shift
  if [[ -t 3 && -z "${NO_COLOR}" && "${TERM:-dumb}" != dumb ]]; then
    case "${level}" in
      OK) color=$'\033[32m' ;;
      FAIL) color=$'\033[31m' ;;
      WARN) color=$'\033[33m' ;;
    esac
    [[ -z "${color}" ]] || reset=$'\033[0m'
  fi
  printf '%s[%-4s]%s %s\n' "${color}" "${level}" "${reset}" "$*" >&3
}

step_begin() {
  STEP_NUMBER=$((STEP_NUMBER + 1))
  STEP_TITLE="$*"
  STEP_STARTED=${SECONDS}
  status_line RUN "[${STEP_NUMBER}/8] ${STEP_TITLE}"
}

step_complete() {
  status_line OK "[${STEP_NUMBER}/8] ${STEP_TITLE} ($((SECONDS - STEP_STARTED))s)"
  STEP_TITLE=""
}

step_skip() {
  STEP_NUMBER=$((STEP_NUMBER + 1))
  status_line SKIP "[${STEP_NUMBER}/8] $*"
}

# Create a private log outside the shipped JSONL collection paths. mktemp
# prevents filename races; reject symlink directories before opening as root.
# Logs survive failed setup and are removed by a full --purge uninstall.
initialize_install_log() {
  local directory=/opt/secweaver-agent/install-logs
  [[ ! -L /opt/secweaver-agent && ! -L "${directory}" ]] || fatal "installation log directory must not be a symlink"
  install -d -m 0755 /opt/secweaver-agent
  install -d -m 0700 "${directory}"
  INSTALL_LOG="$(mktemp "${directory}/install.log.XXXXXXXX")"
  chmod 0600 "${INSTALL_LOG}"
  status_line INFO "Detailed installation log: ${INSTALL_LOG}"
  exec >>"${INSTALL_LOG}" 2>&1
}

# Emit only classified diagnostics, not vendor internals or full configuration
# dumps. Startup-empty logs and verified audit fallback are not failed steps.
# Other warnings/errors remain visible, and the original report stays in the log.
show_diagnostics() {
  local report="$1" line empty=0 fallback=0
  cat "${report}"
  while IFS= read -r line; do
    case "${line}" in
      '[WARN] logs/'*'output log exists but has no recent lines'*) empty=1 ;;
      '[WARN] '*'ebpf/btf:'*'backend=auto falls back to audit'*) fallback=1 ;;
      '[WARN] logtail/cloud_delivery:'*) : ;;
      '[WARN] '*) status_line WARN "${line#'[WARN] '}" ;;
      '[ERROR] '*|'[FAIL] '*) status_line FAIL "${line}" ;;
    esac
  done <"${report}"
  [[ "${empty}" != 1 ]] || status_line INFO "New output logs are awaiting events; this is not proof of cloud delivery."
  if [[ "${fallback}" == 1 && "${FALLBACK_REPORTED}" == 0 ]]; then
    status_line INFO "Kernel BTF unavailable; backend=auto uses audit instead of eBPF."
    FALLBACK_REPORTED=1
  fi
  # Cloud verification is summarized once in the final result, never as a
  # successful local check. Keep its complete diagnostic in the detailed log.
  return 0
}

# Preserve the failing exit status, including signals/unexpected shell errors.
# Do not echo commands or raw vendor tails: they can contain installation tokens.
# Only the top-level shell owns UI completion and temporary-directory cleanup.
finish_install() {
  local rc="$1"
  [[ "${BASHPID:-$$}" == "${UI_OWNER}" ]] || return 0
  trap - EXIT
  if [[ "${rc}" != 0 ]]; then
    status_line FAIL "${STEP_TITLE:-Installation validation} failed (exit=${rc})."
    if [[ -n "${INSTALL_LOG}" ]]; then
      if grep -q 'returned HTTP 401' "${INSTALL_LOG}"; then
        status_line WARN "Enrollment token may be expired, revoked or invalid; generate a new installation command in Data Cloud."
      fi
      status_line INFO "Details: ${INSTALL_LOG}"
    fi
  fi
  cleanup
  exit "${rc}"
}

cleanup() {
  if [[ -n "${TEMP_DIR}" && -d "${TEMP_DIR}" ]]; then
    rm -rf "${TEMP_DIR}"
  fi
}
trap cleanup EXIT INT TERM

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --enterprise-enrollment-token)
      [[ "$#" -ge 2 ]] || fatal "--enterprise-enrollment-token requires a value"
      ENTERPRISE_ENROLLMENT_TOKEN="$2"
      shift 2
      ;;
    --enterprise-enrollment-token=*)
      ENTERPRISE_ENROLLMENT_TOKEN="${1#*=}"
      shift
      ;;
    --enterprise-id)
      [[ "$#" -ge 2 ]] || fatal "--enterprise-id requires a value"
      ENTERPRISE_ID="$2"
      shift 2
      ;;
    --enterprise-id=*)
      ENTERPRISE_ID="${1#*=}"
      shift
      ;;
    --license-server-url)
      [[ "$#" -ge 2 ]] || fatal "--license-server-url requires a value"
      LICENSE_SERVER_URL="$2"
      shift 2
      ;;
    --license-server-url=*)
      LICENSE_SERVER_URL="${1#*=}"
      shift
      ;;
    --license-check-interval-seconds)
      [[ "$#" -ge 2 ]] || fatal "--license-check-interval-seconds requires a value"
      LICENSE_CHECK_INTERVAL_SECONDS="$2"
      shift 2
      ;;
    --license-check-interval-seconds=*)
      LICENSE_CHECK_INTERVAL_SECONDS="${1#*=}"
      shift
      ;;
    --license-heartbeat-interval-seconds)
      [[ "$#" -ge 2 ]] || fatal "--license-heartbeat-interval-seconds requires a value"
      LICENSE_HEARTBEAT_INTERVAL_SECONDS="$2"
      shift 2
      ;;
    --license-heartbeat-interval-seconds=*)
      LICENSE_HEARTBEAT_INTERVAL_SECONDS="${1#*=}"
      shift
      ;;
    --license-outage-grace-seconds)
      [[ "$#" -ge 2 ]] || fatal "--license-outage-grace-seconds requires a value"
      LICENSE_OUTAGE_GRACE_SECONDS="$2"
      shift 2
      ;;
    --license-outage-grace-seconds=*)
      LICENSE_OUTAGE_GRACE_SECONDS="${1#*=}"
      shift
      ;;
    --enrollment-id)
      [[ "$#" -ge 2 ]] || fatal "--enrollment-id requires a value"
      ENROLLMENT_ID="$2"
      shift 2
      ;;
    --enrollment-id=*)
      ENROLLMENT_ID="${1#*=}"
      shift
      ;;
    --release-base-url)
      [[ "$#" -ge 2 ]] || fatal "--release-base-url requires a value"
      RELEASE_BASE_URL="$2"
      shift 2
      ;;
    --release-base-url=*)
      RELEASE_BASE_URL="${1#*=}"
      shift
      ;;
    --version)
      [[ "$#" -ge 2 ]] || fatal "--version requires a value"
      VERSION="$2"
      shift 2
      ;;
    --version=*)
      VERSION="${1#*=}"
      shift
      ;;
    --logtail-install-url)
      [[ "$#" -ge 2 ]] || fatal "--logtail-install-url requires a value"
      LOGTAIL_INSTALL_URL="$2"
      shift 2
      ;;
    --logtail-install-url=*)
      LOGTAIL_INSTALL_URL="${1#*=}"
      shift
      ;;
    --logtail-install-sha256)
      [[ "$#" -ge 2 ]] || fatal "--logtail-install-sha256 requires a value"
      LOGTAIL_INSTALL_SHA256="$2"
      shift 2
      ;;
    --logtail-install-sha256=*)
      LOGTAIL_INSTALL_SHA256="${1#*=}"
      shift
      ;;
    --logtail-aliuid)
      [[ "$#" -ge 2 ]] || fatal "--logtail-aliuid requires a value"
      LOGTAIL_ALIUID="$2"
      shift 2
      ;;
    --logtail-aliuid=*)
      LOGTAIL_ALIUID="${1#*=}"
      shift
      ;;
    --logtail-region)
      [[ "$#" -ge 2 ]] || fatal "--logtail-region requires a value"
      LOGTAIL_REGION="$2"
      shift 2
      ;;
    --logtail-region=*)
      LOGTAIL_REGION="${1#*=}"
      shift
      ;;
    --skip-logtail)
      CONFIGURE_LOGTAIL=0
      shift
      ;;
    --allow-http)
      ALLOW_HTTP=1
      shift
      ;;
    --no-start)
      START_SERVICE=0
      shift
      ;;
    --no-color)
      NO_COLOR=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fatal "unknown argument: $1"
      ;;
  esac
done

if [[ "$(id -u)" -ne 0 && "${SECWEAVER_BOOTSTRAP_ALLOW_NON_ROOT:-0}" != "1" ]]; then
  fatal "run as root, for example: curl -fsSL <bootstrap-url> | sudo bash -s -- ..."
fi

if [[ -n "${ENTERPRISE_ENROLLMENT_TOKEN}" && -n "${ENTERPRISE_ID}" ]]; then
  fatal "provide either --enterprise-enrollment-token or --enterprise-id, not both"
fi
if [[ -n "${ENTERPRISE_ENROLLMENT_TOKEN}" ]]; then
  [[ "${ENTERPRISE_ENROLLMENT_TOKEN}" =~ ^swenr_[a-z2-7]+\.[A-Za-z0-9_-]{40,128}$ ]] || \
    fatal "--enterprise-enrollment-token has an invalid format"
else
  ENTERPRISE_ID="$(printf '%s' "${ENTERPRISE_ID}" | tr '[:lower:]' '[:upper:]')"
  [[ "${ENTERPRISE_ID}" =~ ^[A-Z0-9]{16}$ ]] || \
    fatal "--enterprise-enrollment-token is required; --enterprise-id is supported only for legacy v1 migration"
fi
[[ -n "${LICENSE_SERVER_URL}" && "${LICENSE_SERVER_URL}" != *YOUR_DATA_CLOUD_HOST* && "${LICENSE_SERVER_URL}" != *YOUR_WEB_SHIELD_HOST* ]] || fatal "--license-server-url is required and must not be a placeholder"
[[ "${LICENSE_SERVER_URL}" =~ ^https:// ]] || fatal "--license-server-url must use HTTPS"
[[ "${LICENSE_CHECK_INTERVAL_SECONDS}" =~ ^[0-9]+$ ]] || fatal "--license-check-interval-seconds must be an integer"
[[ "${LICENSE_HEARTBEAT_INTERVAL_SECONDS}" =~ ^[0-9]+$ ]] || fatal "--license-heartbeat-interval-seconds must be an integer"
[[ "${LICENSE_OUTAGE_GRACE_SECONDS}" =~ ^[0-9]+$ ]] || fatal "--license-outage-grace-seconds must be an integer"
(( 10#${LICENSE_OUTAGE_GRACE_SECONDS} <= 604800 )) || fatal "--license-outage-grace-seconds must not exceed 604800"
[[ -z "${VERSION}" || "${VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9.-]+)?$ ]] || fatal "invalid --version"
[[ -n "${RELEASE_BASE_URL}" ]] || fatal "release base URL is not configured"
[[ "${RELEASE_BASE_URL}" != *YOUR_DATA_CLOUD_HOST* ]] || fatal "embedded release base URL is not configured"
[[ "${RELEASE_BASE_URL}" != *[[:space:]]* && "${RELEASE_BASE_URL}" != *\?* && "${RELEASE_BASE_URL}" != *\#* ]] || fatal "invalid --release-base-url"
[[ "${UPDATE_MANIFEST_URL}" =~ ^https:// ]] || fatal "embedded update manifest URL must use HTTPS"
[[ "${UPDATE_MANIFEST_URL}" != *YOUR_DATA_CLOUD_HOST* && "${UPDATE_MANIFEST_URL}" != *[[:space:]]* && "${UPDATE_MANIFEST_URL}" != *\#* ]] || fatal "embedded update manifest URL is not configured"
[[ -z "${UPDATE_PUBLIC_KEY}" || "${UPDATE_PUBLIC_KEY}" =~ ^[A-Za-z0-9+/]{43}=$ ]] || fatal "embedded Ed25519 update public key is invalid"

if [[ "${SECWEAVER_BOOTSTRAP_ALLOW_FILE:-0}" == "1" && "${RELEASE_BASE_URL}" =~ ^file:// ]]; then
  : # Test-only local release directory; no user-facing flag enables this mode.
elif [[ "${ALLOW_HTTP}" == "1" ]]; then
  [[ "${RELEASE_BASE_URL}" =~ ^https?:// ]] || fatal "release URL must use HTTP or HTTPS"
else
  [[ "${RELEASE_BASE_URL}" =~ ^https:// ]] || fatal "release URL must use HTTPS; --allow-http is for local testing only"
fi
RELEASE_BASE_URL="${RELEASE_BASE_URL%/}"

if [[ "${CONFIGURE_LOGTAIL}" == "1" ]]; then
  [[ "${ENROLLMENT_ID}" =~ ^[A-Za-z0-9][A-Za-z0-9._:-]{1,127}$ ]] || fatal "--enrollment-id must contain 2-128 safe ASCII characters"
  [[ "${LOGTAIL_ALIUID}" =~ ^[0-9]{6,32}$ ]] || fatal "embedded Logtail AliUid is not configured; contact the Data Cloud administrator"
  [[ "${LOGTAIL_REGION}" =~ ^[a-z0-9][a-z0-9-]{1,31}$ ]] || fatal "embedded Logtail region is not configured; contact the Data Cloud administrator"
  if [[ -n "${LOGTAIL_INSTALL_SHA256}" ]]; then
    LOGTAIL_INSTALL_SHA256="$(printf '%s' "${LOGTAIL_INSTALL_SHA256}" | tr '[:upper:]' '[:lower:]')"
    [[ "${LOGTAIL_INSTALL_SHA256}" =~ ^[0-9a-f]{64}$ ]] || fatal "invalid Logtail installer SHA-256"
  fi
fi

[[ "$(uname -s)" == "Linux" ]] || fatal "this bootstrap installer currently supports Linux only"
case "$(uname -m)" in
  x86_64|amd64)
    ARCH="amd64"
    ;;
  aarch64|arm64)
    ARCH="arm64"
    ;;
  loongarch64|loong64)
    ARCH="loong64"
    ;;
  *)
    fatal "unsupported CPU architecture: $(uname -m)"
    ;;
esac

for command_name in tar mktemp awk wc cat timeout; do
  command -v "${command_name}" >/dev/null 2>&1 || fatal "required command not found: ${command_name}"
done

# Emit only the endpoint host: a future URL may include credentials or tokens.
download_host() {
  local host="${1#*://}"
  host="${host%%/*}"; host="${host##*@}"; host="${host%%\?*}"; host="${host%%\#*}"
  printf '%s' "${host}"
}

# Bound both per-attempt work and total retries. The outer timeout also covers
# DNS/proxy/slow-drip behavior and differences between curl/wget versions.
download() {
  local url="$1"
  local output="$2"
  local stage="${3:-release-download}" rc=0
  if [[ "${SECWEAVER_BOOTSTRAP_ALLOW_FILE:-0}" == "1" && "${url}" =~ ^file:// ]]; then
    cp "${url#file://}" "${output}"
    return
  fi
  log "stage=${stage} host=$(download_host "${url}") download started (total limit 300s)"
  local tls=()
  if command -v curl >/dev/null 2>&1; then
    [[ "${ALLOW_HTTP}" == 1 ]] || tls=(--proto '=https' --proto-redir '=https' --tlsv1.2)
    timeout --kill-after=10 300 curl --fail --silent --show-error --location \
      --connect-timeout 10 --max-time 120 --retry 2 --retry-delay 2 --retry-max-time 260 \
      "${tls[@]}" --output "${output}" "${url}" || rc=$?
  elif command -v wget >/dev/null 2>&1; then
    [[ "${ALLOW_HTTP}" == 1 ]] || tls=(--https-only)
    timeout --kill-after=10 300 wget --quiet --timeout=30 --dns-timeout=10 \
      --connect-timeout=10 --tries=3 --waitretry=2 "${tls[@]}" --output-document="${output}" "${url}" || rc=$?
  else
    fatal "stage=${stage}: curl or wget is required"
  fi
  if [[ "${rc}" != 0 ]]; then
    rm -f -- "${output}"
    fatal "stage=${stage} host=$(download_host "${url}") download failed (exit=${rc}; 124/137=timeout). Check DNS, proxy and endpoint reachability; retry the installation command. No network mode was changed."
  fi
}

# Interpose only inside the vendor subprocess, leaving the pinned installer
# byte-for-byte intact. Current vendor scripts invoke curl/wget by name. Absolute
# paths or future download tools remain bounded by the overall 600-second limit.
vendor_download() {
  local tool="$1" arg host="unknown" rc=0
  shift
  for arg in "$@"; do
    case "${arg}" in http://*|https://*) host="$(download_host "${arg}")" ;; esac
  done
  if [[ "${host}" != unknown ]]; then
    printf '[secweaver-agent bootstrap] stage=logtail-binary-download host=%s\n' "${host}" >&2
  fi
  if [[ "${tool}" == curl ]]; then
    timeout --kill-after=10 300 "${SECWEAVER_VENDOR_CURL}" "$@" \
      --connect-timeout 10 --max-time 120 --retry 2 --retry-delay 2 --retry-max-time 260 || rc=$?
  else
    timeout --kill-after=10 300 "${SECWEAVER_VENDOR_WGET}" "$@" \
      --timeout=30 --dns-timeout=10 --connect-timeout=10 --tries=3 --waitretry=2 || rc=$?
  fi
  if [[ "${rc}" != 0 && "${host}" != unknown ]]; then
    printf '[secweaver-agent bootstrap] stage=logtail-binary-download host=%s failed exit=%s\n' "${host}" "${rc}" >&2
  fi
  return "${rc}"
}

# Do not retry a partially executed installer automatically: it may already have
# changed files/services. The parent retains the install lock; the child closes
# its inherited FD so a daemon cannot hold that lock after bootstrap exits.
run_logtail_installer() (
  local rc=0
  export SECWEAVER_VENDOR_CURL="$(type -P curl || true)"
  export SECWEAVER_VENDOR_WGET="$(type -P wget || true)"
  curl() { vendor_download curl "$@"; }
  wget() { vendor_download wget "$@"; }
  export -f download_host vendor_download curl wget
  log "stage=logtail-install region=${LOGTAIL_REGION} total limit=600s; no automatic network fallback"
  timeout --kill-after=10 600 bash "$1" install "${LOGTAIL_REGION}" 9>&- || rc=$?
  if [[ "${rc}" != 0 ]]; then
    if [[ "${LOGTAIL_REGION}" != *-internet ]]; then
      log "If this is an ordinary public-network host, retry with --logtail-region ${LOGTAIL_REGION}-internet after confirming that selector is supported by your SLS region."
    fi
    fatal "stage=logtail-install region=${LOGTAIL_REGION} failed (exit=${rc}; 124/137=timeout). Check the preceding logtail-binary-download host/error; otherwise inspect vendor install/service output. No upload success is claimed."
  fi
)

sha256_file() {
  local file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "${file}" | awk '{print $1}'
    return
  fi
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "${file}" | awk '{print $1}'
    return
  fi
  if command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 "${file}" | awk '{print $NF}'
    return
  fi
  fatal "sha256sum, shasum, or openssl is required for package verification"
}

logtail_installed() {
  [[ "${SECWEAVER_LOGTAIL_ASSUME_INSTALLED:-0}" == "1" ]] && return 0
  command -v ilogtaild >/dev/null 2>&1 && return 0
  command -v loongcollector >/dev/null 2>&1 && return 0
  [[ -x /usr/local/ilogtail/ilogtail || -x /usr/local/ilogtail/ilogtaild || -x /usr/local/ilogtail/loongcollector ]] && return 0
  [[ -x /etc/init.d/ilogtaild || -x /etc/init.d/loongcollectord ]] && return 0
  return 1
}

install_logtail() {
  if logtail_installed; then
    log "Logtail/LoongCollector is already installed; existing endpoints are retained (region selector is used only for a fresh vendor install)"
    return
  fi
  [[ -n "${LOGTAIL_INSTALL_URL}" && "${LOGTAIL_INSTALL_URL}" != *YOUR_DATA_CLOUD_HOST* ]] || fatal "Logtail is not installed and the embedded installer URL is not configured"
  [[ -n "${LOGTAIL_INSTALL_SHA256}" ]] || fatal "Logtail installer checksum is not pinned; contact the Data Cloud administrator"
  [[ "${LOGTAIL_INSTALL_URL}" != *[[:space:]]* && "${LOGTAIL_INSTALL_URL}" != *\?* && "${LOGTAIL_INSTALL_URL}" != *\#* ]] || fatal "invalid Logtail installer URL"
  if [[ "${SECWEAVER_BOOTSTRAP_ALLOW_FILE:-0}" == "1" && "${LOGTAIL_INSTALL_URL}" =~ ^file:// ]]; then
    :
  elif [[ "${ALLOW_HTTP}" == "1" ]]; then
    [[ "${LOGTAIL_INSTALL_URL}" =~ ^https?:// ]] || fatal "Logtail installer URL must use HTTP or HTTPS"
  else
    [[ "${LOGTAIL_INSTALL_URL}" =~ ^https:// ]] || fatal "Logtail installer URL must use HTTPS"
  fi

  local installer_path="${TEMP_DIR}/logtail-install.sh"
  log "downloading pinned Logtail installer"
  download "${LOGTAIL_INSTALL_URL}" "${installer_path}" logtail-installer-download
  local actual_sha256
  actual_sha256="$(sha256_file "${installer_path}" | tr '[:upper:]' '[:lower:]')"
  [[ "${actual_sha256}" == "${LOGTAIL_INSTALL_SHA256}" ]] || fatal "Logtail installer checksum mismatch"
  log "Logtail installer checksum verified"
  run_logtail_installer "${installer_path}"
  logtail_installed || fatal "Logtail installer completed but Logtail/LoongCollector was not found"
}

configure_logtail_identity() {
  local users_dir="${LOGTAIL_CONFIG_DIR}/users"
  local enrollment_temp
  install -d -m 0755 "${users_dir}"
  install -m 0644 /dev/null "${users_dir}/${LOGTAIL_ALIUID}"
  enrollment_temp="$(mktemp "${LOGTAIL_CONFIG_DIR}/.user_defined_id.XXXXXX")"
  printf '%s\n' "${ENROLLMENT_ID}" >"${enrollment_temp}"
  chmod 0644 "${enrollment_temp}"
  mv -f "${enrollment_temp}" "${LOGTAIL_CONFIG_DIR}/user_defined_id"
  log "Logtail identity configured for the Data Cloud custom-identifier machine group"
}

# The vendor installer starts a daemon outside systemd. Serialize bootstrap
# instances and hand it over only after the old owner has released its PID lock.
logtail_processes() {
  local pid exe
  for pid in $(pgrep -f 'ilogtail|loongcollector' || true); do
    exe="$(readlink "/proc/${pid}/exe" 2>/dev/null || true)"
    case "${exe}" in
      /usr/local/ilogtail/ilogtail*|/usr/local/ilogtail/loongcollector*)
        [[ "$(readlink "/proc/${pid}/ns/pid" 2>/dev/null)" == "$(readlink /proc/1/ns/pid)" ]] && printf '%s\n' "${pid}"
        ;;
    esac
  done
  return 0
}

# Never unlink a live lock: force-stop is the vendor's bounded recovery path,
# followed by an independent /proc check (oneshot active/exited is insufficient).
stop_logtail_for_handoff() {
  local service_name="$1" init_script="$2" attempt file
  if [[ -n "${service_name}" ]]; then
    timeout 60 systemctl stop "${service_name}" || log "Logtail service stop needs process verification"
    [[ "$(systemctl show -p ActiveState "${service_name}")" != ActiveState=deactivating ]] || fatal "${service_name} is still stopping; retry after its stop job finishes"
  fi
  if [[ -n "$(logtail_processes)" ]]; then
    timeout 40 "${init_script}" stop || true
  fi
  if [[ -n "$(logtail_processes)" ]]; then
    log "Logtail graceful stop did not finish; using vendor force-stop"
    # Recovery is visible once; repetitive vendor PID messages stay in the log.
    if declare -F status_line >/dev/null; then
      status_line WARN "Logtail graceful stop timed out; using bounded force-stop before service verification."
    fi
    timeout 10 "${init_script}" force-stop || true
  fi
  for ((attempt=0; attempt<10; attempt++)); do
    [[ -z "$(logtail_processes)" ]] && break
    sleep 1
  done
  [[ -z "$(logtail_processes)" ]] || fatal "Logtail processes remain; refusing to remove live PID locks"
  # Some vendor init versions remove '.pid' rather than the versioned PID file.
  # Restrict cleanup to this installation, after proving no owner remains.
  for file in /usr/local/ilogtail/ilogtail*.pid /usr/local/ilogtail/loongcollector*.pid; do
    [[ ! -f "${file}" ]] || rm -f -- "${file}"
  done
}

start_logtail() {
  local service_name init_script
  if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
    for service_name in loongcollectord.service ilogtaild.service; do
      if systemctl cat "${service_name}" >/dev/null 2>&1; then
        init_script="/etc/init.d/${service_name%.service}"
        [[ -x "${init_script}" ]] || fatal "missing supported Logtail init script: ${init_script}"
        stop_logtail_for_handoff "${service_name}" "${init_script}"
        [[ "${START_SERVICE}" == 1 ]] || return 0
        systemctl reset-failed "${service_name}" || true
        systemctl enable "${service_name}"
        timeout 45 systemctl start "${service_name}" || fatal "${service_name} failed to start"
        systemctl is-active --quiet "${service_name}" && timeout 5 "${init_script}" status >/dev/null 2>&1 || fatal "${service_name} has no healthy collector processes"
        log "${service_name} is active"
        return
      fi
    done
  fi
  for service_name in loongcollectord ilogtaild; do
    if [[ -x "/etc/init.d/${service_name}" ]]; then
      stop_logtail_for_handoff "" "/etc/init.d/${service_name}"
      [[ "${START_SERVICE}" == 1 ]] || return 0
      timeout 45 "/etc/init.d/${service_name}" start
      timeout 5 "/etc/init.d/${service_name}" status >/dev/null 2>&1 || fatal "${service_name} init service did not become active"
      log "${service_name} init service is active"
      return
    fi
  done
  fatal "Logtail is installed but no supported Logtail/LoongCollector service manager was found"
}

TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/secweaver-agent-bootstrap.XXXXXX")"
trap 'finish_install "$?"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
initialize_install_log
status_line INFO "SecWeaver Agent installation (linux/${ARCH})"
step_begin "Resolve release version"

# Resolve once before install side effects. Publishers switch this HTTPS pointer
# only after every immutable archive exists. Missing/invalid pointers fail closed.
# Initial trust and default updates use HTTPS + SHA-256; an embedded key opts
# the installed Agent into signed-manifest verification.
if [[ -z "${VERSION}" ]]; then
  VERSION_FILE="${TEMP_DIR}/latest-version.txt"
  download "${RELEASE_BASE_URL}/latest-version.txt" "${VERSION_FILE}" agent-version-download
  (( $(wc -c <"${VERSION_FILE}") <= 65 )) || fatal "release version pointer exceeds 65 bytes"
  VERSION="$(cat "${VERSION_FILE}")"
  [[ "${VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9.-]+)?$ && ${#VERSION} -le 64 ]] || fatal "invalid release version pointer"
  (( $(wc -c <"${VERSION_FILE}") <= ${#VERSION} + 1 )) || fatal "invalid release version pointer whitespace"
fi
step_complete

PACKAGE_NAME="${APP_NAME}_${VERSION}_linux_${ARCH}"
ARCHIVE_NAME="${PACKAGE_NAME}.tar.gz"
PACKAGE_URL="${RELEASE_BASE_URL}/${VERSION}/${ARCHIVE_NAME}"
CHECKSUM_URL="${PACKAGE_URL}.sha256"

ARCHIVE_PATH="${TEMP_DIR}/${ARCHIVE_NAME}"
CHECKSUM_PATH="${ARCHIVE_PATH}.sha256"

step_begin "Download and verify Agent package"
log "downloading ${PACKAGE_URL}"
download "${PACKAGE_URL}" "${ARCHIVE_PATH}" agent-package-download
download "${CHECKSUM_URL}" "${CHECKSUM_PATH}" agent-checksum-download

EXPECTED_SHA256="$(awk 'NR == 1 {print tolower($1)}' "${CHECKSUM_PATH}")"
[[ "${EXPECTED_SHA256}" =~ ^[0-9a-f]{64}$ ]] || fatal "invalid checksum file: ${CHECKSUM_URL}"
ACTUAL_SHA256="$(sha256_file "${ARCHIVE_PATH}" | tr '[:upper:]' '[:lower:]')"
[[ "${ACTUAL_SHA256}" == "${EXPECTED_SHA256}" ]] || fatal "package checksum mismatch"
log "package checksum verified"

while IFS= read -r entry; do
  case "${entry}" in
    /*|../*|*/../*|*/..)
      fatal "unsafe archive entry: ${entry}"
      ;;
  esac
done < <(tar -tzf "${ARCHIVE_PATH}")

tar -xzf "${ARCHIVE_PATH}" -C "${TEMP_DIR}"
PACKAGE_ROOT="${TEMP_DIR}/${PACKAGE_NAME}"
[[ -x "${PACKAGE_ROOT}/install.sh" ]] || fatal "package install.sh not found or not executable"
step_complete

step_begin "Install Agent and register/configure device"
log "installing ${APP_NAME} ${VERSION} for linux/${ARCH}"
INSTALL_ARGS=(
  --deployment-mode sls_saas
  --license-server-url "${LICENSE_SERVER_URL}"
  --license-check-interval-seconds "${LICENSE_CHECK_INTERVAL_SECONDS}"
  --license-heartbeat-interval-seconds "${LICENSE_HEARTBEAT_INTERVAL_SECONDS}"
  --license-outage-grace-seconds "${LICENSE_OUTAGE_GRACE_SECONDS}"
  --update-manifest-url "${UPDATE_MANIFEST_URL}"
)
if [[ -n "${UPDATE_PUBLIC_KEY}" ]]; then
  INSTALL_ARGS+=(--update-public-key "${UPDATE_PUBLIC_KEY}")
fi
if [[ -n "${ENTERPRISE_ENROLLMENT_TOKEN}" ]]; then
  INSTALL_ARGS+=(--enterprise-enrollment-token "${ENTERPRISE_ENROLLMENT_TOKEN}")
else
  INSTALL_ARGS+=(
    --enterprise-id "${ENTERPRISE_ID}"
    --license-enrollment-id "${ENROLLMENT_ID}"
  )
fi
"${PACKAGE_ROOT}/install.sh" "${INSTALL_ARGS[@]}"
ENTERPRISE_ENROLLMENT_TOKEN=""
INSTALL_ARGS=()
step_complete

step_begin "Check platform and collection prerequisites"
command -v secweaver-agent >/dev/null 2>&1 || fatal "secweaver-agent was not installed in PATH"
PREFLIGHT_RC=0
secweaver-agent preflight -config /opt/secweaver-agent/etc/config.json -strict >"${TEMP_DIR}/preflight.txt" 2>&1 || PREFLIGHT_RC=$?
show_diagnostics "${TEMP_DIR}/preflight.txt"
[[ "${PREFLIGHT_RC}" == 0 ]] || exit "${PREFLIGHT_RC}"
step_complete

if [[ "${CONFIGURE_LOGTAIL}" == "1" ]]; then
  step_begin "Install or reuse Logtail (${LOGTAIL_REGION})"
  for dependency in timeout flock pgrep readlink; do
    command -v "${dependency}" >/dev/null 2>&1 || fatal "Logtail handoff requires ${dependency}"
  done
  install -d -m 0755 /run/lock
  exec 9>/run/lock/secweaver-logtail-install.lock
  flock -w 120 9 || fatal "another Logtail bootstrap is still running"
  # Persist intent before download: doctor must detect an interrupted SLS setup,
  # including the case where the collector has not been installed at all.
  SHIPPER_KIND_TEMP="$(mktemp /opt/secweaver-agent/etc/.shipper-kind.XXXXXX)"
  printf 'logtail\n' > "${SHIPPER_KIND_TEMP}"
  chmod 0600 "${SHIPPER_KIND_TEMP}"
  mv -f "${SHIPPER_KIND_TEMP}" /opt/secweaver-agent/etc/shipper-kind
  install_logtail
  step_complete
  step_begin "Configure Logtail identity and service handoff"
  configure_logtail_identity
  start_logtail
  step_complete
else
  step_skip "Logtail installation (--skip-logtail)"
  step_skip "Logtail identity/service (--skip-logtail)"
fi

if [[ "${START_SERVICE}" == "1" ]]; then
  step_begin "Start Agent service"
  command -v systemctl >/dev/null 2>&1 || fatal "systemctl not found after installation"
  systemctl enable secweaver-agent
  systemctl restart secweaver-agent
  sleep 2
  if ! systemctl is-active --quiet secweaver-agent; then
    systemctl --no-pager --full status secweaver-agent >&2 || true
    fatal "secweaver-agent service did not become active"
  fi
  step_complete
  step_begin "Verify local installation health"
  DOCTOR_RC=0
  secweaver-agent doctor -config /opt/secweaver-agent/etc/config.json >"${TEMP_DIR}/doctor.txt" 2>&1 || DOCTOR_RC=$?
  show_diagnostics "${TEMP_DIR}/doctor.txt"
  if [[ "${DOCTOR_RC}" != 0 ]]; then
    systemctl --no-pager --full status secweaver-agent >&2 || true
    exit "${DOCTOR_RC}"
  fi
  step_complete
  if [[ "${CONFIGURE_LOGTAIL}" == "1" ]]; then
    status_line OK "Agent ${VERSION} and Logtail are running."
    status_line INFO "Data Cloud must confirm machine-group heartbeat and Logstore delivery."
  else
    status_line OK "Agent ${VERSION} is running; Logtail was not configured."
  fi
else
  step_skip "Agent service start (--no-start)"
  step_skip "Running-service diagnostics (--no-start)"
  status_line OK "Agent ${VERSION} installed; service start was skipped."
fi
status_line INFO "Config: /opt/secweaver-agent/etc/config.json"
status_line INFO "Collection logs: /opt/secweaver-agent/logs"
status_line INFO "Detailed installation log: ${INSTALL_LOG}"

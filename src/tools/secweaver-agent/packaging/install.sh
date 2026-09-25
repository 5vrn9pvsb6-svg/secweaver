#!/usr/bin/env bash
set -euo pipefail

INSTALL_ROOT="${INSTALL_ROOT:-/opt/secweaver-agent}"
BIN_DIR="${BIN_DIR:-${INSTALL_ROOT}/bin}"
CONFIG_DIR="${CONFIG_DIR:-${INSTALL_ROOT}/etc}"
STATE_DIR="${STATE_DIR:-${INSTALL_ROOT}/data}"
LOG_DIR="${LOG_DIR:-${INSTALL_ROOT}/logs}"
SHIPPER_DIR="${SHIPPER_DIR:-${INSTALL_ROOT}/shipper}"
COMMAND_LINK="${COMMAND_LINK:-/usr/local/bin/secweaver-agent}"
SYSTEMD_DIR="${SYSTEMD_DIR:-/etc/systemd/system}"
INSTALL_DEPS="${INSTALL_DEPS:-1}"
REQUIRE_SYSTEMD="${REQUIRE_SYSTEMD:-1}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENTERPRISE_ID=""
DEPLOYMENT_MODE=""
ENTERPRISE_ENROLLMENT_TOKEN=""
LICENSE_SERVER_URL=""
LICENSE_ENROLLMENT_ID=""
LICENSE_CHECK_INTERVAL_SECONDS="21600"
LICENSE_HEARTBEAT_INTERVAL_SECONDS="180"
LICENSE_OUTAGE_GRACE_SECONDS="86400"
LICENSE_PROTOCOL="legacy_v1"
UPDATE_MANIFEST_URL=""
UPDATE_PUBLIC_KEY=""
UPDATE_DEVICE_ID=""
UPDATE_CA_FILE=""
UPDATE_REQUIRE_SERVER_POLICY="true"
BOOTSTRAP_CA_FILE="${SECWEAVER_BOOTSTRAP_CA_FILE:-}"
PERSISTENT_CA_FILE="${SHIPPER_DIR}/ca.crt"
LEGACY_PERSISTENT_CA_FILE="${CONFIG_DIR}/shipper/ca.crt"

usage() {
  cat <<'EOF'
Usage: sudo ./install.sh --enterprise-enrollment-token <token> --license-server-url <url>

Options:
  --deployment-mode MODE             sls_saas or es_private; upgrades preserve existing mode
  --enterprise-enrollment-token TOKEN Reusable enterprise-scoped installation credential
  --enterprise-id ID                  Legacy v1 platform-issued enterprise ID
  --license-server-url URL            WEB shield authorization server URL
  --license-enrollment-id ID          Enrollment ID used for device authorization
  --license-check-interval-seconds N  Periodic authorization recheck interval (default: 21600)
  --license-heartbeat-interval-seconds N
                                      Device heartbeat interval (default: 180)
  --license-outage-grace-seconds N    Cached authorization grace for transient outages (default: 86400)
  --update-manifest-url URL           Signed Agent update manifest HTTPS URL
  --update-public-key KEY             Trusted Ed25519 update public key in Base64
  --update-device-id ID               Legacy rollout identity; token installs derive it from enrollment
  --update-ca-file PATH               PEM CA file for the update HTTPS endpoint
  --update-require-server-policy BOOL Require Data Cloud approval (default: true)
  -h, --help                          Show this help
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --deployment-mode)
      [[ "$#" -ge 2 ]] || { usage >&2; exit 2; }
      DEPLOYMENT_MODE="$2"
      shift 2
      ;;
    --deployment-mode=*)
      DEPLOYMENT_MODE="${1#*=}"
      shift
      ;;
    --enterprise-id)
      [[ "$#" -ge 2 ]] || { usage >&2; exit 2; }
      ENTERPRISE_ID="$2"
      shift 2
      ;;
    --enterprise-id=*)
      ENTERPRISE_ID="${1#*=}"
      shift
      ;;
    --enterprise-enrollment-token)
      [[ "$#" -ge 2 ]] || { usage >&2; exit 2; }
      ENTERPRISE_ENROLLMENT_TOKEN="$2"
      shift 2
      ;;
    --enterprise-enrollment-token=*)
      ENTERPRISE_ENROLLMENT_TOKEN="${1#*=}"
      shift
      ;;
    --license-server-url)
      [[ "$#" -ge 2 ]] || { usage >&2; exit 2; }
      LICENSE_SERVER_URL="$2"
      shift 2
      ;;
    --license-server-url=*)
      LICENSE_SERVER_URL="${1#*=}"
      shift
      ;;
    --license-enrollment-id)
      [[ "$#" -ge 2 ]] || { usage >&2; exit 2; }
      LICENSE_ENROLLMENT_ID="$2"
      shift 2
      ;;
    --license-enrollment-id=*)
      LICENSE_ENROLLMENT_ID="${1#*=}"
      shift
      ;;
    --license-check-interval-seconds)
      [[ "$#" -ge 2 ]] || { usage >&2; exit 2; }
      LICENSE_CHECK_INTERVAL_SECONDS="$2"
      shift 2
      ;;
    --license-check-interval-seconds=*)
      LICENSE_CHECK_INTERVAL_SECONDS="${1#*=}"
      shift
      ;;
    --license-heartbeat-interval-seconds)
      [[ "$#" -ge 2 ]] || { usage >&2; exit 2; }
      LICENSE_HEARTBEAT_INTERVAL_SECONDS="$2"
      shift 2
      ;;
    --license-heartbeat-interval-seconds=*)
      LICENSE_HEARTBEAT_INTERVAL_SECONDS="${1#*=}"
      shift
      ;;
    --license-outage-grace-seconds)
      [[ "$#" -ge 2 ]] || { usage >&2; exit 2; }
      LICENSE_OUTAGE_GRACE_SECONDS="$2"
      shift 2
      ;;
    --license-outage-grace-seconds=*)
      LICENSE_OUTAGE_GRACE_SECONDS="${1#*=}"
      shift
      ;;
    --update-manifest-url)
      [[ "$#" -ge 2 ]] || { usage >&2; exit 2; }
      UPDATE_MANIFEST_URL="$2"
      shift 2
      ;;
    --update-manifest-url=*)
      UPDATE_MANIFEST_URL="${1#*=}"
      shift
      ;;
    --update-public-key)
      [[ "$#" -ge 2 ]] || { usage >&2; exit 2; }
      UPDATE_PUBLIC_KEY="$2"
      shift 2
      ;;
    --update-public-key=*)
      UPDATE_PUBLIC_KEY="${1#*=}"
      shift
      ;;
    --update-device-id)
      [[ "$#" -ge 2 ]] || { usage >&2; exit 2; }
      UPDATE_DEVICE_ID="$2"
      shift 2
      ;;
    --update-device-id=*)
      UPDATE_DEVICE_ID="${1#*=}"
      shift
      ;;
    --update-ca-file)
      [[ "$#" -ge 2 ]] || { usage >&2; exit 2; }
      UPDATE_CA_FILE="$2"
      shift 2
      ;;
    --update-ca-file=*)
      UPDATE_CA_FILE="${1#*=}"
      shift
      ;;
    --update-require-server-policy)
      [[ "$#" -ge 2 ]] || { usage >&2; exit 2; }
      UPDATE_REQUIRE_SERVER_POLICY="$2"
      shift 2
      ;;
    --update-require-server-policy=*)
      UPDATE_REQUIRE_SERVER_POLICY="${1#*=}"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

log() {
  echo "[secweaver-agent install] $*"
}

warn() {
  echo "[secweaver-agent install] WARN: $*" >&2
}

fatal() {
  echo "[secweaver-agent install] ERROR: $*" >&2
  exit 1
}

# The enrollment one-liner downloads its trust anchor into a temporary file
# that is deleted when the outer installer exits. Persist it before any config
# command validates an existing license/update CA path. The second destination
# keeps upgrades from layouts that used etc/shipper/ca.crt operational; new
# configurations use the product-owned shipper/ca.crt path.
persist_bootstrap_ca() {
  [[ -n "${BOOTSTRAP_CA_FILE}" ]] || return 0
  [[ -f "${BOOTSTRAP_CA_FILE}" && -r "${BOOTSTRAP_CA_FILE}" && -s "${BOOTSTRAP_CA_FILE}" ]] || \
    fatal "SECWEAVER_BOOTSTRAP_CA_FILE must be a readable non-empty regular file"

  local destination destination_dir temporary
  for destination in "${PERSISTENT_CA_FILE}" "${LEGACY_PERSISTENT_CA_FILE}"; do
    destination_dir="$(dirname "${destination}")"
    install -d -m 0700 "${destination_dir}"
    temporary="$(mktemp "${destination_dir}/.ca.crt.XXXXXX")" || \
      fatal "cannot create temporary CA file in ${destination_dir}"
    if ! install -m 0644 "${BOOTSTRAP_CA_FILE}" "${temporary}"; then
      rm -f "${temporary}"
      fatal "cannot stage bootstrap CA for ${destination}"
    fi
    if ! mv -f "${temporary}" "${destination}"; then
      rm -f "${temporary}"
      fatal "cannot install bootstrap CA at ${destination}"
    fi
  done

  # A generated installer can pass the same temporary CA as --update-ca-file.
  # Store only the durable path because the outer command removes the source.
  if [[ "${UPDATE_CA_FILE}" == "${BOOTSTRAP_CA_FILE}" ]]; then
    UPDATE_CA_FILE="${PERSISTENT_CA_FILE}"
  fi
  log "bootstrap CA installed: ${PERSISTENT_CA_FILE}"
}

[[ "${LICENSE_CHECK_INTERVAL_SECONDS}" =~ ^[0-9]+$ ]] || fatal "--license-check-interval-seconds must be an integer"
[[ "${LICENSE_HEARTBEAT_INTERVAL_SECONDS}" =~ ^[0-9]+$ ]] || fatal "--license-heartbeat-interval-seconds must be an integer"
[[ "${LICENSE_OUTAGE_GRACE_SECONDS}" =~ ^[0-9]+$ ]] || fatal "--license-outage-grace-seconds must be an integer"
(( 10#${LICENSE_OUTAGE_GRACE_SECONDS} <= 604800 )) || fatal "--license-outage-grace-seconds must not exceed 604800"

if [[ -n "${ENTERPRISE_ENROLLMENT_TOKEN}" && -n "${ENTERPRISE_ID}" ]]; then
  fatal "provide either --enterprise-enrollment-token or --enterprise-id, not both"
fi
if [[ -n "${ENTERPRISE_ENROLLMENT_TOKEN}" ]]; then
  LICENSE_PROTOCOL="device_v2"
  [[ "${ENTERPRISE_ENROLLMENT_TOKEN}" =~ ^swenr_[a-z2-7]+\.[A-Za-z0-9_-]{40,128}$ ]] || \
    fatal "--enterprise-enrollment-token has an invalid format"
  [[ "${LICENSE_SERVER_URL}" =~ ^https:// ]] || \
    fatal "--license-server-url with HTTPS is required for device enrollment"
else
  ENTERPRISE_ID="$(printf '%s' "$ENTERPRISE_ID" | tr '[:lower:]' '[:upper:]')"
  [[ "$ENTERPRISE_ID" =~ ^[A-Z0-9]{16}$ ]] || \
    fatal "--enterprise-id is required for legacy installation and must contain 16 ASCII letters or digits"
fi

need_cmd() {
  command -v "$1" >/dev/null 2>&1 && return 0
  [[ -x "/usr/sbin/$1" || -x "/sbin/$1" || -x "/usr/bin/$1" || -x "/bin/$1" ]]
}

is_systemd_running() {
  [[ -d /run/systemd/system ]] && return 0
  if [[ -r /proc/1/comm ]] && grep -qx "systemd" /proc/1/comm; then
    return 0
  fi
  if [[ -r /proc/1/exe ]] && [[ "$(readlink /proc/1/exe 2>/dev/null || true)" == *"/systemd" ]]; then
    return 0
  fi
  return 1
}

require_systemd() {
  if [[ "${REQUIRE_SYSTEMD}" == "0" || "${REQUIRE_SYSTEMD}" == "false" || "${REQUIRE_SYSTEMD}" == "no" ]]; then
    warn "systemd check skipped by REQUIRE_SYSTEMD=${REQUIRE_SYSTEMD}"
    return 0
  fi
  if ! need_cmd systemctl; then
    fatal "systemctl not found; secweaver-agent release installer currently supports systemd Linux only"
  fi
  if ! is_systemd_running; then
    local init_name="unknown"
    if [[ -r /proc/1/comm ]]; then
      init_name="$(cat /proc/1/comm 2>/dev/null || echo unknown)"
    fi
    fatal "systemd is not running as PID 1 (pid1=${init_name}); unsupported init system. Use a systemd host or run REQUIRE_SYSTEMD=0 ./install.sh to bypass this check at your own risk"
  fi
  if ! systemctl is-system-running >/dev/null 2>&1; then
    local state
    state="$(systemctl is-system-running 2>/dev/null || true)"
    case "${state}" in
      running|degraded|starting|initializing)
        ;;
      *)
        fatal "systemd is present but not usable (state=${state:-unknown})"
        ;;
    esac
  fi
}

detect_package_manager() {
  if need_cmd apt-get; then
    echo "apt"
    return 0
  fi
  if need_cmd dnf; then
    echo "dnf"
    return 0
  fi
  if need_cmd yum; then
    echo "yum"
    return 0
  fi
  if need_cmd zypper; then
    echo "zypper"
    return 0
  fi
  return 1
}

install_packages() {
  local pm="$1"
  shift
  if [[ "$#" -eq 0 ]]; then
    return 0
  fi
  log "installing packages with ${pm}: $*"
  case "${pm}" in
    apt)
      DEBIAN_FRONTEND=noninteractive apt-get update
      DEBIAN_FRONTEND=noninteractive apt-get install -y "$@"
      ;;
    dnf)
      dnf install -y "$@"
      ;;
    yum)
      yum install -y "$@"
      ;;
    zypper)
      zypper --non-interactive install "$@"
      ;;
    *)
      return 1
      ;;
  esac
}

ensure_linux_dependencies() {
  if [[ "${INSTALL_DEPS}" == "0" || "${INSTALL_DEPS}" == "false" || "${INSTALL_DEPS}" == "no" ]]; then
    log "dependency installation skipped by INSTALL_DEPS=${INSTALL_DEPS}"
    return 0
  fi
  local missing=()
  if ! need_cmd auditctl; then
    missing+=("auditd")
  fi
  if ! need_cmd netstat; then
    missing+=("net-tools")
  fi
  if [[ "${#missing[@]}" -eq 0 ]]; then
    log "dependencies already installed: auditctl, netstat"
    start_auditd_service
    return 0
  fi

  local pm
  if ! pm="$(detect_package_manager)"; then
    warn "unsupported package manager; please install auditd/auditctl and net-tools manually"
    return 1
  fi

  local packages=()
  case "${pm}" in
    apt)
      if ! need_cmd auditctl; then
        packages+=("auditd")
      fi
      if ! need_cmd netstat; then
        packages+=("net-tools")
      fi
      ;;
    dnf|yum|zypper)
      if ! need_cmd auditctl; then
        packages+=("audit")
      fi
      if ! need_cmd netstat; then
        packages+=("net-tools")
      fi
      ;;
  esac

  install_packages "${pm}" "${packages[@]}"

  if ! need_cmd auditctl; then
    warn "auditctl is still unavailable after package installation"
    return 1
  fi
  if ! need_cmd netstat; then
    warn "netstat is still unavailable after package installation"
    return 1
  fi
  start_auditd_service
}

start_auditd_service() {
  if ! need_cmd systemctl; then
    warn "systemctl not found; cannot enable/start auditd automatically"
    return 0
  fi
  if systemctl cat auditd.service >/dev/null 2>&1; then
    systemctl enable --now auditd.service || systemctl start auditd.service || true
  else
    warn "auditd.service not found in systemd unit files"
  fi
}

stop_legacy_collectors() {
  if command -v systemctl >/dev/null 2>&1; then
    local service
    for service in syslog-risk-json.service audit-port-execmon.service; do
      if systemctl cat "${service}" >/dev/null 2>&1; then
        warn "stopping legacy standalone service: ${service}"
        systemctl disable --now "${service}" || fatal "failed to stop legacy service ${service}"
      fi
    done
  fi

  if command -v pgrep >/dev/null 2>&1; then
    local legacy_processes
    legacy_processes="$(pgrep -af '(^|/)(syslog-risk-json|audit-port-execmon)([[:space:]]|$)' 2>/dev/null || true)"
    if [[ -n "${legacy_processes}" ]]; then
      printf '%s\n' "${legacy_processes}" >&2
      fatal "legacy standalone collector process is still running; stop it before installing secweaver-agent"
    fi
  fi
}

# Validate delivery ownership before stopping services or changing credentials.
# Include the legacy source when this upgrade will migrate its configuration.
MODE_CONFIG="${CONFIG_DIR}/config.json"
if [[ ! -f "${MODE_CONFIG}" && -f /etc/secweaver-agent/config.json ]]; then
  MODE_CONFIG=/etc/secweaver-agent/config.json
fi
"${ROOT_DIR}/bin/secweaver-agent" config set-deployment-mode -config "${MODE_CONFIG}" -mode "${DEPLOYMENT_MODE}" -check-only
require_systemd
stop_legacy_collectors
ensure_linux_dependencies

# Product-owned files live below one root. The command symlink and systemd unit
# are the only integration points outside this tree.
install -d -m 0755 "${INSTALL_ROOT}" "${BIN_DIR}"
install -d -m 0700 "${CONFIG_DIR}" "${STATE_DIR}" "${SHIPPER_DIR}"
install -d -m 0750 "${LOG_DIR}"
persist_bootstrap_ca

# Upgrades copy legacy state rather than moving it. The old installation stays
# available for rollback until an operator explicitly removes it.
if [[ ! -f "${CONFIG_DIR}/config.json" && -f /etc/secweaver-agent/config.json ]]; then
  install -m 0600 /etc/secweaver-agent/config.json "${CONFIG_DIR}/config.json"
  "${ROOT_DIR}/bin/secweaver-agent" config migrate-layout -platform linux -config "${CONFIG_DIR}/config.json"
  log "migrated legacy Agent configuration into ${CONFIG_DIR}"
fi
if [[ -d /var/lib/secweaver-agent ]] && [[ -z "$(find "${STATE_DIR}" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
  cp -a /var/lib/secweaver-agent/. "${STATE_DIR}/"
  log "copied legacy Agent state into ${STATE_DIR}"
fi
if [[ ! -f "${CONFIG_DIR}/config.json" ]]; then
  install -m 0600 "${ROOT_DIR}/etc/secweaver-agent/config.example.json" "${CONFIG_DIR}/config.json"
fi
"${ROOT_DIR}/bin/secweaver-agent" config set-deployment-mode -config "${CONFIG_DIR}/config.json" -mode "${DEPLOYMENT_MODE}"
if [[ -n "${ENTERPRISE_ENROLLMENT_TOKEN}" ]]; then
  log "enrolling this host with SecWeaver Data Cloud"
  # Use one successful enrollment response for both tenant and rollout identity.
  # Re-enrollment reuses the persisted device key; never invent an update ID.
  ENROLLED_IDENTITY="$("${ROOT_DIR}/bin/secweaver-agent" enroll \
    -server-url "${LICENSE_SERVER_URL}" \
    -enterprise-enrollment-token "${ENTERPRISE_ENROLLMENT_TOKEN}" \
    -state-path "${STATE_DIR}/license-state.json" \
    -identity-key-path "${STATE_DIR}/device-ed25519.key" \
    -output installer)" || \
    fatal "SecWeaver Data Cloud device enrollment failed"
  ENTERPRISE_ENROLLMENT_TOKEN=""
  [[ "${ENROLLED_IDENTITY}" =~ ^([A-Z0-9]{16})$'\t'(swd_[a-z2-7]{52})$ ]] || \
    fatal "device enrollment returned an invalid installer identity"
  ENTERPRISE_ID="${BASH_REMATCH[1]}"
  ENROLLED_DEVICE_ID="${BASH_REMATCH[2]}"
  [[ -z "${UPDATE_DEVICE_ID}" || "${UPDATE_DEVICE_ID}" == "${ENROLLED_DEVICE_ID}" ]] || \
    fatal "--update-device-id does not match the enrolled device identity"
  UPDATE_DEVICE_ID="${ENROLLED_DEVICE_ID}"
  [[ "${ENTERPRISE_ID}" =~ ^[A-Z0-9]{16}$ ]] || \
    fatal "device enrollment returned an invalid enterprise ID"
fi
"${ROOT_DIR}/bin/secweaver-agent" config set-enterprise-id \
  -config "${CONFIG_DIR}/config.json" \
  -enterprise-id "${ENTERPRISE_ID}"
"${ROOT_DIR}/bin/secweaver-agent" config ensure-host-process-snapshot \
  -config "${CONFIG_DIR}/config.json"
"${ROOT_DIR}/bin/secweaver-agent" config ensure-host-state-snapshot \
  -config "${CONFIG_DIR}/config.json"
"${ROOT_DIR}/bin/secweaver-agent" config optimize-collectors \
  -config "${CONFIG_DIR}/config.json"
if [[ -n "${LICENSE_SERVER_URL}" ]]; then
  if [[ "${LICENSE_PROTOCOL}" == "legacy_v1" ]]; then
    [[ -n "${LICENSE_ENROLLMENT_ID}" ]] || \
      fatal "legacy installation requires --license-enrollment-id with --license-server-url"
    "${ROOT_DIR}/bin/secweaver-agent" config set-license \
      -config "${CONFIG_DIR}/config.json" \
      -protocol legacy_v1 \
      -server-url "${LICENSE_SERVER_URL}" \
      -enrollment-id "${LICENSE_ENROLLMENT_ID}" \
      -check-interval-seconds "${LICENSE_CHECK_INTERVAL_SECONDS}" \
      -heartbeat-interval-seconds "${LICENSE_HEARTBEAT_INTERVAL_SECONDS}" \
      -outage-grace-seconds "${LICENSE_OUTAGE_GRACE_SECONDS}" \
      -fail-closed true
  else
    "${ROOT_DIR}/bin/secweaver-agent" config set-license \
      -config "${CONFIG_DIR}/config.json" \
      -protocol device_v2 \
      -server-url "${LICENSE_SERVER_URL}" \
      -state-path "${STATE_DIR}/license-state.json" \
      -identity-key-path "${STATE_DIR}/device-ed25519.key" \
      -check-interval-seconds "${LICENSE_CHECK_INTERVAL_SECONDS}" \
      -heartbeat-interval-seconds "${LICENSE_HEARTBEAT_INTERVAL_SECONDS}" \
      -outage-grace-seconds "${LICENSE_OUTAGE_GRACE_SECONDS}" \
      -fail-closed true
  fi
elif [[ -n "${LICENSE_ENROLLMENT_ID}" ]]; then
  fatal "--license-enrollment-id requires --license-server-url"
fi
if [[ -n "${UPDATE_PUBLIC_KEY}" && -z "${UPDATE_MANIFEST_URL}" ]]; then
  fatal "--update-manifest-url is required when --update-public-key is set"
fi
if [[ -n "${UPDATE_MANIFEST_URL}" ]]; then
  [[ "${UPDATE_MANIFEST_URL}" =~ ^https:// ]] || fatal "--update-manifest-url must use HTTPS"
  [[ -z "${UPDATE_PUBLIC_KEY}" || "${UPDATE_PUBLIC_KEY}" =~ ^[A-Za-z0-9+/]{43}=$ ]] || fatal "--update-public-key must be a base64 Ed25519 public key"
  [[ -n "${UPDATE_DEVICE_ID}" ]] || fatal "--update-device-id is required when updates are enabled"
  [[ "${UPDATE_REQUIRE_SERVER_POLICY}" == "true" || "${UPDATE_REQUIRE_SERVER_POLICY}" == "false" ]] || fatal "--update-require-server-policy must be true or false"
  update_args=(
    -config "${CONFIG_DIR}/config.json"
    -manifest-url "${UPDATE_MANIFEST_URL}"
    -device-id "${UPDATE_DEVICE_ID}"
    -channel stable
    -auto-install true
    -require-server-policy "${UPDATE_REQUIRE_SERVER_POLICY}"
    -health-timeout-seconds 90
  )
  if [[ -n "${UPDATE_PUBLIC_KEY}" ]]; then
    update_args+=( -public-key "${UPDATE_PUBLIC_KEY}" )
  fi
  if [[ -n "${UPDATE_CA_FILE}" ]]; then
    update_args+=( -ca-file "${UPDATE_CA_FILE}" )
  fi
  "${ROOT_DIR}/bin/secweaver-agent" config set-update \
    "${update_args[@]}"
fi
install -m 0755 "${ROOT_DIR}/bin/secweaver-agent" "${BIN_DIR}/secweaver-agent"
install -m 0755 "${ROOT_DIR}/libexec/secweaver-agent-launch" "${BIN_DIR}/secweaver-agent-launch"
# Keep the destructive lifecycle entrypoint inside the product-owned tree. The
# archive-root copy is only the package bootstrap input; upgrades and operators
# must have one stable path that survives the current working directory.
install -m 0755 "${ROOT_DIR}/uninstall.sh" "${BIN_DIR}/uninstall.sh"
install -d -m 0755 "$(dirname "${COMMAND_LINK}")"
ln -sfn "${BIN_DIR}/secweaver-agent" "${COMMAND_LINK}"
if [[ ! -f "${CONFIG_DIR}/audit-port-execmon.json" ]]; then
  if [[ -f /etc/secweaver-agent/audit-port-execmon.json ]]; then
    install -m 0600 /etc/secweaver-agent/audit-port-execmon.json "${CONFIG_DIR}/audit-port-execmon.json"
    "${BIN_DIR}/secweaver-agent" config migrate-layout -platform linux -config "${CONFIG_DIR}/audit-port-execmon.json"
  else
    install -m 0600 "${ROOT_DIR}/etc/secweaver-agent/audit-port-execmon.example.json" "${CONFIG_DIR}/audit-port-execmon.json"
  fi
fi
if [[ ! -f "${CONFIG_DIR}/host-persistence.json" ]]; then
  if [[ -f /etc/secweaver-agent/host-persistence.json ]]; then
    install -m 0600 /etc/secweaver-agent/host-persistence.json "${CONFIG_DIR}/host-persistence.json"
    "${BIN_DIR}/secweaver-agent" config migrate-layout -platform linux -config "${CONFIG_DIR}/host-persistence.json"
  else
    install -m 0600 "${ROOT_DIR}/etc/secweaver-agent/host-persistence.example.json" "${CONFIG_DIR}/host-persistence.json"
  fi
fi

if [[ -d "${SYSTEMD_DIR}" ]]; then
  install -m 0644 "${ROOT_DIR}/systemd/secweaver-agent.service" "${SYSTEMD_DIR}/secweaver-agent.service"
  if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
  fi
  log "systemd unit installed: ${SYSTEMD_DIR}/secweaver-agent.service"
  log "enable with: sudo systemctl enable --now secweaver-agent"
fi

log "installation root: ${INSTALL_ROOT}"
log "installed: ${BIN_DIR}/secweaver-agent"
log "command link: ${COMMAND_LINK}"
log "config: ${CONFIG_DIR}/config.json"
log "state: ${STATE_DIR}"
log "logs: ${LOG_DIR}"
log "audit module config: ${CONFIG_DIR}/audit-port-execmon.json"
log "host persistence config: ${CONFIG_DIR}/host-persistence.json"

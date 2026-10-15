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
AUDIT_TUNE="${AUDIT_TUNE:-1}"
REQUIRE_SYSTEMD="${REQUIRE_SYSTEMD:-1}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENTERPRISE_ID=""
DEPLOYMENT_MODE=""
LEARNING_MODE="preserve"
ENTERPRISE_ENROLLMENT_TOKEN=""
LICENSE_SERVER_URL=""
LICENSE_ENROLLMENT_ID=""
LICENSE_CHECK_INTERVAL_SECONDS="21600"
# Zero preserves an existing interval; the Agent initializes new hosts at 300s.
LICENSE_HEARTBEAT_INTERVAL_SECONDS="0"
LICENSE_OUTAGE_GRACE_SECONDS="86400"
LICENSE_PROTOCOL="legacy_v1"
UPDATE_MANIFEST_URL=""
UPDATE_PUBLIC_KEY=""
UPDATE_DEVICE_ID=""
UPDATE_CA_FILE=""
UPDATE_USE_SYSTEM_CA=0
UPDATE_REQUIRE_SERVER_POLICY="true"
BOOTSTRAP_CA_FILE="${SECWEAVER_BOOTSTRAP_CA_FILE:-}"
PERSISTENT_CA_FILE="${SHIPPER_DIR}/ca.crt"
LEGACY_PERSISTENT_CA_FILE="${CONFIG_DIR}/shipper/ca.crt"
# Set during dependency detection. The value is persisted in the module JSON
# only after the product-owned configuration has been copied into place.
AUDIT_RUNTIME_MODE="auto"

usage() {
  cat <<'EOF'
Usage: sudo ./install.sh --enterprise-enrollment-token <token> --license-server-url <url>

Options:
  --deployment-mode MODE             sls_saas or es_private; upgrades preserve existing mode
  --learning-mode MODE              preserve, shadow, enable, or disable; default: preserve
  --enterprise-enrollment-token TOKEN Reusable enterprise-scoped installation credential
  --enterprise-id ID                  Legacy v1 platform-issued enterprise ID
  --license-server-url URL            WEB shield authorization server URL
  --license-enrollment-id ID          Enrollment ID used for device authorization
  --license-check-interval-seconds N  Periodic authorization recheck interval (default: 21600)
  --license-heartbeat-interval-seconds N
                                      Device heartbeat interval (new host: 300; preserve existing by default)
  --license-outage-grace-seconds N    Cached authorization grace for transient outages (default: 86400)
  --update-manifest-url URL           Signed Agent update manifest HTTPS URL
  --update-public-key KEY             Trusted Ed25519 update public key in Base64
  --update-device-id ID               Legacy rollout identity; token installs derive it from enrollment
  --update-ca-file PATH               PEM CA file for the update HTTPS endpoint
  --update-use-system-ca              Explicitly clear an existing update CA override
  --update-require-server-policy BOOL Require Data Cloud approval (default: true)
  -h, --help                          Show this help

Environment:
  AUDIT_TUNE=0                       Preserve host audit queues (default: raise small queues)
  INSTALL_DEPS=0                     Skip dependency and audit service/configuration management
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
    --learning-mode)
      [[ "$#" -ge 2 ]] || { usage >&2; exit 2; }
      LEARNING_MODE="$2"
      shift 2
      ;;
    --learning-mode=*)
      LEARNING_MODE="${1#*=}"
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
    --update-use-system-ca)
      UPDATE_USE_SYSTEM_CA=1
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
case "${LEARNING_MODE}" in
  preserve|shadow|enable|disable) ;;
  *) fatal "--learning-mode must be preserve, shadow, enable, or disable" ;;
esac

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

# auditctl -s is the usable-kernel check, not merely a binary existence check.
# Kylin and hardened images can ship auditctl while booting with audit=0; in
# that case attempting queue tuning or auditd lifecycle operations is invalid.
audit_kernel_control_available() {
  need_cmd auditctl || return 1
  local status
  status="$(timeout --kill-after=5s 10s auditctl -s 2>/dev/null || true)"
  [[ "${status}" =~ (^|[[:space:]])enabled[[:space:]]+(1|2)([[:space:]]|$) ]]
}

# This is intentionally a conservative prerequisite probe. The actual Agent
# startup still performs the CO-RE verifier/attach check, so a false positive
# fails with the kernel's concrete reason instead of silently selecting audit.
ebpf_kernel_prerequisites_available() {
  local arch
  arch="$(uname -m 2>/dev/null || true)"
  case "${arch}" in
    x86_64|amd64|aarch64|arm64) ;;
    *) return 1 ;;
  esac
  [[ -r /sys/kernel/btf/vmlinux ]] || return 1
  local group name group_name
  for group_name in "syscalls sys_enter_execve" "syscalls sys_exit_execve" "sched sched_process_exec"; do
    read -r group name <<<"${group_name}"
    [[ -r "/sys/kernel/tracing/events/${group}/${name}/format" || -r "/sys/kernel/debug/tracing/events/${group}/${name}/format" ]] || return 1
  done
}

detect_linux_collection_mode() {
  if audit_kernel_control_available; then
    AUDIT_RUNTIME_MODE="auto"
    return 0
  fi
  if ebpf_kernel_prerequisites_available; then
    AUDIT_RUNTIME_MODE="ebpf_only"
    if [[ -r /proc/cmdline ]] && grep -Eq '(^|[[:space:]])audit=0([[:space:]]|$)' /proc/cmdline; then
      log "audit kernel support disabled by boot parameter audit=0; selecting product eBPF-only mode"
    else
      log "audit kernel control unavailable; selecting product eBPF-only mode"
    fi
    return 0
  fi
  return 1
}

# A stopped daemon can expose enabled=0 or pid=0, but a failed netlink status
# means the current kernel cannot provide Audit. Do not try auditd lifecycle
# operations merely because the installed auditctl binary has a version string.
prepare_linux_collection_mode() {
  if detect_linux_collection_mode; then
    [[ "${AUDIT_RUNTIME_MODE}" == "ebpf_only" ]] || start_auditd_service
    return 0
  fi
  local status
  status="$(timeout --kill-after=5s 10s auditctl -s 2>/dev/null || true)"
  if [[ "${status}" =~ (^|[[:space:]])enabled[[:space:]]+0([[:space:]]|$) ]]; then
    start_auditd_service
    detect_linux_collection_mode && return 0
  fi
  fatal "Linux collection unavailable: kernel Audit is not usable and required eBPF BTF/tracepoints are missing; enable Audit at boot or use an eBPF-capable kernel"
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
    detect_linux_collection_mode || fatal "Linux collection unavailable: auditctl -s is not usable and required eBPF BTF/tracepoints are missing"
    return 0
  fi
  local ebpf_ready=0
  ebpf_kernel_prerequisites_available && ebpf_ready=1 || true
  local missing=()
  if ! need_cmd auditctl && [[ "${ebpf_ready}" -eq 0 ]]; then
    missing+=("auditd")
  fi
  if ! need_cmd netstat; then
    missing+=("net-tools")
  fi
  if [[ "${#missing[@]}" -eq 0 ]]; then
    log "dependencies already installed: $(need_cmd auditctl && echo auditctl || echo eBPF-runtime), netstat"
    prepare_linux_collection_mode
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
      if ! need_cmd auditctl && [[ "${ebpf_ready}" -eq 0 ]]; then
        packages+=("auditd")
      fi
      if ! need_cmd netstat; then
        packages+=("net-tools")
      fi
      ;;
    dnf|yum|zypper)
      if ! need_cmd auditctl && [[ "${ebpf_ready}" -eq 0 ]]; then
        packages+=("audit")
      fi
      if ! need_cmd netstat; then
        packages+=("net-tools")
      fi
      ;;
  esac

  install_packages "${pm}" "${packages[@]}"

  if ! need_cmd auditctl && [[ "${ebpf_ready}" -eq 0 ]]; then
    warn "auditctl is still unavailable after package installation"
    return 1
  fi
  if ! need_cmd netstat; then
    warn "netstat is still unavailable after package installation"
    return 1
  fi
  prepare_linux_collection_mode
}

# Read only active numeric directives. Refuse ambiguous/invalid configuration
# rather than silently repairing unrelated syntax. Backlog directives can occur
# repeatedly in rule files; q_depth must have one unambiguous effective value.
audit_queue_values() {
  local file="$1" kind="$2"
  [[ ! -L "${file}" ]] || return 1
  if [[ ! -e "${file}" ]]; then
    printf '0 0 0\n'
    return 0
  fi
  [[ -f "${file}" && -r "${file}" ]] || return 1
  [[ "$(wc -c <"${file}")" -le 1048576 ]] || return 1
  LC_ALL=C awk -v kind="${kind}" '
    /^[[:space:]]*(#|$)/ { next }
    {
      line = $0
      if (kind == "q_depth") {
        if (line !~ /^[[:space:]]*q_depth([[:space:]]|=|$)/) next
        sub(/^[[:space:]]*q_depth[[:space:]]*=[[:space:]]*/, "", line)
      } else {
        if (line !~ /^[[:space:]]*-b/) next
        sub(/^[[:space:]]*-b[[:space:]]*/, "", line)
      }
      sub(/[[:space:]]*#.*$/, "", line)
      sub(/[[:space:]]+$/, "", line)
      if (line !~ /^[0-9]+$/ || line + 0 > 4294967295) { invalid = 1; next }
      value = line + 0
      if (!count || value < minimum) minimum = value
      if (value > maximum) maximum = value
      count++
    }
    END {
      if (invalid || (kind == "q_depth" && count > 1)) exit 1
      printf "%d %.0f %.0f\n", count, minimum, maximum
    }
  ' "${file}"
}

# Replace only smaller queue directives, preserving comments and all other
# audit policy. Same-directory staging makes publication atomic; cp -a retains
# ownership, permissions and Linux security metadata. A concurrent operator
# edit aborts publication instead of being overwritten. Backups never match the
# *.rules glob, so neither auditctl nor augenrules will load them accidentally.
audit_queue_raise() {
  local file="$1" kind="$2" floor="$3" values count minimum maximum temporary backup=""
  values="$(audit_queue_values "${file}" "${kind}")" || {
    warn "audit queue configuration is ambiguous, oversized or not a regular file: ${file}; unchanged"
    return 0
  }
  read -r count minimum maximum <<<"${values}"
  if [[ "${count}" -gt 0 && "${minimum}" -ge "${floor}" ]]; then
    log "audit queue: ${kind} preserved (minimum=${minimum}, maximum=${maximum}, file=${file})"
    return 0
  fi
  temporary="$(mktemp "$(dirname "${file}")/.secweaver-audit-stage.XXXXXX")" || \
    fatal "cannot stage audit queue configuration: ${file}"
  if [[ -e "${file}" ]]; then
    backup="$(mktemp "${file}.secweaver-backup.XXXXXX")" || {
      rm -f "${temporary}"
      fatal "cannot back up audit queue configuration: ${file}"
    }
    if ! cp -a "${file}" "${backup}" || ! cp -a "${file}" "${temporary}"; then
      rm -f "${temporary}"
      fatal "cannot preserve audit queue configuration metadata: ${file}; backup=${backup}"
    fi
  else
    chmod 0600 "${temporary}"
  fi
  if ! LC_ALL=C awk -v kind="${kind}" -v floor="${floor}" -v missing="${count}" '
    BEGIN {
      # A directly loaded rules file can finish with immutable -e 2. A new -b
      # must precede that lock instead of being appended after it.
      if (kind == "backlog" && missing == 0) print "-b " floor
    }
    {
      line = $0
      if (kind == "q_depth" && line ~ /^[[:space:]]*q_depth[[:space:]]*=/) {
        seen = 1
        value = line; sub(/^[^=]*=[[:space:]]*/, "", value)
        if (value + 0 < floor) sub(/[0-9]+/, floor, line)
      } else if (kind == "backlog" && line ~ /^[[:space:]]*-b[[:space:]]*[0-9]/) {
        seen = 1
        value = line; sub(/^[[:space:]]*-b[[:space:]]*/, "", value)
        if (value + 0 < floor) sub(/[0-9]+/, floor, line)
      }
      print line
    }
    END {
      if (!seen && kind == "q_depth") print "q_depth = " floor
    }
  ' "${backup:-/dev/null}" >"${temporary}"; then
    rm -f "${temporary}"
    fatal "cannot write audit queue configuration: ${file}; backup=${backup:-none}"
  fi
  if [[ -n "${backup}" ]]; then
    if ! cmp -s "${file}" "${backup}"; then
      rm -f "${temporary}"
      fatal "audit queue configuration changed during installation: ${file}; retry after reviewing backup=${backup}"
    fi
  elif [[ -e "${file}" || -L "${file}" ]]; then
    rm -f "${temporary}"
    fatal "audit queue configuration appeared during installation: ${file}"
  fi
  if [[ "${kind}" == q_depth ]]; then
    # Record intent before publication: interruption or a failed reload must not
    # let the next install confuse an adequate on-disk value with applied state.
    [[ ! -L "${AUDIT_DISPATCHER_PENDING}" ]] && \
      [[ ! -e "${AUDIT_DISPATCHER_PENDING}" || -f "${AUDIT_DISPATCHER_PENDING}" ]] || \
      fatal "unsafe audit dispatcher pending marker: ${AUDIT_DISPATCHER_PENDING}"
    local pending_stage
    pending_stage="$(mktemp "${file}.secweaver-reload-stage.XXXXXX")" || \
      fatal "cannot stage audit dispatcher pending marker: ${file}"
    chmod 0600 "${pending_stage}" && mv -f "${pending_stage}" "${AUDIT_DISPATCHER_PENDING}" || {
      rm -f "${pending_stage}" "${temporary}"
      fatal "cannot record audit dispatcher pending reload: ${file}"
    }
  fi
  if ! mv -f "${temporary}" "${file}"; then
    rm -f "${temporary}"
    fatal "cannot publish audit queue configuration: ${file}; backup=${backup:-none}"
  fi
  # A newly created rules file must get the native SELinux label before a future
  # daemon start; existing files retained their original label through staging.
  if [[ -z "${backup}" ]] && need_cmd restorecon; then
    restorecon "${file}" || fatal "cannot restore audit queue configuration label: ${file}"
  fi
  log "audit queue: ${kind} raised to ${floor} (file=${file}, backup=${backup:-new-file})"
  if [[ "${kind}" == "q_depth" ]]; then
    AUDIT_DISPATCHER_CHANGED=1
    AUDIT_DISPATCHER_BACKUP="${backup}"
  fi
}

# Audit 2.x has a separate audispd; 3.x/4.x integrate the dispatcher into auditd.
# Prepare only native layouts and never edit restart limits, failure actions or
# plugin bindings. Tune both generated audit.rules and its source -b directives
# without loading the full ruleset, which could delete another collector's rules.
prepare_audit_queues() {
  local audit_conf="$1" audisp_conf="$2" rules_dir="$3"
  local version status values count minimum maximum file dispatcher dispatcher_conf="" direct_rules
  local files=() backlog_source=0
  AUDIT_DISPATCHER_CHANGED=0
  AUDIT_DISPATCHER_BACKUP=""
  AUDIT_DISPATCHER_PENDING=""
  AUDIT_BACKLOG_FLOOR=0
  case "${AUDIT_TUNE}" in
    0|false|no) log "audit queue tuning disabled by AUDIT_TUNE=${AUDIT_TUNE}"; return 0 ;;
    1|true|yes) ;;
    *) fatal "AUDIT_TUNE must be 1/0, true/false or yes/no" ;;
  esac
  [[ -f "${audit_conf}" && ! -L "${audit_conf}" ]] || \
    fatal "native auditd configuration is missing or symlinked: ${audit_conf}; use AUDIT_TUNE=0 for an operator-managed layout"
  version="$(timeout --kill-after=5s 10s auditctl -v 2>&1)" || \
    fatal "cannot determine audit version before queue tuning"
  if [[ "${version}" =~ auditctl[[:space:]]+version[[:space:]]+2\. ]]; then
    dispatcher="$(awk -F= '/^[[:space:]]*dispatcher[[:space:]]*=/ {value=$2; gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)} END {print value}' "${audit_conf}")"
    if [[ "${dispatcher}" == /sbin/audispd || "${dispatcher}" == /usr/sbin/audispd ]] && [[ -f "${audisp_conf}" ]]; then
      dispatcher_conf="${audisp_conf}"
    else
      warn "audit 2.x dispatcher is disabled/custom or its configuration is missing; q_depth unchanged"
    fi
  elif [[ "${version}" =~ auditctl[[:space:]]+version[[:space:]]+[34]\. ]]; then
    dispatcher_conf="${audit_conf}"
  else
    warn "unsupported audit version for dispatcher tuning; q_depth unchanged: ${version}"
  fi
  status="$(timeout --kill-after=5s 10s auditctl -s)" || \
    fatal "cannot read kernel audit queue status"
  AUDIT_BACKLOG_FLOOR="$(awk '$1 == "backlog_limit" {print $2}' <<<"${status}")"
  [[ "${AUDIT_BACKLOG_FLOOR}" =~ ^[0-9]{1,10}$ ]] && \
    (( 10#${AUDIT_BACKLOG_FLOOR} <= 4294967295 )) || fatal "invalid audit backlog_limit"
  AUDIT_BACKLOG_FLOOR="$((10#${AUDIT_BACKLOG_FLOOR}))"
  (( AUDIT_BACKLOG_FLOOR >= 8192 )) || AUDIT_BACKLOG_FLOOR=8192
  [[ ! -L "${rules_dir}" ]] || fatal "refusing to tune a symlinked audit rules directory: ${rules_dir}"
  direct_rules="$(dirname "${audit_conf}")/audit.rules"
  [[ ! -e "${direct_rules}" && ! -L "${direct_rules}" ]] || files+=("${direct_rules}")
  for file in "${rules_dir}/"*.rules; do
    [[ -e "${file}" || -L "${file}" ]] || continue
    files+=("${file}")
  done
  [[ "${#files[@]}" -le 256 ]] || fatal "too many audit rule files for automatic queue tuning; use AUDIT_TUNE=0"
  # Plan the complete floor before publishing: an existing larger persistent
  # value anywhere in the native ruleset must never be lowered by this installer.
  for file in ${files[@]+"${files[@]}"}; do
    values="$(audit_queue_values "${file}" backlog)" || \
      fatal "cannot safely inspect audit backlog policy: ${file}; use AUDIT_TUNE=0 after review"
    read -r count minimum maximum <<<"${values}"
    if [[ "${count}" -gt 0 ]]; then
      [[ "${file}" == "${direct_rules}" ]] || backlog_source=1
      (( maximum <= AUDIT_BACKLOG_FLOOR )) || AUDIT_BACKLOG_FLOOR="${maximum}"
    fi
  done
  if [[ -n "${dispatcher_conf}" ]]; then
    AUDIT_DISPATCHER_PENDING="${dispatcher_conf}.secweaver-reload-required"
    [[ ! -L "${AUDIT_DISPATCHER_PENDING}" ]] && \
      [[ ! -e "${AUDIT_DISPATCHER_PENDING}" || -f "${AUDIT_DISPATCHER_PENDING}" ]] || \
      fatal "unsafe audit dispatcher pending marker: ${AUDIT_DISPATCHER_PENDING}"
    audit_queue_raise "${dispatcher_conf}" q_depth 2000
    if [[ -f "${AUDIT_DISPATCHER_PENDING}" ]]; then
      AUDIT_DISPATCHER_CHANGED=1
      log "audit queue: dispatcher reload pending (marker=${AUDIT_DISPATCHER_PENDING})"
    fi
  fi
  for file in ${files[@]+"${files[@]}"}; do
    values="$(audit_queue_values "${file}" backlog)"
    read -r count minimum maximum <<<"${values}"
    [[ "${count}" -eq 0 ]] || audit_queue_raise "${file}" backlog "${AUDIT_BACKLOG_FLOOR}"
  done
  if [[ "${backlog_source}" -eq 0 && -d "${rules_dir}" ]]; then
    audit_queue_raise "${rules_dir}/70-secweaver-backlog.rules" backlog "${AUDIT_BACKLOG_FLOOR}"
  fi
  if [[ -f "${direct_rules}" ]]; then
    # Generated policy is not an augenrules source. Conversely, a source -b does
    # not cover a direct auditctl -R loader: both native paths must persist it.
    values="$(audit_queue_values "${direct_rules}" backlog)"
    read -r count minimum maximum <<<"${values}"
    [[ "${count}" -gt 0 ]] || audit_queue_raise "${direct_rules}" backlog "${AUDIT_BACKLOG_FLOOR}"
  elif [[ ! -d "${rules_dir}" ]]; then
    warn "no native audit rules location found; backlog change will not persist across reboot"
  fi
}

# RHEL/CentOS packages may ship only legacy-actions, with no /etc/init.d/auditd
# and no ExecReload in their unit. Resolve the requested action, not just the
# init script. Direct auditctl signalling is supported only when advertised;
# never convert an unsupported reload into a restart or send an unverified PID.
auditd_lifecycle_command() {
  local action="$1" can_reload help
  AUDIT_SERVICE_COMMAND=(systemctl "${action}" auditd.service)
  if need_cmd service && { [[ -x /etc/init.d/auditd ]] || \
      [[ -x "/usr/libexec/initscripts/legacy-actions/auditd/${action}" ]]; }; then
    AUDIT_SERVICE_COMMAND=(service auditd "${action}")
  elif [[ "${action}" == reload ]]; then
    can_reload="$(timeout --kill-after=5s 10s systemctl show -p CanReload auditd.service)" || \
      fatal "cannot inspect auditd reload support; pending marker=${AUDIT_DISPATCHER_PENDING:-none}"
    if [[ "${can_reload}" != CanReload=yes ]]; then
      help="$(LC_ALL=C timeout --kill-after=5s 10s auditctl -h 2>&1)" || help=""
      if [[ "${help}" == *--signal* ]]; then
        AUDIT_SERVICE_COMMAND=(auditctl --signal reload)
      else
        fatal "auditd has no supported reload interface (CanReload=${can_reload#*=}); install the native auditd legacy-action/service helper; dispatcher backup=${AUDIT_DISPATCHER_BACKUP:-none}; pending marker=${AUDIT_DISPATCHER_PENDING:-none}"
      fi
    fi
  fi
}

# A running daemon is only reloaded, never restarted/killed, preserving live
# audit rules. Pending intent survives failed/interrupted installs and is cleared
# only after successful lifecycle and kernel verification. A reload command's
# success does not prove asynchronous dispatcher configuration was accepted.
start_auditd_service() {
  if ! need_cmd systemctl; then
    warn "systemctl not found; cannot enable/start auditd automatically"
    return 0
  fi
  need_cmd timeout || fatal "timeout is required for bounded audit service setup"
  if ! timeout --kill-after=5s 10s systemctl cat auditd.service >/dev/null 2>&1; then
    fatal "auditd.service is unavailable; inspect systemctl status auditd; use INSTALL_DEPS=0 only for verified operator-managed audit"
  fi
  prepare_audit_queues "/etc/audit/auditd.conf" "/etc/audisp/audispd.conf" "/etc/audit/rules.d"
  timeout --kill-after=5s 30s systemctl enable auditd.service || fatal "cannot enable auditd.service"
  local action=start status pid enabled backlog
  if timeout --kill-after=5s 10s systemctl is-active --quiet auditd.service; then
    if [[ "${AUDIT_DISPATCHER_CHANGED}" -eq 1 ]]; then
      action=reload
    else
      action=""
    fi
  fi
  if [[ -n "${action}" ]]; then
    auditd_lifecycle_command "${action}"
    log "audit queue: lifecycle command=${AUDIT_SERVICE_COMMAND[*]}"
    timeout --kill-after=5s 30s "${AUDIT_SERVICE_COMMAND[@]}" || \
      fatal "auditd ${action} failed; inspect journalctl -u auditd; dispatcher backup=${AUDIT_DISPATCHER_BACKUP:-none}; pending marker=${AUDIT_DISPATCHER_PENDING:-none}"
  fi
  timeout --kill-after=5s 10s systemctl is-active --quiet auditd.service || fatal "auditd.service is not active after setup"
  status="$(timeout --kill-after=5s 10s auditctl -s)" || fatal "cannot verify auditd after setup"
  pid="$(awk '$1 == "pid" {print $2}' <<<"${status}")"
  enabled="$(awk '$1 == "enabled" {print $2}' <<<"${status}")"
  [[ "${pid}" =~ ^[0-9]+$ && "${pid}" != 0 ]] && [[ "${enabled}" == 1 || "${enabled}" == 2 ]] || \
    fatal "auditd is not registered/enabled in the kernel (pid=${pid:-unknown}, enabled=${enabled:-unknown})"
  if [[ "${AUDIT_BACKLOG_FLOOR}" -gt 0 ]]; then
    backlog="$(awk '$1 == "backlog_limit" {print $2}' <<<"${status}")"
    [[ "${backlog}" =~ ^[0-9]{1,10}$ ]] && (( 10#${backlog} <= 4294967295 )) || fatal "invalid audit backlog_limit after service setup"
    backlog="$((10#${backlog}))"
    if (( backlog < AUDIT_BACKLOG_FLOOR )); then
      if [[ "${enabled}" == 2 ]]; then
        warn "audit policy is immutable; backlog floor=${AUDIT_BACKLOG_FLOOR} saved for the next reboot"
      else
        timeout --kill-after=5s 10s auditctl -b "${AUDIT_BACKLOG_FLOOR}" || fatal "cannot raise live audit backlog; existing rules were not reloaded"
        status="$(timeout --kill-after=5s 10s auditctl -s)" || fatal "cannot verify updated audit backlog"
        backlog="$(awk '$1 == "backlog_limit" {print $2}' <<<"${status}")"
        [[ "${backlog}" =~ ^[0-9]{1,10}$ ]] && (( 10#${backlog} >= AUDIT_BACKLOG_FLOOR && 10#${backlog} <= 4294967295 )) || fatal "audit backlog update was not applied"
        log "audit queue: kernel backlog_limit=${backlog} verified"
      fi
    fi
  fi
  if [[ -n "${AUDIT_DISPATCHER_PENDING}" && -f "${AUDIT_DISPATCHER_PENDING}" ]]; then
    rm -f "${AUDIT_DISPATCHER_PENDING}" || fatal "cannot clear verified audit dispatcher pending reload: ${AUDIT_DISPATCHER_PENDING}"
    log "audit queue: dispatcher lifecycle accepted; verify asynchronous reload in auditd journal"
  fi
  log "auditd service ready (pid=${pid}, enabled=${enabled})"
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
ensure_linux_dependencies
# Verify the real embedded programs before enrollment, binary replacement or
# stopping an existing collector. BTF/tracepoint presence alone cannot prove
# verifier/helper/privilege compatibility on vendor kernels.
COLLECTION_CONFIG="${CONFIG_DIR}/audit-port-execmon.json"
if [[ ! -f "${COLLECTION_CONFIG}" ]]; then
  COLLECTION_CONFIG="${ROOT_DIR}/etc/secweaver-agent/audit-port-execmon.example.json"
  [[ ! -f /etc/secweaver-agent/audit-port-execmon.json ]] || COLLECTION_CONFIG=/etc/secweaver-agent/audit-port-execmon.json
fi
"${ROOT_DIR}/bin/secweaver-agent" config check-linux-collection -config "${COLLECTION_CONFIG}" || \
  fatal "Linux collection verification failed; device was not enrolled and Agent binary was not replaced"
stop_legacy_collectors

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
    # Go boolean flags need '='; a separate value stops parsing before trust.
    -auto-install=true
    "-require-server-policy=${UPDATE_REQUIRE_SERVER_POLICY}"
    -health-timeout-seconds 90
  )
  if [[ -n "${UPDATE_PUBLIC_KEY}" ]]; then
    update_args+=( -public-key "${UPDATE_PUBLIC_KEY}" )
  fi
  if [[ -n "${UPDATE_CA_FILE}" ]]; then
    update_args+=( -ca-file "${UPDATE_CA_FILE}" )
  fi
  if [[ "${UPDATE_USE_SYSTEM_CA}" == 1 ]]; then
    update_args+=( -use-system-ca )
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
# Keep legacy configs unchanged by default. Explicit activation alters only the
# learning enabled/shadow switches, never the baseline generation or scope.
"${BIN_DIR}/secweaver-agent" config set-learning-mode \
  -config "${CONFIG_DIR}/audit-port-execmon.json" \
  -mode "${LEARNING_MODE}"
if [[ ! -f "${CONFIG_DIR}/host-persistence.json" ]]; then
  if [[ -f /etc/secweaver-agent/host-persistence.json ]]; then
    install -m 0600 /etc/secweaver-agent/host-persistence.json "${CONFIG_DIR}/host-persistence.json"
    "${BIN_DIR}/secweaver-agent" config migrate-layout -platform linux -config "${CONFIG_DIR}/host-persistence.json"
  else
    install -m 0600 "${ROOT_DIR}/etc/secweaver-agent/host-persistence.example.json" "${CONFIG_DIR}/host-persistence.json"
  fi
fi
if [[ "${AUDIT_RUNTIME_MODE}" == "ebpf_only" ]]; then
  # Persist only the transport choice. The supervisor disables persistence
  # Audit enrichment in memory; custom policy and learning state stay intact.
  "${BIN_DIR}/secweaver-agent" config set-audit-mode \
    -config "${CONFIG_DIR}/audit-port-execmon.json" \
    -mode ebpf_only \
    -auto-only || \
    fatal "cannot persist product eBPF-only mode"
  log "collection mode: eBPF-only (audit kernel interface unavailable)"
else
  log "collection mode: audit-capable (auditd backend remains available)"
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

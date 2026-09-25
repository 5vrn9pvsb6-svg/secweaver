#!/usr/bin/env bash
set -euo pipefail

INSTALL_ROOT="${INSTALL_ROOT:-/opt/secweaver-agent}"
BIN_DIR="${BIN_DIR:-${INSTALL_ROOT}/bin}"
CONFIG_DIR="${CONFIG_DIR:-${INSTALL_ROOT}/etc}"
SYSTEMD_DIR="${SYSTEMD_DIR:-/etc/systemd/system}"
STATE_DIR="${STATE_DIR:-${INSTALL_ROOT}/data}"
LOG_DIR="${LOG_DIR:-${INSTALL_ROOT}/logs}"
SHIPPER_DIR="${SHIPPER_DIR:-${INSTALL_ROOT}/shipper}"
COMMAND_LINK="${COMMAND_LINK:-/usr/local/bin/secweaver-agent}"
SERVICE_NAME="${SERVICE_NAME:-secweaver-agent.service}"
SHIPPER_SERVICE_NAME="${SHIPPER_SERVICE_NAME:-secweaver-agent-shipper.service}"
REMOVE_BINARY=1
REMOVE_CONFIG=0
REMOVE_STATE=0
REMOVE_LOGS=0
CLEAN_AUDIT_RULES=1
JSON_OUTPUT=0
REMOVE_LOGTAIL=0
REMOVE_FILEBEAT=0
# Explicit opt-in is required because standalone collectors may serve other apps.
LOGTAIL_ROOT="${LOGTAIL_ROOT:-/usr/local/ilogtail}"
LOGTAIL_ETC="${LOGTAIL_ETC:-/etc/ilogtail}"
FILEBEAT_ROOT="${FILEBEAT_ROOT:-/usr/share/filebeat}"
FILEBEAT_ETC="${FILEBEAT_ETC:-/etc/filebeat}"
FILEBEAT_STATE="${FILEBEAT_STATE:-/var/lib/filebeat}"
FILEBEAT_LOGS="${FILEBEAT_LOGS:-/var/log/filebeat}"
FILEBEAT_COMMAND="${FILEBEAT_COMMAND:-/usr/bin/filebeat}"
FILEBEAT_LOCAL_COMMAND="${FILEBEAT_LOCAL_COMMAND:-/usr/local/bin/filebeat}"
INIT_DIR="${INIT_DIR:-/etc/init.d}"
VENDOR_SYSTEMD_DIR="${VENDOR_SYSTEMD_DIR:-/usr/lib/systemd/system}"
LEGACY_SYSTEMD_DIR="${LEGACY_SYSTEMD_DIR:-/lib/systemd/system}"

log() {
  echo "[secweaver-agent uninstall] $*" >&2
}

warn() {
  echo "[secweaver-agent uninstall] WARN: $*" >&2
}

fatal() {
  echo "[secweaver-agent uninstall] ERROR: $*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
Usage:
  sudo ./uninstall.sh [options]

Options:
  --purge             Also remove config, state, and log files.
  --remove-config     Remove INSTALL_ROOT/etc or CONFIG_DIR.
  --remove-state      Remove INSTALL_ROOT/data or STATE_DIR.
  --remove-logs       Remove secweaver-agent module log files under LOG_DIR.
  --keep-binary       Keep INSTALL_ROOT/bin and the command link.
  --no-audit-clean    Do not attempt to clean stale SecWeaver audit rules.
  --remove-logtail    Remove standalone Logtail/LoongCollector, including data.
  --remove-filebeat   Remove standalone Filebeat, including data and package.
  --json              Print a machine-readable verification result at the end.
  -h, --help          Show this help.

Environment:
  INSTALL_ROOT=/opt/secweaver-agent
  BIN_DIR=/opt/secweaver-agent/bin
  CONFIG_DIR=/opt/secweaver-agent/etc
  SYSTEMD_DIR=/etc/systemd/system
  STATE_DIR=/opt/secweaver-agent/data
  LOG_DIR=/opt/secweaver-agent/logs
  COMMAND_LINK=/usr/local/bin/secweaver-agent
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --purge)
      REMOVE_CONFIG=1
      REMOVE_STATE=1
      REMOVE_LOGS=1
      ;;
    --remove-config)
      REMOVE_CONFIG=1
      ;;
    --remove-state)
      REMOVE_STATE=1
      ;;
    --remove-logs)
      REMOVE_LOGS=1
      ;;
    --keep-binary)
      REMOVE_BINARY=0
      ;;
    --no-audit-clean)
      CLEAN_AUDIT_RULES=0
      ;;
    --json)
      JSON_OUTPUT=1
      ;;
    --remove-logtail) REMOVE_LOGTAIL=1 ;;
    --remove-filebeat) REMOVE_FILEBEAT=1 ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fatal "unknown option: $1"
      ;;
  esac
  shift
done

# Preserve a machine-readable failure even when an intermediate removal fails.
# Successful verification disables this trap before returning its own exit code.
uninstall_failed() {
  local rc="$1"
  trap - ERR
  if [[ "${JSON_OUTPUT}" == 1 ]]; then
    printf '{"ok":false,"error":"uninstall_incomplete","exit_code":%s}\n' "${rc}"
  fi
  exit "${rc}"
}
set -E
trap 'uninstall_failed "$?"' ERR

# These paths are recursive deletion boundaries, including caller overrides.
# Reject broad roots, relative paths and symlink roots before any service stops.
validate_removal_paths() {
  normalize_service_directories || return 1
  local path
  for path in "${INSTALL_ROOT}" "${BIN_DIR}" "${CONFIG_DIR}" "${STATE_DIR}" "${LOG_DIR}" "${SHIPPER_DIR}" "${SYSTEMD_DIR}" "${VENDOR_SYSTEMD_DIR}" "${LEGACY_SYSTEMD_DIR}" "${INIT_DIR}" "${LOGTAIL_ROOT}" "${LOGTAIL_ETC}" "${FILEBEAT_ROOT}" "${FILEBEAT_ETC}" "${FILEBEAT_STATE}" "${FILEBEAT_LOGS}"; do
    case "${path}" in
      /*/*) ;;
      *) warn "unsafe removal path: ${path}"; return 1 ;;
    esac
    case "${path}" in
      /usr/local|/usr/share|/usr/lib|/var/log|/var/lib|*/../*|*/..|*/./*|*/.|*//*|*/) warn "unsafe removal path: ${path}"; return 1 ;;
    esac
    [[ ! -L "${path}" ]] || { warn "symlink removal root: ${path}"; return 1; }
  done
}

# CentOS/RHEL use /etc/init.d -> rc.d/init.d; merged-/usr distributions
# may link /lib/systemd/system. Resolve only these exact standard mappings.
# Arbitrary operator-supplied links remain forbidden before any service stops.
normalize_service_directories() {
  local variable path target
  for variable in INIT_DIR LEGACY_SYSTEMD_DIR; do
    path="${!variable}"
    [[ -L "${path}" ]] || continue
    target="$(readlink -f -- "${path}")" || return 1
    case "${path}:${target}" in
      /etc/init.d:/etc/rc.d/init.d|/lib/systemd/system:/usr/lib/systemd/system)
        [[ -d "${target}" && ! -L "${target}" ]] || return 1
        printf -v "${variable}" '%s' "${target}"
        ;;
      *) warn "unsupported service directory symlink: ${path}"; return 1 ;;
    esac
  done
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 && return 0
  [[ -x "/usr/sbin/$1" || -x "/sbin/$1" || -x "/usr/bin/$1" || -x "/bin/$1" ]]
}

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    fatal "please run as root, for example: sudo ./uninstall.sh"
  fi
}

stop_systemd_service() {
  if ! need_cmd systemctl; then
    warn "systemctl not found; skip systemd service removal"
    return 0
  fi

  local service_name
  for service_name in "${SERVICE_NAME}" "${SHIPPER_SERVICE_NAME}"; do
    if systemctl cat "${service_name}" >/dev/null 2>&1 || [[ -f "${SYSTEMD_DIR}/${service_name}" ]]; then
      timeout 90 systemctl stop "${service_name}" >/dev/null 2>&1 || true
      systemctl disable "${service_name}" >/dev/null 2>&1 || true
    fi
    rm -rf -- "${SYSTEMD_DIR:?}/${service_name}.d"

    if [[ -e "${SYSTEMD_DIR}/${service_name}" || -L "${SYSTEMD_DIR}/${service_name}" ]]; then
      rm -f "${SYSTEMD_DIR:?}/${service_name}"
      log "removed systemd unit: ${SYSTEMD_DIR}/${service_name}"
    fi

    systemctl reset-failed "${service_name}" >/dev/null 2>&1 || true
  done
  systemctl daemon-reload >/dev/null 2>&1 || true
}

# Match the executable path and host PID namespace, never just the process name
# or a PID file that may belong to a reused PID or a container installation.
collector_pids() {
  local root="$1" pid exe
  for pid in $(pgrep -f 'ilogtail|loongcollector|filebeat' || true); do
    exe="$(readlink "/proc/${pid}/exe" 2>/dev/null || true)"
    case "${exe}" in
      "${root}/"*|/usr/bin/filebeat|/usr/bin/filebeat\ \(deleted\))
        [[ "${root}" == "${FILEBEAT_ROOT}" || "${exe}" == "${root}/"* ]] || continue
        [[ "$(readlink "/proc/${pid}/ns/pid" 2>/dev/null)" == "$(readlink /proc/1/ns/pid)" ]] && printf '%s\n' "${pid}"
        ;;
    esac
  done
  return 0
}

# Stop before deleting any executable/configuration. Package-managed Filebeat is
# removed through its package manager, keeping the package database consistent.
remove_standalone_collector() {
  local kind="$1" root="$2" service pid attempt
  local services=(filebeat)
  [[ "${kind}" != logtail ]] || services=(ilogtaild loongcollectord)
  for service in "${services[@]}"; do
    if need_cmd systemctl; then
      timeout 60 systemctl stop "${service}.service" >/dev/null 2>&1 || true
      systemctl disable "${service}.service" >/dev/null 2>&1 || true
    fi
    if [[ -x "${INIT_DIR}/${service}" && -n "$(collector_pids "${root}")" ]]; then
      timeout 40 "${INIT_DIR}/${service}" stop >&2 || true
    fi
  done
  for pid in $(collector_pids "${root}"); do kill -TERM "${pid}" 2>/dev/null || true; done
  for ((attempt=0; attempt<10; attempt++)); do
    [[ -z "$(collector_pids "${root}")" ]] && break
    sleep 1
  done
  for pid in $(collector_pids "${root}"); do kill -KILL "${pid}" 2>/dev/null || true; done
  for ((attempt=0; attempt<5; attempt++)); do
    [[ -z "$(collector_pids "${root}")" ]] && break
    sleep 1
  done
  [[ -z "$(collector_pids "${root}")" ]] || { warn "${kind} still running; files retained"; return 1; }
  if [[ "${kind}" == filebeat ]]; then
    if command -v rpm >/dev/null 2>&1 && rpm -q filebeat >/dev/null 2>&1; then
      rpm -e filebeat >&2
    elif command -v dpkg-query >/dev/null 2>&1 && dpkg-query -W filebeat >/dev/null 2>&1; then
      dpkg --purge filebeat >&2
    fi
    rm -rf -- "${FILEBEAT_ROOT}" "${FILEBEAT_ETC}" "${FILEBEAT_STATE}" "${FILEBEAT_LOGS}"
    rm -f -- "${FILEBEAT_COMMAND}" "${FILEBEAT_LOCAL_COMMAND}"
  else
    rm -rf -- "${LOGTAIL_ROOT}" "${LOGTAIL_ETC}"
  fi
  for service in "${services[@]}"; do
    if command -v chkconfig >/dev/null 2>&1; then chkconfig --del "${service}" >/dev/null 2>&1 || true; fi
    if command -v update-rc.d >/dev/null 2>&1; then update-rc.d -f "${service}" remove >&2 || true; fi
    rm -f -- "${SYSTEMD_DIR}/${service}.service" "${VENDOR_SYSTEMD_DIR}/${service}.service" "${LEGACY_SYSTEMD_DIR}/${service}.service" "${INIT_DIR}/${service}"
    rm -rf -- "${SYSTEMD_DIR}/${service}.service.d"
    if need_cmd systemctl; then systemctl reset-failed "${service}.service" >/dev/null 2>&1 || true; fi
  done
  if need_cmd systemctl; then systemctl daemon-reload; fi
  log "removed standalone ${kind} and its configuration/state"
}

cleanup_audit_rules_by_exact_keys() {
  local keys=(
    tb_external_listener_exec
    tb_external_listener_connect
    tb_external_listener_file
    tb_external_listener_sensitive
    tb_external_listener_clone
    tb_host_persistence
  )
  local key
  for key in "${keys[@]}"; do
    auditctl -D -k "${key}" >/dev/null 2>&1 || true
  done
}

cleanup_audit_rules_by_listing() {
  local line
  local removed=0
  while IFS= read -r line; do
    case "${line}" in
      *tb_external_listener_*|*tb_port_*|*tb_host_persistence*)
        ;;
      *)
        continue
        ;;
    esac

    if [[ "${line}" == "-a "* ]]; then
      local args=()
      read -r -a args <<<"${line#-a }"
      if auditctl -d "${args[@]}" >/dev/null 2>&1; then
        removed=$((removed + 1))
      fi
      continue
    fi

    if [[ "${line}" == "-w "* ]]; then
      local args=()
      read -r -a args <<<"${line}"
      local i
      for ((i = 0; i < ${#args[@]}; i++)); do
        if [[ "${args[$i]}" == "-w" && $((i + 1)) -lt ${#args[@]} ]]; then
          if auditctl -W "${args[$((i + 1))]}" >/dev/null 2>&1; then
            removed=$((removed + 1))
          fi
          break
        fi
      done
    fi
  done < <(auditctl -l 2>/dev/null || true)

  if [[ "${removed}" -gt 0 ]]; then
    log "removed ${removed} stale audit rules by listing fallback"
  fi
}

cleanup_audit_rules() {
  if [[ "${CLEAN_AUDIT_RULES}" -eq 0 ]]; then
    log "audit rule cleanup skipped"
    return 0
  fi
  if ! need_cmd auditctl; then
    warn "auditctl not found; skip stale audit rule cleanup"
    return 0
  fi

  cleanup_audit_rules_by_exact_keys
  cleanup_audit_rules_by_listing
  log "audit rule cleanup attempted for SecWeaver keys"
}

remove_binary() {
  local binary="${BIN_DIR}/secweaver-agent"
	local launcher="${BIN_DIR}/secweaver-agent-launch"
  if [[ "${REMOVE_BINARY}" -eq 0 ]]; then
    log "binary kept: ${binary}"
    return 0
  fi
  if [[ -e "${binary}" ]]; then
    rm -f "${binary}"
    log "removed binary: ${binary}"
  fi
	if [[ -e "${launcher}" ]]; then
	  rm -f "${launcher}"
	  log "removed launcher: ${launcher}"
	fi
	if [[ -L "${COMMAND_LINK}" && "$(readlink "${COMMAND_LINK}")" == "${binary}" ]]; then
	  rm -f "${COMMAND_LINK}"
	  log "removed command link: ${COMMAND_LINK}"
	fi
}

remove_optional_data() {
  if [[ "${REMOVE_CONFIG}" -eq 1 && -d "${CONFIG_DIR}" ]]; then
    rm -rf "${CONFIG_DIR}"
    log "removed config directory: ${CONFIG_DIR}"
  else
    log "config kept: ${CONFIG_DIR}"
  fi

  if [[ "${REMOVE_STATE}" -eq 1 && -e "${STATE_DIR}" ]]; then
    rm -rf "${STATE_DIR}"
    log "removed state directory: ${STATE_DIR}"
  else
    log "state kept: ${STATE_DIR}"
  fi

  if [[ "${REMOVE_LOGS}" -eq 1 ]]; then
    rm -f \
      "${LOG_DIR}/audit-port-execmon.log"* \
      "${LOG_DIR}/syslog-risk-json.log"* \
      "${LOG_DIR}/host-persistence.log"* \
      "${LOG_DIR}/host-process-snapshot.log"* \
      "${LOG_DIR}/host-state-snapshot.log"* \
      "${LOG_DIR}/host-behavior-summary.log"* \
      "${LOG_DIR}/secweaver-agent-update.log"* \
      "${LOG_DIR}/secweaver-agent-health.log"*
    log "removed known module logs under ${LOG_DIR}"
  else
    log "logs kept under ${LOG_DIR}"
  fi

  # Shipper credentials and binaries are installation-owned, but are retained
  # during a normal uninstall for forensic review and rollback. Purge removes
  # the whole product root after all verification inputs have been collected.
}

json_bool() {
  if [[ "$1" -eq 0 ]]; then
    echo "false"
  else
    echo "true"
  fi
}

json_escape() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//$'\n'/\\n}"
  printf '%s' "${value}"
}

path_exists_bool() {
  if [[ -e "$1" ]]; then
    echo "true"
  else
    echo "false"
  fi
}

service_unit_exists_bool() {
  local service_name
  for service_name in "${SERVICE_NAME}" "${SHIPPER_SERVICE_NAME}"; do
    if [[ -e "${SYSTEMD_DIR}/${service_name}" || -L "${SYSTEMD_DIR}/${service_name}" || -d "${SYSTEMD_DIR}/${service_name}.d" ]]; then
      echo "true"
      return
    fi
    if need_cmd systemctl && systemctl cat "${service_name}" >/dev/null 2>&1; then
      echo "true"
      return
    fi
  done
  echo "false"
}

secweaver_process_count() {
  ps -eo pid=,comm=,args= 2>/dev/null | awk -v self="$$" -v bin_dir="${BIN_DIR}" '
    $1 == self { next }
    $2 == "secweaver-agent" || $2 == "audit-port-execmon" || $2 == "syslog-risk-json" { count++; next }
    index($0, bin_dir "/secweaver-agent ") > 0 { count++; next }
    END { print count + 0 }
  ' | tr -d ' '
}

remaining_audit_rule_count() {
  if ! need_cmd auditctl; then
    echo "-1"
    return
  fi
  local listing
  if ! listing="$(auditctl -l 2>/dev/null)"; then
    echo '-2' # Unreadable audit state is distinct from zero rules or no auditctl.
    return
  fi
  awk '/tb_external_listener|tb_port_|tb_host_persistence/ { count++ } END { print count+0 }' <<<"${listing}"
}

known_logs_exist_bool() {
  local paths=(
    "${LOG_DIR}/audit-port-execmon.log"
    "${LOG_DIR}/syslog-risk-json.log"
    "${LOG_DIR}/host-persistence.log"
    "${LOG_DIR}/host-behavior-summary.log"
	"${LOG_DIR}/host-process-snapshot.log"
	"${LOG_DIR}/host-state-snapshot.log"
    "${LOG_DIR}/secweaver-agent-update.log"
    "${LOG_DIR}/secweaver-agent-health.log"
  )
  local path
  for path in "${paths[@]}"; do
    if compgen -G "${path}*" >/dev/null; then
      echo "true"
      return
    fi
  done
  echo "false"
}

# Verify requested external removals separately. A successful rm is not proof
# that a custom unit or a surviving process has disappeared from the host.
standalone_remaining_bool() {
  local kind="$1" root service path
  local services paths
  if [[ "${kind}" == logtail ]]; then
    root="${LOGTAIL_ROOT}"; services=(ilogtaild loongcollectord)
    paths=("${LOGTAIL_ROOT}" "${LOGTAIL_ETC}")
  else
    root="${FILEBEAT_ROOT}"; services=(filebeat)
    paths=("${FILEBEAT_ROOT}" "${FILEBEAT_ETC}" "${FILEBEAT_STATE}" "${FILEBEAT_LOGS}" "${FILEBEAT_COMMAND}" "${FILEBEAT_LOCAL_COMMAND}")
  fi
  for path in "${paths[@]}"; do
    if [[ -e "${path}" || -L "${path}" ]]; then echo true; return; fi
  done
  for service in "${services[@]}"; do
    if [[ -e "${INIT_DIR}/${service}" || -e "${SYSTEMD_DIR}/${service}.service" || -e "${VENDOR_SYSTEMD_DIR}/${service}.service" || -e "${LEGACY_SYSTEMD_DIR}/${service}.service" ]] || { need_cmd systemctl && systemctl cat "${service}.service" >/dev/null 2>&1; }; then
      echo true; return
    fi
  done
  if [[ -n "$(collector_pids "${root}")" ]]; then echo true; else echo false; fi
}

print_verification_json() {
  local audit_count process_count binary_path unit_exists config_exists state_exists logs_exist
  audit_count="$(remaining_audit_rule_count)"
  process_count="$(secweaver_process_count)"
  binary_path="${BIN_DIR}/secweaver-agent"
  unit_exists="$(service_unit_exists_bool)"
  config_exists="$(path_exists_bool "${CONFIG_DIR}")"
  state_exists="$(path_exists_bool "${STATE_DIR}")"
  logs_exist="$(known_logs_exist_bool)"

  local ok=1
  local logtail_remaining=null filebeat_remaining=null
  if [[ "${REMOVE_LOGTAIL}" == 1 ]]; then
    logtail_remaining="$(standalone_remaining_bool logtail)"
    [[ "${logtail_remaining}" == false ]] || ok=0
  fi
  if [[ "${REMOVE_FILEBEAT}" == 1 ]]; then
    filebeat_remaining="$(standalone_remaining_bool filebeat)"
    [[ "${filebeat_remaining}" == false ]] || ok=0
  fi
  [[ "${unit_exists}" == "false" ]] || ok=0
  [[ "${process_count}" == "0" ]] || ok=0
  [[ "${audit_count}" == "0" || "${audit_count}" == "-1" || "${CLEAN_AUDIT_RULES}" -eq 0 ]] || ok=0
  if [[ "${REMOVE_BINARY}" -eq 1 && -e "${binary_path}" ]]; then ok=0; fi
  if [[ "${REMOVE_CONFIG}" -eq 1 && "${config_exists}" == "true" ]]; then ok=0; fi
  if [[ "${REMOVE_STATE}" -eq 1 && "${state_exists}" == "true" ]]; then ok=0; fi
  if [[ "${REMOVE_LOGS}" -eq 1 && "${logs_exist}" == "true" ]]; then ok=0; fi

  cat <<EOF
{"ok":$(json_bool "${ok}"),"standalone_collectors":{"logtail":{"removal_requested":$(json_bool "${REMOVE_LOGTAIL}"),"remaining":${logtail_remaining}},"filebeat":{"removal_requested":$(json_bool "${REMOVE_FILEBEAT}"),"remaining":${filebeat_remaining}}},"service":{"name":"$(json_escape "${SERVICE_NAME}")","additional_names":["$(json_escape "${SHIPPER_SERVICE_NAME}")"],"unit_exists":${unit_exists}},"processes":{"matching_count":${process_count}},"audit":{"cleanup_requested":$(json_bool "${CLEAN_AUDIT_RULES}"),"remaining_rule_count":${audit_count}},"files":{"binary":"$(json_escape "${binary_path}")","binary_exists":$(path_exists_bool "${binary_path}"),"config_dir":"$(json_escape "${CONFIG_DIR}")","config_exists":${config_exists},"state_dir":"$(json_escape "${STATE_DIR}")","state_exists":${state_exists},"logs_dir":"$(json_escape "${LOG_DIR}")","known_logs_exist":${logs_exist}}}
EOF
  [[ "${ok}" == 1 ]]
}

require_root
validate_removal_paths
# Read before deleting the binary/config. Mode describes ownership, but does
# not authorize removing machine-wide collectors used by other applications.
if [[ -x "${BIN_DIR}/secweaver-agent" && -f "${CONFIG_DIR}/config.json" ]]; then
  if deployment_mode="$("${BIN_DIR}/secweaver-agent" config set-deployment-mode -config "${CONFIG_DIR}/config.json" -check-only 2>/dev/null)"; then
    log "deployment mode: ${deployment_mode}; standalone collector removal remains opt-in"
  fi
fi
command -v timeout >/dev/null
stop_systemd_service
if [[ "${REMOVE_LOGTAIL}" == 1 ]]; then remove_standalone_collector logtail "${LOGTAIL_ROOT}"; fi
if [[ "${REMOVE_FILEBEAT}" == 1 ]]; then remove_standalone_collector filebeat "${FILEBEAT_ROOT}"; fi
cleanup_audit_rules
remove_binary
remove_optional_data

if [[ "${REMOVE_BINARY}" -eq 1 && "${REMOVE_CONFIG}" -eq 1 && "${REMOVE_STATE}" -eq 1 && "${REMOVE_LOGS}" -eq 1 ]]; then
  rm -rf "${SHIPPER_DIR}" "${INSTALL_ROOT}"
  log "removed installation root: ${INSTALL_ROOT}"
else
  rmdir "${BIN_DIR}" "${INSTALL_ROOT}" >/dev/null 2>&1 || true
fi

log "uninstall complete"
if [[ "${JSON_OUTPUT}" -eq 1 ]]; then
  trap - ERR
  print_verification_json
else
  trap - ERR
  print_verification_json >/dev/null
fi

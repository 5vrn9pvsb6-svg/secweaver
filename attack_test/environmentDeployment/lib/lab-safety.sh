#!/bin/bash

# Shared fail-closed guard for every host-mutating or attack-simulation entrypoint.
# The acknowledgement proves intent; the explicit allowlist prevents a copied
# command from silently targeting a different host or public service.
SECWEAVER_LAB_ACK_VALUE="I_UNDERSTAND_THIS_IS_AN_ISOLATED_AUTHORIZED_LAB"

# Every deploy script stashes changed system files and ownership markers here.
# Tests may override the path; production entrypoints retain the host-level default.
LAB_BACKUP_DIR="${LAB_BACKUP_DIR:-/var/lib/secweaver-lab-backup}"

lab_error() {
    echo "ERROR: $*" >&2
    return 2
}

lab_require_acknowledgement() {
    if [[ "${SECWEAVER_LAB_ACK:-}" != "${SECWEAVER_LAB_ACK_VALUE}" ]]; then
        lab_error "set SECWEAVER_LAB_ACK=${SECWEAVER_LAB_ACK_VALUE} before using Attack Lab"
        return 2
    fi
}

lab_require_deploy_host() {
    lab_require_acknowledgement || return $?
    if [[ "${EUID}" -ne 0 ]]; then
        lab_error "deployment and teardown scripts must run as root on a disposable lab host"
        return 2
    fi
    if [[ -e "/proc/1/cgroup" ]] && grep -qE 'docker|containerd|kubepods' /proc/1/cgroup 2>/dev/null; then
        : # containers are the preferred isolation; continue
    elif [[ -f "/etc/secweaver-lab-host" ]]; then
        : # host explicitly marked as a lab machine by its operator
    else
        lab_error "refusing to run on an unmarked host: create /etc/secweaver-lab-host on the disposable lab machine, or prefer the docker-compose deployment"
        return 2
    fi
}

lab_target_host() {
    local target="$1"
    target="${target#*://}"
    target="${target%%/*}"
    target="${target%%:*}"
    printf '%s\n' "${target}"
}

lab_require_attack_target() {
    lab_require_acknowledgement || return $?

    local requested
    requested="$(lab_target_host "$1")"
    if [[ -z "${requested}" || -z "${SECWEAVER_LAB_ALLOWED_TARGETS:-}" ]]; then
        lab_error "set SECWEAVER_LAB_ALLOWED_TARGETS to the exact comma-separated lab hosts"
        return 2
    fi

    local candidate
    local -a allowed_targets
    IFS=',' read -r -a allowed_targets <<< "${SECWEAVER_LAB_ALLOWED_TARGETS}"
    for candidate in "${allowed_targets[@]}"; do
        candidate="${candidate#${candidate%%[![:space:]]*}}"
        candidate="${candidate%${candidate##*[![:space:]]}}"
        if [[ "${requested}" == "${candidate}" ]]; then
            return 0
        fi
    done

    lab_error "target ${requested} is not present in SECWEAVER_LAB_ALLOWED_TARGETS"
    return 2
}

# Convert an operator-controlled path or resource name into a flat state key.
lab_state_key() {
    printf '%s' "$1" | tr '/:[:space:]' '____'
}

# Record a resource created by the lab. Teardown removes only marked resources,
# preventing a copied cleanup command from deleting pre-existing host state.
lab_mark_resource_created() {
    local key
    key="$(lab_state_key "$1")"
    mkdir -p "${LAB_BACKUP_DIR}/resources"
    : > "${LAB_BACKUP_DIR}/resources/${key}.created"
}

lab_resource_was_created() {
    local key
    key="$(lab_state_key "$1")"
    [[ -f "${LAB_BACKUP_DIR}/resources/${key}.created" ]]
}

# Claim a directory for exclusive lab use. Existing unclaimed paths are refused
# because deployment and teardown cannot safely infer who owns their contents.
lab_claim_directory() {
    local path="$1"
    local resource="$2"
    if [[ -e "${path}" ]]; then
        if ! lab_resource_was_created "${resource}"; then
            lab_error "refusing to reuse unowned directory ${path}"
            return 2
        fi
        return 0
    fi
    mkdir -p "${path}"
    lab_mark_resource_created "${resource}"
}

# Remove a path only when deployment recorded that the lab created it.
lab_remove_created_path() {
    local resource="$1"
    local path="$2"
    if lab_resource_was_created "${resource}"; then
        rm -rf -- "${path}"
        echo "removed lab-owned ${path}"
    elif [[ -e "${path}" ]]; then
        echo "preserved unowned ${path}"
    fi
}

# lab_backup_file <path> snapshots both existence and content before mutation.
# The first snapshot wins, so re-deploys never replace the original host state.
lab_backup_file() {
    local path="$1"
    local key
    key="$(lab_state_key "${path}")"
    mkdir -p "${LAB_BACKUP_DIR}"
    if [[ -f "${LAB_BACKUP_DIR}/${key}" || -f "${LAB_BACKUP_DIR}/${key}.absent" ]]; then
        return 0
    fi
    if [[ -f "${path}" ]]; then
        cp -p "${path}" "${LAB_BACKUP_DIR}/${key}"
    else
        : > "${LAB_BACKUP_DIR}/${key}.absent"
    fi
    grep -Fqx -- "${path}" "${LAB_BACKUP_DIR}/files.manifest" 2>/dev/null \
        || printf '%s\n' "${path}" >> "${LAB_BACKUP_DIR}/files.manifest"
}

# Restore the earliest snapshot, or remove a file recorded as originally absent.
lab_restore_file() {
    local path="$1"
    local key
    key="$(lab_state_key "${path}")"
    if [[ -f "${LAB_BACKUP_DIR}/${key}" ]]; then
        mkdir -p "$(dirname -- "${path}")"
        cp -p "${LAB_BACKUP_DIR}/${key}" "${path}"
        echo "restored ${path}"
    elif [[ -f "${LAB_BACKUP_DIR}/${key}.absent" ]]; then
        rm -f -- "${path}"
        echo "removed lab-created file ${path}"
    fi
}

# Restore every file registered by deployment. Static fallbacks remain in the
# teardown entrypoint for backups created by older Attack Lab revisions.
lab_restore_all_files() {
    [[ -f "${LAB_BACKUP_DIR}/files.manifest" ]] || return 0
    while IFS= read -r path; do
        [[ -n "${path}" ]] && lab_restore_file "${path}"
    done < "${LAB_BACKUP_DIR}/files.manifest"
}

# Add a permanent firewall rule and remember ownership only when the rule was
# absent. Teardown therefore never closes a port opened by the operator.
lab_firewall_add() {
    local kind="$1"
    local value="$2"
    command -v firewall-cmd >/dev/null 2>&1 || return 0
    if firewall-cmd --permanent "--query-${kind}=${value}" >/dev/null 2>&1; then
        return 0
    fi
    if firewall-cmd --permanent "--add-${kind}=${value}" >/dev/null 2>&1; then
        lab_mark_resource_created "firewall-${kind}-${value}"
        firewall-cmd --reload >/dev/null 2>&1 || true
    fi
}

lab_firewall_remove_if_added() {
    local kind="$1"
    local value="$2"
    command -v firewall-cmd >/dev/null 2>&1 || return 0
    if lab_resource_was_created "firewall-${kind}-${value}"; then
        firewall-cmd --permanent "--remove-${kind}=${value}" >/dev/null 2>&1 || true
        firewall-cmd --reload >/dev/null 2>&1 || true
    fi
}

# Remove only cron entries carrying the lab marker. Other entries and users are
# preserved even when an attack phase successfully established persistence.
lab_remove_marked_cron() {
    local user="$1"
    local current
    local filtered
    id "${user}" >/dev/null 2>&1 || return 0
    current="$(crontab -u "${user}" -l 2>/dev/null)" || return 0
    filtered="$(printf '%s\n' "${current}" | grep -vF '# secweaver-attack-lab' || true)"
    [[ "${filtered}" == "${current}" ]] && return 0
    if [[ -n "${filtered}" ]]; then
        printf '%s\n' "${filtered}" | crontab -u "${user}" -
    else
        crontab -u "${user}" -r 2>/dev/null || true
    fi
}

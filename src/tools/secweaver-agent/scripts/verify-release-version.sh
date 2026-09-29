#!/usr/bin/env bash
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly REPO_ROOT="$(cd "${ROOT_DIR}/../../.." && pwd)"
readonly AGENT_PATH="src/tools/secweaver-agent"
readonly AGENT_ES_INTEGRATION_PATH="src/tools/secweaver-agent/elasticsearch"
readonly SOURCE_FINGERPRINT_PATH="src/scripts/source_fingerprint.py"
readonly SOURCE_ARCHIVE_PROVENANCE_PATH="src/scripts/source_archive_provenance.py"
readonly VERSION_PATH="${AGENT_PATH}/VERSION"
readonly RELEASE_VERSION="${1:-$(tr -d '[:space:]' <"${ROOT_DIR}/VERSION")}"
readonly CANONICAL_VERSION="$(tr -d '[:space:]' <"${ROOT_DIR}/VERSION")"

fatal() {
  printf 'Agent release version gate: %s\n' "$*" >&2
  exit 1
}

# Release version overrides previously allowed different source trees to publish
# the same package name. Require the tracked VERSION file to remain the sole
# identity so source provenance and update ordering cannot diverge.
[[ "${RELEASE_VERSION}" == "${CANONICAL_VERSION}" ]] || \
  fatal "requested VERSION ${RELEASE_VERSION} differs from canonical ${CANONICAL_VERSION}; update VERSION and commit it"

if ! git -C "${REPO_ROOT}" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  # Official history-free archives carry a byte-level receipt created only
  # after the clean Git checkout passed this gate. This is not an environment
  # override: edits to VERSION, Agent source, or the fingerprint tool invalidate
  # the receipt before any package can be built.
  python3 "${REPO_ROOT}/src/scripts/source_archive_provenance.py" verify \
    --root "${REPO_ROOT}" --expected-version "${CANONICAL_VERSION}" || \
    fatal "history-free source archive provenance validation failed"
  exit 0
fi

readonly HEAD_VERSION="$(git -C "${REPO_ROOT}" show "HEAD:${VERSION_PATH}" 2>/dev/null | tr -d '[:space:]')"
readonly VERSION_COMMIT="$(git -C "${REPO_ROOT}" log -1 --format=%H -- "${VERSION_PATH}")"
[[ -n "${HEAD_VERSION}" && -n "${VERSION_COMMIT}" ]] || \
  fatal "cannot resolve the committed Agent VERSION history"

path_requires_version_bump() {
  local path="$1"
  case "${path}" in
    "${VERSION_PATH}"|"${AGENT_PATH}/dist/"*) return 1 ;;
    "${AGENT_PATH}/"*) return 0 ;;
    "${AGENT_ES_INTEGRATION_PATH}/"*) return 0 ;;
    "${SOURCE_FINGERPRINT_PATH}"|"${SOURCE_ARCHIVE_PROVENANCE_PATH}") return 0 ;;
    *) return 1 ;;
  esac
}

if [[ "${CANONICAL_VERSION}" == "${HEAD_VERSION}" ]]; then
  # Inspect both commits after the last VERSION change and current worktree
  # edits. ALLOW_DIRTY_RELEASE must never bypass the version identity rule.
  while IFS= read -r path; do
    if path_requires_version_bump "${path}"; then
      fatal "${path} changed after VERSION ${CANONICAL_VERSION} was assigned; bump VERSION before packaging"
    fi
  done < <(git -C "${REPO_ROOT}" diff --name-only "${VERSION_COMMIT}..HEAD" -- "${AGENT_PATH}" "${AGENT_ES_INTEGRATION_PATH}" "${SOURCE_FINGERPRINT_PATH}" "${SOURCE_ARCHIVE_PROVENANCE_PATH}")

  while IFS= read -r record; do
    path="${record:3}"
    if [[ "${path}" == *" -> "* ]]; then
      path="${path##* -> }"
    fi
    if path_requires_version_bump "${path}"; then
      fatal "${path} has uncommitted changes under VERSION ${CANONICAL_VERSION}; bump VERSION before packaging"
    fi
  done < <(git -C "${REPO_ROOT}" status --porcelain --untracked-files=all -- "${AGENT_PATH}" "${AGENT_ES_INTEGRATION_PATH}" "${SOURCE_FINGERPRINT_PATH}" "${SOURCE_ARCHIVE_PROVENANCE_PATH}")
fi

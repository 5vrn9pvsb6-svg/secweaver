#!/usr/bin/env bash
set -euo pipefail

APP_NAME="${APP_NAME:-secweaver-agent}"
OUT_DIR="${OUT_DIR:-dist}"
BOOTSTRAP_RELEASE_BASE_URL="${BOOTSTRAP_RELEASE_BASE_URL:-https://agent-gateway.id-net.cn:30443/secweaver-agent/releases}"
BOOTSTRAP_LICENSE_SERVER_URL="${BOOTSTRAP_LICENSE_SERVER_URL:-https://agent-gateway.id-net.cn:30443}"
BOOTSTRAP_ENROLLMENT_ID="${BOOTSTRAP_ENROLLMENT_ID:-}"
BOOTSTRAP_LOGTAIL_INSTALL_URL="${BOOTSTRAP_LOGTAIL_INSTALL_URL:-https://agent-gateway.id-net.cn:30443/logtail/install.sh}"
BOOTSTRAP_LOGTAIL_INSTALL_SHA256="${BOOTSTRAP_LOGTAIL_INSTALL_SHA256:-}"
BOOTSTRAP_LOGTAIL_ALIUID="${BOOTSTRAP_LOGTAIL_ALIUID:-}"
BOOTSTRAP_LOGTAIL_REGION="${BOOTSTRAP_LOGTAIL_REGION:-}"
UPDATE_SIGNING_PRIVATE_KEY_FILE="${UPDATE_SIGNING_PRIVATE_KEY_FILE:-}"
UPDATE_CHANNEL="${UPDATE_CHANNEL:-stable}"
BOOTSTRAP_UPDATE_BASE_URL="${BOOTSTRAP_UPDATE_BASE_URL:-${BOOTSTRAP_LICENSE_SERVER_URL%/}/secweaver-agent/updates/${UPDATE_CHANNEL}}"
BOOTSTRAP_UPDATE_MANIFEST_URL="${BOOTSTRAP_UPDATE_MANIFEST_URL:-${BOOTSTRAP_UPDATE_BASE_URL%/}/update-manifest.json}"
INSTALL_PACKAGES_ONLY="${INSTALL_PACKAGES_ONLY:-0}"
BOOTSTRAP_ONLY="${BOOTSTRAP_ONLY:-0}"

case "${BOOTSTRAP_LOGTAIL_REGION}" in
  hangzhou)
    BOOTSTRAP_LOGTAIL_REGION="cn-hangzhou"
    ;;
esac
LINUX_TARGETS=(
  "linux amd64"
  "linux arm64"
  "linux loong64"
)
WINDOWS_TARGETS=(
  "windows amd64"
  "windows arm64"
)

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "${ROOT_DIR}/../../.." && pwd)"
VERSION="${VERSION:-$(tr -d '[:space:]' <"${ROOT_DIR}/VERSION")}"
ALLOW_DIRTY_RELEASE="${ALLOW_DIRTY_RELEASE:-0}"

# A package may install privileged services and audit rules, so its provenance
# must resolve to one committed tree. The override exists only for local package
# tests and is intentionally explicit in build logs and operator documentation.
if [[ ! "${VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9][A-Za-z0-9.-]*)?$ ]]; then
  echo "invalid Agent VERSION: ${VERSION}" >&2
  exit 1
fi
if git -C "${REPO_ROOT}" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  SOURCE_COMMIT="$(git -C "${REPO_ROOT}" rev-parse HEAD)"
  SOURCE_CHANGES="$(git -C "${REPO_ROOT}" status --porcelain --untracked-files=all -- src/tools/secweaver-agent src/scripts/source_fingerprint.py)"
  if [[ -n "${SOURCE_CHANGES}" && "${ALLOW_DIRTY_RELEASE}" != "1" ]]; then
    echo "refusing Agent package from a dirty source tree; commit the release or set ALLOW_DIRTY_RELEASE=1 for a non-production build" >&2
    printf '%s\n' "${SOURCE_CHANGES}" >&2
    exit 1
  fi
  if [[ -n "${SOURCE_CHANGES}" ]]; then
    SOURCE_COMMIT="${SOURCE_COMMIT}-dirty"
    echo "warning: packaging non-production Agent artifacts from dirty source" >&2
  fi
else
  SOURCE_COMMIT="unknown"
fi
SOURCE_FINGERPRINT="$(python3 "${REPO_ROOT}/src/scripts/source_fingerprint.py" "${ROOT_DIR}")"
ES_INTEGRATION_SOURCE="${ROOT_DIR}/elasticsearch"
if [[ "${OUT_DIR}" = /* ]]; then
  DIST_DIR="${OUT_DIR}"
else
  DIST_DIR="${ROOT_DIR}/${OUT_DIR}"
fi
STAGING_DIR="${DIST_DIR}/staging"
PACKAGE_DIR="${DIST_DIR}/packages"
UPDATE_DIR="${DIST_DIR}/updates/${UPDATE_CHANNEL}"
BOOTSTRAP_UPDATE_PUBLIC_KEY=""

checksum_file() {
  local file="$1" digest
  if command -v sha256sum >/dev/null 2>&1; then
    digest="$(sha256sum "${file}" | awk '{print $1}')"
  else
    digest="$(shasum -a 256 "${file}" | awk '{print $1}')"
  fi
  printf '%s  %s\n' "${digest}" "$(basename "${file}")" >"${file}.sha256"
}

tar_dir() {
  local base_dir="$1"
  local entry="$2"
  local archive="$3"
  local tar_options=()
  if tar --no-xattrs -cf /dev/null --files-from /dev/null >/dev/null 2>&1; then
    tar_options+=(--no-xattrs)
  fi
  COPYFILE_DISABLE=1 tar "${tar_options[@]}" -C "${base_dir}" -czf "${archive}" "${entry}"
}

zip_dir() {
  local base_dir="$1"
  local entry="$2"
  local archive="$3"
  if command -v zip >/dev/null 2>&1; then
    (
      cd "${base_dir}"
      zip -qr "${archive}" "${entry}"
    )
    return
  fi
  if command -v python3 >/dev/null 2>&1; then
    (
      cd "${base_dir}"
      python3 -m zipfile -c "${archive}" "${entry}"
    )
    return
  fi
  echo "zip packaging requires zip or python3" >&2
  exit 1
}

validate_es_integration_inputs() {
  local file
  # The release archive owns a self-contained, Operator-independent ES helper;
  # fail before any cross-build if a required runtime or instruction file is missing.
  for file in \
    "${ES_INTEGRATION_SOURCE}/init_es.py" \
    "${ES_INTEGRATION_SOURCE}/index-template.json" \
    "${ES_INTEGRATION_SOURCE}/filebeat.yml" \
    "${ROOT_DIR}/docs/self-managed-es.md" \
    "${ROOT_DIR}/docs/self-managed-es.zh-CN.md" \
    "${ROOT_DIR}/docs/behavior-learning.md" \
    "${ROOT_DIR}/docs/behavior-learning.zh-CN.md" \
    "${ROOT_DIR}/logtail/behavior-learning.example.json"; do
    [[ -f "${file}" ]] || {
      echo "missing Agent package ES integration file: ${file}" >&2
      exit 1
    }
  done
}

install_es_integration() {
  local package_root="$1"
  # Keep ES setup beside the binary so extracted archives work without a source
  # checkout; the initializer only creates its dedicated template and never
  # depends on the private ES Operator or server modules.
  # Keep the learning operation guide and uploader reference self-contained.
  install -d -m 0755 "${package_root}/elasticsearch" "${package_root}/docs" "${package_root}/logtail"
  install -m 0644 "${ROOT_DIR}/docs/behavior-learning.md" "${package_root}/docs/behavior-learning.md"
  install -m 0644 "${ROOT_DIR}/docs/behavior-learning.zh-CN.md" "${package_root}/docs/behavior-learning.zh-CN.md"
  install -m 0644 "${ROOT_DIR}/logtail/behavior-learning.example.json" "${package_root}/logtail/behavior-learning.example.json"
  install -m 0755 "${ES_INTEGRATION_SOURCE}/init_es.py" "${package_root}/elasticsearch/init_es.py"
  install -m 0644 "${ES_INTEGRATION_SOURCE}/index-template.json" "${package_root}/elasticsearch/index-template.json"
  install -m 0644 "${ES_INTEGRATION_SOURCE}/filebeat.yml" "${package_root}/elasticsearch/filebeat.yml"
  install -m 0644 "${ROOT_DIR}/docs/self-managed-es.md" "${package_root}/elasticsearch/README.md"
  install -m 0644 "${ROOT_DIR}/docs/self-managed-es.zh-CN.md" "${package_root}/elasticsearch/README.zh-CN.md"
}

validate_bootstrap_inputs() {
  [[ "${BOOTSTRAP_RELEASE_BASE_URL}" =~ ^https:// ]] || {
    echo "BOOTSTRAP_RELEASE_BASE_URL must use HTTPS" >&2
    exit 1
  }
  [[ -n "${BOOTSTRAP_RELEASE_BASE_URL}" && "${BOOTSTRAP_RELEASE_BASE_URL}" != *YOUR_DATA_CLOUD_HOST* ]] || {
    echo "BOOTSTRAP_RELEASE_BASE_URL must point to a published Agent release directory" >&2
    exit 1
  }
  [[ "${BOOTSTRAP_RELEASE_BASE_URL}" != *[[:space:]]* && "${BOOTSTRAP_RELEASE_BASE_URL}" != *\?* && "${BOOTSTRAP_RELEASE_BASE_URL}" != *\#* ]] || {
    echo "invalid BOOTSTRAP_RELEASE_BASE_URL" >&2
    exit 1
  }
  [[ "${BOOTSTRAP_LICENSE_SERVER_URL}" =~ ^https:// ]] || {
    echo "BOOTSTRAP_LICENSE_SERVER_URL must use HTTPS" >&2
    exit 1
  }
  [[ -n "${BOOTSTRAP_LICENSE_SERVER_URL}" && "${BOOTSTRAP_LICENSE_SERVER_URL}" != *YOUR_DATA_CLOUD_HOST* && "${BOOTSTRAP_LICENSE_SERVER_URL}" != *YOUR_WEB_SHIELD_HOST* ]] || {
    echo "BOOTSTRAP_LICENSE_SERVER_URL must point to a published authorization origin" >&2
    exit 1
  }
  [[ "${BOOTSTRAP_LICENSE_SERVER_URL}" != *[[:space:]]* && "${BOOTSTRAP_LICENSE_SERVER_URL}" != *\?* && "${BOOTSTRAP_LICENSE_SERVER_URL}" != *\#* ]] || {
    echo "invalid BOOTSTRAP_LICENSE_SERVER_URL" >&2
    exit 1
  }
  if [[ ! "${BOOTSTRAP_ENROLLMENT_ID}" =~ ^[A-Za-z0-9][A-Za-z0-9._:-]{1,127}$ ]]; then
    echo "BOOTSTRAP_ENROLLMENT_ID is required and must contain 2-128 safe ASCII characters" >&2
    exit 1
  fi
  [[ "${BOOTSTRAP_LOGTAIL_INSTALL_URL}" =~ ^https:// ]] || {
    echo "BOOTSTRAP_LOGTAIL_INSTALL_URL must use HTTPS" >&2
    exit 1
  }
  [[ -n "${BOOTSTRAP_LOGTAIL_INSTALL_URL}" && "${BOOTSTRAP_LOGTAIL_INSTALL_URL}" != *YOUR_DATA_CLOUD_HOST* ]] || {
    echo "BOOTSTRAP_LOGTAIL_INSTALL_URL must point to a published Logtail/LoongCollector installer" >&2
    exit 1
  }
  [[ "${BOOTSTRAP_LOGTAIL_INSTALL_URL}" != *[[:space:]]* && "${BOOTSTRAP_LOGTAIL_INSTALL_URL}" != *\?* && "${BOOTSTRAP_LOGTAIL_INSTALL_URL}" != *\#* ]] || {
    echo "invalid BOOTSTRAP_LOGTAIL_INSTALL_URL" >&2
    exit 1
  }
  if [[ ! "${BOOTSTRAP_LOGTAIL_INSTALL_SHA256}" =~ ^[0-9A-Fa-f]{64}$ ]]; then
    echo "BOOTSTRAP_LOGTAIL_INSTALL_SHA256 must contain 64 hexadecimal characters; run publish-logtail-installer.sh first" >&2
    exit 1
  fi
  if [[ ! "${BOOTSTRAP_LOGTAIL_ALIUID}" =~ ^[0-9]{6,32}$ ]]; then
    echo "BOOTSTRAP_LOGTAIL_ALIUID is required and must contain 6-32 digits" >&2
    exit 1
  fi
  if [[ ! "${BOOTSTRAP_LOGTAIL_REGION}" =~ ^[a-z0-9][a-z0-9-]{1,31}$ ]]; then
    echo "BOOTSTRAP_LOGTAIL_REGION is required and must be a valid SLS region" >&2
    exit 1
  fi
  [[ "${BOOTSTRAP_UPDATE_MANIFEST_URL}" =~ ^https:// ]] || {
    echo "BOOTSTRAP_UPDATE_MANIFEST_URL must use HTTPS" >&2
    exit 1
  }
  [[ "${BOOTSTRAP_UPDATE_MANIFEST_URL}" != *[[:space:]]* && "${BOOTSTRAP_UPDATE_MANIFEST_URL}" != *\?* && "${BOOTSTRAP_UPDATE_MANIFEST_URL}" != *\#* ]] || {
    echo "invalid BOOTSTRAP_UPDATE_MANIFEST_URL" >&2
    exit 1
  }
  [[ "${BOOTSTRAP_UPDATE_BASE_URL}" =~ ^https:// ]] || {
    echo "BOOTSTRAP_UPDATE_BASE_URL must use HTTPS" >&2
    exit 1
  }
}

render_bootstrap_installer() {
  local destination="$1"
  local line
  local skip_embedded_config=0
  [[ -z "${BOOTSTRAP_UPDATE_PUBLIC_KEY}" || "${BOOTSTRAP_UPDATE_PUBLIC_KEY}" =~ ^[A-Za-z0-9+/]{43}=$ ]] || {
    echo "BOOTSTRAP_UPDATE_PUBLIC_KEY must be a base64 Ed25519 public key" >&2
    exit 1
  }
  while IFS= read -r line; do
    case "${line}" in
      "# SECWEAVER_BOOTSTRAP_EMBEDDED_CONFIG_BEGIN")
        printf '%s\n' "${line}"
        printf 'readonly EMBEDDED_RELEASE_BASE_URL=%q\n' "${BOOTSTRAP_RELEASE_BASE_URL%/}"
        printf 'readonly EMBEDDED_LICENSE_SERVER_URL=%q\n' "${BOOTSTRAP_LICENSE_SERVER_URL%/}"
        printf 'readonly EMBEDDED_ENROLLMENT_ID=%q\n' "${BOOTSTRAP_ENROLLMENT_ID}"
        printf 'readonly EMBEDDED_LOGTAIL_INSTALL_URL=%q\n' "${BOOTSTRAP_LOGTAIL_INSTALL_URL}"
        printf 'readonly EMBEDDED_LOGTAIL_INSTALL_SHA256=%q\n' "${BOOTSTRAP_LOGTAIL_INSTALL_SHA256}"
        printf 'readonly EMBEDDED_LOGTAIL_ALIUID=%q\n' "${BOOTSTRAP_LOGTAIL_ALIUID}"
        printf 'readonly EMBEDDED_LOGTAIL_REGION=%q\n' "${BOOTSTRAP_LOGTAIL_REGION}"
        printf 'readonly EMBEDDED_UPDATE_MANIFEST_URL=%q\n' "${BOOTSTRAP_UPDATE_MANIFEST_URL}"
        printf 'readonly EMBEDDED_UPDATE_PUBLIC_KEY=%q\n' "${BOOTSTRAP_UPDATE_PUBLIC_KEY}"
        skip_embedded_config=1
        ;;
      "# SECWEAVER_BOOTSTRAP_EMBEDDED_CONFIG_END")
        skip_embedded_config=0
        printf '%s\n' "${line}"
        ;;
      *)
        if [[ "${skip_embedded_config}" == "0" ]]; then
          printf '%s\n' "${line}"
        fi
        ;;
    esac
  done <"${ROOT_DIR}/packaging/bootstrap-install.sh" >"${destination}"
  chmod 0755 "${destination}"
}

render_windows_bootstrap_installer() {
  local destination="$1"
  python3 - \
    "${ROOT_DIR}/packaging/windows/bootstrap-install.ps1" \
    "${destination}" \
    "${BOOTSTRAP_RELEASE_BASE_URL%/}" \
    "${BOOTSTRAP_LICENSE_SERVER_URL%/}" \
    "${BOOTSTRAP_UPDATE_MANIFEST_URL}" \
    "${BOOTSTRAP_UPDATE_PUBLIC_KEY}" <<'PY'
import sys
from pathlib import Path

source_path, destination_path, release_url, license_url, update_manifest_url, update_public_key = sys.argv[1:]
source = Path(source_path).read_text(encoding="utf-8")
begin = "# SECWEAVER_WINDOWS_BOOTSTRAP_EMBEDDED_CONFIG_BEGIN"
end = "# SECWEAVER_WINDOWS_BOOTSTRAP_EMBEDDED_CONFIG_END"
prefix, remainder = source.split(begin, 1)
_, suffix = remainder.split(end, 1)

def ps_quote(value: str) -> str:
    return '"' + value.replace('`', '``').replace('"', '`"').replace('$', '`$') + '"'

embedded = "\n".join(
    (
        begin,
        f"$EmbeddedReleaseBaseUrl = {ps_quote(release_url)}",
        f"$EmbeddedLicenseServerUrl = {ps_quote(license_url)}",
        f"$EmbeddedUpdateManifestUrl = {ps_quote(update_manifest_url)}",
        f"$EmbeddedUpdatePublicKey = {ps_quote(update_public_key)}",
        end,
    )
)
Path(destination_path).write_text(prefix + embedded + suffix, encoding="utf-8", newline="\n")
PY
}

# Render a fresh, version-independent entry point without rebuilding immutable
# Agent archives. An optional existing trust key preserves signed-update mode.
if [[ "${BOOTSTRAP_ONLY}" == "1" ]]; then
  validate_bootstrap_inputs
  "${ROOT_DIR}/scripts/verify-release-version.sh" "${VERSION}"
  if [[ -n "${BOOTSTRAP_UPDATE_PUBLIC_KEY_FILE:-}" ]]; then
    [[ -f "${BOOTSTRAP_UPDATE_PUBLIC_KEY_FILE}" ]] || {
      echo "update public key not found: ${BOOTSTRAP_UPDATE_PUBLIC_KEY_FILE}" >&2
      exit 1
    }
    BOOTSTRAP_UPDATE_PUBLIC_KEY="$(tr -d '[:space:]' <"${BOOTSTRAP_UPDATE_PUBLIC_KEY_FILE}")"
  fi
  mkdir -p "${PACKAGE_DIR}"
  [[ ! -e "${PACKAGE_DIR}/install.sh" && ! -e "${PACKAGE_DIR}/install.ps1" ]] || {
    echo "refusing to overwrite published Bootstrap scripts; use a fresh OUT_DIR" >&2
    exit 1
  }
  render_bootstrap_installer "${PACKAGE_DIR}/install.sh"
  render_windows_bootstrap_installer "${PACKAGE_DIR}/install.ps1"
  exit 0
fi

if [[ "${INSTALL_PACKAGES_ONLY}" != "1" ]]; then
validate_bootstrap_inputs
[[ -z "${UPDATE_SIGNING_PRIVATE_KEY_FILE}" || -f "${UPDATE_SIGNING_PRIVATE_KEY_FILE}" ]] || {
  echo "update signing private key not found: ${UPDATE_SIGNING_PRIVATE_KEY_FILE}" >&2
  exit 1
}
[[ "${UPDATE_CHANNEL}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$ ]] || {
  echo "invalid UPDATE_CHANNEL" >&2
  exit 1
}

# Run the immutable-version gate after input validation so history-free source
# archives can exercise actionable parameter errors without weakening production
# packaging: a fully valid package still requires a Git-backed release check.
"${ROOT_DIR}/scripts/verify-release-version.sh" "${VERSION}"

rm -rf "${UPDATE_DIR}"
mkdir -p "${STAGING_DIR}" "${PACKAGE_DIR}" "${UPDATE_DIR}"
(
  cd "${ROOT_DIR}"
  VERSION="${VERSION}" \
  OUT_DIR="${UPDATE_DIR}" \
  UPDATE_CHANNEL="${UPDATE_CHANNEL}" \
  UPDATE_BASE_URL="${BOOTSTRAP_UPDATE_BASE_URL%/}" \
  UPDATE_SIGNING_PRIVATE_KEY_FILE="${UPDATE_SIGNING_PRIVATE_KEY_FILE}" \
    ./scripts/build-cross.sh
)
if [[ -f "${UPDATE_DIR}/update-signing-key.pub" ]]; then
  BOOTSTRAP_UPDATE_PUBLIC_KEY="$(tr -d '[:space:]' <"${UPDATE_DIR}/update-signing-key.pub")"
fi

render_bootstrap_installer "${PACKAGE_DIR}/install.sh"
render_windows_bootstrap_installer "${PACKAGE_DIR}/install.ps1"
else
  mkdir -p "${STAGING_DIR}" "${PACKAGE_DIR}"
fi

validate_es_integration_inputs

for target in "${LINUX_TARGETS[@]}"; do
  read -r goos goarch <<<"${target}"
  package_name="${APP_NAME}_${VERSION}_${goos}_${goarch}"
  package_root="${STAGING_DIR}/${package_name}"
  binary_path="${package_root}/bin/${APP_NAME}"
	archive_path="${PACKAGE_DIR}/${package_name}.tar.gz"

	rm -rf "${package_root}"
	mkdir -p \
	  "${package_root}/bin" \
	  "${package_root}/etc/secweaver-agent" \
	  "${package_root}/container" \
	  "${package_root}/examples/update-server" \
	  "${package_root}/elasticsearch" \
	  "${package_root}/libexec" \
	  "${package_root}/systemd"

  echo "building ${package_name}"
  (
    cd "${ROOT_DIR}"
    CGO_ENABLED=0 GOOS="${goos}" GOARCH="${goarch}" \
      go build -trimpath -ldflags "-s -w -X main.version=${VERSION} -X secweaver-agent/pkg/auditportexecmon.version=${VERSION}" -o "${binary_path}" .
  )

  install -m 0644 "${ROOT_DIR}/config.example.json" "${package_root}/etc/secweaver-agent/config.example.json"
  install -m 0644 "${ROOT_DIR}/config.production.example.json" "${package_root}/etc/secweaver-agent/config.production.example.json"
  install -m 0644 "${ROOT_DIR}/config.schema.json" "${package_root}/etc/secweaver-agent/config.schema.json"
  install -m 0644 "${ROOT_DIR}/config.windows.example.json" "${package_root}/etc/secweaver-agent/config.windows.example.json"
  install -m 0644 "${ROOT_DIR}/audit-port-execmon.example.json" "${package_root}/etc/secweaver-agent/audit-port-execmon.example.json"
  install -m 0644 "${ROOT_DIR}/host-persistence.example.json" "${package_root}/etc/secweaver-agent/host-persistence.example.json"
  install -m 0644 "${ROOT_DIR}/host-persistence.windows.example.json" "${package_root}/etc/secweaver-agent/host-persistence.windows.example.json"
	# Container artifacts consume the already-built binary from this release root.
	# They are therefore copied into every Linux archive instead of compiling an
	# image during packaging or requiring Docker on the release workstation.
	install -m 0644 "${ROOT_DIR}/packaging/container/Dockerfile" "${package_root}/container/Dockerfile"
	install -m 0644 "${ROOT_DIR}/packaging/container/docker-compose.yaml" "${package_root}/container/docker-compose.yaml"
	install -m 0644 "${ROOT_DIR}/packaging/container/config.container.example.json" "${package_root}/container/config.container.example.json"
	install -m 0644 "${ROOT_DIR}/packaging/secweaver-agent.service" "${package_root}/systemd/secweaver-agent.service"
	install -m 0755 "${ROOT_DIR}/packaging/secweaver-agent-launch" "${package_root}/libexec/secweaver-agent-launch"
  install -m 0755 "${ROOT_DIR}/packaging/install.sh" "${package_root}/install.sh"
  install -m 0755 "${ROOT_DIR}/packaging/uninstall.sh" "${package_root}/uninstall.sh"
  install -m 0644 "${ROOT_DIR}/README.md" "${package_root}/README.md"
  install -m 0644 "${ROOT_DIR}/README.zh-CN.md" "${package_root}/README.zh-CN.md"
  install -m 0644 "${ROOT_DIR}/examples/update-server/"* "${package_root}/examples/update-server/"
  install_es_integration "${package_root}"

	tar_dir "${STAGING_DIR}" "${package_name}" "${archive_path}"
	checksum_file "${archive_path}"
	printf '%s\n' "${SOURCE_FINGERPRINT}" >"${archive_path}.source.sha256"
	printf '%s\n' "${SOURCE_COMMIT}" >"${archive_path}.source.commit"
  echo "packaged ${archive_path}"
done

for target in "${WINDOWS_TARGETS[@]}"; do
  read -r goos goarch <<<"${target}"
  package_name="${APP_NAME}_${VERSION}_${goos}_${goarch}"
  package_root="${STAGING_DIR}/${package_name}"
  binary_path="${package_root}/bin/${APP_NAME}.exe"
  archive_path="${PACKAGE_DIR}/${package_name}.zip"

  rm -rf "${package_root}"
  mkdir -p \
    "${package_root}/bin" \
    "${package_root}/etc/secweaver-agent" \
    "${package_root}/examples/update-server" \
    "${package_root}/elasticsearch"

  echo "building ${package_name}"
  (
    cd "${ROOT_DIR}"
    CGO_ENABLED=0 GOOS="${goos}" GOARCH="${goarch}" \
      go build -trimpath -ldflags "-s -w -X main.version=${VERSION} -X secweaver-agent/pkg/auditportexecmon.version=${VERSION}" -o "${binary_path}" .
  )

  install -m 0644 "${ROOT_DIR}/config.windows.example.json" "${package_root}/etc/secweaver-agent/config.windows.example.json"
  install -m 0644 "${ROOT_DIR}/config.schema.json" "${package_root}/etc/secweaver-agent/config.schema.json"
  install -m 0644 "${ROOT_DIR}/host-persistence.windows.example.json" "${package_root}/etc/secweaver-agent/host-persistence.windows.example.json"
  install -m 0644 "${ROOT_DIR}/README.md" "${package_root}/README.md"
  install -m 0644 "${ROOT_DIR}/README.zh-CN.md" "${package_root}/README.zh-CN.md"
  install -m 0644 "${ROOT_DIR}/packaging/windows/install-service.ps1" "${package_root}/install-service.ps1"
  install -m 0644 "${ROOT_DIR}/packaging/windows/uninstall-service.ps1" "${package_root}/uninstall-service.ps1"
  install -m 0644 "${ROOT_DIR}/examples/update-server/"* "${package_root}/examples/update-server/"
  install_es_integration "${package_root}"

  rm -f "${archive_path}"
	zip_dir "${STAGING_DIR}" "${package_name}" "${archive_path}"
	checksum_file "${archive_path}"
	printf '%s\n' "${SOURCE_FINGERPRINT}" >"${archive_path}.source.sha256"
	printf '%s\n' "${SOURCE_COMMIT}" >"${archive_path}.source.commit"
  echo "packaged ${archive_path}"
done

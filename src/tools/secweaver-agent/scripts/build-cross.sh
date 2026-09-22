#!/usr/bin/env bash
set -euo pipefail

APP_NAME="${APP_NAME:-secweaver-agent}"
OUT_DIR="${OUT_DIR:-dist}"
UPDATE_SIGNING_PRIVATE_KEY_FILE="${UPDATE_SIGNING_PRIVATE_KEY_FILE:-}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "${ROOT_DIR}/../../.." && pwd)"
VERSION="${VERSION:-$(tr -d '[:space:]' <"${ROOT_DIR}/VERSION")}"
ALLOW_DIRTY_RELEASE="${ALLOW_DIRTY_RELEASE:-0}"

# Cross-builds are release evidence. Refuse ambiguous source trees by
# default so the binary manifest can always be mapped back to one Git commit.
if [[ ! "${VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9][A-Za-z0-9.-]*)?$ ]]; then
  echo "invalid Agent VERSION: ${VERSION}" >&2
  exit 1
fi
"${ROOT_DIR}/scripts/verify-release-version.sh" "${VERSION}"
if git -C "${REPO_ROOT}" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  SOURCE_COMMIT="$(git -C "${REPO_ROOT}" rev-parse HEAD)"
  SOURCE_CHANGES="$(git -C "${REPO_ROOT}" status --porcelain --untracked-files=all -- src/tools/secweaver-agent src/scripts/source_fingerprint.py)"
  if [[ -n "${SOURCE_CHANGES}" && "${ALLOW_DIRTY_RELEASE}" != "1" ]]; then
    echo "refusing Agent build from a dirty source tree; commit the release or set ALLOW_DIRTY_RELEASE=1 for a non-production build" >&2
    printf '%s\n' "${SOURCE_CHANGES}" >&2
    exit 1
  fi
  if [[ -n "${SOURCE_CHANGES}" ]]; then
    SOURCE_COMMIT="${SOURCE_COMMIT}-dirty"
    echo "warning: building non-production Agent artifacts from dirty source" >&2
  fi
else
  SOURCE_COMMIT="unknown"
fi
TARGETS=(
  "linux amd64"
  "linux arm64"
  "linux loong64"
  "windows amd64"
  "windows arm64"
)

if [[ -n "${UPDATE_SIGNING_PRIVATE_KEY_FILE}" && ! -f "${UPDATE_SIGNING_PRIVATE_KEY_FILE}" ]]; then
  echo "update signing private key not found: ${UPDATE_SIGNING_PRIVATE_KEY_FILE}" >&2
  exit 1
fi

sha256_file() {
  local file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "${file}" | awk '{print $1}'
  else
    shasum -a 256 "${file}" | awk '{print $1}'
  fi
}

file_size() {
  local file="$1"
  wc -c <"${file}" | tr -d '[:space:]'
}

artifact_name() {
  local goos="$1"
  local goarch="$2"
  local name="${APP_NAME}_${VERSION}_${goos}_${goarch}"
  if [[ "${goos}" == "windows" ]]; then
    name="${name}.exe"
  fi
  printf '%s' "${name}"
}

mkdir -p "${OUT_DIR}"
for target in "${TARGETS[@]}"; do
  read -r goos goarch <<<"${target}"
  output="${OUT_DIR}/$(artifact_name "${goos}" "${goarch}")"
  echo "building ${output}"
  CGO_ENABLED=0 GOOS="${goos}" GOARCH="${goarch}" \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION} -X secweaver-agent/pkg/auditportexecmon.version=${VERSION}" -o "${output}" .
done

manifest="${OUT_DIR}/update-manifest.json"
unsigned_manifest="${OUT_DIR}/.update-manifest.unsigned.json"
trap 'rm -f "${unsigned_manifest}"' EXIT
generated_at="$(python3 -c 'from datetime import datetime,timezone; print(datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"))')"
generation="${UPDATE_MANIFEST_GENERATION:-}"
expires_at="${UPDATE_MANIFEST_EXPIRES_AT:-}"
# Release artifacts sign the fixed-size SHA-256 digest by default. Raw artifact
# signatures remain available only as an explicit compatibility override for
# clients that predate the signature_format manifest field.
artifact_signature_format="${UPDATE_ARTIFACT_SIGNATURE_FORMAT:-ed25519-sha256}"
channel="${UPDATE_CHANNEL:-stable}"
base_url="${UPDATE_BASE_URL:-}"
rollout_percentage="${UPDATE_ROLLOUT_PERCENTAGE:-}"
download_spread_seconds="${UPDATE_DOWNLOAD_SPREAD_SECONDS:-}"

{
  printf '{\n'
  printf '  "schema_version": "1",\n'
  printf '  "app": "%s",\n' "${APP_NAME}"
  printf '  "channel": "%s",\n' "${channel}"
  printf '  "generated_at": "%s",\n' "${generated_at}"
  if [[ -n "${generation}" ]]; then
    printf '  "generation": %s,\n' "${generation}"
  fi
  if [[ -n "${expires_at}" ]]; then
    printf '  "expires_at": "%s",\n' "${expires_at}"
  fi
  printf '  "latest": {"version": "%s"},\n' "${VERSION}"
  if [[ -n "${rollout_percentage}" || -n "${download_spread_seconds}" ]]; then
    printf '  "rollout": {'
    first_rollout=1
    if [[ -n "${rollout_percentage}" ]]; then
      printf '"percentage": %s' "${rollout_percentage}"
      first_rollout=0
    fi
    if [[ -n "${download_spread_seconds}" ]]; then
      if [[ "${first_rollout}" -eq 0 ]]; then
        printf ', '
      fi
      printf '"download_spread_seconds": %s' "${download_spread_seconds}"
    fi
    printf '},\n'
  fi
  printf '  "binaries": {\n'
  first=1
  for target in "${TARGETS[@]}"; do
    read -r goos goarch <<<"${target}"
    platform="${goos}_${goarch}"
    name="$(artifact_name "${goos}" "${goarch}")"
    path="${OUT_DIR}/${name}"
    url="${name}"
    if [[ -n "${base_url}" ]]; then
      url="${base_url%/}/${name}"
    fi
    if [[ "${first}" -eq 0 ]]; then
      printf ',\n'
    fi
    first=0
    printf '    "%s": {"url": "%s", "sha256": "%s", "size": %s}' \
      "${platform}" "${url}" "$(sha256_file "${path}")" "$(file_size "${path}")"
  done
  printf '\n  }\n'
  printf '}\n'
} >"${unsigned_manifest}"

if [[ -n "${UPDATE_SIGNING_PRIVATE_KEY_FILE}" ]]; then
  go run ./cmd/update-sign \
    -manifest "${unsigned_manifest}" \
    -artifact-dir "${OUT_DIR}" \
    -private-key-file "${UPDATE_SIGNING_PRIVATE_KEY_FILE}" \
    -artifact-signature-format "${artifact_signature_format}" \
    -public-key-out "${OUT_DIR}/update-signing-key.pub" \
    -out "${manifest}"
  echo "wrote signed ${manifest}"
else
  mv "${unsigned_manifest}" "${manifest}"
  rm -f "${OUT_DIR}/update-signing-key.pub"
  echo "wrote unsigned ${manifest}; set UPDATE_SIGNING_PRIVATE_KEY_FILE to enable signing"
fi
python3 "${REPO_ROOT}/src/scripts/source_fingerprint.py" "${ROOT_DIR}" >"${OUT_DIR}/SOURCE.sha256"
printf '%s\n' "${SOURCE_COMMIT}" >"${OUT_DIR}/SOURCE.commit"

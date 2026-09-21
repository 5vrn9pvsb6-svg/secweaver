#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]] || ! command -v systemctl >/dev/null 2>&1; then
  echo "This integration test requires Linux with systemd." >&2
  exit 2
fi
if [[ "${EUID}" -ne 0 ]]; then
  echo "Run this integration test as root." >&2
  exit 2
fi

readonly SERVICE="secweaver-agent-upgrade-integration"
readonly UNIT="/etc/systemd/system/${SERVICE}.service"
readonly ROOT="$(mktemp -d /var/tmp/secweaver-agent-upgrade.XXXXXX)"
readonly AGENT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly BIN="${ROOT}/secweaver-agent"
readonly STATE="${ROOT}/state"
readonly CONFIG="${ROOT}/config.json"
readonly LAUNCHER="${ROOT}/secweaver-agent-launch"
readonly GOOD_TARGET="${ROOT}/artifacts/secweaver-agent_0.3.1_linux_$(go env GOARCH)"
readonly FAILED_TARGET="${ROOT}/artifacts/secweaver-agent_0.3.2_linux_$(go env GOARCH)"

cleanup() {
  systemctl stop "${SERVICE}" >/dev/null 2>&1 || true
  systemctl disable "${SERVICE}" >/dev/null 2>&1 || true
  rm -f "${UNIT}"
  systemctl daemon-reload >/dev/null 2>&1 || true
  if [[ "${KEEP_INTEGRATION_ARTIFACTS:-0}" != "1" ]]; then
    rm -rf "${ROOT}"
  else
    echo "kept integration artifacts: ${ROOT}"
  fi
}
trap cleanup EXIT

cd "${AGENT_ROOT}"
mkdir -p "${STATE}" "${ROOT}/artifacts"
install -m 0755 "${AGENT_ROOT}/packaging/secweaver-agent-launch" "${LAUNCHER}"
go build -trimpath -ldflags "-X main.version=0.3.0" -o "${BIN}" .
go build -trimpath -ldflags "-X main.version=0.3.1" -o "${GOOD_TARGET}" .
go build -trimpath -tags integrationhealthfail -ldflags "-X main.version=0.3.2" -o "${FAILED_TARGET}" .
go run ./cmd/update-sign -generate-key "${ROOT}/update-signing.key"

write_manifest() {
  local version="$1"
  local artifact="$2"
  cat >"${ROOT}/unsigned-manifest.json" <<JSON
{
  "schema_version": "1",
  "app": "secweaver-agent",
  "channel": "stable",
  "latest": {"version": "${version}"},
  "binaries": {
    "linux_$(go env GOARCH)": {
      "url": "$(basename "${artifact}")",
      "sha256": "pending"
    }
  }
}
JSON
  go run ./cmd/update-sign \
    -manifest "${ROOT}/unsigned-manifest.json" \
    -artifact-dir "${ROOT}/artifacts" \
    -private-key-file "${ROOT}/update-signing.key" \
    -out "${ROOT}/artifacts/update-manifest.json"
}

write_manifest "0.3.1" "${GOOD_TARGET}"
readonly PUBLIC_KEY="$(tr -d '[:space:]' <"${ROOT}/update-signing.key.pub")"

cat >"${CONFIG}" <<JSON
{
  "enterprise_id": "TESTUPGRADE00001",
  "status_path": "${ROOT}/status.json",
  "license": {"enabled": false},
  "update": {
    "enabled": true,
    "manifest_url": "${ROOT}/artifacts/update-manifest.json",
    "channel": "stable",
    "interval_seconds": 3600,
    "initial_delay_seconds": 1,
	"retry_initial_seconds": 1,
	"retry_max_seconds": 5,
    "auto_install": true,
    "state_dir": "${STATE}",
    "self_path": "${BIN}",
    "status_output": "${ROOT}/update-status.jsonl",
    "device_id": "integration-linux-device",
    "public_key": "${PUBLIC_KEY}",
    "require_server_policy": false,
    "health_timeout_seconds": 5,
    "lock_stale_seconds": 60,
    "max_backups": 2,
    "min_free_space_mb": 1
  },
  "modules": {
    "host-process-snapshot": {
      "enabled": true,
      "restart": "on_failure",
      "args": ["-interval", "30s", "-output", "${ROOT}/host-process.jsonl"]
    }
  }
}
JSON

cat >"${UNIT}" <<UNIT
[Unit]
Description=SecWeaver Agent service-upgrade integration test
StartLimitIntervalSec=0

[Service]
Type=simple
Environment=SECWEAVER_AGENT_BIN=${BIN}
Environment=SECWEAVER_AGENT_UPDATE_STATE_DIR=${STATE}
Environment=SECWEAVER_AGENT_RESTART_EXIT_CODE=75
ExecStart=${LAUNCHER} run -config ${CONFIG}
Restart=on-failure
SuccessExitStatus=75
RestartForceExitStatus=75
RestartSec=1s

[Install]
WantedBy=multi-user.target
UNIT

chmod 0755 "${BIN}"
systemctl daemon-reload
systemctl enable --now "${SERVICE}"

deadline=$((SECONDS + 120))
while (( SECONDS < deadline )); do
  if [[ -f "${STATE}/state.json" ]] \
		&& grep -q '"last_update_status": "healthy"' "${STATE}/state.json" \
		&& "${BIN}" version | grep -q 'secweaver-agent 0.3.1' \
		&& systemctl is-active --quiet "${SERVICE}"; then
		echo "PASS: systemd activated N and confirmed service health"
		break
  fi
  sleep 1
done

if ! grep -q '"last_update_status": "healthy"' "${STATE}/state.json" 2>/dev/null; then
  systemctl status "${SERVICE}" --no-pager || true
  journalctl -u "${SERVICE}" --no-pager -n 200 || true
  cat "${STATE}/state.json" 2>/dev/null || true
  echo "FAIL: systemd service did not complete the healthy upgrade" >&2
  exit 1
fi

write_manifest "0.3.2" "${FAILED_TARGET}"
systemctl restart "${SERVICE}"

deadline=$((SECONDS + 120))
while (( SECONDS < deadline )); do
  if [[ -f "${STATE}/state.json" ]] \
		&& grep -q '"last_update_status": "rolled_back"' "${STATE}/state.json" \
		&& "${BIN}" version | grep -q 'secweaver-agent 0.3.1' \
		&& systemctl is-active --quiet "${SERVICE}"; then
		systemctl stop "${SERVICE}"
		echo "PASS: systemd restored N after N+1 failed its health check"
		exit 0
  fi
  sleep 1
done

systemctl status "${SERVICE}" --no-pager || true
journalctl -u "${SERVICE}" --no-pager -n 200 || true
cat "${STATE}/state.json" 2>/dev/null || true
echo "FAIL: systemd service did not complete automatic rollback" >&2
exit 1

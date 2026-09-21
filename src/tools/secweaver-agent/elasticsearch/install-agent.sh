#!/usr/bin/env bash
# Fresh Linux installations only. Do not convert an enrolled/managed host or
# overwrite identity, state, configuration, service units, or existing binaries.
set -euo pipefail
if [[ $# != 2 ]]; then
  echo "Usage: sudo bash install-agent.sh /absolute/path/secweaver-agent 16_CHAR_LOCAL_ID" >&2
  exit 2
fi
[[ $(uname -s) == Linux && $EUID == 0 ]] || { echo 'Linux root is required' >&2; exit 1; }
[[ $1 == /* && -f $1 && -x $1 ]] || { echo 'An absolute executable Agent binary path is required' >&2; exit 1; }
[[ $2 =~ ^[A-Z0-9]{16}$ ]] || { echo 'ID must be 16 uppercase ASCII letters/digits' >&2; exit 1; }
# The ES helper now lives inside the Agent source tree; resolve its parent
# directly so the installer works from any current working directory.
source_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
target=/opt/secweaver-agent
unit=/etc/systemd/system/secweaver-agent.service
command -v python3 >/dev/null
command -v systemctl >/dev/null
[[ -d /run/systemd/system ]] || { echo 'A running systemd host is required' >&2; exit 1; }
[[ ! -e $target && ! -L $target && ! -e $unit && ! -L $unit ]] || {
  echo 'Existing installation/path found; no files changed. Upgrade manually, preserving identity.' >&2; exit 1;
}
if systemctl cat secweaver-agent.service >/dev/null 2>&1; then
  echo 'Existing systemd unit found; no files changed' >&2; exit 1
fi
"$1" version
for name in config.example.json audit-port-execmon.example.json host-persistence.example.json packaging/secweaver-agent-launch packaging/secweaver-agent.service; do
  [[ -f "$source_dir/$name" ]] || { echo "Missing public source file: $name" >&2; exit 1; }
done
umask 077
# A failed privileged installation must remain inspectable. Never guess which
# files to delete or erase an identity as part of an automatic rollback.
trap 'echo "Installation failed; partial files may remain. Inspect before retrying; no automatic cleanup." >&2' ERR
install -d -m 0700 "$target" "$target/bin" "$target/etc" "$target/data" "$target/logs"
install -m 0755 "$1" "$target/bin/secweaver-agent"
install -m 0755 "$source_dir/packaging/secweaver-agent-launch" "$target/bin/secweaver-agent-launch"
install -m 0600 "$source_dir/audit-port-execmon.example.json" "$target/etc/audit-port-execmon.json"
install -m 0600 "$source_dir/host-persistence.example.json" "$target/etc/host-persistence.json"
# The explicit standalone profile is for a NEW self-managed host only. It has
# no enrollment, remote policy, or automatic update service dependency.
python3 - "$source_dir/config.example.json" "$target/etc/config.json" "$2" <<'PY'
import json
import sys
from pathlib import Path
config = json.loads(Path(sys.argv[1]).read_text())
config['enterprise_id'] = sys.argv[3]
for key in ('license', 'remote_config', 'update'):
    config[key] = {'enabled': False}
with Path(sys.argv[2]).open('x') as stream:
    json.dump(config, stream, indent=2)
    stream.write('\n')
PY
install -m 0644 "$source_dir/packaging/secweaver-agent.service" "$unit"
systemctl daemon-reload
echo 'Installed but NOT started. Inspect configs, then run preflight before enabling the service.'
echo 'On failure, partial files are preserved for inspection; no automatic deletion or rollback.'

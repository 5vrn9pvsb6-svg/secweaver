# Dynamic Bootstrap Version

Agent source 0.3.21 removes the installed-version constant from Linux and Windows
Bootstrap scripts. The fixed installation URL resolves
`https://agent-gateway.id-net.cn:30443/secweaver-agent/releases/latest-version.txt`
once, then downloads the corresponding immutable version directory and SHA-256
sidecar. An explicit `--version` / `-Version` remains for controlled testing.

The pointer is one ASCII version (at most 64 characters), optionally followed by
one LF. Empty, malformed, missing or unavailable pointers stop installation before
host changes; there is no old-version fallback. Initial installation trusts the
HTTPS publication plus archive SHA-256, not a detached signature on this pointer.
After installation, unsigned updates are accepted by default with HTTPS plus artifact SHA-256/size
verification. Configure an update public key to require signed manifests; signed trust changes,
emergency stops, and remote rollbacks remain available only in that mode.
This channel applies to new installs, not forced upgrades of existing devices.

Linux prerequisites remain Bash, curl/wget, tar, SHA-256 tooling, coreutils and
systemd on amd64/arm64/loong64. Windows requires elevated PowerShell 5.1+ on
amd64/arm64; macOS is unsupported. Version pointers must be served with `no-store`.

## Publication

### Enrollment Identity (0.3.22)

The Linux installer derives its update device ID from the same successful
enrollment that supplies the enterprise ID. Token-only installation needs no
`--update-device-id`; an explicitly conflicting value fails closed. Legacy
enterprise-ID installation still needs an explicit update ID when updates are
enabled. Windows behavior is unchanged.

`secweaver-agent enroll` retains enterprise-ID-only stdout by default.
`-output installer` emits exactly `enterprise_id<TAB>device_id<LF>` after saving
the identity. Invalid output formats fail before enrollment; private keys and
tokens are never printed. Pair installers with the binary from the same release;
older binaries do not support this option.

License state/key paths explicitly use `STATE_DIR`. Retry with the same state and
key to reuse the device identity: preserve `data/license-state.json` and
`data/device-ed25519.key` after partial installation. Later failure does not undo
server registration. Do not delete local identity to bypass device quotas.

Run `go test -race . ./pkg/agentlicense` in the Agent directory. Tests cover real
TLS enrollment output and stable retries, plus isolated Bash installation with
token-only, matching/conflicting IDs, malformed output, enrollment failure and
legacy installation. This does not prove live SLS upload. The fix is available from 0.3.22. Publish immutable packages for the current
version and promote the channel, then verify token-only installation, identity reuse,
and upload on a controlled Linux test host; changing only the
outer Bootstrap cannot repair the installer inside old 0.3.19 packages.

Publish all five reviewed archives and matching sidecars under
`<release-root>/<version>/`, using the original immutable bytes. Then run:

```bash
python3 scripts/publish-release-channel.py --release-root /srv/secweaver-agent/releases --version <reviewed-version>
```

The publisher validates names, hashes, size and non-writable/non-symlink files,
then atomically replaces only `latest-version.txt`. A failure preserves the old
pointer. Keep the entire tree publisher-owned and serialize publications. An
explicit older version may be promoted for new installs only; existing devices
still require the signed downgrade authorization workflow.

To render only new Bootstrap scripts, retain all normal `BOOTSTRAP_*` configuration and optionally
set `BOOTSTRAP_UPDATE_PUBLIC_KEY_FILE=<existing-public-key>` before running
`BOOTSTRAP_ONLY=1 OUT_DIR=<fresh-output-directory> ./scripts/package-release.sh`. No signing private
key or Agent rebuild is required in this mode. Source provenance/version gates still apply; dirty
builds are test-only. An omitted key preserves unsigned-update mode; never rotate an existing trust
key silently.
Regular packaging does not promote a channel automatically: promotion happens only
after the archives have reached the actual serving directory.

Agent Gateway (server rc.8+) serves the allowlisted pointer from
`AGENT_RELEASE_ROOT/releases/latest-version.txt`; the query service cannot serve it.
Deploy `install.sh`, `install.ps1`, versioned archives, and the configured Logtail installer before
claiming full installation/upgrade readiness. Publish the update public key and signed assets only
when the optional signed-update mode is selected.

## Verification

`python3 -m unittest tests.test_secweaver_agent_wrappers tests.test_agent_release_channel`
from the repository root checks Linux resolution, explicit pins, missing/invalid
pointers and failed promotion. Server `TestReleaseVersionPointer` checks GET/HEAD,
no-store, invalid content and query-route isolation. Windows syntax/flow must also
be verified on a real Windows test host; source checks are not OS acceptance.

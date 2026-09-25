# Dynamic Bootstrap Version

## Installation Progress (0.3.44)

Linux SaaS Bootstrap now prints eight numbered steps to stderr. Terminal success is
green `OK`, failure red `FAIL`, recovery/other warnings yellow `WARN`; `RUN`, `INFO` and
`SKIP` stay plain. Color depends on stderr being a terminal, not stdin, so the curl
pipeline supports it. Redirected output and `TERM=dumb` are plain. Pass `--no-color`
after the installation arguments or set a nonempty `NO_COLOR` in the sudo environment
to disable ANSI escapes explicitly. No color or progress change applies to Windows
PowerShell or a direct archive `install.sh` invocation in this release.

Steps: resolve version; download/checksum/extract; install/register/configure Agent;
preflight; install/reuse Logtail; configure its identity/service handoff; start Agent;
verify local health. A step gets OK only after its commands succeed, with elapsed
seconds. `--skip-logtail` and `--no-start` show SKIP for omitted work. Existing Logtail
is reused. The installer does not label cloud delivery successful from local checks.

Full child-installer, configuration, vendor and diagnostic output goes to a unique
`/opt/secweaver-agent/install-logs/install.log.*` file (0600, directory 0700), whose path
is printed at the start and end/failure. These text logs are outside collected JSONL
paths and survive setup failure; `uninstall.sh --purge` removes them with the root.
They can contain host/configuration details, so share only reviewed/redacted excerpts.
No command tracing or enrollment arguments are deliberately recorded. Review/remove old
installation logs as needed; there is one file per invocation, not a background stream.
Use `sudo tail -f <printed-log-path>` in a second terminal for detailed progress.

Failure stops the flow, preserves the failing exit status and prints the failed stage
and log path. HTTP 401 adds token recovery guidance. Signals return 130/143. An expected
auto-backend fallback from unavailable BTF and newly empty event logs are INFO; other
diagnostic warnings/errors remain visible. Vendor graceful-stop failure becomes one
WARN before bounded force-stop; repeated PID output stays in the log. Service checks
must still pass before OK. Standalone doctor output/severity is unchanged.

Regression checks exercise real PTYs, plain redirected output, NO_COLOR, child failures,
preflight/doctor failures, immutable pointer failures and private log permissions.
Post-release acceptance should verify the public script on a Linux systemd host, then
confirm services and actual cloud receipt independently.

Since 0.3.42 the Linux SaaS default is `cn-hangzhou-internet`. Explicit intranet selectors
are preserved. Downloads and vendor installation now have bounded time/retries and
stage/host errors; see [network policy](collector-lifecycle.md#network-policy).

Agent 0.3.41 adds serialized Logtail/systemd handoff, stops vendor-started daemons
under `--no-start`, and records SLS intent before download. Doctor runs after collector
startup. See [collector lifecycle and verification](collector-lifecycle.md).

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
enabled. Windows gained the same enrollment identity handling in 0.3.46; see
[Windows installation](windows-installation.md).

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
python3 scripts/publish-release-channel.py --release-root /srv/secweaver-agent/releases --version <reviewed-version> --runtime-user secweaver-agent-gateway
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

# Dynamic Bootstrap Version

## Linux Audit Queue Precheck (0.3.80)

The Linux archive's `install.sh` checks native audit queues after dependencies
are ready and before device enrollment or Agent startup. SLS SaaS and private ES
use this installer. This step targets native systemd Linux hosts with standard
audit configuration paths, not Windows or the Docker workload profile. It needs
root, Bash, coreutils (including GNU `timeout`), awk, auditctl and an auditd unit.

| Setting | Installer behavior |
| --- | --- |
| audit 2.x, including common CentOS 7 versions | Check `q_depth` in `/etc/audisp/audispd.conf` when the native dispatcher is `/sbin/audispd` or `/usr/sbin/audispd` |
| audit 3.x/4.x | Check `q_depth` in `/etc/audit/auditd.conf` |
| Dispatcher queue | Raise missing values or values below `2000` to `2000`; preserve larger values |
| Kernel backlog | Use a floor of `8192`, preserving larger running values or values anywhere in the native persistent ruleset |
| Persistent rules | Inspect `-b` in `/etc/audit/audit.rules` and `/etc/audit/rules.d/*.rules`; provide missing native-loader settings before any `-e 2` lock |

Only smaller queue numbers change. `max_restarts`, `disp_qos`, plugins, `-e`, `-f`
and unrelated rules remain intact. Changed files get unique same-directory
`.secweaver-backup.<suffix>` backups whose complete paths appear in the log,
then atomic replacement retaining permissions, ownership and security metadata.
Backup filenames do not end in `.rules`, so augenrules cannot load them as policy.
Concurrent changes detected before publication stop installation. Repeating an
install does not rewrite adequate values or request another dispatcher reload.

A running daemon is reloaded only when dispatcher settings change, never
restarted or killed. Hosts with native `/etc/init.d/auditd` use
`service auditd start/reload`, including CentOS 7; other hosts use systemctl.
Service operations have 30-second limits; status/auditctl probes have 10-second
limits, followed by up to 5 seconds to terminate the command. No `auditctl -D/-R`
or `augenrules --load` runs. Live backlog uses `auditctl -b` and read-back
verification. The service must be active and the kernel must report a valid
daemon PID and `enabled=1/2`. Start, reload, registration or live-queue failures
stop subsequent installation with a specific error.

For `enabled=2`, retain the immutable policy, persist the backlog floor and warn
that a reboot is required; never unlock it. Dispatcher settings may still reload.
Unknown audit major versions, custom/disabled audit 2.x dispatchers and duplicate
or invalid `q_depth` settings are warned about and left unchanged. Unsafe backlog
syntax, symlinks, files over 1 MiB or more than 256 rule files block automatic
handling. Deployments using custom auditd configuration directories should opt
out and have operators maintain the actual configuration.

Disable queue changes while retaining dependency and service checks:

```bash
sudo env AUDIT_TUNE=0 ./install.sh \
  --enterprise-enrollment-token 'swenr_TOKEN_ID.SECRET' \
  --license-server-url https://agent-gateway.id-net.cn:30443
```

`INSTALL_DEPS=0` skips dependency installation, audit service operations and queue
changes together. It is for controlled hosts where operators have already
prepared and verified audit. Installation success under this override does not
verify those settings. Bootstrap users can pass the same environment variables
through `sudo env`; the Linux child installer inherits them.

Configuration may already have been raised when a later step fails. Backups and
installation logs are retained; the installer does not automatically undo
completed steps. For rollback, stop the Agent, restore each exact backup path
reported in the log, then use native `service auditd reload` or systemctl reload
for dispatcher settings. Restoring backlog also requires consistent persistent
`-b` directives and a mutable live-kernel value; immutable kernels require reboot.
Do not restore multiple backups using a wildcard.

After installation verify daemon PID, backlog_limit and lost deltas with
`auditctl -s`, the matching `q_depth` file, the auditd journal and actual audit.log
writes. Independently verify Agent JSONL and cloud receipt. Larger queues absorb
bursts; they do not fix slow plugins or sustained host-wide fork/exec auditing.
Do not interpret higher values as a cure for `dispatch err (pipe full)`.
Isolated regressions cover both native loaders, audit 2/3/4, larger values,
immutability, idempotence and service/kernel failures. Real CentOS 7 acceptance
still needs the target kernel and plugin configuration, reload verification,
business peaks and the cloud upload path.

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
and log path. From 0.3.70, enrollment failure also shows an allowlisted rejection
code and matching recovery summary; see [enrollment diagnostics](collector-lifecycle.md#enrollment-rejection-diagnostics-0370).
Signals return 130/143. An expected
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
Bootstrap scripts. Newer Bootstrap releases resolve the OS-family pointer once:
Linux reads `releases/latest-linux-version.txt` and Windows reads
`releases/latest-windows-version.txt`. A legacy Gateway returning HTTP 404 for that
family pointer falls back to `releases/latest-version.txt`; TLS, DNS, timeout, 5xx,
empty and malformed responses fail closed. The selected immutable version directory
and SHA-256 sidecar are then downloaded. An explicit `--version` / `-Version` remains
for controlled testing.

Agent 0.3.76 fixes Linux pointer initialization with Bash `set -u`. Both curl
and GNU wget permit legacy fallback only after a completed HTTP 404 error;
a timeout after receiving 404 headers is still a failure. Temporary bodies and
wget response-header files are removed on download failure. Test-only `file://`
fixtures treat an absent family file as 404, but copy errors still fail closed;
this does not enable local-file installation in production. Publish newly rendered
0.3.76 Bootstrap scripts to repair the public entry point; never replace archives
already published as 0.3.75.

The pointer is one ASCII version (at most 64 characters), optionally followed by
one LF. Except for the family-pointer 404 fallback above, empty, malformed,
missing or unavailable pointers stop installation before host changes; no cached
or embedded old version is selected. Initial installation trusts the
HTTPS publication plus archive SHA-256, not a detached signature on this pointer.
After installation, configurations without signing trust accept unsigned updates with HTTPS
plus artifact SHA-256/size verification. A signed SaaS Bootstrap provisions the release public
key and requires signed manifests; signed trust changes, emergency stops and remote rollbacks
remain available only in that mode. Generic archives leave automatic updates disabled. See
[update trust configuration](tenant-auto-update.md#update-trust-configuration-0379).
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

Publish the complete legacy release and matching sidecars under
`<release-root>/<legacy-version>/`, then publish any newer family archives under
their own immutable version directory. For example, Linux can advance while the
legacy and Windows pointers stay on the previous complete release:

```bash
python3 scripts/publish-release-channel.py \
  --release-root /srv/secweaver-agent/releases \
  --version <complete-legacy-version> \
  --linux-version <linux-version> \
  --windows-version <windows-version> \
  --runtime-user secweaver-agent-gateway
```

The publisher validates the five legacy archives plus only the selected Linux/Windows
family archives, checks names, hashes, size and non-writable/non-symlink files, then
atomically replaces each pointer. A failure before replacement preserves the old channel;
each pointer is individually atomic, so serialize publishers. Older Agents continue to
read `latest-version.txt`; newer Bootstraps use the family pointer. Existing devices still
require the signed downgrade authorization workflow.

To render only new Bootstrap scripts, retain all normal `BOOTSTRAP_*` configuration and optionally
set `BOOTSTRAP_UPDATE_PUBLIC_KEY_FILE=<existing-public-key>` before running
`BOOTSTRAP_ONLY=1 OUT_DIR=<fresh-output-directory> ./scripts/package-release.sh`. No signing private
key or Agent rebuild is required in this mode. Source provenance/version gates still apply; dirty
builds are test-only. Signed deployments must supply the existing public key when rendering
their Bootstrap so fresh hosts receive trust. From Agent 0.3.79, an omitted installer key
preserves existing host trust; only a fresh configuration without trust stays unsigned.
Never rotate an existing trust key silently.
Regular packaging does not promote a channel automatically: promotion happens only
after the archives have reached the actual serving directory.

Agent Gateway (server rc.69+) serves the allowlisted global and family pointers from
`AGENT_RELEASE_ROOT/releases/latest-*-version.txt`; the query service cannot serve them.
Deploy `install.sh`, `install.ps1`, versioned archives, and the configured Logtail installer before
claiming full installation/upgrade readiness. Publish the update public key and signed assets only
when the optional signed-update mode is selected.

## Verification

`python3 -m unittest tests.test_secweaver_agent_wrappers tests.test_agent_release_channel`
from the repository root checks Linux resolution, explicit pins, missing/invalid
pointers and failed promotion. Server `TestReleaseVersionPointer` checks GET/HEAD,
no-store, invalid content and query-route isolation. Windows syntax/flow must also
be verified on a real Windows test host; source checks are not OS acceptance.

In the Agent directory, run `go test . ./pkg/agentupdate -run 'TestBootstrapOptionalPointer|TestPlatformManifest'`.
These regressions use deterministic transports and explicit Linux/Windows platform
identities, independent of the test host OS. They cover only version selection
and validation, not Windows SCM upgrade or actual cloud upload acceptance.

# secweaver-agent

Source 0.3.60 fixes localized Windows `cmd ver` fallback labels by reporting only
the complete numeric build; CIM still supplies the preferred product caption.

Source 0.3.59 adds the Windows product name and system version to registration
and heartbeat metadata; Linux already reports its distribution/version. See
[operating-system inventory](#operating-system-inventory) for prerequisites and fallback behavior.

Source 0.3.58 clarifies Windows installation warnings and retains PowerShell 5.1 native architecture detection, persistent offline Windows uninstall/purge with reliable CMD self-removal, Bootstrap cleanup, native Logtail cache compatibility, explicit Windows learning migration, compact PowerShell risk
records and staged installation results. See [Windows installation](docs/windows-installation.md).
It requires an operator-signed Windows SLS collection contract, checks
delivered rules before installation succeeds, and reports missing/wrong routes in
doctor and health logs. See [Windows collection readiness](docs/windows-installation.md#windows-sls-collection-readiness).

Source 0.3.49 completes the Windows 0.3.22 regression fixes: validated Bootstrap
responses, pre-activation installation rollback, redacted HTTP/SCM diagnostics and
explicit automatic-update defaults. See [Windows installation](docs/windows-installation.md).

ES and SLS SaaS share one Agent binary and version. Installation channels persist
their ownership; see [deployment modes](docs/deployment-modes.md).

Source 0.3.46 repairs Windows enrollment/update identity and service diagnostics, verifies
startup readiness, and installs a pinned Windows Logtail collector. See
[Windows installation and cloud acceptance](docs/windows-installation.md).

Source 0.3.42 defaults Linux SaaS Logtail to the Hangzhou public-network selector and
bounds downloads/vendor installation. Explicit intranet settings remain unchanged; see
[network policy and migration](docs/collector-lifecycle.md#network-policy).

Source 0.3.41 fixes Logtail service handoff, adds explicit standalone collector cleanup,
and separates local shipper health from unverified cloud delivery. See
[collector lifecycle and diagnostics](docs/collector-lifecycle.md).

Source 0.3.40 fixes Linux supervisor shutdown ordering: audit pipes remain open until
child modules exit, preventing normal restarts from invalidating behavior learning.
Already degraded generations still require explicit relearning; see the recovery guide.

Source 0.3.39 extends Windows learning to eligible outbound network connections and ordinary
`.log` creations. Each type has exact matching and separate summary counts; authentication,
persistence, sensitive/destructive activity and unverified records remain full-output.

Source 0.3.38 adds Windows Sysmon exec learning to both evidence reader modes. Fresh
Windows installs enable 24-hour learning; 4688 and incomplete/sensitive evidence stay
full-output. See the [Windows prerequisites and verification](docs/behavior-learning.md#windows-0339).

Source 0.3.37 adds Linux behavior learning and bounded log reduction, enabled for new
installations with a 24-hour learning period. See [behavior learning](docs/behavior-learning.md)
for eligibility, failure behavior, summary shipping, and remaining real-platform release gates.

Source 0.3.36 makes update-manifest signatures optional. When no update public key is
configured, the Agent accepts an HTTPS manifest and still requires each downloaded
artifact's SHA-256 and size to match. Configuring `public_key` or `trusted_public_keys`
enables strict signed-envelope verification; trust changes, emergency stops, and remote
rollbacks remain signed-only.

Source 0.3.33 replaces hard-coded archive versions in installation examples with
an explicit downloaded-version variable. Runtime behavior, configuration, and schemas
are unchanged.

Source 0.3.32 clarifies the packaged documentation boundary between Community and
managed services. Self-managed ES troubleshooting now references only the public
Filebeat/ES workflow, and managed Bootstrap values come from deployment-owned inputs
outside the repository. Runtime behavior, configuration, and schemas are unchanged.

Source 0.3.31 updates the packaged documentation index to reference the historical
Agent Linux eBPF/Audit assessment under `docs_dev/history/`. Runtime behavior,
configuration, and schemas are unchanged.

Source 0.3.30 keeps the 0.3.29 Linux container snapshot correction and replaces
live-environment addresses in packaged test fixtures with RFC 5737 documentation
addresses. This release-policy change does not alter runtime behavior or schemas.

Source 0.3.29 corrects Linux container snapshot PID counting across cgroup v1/v2
controller entries. `process_count` is the number of unique observed PIDs; `pids`
contains up to 100 sorted unique values. `process_count > len(pids)` indicates a
truncated list. The existing parser/schema contract is unchanged. After an upgrade,
corrected counts appear in the next full baseline (or after collector restart);
historical events are not rewritten. Windows collection is unchanged. Verify with
`go test ./pkg/hoststatesnapshot -run TestContainerProcessCountDeduplicatesControllersBeforeLimit`
from this directory. This source change does not publish or deploy a package.

Versions in archive-name examples refer to the archive you downloaded. Use its actual version when installing. `VERSION` defines the next source build; changing it does not mean a package has been published.

## Operating-system inventory

Managed registration and heartbeats report `os` (`linux`/`windows`) and optional
`os_version`. These describe the Agent host, not the service receiving its logs.
Standalone logging without registration does not require this metadata.

- Linux reads `/etc/os-release`, then `/usr/lib/os-release`: `PRETTY_NAME` takes
  precedence, otherwise `NAME` plus `VERSION_ID`. For example, `Ubuntu 22.04.5 LTS`
  or `CentOS Stream 9`. Without distribution metadata, a bounded `uname -sr`
  fallback supplies only the kernel; it does not identify a distribution.
- Windows 0.3.59 uses local Windows PowerShell 5.1+ and CIM `Win32_OperatingSystem`
  (`Caption` and `Version`), for example
  `Microsoft Windows Server 2019 Standard (10.0.17763)`. The read-only probe has a
  three-second timeout. If blocked, malformed or unavailable, it falls back to
  `cmd /d /c ver` with a two-second timeout. Since 0.3.60, that fallback extracts
  only the ASCII build, e.g. `Windows (10.0.17763.9245)`, instead of forwarding
  local code-page bytes as UTF-8. No patch digits are dropped and no edition is
  guessed. CIM output with invalid UTF-8 or replacement characters is rejected.
  Failed/unrecognized probes omit this optional field;
  they do not stop enrollment. Labels must fit the existing 128-byte UTF-8 limit.
  The exact fixed PowerShell script is marked as internal collector activity.

Existing managed Windows hosts require the new Agent build and a successful
heartbeat to replace old numeric-only labels. Offline hosts keep their last report;
updating source alone does not publish a package or change stored inventory.
No new protocol field or database migration is required.

Older raw command labels may already contain irreversible replacement characters
in stored metadata. Upgrading to 0.3.60 corrects future registration/heartbeats;
it does not rewrite historical records or upgrade other hosts automatically.

Verify Linux against `/etc/os-release`, and Windows against
`Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version`, then inspect
the host's next registered/heartbeat metadata. From this directory,
`go test ./pkg/agentlicense -run OSVersion` covers formatting, distribution names
and probe failures on any development OS. Cross-compilation and mocked tests do
not replace checking an actual Windows host after installation.

## Choose Your Workflow

| Role / goal | Start here |
|---|---|
| SaaS customer installing a host collector | [Data Cloud customer quickstart](../../../docs_user/29-secweaver-data-system-quickstart.md) |
| Community user sending logs to a self-managed ES | [Public initialization, standalone install, and Filebeat guide](../../../src/tools/secweaver-agent/elasticsearch/README.md) |
| Developer building the public binary | [Build](#build): `make build` needs no SaaS deployment values |
| Release maintainer producing managed packages | [Managed release packaging](#managed-release-packaging): Bootstrap prerequisites apply; signing is optional |

The managed SaaS customer guides are in the Community source archive. An extracted Agent
package includes `elasticsearch/README.md` and `elasticsearch/README.zh-CN.md` for the
self-managed ES path, including its initializer and Filebeat example. This engineering
manual also describes managed-service compatibility; it does not bundle an ES Operator or
provision a SaaS service. Agent 0.3.21 adds dynamic Bootstrap version resolution;
runtime and parser contracts are unchanged. This does not imply new Agent binaries were published.

Agent 0.3.22 fixes Linux token-only installation with automatic updates by reusing
the enrolled device ID. See [identity and retry compatibility](docs/bootstrap-channel.md#enrollment-identity-0322).
Existing published packages are not replaced automatically.

`secweaver-agent` is the unified host-side client. A server installs one binary, and new collectors are added as modules behind the same program.

Built-in modules:

| Module | OS | Source package | Purpose |
|---|---|---|---|
| `audit-port-execmon` | Linux | `pkg/auditportexecmon` | auditd-based exec/connect/file evidence collection for external listener processes |
| `syslog-risk-json` | Linux | `pkg/syslogriskjson` | Linux auth/syslog risk parsing to JSON Lines |
| `host-persistence` | Linux/Windows | `pkg/hostpersistence` | persistence change monitoring for Linux cron/systemd/authorized_keys/sudoers/profile paths and Windows scheduled-task/startup/profile script paths; Linux can enrich with auditd actor/process data |
| `host-process-snapshot` | Linux/Windows | `pkg/hostprocesssnapshot` | emits startup/daily process baselines plus 10-minute start, exit, executable, command, cgroup, and privilege deltas |
| `host-state-snapshot` | Linux/Windows | `pkg/hoststatesnapshot` | inventories listening sockets and tracks identity, service/task, kernel-module, and container-context changes |
| `windows-eventlog-risk-json` | Windows | `pkg/windowseventlogriskjson` | Windows Event Log risk parsing to JSON Lines |
| `windows-process-execmon` | Windows | `pkg/windowsprocessexecmon` | Windows process/network/file evidence from Security 4688 and Sysmon events |

Topic index: [installation, metrics, health logs, disk protection, and releases](docs/README.md).

## Read by Role

- Installation and troubleshooting: start with the support matrix below, then [configuration](#config), [running](#run) and [migration](#migration).
- Release maintenance: see [managed packaging](#managed-release-packaging), [updates](#update) and [key rotation/emergency stop](#signing-key-rotation-and-emergency-stop). Users need not read release parameters first.
- Module development: see [architecture](#architecture), [build](#build) and [adding modules](#adding-modules).
- Metrics, self-managed ES and disk protection procedures remain in the [topic index](docs/README.md).

## Support Matrix And Diagnostics

The supported collection targets are Linux systemd hosts, Windows service hosts,
and Linux container workloads. The Docker profile is intentionally scoped to the
workload container; it is not a substitute for a host security sensor.

| Platform | Status | Notes |
|---|---|---|
| Linux systemd, amd64/arm64/loong64 | Supported | Default Linux packages, `install.sh`, auditd, syslog, and host-persistence target this environment |
| Windows, amd64/arm64 | Pilot supported | Installs as the `SecWeaverAgent` service; depends on Windows Event Log, Security audit policy, optional Sysmon, and file-based host-persistence polling; managed Logtail requires amd64, ARM64 needs a separate shipper |
| WSL2 Linux environment | Client/development only | Can run Community Python tools as Linux, but is not a Windows host sensor and does not collect the host's Event Log, Security 4688, Sysmon, or Windows services |
| Non-systemd Linux | Not a default install target | The binary can be run manually, but the release installer rejects service installation by default |
| Linux containers | Supported workload profile | Non-root Docker deployment collects its own process, socket, identity, and cgroup/container state; it never claims host audit or persistence coverage |
| macOS | Not a collection target | macOS can be used for development/building, but host collection modules are not supported |

Run preflight before installation or during troubleshooting:

```bash
secweaver-agent preflight -config /opt/secweaver-agent/etc/config.json
secweaver-agent preflight -config /opt/secweaver-agent/etc/config.json -strict
secweaver-agent doctor -config /opt/secweaver-agent/etc/config.json
secweaver-agent doctor -config /opt/secweaver-agent/etc/config.json -json
```

`preflight` checks OS/module compatibility, systemd, root privileges, container hints, `auditctl`/audit log, `netstat`/`/proc`, traditional syslog files, `host-persistence` config readability, Windows `wevtutil`/Event Log channels, 4688 command-line audit policy, and scheduled update settings. `-strict` returns non-zero when an `ERROR` check is reported.

`doctor` includes preflight, Agent service state, authorization connectivity, local `status.json`, recent module output, and Logtail service/process/identity checks. Bootstrap records SLS intent before installing Logtail: a missing expected collector is an error, not a skipped success. With no SLS intent or installation, doctor warns that delivery is unverified; it does not require Alibaba Cloud identity for an ES deployment. Local checks never prove cloud ingestion. Use server-side machine-group and Logstore checks for SLS, and the [public ES guide](elasticsearch/README.md) for Filebeat output/ingestion checks. `-json` emits a machine-readable report. `run -dry-run` prints preflight; normal `run` prints warning/error summaries to stderr. Windows service mode records its latest failure in `<config-path>.service-error.txt` (bounded to 16 KiB); also use SCM/Event Viewer and module JSONL outputs.

Known boundaries:

- `syslog-risk-json` reads traditional log files; journald-only input is not implemented yet.
- Windows Event Log modules persist `EventRecordID` cursors under `C:\ProgramData\SecWeaver\Agent\data\*.cursor.json`; after service restarts they resume from the cursor, and only fall back to the lookback window on first start or missing state.
- Windows process command lines require 4688 command-line audit policy; network and file evidence require Sysmon.
- Windows `host-persistence` monitors file-based persistence locations only; registry persistence is not collected by this module yet.

## Docker Container Workload Deployment

Each Linux release archive includes `container/Dockerfile`,
`container/docker-compose.yaml`, and `container/config.container.example.json`.
This profile is for an application owner who needs evidence for one workload
container. It enables `host-process-snapshot` and `host-state-snapshot`, so the
events describe the container PID, network, filesystem identity, and cgroup
namespace. It deliberately disables `audit-port-execmon`, `host-persistence`,
and `syslog-risk-json`: those modules manage or read host security resources and
must run through the normal Linux systemd installation on the host.

Use an extracted, SHA-256-verified Linux Agent archive for the target CPU
architecture. Docker Compose builds the image from that archive's signed binary;
it does not compile Agent source code in the image.

```bash
AGENT_VERSION='<downloaded-version>'
tar -xzf "secweaver-agent_${AGENT_VERSION}_linux_amd64.tar.gz"
cd "secweaver-agent_${AGENT_VERSION}_linux_amd64"
cp container/config.container.example.json config.container.json
# Edit config.container.json: set enterprise_id and, when Data Cloud is used,
# enable and configure license.server_url and license.enrollment_id.
docker compose -f container/docker-compose.yaml up -d --build
docker compose -f container/docker-compose.yaml logs --tail=100 secweaver-agent
curl -fsS http://127.0.0.1:9100/metrics | head
```

The Compose profile runs as UID/GID `65532`, uses a read-only root filesystem,
drops every Linux capability, and persists only `/var/lib/secweaver-agent` in a
named volume. It bind-mounts the host `/etc/machine-id` read-only solely as a
stable fingerprint component; the Agent device private key remains in the named
volume. Do not remove that volume during normal image upgrades, otherwise the
recreated workload registers a new device identity. Agent self-update is
disabled in the container configuration because replacing an immutable image is
the update mechanism:

```bash
# Repeat from the next extracted release directory, preserving the Compose volume.
docker compose -f container/docker-compose.yaml up -d --build
```

`secweaver-agent preflight -strict` returns an error when the Docker profile is
changed to enable `audit-port-execmon` or `host-persistence`. Do not add
`privileged`, `pid: host`, or `network_mode: host` to bypass that boundary. For
host process-tree execution, auditd, persistence, and host syslog coverage,
install the regular Agent service on the Linux host instead.

## Architecture

```text
systemd / shell
  └─ secweaver-agent run -config /opt/secweaver-agent/etc/config.json
       ├─ secweaver-agent module audit-port-execmon ...
       ├─ secweaver-agent module syslog-risk-json ...
       ├─ secweaver-agent module host-persistence ...
	   ├─ secweaver-agent module host-process-snapshot ...
       ├─ secweaver-agent module windows-eventlog-risk-json ...
       └─ secweaver-agent module windows-process-execmon ...
```

The supervisor and modules come from the same binary. This keeps deployment to one installed program while preserving module process isolation.

## Build

The Agent has its own version and does not follow the ES Server, SLS Proxy, or Operator Bundle
version. Use one Agent `VERSION` for its binaries, packages, update manifest, and rollout
target; server bundle builders select that release with `AGENT_VERSION`.

```bash
cd src/tools/secweaver-agent
go build -o secweaver-agent .
```

The legacy `verify-p0-fixes.sh` audit regression helper resolves this directory from
the script location, so it can run from any exported archive or contributor checkout.
It writes its binary, backup, and verification report into this Agent source directory.

Cross-build:

```bash
cd src/tools/secweaver-agent
make build-cross
```

`build-cross.sh` writes `dist/update-manifest.json` without a signature by default. Set
`UPDATE_SIGNING_PRIVATE_KEY_FILE` to sign every platform binary and the manifest envelope;
signed artifacts default to `ed25519-sha256` digest signatures. Keep the private key in the
release environment and configure clients with `update-signing-key.pub` as `update.public_key`.
`UPDATE_BASE_URL` controls artifact URLs and `UPDATE_DOWNLOAD_SPREAD_SECONDS` controls bandwidth
spreading. `UPDATE_ROLLOUT_PERCENTAGE` is only for standalone deployments; managed-service release
gates reject it.

### Managed Release Packaging

This section is for maintainers with managed Bootstrap delivery values. A signing environment is
optional; omit `UPDATE_SIGNING_PRIVATE_KEY_FILE` for the default HTTPS plus SHA-256 update path.
It is not a prerequisite for `make build` or standalone ES ingestion.
The commands below intentionally enforce managed release gates; follow the public ES guide
for a source-built standalone installation without those services.

Unified release packages:

```bash
cd src/tools/secweaver-agent
make package
```

`VERSION` is the single Agent release-version source and is injected into both the root command
and `audit-port-execmon -version`. Cross-builds and packages reject a
dirty Agent source tree by default and write both `SOURCE.sha256` and `SOURCE.commit` provenance.
`ALLOW_DIRTY_RELEASE=1` is reserved for local non-production package tests.
Agent versions are immutable: any change under the Agent source/package boundary requires incrementing
the tracked `VERSION` before packaging. Both release scripts compare current source history and
worktree changes with the commit that assigned the version; environment-only overrides and
`ALLOW_DIRTY_RELEASE` cannot bypass this check. A byte-identical rebuild from the same source is the
only supported reuse of an existing version.

The Linux unit uses the systemd 219-compatible `StartLimitInterval=0` to disable the permanent
start-rate latch and `RestartPreventExitStatus=78` to exclude invalid local configuration.
Transient authorization failures retry in-process with backoff instead of relying on rapid systemd
restarts. See [`docs/reliability-and-disk-protection.md`](docs/reliability-and-disk-protection.md).

Before `make package`, publish the Alibaba Cloud Logtail/LoongCollector installer and load the
generated release environment:

```bash
OUTPUT_DIR=/srv/secweaver-sls-proxy/releases/logtail \
PUBLIC_BASE_URL=https://agent-gateway.id-net.cn:30443 \
LOGTAIL_REGION=cn-hangzhou-internet \
src/tools/secweaver-agent/scripts/publish-logtail-installer.sh
source /srv/secweaver-sls-proxy/releases/logtail/release.env
```

The publishing script calculates `BOOTSTRAP_LOGTAIL_INSTALL_SHA256`. `package-release.sh` rejects
placeholder Logtail URLs and empty checksums. It writes an unsigned manifest by default, or a signed
manifest plus public key when `UPDATE_SIGNING_PRIVATE_KEY_FILE` is set, alongside raw platform update
binaries under `dist/updates/stable/`. The private key must never enter a package or Git.

Packages are written to `dist/packages/`. Linux packages are `.tar.gz`; Windows packages are `.zip`. Each package contains one `secweaver-agent` binary plus the platform installer and example config. Every platform archive also includes an `elasticsearch/` directory with a standalone ES template initializer, Filebeat example, and bilingual instructions. The directory also contains Linux and Windows Bootstrap scripts that can be hosted as `/secweaver-agent/install.sh` and `/secweaver-agent/install.ps1`.

The Windows service and console entry points initialize the same optional Prometheus metrics exporter before module supervision. When enabled, its default endpoint is `127.0.0.1:9100/metrics`; `/live` checks only HTTP liveness, while `/health` returns 200 only when every module is running, authorization is current, and no error diagnostic exists. Windows builds use explicit syscall callback adapters for the Service Control Manager ABI and must pass the same metrics lifecycle checks as Linux before release.

The Agent also writes an operations-health JSON Lines stream by default to `/opt/secweaver-agent/logs/secweaver-agent-health.log` (Windows: `C:\ProgramData\SecWeaver\Agent\logs\secweaver-agent-health.log`). It emits a jittered five-minute `health_snapshot`, immediate `health_transition` records for module, authorization, persistence, or audit-reader changes, and `agent_lifecycle` records for startup and normal shutdown. The stream uses the 100MB/five-backup/0600/disk-budget policy. The Community repository's standalone ES integration includes a Filebeat input for this file; native shipper and Fluent Bit delivery configurations are not in the public Agent package. See [`docs/operations-health-report.md`](docs/operations-health-report.md) for the schema and delivery boundaries.

### Who Maintains Bootstrap Release Values

New installs resolve the version dynamically. See [channel publication and verification](docs/bootstrap-channel.md).

Managed-platform maintainers obtain Bootstrap values from their deployment control plane or
controlled configuration and set `BOOTSTRAP_ENROLLMENT_ID`, `BOOTSTRAP_LOGTAIL_ALIUID`,
`BOOTSTRAP_LOGTAIL_REGION`, `BOOTSTRAP_RELEASE_BASE_URL`, `BOOTSTRAP_LOGTAIL_INSTALL_URL`, and
`BOOTSTRAP_LOGTAIL_INSTALL_SHA256` in the packaging environment. The Community source archive
contains no production onboarding fixture, enterprise identifier, or credentials. The Agent
version comes only from the tracked repository `VERSION`; deployment configuration and environment
variables must not replace it.

For the managed SaaS deployment, the authorization origin defaults to
`https://agent-gateway.id-net.cn:30443`; `endpoint` and `BOOTSTRAP_LICENSE_SERVER_URL` are optional
overrides for private deployments. The Logtail installer selector defaults to
`cn-hangzhou-internet`. Explicit `cn-hangzhou` (or legacy alias `hangzhou`) selects
intranet; it is not silently rewritten. Set another supported region/network selector
for a SaaS instance outside Hangzhou. SLS API connector geography remains `cn-hangzhou`,
without the installer-specific `-internet` suffix.

The release script embeds these shared values into `dist/packages/install.sh`. Do not edit
`packaging/bootstrap-install.sh` or a generated public `install.sh` by hand; rebuild the release
when a value changes. Verify the generated script before publishing it:

```bash
sed -n \
  '/SECWEAVER_BOOTSTRAP_EMBEDDED_CONFIG_BEGIN/,/SECWEAVER_BOOTSTRAP_EMBEDDED_CONFIG_END/p' \
  dist/packages/install.sh
```

The output must not contain `YOUR_DATA_CLOUD_HOST`, an empty `EMBEDDED_ENROLLMENT_ID`, or example
values. The customer-facing command only contains `--enterprise-enrollment-token`; the server
resolves `enterprise_id` from that token binding. The authorization origin, Logtail machine-group
ID, AliUid, and region are embedded in `install.sh`. The Agent version is resolved
from `releases/latest-version.txt` at installation time; it is not embedded.

The `elasticsearch/` helper is copied into every platform archive for consistent distribution.
Its Filebeat paths and standalone Agent procedure target Linux; the initializer itself can also
be run from an administrator workstation against an approved Elasticsearch 8.x endpoint.

Linux packages include:

- `etc/secweaver-agent/config.example.json`
- `etc/secweaver-agent/config.schema.json`
- `etc/secweaver-agent/config.windows.example.json`
- `etc/secweaver-agent/audit-port-execmon.example.json`
- `etc/secweaver-agent/host-persistence.example.json`
- `etc/secweaver-agent/host-persistence.windows.example.json`
- `systemd/secweaver-agent.service`
- `elasticsearch/init_es.py`
- `elasticsearch/index-template.json`
- `elasticsearch/filebeat.yml`
- `elasticsearch/README.md` and `elasticsearch/README.zh-CN.md`
- `examples/update-server/`
- `install.sh`
- `uninstall.sh`
- READMEs

Windows packages include:

- `etc/secweaver-agent/config.windows.example.json`
- `etc/secweaver-agent/config.schema.json`
- `etc/secweaver-agent/host-persistence.windows.example.json`
- `elasticsearch/init_es.py`
- `elasticsearch/index-template.json`
- `elasticsearch/filebeat.yml`
- `elasticsearch/README.md` and `elasticsearch/README.zh-CN.md`
- `install-service.ps1` and `windows-install-common.ps1`
- `uninstall-service.ps1`
- `examples/update-server/`
- READMEs

## Update

Self-update is owned by the unified `secweaver-agent` binary, not by individual modules:

```bash
secweaver-agent update check -manifest-url https://example.com/releases/stable/update-manifest.json -device-id IMMUTABLE_DEVICE_ID
sudo secweaver-agent update install -manifest-url https://example.com/releases/stable/update-manifest.json -device-id IMMUTABLE_DEVICE_ID
sudo secweaver-agent update rollback
```

The update command emits one JSON status record to stderr by default. Use `-status-output /opt/secweaver-agent/logs/secweaver-agent-update.log` to append JSON Lines to a file.

| Flag | Description |
|---|---|
| `-manifest-url` | HTTPS URL or local manifest path; defaults to `SECWEAVER_AGENT_UPDATE_MANIFEST_URL` |
| `-public-key` | Optional trusted Ed25519 release public key in Base64; setting it requires signed manifests |
| `-allow-unsigned-local` | Deprecated compatibility flag; unsigned manifests are already the default when no public key is configured |
| `-allow-insecure-http` | Development diagnostics only: allow HTTP; HTTPS remains required by default |
| `-channel` | Requested channel, default `stable` |
| `-state-dir` | Update lock, state, pending, and backup directory; default `/opt/secweaver-agent/data/update` or `C:\ProgramData\SecWeaver\Agent\data\update` |
| `-self-path` | Binary path to replace; defaults to the current executable |
| `-device-id` | Required immutable rollout identity for a standalone update; managed updates load it from device enrollment state |
| `-host-id` | Deprecated compatibility alias for `-device-id`; it never defaults to hostname |
| `-status-output` | JSON Lines status destination; `-` means stderr |

Scheduled updates are disabled by default. Enable the `update` block in `config.json`:

```json
{
  "enterprise_id": "REPLACE_WITH_16_CHAR_ID",
  "status_path": "/opt/secweaver-agent/data/status.json",
  "update": {
    "enabled": true,
    "manifest_url": "https://example.com/releases/stable/update-manifest.json",
    "channel": "stable",
    "interval_seconds": 21600,
    "initial_delay_seconds": 60,
    "jitter_seconds": 300,
    "retry_initial_seconds": 60,
    "retry_max_seconds": 3600,
    "auto_install": true,
    "require_server_policy": true,
    "health_timeout_seconds": 90,
    "lock_stale_seconds": 3600,
    "max_backups": 3,
    "min_free_space_mb": 256,
    "status_output": "/opt/secweaver-agent/logs/secweaver-agent-update.log"
  }
}
```

With `require_server_policy=true`, installation requires an enterprise rollout policy received over
a device-key-authenticated heartbeat. SLS SaaS uses the hosted Agent Gateway control plane. Self-managed
ES deployments use the standalone Agent profile and do not require a SecWeaver server source tree. The
service controls the target version, stable
rollout ring, maintenance window, percentage and absolute concurrency caps, failure circuit breaker,
controlled rollback, pause state, and automatic installation. The hardware-bound `device_id` is used as the
rollout identity. Managed installation fails closed when the server does not grant a lease or when fewer
than three minutes remain on that lease. Transient manifest or artifact failures use bounded exponential
backoff from one minute to one hour, include stable jitter, and honor HTTP `Retry-After`. A new version is committed only after the default 90-second health period;
all modules must remain running and at least one module output must advance. Restart, unhealthy modules,
or a stalled output path trigger automatic rollback. The stable Linux launcher also recovers when
the new binary cannot execute. Update locks older than one hour are reclaimed, only three binary backups
are retained by default, and installation is rejected before download when the configured free-space
reserve is unavailable. With `auto_install=false`, the Agent checks but does not replace itself.

Binary commit uses a durable write-ahead journal. The Agent persists its backup, recovery markers,
and `commit_prepared` state before atomically replacing a Linux binary or scheduling the Windows
replacement. Once commit starts, a concurrent policy, lease, or process cancellation cannot relabel
the result as `policy_deferred`. If the final state write fails, the prepared journal and backup remain
available for startup health confirmation or automatic rollback.

Update server, nginx, manifest, and client config examples live in [`examples/update-server/README.md`](examples/update-server/README.md).

When signing is enabled, published manifests use a signed envelope. Without a configured public key,
the Agent accepts the plain manifest over HTTPS and still verifies artifact URL, size, and SHA-256.
Any configured or previously persisted trusted key makes signing mandatory, so a signed trust
rotation cannot silently fall back to an unsigned manifest.
Signed `payload` is the Base64-encoded manifest JSON and `signature` covers the decoded bytes:

```json
{
  "key_id": "ed25519-0123456789abcdef",
  "payload": "BASE64_ENCODED_MANIFEST_WITH_ARTIFACT_SIGNATURES",
  "signature": "BASE64_ED25519_SIGNATURE"
}
```

The logical payload metadata requires a monotonic generation and expiry. A 0.3.2 transition manifest
may carry only its already-recognized microsecond `generated_at`; new Agents derive generation and a
14-day expiry from it. After fleet migration, publish explicit `generation` and `expires_at`. The Agent persists the
highest accepted generation and signed digest per channel, rejecting replay, same-generation
equivocation, and expiry before applying trust changes. Each `binaries.<platform>` entry contains
`url`, `sha256`, `size`, `signature_format=ed25519-sha256`, and a signature over the digest. A 0.3.2
transition release may temporarily use the legacy raw `ed25519` signature. Artifacts
stream into a bounded temporary file while hashing and are fsynced before use. Policy revision, pause,
or lease expiry cancels an in-flight download and removes the temporary file. Version checks use strict
SemVer 2.0.0 precedence, including prereleases and build metadata.

The server is the sole rollout authority in managed mode. After receiving a per-device eligibility
decision and lease, the Agent does not reapply manifest `rollout.percentage` or device allow/deny
lists. Managed-service release gates reject those fields in managed release manifests.
`download_spread_seconds` remains a bandwidth-spreading delay for already approved devices and does
not change eligibility. Manifest rollout fields remain available only for standalone updates without
a control plane. Both managed control planes own the target version, frozen campaign device cohort,
stable rollout ring, maintenance window, pause, concurrency limits, failure-rate circuit breaker,
controlled rollback, and automatic-install decision.

### Signing-key rotation and emergency stop

Rotate keys through two consecutive manifests. First sign with the current key and add the new public
key, then sign with the new private key and revoke the old key ID:

```bash
go run ./cmd/update-sign -manifest unsigned.json -artifact-dir dist \
  -private-key-file current.key -add-public-key-file next.key.pub -out update-manifest.json
go run ./cmd/update-sign -manifest unsigned.json -artifact-dir dist \
  -private-key-file next.key -revoke-key-id ed25519-OLD_KEY_ID -out update-manifest.json
```

The Agent persists the signed keyring under its update state directory. Revoked signers are rejected,
and a trust update that would revoke every key is rejected. To stop installation independently of Data
Cloud availability, publish a manifest signed by a currently trusted key with
`-emergency-stop-reason "reason"`. Removing that field in a later trusted manifest resumes updates.

A rollback after successful probation requires all three signing flags: `-rollback-from-version`,
`-rollback-reason`, and a future `-rollback-expires-at`. The Data Cloud policy must also explicitly
authorize downgrade and match both current and target versions; a normal signed manifest cannot downgrade.

After Authenticode signing a production Windows binary, declare the allowed publisher certificate
SHA-256 values in `authenticode_publisher_sha256`. Windows then requires both the Ed25519 release
signature and a valid system Authenticode chain whose publisher matches that allowlist. Transition
artifacts without the field remain compatible.

Actual system-service rollback tests live in
[`integration/service-upgrade/`](integration/service-upgrade/README.md) and run against systemd and
Windows SCM.

Linux installs replace the binary atomically and return `installed`; systemd starts it through a stable
rollback launcher. New Linux units classify the dedicated exit code `75` as a successful forced restart,
while upgraded binaries remain compatible with older units by returning `1` unless the unit opts in.
Windows stages the replacement on the same filesystem and returns `install_scheduled` or
`rollback_scheduled`. After the running process exits, the helper commits it with Windows
`File.Replace` atomic semantics. Windows service recovery runs the external rollback command after
repeated startup failures, and rollback uses the same atomic replacement operation.

## Config

Linux example: [`config.example.json`](config.example.json):

```json
{
  "enterprise_id": "REPLACE_WITH_16_CHAR_ID",
  "update": {
    "enabled": false,
    "manifest_url": "https://updates.example.com/secweaver-agent/stable/update-manifest.json",
    "channel": "stable",
    "interval_seconds": 21600,
    "initial_delay_seconds": 60,
    "jitter_seconds": 300,
    "retry_initial_seconds": 60,
    "retry_max_seconds": 3600,
    "auto_install": true,
	"public_key": "BASE64_ED25519_PUBLIC_KEY",
    "status_output": "/opt/secweaver-agent/logs/secweaver-agent-update.log"
  },
  "modules": {
    "audit-port-execmon": {
      "enabled": true,
      "restart": "on_failure",
      "restart_delay_seconds": 5,
      "args": ["-config", "/opt/secweaver-agent/etc/audit-port-execmon.json"]
    },
    "syslog-risk-json": {
      "enabled": true,
      "restart": "on_failure",
      "restart_delay_seconds": 5,
      "args": ["-secure", "auto", "-messages", "auto", "-output", "/opt/secweaver-agent/logs/syslog-risk-json.log"]
    },
    "host-persistence": {
      "enabled": true,
      "restart": "on_failure",
      "restart_delay_seconds": 5,
      "args": ["-config", "/opt/secweaver-agent/etc/host-persistence.json"]
    }
  }
}
```

Windows example: [`config.windows.example.json`](config.windows.example.json):

```json
{
  "enterprise_id": "REPLACE_WITH_16_CHAR_ID",
  "status_path": "C:\\ProgramData\\SecWeaver\\status.json",
  "modules": {
    "windows-eventlog-risk-json": {
      "enabled": true,
      "args": ["-channels", "Security,System,Microsoft-Windows-PowerShell/Operational,Microsoft-Windows-Sysmon/Operational", "-evidence-output", "C:\\ProgramData\\SecWeaver\\windows-process-execmon.log"]
    },
    "windows-process-execmon": {
      "enabled": false,
      "args": ["-channels", "Security,Microsoft-Windows-Sysmon/Operational"]
    },
    "host-persistence": {
      "enabled": true,
      "args": ["-config", "C:\\ProgramData\\SecWeaver\\host-persistence.json"]
    }
  }
}
```

| Field | Description |
|---|---|
| `enterprise_id` | Required 16-character tenant ID issued by the SecWeaver platform |
| `status_path` | Local Agent health file containing authorization checks, heartbeat errors, module status, PID, restart count, and latest start/exit times |
| `operations_report` | Enabled by default; append-only Agent operations JSONL with 300-second snapshots and up to 60 seconds of stable jitter, covering modules, shared audit reader, authorization, persistence, and shipper configuration |
| `disk_budget` | Enabled by default: 2048MB total managed output, 512MB minimum free space, checked every 30 seconds; snapshots stop before realtime evidence |
| `license.outage_grace_seconds` | Maximum age of the last successful authorization accepted for transient network failures or HTTP 408/425/429/5xx responses; defaults to 86400 seconds, `0` disables it, maximum 604800 |
| `remote_config` | Optional Data Cloud managed policy pull. When enabled, Agent periodically pulls a full signed config, validates it, replaces `config.json`, and exits for the service manager to restart |
| `modules.<name>.enabled` | Enable the module; omitted means enabled |
| `modules.<name>.args` | Native module flags |
| `modules.<name>.restart` | `never`, `on_failure`, or `always`; default `on_failure` |
| `modules.<name>.restart_delay_seconds` | Restart delay; default 3 seconds |
| `modules.<name>.restart_max_delay_seconds` | Exponential backoff cap; default 300 seconds |
| `modules.<name>.restart_failure_limit` | Consecutive failures before circuit open; default 8 |
| `modules.<name>.restart_stable_seconds` | Stable runtime that resets failure count; default 300 seconds |
| `modules.<name>.restart_circuit_seconds` | Module circuit-open pause; default 900 seconds |

Replace `REPLACE_WITH_16_CHAR_ID` with the platform-issued value. [`config.schema.json`](config.schema.json) documents the contract, while runtime validation rejects unknown fields, unknown module flags, and invalid restart policies. `run`, `preflight`, and service startup apply the same validation before collectors start. At startup, the Agent auto-detects and caches the host name and a non-loopback primary IP, then passes that identity to every collector. The shared output boundary guarantees that every collector JSON Lines record contains `enterprise_id`, `host_name`, and `host_ip`. Multi-homed hosts may select an address with `SECWEAVER_HOST_IP`, and `SECWEAVER_HOST_NAME` may override the system host name; invalid or loopback addresses prevent event output from starting.

All growing logs written through the Agent output writer rotate by size, including collector JSON Lines and update status logs. The default cap is 100MB per file with 5 backups named `*.log.1`, `*.log.2`, and so on. POSIX systems enforce mode `0600` on these files; every open also repairs the active file and retained numeric backups, so an upgrade automatically tightens legacy `0644` logs. Windows relies on the installation-root ACL that restricts access to `SYSTEM` and local Administrators rather than POSIX mode bits. The Windows service wrapper itself does not create a dedicated service log file. Local health status, license state, and Windows EventRecordID cursors are small overwrite-style state files, not append-only logs.

The Linux release systemd unit caps the complete Agent process tree at 50% of one CPU, 512MB of memory, 128 tasks, and 8192 open files, while lowering CPU and IO scheduling priority. It also sets `LimitMEMLOCK=infinity` for older kernels that still charge eBPF maps against memlock. The Agent is preferred over business processes when the host is under memory pressure. Transient authorization and network failures retry in-process with bounded backoff, while systemd has no permanent start-rate latch. Invalid local configuration exits with status 78 and is deliberately excluded from restart so it cannot create a restart storm. For exceptional high-density hosts, use `systemctl edit secweaver-agent` for a local override instead of editing the packaged unit.

Authorization remains fail-closed, but a short control-plane outage no longer stops collection immediately. Only transient network failures or HTTP 408/425/429/5xx responses may use the most recent successful authorization within `license.outage_grace_seconds`. First installation, device revocation, subscription expiry, quota denial, other HTTP 4xx responses, certificate errors, invalid configuration, and corrupt local authorization state never use the cache. A known subscription expiry also shortens the grace window.

On Linux, `secweaver-agent run` automatically enables a single `audit.log` reader/demux when multiple audit-consuming modules share the same `audit_log` path and `from_start` behavior. The parent process follows the audit log once, routes raw audit records by audit key, and passes each child module a shared input FD. Each module has a fixed 4096-line ring containing only records that were not delivered successfully; unrelated audit IDs are not buffered, and health-state writes happen outside the demux lock. A full subscriber queue or broken pipe retires that subscription so the supervisor restarts the module and replays pending records. If a module remains unavailable long enough to exhaust the ring, oldest evidence is overwritten, but the cumulative count, audit IDs, and error diagnostic are exported rather than lost silently. Initial open, missing-path, and rotation-reopen failures also affect readiness and clear automatically after recovery. Standalone `secweaver-agent module ...` runs still read audit logs inside the module; setting `host-persistence` `audit.follow_log=false` removes that module from the demux subscription.

`audit-port-execmon` uses a module JSON config. Copy [`audit-port-execmon.example.json`](audit-port-execmon.example.json) to `/opt/secweaver-agent/etc/audit-port-execmon.json` and tune it. The default `exec.process_tree_backend="auto"` uses embedded eBPF CO-RE fork/exec/exit programs on Linux amd64/arm64 hosts with kernel BTF and a successful verifier/attach check. Capability, policy, or load failure now falls back to the bounded `audit` backend: one host-wide exec rule and one clone rule per arch feed a userspace listener-tree map, so kernel rule count no longer grows with PID churn. The default b64 profile therefore installs two syscall rules plus the `/etc/shadow` watch. Use `ebpf` to require eBPF, `audit` to force bounded audit, or the explicit compatibility value `audit_pid` to restore historical per-PID/PPID rules. Target hosts do not need Clang, kernel headers, or libbpf. Defaults allow 131072 tracked processes and allocate a 256KB perf buffer per CPU. Up to 16 arguments of 96 bytes each are captured; truncation emits `command_truncated=true`.

For eBPF exec events, the Agent best-effort enriches `auid`, `auid_name`, `cwd`, `tty`, and `has_tty` from `/proc/<pid>` while the process still exists. `has_tty` is a tri-state contract: `true` and `false` are emitted only when `/proc/<pid>/stat` proves whether a controlling terminal exists; the field is omitted when the process exited too quickly or procfs access failed. Consumers must treat an omitted field as unknown, never as non-interactive execution. Audit-backed events continue to obtain these fields from the kernel audit record and normally provide fuller session context.

eBPF replaces only dynamic exec/clone tracking. Explicit connect/file monitoring and sensitive-file reads still use audit. Connect and file monitoring are disabled by default, while `/etc/shadow` keeps one read watch. Bounded audit records host-wide exec/clone syscalls and rejects unrelated processes before event accumulation; this removes the large kernel rule scan cost, though very high process-creation hosts must still size audit log throughput. Five-minute reconciliation removes dead ownership and repairs missed clone propagation, with `/proc` starttime preventing PID reuse. The `audit.max_rules=1024` budget, transactional rollback, stale-startup cleanup, and shutdown cleanup still apply. Run `secweaver-agent preflight` or `doctor` to inspect BTF, exec tracepoints, and fallback conditions.

Listener reconciliation runs every five minutes by default. Realtime clone/exec ownership remains event-driven through eBPF or audit; reconciliation only repairs listener changes and missed events. Discovery first runs `netstat -tlnp` with `LC_ALL=C` and `LANG=C`. The parser does not depend on column widths or fixed `LISTEN-2`/`LISTEN+1` offsets: it finds the first address-shaped field before a case-insensitive LISTEN token and searches later fields for PID/program ownership. It accepts standard net-tools output, BusyBox-style `*:port` wildcards, bracketed and unbracketed IPv6, extra vendor columns, omitted PID columns, and process labels containing spaces or colons. Each command separately counts raw TCP LISTEN, parsed, and rejected rows. Any rejected listener emits `netstat listener parse incomplete` and forces procfs completion rather than silently accepting a partial result.

When every relevant listener has a valid PID, the Agent does not scan `/proc/<pid>/fd`. It reads `/proc/net/tcp*` and builds a socket-inode map only when netstat fails, returns no listeners, omits a relevant PID, or contains a rejected row. Fallback scanning reads at most 128 FDs per batch, pauses 1ms between batches, and examines at most 32,768 FDs per round. Budget exhaustion is diagnosed and repaired on a later round; an individual inode miss never starts another global scan. Production configurations should keep `listener_rescan_seconds=300`, because shorter values increase process and FD discovery work proportionally. This path applies only to Linux systemd collection targets; Windows uses Event Log/Sysmon, and macOS is not a supported collection target.

`audit.pressure` controls dynamic rule mutation only. It remains active for `audit_pid` and eBPF deployments with per-PID connect/file rules, but bounded `audit` and pure eBPF exec mode skip the 30-second `auditctl -s` poll because they have no dynamic PID rule expansion. Shared-reader backlog, loss, and overwrite diagnostics remain observable through Agent health and metrics.

Remote config is fail-closed. Enabling `remote_config` requires `public_key`, and the Agent verifies the Ed25519 signature before replacing local configuration. `allow_unsigned=true` is only for isolated development. Bad signatures, enterprise mismatches, unknown fields, invalid module flags, and invalid license/update settings are rejected. A temporarily unreachable Data Cloud is logged and retried with bounded exponential backoff starting at one minute and capped at 15 minutes; the Agent stays alive and reconnects automatically. Explicit denials, certificate errors, and invalid local state remain fail-closed.

`host-persistence` uses a module JSON config. On Linux, copy [`host-persistence.example.json`](host-persistence.example.json) to `/opt/secweaver-agent/etc/host-persistence.json`; on Windows, `install-service.ps1` copies [`host-persistence.windows.example.json`](host-persistence.windows.example.json) to `C:\ProgramData\SecWeaver\Agent\etc\host-persistence.json`. The first start builds a baseline without emitting existing files; later creates, modifies, and deletes emit `asset_type=host_persistence`, `event_type=persistence_change` JSON Lines. Events auto-detect and include `host_ip`; multi-homed hosts can set `host_ip` in the module JSON or use `-host-ip` to override the detected address. Linux defaults write `/opt/secweaver-agent/logs/host-persistence.log` and use auditd actor/process enrichment when available. Once per minute, configured paths that currently exist are reconciled against kernel watch rules so new paths and watches invalidated by atomic replacement are restored. An audit reader failure restarts the module instead of silently disabling enrichment. Windows defaults write `C:\ProgramData\SecWeaver\Agent\logs\host-persistence.log`, disable audit enrichment, and monitor scheduled-task, startup-folder, Group Policy script, and PowerShell profile file locations. Small text files include a bounded `content_diff`. If Linux audit volume is high and another local component already consumes `audit.log`, set `audit.follow_log=false` to disable this module's follower; it can still manage watch rules, but events will not include actor/process enrichment.

`host-process-snapshot` is enabled by default on Linux and Windows. It emits a full `process_snapshot` baseline at startup, then scans every 10 minutes for `process_start`, `process_exit`, and `process_change`, with another full baseline every 24 hours. Delta identity is `pid+start_time`; state is atomically persisted in the platform state directory. Baselines retain `command_hash` instead of repeated command payloads, while high-value deltas retain redacted commands. See `docs_user/32-host-process-snapshot.md`.

`host-state-snapshot` is enabled by default on Linux and Windows. It checks listening sockets, identities, and services/tasks every five minutes, and kernel/container context every ten minutes. Every collection emits an initial baseline, then differences, plus a full baseline every 24 hours. Linux socket-owner discovery is capped at 100,000 file descriptors per run by default; an incomplete collection is rejected so it cannot create false deletion events. See `docs_user/33-host-state-snapshot.md`.

Note: `-update-check`, `-update-now`, and `-rollback` from legacy standalone `syslog-risk-json` builds are self-replacement flags. The built-in module rejects them inside `secweaver-agent` to avoid replacing the unified agent with an old module artifact. Upgrade the unified client with `secweaver-agent update ...` or release packages instead.

## Run

### Installation Layout

New installations keep all Agent-owned executables, configuration, state,
logs, and shipper files under one product root:

```text
/opt/secweaver-agent/                 C:\ProgramData\SecWeaver\Agent\
|-- bin/       Agent/launcher         |-- bin\
|-- etc/       config/module config   |-- etc\
|-- data/      state/cursor/update    |-- data\
|-- logs/      module JSONL           |-- logs\
`-- shipper/   shipper/config/CA      `-- shipper\
```

Linux retains `/usr/local/bin/secweaver-agent` only as a command symlink, and
systemd units remain in `/etc/systemd/system`; neither location stores product
data. The Windows installer removes inherited write access from the root and
grants modification rights only to `SYSTEM` and local Administrators, because
ProgramData must not make service executables user-writable.

List built-in modules:

```bash
./secweaver-agent modules
```

Validate config:

```bash
./secweaver-agent run -config ./config.example.json -dry-run
./secweaver-agent preflight -config ./config.example.json
```

Run as a long-lived agent:

```bash
sudo ./secweaver-agent run -config /opt/secweaver-agent/etc/config.json
```

Copy the Bootstrap command from **enterprise workspace → secweaver-agent → One-command installation**. Query AK/SK are available separately under **Agent configuration**:

```bash
curl -fsSL 'https://YOUR_DATA_CLOUD_HOST/secweaver-agent/install.sh' \
  | sudo bash -s -- \
      --enterprise-enrollment-token 'swenr_TOKEN_ID.SECRET'
```

Production Bootstrap requires publicly trusted HTTPS and does not support `curl -k`.

The Bootstrap installer supports Linux systemd hosts, detects `amd64`, `arm64`, or `loong64`, and
verifies the Agent release before installation. The customer command supplies only an enterprise
enrollment token. Initial enrollment creates a hardware-correlated `device_id` and per-device
Ed25519 key; the server-confirmed `enterprise_id` is then written into Agent configuration.
SecWeaver AK/SK stay on Data Cloud. Bootstrap also installs or reuses Logtail and writes the
embedded AliUid and Alibaba Cloud machine-group `enrollment_id` into Logtail configuration. It
runs strict preflight and post-install diagnostics. Project and Logstore are never sent to the
host. Production URLs require HTTPS; `--allow-http` is for local tests only. Use `--skip-logtail`
explicitly for Agent-only installation.

For offline installation, use a release package manually:

```bash
AGENT_VERSION='<downloaded-version>'
tar -xzf "secweaver-agent_${AGENT_VERSION}_linux_amd64.tar.gz"
cd "secweaver-agent_${AGENT_VERSION}_linux_amd64"
sudo ./install.sh \
  --enterprise-enrollment-token 'swenr_TOKEN_ID.SECRET' \
  --license-server-url https://agent-gateway.id-net.cn:30443
sudo systemctl enable --now secweaver-agent
```

When upgrading a split-path installation, the installer copies legacy config
and state into the unified root, then uses `secweaver-agent config migrate-layout`
to rewrite known SecWeaver-owned paths structurally. Custom paths and operating
system inputs such as `/var/log/audit/audit.log` are preserved. Migration copies
rather than deletes old files so the old service command remains available for
rollback. The installer also adds missing host snapshot settings and optimizes
duplicate Windows readers.

When an ES enrollment command supplies `SECWEAVER_BOOTSTRAP_CA_FILE`, the Linux
installer validates and persists that temporary trust anchor before reading an
existing configuration. The current path is `/opt/secweaver-agent/shipper/ca.crt`;
`/opt/secweaver-agent/etc/shipper/ca.crt` is also maintained for upgrades from
older configurations. The temporary download can be removed after installation.

Fresh installs require `--enterprise-enrollment-token`. The installer hashes local hardware signals,
creates an Ed25519 device key and `device_id`, and atomically writes the server-confirmed
`enterprise_id` only after enrollment succeeds. `--enterprise-id` remains available only for v1
legacy migration. During migration the installer stops standalone collectors and blocks duplicate
writer processes. It requires systemd by default and checks or installs `auditctl`, `netstat`, and
their packages. `REQUIRE_SYSTEMD=0` and `INSTALL_DEPS=0` are controlled migration overrides.

The systemd unit includes `ExecStopPost=/opt/secweaver-agent/bin/secweaver-agent audit-cleanup -quiet`, so stopping the service performs best-effort cleanup for `tb_external_listener_*`, `tb_port_*`, and `tb_host_persistence` audit rules. To run the cleanup manually:

```bash
sudo /usr/local/bin/secweaver-agent audit-cleanup
```

After installation, use the stable product-owned uninstaller path:

```bash
sudo /opt/secweaver-agent/bin/uninstall.sh
```

The archive-root `uninstall.sh` is only the package installer input. The Linux
installer copies it to `/opt/secweaver-agent/bin/uninstall.sh`, so operations do
not depend on the directory used to extract the archive or on a temporary test
staging directory. This script stops the Agent and shipper services, removes systemd units,
cleans stale audit rules, and removes `/opt/secweaver-agent/bin` plus the command
symlink by default. Config, state, logs, and shipper data are retained;
`sudo /opt/secweaver-agent/bin/uninstall.sh --purge` removes the complete `/opt/secweaver-agent` root.
Standalone collectors are retained unless explicitly selected. For a clean-host test:
`sudo /opt/secweaver-agent/bin/uninstall.sh --purge --remove-logtail --remove-filebeat --json`.
These flags remove each selected collector's configuration/state/logs, including shared
collection jobs. See [supported paths and verification](docs/collector-lifecycle.md).
The selective removal flags and machine-readable `--json` verification remain available.

Run one module directly:

```bash
sudo SECWEAVER_ENTERPRISE_ID=YOUR_16_CHAR_ID ./secweaver-agent module audit-port-execmon -config /opt/secweaver-agent/etc/audit-port-execmon.json
sudo SECWEAVER_ENTERPRISE_ID=YOUR_16_CHAR_ID ./secweaver-agent module syslog-risk-json -secure auto -messages auto -output -
sudo SECWEAVER_ENTERPRISE_ID=YOUR_16_CHAR_ID ./secweaver-agent module host-persistence -config /opt/secweaver-agent/etc/host-persistence.json
sudo SECWEAVER_ENTERPRISE_ID=YOUR_16_CHAR_ID ./secweaver-agent module host-process-snapshot -once -output -
```

Collect existing logs once:

```bash
sudo /usr/local/bin/secweaver-agent collect-existing-logs -config /opt/secweaver-agent/etc/config.json
sudo /usr/local/bin/secweaver-agent collect-existing-logs -config /opt/secweaver-agent/etc/config.json -lookback 2160h -output /opt/secweaver-agent/logs/syslog-risk-json-history.log
```

`collect-existing-logs` looks back 180 days by default. On Linux it reads the configured `syslog-risk-json` secure/auth and messages/syslog inputs plus common rotated files, including `.gz`, and writes the same JSON Lines shape as realtime `syslog-risk-json`. On Windows it runs a one-shot `windows-eventlog-risk-json` query for the lookback window and disables EventRecordID cursor persistence by default so realtime collection cursors are not advanced. This mode is not started by the service; run it manually for historical attack analysis, first-time backfill, or drills.

Run Windows modules directly from an elevated PowerShell session:

```powershell
.\secweaver-agent.exe module windows-eventlog-risk-json -once -output -
.\secweaver-agent.exe module windows-process-execmon -once -output -
.\secweaver-agent.exe collect-existing-logs -config C:\ProgramData\SecWeaver\Agent\etc\config.json
```

Install a Windows release package as a service:

```powershell
$AgentVersion = '<downloaded-version>'
Expand-Archive ".\secweaver-agent_${AgentVersion}_windows_amd64.zip" -DestinationPath .
Set-Location ".\secweaver-agent_${AgentVersion}_windows_amd64"
Set-ExecutionPolicy -Scope Process Bypass -Force
.\install-service.ps1 `
  -EnterpriseEnrollmentToken 'swenr_TOKEN_ID.SECRET' `
  -LicenseServerUrl 'https://agent-gateway.id-net.cn:30443' `
  -LogtailAliUid '1234567890123456' `
  -LogtailMachineGroup 'YOUR_WINDOWS_ONLY_GROUP'
```

For delivery, prefer the one-click PowerShell command generated with
`generate-agent-install --platform windows`. The installer creates the hardware-correlated
identity and Ed25519 key locally and receives `enterprise_id` from the server-bound token.
`-EnterpriseId` remains only for an explicit legacy v1 migration and is mutually exclusive with
`-EnterpriseEnrollmentToken`.

The elevated installer enables successful **Audit Process Creation** by its stable
subcategory GUID and sets `ProcessCreationIncludeCmdLine_Enabled=1`. New Security 4688
events therefore populate `windows-process-execmon.log` with executable and command-line
evidence without a separate manual policy step. Installation stops before replacing or
stopping an existing Agent if either policy change fails. Domain Group Policy can overwrite
the local setting later; `secweaver-agent doctor` reports the resulting command-line policy.
Because Windows stores command-line arguments as plaintext in the Security log, access to
that log must remain restricted. Uninstall does not disable these host-wide audit settings.

Defaults:

- Binary: `C:\ProgramData\SecWeaver\Agent\bin\secweaver-agent.exe`
- Config: `C:\ProgramData\SecWeaver\Agent\etc\config.json`
- Host persistence config: `C:\ProgramData\SecWeaver\Agent\etc\host-persistence.json`
- Service: `SecWeaverAgent`
- Latest service failure: `<config-path>.service-error.txt` (16 KiB maximum); also inspect SCM and module JSONL outputs

Service operations:

```powershell
Get-Service SecWeaverAgent
Restart-Service SecWeaverAgent
& 'C:\ProgramData\SecWeaver\Agent\bin\uninstall.cmd'
# Remove Agent, Logtail and local data (administrator terminal):
& 'C:\ProgramData\SecWeaver\Agent\bin\uninstall.cmd' -Purge
```

Windows notes:

- `-Purge` deletes local configuration, device identity, learning state, logs and standard-layout Logtail data, including all Logtail collection identities/checkpoints on the host. Add `-KeepLogtail` to retain a shared collector. Cloud history, device records, Sysmon and Windows audit policy are unchanged. `-Json` returns one result object. See [uninstall limits and verification](docs/windows-installation.md#windows-uninstall).

- By default, `windows-eventlog-risk-json` is the single `wevtutil` reader for Security, System, PowerShell, and Sysmon. It writes risks to `windows-eventlog-risk-json.log` and maps Security 4688 plus Sysmon 1/3/11/23 into `host_exec`, `host_connect`, and `host_file_op` records in `windows-process-execmon.log` through `-evidence-output`.
- The standalone `windows-process-execmon` module remains available when unified evidence output is disabled. It polls every five minutes and is disabled by default. If both modules are enabled, pass `-evidence-output=` explicitly to `windows-eventlog-risk-json` to transfer evidence ownership to the standalone reader; otherwise preflight and startup reject the configuration to prevent duplicate queries, duplicate records, and competing writers.
- Both readers use the `internal/windowsevidence` Security/Sysmon classifier. Collector-generated PowerShell activity is registered by the SHA-256 of the complete fixed script; copying only the marker or appending commands does not suppress a risk event.
- The active reader persists one `EventRecordID` cursor at `C:\ProgramData\SecWeaver\Agent\data\windows-eventlog-risk-json.cursor.json`. Output is flushed and synchronized before the cursor advances. Override the path with `-state-file <path>`, or pass an empty value to disable persistence.
- `host-persistence` is enabled by default on Windows and writes `C:\ProgramData\SecWeaver\Agent\logs\host-persistence.log`; it monitors file-based persistence locations and does not collect registry persistence yet.
- `host-process-snapshot` is enabled by default on Windows, scans deltas every 10 minutes, emits a full baseline every 24 hours, and writes `C:\ProgramData\SecWeaver\Agent\logs\host-process-snapshot.log`; it does not create a separate service-wrapper log.
- The elevated service installer enables Audit Process Creation success events and command-line data automatically. Domain Group Policy can subsequently override these local settings; network/file telemetry still requires Sysmon.
- The Windows service entrypoint is `secweaver-agent.exe service -config C:\ProgramData\SecWeaver\Agent\etc\config.json`; `install-service.ps1` registers it automatically.

## Migration

The old standalone tool directories have been removed. Build and install `src/tools/secweaver-agent`, then run collectors through `secweaver-agent run` or `secweaver-agent module <name>`.

The implementation source of truth lives under `src/tools/secweaver-agent/pkg/`. Existing module flags and configs can be reused under `modules.<name>.args`.

`audit_demux.go` owns the supervised reader, routing, and replay path; `audit_demux_observability.go` separately owns reader availability, backlog-overwrite diagnostics, and read-only metric snapshots. `pkg/auditstream` provides the parent audit-log follower and child shared-FD input helpers. Each module declares flags, platforms, output paths, and its optional audit subscription in its own `descriptor.go`; the supervisor no longer parses collector-private JSON or duplicates audit-key policy.

`pkg/auditportexecmon` is split by responsibility so future host collectors do not grow as one large file:

| File | Responsibility |
|---|---|
| `main.go` | CLI flags and module orchestration |
| `config.go` | JSON config, defaults, validation, and option normalization |
| `listeners.go` / `procfs.go` | External listener discovery and `/proc` helpers |
| `monitor_state.go` / `monitor_worker.go` | Process-tree state, asynchronous rule queue, backpressure, and statistics snapshots |
| `monitor_bootstrap.go` / `monitor_listener_reconcile.go` / `monitor_listener_roots.go` | Initial coverage, listener reconciliation, and Web/Java/SSH root policies |
| `monitor_pid.go` / `monitor_pid_rules.go` / `monitor_pid_cleanup.go` / `monitor_ebpf.go` | PID attribution, rule budget/expansion, dead-process cleanup, and eBPF lifecycle attribution |
| `monitor_self.go` / `companion.go` | Agent self-process exclusion and web-gateway companion discovery |
| `audit_rules.go` | auditctl rule add/delete/cleanup helpers |
| `audit_follow.go` / `audit_accumulator.go` | Audit log/shared-stream following, rotation handling, and multi-record accumulation |
| `audit_event.go` / `audit_parse.go` / `audit_identity.go` | Event assembly, field parsing, command resolution, and identity enrichment |
| `output.go` / `types.go` | Output writer helpers and shared package types |

Audit observability now has one production model: the parser uses lock-free atomic counters, while rule expansion and pressure metrics belong to the `processTreeMonitor` lifecycle. On module exit they are combined into one `audit runtime stats` stderr record. The disconnected listener-health subsystem was removed, so skipped rules are no longer mislabeled as installation failures. This record is a module-local exit snapshot, not a Prometheus series on the parent `/metrics` endpoint.

`pkg/hostpersistence` follows the same lifecycle split: `config.go`/`cli.go` own entry and configuration; `platform_nonwindows.go`/`platform_windows.go` isolate platform defaults; `runner.go`/`scanner.go` own polling; `events.go`/`state_store.go` own evidence and atomic baselines; and `audit_rules.go`, `audit_follow.go`, `audit_tracker.go`, and `audit_event.go` separately own rule management, transport, bounded correlation, and actor enrichment. This source-layout change does not alter config fields, defaults, log paths, JSON event formats, or runtime behavior.

Within a module, prefer splitting files by reason to change while retaining one package. Extract a new package only after a stable reusable contract exists; the supervisor must not gain new hard-coded knowledge of collector-private JSON fields, audit keys, or output layouts.

## Adding Modules

1. Implement `func Main(args []string) int` under `pkg/<module>`.
2. Implement `func Descriptor() modulecontract.Descriptor` in that package's `descriptor.go`; the module owns its flags, platforms, outputs, and external-resource requirements.
3. Add the descriptor to `buildModuleRegistry(...)` in `module_registry.go`; duplicate names fail immediately during development startup.
4. Add a sample block to `config.example.json`.
5. Add module docs and a minimal smoke test.

The release artifact remains a single `secweaver-agent` binary.

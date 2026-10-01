# Collector Lifecycle And Diagnostics

## Enrollment Rejection Diagnostics (0.3.70)

The `enroll` command on supported Linux and Windows hosts reports
`HTTP=<status> reason=<code>` plus fixed English/Chinese explanations and recovery
advice on stderr. Successful enterprise/device identity stdout and exit codes are
unchanged. The Linux SaaS Bootstrap shows a concise reason when its registration
step fails; the detailed installation log retains the complete CLI diagnosis.
The Windows installer displays the same CLI stderr through its existing native
command invocation. No automatic retries, identity deletion, revocation or quota
changes are performed.

| HTTP / code | Meaning and recovery |
| --- | --- |
| 403 / `DeviceIdentityConflict` | Local identity was revoked, replaced or has conflicting enterprise/key ownership. Ask the administrator to verify registration and the intended reinstall procedure; preserve local state/key for diagnosis. |
| 403 / `DeviceQuotaExceeded` | Enterprise device entitlement is full or exceeded. Revoke confirmed unused registrations or increase the entitlement. Offline/uninstalled devices count until revoked; deleting local state does not release a slot. |
| 403 / `EnrollmentTokenExhausted` | Token cumulative new-device registrations are exhausted, independently of expiry. Generate a new installation command. Revoking devices does not restore token uses. |
| 403 / `EnterpriseDisabled` | Enterprise is disabled, not provisioned or not yet effective. The administrator must enable/activate it; a new token cannot enable it. |
| 403 / `SubscriptionExpired` | Subscription expired. Renew the enterprise entitlement; replacing the token cannot renew it. |
| 409 / `AmbiguousReinstall` | Multiple active identities match the hardware fingerprint. Verify duplicate registrations before reinstalling. |
| 401 / `RequestReplay` | Request nonce was already used. Retry with a fresh enroll request; inspect proxy replay if repeated. |
| 401 / `Unauthorized` | Authentication failed. Check the current installation command and host clock. Invalid/expired/revoked tokens and failed request authentication deliberately share this response; it does not establish token expiry. |
| 404 / `NotFound` | Check the Gateway enrollment route and reverse proxy; this is not token expiry. |

Prerequisite: the Gateway must return a recognized JSON `errorCode` with the
matching HTTP status. Older JSON `reason` codes are supported, including legacy
HTTP-200 `allowed=false` denials. A human `message` cannot override `errorCode` or
`reason`. Unknown codes, malformed JSON, HTML/WAF responses and inconsistent
status/code pairs are shown as `UnknownRejection`, without guessing the cause or
printing server-controlled text. Unknown 403 responses advise inspecting Gateway
and WAF/proxy logs. Tokens, private keys and URL userinfo/query values are not
printed. Old generic responses cannot distinguish these reasons until the server
provides a code.

Verify from the Agent source directory with
`go test -race . ./pkg/agentlicense -run 'TestEnroll|TestEnrollment'`, and from the
repository root with `python3 -m unittest tests.test_agent_install_presentation`.
Tests use synthetic TLS endpoints and isolated logs to verify every listed 403,
legacy JSON, invalid/WAF bodies, status mismatch, empty failure stdout, preserved
identity across retries, secret redaction and the original installation exit code.
Windows compilation does not replace real PowerShell/SCM acceptance. Publish a
new immutable 0.3.70 package and generated Bootstrap before the public installation
command gains this behavior; already installed binaries keep their existing output.

## 0.3.43 Installation Recovery

Enrollment HTTP 401 advises checking the installation command and host clock;
the credential may be expired, revoked or invalid, or request authentication may
have failed. The client does not infer which check failed, delete identity, retry
authorization blindly or disable TLS verification.
Guidance is stderr-only and applies to the Agent enroll command on Linux and Windows.

The Linux uninstaller accepts the standard `/etc/init.d -> /etc/rc.d/init.d` and
`/lib/systemd/system -> /usr/lib/systemd/system` directory mappings. Other symlink
removal roots still fail before services stop. Requires `readlink -f` (Linux coreutils).

Release promotion requires public directories readable/traversable by all (0755
recommended), archives/checksums readable by all (0644 recommended), and no group/world
write permission. It never repairs permissions implicitly. `--runtime-user NAME` uses
Linux `runuser` with a 10-second deadline per path to check the actual Gateway account,
including ancestor permissions/ACLs. Run as a publisher allowed to use runuser; a missing
user/tool or failed check leaves the old pointer unchanged. Omit this Linux-only option
on other publisher platforms and verify the deployed service separately. Unit tests cover
restrictive directory/file modes and failed runtime-user checks; verify catalog/downloads
over HTTPS after promotion. No automatic fleet update manifest changes are performed.

Agent 0.3.41 changes the Linux SLS bootstrap, Linux uninstaller and Logtail diagnostics.
For Windows from 0.3.46, see [Windows installation](windows-installation.md). Linux bootstrap targets systemd hosts, including
systemd 219 (CentOS 7), and the vendor `/etc/init.d/ilogtaild` or `loongcollectord`
service protocol. `timeout`, `flock`, `pgrep` and `readlink` must be available.
Nonstandard collector layouts/services require their own lifecycle integration.

## Network Policy

Since 0.3.42 the Linux template and release script default to
`BOOTSTRAP_LOGTAIL_REGION=cn-hangzhou-internet`. The UI/customer command needs no extra
region flag. An explicitly configured `cn-hangzhou` retains intranet behavior; the legacy
alias `hangzhou` still normalizes to that intranet selector in publisher/release scripts.
Other SaaS geographies must set a vendor-supported region/network selector for their SLS
deployment. Do not append `-internet` to the SLS API connector's ordinary region field.
There is no automatic intranet/public failover or geographic fallback.

Two independent settings are involved:

| Setting | Purpose |
| --- | --- |
| `BOOTSTRAP_LOGTAIL_INSTALL_URL` and SHA-256 | Mirrored installer script download and integrity |
| `BOOTSTRAP_LOGTAIL_REGION` / `--logtail-region` | Vendor selector affecting internal binary downloads and Logtail endpoints |
| `LOGTAIL_SOURCE_REGION` or `LOGTAIL_SOURCE_URL` | Publisher-only upstream installer source; independent of runtime networking |

`publish-logtail-installer.sh` defaults `LOGTAIL_REGION=cn-hangzhou-internet`, strips only
the `-internet` suffix when forming its public OSS source hostname, and exports the runtime
selector along with URL/checksum in `release.env`. It does not modify the vendor script.

```bash
LOGTAIL_REGION=cn-hangzhou-internet \
OUTPUT_DIR=/srv/secweaver/logtail \
PUBLIC_BASE_URL=https://downloads.example.com \
bash scripts/publish-logtail-installer.sh
source /srv/secweaver/logtail/release.env
# Supply account, enrollment, authorization and other deployment values as usual.
# Use a fresh OUT_DIR and the new Agent VERSION when generating release artifacts.
```

Migration: explicitly change old release/deployment values from `cn-hangzhou` to
`cn-hangzhou-internet` for a public SaaS channel, regenerate pinned metadata and Bootstrap,
then publish the new Agent release. Old exported values take precedence over the new
default. Changing source alone does not update a live download URL. Already installed
collectors are reused; their endpoints are not silently rewritten. Use the vendor's
reconfiguration procedure and verify uploads before migrating existing collectors.

All Bootstrap HTTP downloads require GNU `timeout` (Linux coreutils). Each is limited
to 300 seconds, with TERM followed by KILL after another 10 seconds if necessary. curl
uses 10-second connect/120-second per-attempt limits and up to two retries for retryable
errors; wget uses 10-second DNS/connect, 30-second I/O and at most three tries. An entire
vendor installer invocation is limited to 600 seconds plus at most 10 seconds for forced
termination. It is never automatically rerun after partial side effects. Its named curl/
wget calls receive the same wrappers; absolute paths/other future tools are only covered
by the overall deadline. Publisher curl is also bounded (120 seconds per attempt,
two retries, 260-second retry-start budget); a last attempt may finish after that budget.

Errors carry `stage=agent-version-download`, `agent-package-download`,
`agent-checksum-download`, `logtail-installer-download`, `logtail-binary-download`, or
`logtail-install`. Download diagnostics identify the host without adding URL credentials
or query strings. Exit 124/137 indicates timeout/forced termination. Vendor output may
provide more detail. An internal-mode failure suggests retrying the same install command
with the region's supported public selector (for Hangzhou, `--logtail-region
cn-hangzhou-internet`); it does not perform that switch. Inspect partial installation and
service status before retrying. No failed stage reports successful upload.

The initial shell command's outer curl is outside Bootstrap's control. Operators may
generate it with `curl --connect-timeout 10 --max-time 120 --retry 2 --retry-max-time 260`
in addition to `-fsSL`. The deadlines above do not bound OS package-manager operations
inside the separate Agent package installer.

Network regression tests cover public default, retained explicit intranet, another
region, curl/wget paths, failed downloads and vendor deadlines. Real cloud acceptance
still requires public-host installation plus machine-group/Logstore verification.

## Service Handoff

The vendor installer may start Logtail outside systemd. Bootstrap serializes its Logtail
phase with `/run/lock/secweaver-logtail-install.lock` (120-second acquisition timeout),
stops the managed service, then stops remaining host collector processes through the
vendor init script. A failed graceful stop falls back to vendor `force-stop`. An unfinished
systemd stop job or surviving collector aborts installation; no live PID lock is deleted.
Only after no host collector remains are versioned stale PID files removed. Bootstrap
then enables the service and starts it once, checking both systemd and init-script status.
An `active (exited)` oneshot service alone is insufficient. `--no-start` stops the daemon
started by the vendor installer and leaves it stopped. Doctor runs after this handoff.
This may briefly interrupt other collection jobs on a shared Logtail installation.

Bootstrap writes `/opt/secweaver-agent/etc/shipper-kind` (`logtail`, mode 0600) before
the Logtail download, so interrupted installation is diagnosable. Upgrades do not infer
this intent from `enterprise_id` or ES authorization. Existing installs without the marker
are detected through the conventional collector directories. When intentionally migrating
away from SLS, remove this marker after configuring the replacement collector.

## Uninstallation

```bash
sudo /opt/secweaver-agent/bin/uninstall.sh --purge --remove-logtail --remove-filebeat --json
```

The release archive also contains `uninstall.sh` beside `install.sh` for the
bootstrap phase. After installation, the canonical entrypoint is the copy under
`/opt/secweaver-agent/bin`; do not use a `secweaver-clean-stage-*` test directory
as the operational path.

Plain `--purge` removes Agent-owned files only. Both collector flags are explicit and
remove the selected collector's configuration/state/logs even without `--purge`.
Do not select a collector that must continue serving unrelated applications.

Agent 0.3.65 also closes the split-layout uninstall gap. Before deleting files,
the uninstaller stops and removes `secweaver-agent.service`,
`secweaver-agent-shipper.service`, `swl-agent.service` and the historical
standalone module units. A bounded TERM/KILL fallback handles a missing or
damaged unit; surviving known Agent processes make uninstall fail before data
deletion. Process matching uses product paths and legacy collector names and
does not match `secweaver-agent-gateway`.

Default binary removal includes the legacy `swl-agent`,
`audit-port-execmon`, `syslog-risk-json` and `host-persistence` commands.
`--purge` additionally removes `/etc/secweaver-agent`,
`/var/lib/secweaver-agent`, `/var/log/secweaver-filebeat`, and known
SecWeaver log families plus their rotations under `/var/log`. The script
never recursively removes `/var/log`; unrelated logs and custom legacy output
names remain. `--remove-config`, `--remove-state`, and `--remove-logs`
apply the same current-plus-legacy ownership rules independently. Logtail and
Filebeat programs remain opt-in removals.

- Logtail: `/usr/local/ilogtail`, `/etc/ilogtail`, `ilogtaild`/`loongcollectord` init scripts
  and systemd units/drop-ins.
- Filebeat: RPM/DEB package (through `rpm -e`/`dpkg --purge`), `/usr/share/filebeat`,
  `/etc/filebeat`, `/var/lib/filebeat`, `/var/log/filebeat`, standard command paths,
  init script and systemd unit/drop-ins. Nonstandard tar installs must supply explicit
  `FILEBEAT_ROOT`, `FILEBEAT_ETC`, `FILEBEAT_STATE`, `FILEBEAT_LOGS`,
  `FILEBEAT_COMMAND`, `FILEBEAT_LOCAL_COMMAND` overrides.
- Override `LOGTAIL_ROOT`/`LOGTAIL_ETC` for nonstandard standalone layouts. The script
  rejects relative, broad and symlink deletion roots. It verifies host executable paths
  before terminating residual collector processes and retains files if stopping fails.
- Auditd, system audit history, other audit keys and remote enrollment records are not removed.

`--json` reserves stdout for one JSON object; progress/package-manager output goes to
stderr. Zero matching rules is success. `audit.remaining_rule_count=-1` means auditctl
is unavailable; `-2` means listing failed and verification fails unless audit cleanup was
explicitly skipped. Remaining units/processes/requested files cause a nonzero exit.
`standalone_collectors.<name>.remaining=null` means removal was not requested, not absent.
An interrupted operation emits `ok:false,error:uninstall_incomplete` and exits nonzero.
The same verification controls exit status without `--json`.

The `files` result includes `known_binaries_exist`,
`legacy_config_exists`, `legacy_state_exists`,
`legacy_known_logs_exist`, and `legacy_filebeat_logs_exist`. Any requested
legacy residue changes `ok` to `false`.

## Local And Cloud Verification

```bash
secweaver-agent doctor -config /opt/secweaver-agent/etc/config.json -json
systemctl status ilogtaild.service
sudo /etc/init.d/ilogtaild status
```

Doctor and `secweaver-agent-health.log` share Logtail identity/service/process checks.
Health adds `shipper.service`, `service_status`, `process_status`, `cloud_delivery`,
`reason`, `checked_at`; existing `type`/`configuration` remain. Local collector defects
add `shipper_local_unhealthy` and degrade otherwise healthy output. Probes have 3/5-second
timeouts and are cached for at least 60 seconds during frequent transitions. Quiet hosts
refresh on the next normal health snapshot (default five minutes). `checked_at` identifies
the observation time; this is not continuous collector monitoring.

`cloud_delivery` is **unverified**: no cloud receipt is available to the Agent. Doctor
therefore emits a cloud-delivery warning even when all local checks pass. An active
collector, valid identity, successful Agent heartbeat or readable output log is not proof
of SLS ingestion. No AK/SK is added to the Agent. Verify machine-group online status,
Logstore collection bindings, and recent records matching this host/device and event time
in SLS. Check the operations-health destination as well. For ES/Filebeat/native shipper,
configuration detection alone reports unknown runtime/unverified delivery; use that
shipper's output test and a server-side query. Do not interpret missing telemetry as OK.

Regression coverage uses disposable layouts and mocked services for zero/failed audit
queries, collector retention/removal, graceful/forced handoff, stubborn processes,
no-start and active-oneshot/dead-daemon cases. Release acceptance still requires a real
clean-host installation and server-side ingestion query for each supported delivery setup.

On 2026-09-24 the new lifecycle functions were exercised on the CentOS 7/systemd 219
test host: managed restart, `--no-start`, and a vendor-init-started daemon outside systemd
all passed. The final Logtail service and daemon/worker pair were running. This targeted
test did not replace the installed Agent or publish the 0.3.41 download channel.

# SaaS Update Trust Repair and Legacy Migration

Agent 0.3.84 fixes installation/update diagnostics. The complete packaged
`recovery/` directory can be distributed independently. On 2026-10-09 the user
approved product repair, a 0.3.79 repair script and a one-time 0.3.45/0.3.64 bridge.
Recovery is an explicit operator action, never an automatic installer hook.

## Product Behavior

The old installers passed `-auto-install true`. Go flag parsing stopped at
`true`, potentially ignoring subsequent server-policy, public-key and CA flags.
Linux and Windows now pass `-auto-install=true` and
`-require-server-policy=true`; `config set-update` rejects trailing arguments.

Generic templates no longer reference nonexistent shipper CAs. Public SaaS uses
OS certificate trust with HTTPS verification enabled; private ES explicitly
provisions its CA. Configuration writes check CA readability/PEM and managed
signature trust before committing. Omitted values retain existing trust. To
explicitly remove the CA override, use `config set-update -use-system-ca`, Linux
installer `--update-use-system-ca`, or Windows `-UpdateUseSystemCA`. This conflicts
with a nonempty CA argument. Rotation keys, revocations, replay state and the
status output path are retained.

Doctor/preflight report local `update/ca` and `update/trust` errors without
network requests or replay-state writes. A runtime update CA/key problem does
not terminate collection. Actual fetching/signature verification belongs to the
updater. JSON status and heartbeat classify failures as follows:

| Reason | Class | retryable |
| --- | --- | --- |
| `update_ca_missing`, `update_ca_unreadable`, `update_ca_invalid` | configuration | false |
| `update_trust_missing`, `update_trust_invalid`, `manifest_signer_untrusted`, `manifest_signer_ambiguous` | configuration | false |
| `update_tls_verification_failed`, `manifest_http_rejected` (4xx except 408/429) | configuration | false |
| `manifest_signer_revoked`, `manifest_signature_invalid`, `manifest_signature_required`, `manifest_invalid` | integrity | false |
| Connection/timeouts, HTTP 408/429/5xx: `manifest_fetch_failed` | transport | true |

Non-retryable means configuration/release intervention is needed; it does not
disable future periodic checks or collection. Existing server circuit-breaker
policy still applies. No server protocol, tenant permission or
`health-evidence-v1` capability gate is relaxed by this change.

## Supported Recovery

Copy the **whole** `recovery/` directory, including the Python helper and JSON
profile. The profile contains only public release metadata/public key, never a
private key, enrollment token or device password. Its default target is the
previously published **0.3.83**, retaining the pinned artifacts verified during
recovery testing. Publishing 0.3.84 does not silently retarget this profile. The
bridge repairs trust directly and does not rerun the affected old installer.
Every Linux/Windows archive includes all five recovery files and both language
guides under `docs/`; packaging validates their presence before cross-compilation.

| Script | Source | Prerequisites |
| --- | --- | --- |
| `repair-saas-update.sh` | Linux 0.3.79 (target version allowed for reruns) | root, systemd including CentOS 7/219, Python 3.6+, curl, 256 MiB free |
| `migrate-saas-agent.sh` | Linux 0.3.45/0.3.64 to 0.3.83 | same; amd64/arm64/loong64 |
| `migrate-saas-agent.ps1` | Windows 0.3.45/0.3.64 to 0.3.83 | Administrator PowerShell 5.1+, SCM, x64/ARM64, 256 MiB free |

An existing running service and complete device identity/key are required. The
configured SaaS origin must match the trusted profile. Only the exact known
missing default CA is removed; custom/existing CA, private ES mode or a different
primary signing key requires operator review. Revocations remain authoritative.
Disabled `update.enabled`/`auto_install` settings stay disabled. No re-enrollment,
shipper reinstall, identity deletion or learning/history reset occurs. Unexpected
versions, updater locks and pending health transactions are rejected.

The trust chain is the operator-distributed profile, pinned manifest SHA-256,
pinned binary hash/size, then the native Agent's Ed25519/expiry/replay/revocation
checks. Never bootstrap a key from the unverified manifest itself. The default
manifest expires **2026-10-23 01:44:16 UTC**. After expiry, supply an independently
verified new profile with `--profile` / `-ProfilePath`; never bypass verification
or overwrite old release bytes.

## Commands

Run from the complete `recovery/` directory. Default execution only checks;
`--apply` / `-Apply` explicitly modifies the installation and restarts the Agent.

```bash
sudo bash ./repair-saas-update.sh
sudo bash ./repair-saas-update.sh --apply

sudo bash ./migrate-saas-agent.sh
sudo bash ./migrate-saas-agent.sh --apply
```

Linux overrides: `--root`, `--config`, `--binary`, `--service`,
`--health-timeout` (default 180, range 30–600 seconds). The script verifies the
service ExecStart references these paths. Process hosts sequentially, review one
successful result before continuing, and retain per-host JSON results. Offline
machines first need connectivity restored.

In Administrator PowerShell:

```powershell
& .\migrate-saas-agent.ps1
& .\migrate-saas-agent.ps1 -Apply
```

Windows overrides: `-InstallRoot`, `-ConfigPath`, `-BinaryPath`, `-ServiceName`,
`-HealthTimeoutSeconds`. The default real service name is `SecWeaverAgent`.
Subsequent managed Windows upgrades still need a separate Windows campaign.

## Results and Recovery

Check-only returns `status=checked`, leaving service/config/identity unchanged;
temporary verification directories and a host-local recovery lock file are
allowed. Apply backs up config/binary beneath `data/recovery/<timestamp-random>`,
stops the service, rechecks concurrent config/binary/identity changes, then
atomically replaces config and, for migration, the executable. Success requires
fresh status, matching device, correct version and every module running for 15
seconds. Low-traffic hosts need no generated security events. `status=recovered`
includes observed version and backup path. An immediately unblocked campaign may
install a newer healthy version; this also counts as repair success.

Failure attempts to restore this operation's config/binary and start the old
service. If a normal automatic update has taken ownership, recovery refuses to
overwrite its binary/rollback state and requests operator inspection. Backups are
**not whole-disk snapshots**: new logs, module state and learning data are not
rewound. Power loss/forced termination leaves backups for manual recovery.
Linux retains failed command output in a 0600 `secweaver-recovery-error-*.log`;
Windows retains a temporary diagnostics directory readable only by
Administrators/SYSTEM. Result JSON does not print enrollment credentials.

For manual restoration, first rule out an active automatic update, stop the
service, copy the reported backup's `config.json` and `secweaver-agent[.exe]` to
their original paths, then restart. Do not restore/delete device keys, license
state or learning directories. Retain the recovery record; remove old backups
only according to the operator's retention policy.

Script success proves local trust/signature/startup health. Managed campaign
completion still requires a `last_update_status=healthy` heartbeat; manual
migration never fabricates a campaign-success record.

## Verification

Run `go test . ./pkg/agentupdate` and
`python3 -m unittest discover -s integration/recovery -v` from the Agent directory.
Coverage includes old boolean truncation, key/CA persistence, failure taxonomy,
check-only non-mutation, hash refusal before execution, identity/learning
preservation, health-failure restoration and concurrent-update protection.
Transaction tests use isolated service-boundary fixtures. Native Linux systemd
and Windows SCM migration must also be exercised on independent test services;
unit tests alone are not evidence for the entire deployed fleet.

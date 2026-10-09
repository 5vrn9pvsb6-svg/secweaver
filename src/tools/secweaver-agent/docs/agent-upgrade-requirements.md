# SecWeaver Agent Upgrade Requirements

**Status:** The remediation is implemented in code, migrations, workspace UI, and regression tests; packaging, database migration, and production release remain separate gates.  
**Content revision:** `upgrade-requirements-r2`, 2026-10-04.  
**Scope:** Scheduled checks, staged installation, health confirmation, and rollback for the unified `secweaver-agent`; collector module behavior is out of scope.  
**Current baseline:** Agent `0.3.73`; managed SaaS upgrades are decided jointly by tenant policy, campaign, and device lease in Agent Server.

This document is the requirements baseline. It records the implemented behavior and does not replace release approval or production-change authorization. See the [module and architecture document](agent-upgrade-architecture.md) for ownership and boundaries.

### Authorized Remediation on 2026-10-09 (0.3.84)

The user explicitly requested the product fixes, 0.3.79 repair and one-time
0.3.45/0.3.64 migration scripts, reusing the established trust, identity and
recovery requirements. Installers must consume all signer/CA arguments; public
updates use OS trust, private CAs are explicit. Validate trust before writes,
provide local doctor checks and classify configuration/integrity/transport errors.
Scripts default to checking; explicit apply backs up, changes, restarts and
observes health while retaining identity/learning. Tenant/capability gates remain.
The bridge targets published 0.3.83 with repaired configuration; unpublished
0.3.84 is not automatically released. See the [recovery guide](update-recovery.md)
for scope, platforms, verification and limitations. No database/server protocol
changes are included.

## 1. Context and Goals

Agents run across multiple tenants and Linux/Windows hosts. Upgrades must protect the supply chain, spread fleet activity, preserve service availability, and leave an explainable recovery trail.

### 1.1 Goals

- Provide one self-update path owned by the unified Agent; collector modules must not replace the Agent binary.
- Keep automatic installation disabled by default; a tenant must explicitly allow it and a publisher must explicitly create an activity.
- Use immutable `device_id` values for stable rollout membership, maintenance windows, concurrency limits, and failure circuit breaking.
- Protect manifests and artifacts with HTTPS, SHA-256, and Ed25519 signatures when trust keys are configured.
- Support atomic replacement, restart, health probation, and rollback under Linux systemd and Windows SCM.
- Expose machine-readable reasons for policy denial, download, verification, installation, health, and rollback outcomes.

### 1.2 Non-goals

- The Agent must not hold SLS AK/SK; it uses enrolled device identity and device-key authentication.
- The tenant switch is an allow gate, not a campaign publisher.
- Plain manifests must not silently authorize downgrades; rollback requires signed and server-authorized directives.
- Agent self-update is separate from collector, Logtail, and Filebeat upgrades.
- Temporary control-plane failure must not stop the Agent; it delays the update and retries.
- Do not build a signing service or KMS. Release Operations signs with existing tools in a controlled environment; client signature verification remains intact.

## 2. Roles and Main Flow

| Role | Responsibility | Does not own |
|---|---|---|
| Tenant Owner/Admin | Enables or disables the tenant automatic-update permission | Artifact publishing or signature verification |
| Release Operations | Builds/signs artifacts, publishes manifests, creates campaigns, sets rollout controls | Per-host eligibility edits |
| Agent Server | Owns tenant policy, campaigns, members, leases, and result recording | Client-side verification and atomic replacement |
| Agent | Pulls policy, verifies artifacts, installs, reports status, confirms health, or rolls back | Expanding rollout eligibility |
| Service manager | Stops/starts the Agent and coordinates OS-specific replacement | Upgrade policy decisions |

Flow: publish a signed target -> create a campaign -> enable tenant permission -> Agent heartbeat receives eligibility and lease -> scheduled check applies spread delay -> verify and commit -> restart -> health probation -> report `healthy` or roll back.

## 3. Functional Requirements

### REQ-UPG-001 Defaults and dual permission

- New configurations default both `update.enabled` and `update.auto_install` to false.
- Agent Server defaults `agent_auto_update_enabled` to false. When disabled, heartbeat returns `auto_update_allowed=false` and `tenant_auto_update_disabled`, and removes the device lease.
- Only the enterprise Owner/Admin may change the tenant permission. Two-person approval is not required, but every change must be audited with tenant, actor, old value, new value, time, request source, and result.
- A tenant permission never bypasses activity, target, rollout, maintenance-window, or lease checks.
- Revoked permission, paused activity, or revoked lease must cancel or defer an install that has not entered local commit.
- `config set-update --auto-install` is an explicit administrator action and must not change production template defaults.

**Acceptance:** A fresh Agent does not replace itself; the server gate gives an explainable denial for every device when disabled.

### REQ-UPG-002 Identity and stable rollout

- Managed updates require the immutable enrolled `device_id`; hostname, IP, and PID are not fallbacks.
- A device remains in the same rollout bucket across restart, heartbeat retry, and upgrade.
- Devices registering after a campaign member snapshot must not join silently.

### REQ-UPG-003 Schedule, jitter, and backoff

- The Agent checks on a configured interval; current templates use a six-hour interval, a 60-second initial delay, and 300 seconds of stable jitter.
- Transient network, manifest, and artifact failures use bounded exponential backoff from one minute to one hour and honor HTTP `Retry-After`.
- Jitter is derived from stable identity so restarts do not synchronize the fleet.
- Network operations are cancellable and cannot block service stop forever.

### REQ-UPG-004 Rollout, windows, and concurrency

- Agent Server is the sole rollout authority for managed mode.
- A campaign supports channel, target, ring, member snapshot, percentage rollout, maintenance window, percentage/device concurrency caps, failure samples, and failure threshold.
- Each tenant configures rollout percentage, percentage/absolute concurrency, maintenance window, and failure circuit-breaker thresholds in the enterprise workspace. The UI validates ranges and audits policy changes; safe platform defaults prevent unlimited concurrency or an immediate all-device install.
- Leases expire; the Agent fails closed when less than three minutes remain.
- Failure thresholds automatically pause an activity; devices that have already committed may finish health confirmation, while uncommitted devices cannot install.
- Manifest allow/deny rollout remains for standalone mode only.

### REQ-UPG-005 Bandwidth spreading

- `download_spread_seconds` delays downloads for already authorized devices; it does not grant eligibility.
- Policy changes, lease expiry, or pause during the delay cancel/defer the installation.
- Artifacts are streamed into bounded temporary files while hashing; the whole package is not loaded into memory.

### REQ-UPG-006 Manifest, trust, and integrity

- A manifest contains schema, application, channel, generation/time metadata, target version, and platform artifact metadata.
- HTTPS is the default transport. Once a trusted public key is configured or persisted, signed envelopes are mandatory.
- The Agent checks envelope signature, generation/digest, platform URL, size, SHA-256, and artifact signature.
- Production Windows artifacts should also declare an allowed Authenticode publisher certificate SHA-256 list.
- Key rotation adds a new key before revoking the old key; revoking all trusted keys is rejected.
- Private signing keys remain in release infrastructure and never enter packages or logs.
- Release Operations keeps the private key and uses existing `cmd/update-sign`. Restrict reads to the signing operator (`0600` on Unix or equivalent Windows ACL), keep an access-controlled encrypted backup, and never commit it. CI builds/tests/provenance without a new signing API or long-lived private key; Operator distributes signed artifacts/public keys; Agent verifies.
- Release Operations records rotation and global signed-stop operations. Add the new key under the current trusted signer before revoking the old key, and verify applicable devices trust the new key first. Offline trust migration is manual. If a lost private key cannot be restored, manually migrate client trust rather than silently replace the signer.

### REQ-UPG-007 Atomic installation and lifecycle

- Before commit, acquire the update lock, check free space, back up the current binary, and persist recovery markers.
- Commit order is download -> verify -> backup -> persist `commit_prepared` -> replace/schedule replacement -> persist status.
- Once commit starts, cancellation cannot relabel the result as `policy_deferred`.
- Linux uses same-filesystem atomic replacement and systemd restart. Windows stages a same-directory replacement, performs controlled stop, uses a replacement helper, and restarts through SCM.
- Locks, state, backups, and pending files live in a protected state directory with stale-lock recovery.

### REQ-UPG-008 Health probation and rollback

- A new version enters `installed_pending_health`; the current default probation is 90 seconds.
- All enabled modules must remain running without collection-impacting errors. New business output normally demonstrates progress; a low-traffic host with no business events may instead use collector heartbeats or collection-loop health-probe progress plus successful local health JSONL writes. Business events are not mandatory.
- Substitute evidence must be fresh within this startup's probation window and demonstrate that each enabled collector can work. Parent-process liveness, a generic Agent heartbeat, stale health records, or cloud connectivity alone are insufficient. No business events does not mean a stuck module; no verifiable health progress does not mean success.
- Obtain evidence actively within probation rather than wait for normal reporting intervals. Stuck modules, probe errors, or local output-write failure still fail health. Cloud arrival of business logs is not required, and verification must not fabricate security events.
- Healthy completion clears recovery markers and retains a bounded backup set; current default is three backups.
- Failed probation restores the previous version on both platforms and reports the reason.
- Manual rollback and authorized remote rollback use the same lock, backup, and atomic replacement semantics.

### REQ-UPG-009 Observability

- Every check/install/rollback emits a JSON status record containing status, reason, versions, device, campaign, policy revision, manifest generation/digest, and retry information.
- Reasons distinguish policy denial, tenant disablement, rollout exclusion, lease failure, manifest/download/verification failure, backup/replacement/service/health failure, and rollback failure.
- `doctor`, health JSONL, and service logs must distinguish local generation from cloud delivery.
- Enrollment tokens, private keys, full authorization headers, and sensitive URL parameters must never be logged.

### REQ-UPG-010 Compatibility, private, and offline deployments

- **Agent Server owns backward compatibility:** the SaaS server supports historical Agent versions/protocols within its support policy. Customer Agents may remain on mixed versions; server releases cannot depend on synchronized client upgrades.
- Preserve existing enrollment, heartbeat, update-policy, and status-report contracts. New request fields cannot become mandatory for old protocols; existing fields cannot silently change type or meaning. Responses follow verified protocol/capability evidence, not assumptions based solely on a version string.
- Enforce tenant permission on the server. For Agents that ignore `auto_update_allowed`, use their supported denial contract, such as `enabled=false` and withholding eligibility/leases. A new field alone is not an authorization boundary.
- Defer unsafe managed updates for Agents lacking critical safety capabilities and offer compatible/manual migration while continuing their supported enrollment/heartbeat and normal collection. Compatibility never bypasses existing authentication or authorization.
- Do not require the entire fleet to upgrade after one server release cycle. Protocol retirement requires a separate support policy, advance notice, a migration path, and confirmation. New-Agent tolerance of an older server's missing field is an implementation detail, not the main SaaS compatibility requirement.
- SaaS uses the Agent Gateway heartbeat/policy API. Private and ES deployments may use a local HTTPS manifest and public key without the SaaS source tree.
- Fully offline deployment temporarily supports only manual `secweaver-agent update install`; it does not deploy a local campaign service or unattended offline auto-update. It uses only local trusted manifests, keys, and artifacts and never silently accesses the public Internet.
- Linux support requires systemd; Windows support requires SCM service permissions. Unsupported hosts must receive an explicit reason.

## 4. State Model

```text
disabled -> policy_deferred -> checked -> update_available
  -> download_delayed -> downloaded_verified -> commit_prepared
  -> installed_pending_health -> healthy

Any stage -> failed
failed/health_failed -> rollback_scheduled|rolled_back|rollback_failed
```

`policy_deferred` is an explicit non-eligibility result, not a successful installation. `failed` requires a failure class and retryability. `healthy` is emitted only after probation completes.

## 5. Configuration and Contracts

The Agent `update` block uses the current safe defaults: six-hour interval, 60-second initial delay, 300-second jitter, one-minute to one-hour retry range, `auto_install=false`, managed policy required, 90-second health timeout, one-hour stale-lock recovery, three backups, and 256 MiB free-space reserve. Production must additionally configure an HTTPS manifest, private CA when required, and a trusted Ed25519 public key.

The server policy carries campaign, revision, target, channel, manifest URL, rollout, auto-install, pause, maintenance, concurrency, circuit-breaker, and downgrade/rollback fields. Device responses carry eligibility, lease, expiry, reason, and `auto_update_allowed`.

`state.json` is recovery authority, not a display cache. It stores current/previous/target versions, attempt/campaign/revision, manifest generation/digest, backup/pending paths, health window, failure class, and next retry. A state-write failure must preserve recovery materials for the next startup.

## 6. Acceptance Matrix

| Area | Evidence |
|---|---|
| Safe defaults | Fresh config, `doctor`, and scheduled status show disabled reason |
| Tenant gate | Server test returns `tenant_auto_update_disabled` and no lease |
| Stable rollout | Repeated heartbeats keep the same device eligibility; concurrency is capped |
| Bandwidth spread | Downloads are distributed and cancellable during the spread window |
| Supply-chain checks | Negative cases reject signature, generation, hash, platform, and Authenticode errors |
| Service recovery | Linux systemd and Windows SCM cover healthy zero-event hosts, rejected stuck modules/health-write failures, startup failure, probation timeout, and rollback |
| Network recovery | Agent stays active, backs off, and resumes after recovery |
| Diagnosis | State, status JSONL, health log, and `doctor` expose phase and reason |
| Compatibility/offline | New server contracts cover current/historical Agents, including denial when tenant permission is off; private CA, local manifest, and no-public-network paths are verified |

## 7. Confirmed Decisions and Implementation Results

1. Implemented: only Owner/Admin changes the tenant switch; no two-person approval, but every change is audited.
2. Implemented: each tenant configures rollout, concurrency, maintenance, and circuit-breaker values in the workspace; the platform supplies safe defaults and range validation. New tenants default to `10%` rollout, `10` concurrent devices, `20%` failure threshold, and `1` minimum sample. The maintenance window must be explicitly saved as all-day or as a scheduled interval.
3. Implemented: SaaS Agent Server supports mixed customer Agent versions without synchronized upgrades. Supported-version coverage and any protocol retirement require contract evidence and a separate support policy.
4. Implemented simplification: no signing service/KMS. Release Operations keeps keys and signs/rotates/stops releases with existing tools; CI builds/tests/provenance, Operator distributes signed artifacts/public keys, and Agent verifies. The workspace does not handle release private keys.
5. Implemented: low-traffic hosts may pass using all-module liveness, verifiable collector-health progress/advancing health JSONL, and no collection-impacting errors without business output. Parent liveness or a generic heartbeat alone is insufficient.
6. Implemented: fully offline temporarily supports manual `update install` only and has no local campaign service.

**Implementation note:** Audit without two-person approval, per-tenant settings, manual-only offline upgrades, server-owned compatibility, low-traffic evidence, and no signing service/KMS are implemented. The architecture document records the interface, migration, and health-evidence details.

## 8. Gap-Remediation Scope

**Source:** On 2026-10-04, after the code-backed gap analysis, the user replied "好的，按照你的建议来修复" (proceed with the suggested fixes). This confirms these goals, not an unpresented detailed architecture, production operations, or future work.

| Goal | Requirements | Acceptance |
|---|---|---|
| Unified lock/recovery state | REQ-UPG-007/008 | Failed locks/checks or concurrent confirmation cannot overwrite another transaction |
| Independent startup recovery | REQ-UPG-008/010 | Disabled scheduling still confirms/rolls back manual upgrades without remote sources |
| Low-traffic health | REQ-UPG-008 | Fresh collector-loop progress and local health writes pass with zero events; stale/stalled evidence fails |
| Schedule/backoff/spread | REQ-UPG-003/005 | Equivalent renewals preserve waits, revocation cancels pre-commit work, honor Retry-After |
| Tenant policy | REQ-UPG-004 | Complete workspace controls with safe defaults, validation, audit, permissions, and isolation |
| Historical compatibility | REQ-UPG-010 | Unknown safety capability defers upgrades without breaking supported collection/authentication |
| Healthy completion | REQ-UPG-008/010 | Target version alone is not success; missing proof remains unverified |
| Install defaults | REQ-UPG-001 | Local checking/install default off with explicit enablement and denial diagnostics |
| Audit/observability | REQ-UPG-001/009 | Old/new/request-result audit; consistent doctor/health/log/heartbeat projections |
| Trust/cancellation | REQ-UPG-003/006 | No unsigned managed install; cancellable requests/waits; no signing service/KMS |

**Scope:** Community Agent, independent Agent Server, and independent SaaS workspace. Health interfaces, compatible fields, and additive migrations require architecture approval. Do not change security-event classification/filter semantics, combine shipper upgrades, or maintain former independent-project copies.

**Excluded:** Packaging/upload, production migration/deployment, private-key creation/rotation, offline campaigns, signing service/KMS. Later changed Agent packages increment immutable versions; Server/Operator remain independent.

**Release gate:** Version bump, package build, database migration rehearsal, mixed-version contract tests, and production verification remain before release. See [architecture section 11](agent-upgrade-architecture.md#11-implemented-remediation-design). Tests do not replace the release approval.

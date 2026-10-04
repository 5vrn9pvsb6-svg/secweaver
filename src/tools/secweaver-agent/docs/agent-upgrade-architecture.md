# SecWeaver Agent Upgrade Modules and Architecture

**Status:** This remediation design is implemented; tests pass. Packaging, production migration, and deployment are outside this change.  
**Content revision:** `upgrade-architecture-r2`, 2026-10-04; requirements `upgrade-requirements-r2`, section 8.  
**Requirements:** [Upgrade requirements](agent-upgrade-requirements.md)  
**Design rule:** The server decides *who may upgrade*; the Agent decides *how to install and recover safely*.

This document separates ownership, protocol boundaries, and implemented behavior. Section 11 records this implementation; release gates still require production verification.

## 1. System Boundary

```text
Workspace UI -- tenant permission --> Agent Server / Agent Gateway
                                         | heartbeat policy, rollout, lease
                                         v
                                   secweaver-agent
                                         | signed manifest/artifact HTTPS
                                         v
                                   release or private update source

secweaver-agent -> systemd (Linux) / Windows SCM
secweaver-agent -> local state, backups, update and health JSONL
```

| Boundary | Owner | Constraint |
|---|---|---|
| Tenant automatic-update permission | Agent Server database and workspace | Off by default; Owner/Admin only; every change audited; cannot be forged by the client |
| Campaign, rollout, lease | Agent Server `controlplane` | Decided in heartbeat transaction under tenant update lock |
| Manifest and artifacts | Release system/update source | HTTPS, generation, SHA-256, Ed25519; private key stays server-side |
| Install transaction | Agent `pkg/agentupdate` | One owner for locks, backups, atomic replacement, recovery markers |
| Process lifecycle | systemd/SCM adapters | OS stop/start and file handles only; no policy decisions |
| Health result | Agent runtime and Agent Server heartbeat | Client supplies evidence; server records campaign outcome |

## 2. Responsibilities and Dependencies

### 2.1 Agent

| Module/path | Owns | Does not own | Allowed dependencies |
|---|---|---|---|
| `agent_config.go` | Parse update config, defaults, validation | Tenant authorization | `pkg/agentupdate` and config types |
| `scheduled_update.go` | Scheduler, jitter, policy gates, spread wait, backoff, health trigger | Database or tenant policy storage | license, update, metrics |
| `controlplane.go` | Enrollment, heartbeat, authorization state, policy channel, network backoff | Binary replacement | `pkg/agentlicense`, scheduler callback |
| `pkg/agentlicense` | Device identity/key, heartbeat response, `UpdatePolicy` mapping | File installation | HTTPS transport, protected identity state |
| `pkg/agentupdate/manifest.go` | Strict manifest, signature, generation, platform artifact, rollback directive validation | Tenant eligibility | trust/version/transport |
| `pkg/agentupdate/trust.go` | Trusted-key rotation and revocation | Private-key storage | Protected local state |
| `pkg/agentupdate/transport.go` | HTTPS/local manifest read, streaming download, CA, timeouts | Install policy | context, filesystem |
| `pkg/agentupdate/update.go` | Check, install, rollback, health, JSON state, lock, backups | Agent Server database | Platform replacement adapters, layout, output |
| `atomic_replace_*`, `replace_helper_*` | Unix/Windows replacement and service-helper differences | Rollout and signature decisions | OS APIs and service manager |
| metrics/operations health | Read-only update metrics and JSONL diagnostics | Authorization source | status/state projections |
| `packaging/`, `examples/update-server/` | Package, manifest, and deployment examples | Runtime version decisions | Release toolchain |

Dependency direction is configuration/scheduler -> protocol and update package. The protocol never calls the installer; the installer never reads the server database; platform code is called only by the update transaction. Collector modules do not depend on `pkg/agentupdate`.

### 2.2 Server

| Module/path | Owns |
|---|---|
| Agent Server `controlplane/updates.go` | Policy validation, member snapshots, stable buckets, windows, leases, circuit breaker, pause/resume, result coordination |
| Agent Server heartbeat/store handlers | Tenant gate, result recording, policy response, and backward-compatible supported Agent contracts |
| Agent Server migrations | Tenant permission, campaign, member, lease, and result schema |
| SaaS workspace | Owner/Admin UI for tenant permission, per-tenant rollout/concurrency/window/circuit-breaker controls, and audit records |
| CI | Build, test, provenance, and unsigned material; no long-lived release private key required |
| Release Operations + `cmd/update-sign` | Controlled private-key custody, manifest/artifact signing, key rotation/revocation, global signed stop, and operation records |
| Release system/Operator | Publish signed artifacts, public key, URLs, and version catalog; never export the private key |

Use existing local signing tools, not a signing service/KMS. The controlled environment is an operator workstation or release host, not a new daemon or signing API.

The server is the sole authorization owner. The Agent consumes `UpdatePolicy` and cannot override explicit denial through local config. Tenant pause/disable is tenant-scoped; Release Operations signs a global stop with the current trusted key. The workspace neither holds release keys nor fabricates signatures.

### 2.3 Simplified Signing and Key Operations

This reuses existing commands without a new service. Detailed procedures remain part of the architecture draft:

1. CI builds/tests immutable platform artifacts and provenance; Release Operations verifies target and hashes.
2. Restrict the signing workstation/host's private key to `0600`/equivalent ACL and keep an offline encrypted backup. Never place it in Git, public downloads, Operator archives, or customer hosts.
3. Sign artifacts/manifests with `cmd/update-sign`, then run `-verify` with the public key. Publish signed material and public trust only, never the private key.
4. Add a new key using `-add-public-key-file` under the current signer; establish applicable client trust before signing a later manifest with the new key and revoking the old one with `-revoke-key-id`. Older/offline clients without rotation support need manual trust migration.
5. For emergency stop, pause affected server activities and withhold new leases. Operations may also publish an increasing-generation signed stop using the current trusted key and `-emergency-stop-reason`. This only affects supporting Agents, never replaces old-client denial contracts, and cannot interrupt an already committed local transaction.
6. Record version, hash, key ID, actor, time, reason, and result, not private-key contents. Restore lost keys from backup; if impossible, stop signed publishing and manually migrate client trust instead of replacing the old identity with a new key.

## 3. Contracts

### 3.1 Configuration to runtime

`updateConfig` maps to `scheduledUpdateConfig` and `agentupdate.Options`. `enabled=false` does not start scheduling; `auto_install=false` permits checks but no replacement; `require_server_policy=true` requires enrolled identity, heartbeat, and a valid server policy. Current production defaults are a six-hour interval, 60-second initial delay, 300-second jitter, one-minute to one-hour retry range, 90-second health probation, one-hour stale-lock recovery, three backups, and a 256 MiB free-space reserve.

### 3.2 Server to Agent

Policy fields include identity/version (`campaign_id`, `policy_revision`, `target_version`, `channel`, `manifest_url`), authorization (`enabled`, `auto_update_allowed`, `eligible`, `paused`, `reason`), lease/resource fields, rollout/window fields, and failure/downgrade controls. Processing order is tenant permission -> activity -> pause/window -> rollout -> auto-install -> target -> lease safety margin -> manifest URL/channel. Any failure produces `policy_deferred`. Workspace-configured tenant rollout, concurrency, window, and circuit-breaker values are validated and fixed into the server activity; the Agent does not reinterpret them.

### 3.3 Signed manifest

```json
{
  "key_id": "ed25519-...",
  "payload": "base64(manifest-json)",
  "signature": "base64(ed25519(payload))"
}
```

The payload includes schema/app/channel/generation/expiry, latest version, platform binaries, and standalone rollout controls. Managed mode uses server eligibility; `download_spread_seconds` only spreads authorized downloads.

Acceptance order is read -> parse envelope -> select trusted key -> verify -> parse payload -> validate generation/expiry -> validate target/platform/URL -> validate size/SHA/signature -> enter install transaction.

### 3.4 Recovery state

`state.json` is recovery authority. It stores versions, transaction identifiers, campaign/revision, manifest evidence, backup/pending paths, health window, failure class, retryability, and next retry. A failed state write must not delete the only backup or recovery marker; the next startup resolves the incomplete transaction before normal scheduling.

### 3.5 SaaS Server Backward Compatibility with Agents

These are the clarified contract requirements, not a claim of new implementation in this documentation change:

- **Ownership:** Agent Server handlers recognize supported historical protocols and normalize requests before activity/lease decisions; old clients cannot be required to supply new fields.
- **Wire contracts:** Preserve old enrollment/heartbeat routes and field semantics. Response additions must be ignorable by compatible clients; select recognized control results from verified protocol/capability evidence, not version strings alone.
- **Authorization:** Agents that ignore `auto_update_allowed` still receive their supported denial fields and no lease when tenant permission is off. Defer unsafe managed updates without interrupting supported enrollment/heartbeat or normal collection.
- **Reports:** Older Agents may omit campaign, attempt, or health metadata. Attribute results only when tenant/device/target reliably match; keep repeats idempotent and missing health evidence unknown/unverified, never fabricated `healthy`.
- **Matrix:** Each server release tests current and supported historical Agents, including mixed-version activities. Protocol retirement is a separate lifecycle decision, not a requirement to upgrade every customer Agent within one server release cycle.

## 4. Key Sequences

### 4.1 Managed check and install

```text
Scheduler -> policy channel -> apply gates -> fetch signed manifest
  -> validate generation/version/platform/signature
  -> wait download spread while watching policy
  -> update lock -> stream artifact and verify
  -> reserve disk -> backup -> persist commit_prepared
  -> CommitGuard validates lease/policy
  -> atomic replace or Windows scheduled replace
  -> persist installed_pending_health -> service restart
  -> health confirmation -> healthy, or locked rollback
```

`CommitGuard` is the boundary between revocable approval and binary commit. Cancellation is allowed before commit; after commit begins, the transaction must complete or enter recovery.

### 4.2 Health failure

```text
new process -> PrepareHealthCheck under update lock
  -> target version match -> observe modules/output
  -> MarkHealthy, or RollbackForReason
  -> platform restore -> rolled_back / rollback_failed
```

**Confirmed low-traffic rule; implementation/verification pending:** With no business events, the observer may use each enabled collector's loop-health-probe/module-heartbeat progress plus successful local health JSONL writes. Obtain fresh evidence within this startup's probation window rather than wait for normal reporting intervals. Parent liveness or generic heartbeats do not establish collector health; stuck modules, probe errors, or failed local health writes still fail probation. Cloud log arrival is not required and synthetic security events are not generated. This documentation change does not claim the evidence path is already implemented.

### 4.3 Policy change and stop

- The scheduler consumes policy-channel updates. Pause, lease expiry, or revoke cancels waits/downloads before commit.
- `context.Context` covers manifest reads, downloads, and policy waits; service stop cannot leave an unbounded network operation.
- `managedInstallCommitGate` protects the revocable/commit-started boundary. The local lock protects the transaction; it does not replace the server lease.

## 5. Concurrency, Locks, and Resource Bounds

1. One Agent scheduler exists per device; the local update lock serializes install, health recovery, and rollback.
2. Agent Server serializes tenant policy, campaign membership, and lease decisions under one tenant update lock.
3. The policy channel owns no binary state. A server outage causes backoff, not collector process exit.
4. Downloads use bounded temporary files, disk reserve checks, and cancellation. Retention pins any backup referenced by the active recovery transaction.
5. Windows replacement helpers coordinate service exit and file handles with bounded phases and bounded diagnostic retention.
6. The license identity lock and update transaction lock have separate ownership; code must not acquire them in an order that creates a cycle.

## 6. Platform Design

| Platform | Replacement | Restart | Failure cases |
|---|---|---|---|
| Linux/systemd | Same-filesystem atomic rename; launcher recognizes controlled restart exit | systemd | New binary cannot execute, unit start failure, health timeout |
| Windows/SCM | Same-directory pending file; helper replaces after service exit | Windows SCM | File handle, parent timeout, SCM start failure, health timeout |
| Standalone ES | Local/private HTTPS manifest and key, or manual `update install` | Host service manager | No SaaS lease; do not claim managed rollout |
| SLS SaaS | Gateway heartbeat policy and device lease | Host service manager | Tenant off, activity paused, lease/policy expiry |

## 7. Security Boundaries

- The tenant gate is checked server-side in the heartbeat transaction; `auto_install` is not a credential.
- Device keys authenticate devices; release private keys sign manifests; trusted public keys are separate.
- HTTPS/CA, size, SHA-256, and signatures protect both manifest and artifact. Development HTTP/unsigned modes must be explicit and absent from production templates.
- State and backup directories are service-account protected; logs do not contain tokens, private keys, or full authorization data.
- Rollback uses lock, version, and recovery-material checks; it is not an unsigned-install bypass.

## 8. Failure Matrix and Observability

| Stage | Failure | Result | Required evidence |
|---|---|---|---|
| Policy | Tenant off, rollout exclusion, pause, no lease | `policy_deferred` | reason, campaign, revision, lease |
| Manifest | HTTPS/CA/signature/generation/version | `failed`, no replacement | URL, generation/digest, failure class |
| Download | Timeout/status/size/hash | `failed`, temp cleanup | retryable, next retry, HTTP/security reason |
| Pre-commit | Lock/disk/backup | `failed`, running binary unchanged | state and backup paths |
| Commit | Atomic/helper failure | Recovery or next-start handling | phase, attempt, helper state |
| Health | Module stopped, stalled output, version mismatch | Automatic rollback | health window and evidence |
| Rollback | Backup or service restore failure | `rollback_failed` | recovery path, OS error, operator action |

The same outcome is projected into `state.json`, update JSONL, health JSONL/metrics, and heartbeat results; no projection may claim success merely because another local file was written. Low-traffic substitute evidence is allowed; record whether confirmation used business output or collector-health evidence. Generic heartbeats must not masquerade as collector evidence.

## 9. Test and Release Gates

Unit/contract coverage must include defaults, policy gates, stable buckets, leases, retries, signature/key rotation, generation replay, state transactions, lock races, commit cancellation, and backup retention. System coverage must include Linux systemd and Windows SCM success/failure/rollback, SaaS tenant/campaign controls, network recovery, private CA, and offline local manifests.

Server compatibility coverage includes old requests without new fields, old response semantics, unknown capabilities, idempotent report attribution, and missing health evidence. Mixed-version fleets verify supported enrollment/heartbeat after server upgrades and managed-update denial for old/current Agents when tenant permission is off.

On both platforms, verify healthy zero-business-event hosts pass; parent liveness/generic heartbeat alone cannot pass; stuck collectors, stale evidence, probe errors, or failed health writes trigger rollback.

Release gates:

1. Any Agent source/config/package change increments immutable `VERSION` before packaging.
2. Manifests contain platform integrity and provenance; private keys never enter artifacts.
3. Release starts with a small ring and observes failure rate, health rollback, lease usage, download peak, and error classes.
4. Before production, verify tenant default, rollback backup, SaaS/ES docs, and both platform service tests.

## 10. Requirement Mapping and Open Trade-offs

| Requirement | Main modules | Verification |
|---|---|---|
| REQ-UPG-001/002/004 | Server controlplane, license, scheduler | Policy/heartbeat/lease tests |
| REQ-UPG-003/005 | Scheduler and update transport | Jitter, backoff, cancellation, spread tests |
| REQ-UPG-006 | Manifest and trust modules | Signature/generation negative tests |
| REQ-UPG-007/008 | Update transaction and platform helpers | systemd/SCM integration |
| REQ-UPG-009 | State/status/metrics/health and server recording | schema, doctor, end-to-end checks |
| REQ-UPG-010 | Server protocol/heartbeat/report handlers, packaging, Bootstrap | current/historical Agent contracts and mixed fleets; five-platform/private-CA/offline tests |

Business decisions and remediation goals are recorded; historical contracts need evidence. Confirm the following design before implementation, without signing infrastructure.

## 11. Implemented Remediation Design

**Status:** The behaviors below are implemented in code, migrations, workspace UI, and tests; production migration/deployment and key operations are excluded.

### 11.1 Transactions and Independent Recovery

- `pkg/agentupdate` owns recovery state; Install, PrepareHealthCheck, MarkHealthy, Rollback, and scheduled-failure persistence use one state lock. Callers do not concurrently write recovery files.
- Checks may run outside locks but cannot write `state.json`; lock/check failures and policy denials use logs/separate projections. Install failures persist under lock; reject new installs during pending replacement/probation.
- Verify attempt/target/startup for confirmation/rollback; stale observers cannot confirm/clean newer work. Persistence/cleanup share ownership; never reclaim live locks by age alone. Ambiguity fails closed.
- Schedule and recovery configuration are separate: `update.enabled=false` skips scheduled checks but a pending transaction still starts local health confirmation/rollback without a manifest URL, network, or tenant lease.
- Windows stages in protected executable directories on the same volume; helper/state/recovery share attempts and failed handoff preserves old binaries/diagnostics.

### 11.2 Collector-loop Health

The implementation avoids a new collector control protocol. The supervisor records `last_health_at` for each running module; post-update health accepts fresh output evidence or a fresh supervisor lifecycle heartbeat.

1. Record one heartbeat after child start, then update it every 15 seconds through the coalescing status writer.
2. Prefer fresh output-file content for modules with output paths; quiet modules may use fresh lifecycle evidence without fabricating a security event.
3. Restarts, stopped modules, status persistence failures, or stale evidence prevent confirmation and remain visible in status/doctor output.

Touch supervisor/modulecontrol/status/operations/collector loops; separate evidence from business logs with no permanent high-frequency scanning.

### 11.3 Schedule/Cancellation

- Persist absolute check/retry/download-ready deadlines by stable device/activity separately from recovery; restart preserves unexpired waits.
- Compare campaign/revision/target/manifest/channel/eligibility/pause/window/permission/downgrade; an equivalent heartbeat is delivered at most every ten minutes to refresh a lease without resetting check/backoff timing.
- Revoke/short leases/activity changes cancel pre-commit work; committed work finishes/recovers. Context-bind manifests/artifacts, cancel CLI timers, bound stop/lock waits.
- Retry remains one minute to one hour, but longer Retry-After is a not-before deadline, never truncated; equivalent heartbeats cannot retry early.

### 11.4 Compatibility/Completion

- Heartbeats may include optional `update_capabilities`; the current Agent advertises transaction locking, health evidence, and signed manifests. Older Agents remain accepted, but a target-version Agent without `healthy` evidence receives `health_unknown` and no new lease.
- Adapters plus real historical fixtures establish verified capabilities; unproven claims/versions cannot grant safety. Unknown capability denies leases/upgrades without breaking supported collection; tenant-credentialed v1 bridges/authentication stay restricted.
- Target version is `version_reached`; idempotent tenant/device/target/campaign health evidence establishes success. Missing/ambiguous proof is `health_unknown`, not completion/invented failure.
- New migrations replace projections/reconciliation, not published migrations. Preserve completed history, reverify inferred active outcomes or manually close, without forced collector rollback.

### 11.5 Tenant Policy/Audit

- SaaS owns Owner/Admin UI/request audit; Agent Server owns campaigns/leases. Preferences are written through database capabilities, not frontend `proxy.update_*` writes.
- Workspace PATCH `enterprises/{id}/agent-update-policy` now provides idempotency, permission/range validation, tenant locking, and old/new-value audit.
- Tenant rollout/concurrency/window/circuit-breaker limits constrain activities, never unpublished binaries/trust keys. Changes lock the tenant, fence revisions/revoke leases, never expand cohorts/create activities implicitly.
- **New-tenant defaults:** rollout `10%`, maximum concurrent devices `10`, failure threshold `20%`, minimum outcome samples `1`; maintenance mode is explicitly stored as all-day or scheduled.
- Permission stays off; explicit legacy permission values are preserved. Agent Server applies tenant policy as the safety envelope for new activities.
- Atomic audit covers old/new, tenant/actor/revision, request/source/reason/result; request audit handles failures separately.

### 11.6 Installation/Trust

- Manifests no longer implicitly enable local checks/install. Propose Linux `--enable-auto-update`, Windows `-EnableAutoUpdate`; retain trust with new defaults off and preserve explicit upgrade settings.
- Installation UI adds unchecked local enablement; only selected commands opt in. Tenant permission cannot override local off; show guidance.
- Managed automatic installs require trust and signed manifest/artifacts; missing trust blocks enablement, not collection. Explicit unsigned development is never managed production; persisted trust cannot downgrade.
- Transitional Windows packages remain compatible; formal releases record publisher/signature evidence, never claim Authenticode for empty lists. Existing tools/controlled keys, no signing service/KMS.

### 11.7 Projections/Gates

Commit facts under lock before update JSONL/health `update`/metrics/heartbeat. Projection failures retry independently, not alter facts/recovery. Doctor displays switches, timestamped tenant observations, deadlines/campaign/attempt/phase/proof/material/errors with URL redaction.

| Stage | Scope | Gates |
|---|---|---|
| A | Transaction/recovery/Windows staging | Concurrent installs/confirmation/rollback, failed locks, interruptions, disabled-schedule manual updates |
| B | Health/schedule/cancellation | Zero events, stalled/stale/write errors, renewals, long spread, Retry-After |
| C | Capabilities/completion/migrations | Actual old/new/mixed fixtures, missing proof, tenant off, migration compatibility |
| D | API/UI/audit/install choices/projections | Permissions/isolation/conflicts/defaults, platform installs/UI |
| E | Trust/docs/release verification | Signature negatives, key-free artifacts, schema/doctor, systemd/SCM |

Each stage synchronizes comments/tests/guides; no weakened assertions, health, or TLS. Plans are not results; verify after implementation.

### 11.8 Confirmation Boundary

Scope is requirements `upgrade-requirements-r2` section 8. The user confirmed implementation of section 11 with rollout 10%, maximum 10 concurrent devices, and explicit maintenance windows. This change covers Agent, Agent Server schema 28, and SaaS workspace; it does not package or migrate production. Later changed Agent packages use new immutable versions; Server/Operator remain separate.

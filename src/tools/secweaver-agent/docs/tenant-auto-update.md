# Tenant Automatic-Update Gate

Agent 0.3.73 treats `auto_install` as a fail-closed local default. In managed
SLS SaaS mode (`require_server_policy=true`), installation additionally requires
the heartbeat response to contain `auto_update_allowed=true`, a signed campaign,
rollout eligibility and a live update lease. When the tenant switch is disabled,
the Agent records `tenant_auto_update_disabled` and does not download or replace
the binary.

The workspace switch is an allow gate, not a campaign publisher. Operators still
need to publish a target with Agent Server `--auto-install`; that flag is now
explicit and defaults to false. For standalone ES, set `update.auto_install=true`
only after configuring a trusted manifest/public key and an operational rollback
path. The packaged production examples leave it false.

## Update Trust Configuration (0.3.79)

Linux and Windows use the same configuration command. Generic archives do not
embed a SaaS-specific update key: production and Windows templates have
`update.enabled=false` and `auto_install=false`. A signed SaaS deployment's
published Bootstrap embeds the operator's public key and passes it through the
archive installer (`--update-public-key` / `-UpdatePublicKey`) to
`config set-update -public-key`. Private ES deployments supply their own key.
Downloading a generic archive alone does not provision SaaS update trust.

From 0.3.79, `config set-update` preserves these existing fields when their values
are omitted: `public_key`, `trusted_public_keys`, `revoked_key_ids`, `ca_file` and
`state_dir`. The state directory contains persisted rotations, revocations and
replay protection. An explicit nonempty `-public-key` replaces the primary key;
it does not clear rotation keys or revocations. Disabling updates retains trust.
An empty argument is not a request to erase trust. Invalid retained keys or a
malformed update block fail before writing the configuration.

Standalone unmanaged configurations keep HTTPS/hash compatibility. From 0.3.84,
explicit managed configuration requires a non-revoked trust key and checks its
CA file; existing old Agents can still collect normally. This fix
does not reconstruct already lost keys: binary-only automatic upgrades also keep
the existing configuration. Restore a missing key from the operator's verified
release public key or a verified backup, preserving device identity, learning
settings and update state. Do not use an untrusted manifest to establish its own
signing key or delete revocations to make an update pass.

After backing up and correcting the configuration, restart `secweaver-agent` on
Linux or `SecWeaverAgent` on Windows. Verify the configured signer's derived key
ID against the release, then check service status, running version and
`state.json` in the configured update state directory. A completed automatic
upgrade has `last_update_status=healthy`, `phase=healthy` and a confirmation time;
an active service alone does not prove the upgrade completed. Managed upgrades
still require tenant permission, a campaign and a live lease.

Regression verification: from the Agent directory run
`go test . -run TestSetUpdate`. Tests exercise the shared installer CLI with
omitted/replaced keys, disabled updates and malformed existing trust. Windows
runtime installation still requires a Windows service test; cross-compilation
does not replace that check.

0.3.84 fixes installer boolean-argument truncation and removes the default
private CA from generic templates. See [SaaS update recovery](update-recovery.md)
for explicit CA clearing, reason codes, 0.3.79 repair and legacy migration.

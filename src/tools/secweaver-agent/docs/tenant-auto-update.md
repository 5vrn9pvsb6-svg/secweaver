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

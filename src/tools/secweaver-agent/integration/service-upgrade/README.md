# Agent real-service upgrade integration tests

These tests exercise the actual service manager and Agent executable:

1. Build and install `0.3.0` (N-1).
2. Publish a locally signed healthy `0.3.1` (N) manifest.
3. Verify the production updater activates N and commits it after the health period.
4. Publish a signed `0.3.2` (N+1) built with the `integrationhealthfail` tag.
5. Verify systemd or Windows SCM restores N and returns the service to a running state.

The failure build tag is never enabled by release scripts. Both tests use an isolated service name and temporary directories. CI runs both scripts on native Ubuntu systemd and Windows SCM runners. Test manifests must include UTC RFC3339 `generated_at` and `expires_at` fields; the signer deliberately rejects timezone-free or missing timestamps so integration tests exercise the same contract as production publishing.

Linux with systemd:

```bash
sudo ./integration/service-upgrade/linux-systemd.sh
```

Windows from an elevated PowerShell session:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\integration\service-upgrade\windows-scm.ps1
```

For a real SCM service, the updater passes the registered service name to a
detached replacement helper. A scheduled update reports a successful service
stop so SCM failure recovery cannot reopen the old executable first. The helper
then exclusively waits for unlock, performs the atomic replacement, and starts
the service. Actual startup failures still use SCM recovery and rollback. Its
bounded, path-redacted phase is persisted as `replace-status.json` and printed
with service/update diagnostics before CI cleanup. The Agent waits for the
helper's first atomic status acknowledgement before reporting the planned stop;
if the helper cannot start, the current service process remains available and
the update attempt fails. A private, truncated `replace-helper.stderr` file
records PowerShell startup errors without creating a Windows service log. A
console-mode `service` command deliberately leaves the service name empty
and does not start or modify SCM services.

Set `KEEP_INTEGRATION_ARTIFACTS=1` to retain the temporary state after a run.

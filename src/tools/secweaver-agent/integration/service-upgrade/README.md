# Agent real-service upgrade integration tests

These tests exercise the actual service manager and Agent executable:

1. Build and install `0.3.0` (N-1).
2. Publish a locally signed healthy `0.3.1` (N) manifest.
3. Verify the production updater activates N and commits it after the health period.
4. Publish a signed `0.3.2` (N+1) built with the `integrationhealthfail` tag.
5. Verify systemd or Windows SCM restores N and returns the service to a running state.

The failure build tag is never enabled by release scripts. Both tests use an isolated service name and temporary directories. CI runs both scripts on native Ubuntu systemd and Windows SCM runners.

Linux with systemd:

```bash
sudo ./integration/service-upgrade/linux-systemd.sh
```

Windows from an elevated PowerShell session:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\integration\service-upgrade\windows-scm.ps1
```

Set `KEEP_INTEGRATION_ARTIFACTS=1` to retain the temporary state after a run.

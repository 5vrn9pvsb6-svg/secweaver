# Host state snapshot collection and onboarding

Introduced in `secweaver-agent 0.3.9`, the cross-platform `host-state-snapshot` module is enabled by default. One process and one JSON Lines output collect four logical assets. The package's [`VERSION`](../src/tools/secweaver-agent/VERSION) file is authoritative for the current Agent release.

## Default cadence

| Asset | `asset_type` | Default cadence | Behavior |
|---|---|---:|---|
| Listening sockets | `host_socket` | 5 minutes | Initial/full daily baseline, then TCP/UDP endpoint differences |
| Logins and identities | `host_identity` | 5 minutes | Initial baseline, then account/session differences |
| Services and scheduled tasks | `host_service` | 5 minutes | Initial baseline, then service/timer/cron/task differences |
| Kernel and container context | `host_kernel_context` | 10 minutes | Initial baseline, then module/driver/container differences |

Stateful collectors repeat a full baseline every 24 hours. Baseline events use `action=observed`; additions, changes, and removals use `created`, `modified`, and `deleted`. Changes and removals carry `previous`; login sessions also emit `login_session_started` and `login_session_ended`. Linux reads `/proc`, account files, `who`, and `systemctl`. Socket ownership scanning is capped at 100,000 file descriptors per run by default with `-max-fd-scan`. Windows uses fixed non-profile PowerShell/CIM queries and builds shared process/session/service maps once per collection. Passwords and password hashes are never collected.

## Collection behavior and default files

Collectors start 15 seconds apart in service mode to avoid an aligned startup spike. A partial or timed-out collection does not replace the previous state, so transient permission, command, or FD-budget failures cannot generate false deletion events. Event output is flushed and synchronized before state advances; unchanged state is not rewritten. Corrupt state files are quarantined with a `.corrupt-<timestamp>` suffix and rebuilt from a fresh baseline.

Linux writes `/opt/secweaver-agent/logs/host-state-snapshot.log` and persists state in `/opt/secweaver-agent/data/host-state-snapshot-state.json`. Windows uses `C:\ProgramData\SecWeaver\Agent\logs\host-state-snapshot.log` and `C:\ProgramData\SecWeaver\Agent\data\host-state-snapshot-state.json`.

## Configuration and verification

Insert this fragment under `modules` in the Agent configuration (Linux paths shown):

```json
"host-state-snapshot": {
  "enabled": true,
  "restart": "on_failure",
  "restart_delay_seconds": 5,
  "args": [
    "-socket-interval", "5m",
    "-identity-interval", "5m",
    "-service-interval", "5m",
    "-kernel-interval", "10m",
    "-full-snapshot-interval", "24h",
    "-max-fd-scan", "100000",
    "-output", "/opt/secweaver-agent/logs/host-state-snapshot.log",
    "-state", "/opt/secweaver-agent/data/host-state-snapshot-state.json"
  ]
}
```

Installation and upgrade run `secweaver-agent config ensure-host-state-snapshot`. It adds the module only when absent; it preserves custom settings and explicit disabling.

Run a one-shot check with:

```bash
SECWEAVER_ENTERPRISE_ID=YOUR_16_CHAR_ID secweaver-agent module host-state-snapshot -once -output - -state ''
```

Use one SLS `host-state` Logstore or one `secweaver-host-state-*` ES index and route logical assets by `asset_type`. Do not configure four readers for the same physical file. These periodic snapshots complement, but do not replace, real-time `host_exec`, authentication, network-flow, Windows Security/Sysmon, or container audit evidence.

## SLS and customer-managed ES

For SLS, use one `host-state` Logstore and collect JSON with Logtail. Index `asset_type`, `event_type`, `host`, `user`, `listen_port`, `service_name`, `task_name`, `module_name`, and `container_id`. Query templates filter each logical asset by `asset_type`. For a
customer-managed Elasticsearch or OpenSearch cluster, follow the read-only onboarding flow in
[`Configure Data Sources`](03-configure-data-sources.md) or start from the public ES templates in
[`dataasset/onboarding/es/`](../dataasset/onboarding/es/). The Community edition needs no separate
private asset catalog; configure the public DataAsset objects against the customer's own endpoint
and credentials.

## Limitations

- Periodic snapshots do not replace real-time execution, network-flow, or Windows Security/Sysmon events.
- Linux `who` provides current sessions, not complete authentication history; use `syslog-risk-json` for that history.
- Container context comes from cgroups and runtime service state, not Kubernetes audit or a container event stream.
- Service/task differences do not identify the modifying actor. Correlate with auditd, Windows Security/Sysmon, or `host_persistence` when attribution is needed.

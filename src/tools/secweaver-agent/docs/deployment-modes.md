# Agent deployment modes

Agent 0.3.47+ uses one binary, version and collection implementation for both
delivery channels. Packages differ by OS/architecture, not by ES/SLS backend.
The local `config.json` optionally records `deployment_mode`:

| Mode | Install entry | Delivery |
| --- | --- | --- |
| `sls_saas` | SaaS workspace / SaaS bootstrap | Logtail / LoongCollector to SLS |
| `es_private` | ES Operator enrollment / self-managed ES helper | Filebeat, native SecWeaver Shipper or Fluent Bit to ES/OpenSearch |

The server on 91 serves the SaaS channel. Its workspace downloads do not install
an ES Operator. A common control-plane address, enterprise ID or Agent version
does not identify a delivery backend.

## Installation and upgrades

SaaS bootstrap supplies `--deployment-mode sls_saas` to the Linux package installer
and `-DeploymentMode sls_saas` to the Windows service installer. ES Operator uses
`es_private`. These flags select installation ownership; they do not add a shipper
to the generic Agent archive. Linux SaaS bootstrap manages Logtail. Windows SaaS
uses the pinned Logtail installer and requires configured AliUid and a Windows
machine group; see [Windows prerequisites](windows-installation.md). Windows ES
skips Logtail automatically. The mode flag alone does not prove cloud delivery.

The generic Linux and Windows installers check the existing mode before stopping
services, changing policy or enrolling a device. A conflicting explicit mode
fails; no automatic ES/SLS conversion is available. Omitting the option preserves
the existing mode. New generic Linux/standalone installations may remain
unspecified; Windows defaults new managed installations to SaaS unless ES or
`-SkipLogtail` is specified. Windows ARM64 needs an external supported shipper.

For legacy installations, the mode command recognizes only the Agent-owned
`etc/shipper-kind=logtail` marker or `shipper/filebeat.yml`, `shipper/shipper.json`,
`shipper/fluent-bit.conf` next to the Agent root (also legacy `etc/shipper/`).
Unrelated global collector installations are not migration evidence. Conflicting
evidence fails closed; inspect leftover configuration before retrying.

```sh
secweaver-agent config set-deployment-mode \
  -config /opt/secweaver-agent/etc/config.json -mode sls_saas -check-only
secweaver-agent doctor -config /opt/secweaver-agent/etc/config.json
```

`-check-only` never creates or writes files. Without it the command atomically
persists the field with mode 0600, preserving other JSON fields. This command is
an installer operation; serialize installations and do not run it concurrently
with configuration edits. Normal binary updates retain the configuration. A
signed remote policy may omit deployment mode (the Agent preserves its local
value), but cannot set or switch it. Local mode is not a substitute for update
signatures, authorization or ingestion credentials.

Changing channels is an explicit migration: stop and back up the old installation,
preserve any investigation logs, remove old Agent-owned channel configuration,
then enroll through the destination channel. Uninstall retains configuration by
default, so uninstall alone does not reset mode. Machine-wide Logtail/Filebeat
removal remains opt-in (`--remove-logtail` / `--remove-filebeat`); mode never
authorizes deleting a collector used by another application.

## Diagnostics and verification

Doctor reports the configured mode; health records add optional
`deployment_mode`. Explicit ES mode skips SLS machine-group identity checks and
ignores unrelated Logtail. Explicit SLS mode cannot use an ES config as proof of
delivery. An existing shipper configuration is only a local configuration check;
service status and recent events in the destination cloud/cluster still require
verification. Legacy unspecified configurations retain compatibility detection.

Supported installer platforms remain Linux/systemd and Windows service hosts.
Go regression tests cover legacy inference, conflicting installs, read-only
checks and remote-policy preservation. Validate Linux shell syntax and the
Windows installer on a real Windows host before release; cross-compilation
alone does not verify PowerShell service installation.

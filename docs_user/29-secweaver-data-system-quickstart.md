# SecWeaver Data Cloud Customer Quickstart

**Languages:** English (this page) | [简体中文](29-secweaver-data-system-quickstart.zh-CN.md)

Use the enterprise workspace: query credentials are under **Agent configuration**, and collector installation is under **secweaver-agent → One-command installation**. This guide is for customers, security operators, and end users whose SecWeaver Data Cloud service is
already active. It covers only two tasks:

1. Install `secweaver-agent` on Linux or Windows hosts that need host telemetry collection.
2. Use SecWeaver Skills for data readiness checks, alert confirmation, host risk analysis, and traceability.

**Check your setup first:** skipping query credential configuration applies only when an
administrator has delivered your analysis environment, DataAssets, and query permissions.
If you download Community and run your own local intelligent agent, Agent installation does not
configure local queries. Complete [SLS Proxy local-client onboarding](30-sls-proxy-onboarding.md).
Obtain the platform login URL, account, and analysis environment entry point from your
organization's Data Cloud administrator. `https://sls-proxy.id-net.cn:30443` is a query endpoint,
not the enterprise workspace login page or automatic SaaS activation. Without an activated organization
and administrator handoff, use the public offline cases; do not guess installer URLs or tokens.

SecWeaver Data Cloud is a managed and governed security data foundation. The provider prepares SLS,
SLS Proxy, tenant isolation, field governance, query credentials, DataAssets, and release services.
Customers do not deploy these services.

> The platform operator maintains the server components. They are not included in Community, and customers do not deploy them.

SecWeaver also supports portable laptop ES, Linux server ES, and customer-managed ES. See
[the four data foundation deployment modes](36-data-foundation-deployment-modes.md) when selecting
another foundation.

## 1. End Users Perform Only Two Tasks

| Task | When | User action |
|---|---|---|
| Install the client | Host commands, authentication, persistence, process, or state telemetry is needed | Copy the one-command installer from Data Cloud and run it on the target host |
| Use Skills | An alert, host risk, data gap, or attack path needs analysis | Provide a target, precise time range, and investigation question |

If Web/gateway alerts, gateway access logs, DNS, EDR, or other sources are already connected by Data
Cloud, users do not install an Agent merely to query them. Install `secweaver-agent` only on hosts from
which host telemetry must be collected.

End users do not need to:

- Install SLS Proxy, databases, or Docker server components.
- Create SLS projects, Logstores, indexes, machine groups, Connectors, or Assets.
- Obtain or configure SLS RAM keys, Proxy keys, `enterprise_id`, AliUid, region, or Logstore values.
- Edit Bootstrap, Agent configuration, or tenant isolation conditions in queries.

## 2. Install the Client

### 2.1 Prerequisites

Confirm only these three items:

1. The enterprise has an active SecWeaver Data Cloud subscription and sufficient device capacity.
2. The target host can reach the Data Cloud HTTPS endpoint.
3. Linux users have `sudo`; Windows users use an administrator PowerShell session.

One enterprise installation command may enroll multiple authorized hosts. A separate package is not
required for each host. Do not share the command or enterprise enrollment token outside the enterprise.
Ask the platform operator to revoke and reissue it if exposure is suspected.

### 2.2 One-Command Linux Installation

1. Open the [enterprise workspace](https://sc.id-net.cn:30443/) (`https://sc.id-net.cn:30443/`) and sign in with your enterprise account.
2. Open **enterprise workspace → secweaver-agent → One-command installation**.
3. Select the enterprise and Linux target platform, then copy the displayed command. Bootstrap determines the installed version and CPU architecture.
4. Sign in to the target host over SSH and run the complete generated command.

The generated command has this form. Data Cloud fills in the real host and token:

```bash
curl -fsSL 'https://<DATA_CLOUD_HOST>:30443/secweaver-agent/install.sh' \
  | sudo bash -s -- \
      --enterprise-enrollment-token '<enterprise enrollment token>'
```

Do not add `enterprise_id`, SLS keys, AliUid, region, Logstore, or machine-group parameters. Provider
operators embed the authorization endpoint, Agent version, Logtail/LoongCollector, and shared onboarding
settings in the release artifacts.

### 2.3 One-Command Windows Installation

1. Select the Windows target platform under **enterprise workspace → secweaver-agent → One-command installation**.
2. Choose **Copy install command**.
3. Run the complete generated command in an administrator PowerShell session.

The Windows command downloads and verifies `install.ps1` and the Agent ZIP, registers the device, and
installs the `SecWeaverAgent` service. Do not use `Invoke-Expression` to run an untrusted remote script.

### 2.4 What the Installer Does

After the user runs one command, the installer automatically:

- Detects the host architecture, then downloads and verifies the corresponding Agent release.
- Generates a hardware-related `device_id` and an independent device key.
- Registers the device with the enterprise enrollment token and obtains server-confirmed ownership.
- Installs the unified Agent, collection modules, and system service.
- On Linux, installs or reuses Logtail/LoongCollector and connects it to the managed upload path.
- Starts the service, runs strict preflight checks, and reports device state to Data Cloud.
- Stores the vendor-signed update endpoint and public key; Data Cloud can roll out later versions without
  asking the user to edit configuration.

Automatic updates require both an Ed25519-signed vendor release and an enterprise policy received over
device-key authenticated heartbeats. A new binary is committed only after its modules remain healthy
during probation; startup or module-health failures restore the previous binary. Users do not run manual
upgrade commands. Give the Data Cloud `update_status` to the operator when an exception is reported.

### 2.5 Verify the Installation

First return to the Data Cloud host list and confirm:

```text
Host state = Online
Agent state = Running
Data delay = Normal
```

On Linux, optionally check:

```bash
sudo secweaver-agent preflight \
  -config /opt/secweaver-agent/etc/config.json \
  -strict

sudo systemctl status secweaver-agent
```

On Windows, optionally check:

```powershell
Get-Service SecWeaverAgent
```

The Linux Agent produces these host datasets by default:

| Data | Local file | Purpose |
|---|---|---|
| Command and connection events | `/opt/secweaver-agent/logs/audit-port-execmon.log` | Command execution, outbound connections, and file operations |
| System risk events | `/opt/secweaver-agent/logs/syslog-risk-json.log` | SSH, sudo, root sessions, and system risks |
| Persistence changes | `/opt/secweaver-agent/logs/host-persistence.log` | Changes to cron, systemd, authorized_keys, and similar mechanisms |
| Process baseline and deltas | `/opt/secweaver-agent/logs/host-process-snapshot.log` | Daily full baseline plus 10-minute starts, exits, and tracked changes |
| Host state snapshots | `/opt/secweaver-agent/logs/host-state-snapshot.log` | Ports, users, logins, and baseline host state |

The final success criterion is that new events can be queried through the corresponding Data Cloud Assets.
End users do not inspect or edit internal tenant fields.

## 3. Use Skills

### 3.1 Where to Use Them

Use natural-language Skill requests in an AI Agent that has loaded the SecWeaver project and whose
customer DataAssets and query permissions have been configured by an administrator. Supported Agent
environments include Codex, Cursor, Claude Code, and OpenClaw. The same requests can be entered in a
SecWeaver analysis page when the platform provides one.

End users do not specify Connectors, Logstores, keys, or enterprise filters. Skills fetch data through
authorized DataAssets.

### 3.2 What to Include in a Request

An effective investigation includes at least:

| Information | Example |
|---|---|
| Target | Host name, Asset ID, attacker IP, account, or alert ID |
| Precise time range | `2026-07-24 13:47:00 through 13:50:34 +08:00` |
| Question | Whether an attack succeeded, which hosts were affected, or whether lateral movement occurred |
| Known context | Exercise, change window, business purpose, or confirmed alert |

Avoid vague requests such as "check recent risks." A precise range and timezone reduce unrelated data and
make evidence easier to review.

### 3.3 Recommended Order

```text
data-source-completeness
  -> alert-confirmation or risk-identification
  -> traceability-analysis
  -> close data_gaps and reassess
```

Check whether the data is sufficient before making a judgment. Run full traceability after an attack is
confirmed or assessed as highly suspicious.

### 3.4 Ready-to-Use Requests

**Data readiness**

```text
Use the data-source-completeness Skill to determine whether the current enterprise data from
2026-07-24 13:47:00 through 13:50:34 Asia/Shanghai is sufficient to analyze host web-01.
Fetch the configured DataAssets and report available sources, gaps, blockers, and the recommended next Skill.
```

**Alert confirmation**

```text
Use the alert-confirmation Skill to analyze data related to alert ALERT-001 from
2026-07-24 13:47:00 through 13:50:34 Asia/Shanghai. Determine whether it is a false positive,
a real attack, or a successful attack. Report the evidence chain, confidence, data gaps, and response
recommendations. Do not fill missing evidence with assumptions.
```

**Host risk analysis**

```text
Use the risk-identification Skill to analyze commands, outbound connections, authentication,
persistence, processes, and host state for web-01 from 2026-07-24 13:47:00 through 13:50:34
Asia/Shanghai. Report high-risk behavior, evidence references, possible impact, and recommended actions.
```

**Attack traceability**

```text
Use the traceability-analysis Skill with attacker IP 203.0.113.10 for the period
2026-07-24 13:47:00 through 13:50:34 Asia/Shanghai. Analyze Web/gateway alerts, gateway access,
DNS, and host data to reconstruct initial access, command execution, lateral movement, impact scope,
and response recommendations. Also report uncovered sources and conclusion confidence.
```

### 3.5 Read the Result

| Output | What to review |
|---|---|
| `overall_verdict` / `alert_verdict` | Overall judgment or alert conclusion |
| `confidence` | How strongly current evidence supports the conclusion |
| `evidence_refs` | Original evidence cited by the conclusion |
| `join_edges` | How evidence from different sources was linked |
| `data_gaps` | Missing data and how each gap limits the conclusion |
| `recommended_actions` | Response, data collection, and reassessment actions |
| `next_skill` | Recommended next Skill |

A strong conclusion without `evidence_refs` should not be used directly for response. When critical
`data_gaps` remain, collect the missing data or narrow the conclusion before a security operator applies
business context and makes the final decision.

### 3.6 Offline CLI Experience

To try Skills locally, run the public examples from the repository root:

```bash
make quickstart
.venv/bin/python src/secweaver.py list

.venv/bin/python src/secweaver.py skill alert-confirmation \
  -i examples/alert-confirmation/s4-webshell-attack-success.json

.venv/bin/python src/secweaver.py skill traceability-analysis \
  -i examples/traceability/s1-web-shell-to-ssh-lateral.json
```

These commands use public offline examples and do not query customer Data Cloud. Production investigations
use an analysis environment with configured customer DataAssets and query permissions.

## 4. Customer Troubleshooting

| Symptom | Action |
|---|---|
| The install command still contains `<...>` or `YOUR_...` | Do not run it. Generate it again in Data Cloud; contact the platform operator if placeholders remain |
| Installation reports an invalid token | The token may be expired, paused, or revoked; ask the platform operator to reissue it |
| Installation reports a subscription or device-limit error | Ask the platform operator to renew the subscription or increase device capacity |
| Linux Agent is not running | Run `systemctl status secweaver-agent` and strict preflight, then send the output to the platform operator |
| Windows Agent is not running | Run `Get-Service SecWeaverAgent` and confirm installation used administrator PowerShell |
| Host is online but data is absent | Wait one collection interval; if it remains absent, check Data Cloud delay and contact the platform operator |
| A Skill reports insufficient evidence | Review `data_gaps` and run `data-source-completeness`; do not force a definitive answer |
| A Skill cannot find the target | Verify the host name, Asset ID, time range, timezone, and Data Cloud host state |

Production systems must not bypass certificate validation with `curl -k` or equivalent options. Stop the
installation and ask the platform operator to fix the trusted Data Cloud certificate.

## 5. Further Reading

- [Project Skills and usage](06-skills-and-usage.md)
- [Data source completeness](15-data-source-completeness.md)
- [Alert confirmation](17-alert-confirmation.md)
- [Traceability analysis](18-traceability-analysis.md)
- [Risk identification](19-risk-identification.md)
- [Daily operations and troubleshooting](09-operations-troubleshooting.md)
- [secweaver-agent deployment guide](../src/tools/secweaver-agent/README.md)

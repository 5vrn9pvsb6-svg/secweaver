# Lightweight Triage Policy (Open-Source Prompt Edition)

**Languages:** English (this document) | [Simplified Chinese](policy-lite.zh-CN.md)

> **Role: a reference baseline, not the only source of judgment.**
>
> This document provides shared defaults and examples. The agent acts as a
> **senior security analyst** and may deviate based on ATT&CK knowledge, hunting
> experience, and environment context, but it must explain the reason.
>
> This file does not replace close analysis and active correlation of
> `evidence_bundles`.

## 1. Default alert (`alert_required`)

Recommend an alert with P0 or P1 when any condition below is met.

### Web and application layer

- A child of an externally listening process such as nginx, php-fpm, or httpd
  executes an **interactive shell** or **system discovery**, including `id`,
  `whoami`, `cat /etc/passwd|shadow`, key discovery, or `curl|wget` downloading
  an executable.
- A **known WebShell path** such as `*.phtml`, `cmd.jsp`, or `eval(` is accessed
  and command-execution evidence exists.
- PHP restrictions such as **disable_functions** or **open_basedir** are changed
  or bypassed.

### Credentials and accounts

- `/etc/shadow` is read, SSH private keys are discovered in bulk, or `sshpass`
  or a plaintext password is used for lateral login.
- A root or sudo user is **created**, `usermod -aG wheel|sudo` runs, or a
  sensitive directory such as uploads or webroot is changed to `777` without an
  approved change-window explanation.

### Persistence and defense evasion

- `crontab -e`, a systemd unit, or `.bashrc` receives reverse-shell or download logic.
- SELinux is disabled, `auditd` or `rsyslog` is stopped, or logs/history are
  cleared with commands such as `> /var/log/` or `history -c`.

### Egress, when `host_connect` exists

- A listening process connects to an unusual external port, matches a known C2
  pattern, or connects within five minutes of a download or decode command.

### Syslog and platform alerts

- A `syslog_risk_alert` hit for a WebShell, reverse shell, successful brute
  force, or abnormal account that correlates with `host_exec` increases
  confidence. It is not P0 by itself; without exec corroboration, default to P1.

## 2. Default suppression (`suppress`)

The following signals alone normally merit suppression or P3 unless combined
with an alert condition above:

| Pattern | Explanation |
|---|---|
| Package management | `yum install` or `apt-get` from official repositories, or routine nginx/PHP installation without later WebShell activity |
| Monitoring probes | HTTP health checks from a fixed source or Zabbix/Prometheus collection |
| Log collection | `ilogtail` or `filebeat` install/configuration without abnormal egress |
| One-off SSH failure | One or two `Failed password` events with no later success |
| Declared exercise | Context identifies a drill/red-team exercise and behavior matches its plan |

Every suppression must include a **`suppress_reason`**, such as
`routine_package_install`.

## 3. Monitor

- One-off reconnaissance such as `uname -a`, `netstat`, or `ps` without access
  to sensitive files.
- New-process egress to a known SaaS API. Use CMDB context; without it, report
  medium confidence.

## 4. Correlation boost

Raise severity by one level, up to P0, when multiple signals occur together:

```text
HTTP script upload/access + nginx child shell + shadow read + sshpass lateral login
```

## 5. Environment and exercise context

- If a fixed internal IP such as `10.0.0.2` installs the environment in bulk,
  applies `chmod 777`, and disables SELinux before the attack, describe possible
  lab or exercise preparation. Do not reduce the severity of a proven WebShell
  or lateral movement solely for that reason, though it may affect response priority.

## 6. Output fields

Align with `output-schema.json`:

- `severity`: P0 | P1 | P2 | P3
- `disposition`: alert_required | suppress | monitor
- `confidence`: high | medium | low
- `evidence_refs`: at least one entry containing `asset_type`, `time`, and key fields

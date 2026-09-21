# Detection Label Catalog

**Languages:** English | [简体中文](detection-catalog.zh-CN.md)

A reference for interpreting detection output. Operators edit JSON detection rules; alert policy changes must update both `behavior-policy.md` and `rules/behavior-policy.rules.json`. Scoped environment exceptions belong in the [whitelist](whitelist.md).

## Detection output

| Field | Meaning |
|---|---|
| `matched_rules` | Detection labels listed below |
| `risk_tags` | Tactical semantics from detection rules |
| `mitre_attack` | Techniques and tactics from `rules/attck-map.json` |
| `severity` | Initial P0–P3; policy may override it |
| `risk_module` | exec / connect / dns / persistence / ssh / syslog |
| `summary`, `command`, `listener_*` | Context used by policy |
| `has_tty`, `tty` | Session context, not an independent attack verdict |

The executable policy JSON determines `alert_required`; Markdown records its rationale. These tables explain labels and initial severity. Enabled state, conditions, and thresholds come from the current JSON pack, and do not imply every matching event requires an alert.

## No-TTY context

HTTP/WebShell commands often have `has_tty=false`, `tty=(none)`, a Web listener such as nginx/php-fpm, and an unset audit login identity. Cron/MOTD can also lack a TTY. Combine command and listener evidence; no TTY alone does not confirm compromise. See the [operations handbook](OPS-HANDBOOK.md).

## exec (host_exec)

| matched_rule | Initial severity | Meaning |
|---|---|---|
| `external_listener_shell_exec` | P0 | Shell interpreter descended from a Web listener |
| `download_and_execute` | P0 | Download and execution using curl/wget |
| `reverse_shell` | P0 | Reverse-shell characteristics |
| `persistence_modify` | P0 | Persistence-related command changes |
| `security_control_tampering` | P0 | Disabling audit/firewall controls |
| `sensitive_file_read` | P1 | Reading shadow, keys, or .env |
| `internal_recon` | P1 | Reconnaissance commands or internal probing |
| `webshell_write` | P1 | WebShell write or related request characteristics |
| `network_exfil_tools` | P1 | Transfer tools such as nc/scp/rsync; not proof of successful exfiltration |
| `obfuscated_exec` | P1 | Obfuscation such as base64 decoding or eval |
| `data_staging` | P1 | Archiving data into staging locations |
| `database_dump` | P1 | Database dump in Web context |
| `noise_command` | P3 | Noise-only command |

Rule pack: `rules/exec-rules.json`.

Exec pack 1.3 refines built-in command candidates in `command_semantics.py`:
plain HTTP fetches, health probes and checksum pipes are not `download_and_execute`;
an interpreter pipe/substitution or execution of the saved download is required.
Read-only `ls`/`grep`/`crontab -l` and copying a service file **to a backup** are not
`persistence_modify`; writes **to** a persistence path remain candidates. Pure
`scp -t` and `sftp-server` receivers do not imply `network_exfil_tools`; outbound
transfers and mixed command sequences remain candidates, not proof of exfiltration.

The Python engine accepts POSIX command strings, argv lists and JSON-encoded argv,
with at most four nested shell `-c` levels. It does not execute or fully interpret
shells, expand variables, or establish a download's trustworthiness. Windows
PowerShell/cmd syntax needs separate detection rules. Other matched rules and
Web-listener guardrails still apply; this is not a domain/tool allowlist. Custom
rules using these built-in IDs on `command` share the semantic checks; other
fields retain their configured matching behavior. Verify using the regression
cases in `tests/test_detection_rules.py` and the repository Python test runner.

Native source replays are removed before risk thresholds. SSH failures with
different native IDs in the same second remain distinct; without native IDs,
the legacy host/source/time/user deduplication heuristic remains in effect.
`evidence_deduplication` reports per-bundle counts and retained/duplicate references.

## connect (host_connect)

| matched_rule | Initial severity | Meaning |
|---|---|---|
| `external_c2_connect` | P0 | Public egress from a Web listener |
| `suspicious_port_connect` | P0/P1 | Suspicious destination port |
| `exec_correlated_egress` | P1 | Nearby curl/wget command |
| `non_whitelist_egress` | P2 | Egress outside the public allowlist |
| `business_whitelist_connect` | P3 | Allowed internal business port |

Rule pack: `rules/connect-rules.json`.

## dns (dns_log + host_connect)

| matched_rule | Initial severity | Meaning |
|---|---|---|
| `high_nxdomain_burst` | P1/P2 | Many NXDOMAIN responses for one client in a short window |
| `suspected_dga_domain` | P1 | High entropy, long labels, or unusual digit ratio |
| `uncommon_tld_query` | P2 | Uncommon/high-abuse TLD |
| `dns_tunnel_suspected` | P1 | Long queries/labels or TXT/NULL/ANY tunneling characteristics |
| `doh_egress` | P1 | Connection to a known DoH resolver on 443 |
| `dot_egress` | P1 | DNS-over-TLS egress on 853 |

Rule pack: `rules/dns-rules.json`.

DNS explains domain and tunneling characteristics. Session direction, byte counts, proxy actions, and beacon timing still require firewall/NTA/proxy evidence.

## persistence (host_persistence)

| matched_rule | Initial severity | Meaning |
|---|---|---|
| `persistence_ld_preload_modify` | P0 | Change to ld.so.preload |
| `persistence_ssh_key_modify` | P0 | Change to authorized_keys |
| `persistence_sudoers_modify` | P1 | Change to sudoers or sudoers.d |
| `persistence_systemd_modify` | P1 | Systemd unit change |
| `persistence_cron_modify` | P1 | Cron/crontab change |
| `persistence_profile_modify` | P1 | Shell profile/bashrc/rc.local change |
| `persistence_kernel_module_modify` | P1 | Kernel module loading or blacklist configuration change |
| `persistence_generic_change` | P2 | Other monitored persistence path change |

Rule pack: `rules/persistence-rules.json`.

## ssh (ssh_auth)

| matched_rule | Initial severity | Meaning |
|---|---|---|
| `ssh_bruteforce` | P0 | Burst of authentication failures |

Rule pack: `rules/ssh-rules.json`.

`assess.py` explicitly passes `params.ssh_brute_threshold` (default 10) and `params.ssh_brute_window_sec` (default 300). Tune these parameters at that entry point. Direct engine calls without overrides use `brute_force.threshold` and `brute_force.window_sec` in the pack. `thresholds[]` maps failure counts to detection severity only after burst admission; `SSH-BRUTE-001` may then promote severity to P0. Review all `ssh_brute_waves`.

## syslog (syslog_risk_alert)

| matched_rule | Initial severity | Meaning |
|---|---|---|
| `account_created` | P0 | Local account creation |
| `account_modified` | P1 | Account/password change |
| `sudo_high_risk` | P1 | High/critical sudo event |
| `sudo_command` | P2 | Ordinary sudo event |
| `sudo_useradd` | P0 | useradd/adduser in message |
| `sudo_chpasswd` | P1 | chpasswd/passwd in message |
| `root_ssh_login` | P1 | Successful root SSH login |
| `root_session_opened` | P1 | Root session |
| `su_failure` | P1 | Failed su |
| `security_policy_denied` | P1 | SELinux/AppArmor denial |
| `firewall_event` | P1 | Firewall change |
| `suspicious_cron` | P1 | Suspicious cron |
| `kernel_panic` | P0 | Kernel panic |
| `network_anomaly` | P2 | Network anomaly |
| `process_crash` / `oom_kill` / `device_attached` | P2 | Host anomaly; some rules are disabled by default |

Rule pack: `rules/syslog-rules.json`.

Use `asset_type=syslog_risk_alert`; the asset ID depends on onboarding configuration. Raw SSH failure events in `exclude_event_types` are handled by SSH aggregation rather than this module.

## ATT&CK mapping

After policy evaluation, `risk_item.mitre_attack` records `technique_ids`, `techniques`, and `tactics`. Detection labels map through `attck-map.json` → `matched_rules.<id>.techniques`; policy IDs map through `policy_rules.<id>.techniques`. Add mappings for new labels/IDs without changing Python.

## Maintenance boundary

| Goal | Edit |
|---|---|
| Pattern, keyword, port, or threshold | Corresponding detection JSON |
| Alert, suppression, or platform-wide exception | Both policy Markdown and executable JSON; replay positive and negative examples |
| Scoped environment exception | Whitelist with explicit scope and guard checks |
| Cross-host narrative | Traceability Skill and shared chain patterns |

See the [detection engine reference](../../../docs_dev/18-risk-identification-engine-design.md), [policy reference](../../../docs_dev/19-behavior-policy-engine-design.md), and [operations playbooks](OPS-HANDBOOK.md). The canonical natural-language policy text is currently Chinese; the English policy reference documents the executable contract.

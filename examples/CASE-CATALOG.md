# SecWeaver Offline Case Catalog

**Languages:** English (this page) | [简体中文](CASE-CATALOG.zh-CN.md)

These synthetic inputs illustrate what each Skill can and cannot infer. Expected results come from each input's `_meta` and the current offline regression; they are not findings about a real environment. Sample addresses, hosts, timestamps and events are illustrative. Running these inputs does not connect to a production data source.

## Run the cases

From the repository root, install test dependencies with `make setup` on the first run:

```bash
# Execute all 27 assessment inputs; check verdicts, rules, Joins and output Schemas.
# Also inspect six raw log samples, WAF/host-exec normalization and prompt-report structure.
.venv/bin/python -m unittest discover -s tests -p test_skill_catalog_and_output_contracts.py -v

# Run one case directly; see the directory READMEs for other assessment scripts.
.venv/bin/python src/skills/risk-identification/scripts/assess.py \
  -i examples/risk-identification/s8-dns-dga-p1.json
```

There are **27 distinct executable assessment inputs**: eight completeness, five alert, three traceability and eleven risk cases. The 27 Showcase routes cover these inputs once each; the four Demo reports are outputs, not additional inputs. Prompt analysis also has two offline fetch results, and format discovery has six raw log samples.

## Data source completeness: 8

These cases contain registered assets, scenarios and investigation parameters, **not log events**. `full_traceable` means the preregistered sources satisfy a precheck; it does not establish that an attack happened.

| Input | Situation | Expected result and limit |
|---|---|---|
| [s1-full-traceable.json](data-source-completeness/s1-full-traceable.json) | Nine relevant asset types registered for S1 external-IP traceability | `full_traceable`; traceability may start, but it still needs actual events |
| [s1-not-traceable-missing-exec.json](data-source-completeness/s1-not-traceable-missing-exec.json) | S1 lacks critical `host_exec` needed to corroborate execution after a Web request | `not_traceable`, `next_skill_blocked=true`; reports the missing source |
| [s4-alert-triage-only.json](data-source-completeness/s4-alert-triage-only.json) | S4 has WAF and Web assets but no host evidence | `alert_triage_only`; can classify an alert but cannot confirm a breach |
| [s4-partial-missing-connect.json](data-source-completeness/s4-partial-missing-connect.json) | S4 has required sources but lacks recommended `host_connect` | `partial_traceable`; basic confirmation is possible, egress claims are limited |
| [s6-full-traceable.json](data-source-completeness/s6-full-traceable.json) | S6 authentication, post-login execution, persistence and firewall sources are registered | `full_traceable`; source readiness does not prove account compromise |
| [s6-not-traceable-missing-auth.json](data-source-completeness/s6-not-traceable-missing-auth.json) | S6 has post-login sources but no P0 authentication source | `not_traceable`, `next_skill_blocked=true`; downstream activity cannot establish which account logged in |
| [s7-full-traceable.json](data-source-completeness/s7-full-traceable.json) | S7 file, connection, DNS, traffic-volume and execution sources are registered | `full_traceable`; actual events are still required to prove exfiltration |
| [s7-partial-missing-traffic-volume.json](data-source-completeness/s7-partial-missing-traffic-volume.json) | S7 has required file and connection sources but no NTA/firewall volume source | `partial_traceable`; transfer direction and volume remain constrained |

## Alert confirmation: 5

Four inputs have one primary alert; the batch input has three. Related Web/host evidence lets the Skill evaluate attack authenticity and outcome separately. `attack_success=false` does not necessarily mean the request was benign.

| Input | Situation | Expected result and limit |
|---|---|---|
| [s4-false-positive-uuid-param.json](alert-confirmation/s4-false-positive-uuid-param.json) | A normal UUID parameter triggers a WAF rule, with no corroborating effect | `false_positive`, `not_applicable` |
| [s4-scanner-generic-no-payload.json](alert-confirmation/s4-scanner-generic-no-payload.json) | A generic scanner rule fires without a meaningful payload or host evidence | `scanning_or_probe`, `success_unknown`; neither success nor a false positive is established |
| [s4-sqli-blocked-no-breach.json](alert-confirmation/s4-sqli-blocked-no-breach.json) | WAF blocks a SQL injection attempt; host-side breach evidence is absent | `confirmed_attack`, `blocked`, `attack_success=false` |
| [s4-webshell-attack-success.json](alert-confirmation/s4-webshell-attack-success.json) | WebShell alert is corroborated by Web access, command execution, connection and file activity | `confirmed_attack`, `success_confirmed`; proceed to traceability |
| [s4-batch-mixed-with-query-gap.json](alert-confirmation/s4-batch-mixed-with-query-gap.json) | One batch contains a false positive, a scan and a blocked attack; the recorded host query fails | Exact 1/1/1 classification; `query_integrity=incomplete`, so missing host evidence cannot support a negative conclusion |

## Traceability: 3

These `evidence_bundles` combine WAF, Web, host and SSH events to exercise correlation edges. A `join_edges` entry does not mean every recommended Join succeeded. The WebShell-to-SSH Showcase observes a WebShell control point without establishing the original compromise point.

| Input | Situation | Expected result and limit |
|---|---|---|
| [s1-scan-only-no-host-exec.json](traceability/s1-scan-only-no-host-exec.json) | WAF and Web requests correlate, but there is no command execution | `scanning_or_attempt_only`; do not claim successful intrusion |
| [s1-web-shell-to-ssh-lateral.json](traceability/s1-web-shell-to-ssh-lateral.json) | Host execution, download/egress, file changes and SSH lateral evidence follow the WebShell activity | `confirmed_intrusion_chain`; `web_access_to_host_exec` and `host_to_cmdb` still have no matching Join |
| [s2-initial-access-no-lateral.json](traceability/s2-initial-access-no-lateral.json) | Web-side host execution and one failed SSH login, but no successful SSH login | `initial_access_only`; a failed SSH event may create an edge without proving lateral success |

## Risk identification: 11

These cases exercise rule matches, severity and whitelisting on **synthetic evidence**. A sample P0/P1 rule grade is not by itself an operational finding about a real host.

| Input | Situation | Expected result and limit |
|---|---|---|
| [s5-curl-download-exec-p0.json](risk-identification/s5-curl-download-exec-p0.json) | Web-service child runs `curl | bash` and opens a connection | `high_risk_detected`, at least two findings, highest P0 |
| [s5-reverse-shell-p0.json](risk-identification/s5-reverse-shell-p0.json) | Web-service shell issues a `/dev/tcp` reverse-connection command | Matches `reverse_shell`, highest P0 |
| [s5-external-connect-p0.json](risk-identification/s5-external-connect-p0.json) | A listening Web process opens connections without corresponding `host_exec` events | Matches `external_c2_connect`, highest P0; documentation-only IPs do not establish real Internet traffic |
| [s5-whoami-recon-p0.json](risk-identification/s5-whoami-recon-p0.json) | Shell child of a Web listener runs `whoami` | Matches `internal_recon` and `external_listener_shell_exec`, highest P0 because of the Web process context, not `whoami` alone |
| [s5-nginx-config-test-whitelisted.json](risk-identification/s5-nginx-config-test-whitelisted.json) | Operator runs `nginx -t` | `wl-nginx-config-test` matches, `no_risk_detected`; finding remains visible without an alert |
| [s5-ssh-bruteforce-p0.json](risk-identification/s5-ssh-bruteforce-p0.json) | Ten SSH authentication failures from the same source in a short interval | One brute-force wave, highest P0; no successful login is shown |
| [s5-ssh-nine-failures-below-threshold.json](risk-identification/s5-ssh-nine-failures-below-threshold.json) | Same conditions, but without the tenth failure | `insufficient_data`, no risk item or brute-force wave; below threshold is not proof of safety |
| [s5-persistence-authorized-keys-p0.json](risk-identification/s5-persistence-authorized-keys-p0.json) | Host changes `.ssh/authorized_keys` | Matches `persistence_ssh_key_modify`, highest P0; authorization context is needed for real triage |
| [s8-dns-dga-p1.json](risk-identification/s8-dns-dga-p1.json) | DGA-like domain query with an empty `host_connect` bundle | DNS module matches `suspected_dga_domain`, highest P1; no session or traffic-volume proof of C2 or exfiltration |
| [s6-root-ssh-login-p1.json](risk-identification/s6-root-ssh-login-p1.json) | Successful root SSH login from a documentation address | Matches `root_ssh_login`, highest P1; suspicious authentication is not proof that the account is compromised |
| [s7-data-staging-and-scp-p0.json](risk-identification/s7-data-staging-and-scp-p0.json) | A database service process stages application files, runs outbound SCP and has a same-process connection | Matches `data_staging` and `network_exfil_tools`, elevated to P0 by correlated connection context; transfer completion and byte volume remain unproven |

## Prompt analysis and evidence: 2 inputs

`prompt-risk-analysis` is a prompt-only Skill without a deterministic verdict script like the four assessment Skills. The following inputs are offline results following the `evidence-fetch` contract. Golden reports help review analysis quality but are not generated ground truth.

| File | Purpose |
|---|---|
| [fetch-exec-syslog-mini.json](prompt-risk-analysis/fetch-exec-syslog-mini.json) | Six host-exec and two system-risk events between 14:00 and 18:30. The SSH command is an attempt, while earlier events on 92 are context, not proof of lateral success; compare the [Chinese narrative report](prompt-risk-analysis/report-exec-syslog-mini.zh-CN.md) |
| [fetch-waf-bypass-mini.json](prompt-risk-analysis/fetch-waf-bypass-mini.json) | Seven deduplicated WAF/Web/host events mixing blocked, bypassed and benign traffic; compare the [schema-checked JSON report](prompt-risk-analysis/report-waf-bypass-mini.json) and [Chinese report](prompt-risk-analysis/report-waf-bypass-mini.zh-CN.md) |

The automated regression checks both fetch Schemas and the WAF JSON report Schema. It **does not check** the quality or repeatability of a model's reasoning. See the [prompt example README](prompt-risk-analysis/README.md) for the manual workflow.

## Format discovery: 6 raw logs

These `.sample` files are **raw text**, not normalized assessment input. Regression tests check format detection and preview fields. The WAF and host-exec samples also exercise normalized previews through public `discovery` assets. Applying mappings and fetching downstream evidence still need separate verification.

| File | What it exercises |
|---|---|
| [waf-jsonl.sample](log-format-discovery/waf-jsonl.sample) | WAF JSONL with `client_ip`/`remote_addr` aliases |
| [ssh-auth.log.sample](log-format-discovery/ssh-auth.log.sample) | SSH successes and failures in `auth.log` format |
| [host-exec-jsonl.sample](log-format-discovery/host-exec-jsonl.sample) | Host execution and active connection JSONL events |
| [host-exec-webshell-no-tty.sample](log-format-discovery/host-exec-webshell-no-tty.sample) | Web process command execution without TTY |
| [vendor-cloud-audit.sample](log-format-discovery/vendor-cloud-audit.sample) | Multiple cloud audit formats with noncanonical fields |
| [vendor-edr-identity.sample](log-format-discovery/vendor-edr-identity.sample) | Multiple EDR/identity formats with noncanonical fields |

The [format discovery README](log-format-discovery/README.md) runs the WAF sample with `asset-waf-api-prod`; regression also runs host execution with `asset-sls-proxy-host-exec-demo`. Other log types need an appropriate discovery asset; identifying JSONL does not prove field mapping is complete.

Regression also perturbs existing fixtures without counting them as new cases: removing WebShell host evidence must make success unknown; changing accepted SSH logins to failed or unrelated-source logins must remove confirmed lateral movement; lowering the S6 source risk removes the root-login finding; removing S7 connection context keeps both rules but lowers them from P0 to P1. The Showcase traceability route disables online IP intelligence and notifications; add `--no-ip-intel --no-notify` when invoking traceability manually with the same offline boundary.

## Showcase and output reports

The original five `offline-showcase` IDs remain available: `webshell-attack-confirmation`, `false-positive-parameter`, `webshell-to-ssh-lateral`, `reverse-shell-risk` and `missing-host-exec-data`. The catalog now also includes the remaining assessment inputs; an unqualified request runs all 27. The additional case IDs are their input filenames without `.json`. See [Showcase case IDs and commands](ai-showcase/README.md).

The four `demo-*-output.json` files under `examples/reports/` each show a complete result from an existing completeness, alert, risk or traceability input. The [report guide](reports/README.md) explains their fields. Operational/advisory Skills such as `dataasset-connectivity-check` and `dataasset-validation-advisor` have no separate JSON assessment cases here; their own workflows and repository tests cover them. The `external-listener-cmd-risk` and `external-listener-connect-risk` subskills are represented indirectly by the risk examples.

# Traceability Analysis — Cross-Source Test Data

This directory provides **offline evidence_bundles** that simulate cross-source Join chains defined in [`correlation-matrix.json`](../../dataasset/assets/correlation-matrix.json), without live fetch.

Reference: [跨源字段关联说明](../../docs_user/21-cross-source-field-correlation.md)

## Scenarios

| File | Scenario | Expected verdict | Notes |
|---|---|---|---|
| [s1-web-shell-to-ssh-lateral.json](s1-web-shell-to-ssh-lateral.json) | S1 + S2 + S3 | `confirmed_intrusion_chain` | Host behavior and SSH lateral movement; WEB-to-host Join unmatched |
| [s1-scan-only-no-host-exec.json](s1-scan-only-no-host-exec.json) | S1 negative case | `scanning_or_attempt_only` | WAF/WEB only, no host_exec |
| [s2-initial-access-no-lateral.json](s2-initial-access-no-lateral.json) | S2 | `initial_access_only` | WEB breached, no SSH Accepted |

The offline regression checks observed Join IDs as well as verdicts. These
samples do not currently match `web_access_to_host_exec` or `host_to_cmdb`;
the confirmed chain is supported by other evidence and must not be presented
as if every recommended Join had matched. An SSH failure can match a Join edge
without confirming lateral movement; rely on the verdict and edge classification.
The regression also changes accepted SSH logins to failed or unrelated-source
logins: neither change may retain confirmed lateral movement. The observed
WebShell control point is not the original compromise point, which remains
`unresolved` in this fixture.

## Cross-source Join path (example 1)

```text
203.0.113.55 (attacker_ip)
    │
    ├─ waf_alert (waf-001)          join: src_ip
    │       └─ web_access_log (web-001)     waf_to_web_access_by_ip ±10min
    ├─ host_exec (exec-001…)        web_access_to_host_exec: no_match
    │       ├─ host_connect (connect-001)   d2_exec_connect_same_listener
    │       └─ host_file_op (file-001)      d2_exec_file_same_host
    │
    └─ host_exec.host_ip 10.0.1.5
            ├─ firewall_log (fw-001)        DMZ→internal :22
            └─ ssh_auth (ssh-002, ssh-003)  host_ip_to_ssh_auth_lateral
                    → db-01, app-02
```

## Run

```bash
# Host activity and SSH lateral movement; original compromise unresolved
python3 src/skills/traceability-analysis/scripts/correlate.py \
  -i examples/traceability/s1-web-shell-to-ssh-lateral.json \
  --no-ip-intel --no-notify \
  -o /tmp/trace-s1-out.json

# Scan-only negative case
python3 src/skills/traceability-analysis/scripts/correlate.py \
  -i examples/traceability/s1-scan-only-no-host-exec.json

# Breach without lateral movement
python3 src/skills/traceability-analysis/scripts/correlate.py \
  -i examples/traceability/s2-initial-access-no-lateral.json
```

## Field conventions

- All events use **canonical** field names (`src_ip`, `host`, `timestamp`), consistent with post-fetch normalization
- `host_exec` includes `host_ip`, `listener_pid`, `listener_port` for D2 intra-host correlation and lateral Joins
- `evidence_id` maps one-to-one to `evidence_refs` in `correlate.py` output

## Maintenance

When adding a scenario:

1. Design the timeline and Join keys per `correlation-matrix.json` → `anchor_patterns`
2. Run `correlate.py` to verify `overall_verdict` and `attack_chain`
3. Add a scenario row in this README and the parent [examples/README.md](../README.md)

# Risk Identification — Test Data

Offline `evidence_bundles` for validating S5/S6/S7/S8 host, account, transfer, SSH, persistence and DNS risk grading and whitelisting.

## Scenarios

| File | Scenario | Expected overall_verdict | Notes |
|---|---|---|---|
| [s5-curl-download-exec-p0.json](s5-curl-download-exec-p0.json) | curl\|bash download-and-execute | `high_risk_detected` | P0 exec + connect |
| [s5-reverse-shell-p0.json](s5-reverse-shell-p0.json) | Reverse shell | `high_risk_detected` | `/dev/tcp` signature |
| [s5-external-connect-p0.json](s5-external-connect-p0.json) | Web listener connects to a synthetic documentation address | `high_risk_detected` | `external_c2_connect`; not proof of actual Internet traffic |
| [s5-whoami-recon-p0.json](s5-whoami-recon-p0.json) | whoami reconnaissance | `high_risk_detected` | Includes `internal_recon` rule |
| [s5-nginx-config-test-whitelisted.json](s5-nginx-config-test-whitelisted.json) | nginx -t ops task | `no_risk_detected` | Whitelist `wl-nginx-config-test`, finding retained without alert |
| [s5-ssh-bruteforce-p0.json](s5-ssh-bruteforce-p0.json) | 10 SSH failures from one source | `high_risk_detected` | One P0 brute-force wave |
| [s5-ssh-nine-failures-below-threshold.json](s5-ssh-nine-failures-below-threshold.json) | Same source and window, only 9 failures | `insufficient_data` | Zero risk items or brute-force waves; below the current 10-failure threshold, not proof of safety |
| [s5-persistence-authorized-keys-p0.json](s5-persistence-authorized-keys-p0.json) | Authorized keys modified | `high_risk_detected` | P0 persistence change |
| [s8-dns-dga-p1.json](s8-dns-dga-p1.json) | Suspicious DNS query without matching connection | `high_risk_detected` | P1 DNS profile; no network-session proof |
| [s6-root-ssh-login-p1.json](s6-root-ssh-login-p1.json) | Successful external root SSH login | `high_risk_detected` | P1 candidate; not proof of account compromise |
| [s7-data-staging-and-scp-p0.json](s7-data-staging-and-scp-p0.json) | Staging plus outbound SCP and connection | `high_risk_detected` | P0 after context boost; transfer completion unproven |

## Run

```bash
python3 src/skills/risk-identification/scripts/assess.py \
  -i examples/risk-identification/s5-curl-download-exec-p0.json

# Run all eleven fixtures and verify their expected rules and output Schema.
.venv/bin/python -m unittest discover -s tests -p test_skill_catalog_and_output_contracts.py -v
```

The regression checks that the 9- and 10-failure fixtures differ by just one
event. If the SSH threshold changes, update both inputs and expectations together.

Whitelist config: `src/skills/risk-identification/whitelist.json`

## Related

- Skill: `src/skills/risk-identification/SKILL.md`
- Sub-modules: exec / connect rules in `external-listener-cmd-risk`, `external-listener-connect-risk`

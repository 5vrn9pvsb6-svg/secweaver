# Active Outbound Risk Identification Rules

> Risk identification sub-module: host_connect / active_connect  
> Orchestration: `risk-identification/scripts/assess.py` → `connect_rules.py`

Generic download-correlated or non-allowlisted egress carries `network_activity`, not proof of exfiltration. These rules have no automatic T1048.003 mapping; severity and review actions are unchanged.

## P0

| Rule | Condition |
|---|---|
| `external_c2_connect` | Web listener (443/80/8080 or nginx/php-fpm) egress to **public** IP |
| `suspicious_port_connect` | dst port ∈ {4444, 5555, 1337, 31337, 9001, 6666, 1234} |

## P1

| Rule | Condition |
|---|---|
| `exec_correlated_egress` | exec with curl/wget/fetch within ±5min |
| `suspicious_port_connect` | Suspicious port egress outside Web listener context |

## P2

| Rule | Condition |
|---|---|
| `non_whitelist_egress` | Public egress, no P0/P1 hit |

## P3 / whitelist

| Rule | Condition |
|---|---|
| `business_whitelist_connect` | dst IP in internal CIDR and common business ports (3306/6379/443/80, etc.) |

## Whitelist

Public business egress, known trusted APIs, etc. are not hard-coded in connect rules. Maintain unified whitelist:

- `src/skills/risk-identification/whitelist.json`
- Docs: [../risk-identification/whitelist.md](../risk-identification/whitelist.md)

Example rule `wl-connect-trusted-public-api` may allow specified public CIDRs via `dst_cidrs`.

## Output alert_type

`high_risk_connect`

# Traceability Analysis — Correlation and Verdict Rules

> Attack chain narratives: [risk-identification/rules/chain-patterns.json](../risk-identification/rules/chain-patterns.json) (shared with risk-identification).  
> Heuristic thresholds: [heuristic-rules.json](heuristic-rules.json); operations guide: [heuristic-rules.md](heuristic-rules.md).
> Deprecated: [attack-patterns.json](attack-patterns.json) (stub only).  
> Deterministic correlation: [scripts/correlate.py](scripts/correlate.py)

## 1. Preconditions gate

| Condition | Action |
|---|---|
| `completeness_precheck.next_skill_blocked = true` | Output `insufficient_evidence`; no confirmed chain |
| `overall_verdict = not_traceable` | Same |
| No `completeness_precheck` | May analyze but `confidence_ceiling ≤ 0.7`; Markdown label “no completeness precheck” |

---

## 2. Correlation join rules

| Join | Keys | Time window |
|---|---|---|
| WAF → initial_access | `src_ip = attacker_ip` | `[time_start, time_end]` |
| WAF → exec | same `host` | anchor ± 15min |
| exec → connect | same `host` | ± 2min |
| exec → file_op | same `host` | ± 5min |
| Entry host → SSH | `ssh_auth.src_ip = host_ips[entry_host]` | ≥ anchor |
| SSH lateral BFS | new victim host IP becomes next-hop src | iterate to max_hops=10 |
| firewall assist | `src_ip→dst_ip:22` same window as SSH Accepted | ± 10min |

---

## 3. Attack stage mapping

| asset_type | Event signature | stage |
|---|---|---|
| waf_alert | URL with webshell signature | initial_access |
| web_access_log | attack IP + suspicious URL | initial_access |
| host_exec | bash/sh/curl/wget | execution |
| host_connect | external 80/443/non-standard port | execution or command_and_control |
| host_file_op | create under /tmp, /var/www | persistence or execution |
| host_persistence | cron/systemd/authorized_keys/sudoers change | persistence |
| ssh_auth Accepted | internal src → new host | lateral_movement |
| ssh_auth many Failed | same src consecutive failures | suspected_lateral |
| firewall_log | internal :22 connection | lateral_movement (assist) |

### WebShell URL signatures

`shell`, `webshell`, `cmd=`, `eval(`, `upload`, `.php`, `.jsp`, `.asp`, `backdoor`

### Download/execute signatures

`curl`, `wget`, `fetch`, `| bash`, `| sh`, `chmod +x`

### Lateral tool signatures

`hydra`, `ncrack`, `medusa`, `sshpass`, `patator`

---

## 4. Lateral movement three-tier classification

| lateral_class | Condition | Output wording |
|---|---|---|
| `confirmed_lateral` | SSH Accepted + explainable source IP | “Lateral to {host}” |
| `suspected_lateral` | Many Failed or firewall :22 without Accepted | “Suspected lateral attempt to {host}” |
| `unknown` | SSH coverage partial | “At least lateral to …; **may be incomplete**” |

---

## 5. overall_verdict determination

```text
IF blocked OR no initial AND no execution:
  verdict = insufficient_evidence

ELSE IF initial without execution AND no host_exec bundle:
  verdict = scanning_or_attempt_only

ELSE IF initial + execution + lateral confirmed:
  verdict = confirmed_intrusion_chain
  requires: host_exec evidence exists

ELSE IF initial + execution without lateral:
  verdict = initial_access_only

ELSE IF initial OR execution:
  verdict = likely_intrusion_chain

ELSE:
  verdict = insufficient_evidence
```

### Hard constraints

- No `host_exec` → no `confirmed_intrusion_chain`
- No SSH Accepted → no confirmed lateral (max likely / initial_access_only)
- Every `attack_chain` entry must have `evidence_refs` present in `evidence_index`

---

## 6. Confidence

```text
confidence_ceiling = completeness_precheck.confidence (default 1.0)
Per stage:
  initial_access + WAF payload/url: 0.90
  execution + connect correlated: 0.95
  execution exec only: 0.85
  lateral + firewall corroboration: 0.88
  lateral ssh Accepted only: 0.82
  suspected_lateral: ≤ 0.55

overall = min(ceiling, avg(attack_chain.confidence))
```

SSH partial coverage → impacted_assets.note required; summary uses “at least lateral to”

---

## 7. hypotheses vs attack_chain

| Write to attack_chain | Write to hypotheses |
|---|---|
| Has direct evidence_ref | No direct evidence; indirect inference only |
| SSH Accepted | WAF only, no exec |
| exec + connect same window | exec but no SSH Accepted |
| — | Many SSH Failed, no Accepted |

---

## 8. BFS lateral pseudocode

```text
seeds = [initial_access.host]
visited = set(seeds)
queue = [(h, depth=0) for h in seeds]

while queue and depth < 10:
  current = pop
  current_ip = host_ips[current]
  for ssh in ssh_auth where src_ip in (current_ip, current):
    if result == Accepted:
      add lateral node(current → target)
      if target not in visited:
        visited.add(target); push(target)
  if failed_count >= 5 and no Accepted:
    add suspected_lateral for current
```

---

## 9. Recommended action templates

| verdict | recommended_actions |
|---|---|
| confirmed / likely | Isolate initial_compromise; investigate lateral_target; preserve logs; reset accounts/keys |
| initial_access_only | Isolate WEB host; check for remaining WebShell; strengthen WAF |
| scanning_or_attempt_only | Block IP; monitor; no host isolation |
| insufficient_evidence | Onboard data sources; rerun completeness analysis |

---

## 10. public S1/S3 traceability scenarios acceptance checklist

- [ ] initial_access.host = web-01
- [ ] Timeline: WebShell → curl → SSH Accepted
- [ ] Lateral includes db-01, app-02
- [ ] lateral_movement_graph renderable
- [ ] partial SSH uses “at least” and “may be incomplete”

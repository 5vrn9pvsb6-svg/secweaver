# Prompt Risk Analysis Examples

**Languages:** English (this document) | [Simplified Chinese](examples.zh-CN.md)

This workflow continues from [evidence-fetch examples](../evidence-fetch/examples.md):
**fetch evidence first, then let a senior-expert agent analyze it**. This Skill
contains no Python analysis engine.

## 0. Offline golden path (no Vault required)

```text
examples/prompt-risk-analysis/fetch-exec-syslog-mini.json
examples/prompt-risk-analysis/report-exec-syslog-mini.zh-CN.md  <- narrative reference

examples/prompt-risk-analysis/fetch-waf-bypass-mini.json
examples/prompt-risk-analysis/report-waf-bypass-mini.json       <- strict schema reference
examples/prompt-risk-analysis/report-waf-bypass-mini.zh-CN.md   <- WAF bypass narrative reference
```

Agent workflow:

1. Read `PROMPT.md`, `analysis-contract.md`, and `correlation-cheatsheet.md`.
2. Analyze `evidence_bundles` in a mini fetch fixture.
3. Verify the report includes **attack_status**, **chain_coverage**,
   **evidence_id**, **join_refs**, and **fetch_next**. S4 reports must also
   include **waf_coverage**.

See [the prompt-risk-analysis fixture guide](../../../examples/prompt-risk-analysis/README.md).

## 1. Host exec and syslog (live fetch)

```bash
python3 src/skills/evidence-fetch/scripts/fetch_evidence.py \
  --from-bundle \
  --asset-id asset-secweaver-host-exec \
  --asset-id asset-secweaver-sys-risk-alert \
  --params '{
    "hosts": ["192.0.2.91", "192.0.2.92"],
    "time_start": "2026-06-20T00:00:00+08:00",
    "time_end": "2026-07-03T23:59:59+08:00"
  }' \
  -o /tmp/fetch-exec-syslog.json
```

The agent then:

1. Reads `PROMPT.md`, **`analysis-contract.md`**, and `correlation-cheatsheet.md`.
2. Analyzes `evidence_bundles` in `/tmp/fetch-exec-syslog.json`; `policy-lite.md`
   is optional guidance.
3. Samples large event sets and records **chain_coverage**, **join_refs**, and
   **fetch_next**.
4. Produces a Markdown report and optional JSON conforming to `output-schema.json`.

## 2. Offline input from any fetch result

Use any fetch JSON that contains `evidence_bundles`. Every conclusion must cite
evidence.

## 3. Agent pseudocode

```text
1. Run evidence-fetch (or load fetch JSON / a mini offline fixture)
2. Read PROMPT.md + analysis-contract.md + correlation-cheatsheet.md
3. Analyze evidence_bundles (policy-lite is reference only)
4. Report attack_status + chain_coverage + evidence_id + join_refs + fetch_next
   and an evidence-backed attack narrative
```

## 4. Sampling high-volume results

When `fetch_summary.total_events` is large:

- constrain the review to `params.hosts` and the requested time window;
- prioritize web-process shells, shadow-file access, `sshpass`, and
  `account_created` events;
- state the scope, for example: `N events fetched; M reviewed in depth`, and explain why.

## 5. Example report statements

- **P0:** nginx:80 child process reads shadow (T1505.003 / T1003.008);
  `join_refs` may be empty or cite the same-host exec relationship.
- **P0:** nginx executes `sshpass` against host 92 and reads shadow remotely;
  `join_refs`: `lateral_from_exec`, window `lateral_movement`.
- **fetch_next:** fetch `host_connect` with join
  `d2_exec_connect_same_listener` and bundle `bundle-host-risk-default`.

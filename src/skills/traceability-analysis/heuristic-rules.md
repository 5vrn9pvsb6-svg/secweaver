# Traceability `heuristic-rules` Operations Guide

**Languages:** English (this document) | [Simplified Chinese](heuristic-rules.zh-CN.md)

> File: [heuristic-rules.json](heuristic-rules.json)
>
> Loader: `scripts/heuristic_rules.py`
>
> Full configuration inventory and workflow:
> [Traceability Operations Configuration Guide](../../../docs_user/25-traceability-analysis-ops-config-guide.md)

## Purpose

`heuristic-rules.json` moves TigerSec-specific heuristics out of Python. It
covers syslog lateral evidence, risky target-host exec corroboration, exec-based
lateral inference, `has_tty` confidence, and confidence adjustments. Routine
operations changes should edit this JSON and do not require a code release.

Cross-source joins and all **minute-based time-window values** belong to
[correlation-matrix.json](../../../dataasset/assets/correlation-matrix.json) under
`time_windows`. A heuristic block may only specify **`time_window`**, referencing
a matrix window ID such as the default `lateral_movement`. Do not add
`window_before_min`, `window_after_min`, or `lookback_before_anchor_min` here.

## Common changes

| Requirement | Configuration |
|---|---|
| Raise or lower the `likely_lateral` threshold | `target_exec_lateral.min_high_risk_events` and `min_risk_categories` |
| Expand or shrink a heuristic corroboration window | `correlation-matrix.json` -> `time_windows.lateral_movement` (`before_minutes` / `after_minutes`) |
| Use another matrix window | Set the block's `time_window`, for example `attack_success`; the ID must exist in the matrix |
| Add a high-risk command pattern | Add `{id, pattern, category, flags, enabled}` to `target_exec_lateral.high_risk_exec_rules[]` |
| Define successful-login syslog events | `ssh_auth_result.syslog_success_event_types` |
| Set confirmed syslog lateral confidence | `syslog_lateral.confirmed_lateral.confidence` |
| Set exec-inferred lateral confidence | `lateral_from_exec.confidence` |
| Set WebShell noninteractive entry confidence | `initial_access_exec_inferred.confidence_non_interactive` |
| Change the overall `+0.03` boost | `confidence_adjustments.likely_lateral_boost` |
| Temporarily disable a heuristic | Set its `enabled` field to `false` |
| Change BFS hops or SSH lateral confidence | `policy.bfs_lateral` |
| Change verdict tiers | `policy.verdict_rules` |
| Change execution-chain corroboration seconds | `policy.execution_chain`; its minute window references matrix `host_behavior_chain` |
| Change SSH listener or web ports | `policy.listener`; web process names come from `exec-rules.json` `web_listeners` |

## Example: make target-host corroboration more sensitive

Update these fields inside the existing `target_exec_lateral` object and keep
the other configuration:

```json
{ "min_high_risk_events": 2, "min_risk_categories": 1 }
```

## Example: add a transfer-behavior candidate

```json
{
  "id": "network-transfer-scp",
  "pattern": "\\bscp\\b.*@",
  "category": "network_activity",
  "flags": "i",
  "enabled": true
}
```

`scp` can be a normal upload, download, or internal operations command. This
example demonstrates pattern configuration and does not prove exfiltration.
Do not add such a broad expression directly to production high-risk
corroboration. Narrow it using actual destination, direction, data, and context,
and test normal-transfer negative cases before enabling it.

## Validation

```bash
.venv/bin/python src/skills/traceability-analysis/scripts/tests/test_heuristic_rules.py
.venv/bin/python src/skills/traceability-analysis/scripts/correlate.py --no-notify \
  -i examples/traceability/s1-web-shell-to-ssh-lateral.json -o /tmp/trace-test.json
```

Run these offline commands from the repository root. After changing the
heuristic JSON, rerun `correlate.py` to verify the analysis result.
`evidence-fetch` only collects data and cannot validate heuristic verdicts. Keep
both positive and negative fixtures for new rules; Python changes are normally
unnecessary.

## Time-window reference (the matrix owns minute values)

| Matrix ID | Default before/after | Use |
|---|---|---|
| `lateral_movement` | 30m / 120m | syslog, target exec, and lateral-from-exec |
| `host_behavior_chain` | 5m / 5m | `policy.execution_chain` anchor lookback |
| `attack_success` | 5m / 30m | second-layer alert-confirmation behavior |

Second-level corroboration remains in
`policy.execution_chain.connect_near_seconds`, `file_op_near_seconds`, and
`policy.bfs_lateral.firewall_near_seconds`.

## Relationship to `rules.md`

- `rules.md` explains verdict logic for human readers.
- `heuristic-rules.json` is the engine-executed threshold and pattern source.

Keep them synchronized. The JSON is authoritative for runtime behavior.

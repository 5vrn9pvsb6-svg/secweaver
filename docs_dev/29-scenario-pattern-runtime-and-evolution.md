# Scenario Pattern Runtime and Evolution

**Languages:** English (this page) | [简体中文](29-scenario-pattern-runtime-and-evolution.zh-CN.md)

This reference is for DataAsset, correlation, and Skill maintainers. It records the
Scenario Pattern runtime, configuration synchronization boundaries, and supported
extension direction. Security operators should start with the
[Scenario Patterns user guide](../docs_user/22-scenario-patterns.md).

This document is not a release acceptance record. Current behavior comes from code,
`dataasset/scenarios/anchor-patterns.json`, and completeness scenario definitions.
Run the validation commands at the end after any change.

## 1. Runtime Implementation Map

| Capability | Implementation entry | Behavior |
|---|---|---|
| Pattern configuration | `dataasset/scenarios/anchor-patterns.json` | Stores anchors, windows, Bundles, and Join chains separately |
| Pattern loading | `load_anchor_patterns()` | Loads the normalized Pattern registry |
| Scenario selection | `anchor_pattern_for_scenarios()` | Selects a Pattern using scenarios and `scenario_priority` |
| Parameter resolution | `resolve_anchor_params()` | Fills missing time parameters from the anchor and investigation window |
| Fetch planning | `plan_fetch()` | Builds `correlation_fetch_plan` from the Bundle and Join `fetch_plan` entries |
| Plan execution | `fetch_scenario_evidence()` / `fetch_correlation_plan_evidence()` | Fetches by plan; permits a bounded Bundle fallback when no usable plan exists |
| Join execution | `run_recommended_chain()` / `correlate_bundles()` | Runs `recommended_chain` and emits `join_edges` and `data_gaps` |
| Static validation | `src/dataasset/validate.py` | Validates schema, Joins, windows, Bundles, and asset coverage |

The runtime does not ask a model to invent Joins. A Pattern references only registered,
auditable Joins from `correlation-matrix.json`.

## 2. Current Scenario Coverage

| Scenario | Pattern ID | Anchors | Recommended assets | Default Bundle |
|---|---|---|---|---|
| S3 lateral movement | `S3_lateral_movement` | `host_ip` / `user` / `src_ip` | `ssh_auth`, `firewall_log`, `host_exec`, `asset_inventory` | `bundle-incident-trace-default` |
| S6 account compromise | `S6_account_compromise` | `user` + `src_ip` | `ssh_auth`, `host_exec` | `bundle-incident-trace-default` |
| S7 data exfiltration | `S7_data_exfiltration` | `host` / `dst_ip` / `domain` | `host_connect`, `dns_log`, `network_traffic_audit`, `db_audit` | `bundle-data-exfiltration-default` |

S3 and S6 reuse the default traceability Bundle to avoid duplicate configuration for
the same SSH/host evidence chain. S7 uses a dedicated Bundle because it depends on DNS,
full-traffic, and database-audit D4/D7 sources. Configuration presence does not prove
source readiness; each Connector still requires a successful live-query acceptance test.

## 3. Schema and Reference Validation

[anchor-patterns.schema.json](../dataasset/schema/anchor-patterns.schema.json) requires
top-level `version` and `patterns`. Every Pattern requires `label`, a nonempty
`recommended_chain`, and `bundle_id`; the schema also constrains `anchor`,
`scenario_priority`, and related fields.

Validation also checks that:

- Join IDs exist in the internal or cross-source Join registry.
- `bundle_id` exists and covers asset types required by the Join chain.
- Composite Join expansion remains covered by the Bundle.
- Anchor fields, anchor sources, and layer asset types follow registered contracts.
- The Bundle covers `fallback_asset_types`.
- Pattern scenarios agree with the Bundle's `investigation_scenarios`.

## 4. Completeness Synchronization Boundary

Completeness supports S1-S8 and uses `anchor_pattern_for_scenarios()` plus
`resolve_anchor_params()` to select a Pattern and fill parameters. P0/P1/P2 source
requirements still come from `src/skills/data-source-completeness/scenarios.json`;
they are not derived automatically from every `recommended_chain`.

When changing a Pattern's Join chain, also verify:

1. The completeness scenario requires any newly introduced evidence type.
2. The Bundle contains assets needed by the Join chain and fallback.
3. Query templates bound time, host, tenant, and result count.
4. Positive, negative, and missing-data cases still produce the expected verdicts.

## 5. Fallback and Resource Boundaries

`plan_fetch()` depends on each Join's `fetch_plan`. Missing or incomplete plans may
trigger Bundle fetching. This fallback preserves compatibility; it does not relax
authorization or resource limits. Prefer a bounded `fetch_plan` for every new or changed
Join and verify its time range, limit, and asset scope.

Some `anchor` fields remain semantic configuration rather than automatic extraction
inputs. Complex lateral BFS is also not fully matrix-driven, and a few alert-confirmation
paths retain fixed Join calls. Extensions should converge on Pattern APIs while preserving
old inputs and offline-case compatibility.

## 6. Report Evidence Contract

Key conclusions should reference `join_edges`, while incomplete paths remain in
`data_gaps`:

```json
{
  "conclusion": "The attack may have breached the web host",
  "supporting_join_edges": [
    "waf_to_web_access_by_ip:waf-001->web-001",
    "web_access_to_host_exec:web-001->exec-001"
  ],
  "remaining_data_gaps": [
    "no_match:d2_exec_connect_same_listener"
  ]
}
```

An intelligent agent may explain evidence, but it must not turn a missing Join or an
event that was not returned into a fact.

## 7. Evolution Direction

- Generate candidate completeness diffs from Join chains, then require maintainer review before updating scenario definitions.
- Move complex lateral expansion and remaining fixed alert-confirmation Joins onto Pattern APIs.
- Expand automatic anchor extraction while keeping explicit parameter precedence and auditable provenance.

These are extension directions, not current release commitments. Mark them supported only
after code, configuration, bilingual documentation, and regression tests are complete.

## 8. Validation

Run from the repository root:

```bash
make validate
.venv/bin/python -m unittest discover -s src/skills/_shared/data-access/tests -p 'test_correlation*.py' -v
.venv/bin/python -m unittest discover -s src/skills/traceability-analysis/scripts/tests -p 'test_correlation_trace.py' -v
make docs-check
```

If test module names change, use the current tests covering `anchor_patterns`,
`scenario_fetch`, and correlation, then update both language versions of this document.

**Language:** English (this page) | [简体中文](16-traceability-analysis-architecture-evaluation.zh-CN.md)

# traceability-analysis Skill — Architecture Evaluation

Current implementation note (2026-09-16): the report below preserves its dated
evaluation. `bundle-trace-oss-demo` is historical and is not shipped; the current
default is `bundle-incident-trace-default`. Input adapters and shared Skill calls
now live in [_shared/skill_runtime](../../src/skills/_shared/skill_runtime/README.md),
while scenario evidence planning/fetching lives in `data-access/scenario_fetch.py`.
Historical `skill_input.py` imports remain compatible.

> **Scope:** `src/skills/traceability-analysis/` and shared data-access layer
> **Related:** [Traceability skill design](../15-traceability-analysis-skill-design.md) | [Correlation matrix evaluation](22-correlation-matrix-design-evaluation.md)
> **Date:** 2026-07-02
> **Historical status (v1.1):** Traceability unit tests entered `tests/run_tests.py` (CI `make test`); the then-used OSS and operations bundles were separated; `scenario_priority` moved to anchor-patterns; join→stage moved to `trace_stage_map` + `get_join_trace_stage()`; attack narratives moved to `chain-patterns.json` (`attack-patterns.json` deprecated); source adapters and `heuristic-rules.json` were introduced. The historical OSS bundle is no longer shipped.
> **Public operations workflow:** [Traceability Operations Configuration Guide](../../docs_user/25-traceability-analysis-ops-config-guide.md)

---

## Executive summary

| Dimension | Rating | Summary |
|-----------|--------|---------|
| **Architecture clarity** | ★★★★☆ | Matrix-first three-layer pipeline with auditable `correlation_source` |
| **Extensibility** | ★★★☆☆ | Joins/scenarios easy; BFS/verdict thresholds still code-bound |
| **Flexibility** | ★★★★☆ | Strong multi-mode + gap-fill heuristics; partial threshold tuning via JSON |
| **Ops / OSS separation** | ★★★★☆ | Public hosts and fixtures are synthetic; credentials and environment overlays stay outside the Community archive |
| **Testability / CI** | ★★★★☆ | Traceability tests in unified CI; BFS/verdict edge cases still thin |
| **Cross-skill collaboration** | ★★★★☆ | Hard completeness gate; soft risk handoff |

**Overall:** Matrix contract and layering are sound. Config-driven paths (matrix, heuristic-rules, chain-patterns) coexist with hardcoded orchestration (BFS, verdict, execution-chain windows). The synthetic two-host scenario validates heuristic gap-fill.

---

## 1. Architecture overview

### 1.1 Three-layer pipeline

```text
L0 Orchestration / fetch (skill_input.py)
L1 Correlation contract (correlation_trace.py + correlation_engine.py)
L2 Narrative / gap-fill (traceability_analysis/* + host_normalize.py + source_adapters/)
```

### 1.2 Key modules

| Path | Role |
|------|------|
| `scripts/correlate.py` | Thin CLI entrypoint and compatibility exports |
| `scripts/traceability_analysis/engine.py` | Orchestrator: gate → normalize → matrix → heuristic → verdict JSON |
| `scripts/traceability_analysis/initial_access.py` | Initial access and victim reverse lookup |
| `scripts/traceability_analysis/execution.py` | Host execution-chain stages |
| `scripts/traceability_analysis/lateral.py` | SSH lateral detection and BFS graph |
| `scripts/traceability_analysis/result.py` | Gate, verdict, confidence, blocked result, report wrapper |
| `scripts/correlation_trace.py` | Trace contract, join→stage |
| `scripts/host_normalize.py` | Host identity normalization, host registry injection, and SSH parsing |
| `../_shared/data-access/correlation_engine.py` | Shared matrix join engine |
| `../_shared/data-access/scenario_fetch.py` | Scenario evidence planning and fetch orchestration |
| `risk-identification/rules/chain-patterns.json` | Attack narratives, `matched_pattern` |
| `heuristic-rules.json` | TigerSec heuristic thresholds |
| `correlation-matrix.json` | Joins, `trace_stage_map`, time windows |
| ~~`attack-patterns.json`~~ | **Deprecated** stub |

---

## 2. Extensibility

### 2.1 Data-driven (low cost)

- New joins in `correlation-matrix.json` + `trace_stage_map` or `join.trace_stage`
- Scenarios in `anchor-patterns.json` (`scenario_priority` is single source)
- Heuristic tuning in `heuristic-rules.json`
- Attack narratives in `chain-patterns.json` (shared with risk-identification)

### 2.2 Code-bound (higher cost)

- **Join→stage:** matrix-driven via `get_join_trace_stage()`; heuristic-only joins need `lateral_join_ids` in heuristic-rules
- **BFS lateral / verdict / execution-chain windows:** still Python-owned, now split across `traceability_analysis/lateral.py`, `result.py`, and `execution.py` (see ops config doc §5.1)
- **`risk_rules_bridge`:** literal fallbacks for some `required_rules` matching

**Rating:** ★★★☆☆

---

## 3. Flexibility

### 3.1 Runtime modes

| Mode | Support and boundary |
|---|---|
| Offline JSON | `correlate.py -i input.json` |
| Bundle fetch | `--from-bundle --fetch` runs completeness precheck and matrix-driven fetch |
| Completeness override | `--skip-completeness` continues with a confidence cap |
| Anchor override | `--anchor-pattern` selects the scenario contract explicitly |
| Fetch dry run | Produces the fetch plan without querying a backend |
| Upstream handoff | Accepts normalized `evidence_bundles` directly |
| risk-identification handoff | Documented payload boundary; no code-level pipeline dependency |

### 3.2 Matrix and heuristic paths

Matrix matches carry `correlation_source: matrix`. When source coverage is incomplete, bounded heuristics can add `exec_inferred`, `heuristic_fallback`, or BFS-derived evidence; combined stages retain both sources. The synthetic two-host scenario demonstrates why this fallback is useful when WAF or Web evidence is unavailable. Confidence rules and fallback IDs are configured in `heuristic-rules.json`, while matrix and anchor time windows remain data-driven.

The output is structured JSON with join coverage, the resolved contract, hypotheses, and classified lateral findings. Repository-owned anchor and matrix paths in `correlation_contract` are repository-relative so published reports remain portable. Markdown narrative is generated through the Skill report contract; `correlate.py` does not currently have a standalone Markdown mode.

---

## 4. Operations and Community boundary

The Skill consumes normalized `evidence_bundles` and must not read secrets. The Community tree contains the engine, matrix, anchors, synthetic host definitions, and synthetic fixtures. Operators provide Connectors, credential references, customer Assets, host overlays, and environment-specific bundles in their selected private asset root.

`inject_registered_hosts()` loads active host definitions and filters them to the investigation scope before creating `asset_inventory`. Public host records therefore use documentation ranges and demo identities; real inventories belong in a private overlay and must not enter a Community release.

The current default bundle is `bundle-incident-trace-default`. The historical `bundle-trace-oss-demo` name may appear in dated discussion only and is not a file shipped by the current repository.

---

## 5. Boundaries with other Skills

| Relationship | Contract |
|---|---|
| data-source-completeness → traceability | Hard gate through `gate_precheck` |
| alert-confirmation → traceability | Confirmed, successful evidence can become an investigation anchor |
| risk-identification → traceability | Soft handoff through normalized evidence; no direct import |
| Shared correlation matrix | Platform contract reused by alert, risk, and trace Skills |

Traceability reconstructs evidence and gaps. It does not replace alert truth assessment or the risk policy decision.

---

## 6. Testing

| Suite | In `make test`? |
|-------|-----------------|
| `correlation_engine` | ✅ |
| `traceability-analysis/scripts/tests/*` | ✅ (`tests/run_tests.py`) |
| `demo traceability` | ✅ (smoke) |

Gaps: `bfs_lateral`, `determine_verdict` boundaries, Vault fetch integration.

---

## 7. Key abstractions

| Abstraction | Purpose |
|---|---|
| `join_edge` | Auditable matrix match produced by the shared engine |
| attack-chain stage | Narrative stage with join IDs and `correlation_source` |
| `resolve_trace_contract` | Snapshot of scenario, anchor, and join expectations |
| `victim_host_from_event` | Cross-source host identity normalization |
| `completeness_precheck` | Blocking decision and confidence ceiling before correlation |

---

## 8. Strengths and remaining risks

The design combines a matrix-primary path with explicitly labelled heuristic gap filling, centralizes cross-source joins, aligns fetch planning with the same contract, injects synthetic or operator-managed host context, and remains runnable against offline fixtures.

Remaining risks are concentrated in configuration split points: heuristic-only lateral IDs must stay aligned with `trace_stage_map`; a few join special cases remain in Python; report rendering is outside the deterministic correlator; and BFS, verdict, and execution-chain edge cases need more focused tests.

---

## 9. Recommendations

### Done (former P0 / partial P1)

1. Traceability tests in CI ✅
2. Separate public fixtures from operations bundles; the historical `bundle-trace-oss-demo` is no longer shipped ✅
3. Unified `scenario_priority` ✅
4. `trace_stage_map` + `get_join_trace_stage` ✅
5. `chain-patterns.json` + `risk_rules_bridge`; `attack-patterns.json` deprecated ✅
6. TigerSec `source_adapters/*` + `heuristic-rules.json` ✅

### Remaining

See the [operations configuration guide](../../docs_user/25-traceability-analysis-ops-config-guide.md) for the public configuration boundary and verification workflow.

---

## 10. Synthetic two-host scenario validation (2026-07-02)

| Metric | Result |
|--------|--------|
| verdict | `confirmed_intrusion_chain` (~0.92) |
| `matched_pattern` | `web_shell_to_ssh_lateral` |
| initial_access | 192.0.2.91 (`exec_inferred`, `has_tty=false`) |
| target-host lateral movement | `likely_lateral` via `lateral_from_target_exec` + syslog SSH failures |
| matrix joins | 2/9 (minimal two-asset bundle) |
| host registry | `host-source-demo` and `host-target-demo` synthetic identities |

---

*Document version: v1.1 | Updated: 2026-07-02*

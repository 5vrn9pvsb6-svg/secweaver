# Trace Profile Design

**Languages:** English (this document) | [Simplified Chinese](21-trace-profile-design.zh-CN.md)

This document describes the `trace_profile` mechanism. Its goal is to move stable log-shape and semantic normalization rules out of Python adapters and into declarative JSON profiles.

## 1. Background

Two groups of traceability behavior were historically tied to Python:

- `syslog_risk_normalize.py`: JSON unwrapping, victim-host selection through `__source__`, and syslog-to-SSH-auth derivation.
- `tigersec.py`: TTY/session signals, web-entry inference, and `sshpass` lateral-movement parsing.

For L0-style operator extensibility, similar log formats should be handled by copying and tuning templates rather than writing a new adapter.

## 2. File Layout

Trace profiles are organized as:

- schema files that define supported blocks,
- templates for known log families,
- an engine that applies profile instructions,
- adapters that call the engine from existing fetch/normalize paths.

Assets can reference a profile through `trace_profile_id`, or provide an inline `trace_profile` override. Inline configuration is deep-merged with the selected profile. Default profiles can also be selected by asset type.

## 3. Schema Capability Blocks

The profile schema supports:

- `event_repairs`
- `host_identity`
- `session_signals`
- `web_entry_inference`
- `lateral_parse`
- `ssh_auth_derivation`

### 3.1 External References

Profiles can reference existing rule/config sources instead of duplicating everything:

- `web_listeners_ref`
- `ssh_listeners_ref`
- `web_ports_ref`

These references resolve from exec rules, heuristic settings, or correlation matrices. Fallback values keep profiles usable when an external reference is missing.

### 3.2 Event Repairs

Supported event repair operations include:

- `unwrap_json_in_fields`
- `fallback_timestamp`
- `map_source_to_host`

These cover common data-shape problems without requiring a new parser.

## 4. Runtime Integration

Trace profiles are applied in several places:

1. SLS fetch post-processing repairs source events.
2. `normalize_events` applies profile-driven normalization.
3. Correlation and `tigersec` adapters use profile output for session and web-entry signals.
4. `inject_ssh_auth_from_syslog_risk` derives SSH-auth events when configured.

The profile engine is intentionally narrow: it handles repeatable normalization and semantic extraction, not arbitrary investigation logic.

## 5. Operator Workflow for a New Log Shape

For a new source format:

1. Run log-format discovery.
2. Copy the closest trace-profile template.
3. Add `trace_profile_id` to the asset, or use an inline profile override.
4. Tune exec rules, heuristics, and correlation matrices if needed.
5. Validate the profile and run traceability checks.

Python is still expected when the source introduces a new bundle type, a new join semantic, or an event-repair operation that the schema does not support.

## 6. Minimum Implemented Scope

Implemented:

- schema,
- two templates,
- profile engine,
- delegated syslog and `tigersec` behavior,
- asset mounting,
- tests.

Not fully migrated:

- narrative text inference,
- `tigersec_syslog` target impact windows and stages,
- custom event-repair types outside the schema.

## 7. Validation

Run:

```bash
make validate
make test
```

For release cleanup, also run:

```bash
make docs-check
python src/scripts/release_scan.py --json
```

## 8. Related Operations Docs

- [Traceability Analysis Operations Configuration Guide](../docs_user/25-traceability-analysis-ops-config-guide.zh-CN.md)
- [Traceability Analysis Operations Configuration Guide](../docs_user/25-traceability-analysis-ops-config-guide.md)

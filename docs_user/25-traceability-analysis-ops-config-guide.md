# Traceability Operations Configuration Guide

**Languages:** English (this page) | [简体中文](25-traceability-analysis-ops-config-guide.zh-CN.md)

This guide describes the Community workflow for adapting traceability analysis to a new environment without changing the investigation engine. It covers public DataAsset, trace profile, correlation, heuristic, and scenario configuration only. This guide does not cover vendor adapter implementation; public adapters are under [`source_adapters/`](../src/skills/traceability-analysis/scripts/source_adapters/). Private deployment overlays are outside the Community archive.

## Configuration boundary

Use configuration when the new source has an existing SecWeaver evidence type and only its field names, query template, thresholds, or correlations differ.

| Change | Public configuration entry point | Code required? |
|---|---|---|
| Connector endpoint and authentication reference | `dataasset/connectors/*.json` | No |
| Asset fields and query templates | `dataasset/assets/*.json` | No |
| Vendor fields mapped to canonical fields | `dataasset/trace-profiles/*.json` and asset `field_aliases` | No |
| Join keys and time windows | `dataasset/assets/correlation-matrix.json` | No |
| Investigation thresholds and narratives | `src/skills/traceability-analysis/heuristic-rules.json` | No |
| A new evidence type or new correlation operator | Engine and schema implementation | Yes |

`dataasset/` is the source of truth for data contracts. Skill configuration must not duplicate connector credentials or physical data-source routing.

## Recommended workflow

1. Copy the nearest connector and asset examples under `dataasset/`.
2. Give every object a new globally unique ID; do not reuse the sample ID for a production asset.
3. Map source fields to SecWeaver canonical fields with `field_aliases` or a trace profile.
4. Select or add query templates for the asset's supported investigation parameters.
5. Add only the correlations and heuristics that the available evidence can support.
6. Keep the asset in `draft` while fields, indexes, and sample queries are being verified.
7. Run `make validate` and the relevant Skill tests.
8. Change the asset to `active` only after a real query returns normalized evidence with correct timestamps and host or identity fields.

## Trace profile example

Start from a profile with the same evidence semantics. Change field aliases and source-specific parsing, but keep canonical output names stable.

```json
{
  "asset_id": "asset-example-host-exec",
  "asset_type": "host_exec",
  "trace_profile_id": "secweaver-host-exec",
  "field_aliases": {
    "source_host": "host",
    "source_ip": "host_ip",
    "process_command": "command"
  }
}
```

Do not copy real credentials into an asset. Connectors reference a credential ID; secrets belong in the configured credential store.

## Verification

From the repository root, run configuration validation and regression tests (`make validate` prepares the Python dependencies first):

```bash
make validate
make test
```

For a new source, also run one bounded query for every template used by the asset and confirm:

- timestamps use the expected timezone and parsing format;
- host, IP, user, process, and event identifiers normalize consistently;
- correlation keys do not join unrelated entities;
- empty or unavailable evidence is reported as a data gap, not as a clean verdict;
- the query cannot access data outside the connector's intended scope.

## Related documentation

- [Configure Data Sources](03-configure-data-sources.md)
- [Traceability Analysis](18-traceability-analysis.md)
- [Cross-source Field Correlation](21-cross-source-field-correlation.md)
- [Trace Profile Design](../docs_dev/21-trace-profile-design.md)
- [Community Asset and Connector Contribution](../docs_dev/03-community-add-asset-connector.md)

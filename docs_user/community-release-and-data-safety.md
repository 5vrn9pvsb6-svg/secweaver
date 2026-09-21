# Community releases and handling real data

**Languages:** English (this page) | [简体中文](community-release-and-data-safety.zh-CN.md)

## Independent operation and release

Local synthetic Community workflows do not require private servers. Self-managed sources need your services, read-only accounts, and network access; SaaS SLS Proxy needs the managed service and credentials. This page is for data users; maintainers should follow the [release checklist](../docs_dev/community-release-checklist.md).

## Elasticsearch TLS and compatibility

This applies to the public Python ES Connector, discovery and local Studio. Use a trusted
HTTPS endpoint, a valid certificate matching its hostname and a read-only account. Supply a
private CA through `ca_file`; relative paths resolve from `DATAASSET_ROOT`. The browser wizard
explicitly sends `tls_verify: true`, and generated configuration defaults to verification.
Unknown CAs, expired certificates and hostname mismatches fail without an insecure retry. Fetch and discovery reject HTTP redirects to prevent credential forwarding or downgrades; configure the final HTTPS endpoint directly.

Dedicated ES Discovery and Studio probe APIs retain explicit boolean `false` for controlled
diagnostics. Live Connector fetch, the public Connector Schema, and activation validation
all reject `false`. Nulls, numbers and strings, including `"false"`, are
rejected. Previously omitted settings now verify certificates: migrate by supplying the
correct CA instead of depending on the old insecure default.
Run `python3 -m unittest discover -s tests -p test_es_tls_transport.py` with OpenSSL and
loopback-listening permission to verify unknown-peer rejection, private CA success and
explicit diagnostic compatibility.

HTTP API, Splunk, and external executors use the same transport boundary: remote endpoints
require HTTPS, loopback endpoints may use HTTP, and all redirects are rejected. HTTP API and
Splunk private CAs also use `ca_file`.

## Interpreting incomplete queries

An ES HTTP 200 response may time out, terminate early or include failed shards. ES page size
and local `max_records_per_request` also limit results. Fetching retains useful evidence and exposes:

- `query_meta.partial` and `incomplete_reasons`: known incomplete responses and reasons.
- `query_meta.truncated`: actual or possible truncation from page limits, lower-bound totals or local limits.
- `timed_out`, `terminated_early`, `failed_shards`, `total_hits`: server status.
- `fetch_summary.query_integrity`: gaps from failed/partial queries, including cache hits, for downstream reports.

With `status=incomplete`, missing returned events cannot rule out an attack. Narrow or split
the time window, inspect the cluster or add sources. `no_known_gaps` means executed queries
reported no gaps, not that every source is complete. Without executed queries or metadata,
the status is `unknown`. Fetching does not automatically paginate or silently retry to clear warnings.

An existing completeness precheck receives `query_integrity` and the `query_results_incomplete`
data gap. Positive evidence remains available; results are not overwritten and confidence is
not arbitrarily reduced. The AI agent must explain conclusions in light of query gaps.
Offline/manual evidence lacks server status; event counts alone do not establish query completeness.

## Evidence ID migration

Generated IDs are namespaced by asset and connector. The base format is
`<asset-type>-v2-<digest>`; ES prefers
index plus document ID. Other events use a canonical full-content digest independent of query
order. Explicit caller-supplied `evidence_id` values remain unchanged; callers own their uniqueness.

Exception: events with a native `audit_id`/`event_id`, host and source time now use
`<asset-type>-v3-<digest>`. The digest retains source payload and namespace but
excludes SLS pack/receive time and analysis bookkeeping, so reuploads deduplicate.
Different hosts, source times or payloads remain separate. Existing explicit IDs,
including exported v2 IDs, are preserved. After upgrading, fetch again and rebuild
reports/indexes that depend on generated native IDs; do not mix v2/v3 references.
Risk assessment also deduplicates old native-event exports before thresholds and
retains discarded-to-first-reference mappings in `evidence_deduplication`.

Older sequence-based generated IDs are incompatible with v2: regenerate related reports/indexes rather than
mixing old references with new results. Identical records without native IDs cannot be
distinguished, and field projection changes can change content digests. IDs are generated
before masking and are not an anonymization guarantee.

## Sensitive fields are not automatically masked

Vault credentials are not appended to events, but source logs may contain tokens, passwords,
cookies or headers. Missing/empty `masking` retains values. `pii_fields` is governance metadata
and does not perform masking. Before passing data to an AI agent or sharing reports, configure
rules for actual fields and inspect raw fields, aliases and nested copies.

Merge this fragment into an Asset that needs to hide entire commands and headers. It removes
information needed for command analysis; perform necessary analysis locally first, or design
more precise rules for the log format:

```json
{
  "masking": {
    "command": "redact",
    "raw_command": "redact",
    "Authorization": "redact",
    "authorization": "redact",
    "headers.Authorization": "redact",
    "headers.authorization": "redact",
    "headers.Cookie": "redact",
    "headers.cookie": "redact"
  }
}
```

Field matching is case-sensitive. This example does not cover arbitrary raw logs or every
possible field. Fetch synthetic sensitive values and inspect output JSON and reports for all
copies before using real data.

## SLS → ES migration helper

`src/dataasset/migrate_sls_to_es.py` no longer assumes private directories or internal mapping
names. Supply `--config`, `--source-root` and at least one `--mapping`; unknown mappings fail.
Maintain your own mapping file, for example:

```json
{
  "mappings": [{
    "source_connector_id": "conn-sls-source",
    "target_connector_id": "conn-es-target",
    "target_index": "logs-security-*"
  }]
}
```

Start with a read-only source preview, replacing paths, times, gateway and CA:

```bash
python3 src/dataasset/migrate_sls_to_es.py \
  --config /path/to/migration.json --source-root /path/to/source-dataasset \
  --mapping conn-es-target --time-start 2026-09-01T00:00:00Z \
  --time-end 2026-09-01T01:00:00Z \
  --ingest-url https://ingest.example.com --ca-file /path/to/ca.pem --dry-run
```

The source directory needs a complete DataAsset configuration and working read-only credentials.
Actual writes additionally require an ES `_bulk`-compatible HTTPS ingest gateway and a separate
writer account, supplied through `SECWEAVER_INGEST_USER` and `SECWEAVER_INGEST_PASSWORD`.
The helper does not deploy a private gateway. Verify source assets, counts and target indices
in the preview before deciding what to write.

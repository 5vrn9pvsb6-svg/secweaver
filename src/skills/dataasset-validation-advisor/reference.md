# Data Asset Validation Advisor — Reference

## Key contracts

- Only `status=active` assets are considered available.
- `status=active` bundles must not reference draft/discovery/disabled assets.
- Connectors store non-sensitive `config` and `credentials_ref` only; real secrets in SOPS Vault.
- Assets no longer use `host_binding`; host coverage via `coverage.hosts` log source IPs; single-host collection target via `connector.config.host_id`.
- `pii_fields` is governance annotation only; runtime masking uses `masking` only.
- `correlation_keys` are not hand-written; derived from matrix + fields.

## Pre-release checklist

1. `validate.py` 0 errors.
2. Active connectors have real config, not `YOUR_*` placeholders.
3. Active assets have usable `query_template_ids`.
4. Active bundle members all active.
5. Preview the query plan from the repository root; `--dry-run` does not decrypt credentials or prove connectivity:

```bash
python3 src/dataasset/test_connector.py asset-sls-proxy-host-exec-demo --by-asset --dry-run \
  --params '{"time_start":"2026-06-21T09:00:00+08:00","time_end":"2026-06-21T10:00:00+08:00"}'
```

For live acceptance, replace the asset ID with a configured, authorized asset, set its `DATAASSET_ROOT`, and omit `--dry-run` to run a read-only connectivity test.

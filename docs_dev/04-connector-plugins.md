# Connector Plugins

**Languages:** English (this page) | [简体中文](04-connector-plugins.zh-CN.md)

Connector plugins are for integrations that should not live in SecWeaver core but still need first-class discovery and fetch execution. A plugin is a local directory with a manifest and a small program.

Run `make quickstart` once from the repository root before following the commands below.
They invoke `.venv/bin/python` directly so plugin checks use the repository environment.

## Directory Layout

```text
src/dataasset/plugins/connectors/<plugin_name>/
  plugin.json
  fetch.py
  requirements.txt
  README.md
```

The bundled demo is [`../src/dataasset/plugins/connectors/demo_plugin_logs/`](../src/dataasset/plugins/connectors/demo_plugin_logs/).
Plugin code does not live under `DATAASSET_ROOT`. For an operator-owned plugin
directory, set `SECWEAVER_PLUGIN_ROOT=/path/to/connectors` before starting the
CLI or UI.

You can scaffold the directory first:

```bash
.venv/bin/python src/secweaver.py connector plugin init vendor_logs \
  --query-key vendor_query
```

Then replace the sample event block in `fetch.py` and keep SDK dependencies in the plugin's own `requirements.txt`.

## Manifest

```json
{
  "name": "Vendor Logs",
  "api_version": "1.0",
  "connector_type": "vendor_logs",
  "query_key": "vendor_query",
  "runtime": "plugin",
  "protocol": "stdio-json",
  "entrypoint": "fetch.py",
  "timeout_sec": 30,
  "python": ".venv/bin/python"
}
```

Required fields: `api_version: "1.0"`, `connector_type`, `query_key`, `runtime: "plugin"`, `protocol: "stdio-json"`, and `entrypoint`.

`python` is optional. When omitted, SecWeaver uses the current Python executable. When set, it may point to a plugin-local virtual environment, so SDK dependencies stay outside core requirements.

Discovery, CLI validation and runtime execution share
[`plugin_contract.py`](../src/dataasset/plugin_contract.py). The optional
`timeout_sec` defaults to **30 seconds** in both CLI and runtime. Explicit
`--timeout-sec` (smoke test) or Connector `constraints.request_timeout_sec`
(runtime) overrides that value. Use positive integer seconds; booleans, fractional,
zero and null values are rejected. A timed-out attempt is not automatically retried.

## Contract Validation

After writing a plugin, run the manifest + stdio-json smoke validator:

```bash
.venv/bin/python src/secweaver.py connector plugin validate src/dataasset/plugins/connectors/vendor_logs
.venv/bin/python src/secweaver.py connector plugin validate --json
.venv/bin/python src/secweaver.py connector plugin validate --no-exec --json
```

The validator checks:

- Required `plugin.json` fields and `api_version`.
- `entrypoint` exists and does not escape the plugin directory.
- `protocol` is `stdio-json`.
- The entrypoint reads one JSON object from stdin and returns one JSON object on stdout.
- The response includes one of `events`, `data`, `results`, `records`, `items`, or `alerts`.

`--no-exec` validates the manifest, entrypoint containment (including symlinks),
and optional interpreter path without launching plugin code. It does not prove
response correctness or backend connectivity. The normal smoke test supplies
empty credentials and config; it checks the protocol, not live authentication.
An operator-selected interpreter may live outside the plugin directory; the
entrypoint may not. Install plugins only from trusted sources: `shell=False`
does not sandbox their Python code.

## Protocol

SecWeaver runs the entrypoint with `shell=False`, sends one JSON object on stdin, and expects one JSON object on stdout.

Input:

```json
{
  "connector": {},
  "credentials": {},
  "query": "vendor query text",
  "params": {
    "src_ip": "203.0.113.10",
    "limit": 100
  }
}
```

Output:

```json
{
  "events": [
    {
      "timestamp": "2026-07-07T00:10:00Z",
      "src_ip": "203.0.113.10",
      "action": "blocked"
    }
  ],
  "meta": {
    "backend": "vendor_logs",
    "rows_returned": 1
  }
}
```

The response can use `events`, `data`, `results`, `records`, `items`, or `alerts` for the event array.

The first array in that fixed order wins, even if empty; aliases are not merged.
Every item must be a JSON object. `meta` may be omitted or null, otherwise it
must be an object. Any invalid row or metadata fails the entire response, before
row limits are applied; malformed rows are not silently discarded. JSON/response
format errors do not echo stdout. On nonzero exit, runtime always discards stdout
and returns only a bounded stderr excerpt after recursively redacting credential
values. If a credential value is too short to redact reliably, stderr is omitted.
Plugins must still avoid writing credentials to either stream.

### Compatibility and migration

API version remains `1.0`, but discovery now checks the raw manifest before
adding catalog metadata. Older incomplete manifests that relied on guessed
`api_version`, `runtime`, `protocol` or `entrypoint` must declare all six required
fields. Invalid manifests are omitted from discovery; run `connector plugin
validate --json` for actionable errors. Fix mixed event arrays and non-object
metadata, then validate again. Runtime's former implicit 60-second timeout is
now 30 seconds; declare `timeout_sec: 60` if that duration is required.

After changing a manifest, restart the CLI/UI process or use the UI's
`/api/connectors/reload` cache refresh. Template query-key selection reads the
refreshed registry, so a successful reload does not require a process restart.
No DataAsset credential or database migration is needed.

## Onboarding Config

After adding `plugin.json`, use the new type in `dataasset/onboarding/examples/*.json`:

```json
{
  "name": "demo-vendor-plugin",
  "connector_type": "vendor_logs",
  "asset_type": "waf_alert",
  "credentials_ref": "vault://vendor/security-readonly",
  "template": {
    "params": ["src_ip", "limit"],
    "defaults": {
      "limit": 100
    },
    "vendor_query": "src_ip={src_ip} limit {limit}"
  }
}
```

Preview:

```bash
.venv/bin/python src/secweaver.py asset apply \
  -f dataasset/onboarding/examples/vendor-quickstart-plugin-connector.json \
  --dry-run
```

Fetch smoke test:

```bash
.venv/bin/python src/secweaver.py connector plugin validate src/dataasset/plugins/connectors/demo_plugin_logs
.venv/bin/python -m unittest src/skills/_shared/data-access/tests/test_plugin_connectors.py -v
.venv/bin/python -m unittest tests.test_plugin_contract -v
```

## When to Use Plugins

Use a plugin when the integration is runnable on the same host and benefits from local code, SDKs, or custom parsing. Use an external executor when the integration should run as a service or in a different network boundary. Use an in-core connector only when the behavior is common enough to maintain as part of SecWeaver itself.

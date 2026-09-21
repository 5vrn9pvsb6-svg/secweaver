# Connector Plugin Examples

**Languages:** English (this page) | [简体中文](README.zh-CN.md)

This directory contains local connector plugins. Use plugins when an integration needs local code, vendor SDKs, custom parsing, or network placement that should not become a core SecWeaver dependency.

Plugin code is deliberately separate from `DATAASSET_ROOT`. Set
`SECWEAVER_PLUGIN_ROOT=/path/to/connectors` to discover an operator-owned plugin
directory outside this repository.

## Included Example

| Plugin | connector_type | Purpose |
|---|---|---|
| [`demo_plugin_logs/`](demo_plugin_logs/) | `demo_plugin_logs` | Minimal stdio-json plugin for community copy/paste and contract tests |

## Create a Plugin

```bash
python3 src/secweaver.py connector plugin init vendor_logs \
  --query-key vendor_query
```

Then edit:

- `plugin.json`: manifest with `api_version`, `connector_type`, `query_key`, `runtime`, `protocol`, and `entrypoint`.
- `fetch.py`: reads one JSON object from stdin and writes one JSON object to stdout.
- `requirements.txt`: plugin-owned SDK dependencies.

## Validate

```bash
python3 src/secweaver.py connector plugin validate src/dataasset/plugins/connectors/vendor_logs
python3 src/secweaver.py connector plugin validate --json
```

Full docs: [`../../../../docs_dev/04-connector-plugins.md`](../../../../docs_dev/04-connector-plugins.md).

# Demo Plugin Logs Connector

This is the smallest runnable connector plugin example.

SecWeaver discovers this connector from `plugin.json` and runs `fetch.py` as a subprocess using the `stdio-json` protocol. The plugin receives connector metadata, credentials, the rendered query, and template params on stdin, then returns normalized events and metadata on stdout.

Copy this directory to create a new connector without changing core Python code:

1. Rename the directory.
2. Update `plugin.json` with a new `connector_type` and `query_key`.
3. Replace `fetch.py` with your vendor/API/database fetch logic.
4. Add dependencies to `requirements.txt` and optionally set `"python": ".venv/bin/python"` in `plugin.json`.

Validate the contract before opening a PR:

```bash
python3 src/secweaver.py connector plugin validate src/dataasset/plugins/connectors/demo_plugin_logs
```

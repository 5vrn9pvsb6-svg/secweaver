# Self-managed Elasticsearch From an Agent Package

English | [简体中文](self-managed-es.zh-CN.md)

This page is package-local navigation. The [Elasticsearch guide](../elasticsearch/README.md) owns initialization, account separation, CA configuration, Filebeat, and ingestion verification. It is available inside the extracted package without a source checkout.

Supported setup: Linux systemd, Elasticsearch 8.x, Filebeat 8.19.x. Bring your own ES, Filebeat, trusted HTTPS certificate, and separate setup/write/read-only accounts. This path needs neither SaaS SLS Proxy nor private server code.

## Start here

1. From the extracted package root, run `python3 elasticsearch/init_es.py` for an offline template preview.
2. Follow the full guide to create the template with the setup account. Review drift rather than overwriting existing indices.
3. Configure Filebeat inputs, keystore, and CA; test configuration and output before enabling collection.
4. Run the guide's `--check` command with a separate read-only account. No recent events, timeouts, or failed shards do not pass acceptance.

The package's `elasticsearch/` includes `init_es.py`, `index-template.json`, `filebeat.yml`, and bilingual READMEs. Never package production credentials. Preserve Filebeat registry and `path.data` during reconfiguration or upgrades to avoid rereading data.

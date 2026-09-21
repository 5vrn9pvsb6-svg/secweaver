# External Connector Executors

**Languages:** English (this page) | [简体中文](05-external-connector-executors.zh-CN.md)

SecWeaver keeps optional vendor SDKs outside the core package. Connector types with
`runtime: "local_or_external_executor"` can be used in three ways:

1. Local samples through `connector.config.sample_file`, `sample_dir`, `base_path`, or local `bucket/prefix`.
2. An external HTTP executor through `connector.config.endpoint` or `base_url`.
3. Planned metadata when neither samples nor endpoint are configured.

Remote executors must use their final HTTPS URL; plain HTTP is limited to loopback
development endpoints. Runtime requests reject remote cleartext before sending and do
not follow redirects. Configure a private CA with `ca_file`, resolved relative to
`DATAASSET_ROOT`; resolved relative paths and symlinks cannot escape that root.
Cloud connectors use `executor_endpoint` / `external_endpoint`;
generic config-only connectors use the `endpoint` or `base_url` declared by their manifest.

## HTTP contract

SecWeaver POSTs this JSON payload to the configured endpoint:

```json
{
  "query": "fields @timestamp, @message | sort @timestamp desc | limit {limit}",
  "params": {
    "src_ip": "203.0.113.10",
    "time_start": "2026-07-07T00:00:00+00:00",
    "time_end": "2026-07-07T01:00:00+00:00",
    "limit": 100
  },
  "config": {
    "region": "ap-southeast-1",
    "log_group": "/aws/cloudtrail/organization",
    "executor_endpoint": "http://127.0.0.1:8788/fetch"
  }
}
```

The executor should return JSON with one of these list fields: `events`, `data`,
`results`, `records`, `items`, or `alerts`.

```json
{
  "events": [
    {
      "@timestamp": "2026-07-07T00:10:00Z",
      "sourceIPAddress": "203.0.113.10",
      "eventName": "ConsoleLogin"
    }
  ],
  "meta": {
    "backend": "aws_cloudwatch",
    "rows_returned": 1
  }
}
```

Do not pass raw secrets in `config`. Use the executor process environment,
cloud instance roles, or local SDK profiles.

## AWS CloudWatch example

The repository includes an optional executor at
[`examples/executors/aws_cloudwatch_executor.py`](../examples/executors/aws_cloudwatch_executor.py).
It uses CloudWatch Logs Insights and requires `boto3` only in the executor
environment:

```bash
python3 -m pip install boto3
python3 examples/executors/aws_cloudwatch_executor.py --port 8788
```

Then set `executor_endpoint` on the connector:

```json
{
  "connector_type": "aws_cloudwatch",
  "connector": {
    "config": {
      "region": "ap-southeast-1",
      "log_group": "/aws/cloudtrail/organization",
      "executor_endpoint": "http://127.0.0.1:8788/fetch"
    }
  },
  "template": {
    "cloudwatch_query": "fields @timestamp, @message | filter sourceIPAddress = '{src_ip}' | sort @timestamp desc | limit {limit}"
  }
}
```

This keeps the core open-source runtime small while still giving operators a
copyable path for real cloud data.

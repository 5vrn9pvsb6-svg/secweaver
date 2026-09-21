# 外部 Connector 执行器

**语言：** 简体中文（本文） | [English](05-external-connector-executors.md)

SecWeaver 不把可选厂商 SDK 放进核心依赖。`runtime: "local_or_external_executor"` 的 connector 类型有三种运行方式：

1. 配置 `connector.config.sample_file`、`sample_dir`、`base_path` 或本地 `bucket/prefix`，走本地样本执行器。
2. 配置 `connector.config.endpoint` 或 `base_url`，把查询交给外部 HTTP 执行器。
3. 两者都不配时返回 planned 元信息，用于确认查询和参数已经渲染完成。

远程执行器必须使用最终 HTTPS 地址；HTTP 仅允许本机回环开发地址。运行时不跟随
重定向，并在发送请求前拒绝远程明文 HTTP。私有 CA 使用 `ca_file`，相对路径以
`DATAASSET_ROOT` 为基准且解析后不得越界；符号链接也受同一限制。云 Connector 使用 `executor_endpoint` / `external_endpoint`，
配置型通用 Connector 使用其 manifest 声明的 `endpoint` 或 `base_url`。

## HTTP 协议

SecWeaver 会向 endpoint POST 这类 JSON：

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

执行器返回 JSON 即可，事件列表字段可以是 `events`、`data`、`results`、`records`、`items` 或 `alerts`。

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

不要把真实密钥写进 `config`。推荐由执行器进程自己从环境变量、云主机角色、容器任务角色或本地 SDK profile 读取凭证。

## AWS CloudWatch 示例

仓库提供了一个可选执行器：
[`examples/executors/aws_cloudwatch_executor.py`](../examples/executors/aws_cloudwatch_executor.py)。
它使用 CloudWatch Logs Insights，只在执行器环境里需要 `boto3`：

```bash
python3 -m pip install boto3
python3 examples/executors/aws_cloudwatch_executor.py --port 8788
```

然后在 connector 配置里填 `executor_endpoint`：

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

这样核心开源包保持轻量，运营同学也有一条能复制落地的真实云数据接入路径。

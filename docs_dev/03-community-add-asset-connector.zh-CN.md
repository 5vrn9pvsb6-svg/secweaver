# 社区手册：新增一个资产和它的 Connector

**语言：** 简体中文（本文） | [English](03-community-add-asset-connector.md)

这份手册面向社区贡献者：你想贡献一种新的数据源样例、资产模板，或帮助运营同学把某类日志快速接入 SecWeaver。默认目标是**不改核心 Python 代码**，先用配置、模板、样本和可选外部执行器完成接入。

开始前先在仓库根目录运行一次 `make quickstart`。下文命令直接使用
`.venv/bin/python`，确保执行的是仓库固定的虚拟环境。

## 你要交付什么

| 文件 | 作用 | 推荐位置 |
|---|---|---|
| connector | 描述怎么连接数据源，只写非敏感配置和 `credentials_ref` | `dataasset/examples/connectors/conn-<vendor>-<purpose>-example.json` |
| asset | 描述这类数据代表什么、字段怎么解释、覆盖哪些对象 | 通过 `asset apply --dry-run` 生成后，优先作为示例配置提交 |
| query template | 描述按调查参数怎么查询，例如按 `src_ip + time` | `dataasset/query-templates/templates.json` 或 onboarding 模板 |
| onboarding config | 让运营同学复制后只改配置即可生成三件套 | `dataasset/onboarding/examples/*.json` |
| local sample | 合成日志样本，用于格式发现和 dry-run | `examples/` 或 PR 里的说明 |
| docs | 说明它解决什么场景、怎么验证 | `docs_dev/` 或 `docs_user/` |

默认不要直接把新对象放进正式 registry（`dataasset/assets/`、`dataasset/connectors/`）。先放 `dataasset/examples/` 或 onboarding 示例，维护者确认后再提升为内置 demo。

## 先判断 connector 类型

完整内置 connector 清单见 [`../dataasset/onboarding/README.zh-CN.md`](../dataasset/onboarding/README.zh-CN.md) 的“内置 connector 清单”。内置 connector 的权威元数据是 [`../dataasset/configure/connector-catalog.json`](../dataasset/configure/connector-catalog.json)，query key、runtime、依赖策略、模板选择和 Studio profile 都在同一条目维护；Python 不再保存重复的兜底常量。

| 情况 | 做法 |
|---|---|
| 已有类型，如 `sls`、`es`、`http_api`、`database_ro`、`aws_cloudwatch` | 直接写 onboarding 配置 |
| 新类型，但可以走本地样本或外部 HTTP 程序 | 只改 `dataasset/configure/external-connectors.json` 注册 |
| 新类型需要本地代码、SDK 或自定义解析，但不应进入核心依赖 | 在 `src/dataasset/plugins/connectors/<plugin_name>/` 增加插件 |
| 新类型必须内置 SDK 直连 | 先提 Issue/RFC；核心依赖需要维护者确认 |

新增配置型类型示例：

```json
{
  "connectors": {
    "vendor_logs": {
      "query_key": "vendor_query",
      "runtime": "local_or_external_executor",
      "description": "External executor example for Vendor Logs.",
      "onboarding_template": "external_generic",
      "onboarding_profile": {
        "label": "Vendor Logs",
        "fields": ["endpoint", "sample_file"],
        "required": [],
        "defaults": {"sample_file": "examples/log-format-discovery/waf-jsonl.sample"},
        "default_asset_type": "waf_alert",
        "template_params": ["src_ip", "time_start", "time_end", "limit"],
        "template_defaults": {"limit": 1000},
        "default_query": "src_ip:{src_ip} limit {limit}",
        "hint": "使用本地样本或外部执行器。"
      }
    }
  }
}
```

`query_key` 是 query template 里的查询字段名，例如 `cloudwatch_query`、`splunk_search`、`sql`。`runtime: "local_or_external_executor"` 表示它可以读本地样本，也可以把查询 POST 给外部执行器。

## 推荐路径：用 onboarding 配置生成三件套

复制一份配置：

```bash
cp dataasset/onboarding/examples/data-sources.sample.json /tmp/my-source.json
```

最小结构：

```json
{
  "version": "1.0",
  "output_dir": "dataasset",
  "data_sources": [
    {
      "name": "demo-vendor-waf",
      "connector_type": "vendor_logs",
      "asset_type": "waf_alert",
      "credentials_ref": "vault://vendor/security-readonly",
      "status": "discovery",
      "owner_team": "security-ops",
      "environment": "production",
      "endpoint": "http://127.0.0.1:8788/fetch",
      "sample_file": "examples/log-format-discovery/waf-jsonl.sample",
      "asset": {
        "text_parser": "json_lines",
        "schema": {
          "fields": ["timestamp", "src_ip", "url", "action"],
          "time_field": "timestamp",
          "retention_days": 30
        },
        "field_aliases": {
          "client_ip": "src_ip"
        },
        "coverage": {
          "zones": ["edge"],
          "apps": ["demo-gateway"],
          "hosts": []
        }
      },
      "template": {
        "params": ["src_ip", "time_start", "time_end", "limit"],
        "defaults": {
          "limit": 1000
        },
        "vendor_query": "source:security src_ip:{src_ip} limit {limit}"
      }
    }
  ]
}
```

预览生成内容：

```bash
.venv/bin/python src/secweaver.py asset apply -f /tmp/my-source.json --dry-run
```

对比当前仓库会发生什么变化：

```bash
.venv/bin/python src/secweaver.py asset diff -f /tmp/my-source.json
```

确认后写入：

```bash
.venv/bin/python src/secweaver.py asset apply -f /tmp/my-source.json
```

这会生成：

```text
dataasset/connectors/conn-*.json
dataasset/assets/asset-*.json
dataasset/query-templates/templates.json
```

如果写入后发现配置方向错了，可以先预览回退，再显式确认删除这份配置生成的对象：

```bash
.venv/bin/python src/secweaver.py asset rollback -f /tmp/my-source.json --dry-run
.venv/bin/python src/secweaver.py asset rollback -f /tmp/my-source.json --confirm-delete
```

## UI 路径

也可以打开本地 DataAsset UI：

```bash
DATAASSET_UI_PORT=8765 .venv/bin/python dataasset-ui/server.py
```

访问：

```text
http://127.0.0.1:8765/onboarding.html
```

在页面里选择 `Connector 类型`，填写基础信息、连接参数、解析器、覆盖范围和模板参数，然后：

1. 点“生成配置”
2. 审阅右侧配置 JSON
3. 点“预览三件套”
4. 确认后点“写入 DataAsset”

对于 `local_or_external_executor` 类型，页面会提示 query key 和运行方式。比如 `aws_cloudwatch` 会使用 `cloudwatch_query`，并提示可选外部执行器。

## 外部执行器怎么接

如果你的 connector 不适合进入核心依赖，例如需要云厂商 SDK、商业平台 SDK 或内部网络访问，推荐提供外部执行器。SecWeaver 会向 `connector.config.endpoint` POST：

```json
{
  "query": "vendor query text",
  "params": {
    "src_ip": "203.0.113.10",
    "time_start": "2026-07-07T00:00:00+00:00",
    "time_end": "2026-07-07T01:00:00+00:00",
    "limit": 100
  },
  "config": {
    "endpoint": "http://127.0.0.1:8788/fetch"
  }
}
```

执行器返回：

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

不要把真实密钥写进提交的 JSON。外部执行器应从环境变量、云角色、本地 profile 或部署平台读取密钥。

CloudWatch 示例：

```bash
.venv/bin/python -m pip install boto3
.venv/bin/python examples/executors/aws_cloudwatch_executor.py --port 8788
```

更多协议细节见 [外部 Connector 执行器](05-external-connector-executors.zh-CN.md)。

## Connector 插件怎么接

如果你的集成不想作为 HTTP 服务运行，但需要本地代码、SDK 或自定义解析，可以增加插件目录：

```text
src/dataasset/plugins/connectors/vendor_logs/
  plugin.json
  fetch.py
  requirements.txt
  README.md
```

`plugin.json` 注册类型：

```json
{
  "api_version": "1.0",
  "connector_type": "vendor_logs",
  "query_key": "vendor_query",
  "runtime": "plugin",
  "protocol": "stdio-json",
  "entrypoint": "fetch.py"
}
```

然后在 onboarding 配置里直接使用 `connector_type: "vendor_logs"`。详见 [Connector 插件](04-connector-plugins.zh-CN.md)，也可以复制 `src/dataasset/plugins/connectors/demo_plugin_logs/` 示例目录。

插件提交前运行契约校验：

```bash
.venv/bin/python src/secweaver.py connector plugin validate src/dataasset/plugins/connectors/vendor_logs
```

## 字段和解析规则

| 字段 | 说明 |
|---|---|
| `asset_type` | 逻辑类型，例如 `waf_alert`、`web_access_log`、`ssh_auth`、`db_audit` |
| `text_parser` | 文本解析器，例如 `json_lines`、`syslog_auth`、`nginx_combined` |
| `schema.fields` | 贡献者承诺可用于分析的字段 |
| `schema.time_field` | 时间字段 |
| `field_aliases` | 源字段到标准字段的映射，例如 `client_ip -> src_ip` |
| `coverage` | 这份数据覆盖的 zone、app、host 范围 |
| `query_template_ids` | 资产可使用的查询模板 |

新日志格式建议先设 `status: "discovery"`，用格式发现流程补齐字段映射：

```bash
.venv/bin/python src/skills/log-format-discovery/scripts/discover.py \
  --asset-id YOUR_ASSET_ID \
  -i examples/your-sample.jsonl \
  --apply --apply-dry-run
```

## 提交前检查

至少运行：

```bash
.venv/bin/python src/secweaver.py validate --json --only-active
.venv/bin/python tests/run_tests.py
.venv/bin/python src/scripts/release_scan.py
.venv/bin/python src/scripts/check_docs_links.py
```

如果你改了 onboarding、connector registry 或 CLI，建议再跑：

```bash
.venv/bin/python -m unittest tests.test_secweaver_cli tests.test_dataasset_ui -v
```

如果你提供了外部执行器示例，至少保证语法检查通过：

```bash
.venv/bin/python -m py_compile examples/executors/<your_executor>.py
```

## PR 清单

- [ ] 没有真实密钥、AK、token、私钥、客户日志、生产主机名或批量内网资产清单
- [ ] `connector_id` / `asset_id` 唯一，并使用 `example` 或 `demo` 后缀
- [ ] 凭证只写 `vault://...` 引用
- [ ] 查询模板使用标准参数名，如 `src_ip`、`time_start`、`time_end`、`limit`
- [ ] 新 connector_type 已在 `dataasset/configure/external-connectors.json` 或插件 `plugin.json` 中注册
- [ ] 本地样本使用合成数据，IP 使用 RFC 5737 文档地址段
- [ ] 文档说明这个资产服务哪个场景或 Skill
- [ ] 本地检查通过，PR 描述里贴出命令结果

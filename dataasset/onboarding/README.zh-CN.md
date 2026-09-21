# 新数据源接入 — 运营配置优先

推荐路径：运营同学维护一份 JSON 配置，先 `--dry-run` 审阅生成内容，再由 CLI 写入 connector、asset 和 query template。

```bash
python3 src/secweaver.py asset apply \
  -f dataasset/onboarding/examples/data-sources.sample.json \
  --dry-run

python3 src/secweaver.py asset apply \
  -f dataasset/onboarding/examples/data-sources.sample.json
```

运营生命周期建议：

```bash
# 先对比当前 DataAsset 会新增/覆盖什么
python3 src/secweaver.py asset diff \
  -f dataasset/onboarding/examples/data-sources.sample.json

# 写入后做连通测试；成功后可晋级 draft -> active
python3 src/secweaver.py asset promote \
  --asset asset-demo-waf-sls \
  --params '{"src_ip":"203.0.113.10"}' \
  --dry-run

# 如果要撤回本次配置生成物，先 dry-run，再显式确认删除
python3 src/secweaver.py asset rollback \
  -f dataasset/onboarding/examples/data-sources.sample.json \
  --dry-run
python3 src/secweaver.py asset rollback \
  -f dataasset/onboarding/examples/data-sources.sample.json \
  --confirm-delete
```

配置 schema：[`data-sources.schema.json`](data-sources.schema.json)。样例配置：[`examples/data-sources.sample.json`](examples/data-sources.sample.json)。

## Vendor quickstart 样例

| 样例 | 覆盖场景 | 运行方式 |
|---|---|---|
| [`examples/data-sources.sample.json`](examples/data-sources.sample.json) | SLS、ES、SSH 文件三类基础接入 | 内置 fetch / 文件读取 |
| [`examples/secweaver-saas-sls-proxy-assets.json`](examples/secweaver-saas-sls-proxy-assets.json) | SecWeaver SaaS SLS Proxy：8 个公开 Logstore、13 类主机/DNS/WEB/WAF 逻辑资产 | 内置 SLS Proxy fetch |
| [`examples/vendor-quickstart-cloudwatch.json`](examples/vendor-quickstart-cloudwatch.json) | AWS CloudWatch Logs / CloudTrail | 可选外部执行器 |
| [`examples/vendor-quickstart-cloud-vendors.json`](examples/vendor-quickstart-cloud-vendors.json) | Azure Monitor、GCP Logging、Tencent CLS、Huawei LTS | 本地样本 / REST / 外部执行器 |
| [`examples/vendor-quickstart-cloud-audit-siem.json`](examples/vendor-quickstart-cloud-audit-siem.json) | AWS CloudTrail、Azure Activity / Entra、GCP Audit、Splunk ES notable 事件 | 本地样本 / REST / 外部执行器 |
| [`examples/vendor-quickstart-siem-warehouse.json`](examples/vendor-quickstart-siem-warehouse.json) | Splunk + ClickHouse | live fetch |
| [`examples/vendor-quickstart-external-connector.json`](examples/vendor-quickstart-external-connector.json) | 配置型新 connector_type，如 Datadog | 本地样本 / 外部执行器 |
| [`examples/vendor-quickstart-databases.json`](examples/vendor-quickstart-databases.json) | MySQL、SQL Server、SQLite 只读审计 | live fetch / 本地 SQLite |
| [`examples/vendor-quickstart-document-cache.json`](examples/vendor-quickstart-document-cache.json) | MongoDB 文档日志 + Redis 资产缓存 | live fetch |
| [`examples/vendor-quickstart-identity-edge-edr.json`](examples/vendor-quickstart-identity-edge-edr.json) | Okta、Cloudflare、CrowdStrike 外部接入 | 本地样本 / 外部执行器 |
| [`examples/vendor-quickstart-edr-identity-vendors.json`](examples/vendor-quickstart-edr-identity-vendors.json) | Microsoft Defender XDR、SentinelOne、CrowdStrike、Okta、Google Workspace、Entra ID | 本地样本 / 外部执行器 |
| [`examples/vendor-quickstart-plugin-connector.json`](examples/vendor-quickstart-plugin-connector.json) | 本地 connector 插件示例 | 插件子进程 |

这些文件也会出现在 DataAsset UI 的 Quickstart 下拉里；也可以先 dry-run：

```bash
python3 src/secweaver.py asset apply \
  -f dataasset/onboarding/examples/vendor-quickstart-cloudwatch.json \
  --dry-run
```

使用托管 SLS Proxy 时，优先预览完整资产模板：

```bash
python3 src/secweaver.py asset apply \
  -f dataasset/onboarding/examples/secweaver-saas-sls-proxy-assets.json \
  --dry-run
```

模板不包含凭证，生成的 Connector/Asset 默认保持 `draft/discovery`。正式写入前删除不需要或未获授权的数据源；DNS、TS 访问和 WAF 路由还必须在服务端完成 `enterprise_id` 接入与字段索引，并通过真实查询验收。

查看完整能力目录（来源、运行方式、query key、依赖策略）：

```bash
python3 src/secweaver.py connector catalog
python3 src/secweaver.py connector catalog --json
```

## 内置 connector 清单

运营同学可以直接在本文查看当前内置 connector；DataAsset UI 的 `Connector 类型` 下拉也会读取同一份注册表。

| connector_type | 运行方式 | query key |
|---|---|---|
| `sls` | 内置 fetch | `sls_query` |
| `sls_proxy` | 内置 fetch | `sls_query` |
| `ssh_file` | 内置 fetch | `ssh_command` |
| `ssh_command` | 内置 fetch | `ssh_command` |
| `database_ro` | 内置 fetch | `sql` |
| `http_api` | 内置 fetch | `http` |
| `es` | 内置 fetch | `es_query` |
| `local_file` | 内置 fetch | `local_file_command` |
| `splunk` | 内置 fetch | `splunk_search` |
| `clickhouse` | 内置 fetch | `sql` |
| `hive` | 内置 fetch | `sql` |
| `mongodb` | 内置 fetch | `mongo_query` |
| `redis` | 内置 fetch | `redis_query` |
| `agent_stream` | 本地样本 / 外部执行器 | `stream_query` |
| `syslog_ingest` | 本地样本 / 外部执行器 | `syslog_query` |
| `object_storage` | 本地样本 / 外部执行器 | `object_query` |
| `aws_cloudwatch` | 内置 fetch / 外部执行器 | `cloudwatch_query` |
| `aws_s3_logs` | 内置 fetch / 外部执行器 | `object_query` |
| `azure_monitor` | 内置 fetch / 外部执行器 | `kql` |
| `gcp_logging` | 内置 fetch / 外部执行器 | `gcp_logging_filter` |
| `tencent_cls` | 内置 fetch / 外部执行器 | `cls_query` |
| `huawei_lts` | 内置 fetch / 外部执行器 | `lts_query` |

内置 connector 的权威元数据在 [`../configure/connector-catalog.json`](../configure/connector-catalog.json)，包含 query key、runtime、依赖策略、`onboarding_template` 和 `onboarding_profile`。Python 注册表 [`../../src/skills/_shared/data-access/connector_registry.py`](../../src/skills/_shared/data-access/connector_registry.py) 直接加载该合同；私有资产目录缺少它时读取仓库公开 Catalog，不再维护 Python 兜底常量。实际 fetch 分发在 [`../../src/skills/_shared/data-access/extended_fetch.py`](../../src/skills/_shared/data-access/extended_fetch.py)。

## Connector SDK 策略矩阵

“内置支持”表示平台内置了 `connector_type`、query key、onboarding 模板和 fetch 路由；**不表示默认安装了所有厂商官方 SDK**。默认依赖只放高频、轻量、稳定的包；其它 SDK/驱动采用 lazy import、REST fallback、插件或外部执行器。

| connector | 默认/可选依赖策略 | 当前 live fetch 路径 | 没装 SDK/驱动时 |
|---|---|---|---|
| `sls` | 默认安装 `aliyun-log-python-sdk` | 官方 SLS SDK | 缺依赖时报明确安装提示 |
| `ssh_file` / `ssh_command` | 默认安装 `paramiko` | Paramiko SSH 只读命令/文件 | 缺依赖时报明确安装提示 |
| `database_ro` MySQL/PostgreSQL | 默认安装 `pymysql`、`psycopg[binary]` | 对应 DB driver，select-only 防护 | 缺依赖时报明确安装提示 |
| `database_ro` Oracle/SQL Server | 可选 `oracledb`、`pyodbc` lazy import | 对应 DB driver，select-only 防护 | 缺依赖时报明确安装提示 |
| `database_ro` SQLite | Python 标准库 `sqlite3` | 只读 SQLite URI | 不需要额外 SDK |
| `http_api` / `es` / `splunk` | 不默认安装厂商 SDK | HTTP/REST API | 不需要 SDK，按 connector 配置访问 |
| `local_file` | Python 标准库 | 本地文件读取与解析 | 不需要 SDK |
| `clickhouse` / `hive` | 可选 `clickhouse-connect`、`PyHive` lazy import | 对应官方/社区 driver | 缺依赖时报明确安装提示 |
| `mongodb` / `redis` | 可选 `pymongo`、`redis` lazy import | 对应官方 driver | 缺依赖时报明确安装提示 |
| `aws_cloudwatch` / `aws_s3_logs` | 可选 `boto3` lazy import，不进默认依赖 | 本地样本 → 外部执行器 → `boto3` → SigV4 REST fallback | 没装 `boto3` 自动走 REST fallback |
| `azure_monitor` | 不默认安装 Azure SDK | 本地样本 → 外部执行器 → OAuth + Log Analytics REST | 不需要 Azure SDK；也可用外部执行器封装 SDK |
| `gcp_logging` | 可选 `google-auth` lazy import | 本地样本 → 外部执行器 → `google-auth` 取 token → Cloud Logging REST | token 已配置则不需要 SDK；服务账号缺依赖时报提示 |
| `tencent_cls` | 不默认安装腾讯云 SDK | 本地样本 → 外部执行器 → TC3 签名 REST | 不需要 SDK；也可用外部执行器封装 SDK |
| `huawei_lts` | 不默认安装华为云 SDK | 本地样本 → 外部执行器 → Token/AKSK 签名 REST | 不需要 SDK；也可用外部执行器封装 SDK |
| `agent_stream` / `syslog_ingest` / `object_storage` | 不绑定厂商 SDK | 本地样本 / 外部执行器 / 专用轻量 fetcher | 无 endpoint 时返回 planned meta |

推荐判断口径：

- 想要最小开源核心：使用默认依赖 + REST fallback + 本地样本。
- 想用官方 SDK 但不污染核心：写 connector 插件，或写外部执行器。
- 需要把某个 SDK 变成内置体验：在对应 `*_fetch.py` 里加 optional lazy import，并保留无 SDK fallback。

## 不改 Python 新增 connector_type

现在有两条不改核心代码的路径：

- 在 `dataasset/configure/external-connectors.json` 注册配置型 connector，用于本地样本或外部 HTTP 执行器。
- 在 `src/dataasset/plugins/connectors/<plugin_name>/` 增加 connector 插件，用本地代码或 SDK 执行，但不把依赖塞进核心。

先在 [`../configure/external-connectors.json`](../configure/external-connectors.json) 注册类型：

```json
{
  "connectors": {
    "datadog_logs": {
      "query_key": "datadog_query",
      "runtime": "local_or_external_executor",
      "description": "Datadog external executor",
      "onboarding_template": "external_generic",
      "onboarding_profile": {
        "label": "Datadog Logs",
        "fields": ["endpoint", "sample_file"],
        "required": [],
        "defaults": {"sample_file": "examples/log-format-discovery/waf-jsonl.sample"},
        "default_asset_type": "waf_alert",
        "template_params": ["src_ip", "time_start", "time_end", "limit"],
        "template_defaults": {"limit": 1000},
        "default_query": "source:security @network.client.ip:{src_ip} limit {limit}",
        "hint": "使用本地样本或外部执行器。"
      }
    }
  }
}
```

当前已经注册的可复制配置型厂商示例包括 `datadog_logs`、`okta_system_log`、
`cloudflare_logs`、`crowdstrike_fdr`、`microsoft_entra_signin`、
`google_workspace_audit`、`microsoft_defender_xdr` 和 `sentinelone_events`。

然后在 onboarding 配置里直接使用这个 `connector_type`。`asset apply` 使用 manifest 声明的 `onboarding_template`，并自动注入同一 manifest 里的 `query_key`；Studio 表单使用其中的 `onboarding_profile`。

```json
{
  "name": "demo-datadog",
  "connector_type": "datadog_logs",
  "asset_type": "waf_alert",
  "connector": {
    "config": {
      "endpoint": "https://executor.example.com/datadog",
      "sample_file": "examples/log-format-discovery/waf-jsonl.sample"
    }
  },
  "template": {
    "datadog_query": "source:security src_ip:{src_ip}"
  }
}
```

运行语义：

- 配置 `sample_file`、`sample_dir`、`base_path` 或本地 `bucket/prefix` 时，使用内置本地样本执行器。
- 配置 `endpoint` 或 `base_url` 时，SecWeaver 会 POST `query`、`params` 和去敏后的 connector `config` 给外部程序。
- 两者都没有配置时，fetch 返回计划元信息，不会因为未知类型直接失败。

外部执行器协议与 AWS CloudWatch 可选示例见
[`../../docs_dev/05-external-connector-executors.zh-CN.md`](../../docs_dev/05-external-connector-executors.zh-CN.md)。
CloudWatch 可以这样启动：

```bash
python3 -m pip install boto3
python3 examples/executors/aws_cloudwatch_executor.py --port 8788
```

然后把 `connector.config.endpoint` 配成 `http://127.0.0.1:8788/fetch`。

插件 connector 可在 `src/dataasset/plugins/connectors/` 下增加 `plugin.json` 和 `fetch.py`，也可以用 `SECWEAVER_PLUGIN_ROOT` 指向外部代码目录。示例类型 `demo_plugin_logs` 来自 [`../../src/dataasset/plugins/connectors/demo_plugin_logs/plugin.json`](../../src/dataasset/plugins/connectors/demo_plugin_logs/plugin.json)，可这样预览：

也可以先用 CLI 生成插件骨架：

```bash
python3 src/secweaver.py connector plugin init vendor_logs \
  --query-key vendor_query
```

插件提交前先跑契约校验：

```bash
python3 src/secweaver.py connector plugin validate src/dataasset/plugins/connectors/vendor_logs
```

```bash
python3 src/secweaver.py asset apply \
  -f dataasset/onboarding/examples/vendor-quickstart-plugin-connector.json \
  --dry-run
```

协议细节见 [`../../docs_dev/04-connector-plugins.zh-CN.md`](../../docs_dev/04-connector-plugins.zh-CN.md)。

每个 `data_sources[]` 都支持三个深度合并的覆盖段：

| 段落 | 用途 |
|---|---|
| `connector` | 通用参数之外的连接细节，例如嵌套 `config`、拉取限制、TLS 设置或源侧特殊选项 |
| `asset` | 运行时解析方式，例如 `text_parser`、`schema.fields`、`schema.time_field`、`field_aliases`、`coverage.zones/apps/hosts`、标签和状态元数据 |
| `template` | 查询模板行为，例如 `params`、`defaults`、`sls_query`、`es_query`、SQL 文本、描述和自定义 `template_id` |

这些段会在占位符替换之后合并进生成的 connector、asset 和 query template JSON。私有部署值请放在私有配置文件中，提交到仓库的示例继续使用 `YOUR_*` 或 `vault://...` 占位符。

单个数据源也可以继续用命令参数生成：

```bash
python3 src/secweaver.py asset init \
  --connector-type sls \
  --asset-type waf_alert \
  --name demo-waf \
  --project YOUR_SLS_PROJECT \
  --logstore YOUR_LOGSTORE
```

如需审阅生成内容但不写文件：

```bash
python3 src/secweaver.py asset init \
  --connector-type sls \
  --asset-type waf_alert \
  --name demo-waf \
  --dry-run
```

也可以手工复制对应 `connector_type` 目录下的三个文件，全局替换占位符后写入 `dataasset/`：

| 占位符 | 说明 |
|---|---|
| `YOUR_CONN_ID` | 连接器 ID，如 `conn-sls-my-log` |
| `YOUR_ASSET_ID` | 资产 ID，如 `asset-my-log-prod` |
| `YOUR_SLS_PROJECT` / `YOUR_INDEX` | 真实 project、logstore 或 ES index |
| `YOUR_HOST` | SSH/DB 主机名 |
| `YOUR_HOST_ID` | 主机注册 ID，如 `host-web-01`（见 [hosts/](../hosts/)） |

## 目录

| 目录 | connector_type | 文件 |
|---|---|---|
| [sls/](sls/) | `sls` | connector.json · asset.json · template.snippet.json |
| [es/](es/) | `es` | 同上 |
| [ssh_file/](ssh_file/) | `ssh_file` | 同上 |
| [database_ro/](database_ro/) | `database_ro` | 同上 |
| [http_api/](http_api/) | `http_api` | 同上 |
| [local_file/](local_file/) | `local_file` | 同上 |
| [mongodb/](mongodb/) | `mongodb` | 同上 |
| [redis/](redis/) | `redis` | 同上 |
| [clickhouse/](clickhouse/) | `clickhouse` | 同上 |
| [hive/](hive/) | `hive` | 同上 |
| [splunk/](splunk/) | `splunk` | 同上 |
| [aws_cloudwatch/](aws_cloudwatch/) | `aws_cloudwatch` | 同上 |
| [aws_s3_logs/](aws_s3_logs/) | `aws_s3_logs` | 同上 |
| [azure_monitor/](azure_monitor/) | `azure_monitor` | 同上 |
| [gcp_logging/](gcp_logging/) | `gcp_logging` | 同上 |
| [tencent_cls/](tencent_cls/) | `tencent_cls` | 同上 |
| [huawei_lts/](huawei_lts/) | `huawei_lts` | 同上 |

## 接入流程（简）

```text
1. 编辑 dataasset/onboarding/examples/data-sources.sample.json（或你的私有配置副本）
2. 执行 secweaver asset apply --dry-run，审阅 connector / asset / template
3. 执行 secweaver asset apply，写入 dataasset/connectors/ + assets/ + query-templates/templates.json
4. 执行 secweaver validate --json --only-active
5. 新格式：asset status=discovery → discover.py + log-format-discovery Skill
6. discover.py ... --apply（或 --apply mapping.json）写入 field_aliases / schema / 模板
7. validate.py → test_connector.py → status active
```

连接测试可以走资产入口，也可以走 connector 统一入口：

```bash
python3 src/secweaver.py connector test YOUR_ASSET_ID --by-asset --dry-run
python3 src/secweaver.py connector test YOUR_ASSET_ID --by-asset --plan
```

格式发现一键写入见：

```bash
python3 src/skills/log-format-discovery/scripts/discover.py \
  --asset-id YOUR_ASSET_ID -i samples.json --apply --apply-dry-run

# 审阅后正式写入
python3 src/skills/log-format-discovery/scripts/discover.py \
  --asset-id YOUR_ASSET_ID -i samples.json --apply
```

如果是新的文本日志格式，可以先生成自定义 parser 草稿：

```bash
python3 src/secweaver.py asset discover-format YOUR_ASSET_ID \
  -i samples.log \
  --parser-id vendor-kv-log \
  --emit-parser dataasset/parsers/vendor-kv-log.json
```

**字段别名默认写入 `asset.field_aliases`**（per-asset 覆盖全局）；加 `--global-aliases` 则合并进 `evidence-minimum-fields.json`。

详见[完整数据源接入](../../docs_user/03-configure-data-sources.zh-CN.md) · [字段发现与归一化](../../docs_user/20-log-format-discovery.zh-CN.md) · [字段说明样例](../../docs_ai/asset-es-waf-prod-field-guide.zh-CN.md)

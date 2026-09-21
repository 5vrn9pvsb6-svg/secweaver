# 11. 数据源接入 UI 图文教程

**语言：** 简体中文（本文） | [English](11-onboarding-ui-walkthrough.md)

这篇教程面向运营同学：不改 Python，只通过页面和配置文件接入一个新数据源。

## 启动页面

先从仓库根目录准备环境：

```bash
make quickstart
source .venv/bin/activate
export DATAASSET_ROOT=dataasset
```

默认直接编辑 `dataasset/`。如需把本地配置与仓库样例隔离，可在写入配置和凭证前选择以下可选步骤：

```bash
if [ ! -e dataasset_my ]; then
  cp -R dataasset dataasset_my
fi
export DATAASSET_ROOT=dataasset_my
```

已有 `dataasset_my/` 保留原样。选择隔离目录后，后文配置路径中的 `dataasset/` 均替换为 `dataasset_my/`；`src/dataasset/` 是程序目录，不替换。
CLI、UI 和智能体必须使用同一资产根目录；新终端重新设置所选 `DATAASSET_ROOT` 并激活虚拟环境，桌面智能体不继承变量时在任务中明确指定。
无论选择哪个目录，Connector JSON 只保存凭证引用；真实密钥、私钥、加密凭证和客户配置不要提交公开仓库。

保存凭证前按[凭证指南](../dataasset/credentials/README.zh-CN.md)初始化 SOPS/age。

```bash
make ui
```

打开 `http://127.0.0.1:8765/onboarding.html`。UI 占用当前终端；后文 CLI 命令在另一已配置终端运行，或按 Ctrl+C 停止 UI 后运行。

## 路径 0：从 Quickstart 开始

页面顶部的 Quickstart 下拉会列出 `dataasset/onboarding/examples/*.json`。选择一个示例后点“载入示例”，右侧配置 JSON 会直接变成可预览配置；左侧表单会同步展示第一个数据源。

常用示例：

| 示例 | 适合场景 |
|---|---|
| `secweaver-saas-sls-proxy-assets.json` | SecWeaver SaaS SLS Proxy 的 8 个公开 Logstore、13 类逻辑资产 |
| `vendor-quickstart-cloudwatch.json` | AWS CloudWatch / CloudTrail |
| `vendor-quickstart-cloud-audit-siem.json` | AWS / Azure / GCP 审计 + Splunk ES |
| `vendor-quickstart-databases.json` | MySQL、SQL Server、SQLite 审计 |
| `vendor-quickstart-document-cache.json` | MongoDB + Redis |
| `vendor-quickstart-identity-edge-edr.json` | Okta、Cloudflare、CrowdStrike 外部执行器 |
| `vendor-quickstart-edr-identity-vendors.json` | Defender XDR、SentinelOne、CrowdStrike、Okta、Google Workspace、Entra |
| `vendor-quickstart-plugin-connector.json` | 本地 connector 插件 |

页面里的 **真实 Vendor 引导** 卡片是这些示例的快捷入口。点击卡片后，页面会直接把样例载入表单和右侧配置 JSON。卡片下方的详情区会展示：

- 数据源数量和 connector 类型
- 本地样本路径
- 建议操作步骤
- CLI dry-run 命令

常见真实厂商接入优先从这两张卡开始：

| 卡片 | 适合场景 |
|---|---|
| 云审计 + SIEM | 同时参考 AWS CloudTrail、Azure Activity / Entra、GCP Audit、Splunk ES notable 样例 |
| EDR + 身份源 | 接入 Defender XDR、SentinelOne、CrowdStrike、Okta、Google Workspace、Entra 等终端与身份源 |

Connector 能力目录支持搜索 `aws`、`splunk`、`defender`、`entra`、`plugin`，也可以按“内置 / 外置 / 插件”筛选，避免下拉项太多时找不到目标。

## 路径 A：接入内置 connector

适合 `sls`、`es`、`ssh_file`、`database_ro`、`http_api`、`splunk`、`clickhouse` 等已有类型。

1. 选择 `Connector 类型`
2. 页面会按 connector 类型只展示相关连接参数
3. 填凭证引用，例如 `vault://sls/security-readonly`
4. 填连接参数，例如 `project/logstore`、`url/index`、`database/collection`
5. 填 `Asset 类型`，例如 `waf_alert`
6. 填 `文本解析器`、字段列表、字段别名和覆盖范围
7. 填模板参数和 query
8. 点“生成配置”
9. 点“预览三件套”
10. 确认后点“写入 DataAsset”

写入前可以先复制已有样例：

```bash
python3 src/secweaver.py asset apply --output-dir "$DATAASSET_ROOT" \
  -f dataasset/onboarding/examples/data-sources.sample.json \
  --dry-run
```

## 路径 B：接入 CloudWatch 外部执行器

先点 `AWS CloudWatch / CloudTrail` 卡片。卡片详情会展示建议步骤、样本路径和 dry-run 命令；载入示例后，表单会自动切换到 `aws_cloudwatch`。

选择 `aws_cloudwatch` 后，connector guide 会提示：

- 运行方式：内置 fetch / 可选外部执行器；本节演示外部执行器方式，内置查询无需启动该服务
- query key：`cloudwatch_query`
- 可选执行器：`examples/executors/aws_cloudwatch_executor.py`

![CloudWatch 外部执行器配置](images/onboarding-cloudwatch.png)

启动可选执行器：

```bash
python3 -m pip install boto3
python3 examples/executors/aws_cloudwatch_executor.py --port 8788
```

页面中重点填写：

| 字段 | 示例 |
|---|---|
| Endpoint | `http://127.0.0.1:8788/fetch` |
| Region | `ap-southeast-1` |
| CloudWatch Log Group | `/aws/cloudtrail/organization` |
| 凭证引用 | `vault://aws/security-readonly` |
| Template Query | `cloudwatch_query` |

也可以直接用配置样例：

```bash
python3 src/secweaver.py asset apply --output-dir "$DATAASSET_ROOT" \
  -f dataasset/onboarding/examples/vendor-quickstart-cloudwatch.json \
  --dry-run
```

## 路径 C：新增一个配置型 connector_type

如果下拉框里还没有你的类型，例如 `vendor_logs`，先在：

```text
dataasset/configure/external-connectors.json
```

注册：

```json
{
  "vendor_logs": {
    "query_key": "vendor_query",
    "runtime": "local_or_external_executor"
  }
}
```

然后刷新 UI，下拉框会出现这个类型。没有专属 onboarding 目录时，平台会使用通用 external 模板生成三件套。

可参考：

```bash
python3 src/secweaver.py asset apply --output-dir "$DATAASSET_ROOT" \
  -f dataasset/onboarding/examples/vendor-quickstart-external-connector.json \
  --dry-run
```

## 路径 D：新增 connector 插件

如果 connector 需要本地代码、SDK 或自定义解析，但不想进入核心依赖，可以在这里增加插件目录：

```text
src/dataasset/plugins/connectors/<plugin_name>/
```

示例 `demo_plugin_logs` 已经内置，刷新 UI 后会出现在 Connector 类型下拉里。可这样预览：

```bash
python3 src/secweaver.py asset apply --output-dir "$DATAASSET_ROOT" \
  -f dataasset/onboarding/examples/vendor-quickstart-plugin-connector.json \
  --dry-run
```

manifest 和 stdio-json 协议见 [`docs_dev/04-connector-plugins.zh-CN.md`](../docs_dev/04-connector-plugins.zh-CN.md)。

## 写入后检查

写入后运行：

```bash
python3 src/dataasset/validate.py --json --only-active
python3 src/dataasset/test_connector.py YOUR_ASSET_ID --by-asset --plan --dry-run
```

如果是新日志格式，先保持 `status: discovery`，再走格式发现：

```bash
python3 src/skills/log-format-discovery/scripts/discover.py \
  --asset-id YOUR_ASSET_ID \
  -i examples/your-sample.jsonl \
  --apply --apply-dry-run
```

## 常见错误

| 现象 | 处理 |
|---|---|
| 下拉框没有你的 connector_type | 检查 `external-connectors.json` 或插件 `plugin.json` 是否注册，刷新页面 |
| 预览失败提示 unknown field | 字段不在 `data-sources.schema.json`，放到 `connector.config` 或补 schema |
| query key 不对 | 看页面提示，例如 CloudWatch 应写 `cloudwatch_query` |
| active 校验失败 | 新源先用 `discovery` 或 `draft`，确认字段和连通性后再 active |
| 外部执行器没有数据 | 先用 `sample_file` 验证字段和模板，再接真实 endpoint |

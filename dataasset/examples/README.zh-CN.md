# DataAsset 字段参考示例

本目录存放**非生产**的字段参考资产，供接入新数据源时对照「平台支持哪些列、如何命名」。

## 文件

| 文件 | 说明 |
|---|---|
| [`reference-assets.json`](reference-assets.json) | **单一合并资产** `asset-example-all-fields`：`schema.fields` 含公开 Schema 中全部 `asset_type` 的去重字段并集 |
| [`connectors/`](connectors/) | 非生产示例连接器，供接入新 connector 类型或复制模板时参考；不会进入正式 `catalog.json` |
| [`hosts/`](hosts/) | 脱敏主机资产模板，默认 inactive，不进入正式 demo registry |
| [`networks/`](networks/) | 脱敏网络区域模板，默认 inactive，不进入正式 demo registry |

开箱即用配置样例见 [`../onboarding/examples/`](../onboarding/examples/)：

| 样例 | 说明 |
|---|---|
| `secweaver-saas-sls-proxy-assets.json` | SecWeaver SaaS SLS Proxy 的 8 个公开 Logstore、13 类逻辑资产模板 |
| `vendor-quickstart-cloudwatch.json` | AWS CloudWatch Logs + 外部执行器 |
| `vendor-quickstart-siem-warehouse.json` | Splunk 和 ClickHouse |
| `vendor-quickstart-external-connector.json` | 配置型新增 connector_type |
| `vendor-quickstart-databases.json` | MySQL、SQL Server、SQLite 只读审计 |
| `vendor-quickstart-document-cache.json` | MongoDB 文档日志 + Redis 资产缓存 |
| `vendor-quickstart-identity-edge-edr.json` | Okta、Cloudflare、CrowdStrike 外部接入 |
| `vendor-quickstart-plugin-connector.json` | 本地 connector 插件示例 |

## 结构

以下仅为结构示意，完整可复制数据请打开上述 JSON 文件：

```text
{
  "version": "2.0",
  "asset": { "...": "可直接复制到 dataasset/assets/ 的完整资产 JSON" },
  "_derived": {
    "fields_by_asset_type": { "waf_alert": ["..."], "..." },
    "correlation_keys_by_asset_type": { "..." },
    "all_correlation_keys": ["..."]
  }
}
```

- **`asset`**：合并后的全量字段资产（`field_aliases` 已合并）
- **`_derived`**：按 `asset_type` 拆分的字段子集与关联键推导（只读索引，勿写入正式资产）

合并资产的 `asset_type` 固定为 `linux_syslog`（仅满足 JSON Schema）；接入真实源时请改为对应类型并**删减**无关 `fields`。

## 字段来源

由 [`../../src/dataasset/build_field_reference.py`](../../src/dataasset/build_field_reference.py) 从以下规范合并生成：

1. [`../configure/evidence-minimum-fields.json`](../configure/evidence-minimum-fields.json)
2. [`../assets/correlation-matrix.json`](../assets/correlation-matrix.json)
3. 各类型常见源字段名（`ip`、`host_name`、`trace_id` 等）

## 使用方式

```bash
# 重新生成（evidence / matrix 变更后）
python3 src/dataasset/build_field_reference.py
```

接入新源时：

1. 打开 `reference-assets.json` → 复制 `asset` 对象  
2. 对照 `_derived.fields_by_asset_type.<你的类型>` 删减 `schema.fields`  
3. 改 `asset_id`、`asset_type`、`connector_id`、`query_template_ids`、`status`  
4. 写入 `dataasset/assets/`

**勿**将 `asset-example-all-fields` 加入生产 `bundles`。

## 覆盖契约

类型集合以 [`data-asset.schema.json`](../schema/data-asset.schema.json) 的 `asset_type.enum` 为准，不能以手工类型表或文档中的数量代替。生成器对最小字段规范中的未知类型报错；尚无专属最小字段规范的类型采用基础字段和常见源字段，不代表完整厂商字段清单。Matrix 用于推导关联键，不自动补齐实际源列。更新 Schema、字段规范或生成器后重新生成并运行 `python3 -m unittest tests.test_field_reference`。

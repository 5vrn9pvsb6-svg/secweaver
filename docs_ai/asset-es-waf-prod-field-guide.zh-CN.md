# Elasticsearch WAF 资产字段指南

**语言：** [English](asset-es-waf-prod-field-guide.md) | 简体中文（本文）

本文解释公开示例 [`asset-es-waf-prod.json`](../dataasset/assets/asset-es-waf-prod.json) 与
[`conn-es-waf-prod.json`](../dataasset/connectors/conn-es-waf-prod.json)。适用于已有 ES WAF
日志的字段接入，不负责安装 ES，也不把示例资产视为可查询的生产资产。
首次接入按[数据源配置指南](../docs_user/03-configure-data-sources.zh-CN.md)操作。

## 1. 配置目录与使用边界

默认直接修改 `dataasset/`。需要隔离时，可从仓库根目录复制一次并选择该目录：

```bash
if [ ! -e dataasset_my ]; then
  cp -R dataasset dataasset_my
fi
export DATAASSET_ROOT=dataasset_my
```

已有目录保留原样。隔离使用时，下文 `dataasset/` 配置路径替换为 `dataasset_my/`，
程序路径 `src/dataasset/` 不替换；CLI、UI 和智能体使用同一个 `DATAASSET_ROOT`。
切回默认目录使用 `export DATAASSET_ROOT=dataasset`。

真实凭证存入所选目录的 SOPS Vault，Connector 只保存 `credentials_ref`。
无论选择哪个目录，都不要提交真实密钥、私钥、加密凭证或客户配置。
文件名中的 `prod` 和 `environment: production` 是示例命名与分类，不代表已连接生产系统。

## 2. 资产字段

| 字段 | 本例 | 配置含义 |
|---|---|---|
| `asset_id` | `asset-es-waf-prod` | 唯一 ID，匹配 `^asset-[a-z0-9-]+$` |
| `name` | Elasticsearch WAF 安全告警 | 人类可读名称 |
| `asset_type` / `domain` | `waf_alert` / `D1` | WAF/网关安全告警及其数据域 |
| `owner_team` | `security-ops` | 责任团队 |
| `environment` | `production` | 可选 `production`、`staging`、`development` |
| `status` | `draft` | 接入中；完成校验和真实查询验收后再改为 `active` |
| `connector_id` | `conn-es-waf-prod` | 引用 ES Connector |
| `coverage.hosts` | `[]` | 日志来源 IP 数组；空数组不声明具体主机覆盖 |
| `query_template_ids` | `waf_es_by_src_ip_time` | 引用与 `waf_alert` 和 `es` 匹配的查询模板 |
| `sensitivity` | `internal` | 治理分类；不自动执行脱敏 |
| `masking` | `payload: truncate_500` | 归一化后截断该字段，不代表所有敏感字段都已处理 |
| `field_aliases` | 本例未配置 | 可选的源字段 → canonical 映射，优先于全局同名映射 |
| `tags` / `description` | 见 JSON | 分类与接入备注 |

`coverage.hosts` 只能填写来源 IP，例如 `192.0.2.10`，不能填写 `web-01`、FQDN 或别名。
主机名称及别名登记在 `hosts/` 对象中。当前示例没有 `coverage.zones`、`coverage.apps`，
不要从旧字段指南复制这两项作为本例必填配置。

资产完整字段、当前 `asset_type` 枚举与扩展能力以
[DataAsset Schema](../dataasset/schema/data-asset.schema.json) 为准。
多连接器聚合使用 `connector_ids`、`aggregate.max_events` 和 `aggregate.dedupe_by`；
仅当确需合并多个来源时配置，详见[资产设计](../docs_dev/09-data-asset-design.zh-CN.md)。

## 3. 字段契约与归一化

| 字段 | 本例 | 含义 |
|---|---|---|
| `schema.fields` | 见资产 JSON | 声明可用字段，需用真实样本核对 |
| `schema.time_field` | `timestamp` | 归一化后的时间字段，不是 ES 源字段 `@timestamp` |
| `schema.retention_days` | `30` | 后端保留期声明；不会修改 ES 保留策略 |
| `schema.correlation_keys` | 未配置 | 已废弃；由关联矩阵与 `schema.fields` 推导，不再手写 |

WAF 的最小字段为 `src_ip`、`timestamp`、`url`、`action`；`payload` 强烈建议提供。
共同必需字段还包括 `evidence_id`，由归一化流程处理。完整清单见
[evidence-minimum-fields.json](../dataasset/configure/evidence-minimum-fields.json)。

源字段名称不一致时，在当前资产配置映射，例如：

```json
{
  "field_aliases": {
    "client_ip": "src_ip",
    "request_uri": "url"
  }
}
```

映射只重命名已有信息，不能补出源日志未记录的字段。优先维护资产级别名；只有共享
映射确实适用于所有相关资产时才修改全局 `evidence-minimum-fields.json`。
ES 查询仍使用源索引字段，证据研判使用归一化字段；配置别名不会自动改写查询模板。

## 4. Connector 与查询模板

| Connector 字段 | 本例 | 接入要求 |
|---|---|---|
| `connector_type` | `es` | 与资产和模板的类型兼容 |
| `status` | `draft` | 与资产状态分别管理 |
| `credentials_ref` | `vault://es/security-readonly` | SOPS Vault 中的只读账号引用 |
| `config.url` | `https://es.example.com:9200` | 替换成获授权的真实 HTTPS 地址 |
| `config.index` | `logs-waf-*` | 替换成获授权的索引或 pattern |
| `config.time_field` | `@timestamp` | ES 源时间字段 |
| `constraints.max_records_per_request` | `2000` | 单次请求条数上限 |
| `constraints.request_timeout_sec` | `30` | 请求超时秒数 |

TLS 默认校验证书，私有 CA 使用 `config.ca_file`，不要用关闭校验处理证书错误。
Connector 类型不是本文维护的固定枚举：内置类型、依赖和执行模式见
[Connector Catalog](../dataasset/configure/connector-catalog.json)，外部类型见
[扩展指南](../docs_dev/04-connector-plugins.zh-CN.md)。

查询模板来自 [templates.json](../dataasset/query-templates/templates.json)。本例使用
`waf_es_by_src_ip_time`，参数包括 `src_ip`、`time_start`、`time_end` 和可选 `limit`。
时间包含时区，IP 与调查窗口必须来自实际授权任务。下例只是请求结构，不能代替生产参数：

```json
{
  "asset_id": "asset-es-waf-prod",
  "template_id": "waf_es_by_src_ip_time",
  "params": {
    "src_ip": "203.0.113.10",
    "time_start": "2026-06-21T08:00:00+08:00",
    "time_end": "2026-06-21T20:00:00+08:00",
    "limit": 500
  }
}
```

## 5. 脱敏与生命周期

`masking` 支持字段名或点号路径，规则包括 `redact`、`truncate_<N>`、`phone`、
`id_card` 及 Schema 中定义的对象形式。缺省或空配置保留原值；`pii_fields` 只作标注。
检查源字段、别名和嵌套副本，详见[真实数据使用说明](../docs_user/community-release-and-data-safety.zh-CN.md)。

新格式先以 `discovery` 进入格式发现，再转为 `draft`。本例已有已知格式，以 `draft`
开始；校验、模板预览和真实事件查询验收通过后，再激活 Connector 与 Asset。
仅改成 `active` 或查询返回空结果，都不代表数据接入成功。

## 6. 接入检查清单

1. 按接入指南准备 Python、SOPS/age 和所选资产目录，默认是 `dataasset/`。
2. 编辑该目录的 `connectors/conn-es-waf-prod.json`，填写真实地址、索引、时间字段和必要 CA。
3. 在该目录的凭证库保存 `vault://es/security-readonly`，不把密码写入 JSON 或提示词。
4. 对照真实样本核对资产字段、来源 IP 和资产级别名，检查模板使用的 ES 源字段。
5. 在仓库根目录运行 `.venv/bin/python src/secweaver.py validate`；保持所选 `DATAASSET_ROOT`。
6. 按[查询验收与启用](../docs_user/03-configure-data-sources.zh-CN.md#查询验收与启用)先预览查询，再确认一条已知事件及其字段，最后激活。

## 7. 复制为其他资产指南

保留资产用途、配置目录、关键字段、查询参数、失败边界和验收步骤。完整枚举与运行时
契约链接到 Schema、Catalog 和查询模板，不复制一份容易过时的“全集”。

更新：2026-09-16。机器可读契约优先于本文说明。

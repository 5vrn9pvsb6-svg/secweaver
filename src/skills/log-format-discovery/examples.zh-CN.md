# 格式发现 — 可复现样例

从仓库根目录运行；目标 `asset-waf-api-prod` 是公开的 `status=discovery` 示例。以下预处理和应用预览不查询真实数据，也不写配置。

## 1. 读取离线样本并生成建议

```bash
python3 src/skills/log-format-discovery/scripts/discover.py \
  --asset-id asset-waf-api-prod \
  -i src/skills/log-format-discovery/samples/waf-jsonl.example \
  --pretty -o /tmp/discovery-waf.json --prompt /tmp/discovery-waf-prompt.md
```

## 2. 审阅映射

预处理结果中的 `derived_correlation_keys` 由 matrix 和字段推导，只读查看，不复制进 `proposed_asset_schema` 或资产 JSON。运营只维护实际字段及映射；不要手写旧 `correlation_keys`。

下面是满足 [output-schema.json](output-schema.json) 的最小映射示例。按实际样本审阅别名和字段后保存为 `/tmp/discovery-waf-mapping.json`。文件内 `asset_id` 必须与命令目标一致；这里没有展示所有可选建议，也不表示可以直接激活：

```json
{
  "asset_id": "asset-waf-api-prod",
  "asset_type": "waf_alert",
  "proposed_field_aliases": {
    "rule_action": "action",
    "hostname": "host"
  },
  "proposed_asset_schema": {
    "fields": [
      "src_ip",
      "timestamp",
      "url",
      "action",
      "host",
      "payload"
    ],
    "time_field": "timestamp"
  },
  "implementation_checklist": [
    "Review aliases against actual samples",
    "Preview changes before applying",
    "Validate and test connectivity before activation"
  ],
  "confidence": "medium"
}
```

## 3. 预览、写入与晋升

```bash
python3 src/skills/log-format-discovery/scripts/discover.py \
  --asset-id asset-waf-api-prod \
  -i src/skills/log-format-discovery/samples/waf-jsonl.example \
  --apply /tmp/discovery-waf-mapping.json --apply-dry-run
```

审阅预览后，去掉 `--apply-dry-run` 才会写入当前 `DATAASSET_ROOT`（默认 `dataasset/`），并默认将 discovery 提升为 draft。需要隔离时，先按[配置指南](../../../docs_user/03-configure-data-sources.zh-CN.md)准备 `dataasset_my/`。通过静态校验后，还须配置授权数据源、完成真实连通与取数验收，才能提升 active；离线样本通过不代表线上就绪。

```bash
python3 src/secweaver.py validate --json
python3 src/dataasset/test_connector.py asset-waf-api-prod --by-asset --dry-run \
  --params '{"src_ip":"203.0.113.10","time_start":"2026-06-21T09:00:00+08:00","time_end":"2026-06-21T10:00:00+08:00"}'
```

## 4. 已有 active 资产如何改字段

通常维护资产的 `field_aliases`、`text_parser` 所引用的解析器 JSON 或查询模板，不需要修改 Python normalizer。格式发现默认面向 discovery 资产；不要为了绕过状态检查随意改线上状态。先在隔离资产库审阅变更，运行上述静态检查和查询计划预览，再在授权范围内去掉连接测试的 `--dry-run` 验证真实数据。仅新增解析能力且配置无法表达时，才走开发者扩展流程。

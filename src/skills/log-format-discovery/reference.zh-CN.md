# 格式发现 — 参考

> [日志格式发现设计.md](../../../docs_dev/20-log-format-discovery-design.md) | [日志格式发现.md](../../../docs_user/20-log-format-discovery.md)

## dataasset `discovery` 状态

| 问题 | 答案 |
|---|---|
| 处理哪些数据源？ | **仅** `dataasset/assets/*.json` 中 `status: discovery` |
| 其他资产？ | draft/active/disabled **不处理** |
| 如何入队？ | 新建或修改资产，设 `"status": "discovery"` |
| 如何出队？ | 映射完成后 `discovery` → `draft` → `active` |
| CLI | `--asset-id`（必填）或 `--list-discovery` |

## 规范对照

| 规范文件 | 本 Skill 产出如何写入 |
|---|---|
| `dataasset/assets/{asset_id}.json` | 更新 discovery 资产的 schema、template_ids、status |
| `configure/text-log-parsers.json` | 内置 text_parser 清单 |
| `parsers/*.json` | 自定义 line_regex（运营可编辑） |
| `configure/evidence-minimum-fields.json` | 全局 `field_aliases` |
| `query-templates/templates.json` | 新模板（若需要） |

## discover.py 报告字段

```json
{
  "asset_id": "asset-waf-api-prod",
  "dataasset_context": {
    "discovery_asset": { "status": "discovery", "fields": [] },
    "matching_templates": []
  },
  "discovery_asset_hints": {
    "current_fields": [],
    "current_template_ids": []
  }
}
```

## 验证

```bash
python3 src/dataasset/validate.py --sync-catalog
python3 src/dataasset/test_connector.py <asset_id> --by-asset --dry-run
```

discovery 资产校验较宽松（模板匹配非强制）；晋升 draft/active 后按完整规则校验。

# 自定义文本日志解析器（可选）

当内置 `text_parser`（`syslog_auth` / `nginx_combined`）不满足时，在此目录新增 JSON，**不要改** `src/skills/_shared/data-access/` 下的 Python。

可以从样本日志生成草稿：

```bash
python3 src/secweaver.py asset discover-format YOUR_ASSET_ID \
  -i samples.log \
  --parser-id vendor-kv-log \
  --emit-parser dataasset/parsers/vendor-kv-log.json
```

生成的 `line_regex` 是草稿，请先审阅命名捕获组，再把资产的 `text_parser` 指向该 `parser_id`。

## 文件格式

`dataasset/parsers/my-format.json`：

```json
{
  "parser_id": "my-format",
  "description": "pipe 分隔 key=value",
  "line_regex": "^(?P<timestamp>\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}) \\| user=(?P<user>\\S+) \\| ip=(?P<src_ip>\\S+)",
  "timestamp_field": "timestamp",
  "timestamp_formats": ["%Y-%m-%d %H:%M:%S"]
}
```

- `line_regex`：须含 **命名捕获组**，组名即 canonical 字段名（或与 `field_aliases` 对齐的源名）
- `timestamp_formats`：可选，用于 ISO 归一化

## 资产引用

```json
{
  "asset_id": "asset-my-custom-log",
  "text_parser": "my-format"
}
```

内置解析器见 [`configure/text-log-parsers.json`](../configure/text-log-parsers.json)。

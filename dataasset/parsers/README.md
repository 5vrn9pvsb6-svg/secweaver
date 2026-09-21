# Custom Text Log Parsers (Optional)

**Languages:** English (this page) | [简体中文](README.zh-CN.md)

When built-in `text_parser` options (`syslog_auth` / `nginx_combined`) are not enough, add JSON files in this directory. **Do not modify** Python under `src/skills/_shared/data-access/`.

Generate a draft from sample logs:

```bash
python3 src/secweaver.py asset discover-format YOUR_ASSET_ID \
  -i samples.log \
  --parser-id vendor-kv-log \
  --emit-parser dataasset/parsers/vendor-kv-log.json
```

The generated `line_regex` is a draft. Review named capture groups before pointing an asset's `text_parser` at the new `parser_id`.

## File format

`dataasset/parsers/my-format.json`:

```json
{
  "parser_id": "my-format",
  "description": "pipe-delimited key=value",
  "line_regex": "^(?P<timestamp>\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}) \\| user=(?P<user>\\S+) \\| ip=(?P<src_ip>\\S+)",
  "timestamp_field": "timestamp",
  "timestamp_formats": ["%Y-%m-%d %H:%M:%S"]
}
```

- `line_regex`: must include **named capture groups**; group names become canonical field names (or source names aligned with `field_aliases`)
- `timestamp_formats`: optional; used for ISO normalization

## Asset reference

```json
{
  "asset_id": "asset-my-custom-log",
  "text_parser": "my-format"
}
```

Built-in parsers: [`configure/text-log-parsers.json`](../configure/text-log-parsers.json).

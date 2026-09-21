# Connector 插件示例

**语言：** [English](README.md) | 简体中文（本文）

这个目录放本地 connector 插件。适合需要本地代码、厂商 SDK、自定义解析或特殊网络位置，但又不应该进入 SecWeaver 核心依赖的接入。

插件代码与 `DATAASSET_ROOT` 明确分离。运营侧自有插件可以设置
`SECWEAVER_PLUGIN_ROOT=/path/to/connectors`，指向仓库外的插件代码目录。

## 内置示例

| 插件 | connector_type | 用途 |
|---|---|---|
| [`demo_plugin_logs/`](demo_plugin_logs/) | `demo_plugin_logs` | 最小 stdio-json 插件，供社区复制和契约测试 |

## 创建插件

```bash
python3 src/secweaver.py connector plugin init vendor_logs \
  --query-key vendor_query
```

然后修改：

- `plugin.json`：包含 `api_version`、`connector_type`、`query_key`、`runtime`、`protocol`、`entrypoint` 的 manifest。
- `fetch.py`：从 stdin 读取一个 JSON object，并向 stdout 输出一个 JSON object。
- `requirements.txt`：插件自己的 SDK 依赖。

## 校验

```bash
python3 src/secweaver.py connector plugin validate src/dataasset/plugins/connectors/vendor_logs
python3 src/secweaver.py connector plugin validate --json
```

完整文档见：[`../../../../docs_dev/04-connector-plugins.zh-CN.md`](../../../../docs_dev/04-connector-plugins.zh-CN.md)。

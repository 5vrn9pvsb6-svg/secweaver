# Connector 插件

**语言：** 简体中文（本文） | [English](04-connector-plugins.md)

Connector 插件适合“不应该放进 SecWeaver 核心依赖，但需要被平台发现并执行”的接入。一个插件就是本地目录里的 manifest 和一个小程序。

开始前先在仓库根目录运行一次 `make quickstart`。下文命令直接使用
`.venv/bin/python`，确保插件校验使用仓库虚拟环境。

## 目录结构

```text
src/dataasset/plugins/connectors/<plugin_name>/
  plugin.json
  fetch.py
  requirements.txt
  README.md
```

内置示例见 [`../src/dataasset/plugins/connectors/demo_plugin_logs/`](../src/dataasset/plugins/connectors/demo_plugin_logs/)。
插件代码不再放到 `DATAASSET_ROOT`。运营侧自有插件目录可在启动 CLI 或 UI
前设置 `SECWEAVER_PLUGIN_ROOT=/path/to/connectors`。

也可以用 CLI 生成骨架：

```bash
.venv/bin/python src/secweaver.py connector plugin init vendor_logs \
  --query-key vendor_query
```

生成后再替换 `fetch.py` 中的样例事件块，把 SDK 依赖写进插件目录自己的 `requirements.txt`。

## Manifest

```json
{
  "name": "Vendor Logs",
  "api_version": "1.0",
  "connector_type": "vendor_logs",
  "query_key": "vendor_query",
  "runtime": "plugin",
  "protocol": "stdio-json",
  "entrypoint": "fetch.py",
  "timeout_sec": 30,
  "python": ".venv/bin/python"
}
```

必填字段：`api_version: "1.0"`、`connector_type`、`query_key`、`runtime: "plugin"`、`protocol: "stdio-json"` 和 `entrypoint`。

`python` 可选。不填时使用当前 Python；填写时可指向插件目录里的虚拟环境，让 SDK 依赖留在插件里，不污染核心依赖。

插件发现、CLI 校验和运行时执行共用
[`plugin_contract.py`](../src/dataasset/plugin_contract.py)。可选 `timeout_sec`
在 CLI 和运行时均默认 **30 秒**。显式指定 `--timeout-sec`（冒烟测试）或
Connector 的 `constraints.request_timeout_sec`（运行时）可覆盖该值。
使用正整数秒；布尔值、小数、零和 null 会被拒绝。超时后不自动重试本次请求。

## 契约校验

插件写好后先跑 manifest + stdio-json 冒烟校验：

```bash
.venv/bin/python src/secweaver.py connector plugin validate src/dataasset/plugins/connectors/vendor_logs
.venv/bin/python src/secweaver.py connector plugin validate --json
.venv/bin/python src/secweaver.py connector plugin validate --no-exec --json
```

校验会检查：

- `plugin.json` 必填字段和 `api_version`。
- `entrypoint` 是否存在且没有逃逸插件目录。
- `protocol` 是否为 `stdio-json`。
- 入口程序是否能从 stdin 读取 JSON，并在 stdout 返回 JSON object。
- 返回体是否包含 `events`、`data`、`results`、`records`、`items` 或 `alerts` 之一。

`--no-exec` 不启动插件程序，仍检查 manifest、入口路径 containment（包括符号
链接）和可选解释器路径，但不证明响应格式或后端连通性。普通冒烟测试传入空凭证
和空配置，只验证协议，不验证真实身份认证。运维指定的解释器可以位于插件目录外，
入口文件则不能。只安装可信来源的插件：`shell=False` 不会沙箱化 Python 程序。

## 协议

SecWeaver 使用 `shell=False` 运行入口文件，在 stdin 写入一个 JSON object，并要求 stdout 返回一个 JSON object。

输入：

```json
{
  "connector": {},
  "credentials": {},
  "query": "vendor query text",
  "params": {
    "src_ip": "203.0.113.10",
    "limit": 100
  }
}
```

输出：

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

事件数组字段可使用 `events`、`data`、`results`、`records`、`items` 或 `alerts`。

按上述固定顺序选择第一个数组，即使为空也不回退，不合并多个别名数组。每条事件
必须是 JSON object。`meta` 可缺省或为 null，提供其他值时必须是 object。任何
非法事件或 metadata 都在应用行数限制前使整个响应失败，不再静默丢弃错误行。
JSON/响应格式错误不会回显 stdout。插件非零退出时，运行时始终丢弃 stdout，
只返回限长且递归替换凭证值后的 stderr；凭证值过短、无法可靠替换时，stderr
整段省略。插件仍不得向任何输出流写入凭证明文。

### 兼容与迁移

API 版本仍为 `1.0`，但发现阶段会先校验原始 manifest，再补充目录展示元数据。
旧插件如果依赖推测的 `api_version`、`runtime`、`protocol` 或 `entrypoint`，
需要补齐六个必填字段。非法 manifest 不会出现在发现结果中；运行
`connector plugin validate --json` 查看具体原因。修复混合类型的事件数组或
非 object metadata 后重新校验。运行时原先隐式的 60 秒超时统一改为 30 秒；
确需原时长时显式声明 `timeout_sec: 60`。

修改 manifest 后重启 CLI/UI 进程，或使用 UI 的 `/api/connectors/reload`
刷新缓存。模板 query key 判断读取刷新后的注册表，刷新成功后不需要重启进程。
不需要迁移 DataAsset 凭证或数据库。

## Onboarding 配置

加好 `plugin.json` 后，就能在 `dataasset/onboarding/examples/*.json` 中直接使用新类型：

```json
{
  "name": "demo-vendor-plugin",
  "connector_type": "vendor_logs",
  "asset_type": "waf_alert",
  "credentials_ref": "vault://vendor/security-readonly",
  "template": {
    "params": ["src_ip", "limit"],
    "defaults": {
      "limit": 100
    },
    "vendor_query": "src_ip={src_ip} limit {limit}"
  }
}
```

预览：

```bash
.venv/bin/python src/secweaver.py asset apply \
  -f dataasset/onboarding/examples/vendor-quickstart-plugin-connector.json \
  --dry-run
```

fetch 冒烟测试：

```bash
.venv/bin/python src/secweaver.py connector plugin validate src/dataasset/plugins/connectors/demo_plugin_logs
.venv/bin/python -m unittest src/skills/_shared/data-access/tests/test_plugin_connectors.py -v
.venv/bin/python -m unittest tests.test_plugin_contract -v
```

## 什么时候用插件

如果集成可以在同一台机器上运行，并且需要本地代码、SDK 或自定义解析，优先用插件。如果集成应该作为服务运行，或需要放在不同网络边界，优先用外部执行器。只有当能力足够通用、值得长期维护时，才放进核心内置 connector。

# 查询模板

AI / Claw **不得**自行拼接 SLS SQL 或 SSH 命令，应使用 `template_id` + `params`。

模板定义见：[templates.json](templates.json)，结构契约见
[`../schema/query-templates.schema.json`](../schema/query-templates.schema.json)。
平台按 `connector_type` 选择渲染字段：`sls_query` / `ssh_command` / `local_file_command` / `sql` / `http` / **`es_query`**。

## 模板如何选择

单 connector 资产：`template_select` 按 `asset.query_template_ids` 顺序，结合 `params` 与 `connector_type` 选第一条可用模板。

**多 connector 聚合**（资产含 `connector_ids`）：每个 connector **独立**选模板，组成 fetch plan：

```text
asset-ssh-internal
  ├── conn-sls-ssh-auth-web-01 (sls)     → ssh_auth_by_src_ip_time
  ├── conn-ssh-web-01-auth (ssh_file)    → ssh_file_grep_auth
  └── conn-sls-ssh-auth-internal (sls)    → ssh_auth_by_src_ip_time
         ↓ merge + dedupe_by
  evidence_bundles.ssh_auth[]
```

规则：

1. 遍历 `connector_ids`（含 `connector_id`），`params.host` 存在时按 `config.hostname` 过滤
2. 对每个 connector 在 `query_template_ids` 中找**第一条**同时满足：`connector_types` 匹配、必填 `params` 已齐
3. 无匹配则 fallback 到该 `asset_type` 的默认模板（须仍兼容 connector 类型）
4. 合并后按 `asset.aggregate.dedupe_by` 去重

查看计划：

```bash
python3 src/dataasset/test_connector.py asset-ssh-internal --by-asset --plan \
  --params '{"attacker_ip":"203.0.113.10","host":"web-01","time_start":"2026-06-21T08:00:00+08:00","time_end":"2026-06-21T20:00:00+08:00"}'
```

### 聚合资产的 `query_template_ids` 写法

| connector_type | 示例模板 | 典型 params |
|---|---|---|
| `sls` | `ssh_auth_by_src_ip_time` | `src_ip`, `time_start`, `time_end` |
| `ssh_file` | `ssh_file_grep_auth` | `grep_pattern`（可由 `attacker_ip` 映射） |
| `local_file` | `local_file_grep_auth` | 同 `ssh_file`（本地 grep/tail，无 SSH） |
| `database_ro` | `cmdb_all_hosts` | `limit` |
| `http_api` | `waf_api_search` | `src_ip`, `time_start`, `time_end` |
| `es` | `waf_es_by_src_ip_time` | `src_ip`, `time_start`, `time_end`, `limit` |

**同一 asset 的列表里应包含聚合内各类型至少一条**；不必每条模板适配所有 connector。`validate.py` 校验「每个 connector 至少一条可用模板」。
新增字段或查询载荷类型时须同步更新 Schema，并运行 `.venv/bin/python src/secweaver.py validate --strict`。

## DataRequest 示例（SLS）

```json
{
  "asset_id": "asset-waf-prod-01",
  "template_id": "waf_by_src_ip_time",
  "params": {
    "src_ip": "203.0.113.10",
    "time_start": "2026-06-21T08:00:00+08:00",
    "time_end": "2026-06-21T20:00:00+08:00",
    "limit": 2000
  }
}
```

## DataRequest 示例（SSH 读日志）

适用于 `connector_type: ssh_file`，模板 `ssh_file_grep_auth`：

```json
{
  "asset_id": "asset-ssh-web-01-file",
  "template_id": "ssh_file_grep_auth",
  "params": {
    "attacker_ip": "203.0.113.10",
    "grep_pattern": "203.0.113.10",
    "log_path": "/var/log/auth.log",
    "max_lines": 5000
  }
}
```

平台渲染为远程只读命令（**AI 不拼**）：

```text
grep -E '203.0.113.10' /var/log/auth.log | tail -n 5000
```

| 参数 | 说明 |
|---|---|
| `grep_pattern` | 可省略；`attacker_ip` / `src_ip` 会自动映射 |
| `log_path` | 可省略；从 connector `log_paths[asset_type]` 补全 |
| `max_lines` | 默认 5000，受 connector `max_lines_per_query` 限制 |

测试：

```bash
python3 src/dataasset/test_connector.py asset-ssh-web-01-file --by-asset \
  --params '{"attacker_ip":"203.0.113.10"}' --dry-run
```

## DataRequest 示例（本地文件）

适用于 `connector_type: local_file`，模板 `local_file_grep_auth`（参数与 SSH 读日志相同）：

```json
{
  "asset_id": "asset-local-lab-auth",
  "template_id": "local_file_grep_auth",
  "params": {
    "attacker_ip": "203.0.113.10",
    "grep_pattern": "203.0.113.10",
    "log_path": "auth.log",
    "max_lines": 5000
  }
}
```

平台在 Claw 主机本地执行等效 `grep -E | tail`（**不调用 shell**）。`base_path` 下相对路径由 connector 解析；样例日志见 `dataasset/samples/local-logs/`。

测试：

```bash
python3 src/dataasset/test_connector.py asset-local-lab-auth --by-asset \
  --params '{"attacker_ip":"203.0.113.10","host":"web-01"}' --fetch
```

## DataRequest 示例（DB / HTTP / ES）

| connector_type | 模板 | 渲染字段 |
|---|---|---|
| `database_ro` | `cmdb_all_hosts` | `sql`（`:param` 绑定） |
| `http_api` | `waf_api_search` | `http.method/path/body` |
| `es` | `waf_es_by_src_ip_time` | `es_query`（Query DSL JSON，支持 `{src_ip}` 等占位） |

### ES 模板示例

```json
"es_query": {
  "query": {
    "bool": {
      "must": [
        { "term": { "src_ip": "{src_ip}" } },
        { "range": { "@timestamp": { "gte": "{time_start}", "lte": "{time_end}" } } }
      ]
    }
  },
  "size": "{limit}"
}
```

连接器 `config` 需 `url` + `index`；凭证 `vault://es/security-readonly`（`type: es`）。

## 凭证规则

`credentials_ref` 由平台根据**各 connector** 自动注入，大模型**只传 ref 或不传**（禁止传明文密钥）。聚合 fetch 时每个 connector 独立解密，Skill 只见合并后的 evidence。

# Community 真实数据使用与安全

**语言：** [English](community-release-and-data-safety.md) | 简体中文（本文）

## 独立运行与发布

Community 的本地合成数据流程无需私有服务端。自建数据源需要自己的服务、只读账号与网络权限；SaaS SLS Proxy 需要对应平台服务与凭证。本文面向真实数据使用者；维护者请看 [发布验收清单](../docs_dev/community-release-checklist.zh-CN.md)。

## Elasticsearch TLS 与兼容性

适用于公开 Python ES Connector、ES 探测及本地 Studio；需要受信 HTTPS endpoint、
匹配主机名的有效证书及只读账号。使用私有 CA 时设置 `ca_file`，相对路径从
`DATAASSET_ROOT` 解析。浏览器向导显式使用 `tls_verify: true`，生成配置也默认开启。
未知 CA、证书过期或主机名错误会失败；不会通过关闭验证自动重试。取数与探测均拒绝 HTTP 重定向，防止凭证被转发或连接降级；请直接配置最终 HTTPS 地址。

专用 ES Discovery 与 Studio 探测 API 保留显式布尔值 `false`，仅供受控诊断；
实时 Connector 取数、公开 Connector Schema 和上线校验均拒绝 `false` 配置。
`null`、数字或字符串（包括 `"false"`）会被拒绝，不能代替 JSON 布尔值。
旧配置缺少此字段时，现在会验证证书；迁移时补充正确 CA，不要依赖旧的不安全默认值。
验证可运行 `python3 -m unittest discover -s tests -p test_es_tls_transport.py`：
需要 OpenSSL 和本地回环监听权限，测试覆盖不受信证书拒绝、私有 CA 成功及显式诊断兼容。

HTTP API、Splunk 与外部执行器使用同一传输边界：远程地址必须为 HTTPS，回环地址
可使用 HTTP，所有重定向都会被拒绝；HTTP API 与 Splunk 的私有 CA 同样使用 `ca_file`。

## 查询不完整时如何研判

ES HTTP 200 仍可能超时、提前终止或部分分片失败。返回条数还可能受 ES 页大小和
本地 `max_records_per_request` 限制。取数保留已获得的证据，同时输出：

- `query_meta.partial`、`incomplete_reasons`：已知不完整状态及原因。
- `query_meta.truncated`：页限制、总量下界或本地条数限制导致的截断/可能截断。
- `timed_out`、`terminated_early`、`failed_shards`、`total_hits`：服务端状态。
- `fetch_summary.query_integrity`：把失败、部分结果和缓存命中的缺口传给下游报告。

`status=incomplete` 时不能以“未返回某事件”排除攻击；应缩小时间窗、分段查询，
检查集群或补充数据源。`no_known_gaps` 只表示已执行查询未报告缺口，不证明所有数据源完整；
未执行或没有查询元数据时为 `unknown`。不会自动分页或为了消除告警而静默重试。

存在完整性预检时，会补充 `query_integrity` 和 `query_results_incomplete` 数据缺口。
保留已有正向证据，不自动覆盖研判结果或任意扣减置信度；智能体必须结合查询缺口解释结论。
离线/手工传入证据没有服务端状态，不能从事件数量推断查询已经完整。

## 证据 ID 迁移

自动生成 ID 的基本格式为 `<asset-type>-v2-<digest>`，摘要包含资产和连接器命名空间。
ES 优先使用索引与文档 ID；其他事件使用排序稳定的完整内容摘要，忽略查询返回序号。
已有显式 `evidence_id` 保持原样，调用方负责其唯一性。

例外：同时带有原生 `audit_id`/`event_id`、主机和源时间的事件现使用
`<asset-type>-v3-<digest>`。摘要保留源内容与命名空间，排除 SLS 上传批次、接收时间
和分析辅助字段，因此重新上传可以去重；不同主机、源时间或内容仍保留为不同事件。
已有显式 ID（包括导出的 v2 ID）不会被重写。升级后应重新取数并重建依赖原生事件
自动 ID 的报告/索引，不要混用 v2/v3 引用。风险研判也会在阈值统计前对旧导出的
原生事件去重，并在 `evidence_deduplication` 保留重复引用到首条证据的映射。

早期基于返回序号的自动 ID 不与 v2 兼容：重新生成关联报告/索引，不要混用旧引用与新取数结果。
无原始标识时，完全相同的记录无法彼此区分；字段投影变化也可能改变内容摘要。
ID 在脱敏前生成，不是匿名化承诺。

## 敏感字段不会默认自动脱敏

Vault 凭证不会附加到事件，但源日志本身可能有 Token、密码、Cookie 或请求头。
`masking` 缺省/为空时保留原值；`pii_fields` 只作治理标注，不会触发脱敏。
在数据交给智能体或分享报告前，依据实际字段配置脱敏，并检查原始字段、别名和嵌套副本。

以下片段可合并到需要严格隐藏命令与请求头的 Asset；它会损失命令分析所需信息，
应先在本地完成必要分析，或为具体日志设计更细的规则：

```json
{
  "masking": {
    "command": "redact",
    "raw_command": "redact",
    "Authorization": "redact",
    "authorization": "redact",
    "headers.Authorization": "redact",
    "headers.authorization": "redact",
    "headers.Cookie": "redact",
    "headers.cookie": "redact"
  }
}
```

字段匹配区分大小写；上例没有覆盖任意原始日志或所有可能字段。
使用合成敏感值取数后检查输出 JSON 和报告，确认所有副本均被处理，再接入真实数据。

## SLS → ES 迁移工具

`src/dataasset/migrate_sls_to_es.py` 不再默认引用私有资产目录或内部映射名称。
调用必须传入 `--config`、`--source-root` 和至少一个 `--mapping`；未知映射直接报错。
映射文件由用户管理，例如：

```json
{
  "mappings": [{
    "source_connector_id": "conn-sls-source",
    "target_connector_id": "conn-es-target",
    "target_index": "logs-security-*"
  }]
}
```

先运行只读取源数据的预演，按实际目录、时间、网关和 CA 替换参数：

```bash
python3 src/dataasset/migrate_sls_to_es.py \
  --config /path/to/migration.json --source-root /path/to/source-dataasset \
  --mapping conn-es-target --time-start 2026-09-01T00:00:00Z \
  --time-end 2026-09-01T01:00:00Z \
  --ingest-url https://ingest.example.com --ca-file /path/to/ca.pem --dry-run
```

源目录需要完整的 DataAsset 配置和可用只读凭证。正式写入另需兼容 ES `_bulk` 的 HTTPS
写入网关及独立写入账号，通过 `SECWEAVER_INGEST_USER`、`SECWEAVER_INGEST_PASSWORD` 提供。
工具不会部署私有网关。先验证预演的源资产、事件数和目标索引，再决定写入范围。

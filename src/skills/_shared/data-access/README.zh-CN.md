# 证据取数（只拉日志，不研判）

**语言：** 简体中文（本文） | [English](README.md)

本目录负责资产读取、证据取数与归一化，不负责 Skill 研判。场景计划、调查时间窗
和有界证据扩展放在 `scenario_fetch.py`；输入适配与跨 Skill 执行放在
[`../skill_runtime/`](../skill_runtime/README.zh-CN.md)。原 `skill_input.py`、
`prepare.py` 和 `run_pipeline.py` 路径保留为兼容入口，下列命令无需迁移。
`--from-bundle` 是各 Skill 脚本的参数；准备脚本使用 `--bundle ID`。

专用 Skill：[../../evidence-fetch/SKILL.zh-CN.md](../../evidence-fetch/SKILL.zh-CN.md)

```bash
python3 src/skills/evidence-fetch/scripts/fetch_evidence.py \
  --from-bundle --bundle bundle-host-risk-default \
  --params '{"hosts":["192.0.2.91"],"time_start":"...","time_end":"..."}' \
  --pretty
```

输出 `evidence_bundles` 供大模型或下游 Skill（risk / alert / trace）消费。

SLS 与 SLS Proxy 的 HTTPS 查询默认验证证书。`tls_verify` 必须是布尔值；实时
Connector 必须保持 `true`，专用探测接口才保留显式 `false` 诊断参数。私有 PEM CA
使用 `ca_file`（绝对路径或相对于 `DATAASSET_ROOT`），不能与关闭验证同时配置。Proxy 探测和 SDK 查询共用该策略，
证书失败不切换备用入口。详见 [SLS Proxy 接入指南](../../../../docs_user/30-sls-proxy-onboarding.zh-CN.md)。

ES、HTTP API、Splunk 和外部 HTTP 执行器共用严格传输策略：远程地址必须使用
HTTPS，HTTP 只允许明确的回环地址；请求不跟随重定向，避免认证头跨目标或降级转发。
HTTPS 默认使用系统信任库，私有 CA 通过 `ca_file` 配置。ES/HTTP API 的
`tls_verify` 与 Splunk 的 `verify_tls` 在实时取数时必须为 `true`。
相对 CA 路径解析后必须位于 `DATAASSET_ROOT` 内，符号链接越界也会被拒绝；
系统管理员维护的 CA 文件可使用绝对路径。

## 一键命令

```bash
# 完整性分析（从默认资产包）
python3 src/skills/data-source-completeness/scripts/check.py \
  --from-bundle \
  --params '{"attacker_ip":"203.0.113.10","time_start":"2026-06-21T08:00:00+08:00","time_end":"2026-06-21T20:00:00+08:00","host":"web-01"}'

# 溯源（内置完整性预检 + Vault 拉 live 证据：SLS / SSH）
python3 src/skills/traceability-analysis/scripts/correlate.py \
  --from-bundle --bundle bundle-incident-trace-default \
  --params '{"attacker_ip":"203.0.113.10","time_start":"...","time_end":"...","host":"web-01"}' \
  --fetch

# 告警确认
python3 src/skills/alert-confirmation/scripts/confirm.py \
  --from-bundle --bundle bundle-alert-confirm-min \
  --params '{"attacker_ip":"203.0.113.10","time_start":"...","time_end":"...","host":"web-01","primary_alerts":[...]}' \
  --fetch

# 流水线（完整性 → 溯源 / 告警）
python3 src/skills/_shared/data-access/run_pipeline.py trace-chain \
  --params '{"attacker_ip":"203.0.113.10","time_start":"...","time_end":"...","host":"web-01"}' \
  --fetch --pretty
```

## 共用参数

| 参数 | 说明 |
|---|---|
| `--from-bundle` | 从 `dataasset/bundles` 加载（替代 `-i` / stdin） |
| `--bundle ID` | 资产包 ID（省略则用各 Skill 默认包） |
| `--params JSON` | 调查参数（`attacker_ip` 自动映射为 `src_ip`） |
| `--params-file` | 参数 JSON 文件 |
| `--fetch` | SOPS 解密并拉 live 证据（SLS / SSH / 本地文件 / DB / HTTP / ES，经 normalizer） |
| `--dry-run` | 构建请求，不解密 Vault |
| `--skip-completeness` | 溯源/告警跳过内置完整性预检 |

仍支持 `-i input.json` 或管道 JSON（离线 / 样例模式）。

## 执行状态边界

`fetch()` 默认使用生产 Skill 模式，Asset 与 Connector 必须同时为 `active`；
`draft`、`discovery` 会在模板渲染和凭证解析前被拒绝。Connector 测试、格式发现、
连通性检查和 draft 提升会显式使用 `onboarding_test`，允许在接入验收阶段测试
`draft/discovery`。任何模式下 `disabled` 都是不可绕过的停用开关。

## 字段清单与完整性

取数报告区分注册元数据与实际证据。附带的 `completeness_precheck` 中，
`assessment_basis=registry_metadata` 和 `metadata_readiness` 表示原有静态评估；
旧 verdict/confidence/block 字段为兼容保留，不能证明当天实际有数据。
`fetch_summary.evidence_readiness`（同时附到预检）返回 `no_evidence`、`partial`、
`evidence_observed`，或空 dry-run/计划的 `not_evaluated`，并列出已评估需求中缺少
事件的 P0 类型。`evidence_observed` 仅表示有事件且未观察到需求/查询缺口，不保证
检测器覆盖完整。live 取数中，声明资产没有实际请求记录时，`query_integrity` 增加
`not_queried` 缺口；查询成功但无数据与查询失败分开。可运行 data-access 测试集验证。

`fetch_summary.analysis_constraints` 将上述状态统一转换为下游结论边界：已返回事件
可支持正向发现；只有 live 取数已观察到证据且无已知查询缺口时，才允许负向结论。
plan/dry-run、失败、部分返回、截断、未查询和成功但空结果均会设置
`absence_is_not_evidence=true`。输出的置信度上限是公共建议值，领域评分仍由各 Skill 负责。

`schema.fields` 保留源侧真实字段名；全局 `evidence-minimum-fields.field_aliases` 与 `asset.field_aliases` 将源字段映射到 canonical 字段；查询参数映射由 Join 级 `fetch_plan.param_map` 与 `query-templates` 负责。共享 `field_inventory.py` 统一输出：

| API | 说明 |
|---|---|
| `raw_fields(asset)` | 源字段集合，来自 `schema.fields` 或 registered asset 的 `fields` |
| `canonical_fields(asset)` | 通过全局/资产别名、`time_field` 可达的标准字段 |
| `effective_fields(asset)` | `raw_fields ∪ canonical_fields`，用于 Skill 语义判断 |
| `check_required_fields(asset, required)` | 字段完整性检查，返回是否满足与缺失字段 |

完整性 Skill、registry、后续需要判断“资产能否支撑某调查字段”的 Skill 应复用该模块，避免各自只检查 `fields` 导致误判。

## 模块

| 文件 | 作用 |
|---|---|
| `scenario_fetch.py` | 场景取数计划与有界证据扩展；不导入或调用具体 Skill 的 Python 实现 |
| `trace_time_window.py` | 溯源时间解析、攻击者时间窗收窄与有界回退的证据过滤 |
| `skill_input.py` | `skill_runtime.inputs` 的兼容模块别名；不复制输入逻辑 |
| `prepare.py` | `skill_runtime.prepare` 的兼容 CLI；使用 `--bundle ID`、可选 `--run-skill` |
| `registry.py` | 读 dataasset |
| `vault.py` | SOPS 解密 `credentials_ref` |
| `fetch.py` | live 拉证据的主流程编排与 fetch 后归一化；不放具体 connector 分支 |
| `connector_fetch_dispatch.py` | 统一 connector fetch 策略注册表；内置 connector 在这里登记 |
| `aggregate.py` | 多 connector 聚合、host 过滤、去重 |
| `normalizer.py` | evidence_id、timestamp、**time_correction**、别名、masking |
| `field_inventory.py` | 共享字段清单与完整性检查：raw / canonical / effective fields |
| `field_resolver.py` | correlation-matrix 字段读值（Join 声明字段 + variants + alias 正反向候选） |
| `correlation_keys.py` | matrix + effective fields 推导关联键；`asset_to_registered` / 完整性 Skill 消费 |
| `correlation_engine.py` | matrix 驱动 Join 匹配、时间窗、fetch 编排；`fill_investigation_window` / `resolve_anchor_params` 按 anchor 填充调查时间窗 |
| `sls_fetch.py` | 阿里云 SLS live fetch |
| `db_fetch.py` | `database_ro` 分发器；engine 校验与行过滤 |
| `db_common.py` | 共享 SQL 安全校验、参数绑定、默认端口、凭证匹配 |
| `mysql_fetch.py` | MySQL / MariaDB database_ro |
| `postgresql_fetch.py` | PostgreSQL database_ro |
| `oracle_fetch.py` | Oracle / PLSQL database_ro |
| `sqlserver_fetch.py` | SQL Server / MSSQL database_ro |
| `sqlite_fetch.py` | SQLite database_ro |
| `mongodb_fetch.py` | MongoDB 文档查询 connector |
| `redis_fetch.py` | Redis 只读命令 connector |
| `http_fetch.py` | http_api REST |
| `es_fetch.py` | Elasticsearch `_search` |
| `ssh_fetch.py` | SSH 读日志 |
| `local_file_fetch.py` | 本地文件读日志（无 shell / 无 Vault） |
| `connector_registry.py` | 汇总内置、外置和插件 connector 类型；支持缓存刷新 |
| `connector_catalog.py` | 给 CLI/UI 展示 connector 能力、来源、依赖策略 |
| `extended_fetch.py` | 扩展 connector 调度器；不放厂商 fetch 细节 |
| `connector_fetch_common.py` | 共享 HTTP、本地样本、时间范围、外部执行器 helper |
| `*_fetch.py` | 一个 connector 一个文件，例如 `aws_cloudwatch_fetch.py`、`azure_monitor_fetch.py`、`splunk_fetch.py` |
| `template_select.py` | 按 asset.query_template_ids 选模板 |
| `run_pipeline.py` | `skill_runtime.pipeline` 的兼容 CLI 入口 |
| `tests/test_ssh_fetch.py` | SSH 命令校验与日志解析单元测试 |
| `tests/test_local_file_fetch.py` | 本地文件 grep/tail 单元测试 |

扩展 connector 规则：

- `fetch.py` 只负责编排：加载 asset/connector、渲染模板、解析凭证、调用 dispatcher、归一化事件。
- 新增内置 live connector 时，新建对应 `*_fetch.py`，再在 `connector_fetch_dispatch.py` 或 `extended_fetch.py` 的策略表登记。
- 不要在 `fetch.py` 继续追加 `if/elif connector_type`；主流程保持稳定，社区贡献时只需要看自己的 fetch 文件和注册表。
- 配置型外置 connector / 插件 connector 仍通过 `connector_registry.py` 发现，UI 可通过 `/api/onboarding/meta?refresh=1` 或 `/api/connectors/reload` 刷新运行时缓存。
- 模板兼容判断每次读取当前 Connector 注册表；缓存刷新成功后，query key 选择无需重启进程即可生效。
- 插件契约统一维护在 `src/dataasset/plugin_contract.py`，不要在 CLI 和执行器各写一份。详见 [Connector 插件](../../../../docs_dev/04-connector-plugins.zh-CN.md)。
- 取数层不得导入 Skill 研判实现或 `skill_runtime`。新增输入/预检适配和跨 Skill 流程放在 `../skill_runtime/`；仅三个历史兼容入口可向上转发。

这样厂商 SDK、签名逻辑、响应解析互相隔离，社区贡献时不用读完整 fetch 主流程。

## 本地文件（local_file）

当 asset 绑定 `connector_type: local_file` 时，`--fetch` 在 Claw 主机上只读本地日志（Python 正则过滤，**不调用 shell**，**无需 Vault**）：

```bash
python3 src/dataasset/test_connector.py asset-local-lab-auth --by-asset \
  --params '{"attacker_ip":"203.0.113.10","host":"web-01"}' --fetch
```

`base_path` 可为相对路径（相对仓库根）；`log_path` 与 `grep_pattern` 补全规则同 `ssh_file`。样例：`dataasset/samples/local-logs/`。

## SSH 读日志（ssh_file）

当 asset 绑定 `connector_type: ssh_file` 时，`--fetch` 经 paramiko 执行模板渲染的 `grep | tail`：

```bash
# dry-run：只看渲染命令，不解密 Vault
python3 src/dataasset/test_connector.py asset-ssh-web-01-file --by-asset \
  --params '{"attacker_ip":"203.0.113.10"}' --dry-run

# live（需 vault://ssh/readonly-web-01 与可达主机）
python3 src/dataasset/test_connector.py asset-ssh-web-01-file --by-asset \
  --params '{"attacker_ip":"203.0.113.10"}'
```

`attacker_ip` 自动映射为 `grep_pattern`；`log_path` 从 connector `log_paths` 补全。支持 `bastion_id` 堡垒跳转。

## 依赖

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-data-access.txt
DATAASSET_ROOT=dataasset src/dataasset/credentials/sops-vault.sh edit vault://sls/security-readonly

# 测试 SSH 连接器（需真实主机与 Vault 凭证）
python3 src/dataasset/test_connector.py asset-ssh-web-01-file --by-asset \
  --params '{"attacker_ip":"203.0.113.10"}'
```

凭证规则：Skill 输出与 LLM 均不含 secret 明文；解密仅在 `vault.py` / `fetch.py` / `ssh_fetch.py` 内部。
插件非零退出时，运行时丢弃 stdout，只保留限长且递归替换凭证值后的 stderr；
凭证值过短、无法可靠替换时，stderr 整段省略。

## 新 log 类型接入

注册新 asset 前，若字段未映射或格式未知，先走 [日志格式发现](../../../../docs_user/20-log-format-discovery.md)：`discover.py` 预处理 + **大模型**字段映射 → 再改 `evidence-minimum-fields.json` / `normalizer.py` / dataasset。详见 [日志格式发现设计.md](../../../../docs_dev/20-log-format-discovery-design.md).

## 真实数据与发布边界

ES 默认校验证书，支持私有 CA；查询不完整状态会进入取数摘要和报告。
带原生 audit/event 标识的自动证据 ID 使用 v3，其他自动 ID 保留 v2；源日志敏感字段仍需显式配置 masking。
发布检查、兼容性、迁移参数与脱敏示例见[使用说明](../../../../docs_user/community-release-and-data-safety.zh-CN.md)。

SLS 和 SLS Proxy 将 SDK 时间保留为 `_sls_timestamp`；`timestamp` 优先采用有效的
`schema.time_field`，再尝试 timestamp/time 别名和传输时间回退。历史事件不会仅因
重新上传而被当成分析窗口内的新事件。`truncated_asset_types` 优先采用实际查询的
显式截断标志，不将多时间窗、分页合并总数与单页 limit 比较；缺少标志的旧输入仍
使用 limit 启发式判断。实际查询成功后仅清除派生的 `query_results_incomplete`
预检缺口；未知、失败、部分返回或未查询的数据不能视为完整覆盖。

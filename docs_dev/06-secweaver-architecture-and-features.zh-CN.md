**语言：** [English](06-secweaver-architecture-and-features.md) | 简体中文（本文）

# SecWeaver 架构与功能说明

> SecWeaver 是一个面向安全运营的 AI 原生安全分析与溯源调查平台。  
> 架构总览、模块职责、技能链与文档索引

**一句话定位**：SecWeaver 是一个面向安全运营的 AI 原生安全分析与溯源调查平台。

---

## 一、本文边界

本文描述模块依赖、数据流与实现边界。产品概念见 [入门](../docs_user/01-getting-started.zh-CN.md)，按任务选择技能见 [技能目录](../docs_user/06-skills-and-usage.zh-CN.md)。Community 本地流程不依赖私有服务端；托管接入只依赖公开客户端契约。

## 二、总体架构

### 2.1 分层架构

```text
┌─────────────────────────────────────────────────────────────────────────┐
│  交互层：AI Agent 对话（Cursor / CC / Codex / OpenClaw …）/ CLI / run_pipeline.py │
│  自然语言任务 · 勾选资产包 · --from-bundle --fetch                       │
└───────────────────────────────┬─────────────────────────────────────────┘
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  技能层（src/skills/）                                               │
│  完整性分析 │ 告警确认 │ 溯源分析 │ 风险识别 │ 格式发现                    │
└───────────────────────────────┬─────────────────────────────────────────┘
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  数据访问层（src/skills/_shared/data-access/）                        │
│  registry → template_select → vault → fetch → aggregate → normalizer    │
└───────────────────────────────┬─────────────────────────────────────────┘
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  资产层（dataasset/）                                                    │
│  assets · connectors · bundles · query-templates · schema · credentials │
└───────────────────────────────┬─────────────────────────────────────────┘
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  数据源（生产系统）                                                        │
│  阿里云 SLS · SSH 日志 · MySQL · HTTP API · Elasticsearch · Agent→SLS    │
└─────────────────────────────────────────────────────────────────────────┘
```

### 2.2 调查流水线（典型）

```text
                    ┌──────────────────────┐
  新 log 类型 ──────▶│ 格式发现（discovery）│──▶ draft/active 资产
                    └──────────────────────┘
                                │
  用户发起调查 ◀────────────────┘
        │
        ▼
  选择 bundle + 填写 params（IP、时间、主机、告警）
        │
        ▼
  ┌─────────────────┐
  │ 数据源完整性分析 │── P0 缺失 → 阻断，输出接入建议
  └────────┬────────┘
           │ ready / partial
           ▼
  ┌─────────────────┐     ┌─────────────────┐
  │ fetch + normalize│────▶│ evidence_bundles │
  └────────┬────────┘     └────────┬────────┘
           │                       │
     ┌─────┴─────┐                 │
     ▼           ▼                 ▼
  告警确认    溯源分析         风险识别（exec/connect）
     │           │
     └───── 成功 / 需深挖 ────▶ 溯源分析
```

### 2.3 证据数据流

```text
params + asset_id + template_id
        │
        ▼
template_select（按 connector_type 选 sls_query / ssh_command / local_file_command / sql / http / es_query）
        │
        ▼
vault.resolve(credentials_ref)  ← AI / Skill 只见 ref
        │
        ▼
fetch（sls │ ssh_file │ local_file │ database_ro │ http_api │ es）
        │
        ▼
text_log_parser（SSH 文本，按 asset.text_parser 配置）
        │
        ▼
normalizer（evidence_id · ISO 时间 · field_aliases · masking）
        │
        ▼
aggregate（多 connector 去重合并，可选）
        │
        ▼
evidence_bundles.{asset_type}[]
        │
        ▼
Skill 脚本 + LLM 研判
```

---

## 三、仓库结构

```text
secweaver/
├── README.md                          # 产品简介
├── docs_dev/                          # 开发、架构与设计文档
│   ├── secweaver-architecture-and-features.zh-CN.md    # 本文
│   ├── data-asset-design.zh-CN.md     # dataasset 主设计
│   └── agent-collection-and-evidence-spec.zh-CN.md   # 采集链 + evidence 字段
├── docs_user/                         # 安全运营与 SOC 使用文档
│   ├── 13-SecWeaver-CLI.zh-CN.md         # 本地 CLI 使用说明
│   ├── 16-data-source-onboarding-faq.zh-CN.md           # 接入短问答与主文档导航
│   └── …（各 Skill 使用说明；英文：同名 .md）
├── dataasset/                         # 可编辑资产目录（L1/L2）
│   ├── assets/                        # 逻辑数据资产
│   ├── connectors/                    # 连接器
│   ├── bundles/                       # 调查用资产包
│   ├── query-templates/               # 参数化查询模板
│   ├── schema/                        # JSON Schema + evidence 规范
│   ├── parsers/                       # 自定义文本 log regex（可选）
│   ├── credentials/                   # SOPS Vault
│   └── scripts/                       # validate · test-connector · catalog
├── src/skills/                    # Agent Skills（Cursor / CC / Codex / OpenClaw 等通用）
│   ├── _shared/data-access/           # 数据访问层实现
│   ├── data-source-completeness/
│   ├── alert-confirmation/
│   ├── traceability-analysis/
│   ├── external-listener-cmd-risk/
│   └── log-format-discovery/
├── src/tools/
│   └── secweaver-agent/               # 统一主机侧采集客户端（Go）
└── requirements-data-access.txt       # fetch 层 Python 依赖
```

---

## 四、数据资产层（dataasset）

### 4.1 两层模型

| 层级 | 对象 | 职责 |
|---|---|---|
| **L1** | `DataAsset` | 调查可见的「有什么数据」：asset_type、schema、coverage |
| **L2** | `DataConnector` | 「怎么连」：endpoint、host、index；**不含密钥** |

逻辑资产通过 `connector_id` / `connector_ids[]` 绑定一个或多个连接器；同一 `asset_type` 可多源聚合（如 SLS 汇聚 + 多主机 SSH）。

### 4.2 资产状态

| status | 含义 | 对话框可选 |
|---|---|---|
| `discovery` | 格式发现队列，待字段映射 | 否 |
| `draft` | 编辑中 | 否 |
| `active` | 已发布 | 是 |
| `disabled` | 停用 | 否 |

### 4.3 支持的连接器类型

| connector_type | 用途 | 模板字段 | fetch 模块 |
|---|---|---|---|
| `sls` | 阿里云日志服务 | `sls_query` | `fetch.py` |
| `ssh_file` | SSH 读 auth/nginx 等 | `ssh_command` | `ssh_fetch.py` |
| `local_file` | 智能体所在主机本地日志 | `local_file_command` | `local_file_fetch.py` |
| `database_ro` | MySQL / PostgreSQL 只读 | `sql` | `db_fetch.py` |
| `http_api` | REST API | `http` | `http_fetch.py` |
| `es` | Elasticsearch `_search` | `es_query` | `es_fetch.py` |
| `agent_stream` | 采集拓扑文档 | — | 查询走 sink SLS |

文本日志解析由 **`asset.text_parser`** 配置（内置 `syslog_auth` / `nginx_combined` / `json_lines`，或 `dataasset/parsers/*.json`），**运营不改 Python**。

### 4.4 凭证与安全

```text
connectors/*.json  →  credentials_ref: vault://sls/security-readonly
                              ↓
credentials/secrets/*.enc.yaml  （SOPS 加密，可提交 Git）
                              ↓
vault.py / fetch.py 解密注入（Skill 与 LLM 不见明文）
```

### 4.5 工具链

| 命令 | 作用 |
|---|---|
| `python3 src/dataasset/validate.py` | JSON Schema、引用、模板匹配门禁 |
| `python3 src/dataasset/validate.py --sync-catalog` | 同步 catalog.json |
| `python3 src/dataasset/test_connector.py` | 单资产/聚合 dry-run 或 live fetch |

详见 [dataasset/README.md](../dataasset/README.md)、[数据源资产设计.md](09-data-asset-design.zh-CN.md)。

---

## 五、数据访问层

路径：`src/skills/_shared/data-access/`

| 模块 | 职责 |
|---|---|
| `registry.py` | 加载 assets / connectors / bundles / templates |
| `vault.py` | SOPS 解密 `credentials_ref` |
| `template_select.py` | 按 asset + connector + params 选模板 |
| `fetch.py` | 统一 fetch 入口，分发各 connector_type |
| `aggregate.py` | 多 connector 合并、host 过滤、去重 |
| `normalizer.py` | evidence_id、ISO 时间、field_aliases、masking |
| `text_log_parser.py` | 配置化文本 log 解析（SSH / local_file 共用） |
| `scenario_fetch.py` | 场景取数计划、调查时间窗、有界证据扩展；不调用具体 Skill Python 实现 |
| `skill_input.py` | `../skill_runtime/inputs.py` 的兼容模块别名 |
| `prepare.py` | 兼容入口；`--bundle ID` 准备元数据，`--run-skill` 同时研判 |
| `run_pipeline.py` | `../skill_runtime/pipeline.py` 的兼容入口 |

共用 Skill 输入/预检适配、研判调用和流程顺序放在
[`src/skills/_shared/skill_runtime/`](../src/skills/_shared/skill_runtime/README.zh-CN.md)。
各 Skill 自己负责规则与结论；证据层不导入其 Python 实现。插件发现/校验/执行
共用 `src/dataasset/plugin_contract.py`，统一默认 30 秒并校验整个响应。
迁移方式见 [Connector 插件](04-connector-plugins.zh-CN.md)。

Evidence 最小字段见 `dataasset/configure/evidence-minimum-fields.json` 与 [Agent采集与Evidence规范.md](12-agent-collection-and-evidence-spec.zh-CN.md)。

---

## 六、技能（Skill）体系

所有 Skill 位于 `src/skills/`（仓库约定路径，**非 Cursor 专有**），通过 **SKILL.md** 指导各 Agent 智能体执行；核心 Skill 配有 **确定性 Python 脚本** 保证可重复、可测试。

### 6.1 技能与场景索引

技能清单和 S1–S8 对照统一维护在 [技能目录](../docs_user/06-skills-and-usage.zh-CN.md)；本节只说明调用链和阻断规则。

### 6.3 技能链与阻断规则

```text
数据源完整性分析
  ├── overall_verdict = insufficient → next_skill_blocked = true
  └── P0 ready → 允许 告警确认 / 溯源分析

告警确认
  ├── attack_outcome = success → 建议启动溯源
  └── 仅 WAF、无 D2 → 无法确认「成功」，置信度上限受限

溯源分析
  └── 内置完整性预检（--from-bundle 时可跳过 --skip-completeness）
```

### 6.4 CLI 流水线

```bash
# 完整性 + 溯源（live fetch）
python3 src/skills/_shared/data-access/run_pipeline.py trace-chain \
  --params '{"attacker_ip":"203.0.113.10","time_start":"...","time_end":"...","host":"web-01"}' \
  --fetch --pretty

# 完整性 + 告警确认
python3 src/skills/_shared/data-access/run_pipeline.py alert-chain \
  --bundle bundle-alert-confirm-min \
  --params '{...}' --fetch
```

单 Skill 亦支持 `--from-bundle --fetch`，见 [_shared/data-access/README.md](../src/skills/_shared/data-access/README.md)。

---

## 七、主机采集与 Agent 链

### 7.1 audit-port-execmon

路径：`src/tools/secweaver-agent/pkg/auditportexecmon/`（Go + auditd 模块）

- 监控**对外监听端口**对应进程的 `execve`、可选 `connect`、文件操作
- 输出 JSON Lines → 接入 SLS → 注册为 `host_exec` / `host_connect` / `host_file_op` 资产
- Skill：**external-listener-cmd-risk**

### 7.2 Agent → SLS

exec/connect 等主机行为数据由 Agent 写入 SLS；**fetch 始终走 `sls` connector**，不用 `agent_stream` 直接查询。详见 [Agent采集与Evidence规范.md](12-agent-collection-and-evidence-spec.zh-CN.md) §1.2。

---

## 八、新数据源接入

```text
1. connectors/ + credentials（SOPS）
2. assets/ 注册，新格式设 status=discovery
3. log-format-discovery：discover.py + 大模型映射
4. 配置 text_parser / field_aliases / query-template
5. status: discovery → draft → active
6. validate.py + test_connector.py
```

短 FAQ：[数据源接入FAQ.md](../docs_user/16-data-source-onboarding-faq.zh-CN.md)

---

## 九、七大数据域（D1–D7）

| 域 | 含义 | 典型 asset_type |
|---|---|---|
| D1 | 边界与 WEB | waf_alert, web_access_log |
| D2 | 主机行为 | host_exec, host_connect, host_file_op, windows_event_log, linux_syslog |
| D3 | 认证访问 | ssh_auth |
| D4 | 网络 | firewall_log, dns_log, network_traffic_audit |
| D5 | 应用与 API | app_api_log |
| D6 | 资产与漏洞 | asset_inventory, vuln_scan |
| D7 | 审计与 DB | db_audit |

完整性分析 Skill 按场景（S1–S8）检查各域 P0/P1/P2 覆盖情况。

---

## 十、当前公开实现摘要

下表用于帮助开发者定位已公开的主要能力，不作为独立版本清单。当前行为以仓库代码、
DataAsset Schema、自动化测试和各模块 README 为准；版本变化与迁移要求见根目录
[`CHANGELOG.md`](../CHANGELOG.md)。

| 能力 | 状态 |
|---|---|
| dataasset 目录 + JSON Schema + validate | ✅ |
| SOPS Vault + credentials_ref | ✅ |
| 多源 fetch（SLS / SSH / 本地文件 / DB / HTTP / ES / 云厂商 / SIEM / 数仓 / 插件 / 外置执行器） | ✅ |
| normalizer + 多 connector 聚合 | ✅ |
| 配置化 text_parser | ✅ |
| 格式发现 Skill（discovery 队列） | ✅ |
| 四大研判 Skill + run_pipeline | ✅ |
| audit-port-execmon 采集工具 | ✅ |
| DataAsset Studio | ✅ 本地配置、诊断、接入向导和样例报告查看 |
| 多用户 RBAC / 审批流 | 不属于 Community 本地 Studio；托管能力不作为开源功能承诺 |
| 多数据库 driver | ✅ MySQL / PostgreSQL / Oracle / SQL Server / SQLite 等按独立 fetch 文件拆分 |

历史设计差距与决策背景见[历史数据源资产设计评估](history/10-data-asset-design-evaluation.zh-CN.md)；
其中的日期、评分和待办只代表评估当时状态。

---

## 十一、文档索引

### 11.1 平台与架构

| 文档 | 说明 |
|---|---|
| [README.md](../README.md) | 产品定位与快速入门 |
| **本文** | 架构与功能总览 |
| [13-SecWeaver-CLI.zh-CN.md](../docs_user/13-SecWeaver-CLI.zh-CN.md) | 本地 CLI 命令、demo 与 Skill 封装说明 |
| [数据源资产设计.md](09-data-asset-design.zh-CN.md) | dataasset 详细设计 |
| [历史数据源资产设计评估](history/10-data-asset-design-evaluation.zh-CN.md) | 特定时间点的实现评审，不作为当前待办 |
| [Agent采集与Evidence规范.md](12-agent-collection-and-evidence-spec.zh-CN.md) | 采集与 evidence |
| [如何配置数据源](../docs_user/03-configure-data-sources.zh-CN.md) | 完整接入生命周期 |
| [数据源接入FAQ.md](../docs_user/16-data-source-onboarding-faq.zh-CN.md) | 接入短问答与主文档导航 |

### 11.2 Skill 使用说明

| 文档 | Skill |
|---|---|
| [数据源完整性分析.md](../docs_user/15-data-source-completeness.zh-CN.md) | data-source-completeness |
| [告警确认.md](../docs_user/17-alert-confirmation.zh-CN.md) | alert-confirmation |
| [溯源分析.md](../docs_user/18-traceability-analysis.zh-CN.md) | traceability-analysis |
| [风险识别.md](../docs_user/19-risk-identification.zh-CN.md) | risk-identification |
| [对外监听进程命令高危识别.md](../docs_user/23-external-listener-command-risk.zh-CN.md) | external-listener-cmd-risk（exec 子模块） |
| [日志格式发现.md](../docs_user/20-log-format-discovery.zh-CN.md) | log-format-discovery |

### 11.3 Skill 设计文档

| 文档 | 说明 |
|---|---|
| [数据源完整性分析技能设计.md](13-data-source-completeness-skill-design.zh-CN.md) | |
| [告警确认技能设计.md](14-alert-confirmation-skill-design.zh-CN.md) | |
| [风险识别技能设计.md](17-risk-identification-skill-design.zh-CN.md) | |
| [溯源分析技能设计.md](15-traceability-analysis-skill-design.zh-CN.md) | |
| [日志格式发现设计.md](20-log-format-discovery-design.zh-CN.md) | |

### 11.4 实现与运维

| 路径 | 说明 |
|---|---|
| [dataasset/README.md](../dataasset/README.md) | 资产目录编辑 |
| [src/skills/README.md](../src/skills/README.md) | Skill 目录与命令 |
| [_shared/data-access/README.md](../src/skills/_shared/data-access/README.md) | fetch / Vault CLI |
| [src/tools/secweaver-agent/README.zh-CN.md](../src/tools/secweaver-agent/README.zh-CN.md) | 统一主机采集客户端 |

---

## 十二、快速命令参考

```bash
# 依赖
pip install -r requirements-data-access.txt

# 校验资产目录
python3 src/dataasset/validate.py --sync-catalog

# 格式发现队列
python3 src/skills/log-format-discovery/scripts/discover.py --list-discovery

# 完整性分析
python3 src/skills/data-source-completeness/scripts/check.py \
  --from-bundle --params '{"attacker_ip":"203.0.113.10"}'

# 调查流水线
python3 src/skills/_shared/data-access/run_pipeline.py trace-chain \
  --params '{"attacker_ip":"203.0.113.10","time_start":"2026-06-21T08:00:00+08:00","time_end":"2026-06-21T20:00:00+08:00"}' \
  --fetch --pretty
```

---

## 十三、与传统 SOC 工具的关系

SecWeaver **不替代** WAF、SIEM、EDR，而是：

1. **统一注册**这些系统的数据为 dataasset  
2. **拉取并归一化**为 evidence，供 Skill 跨源关联  
3. **智能体** 在技能边界内做完整性检查、告警确认、溯源与报告

密钥与查询模板由安全团队掌控；AI 负责重复劳动与结构化输出，关键结论仍可由人工复核。

---

*维护说明：架构变更（新 connector、新 Skill、流水线调整）请同步更新本文与 [数据源资产设计.md](09-data-asset-design.zh-CN.md)。*

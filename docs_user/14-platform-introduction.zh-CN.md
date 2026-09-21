**语言：** [English](14-platform-introduction.md) | 简体中文（本文）

# AI原生安全分析与溯源平台介绍

> 让安全运营经验沉淀为可复用的 AI 技能，让多源安全数据真正参与分析、确认与溯源。

---

本文为可选产品介绍，不承担安装或配置参考。范围核对日期：2026-09-18；首次使用从 [快速上手](00-security-operator-quickstart.zh-CN.md) 开始，模块实现边界见 [架构](../docs_dev/06-secweaver-architecture-and-features.zh-CN.md)。

## 1. 平台定位：面向安全运营的 AI 分析执行平台

SecWeaver 是一个面向安全运营的 AI 原生安全分析与溯源调查平台。

它不是简单的聊天机器人，也不是单一日志查询工具，而是把安全运营中的数据资产、专家经验、分析流程和工具执行能力统一编排起来，让 AI 在明确边界内完成安全分析任务。

**一句话定位：**

> 定义数据资产，沉淀安全技能，交给 AI 执行分析、确认与溯源。

核心目标：

- 降低安全分析对个人经验的强依赖
- 把专家 SOP 沉淀为可复用 Skill
- 让告警、日志、主机行为、网络连接等多源证据自动关联
- 帮助安全团队更快确认告警、识别风险、还原攻击链

---

## 2. 为什么需要这样的平台

传统安全运营面临三个长期问题。

### 告警太多，人工确认成本高

WAF、IDS、EDR、防火墙、SIEM 会持续产生告警，但大量告警需要人工判断：

- 是误报还是真攻击？
- 攻击是否成功？
- 是否已经打到主机？
- 是否存在后续横向移动？

### 数据很多，但难以真正关联

安全数据分散在不同系统中：

- WAF / WEB 访问日志
- SSH / 系统认证日志
- 主机命令执行日志
- 主机主动外联日志
- DNS / 防火墙 / 网络流量日志
- CMDB / 主机资产信息

这些数据只有被统一注册、字段归一、时间窗对齐、Join 规则明确后，才能成为可分析的证据链。

### 专家经验难复制

安全专家知道如何判断攻击是否成功、如何从 IP 追到主机、如何从命令追到外联，但这些经验往往存在于个人脑中或零散文档里。

平台要做的是把这些经验沉淀为：

- 可执行的 Skill
- 可审计的流程
- 可复用的关联规则
- 可持续优化的数据资产体系

---

## 3. 六大核心能力

SecWeaver 围绕安全运营的关键闭环构建六大能力。

| 能力 | 作用 |
|---|---|
| 数据资产管理 | 统一管理日志源、连接器、凭证、主机、关联矩阵 |
| 安全技能沉淀 | 将专家分析经验封装为 Skill，可复用、可审计 |
| 数据源完整性分析 | 判断当前数据是否足够支撑告警确认和溯源 |
| 风险识别 | 对主机命令执行、主动外联等行为进行风险研判 |
| 溯源分析 | 跨 WAF、WEB、主机、SSH、防火墙等数据还原攻击链 |
| 告警确认 | 判断告警是误报、尝试攻击还是真实攻击，并确认是否成功 |

---

## 4. 数据资产是 AI 分析的基础

AI 能否做出可靠安全分析，首先取决于它能看到什么数据、这些数据是否可信、字段是否一致、时间是否可对齐、证据之间是否能关联。安全运营中的日志、告警、主机行为、网络连接、身份与资产信息，如果没有被资产化管理，对 AI 来说只是分散的文本和记录；只有被注册为标准化数据资产后，才能成为可检索、可校验、可关联、可复用的分析上下文。

因此，数据资产不是简单的“数据源清单”，而是 AI 安全分析的底座。

它决定了：

- AI 知道有哪些数据可用
- AI 知道每类数据代表什么安全语义
- AI 知道应该通过哪个 connector 拉取证据
- AI 知道哪些字段可以用于确认告警、定位主机和还原攻击链
- 平台可以在分析前判断数据是否足够，避免盲查和误判

平台把安全运营依赖的数据统一抽象为五类核心对象。

| 核心对象 | 说明 | 解决的问题 |
|---|---|---|
| Asset | 数据源资产，描述有什么数据、属于哪个安全域、覆盖哪些主机或业务 | AI 应该用哪些数据 |
| Connector | 连接器，描述怎么连接数据源 | 如何拉取日志或证据 |
| Credentials | 凭证引用，描述用什么密钥连接 | 密钥安全与权限边界 |
| Host | 关键主机注册表 | 主机身份、区域、角色、IP 统一 |
| Correlation Matrix | 跨源关联矩阵 | 证据之间如何 Join、用多大时间窗、服务哪些场景 |

### 数据资产关联决定能否形成证据链

单一数据源通常只能回答局部问题：WAF 能看到攻击请求，WEB 日志能看到访问上下文，主机日志能看到命令执行，网络日志能看到外联，SSH 日志能看到横向登录。真正的安全分析需要把这些数据串起来，形成从“告警”到“主机行为”再到“影响范围”的完整证据链。

例如一次 Web 攻击确认，平台需要把以下证据关联起来：

```text
WAF 告警
  → WEB 访问日志
  → 主机命令执行
  → 主机主动外联
  → SSH 登录 / 横向移动
  → 受影响主机和业务范围
```

如果没有数据资产关联，AI 只能分别读取几段日志，结论容易停留在“可能有关”；有了明确的资产关系、字段映射、Join 规则和时间窗，AI 才能给出可解释、可复核的判断：攻击是否成功、入口在哪里、执行了什么命令、是否发生外联、影响了哪些主机。

这也是SecWeaver 的核心设计：先把数据资产标准化，再把数据资产关联起来，最后让 AI 在可信证据链上完成分析、确认与溯源。

---

## 5. 数据接入与运营分离

平台采用 GitOps + 表单向导 + validate 上线门禁的方式，让数据接入从“开发改代码”转变为“运营人员配置，平台自动校验与执行”。

### 运营人员负责

- 登记主机与关键资产
- 配置数据源资产和连接器
- 配置字段归一化和查询模板
- 运行校验和连通测试
- 将数据源从 draft 推进到 active

### 平台负责

- 提供标准化的数据资产模型
- 校验配置是否完整、可用、可上线
- 根据 connector 和 query template 自动执行取数
- 自动完成字段归一化、脱敏和证据标准化
- 按 correlation-matrix 执行跨源关联
- 将可用证据交给 AI Skill 进行分析、确认与溯源

这种分工让数据接入更可控：运营人员只需要按平台规范维护配置，平台负责把配置转化为可执行、可审计、可复用的安全分析能力。

### 目前支持的 Connector 类型

Connector 用来描述平台如何连接数据源。当前配置模型已支持以下类型，并按能力成熟度分为“可直接取数执行”和“接入/扩展预留”两类。

| 对外数据源类型 | 平台配置类型 | 适用数据源 | 当前能力说明 |
|---|---|---|---|
| 阿里云 SLS | `sls` | SLS Project / LogStore | 已支持 live fetch，通过参数化 `sls_query` 按时间窗、IP、主机等条件拉取日志 |
| Elasticsearch / OpenSearch | `es` | ES / OpenSearch 日志索引 | 已支持 live fetch，通过 `es_query` Query DSL 拉取证据 |
| SSH 文件日志 | `ssh_file` | 远程 Linux / Windows 主机日志文件 | 已支持通过 SSH 读取文本日志，适合 auth.log、syslog、nginx access 等文件型日志 |
| 本地文件 / 离线样本 | `local_file` | 本地文本日志、离线样本、演示数据 | 已支持本地文本文件读取，适合离线验证、样本回放和演示环境 |
| MySQL 只读库 | `database_ro` + `config.engine=mysql` | CMDB、堡垒机、审计库、业务安全库 | 已支持只读 SQL 查询，使用参数绑定，避免拼接裸 SQL |
| MariaDB 只读库 | `database_ro` + `config.engine=mariadb` | CMDB、堡垒机、审计库、业务安全库 | 已支持只读 SQL 查询，配置方式与 MySQL 一致 |
| PostgreSQL 只读库 | `database_ro` + `config.engine=postgresql` | CMDB、资产库、审计库、数据仓库 | 已支持只读 SQL 查询，可配置 `sslmode` 等连接参数 |
| HTTP / REST API | `http_api` | WAF、SIEM、工单或安全产品 API | 已支持 REST API 取数，通过模板定义 method、path、body |
| AWS CloudWatch Logs | `aws_cloudwatch` | 云上应用日志、CloudTrail、VPC Flow Logs 等 | 支持扩展型 Connector，模板使用 `cloudwatch_query` 描述查询 |
| AWS S3 日志归档 | `aws_s3_logs` | ALB / CloudFront / CloudTrail / 安全产品落 S3 日志 | 支持扩展型 Connector，模板使用 `object_query` 描述对象前缀与过滤逻辑 |
| Azure Monitor | `azure_monitor` | Log Analytics Workspace、Azure 安全日志 | 支持扩展型 Connector，模板使用 KQL 查询 |
| Google Cloud Logging | `gcp_logging` | GCP 项目日志、审计日志、VPC Flow Logs | 支持扩展型 Connector，模板使用 `gcp_logging_filter` 描述过滤条件 |
| 腾讯云 CLS | `tencent_cls` | 腾讯云日志服务 Topic | 支持扩展型 Connector，模板使用 `cls_query` 描述检索语句 |
| 华为云 LTS | `huawei_lts` | 华为云日志流 | 支持扩展型 Connector，模板使用 `lts_query` 描述检索语句 |
| Splunk | `splunk` | 企业已有 SIEM / Splunk Index | 支持扩展型 Connector，模板使用 `splunk_search` 描述 SPL 查询 |
| ClickHouse | `clickhouse` | 大规模日志明细表、流量与审计明细表 | 支持扩展型 Connector，模板复用只读 `sql` 查询 |
| Hive | `hive` | 数据湖、离线日志仓库、长期留存日志 | 支持扩展型 Connector，模板复用只读 `sql` 查询 |
| Agent 上报流 | `agent_stream` | Agent 数据接入和采集链路汇聚点 | 已纳入连接器模型，适合作为 Agent 数据接入和下游 sink 描述 |
| SSH 命令采集 | `ssh_command` | 受控 SSH 命令执行型采集 | 已纳入模板与连接器枚举，适合后续扩展为更严格的命令白名单采集 |
| Syslog 推送接入 | `syslog_ingest` | 网络设备、主机、网关的 Syslog 推送 | 已预留为接入型 connector，用于描述被动接收日志的入口 |
| 对象存储日志归档 | `object_storage` | OSS / S3 等对象存储中的批量或归档日志 | 已预留为批量日志、归档日志和离线回溯接入类型 |

其中，`sls`、`es`、`ssh_file`、`local_file`、`http_api` 以及 MySQL / MariaDB / PostgreSQL 只读库已具备通用 fetch 执行能力；数据库类在平台配置中统一使用 `database_ro`，再通过 `config.engine` 指定具体数据库。AWS CloudWatch、AWS S3 Logs、Azure Monitor、GCP Logging、腾讯云 CLS、华为云 LTS、Splunk、ClickHouse、Hive 已纳入扩展型 Connector 体系，可通过各自查询模板渲染取数请求，并按客户环境补齐凭证、 endpoint 和执行依赖。

---

## 6. 字段归一：让不同日志说同一种语言

不同日志源对同一语义字段的命名可能完全不同。

例如：

| 日志源字段 | 平台 canonical 字段 |
|---|---|
| ip / client_ip / remote_addr | src_ip |
| time / __time__ / @timestamp | timestamp |
| host_name / hostname | host |
| trace_id | alert_id |

SecWeaver 通过 field_aliases 和 shared field inventory 统一处理字段差异。

好处：

- Skill 不需要关心每个日志源的原始字段名
- 完整性检查可以按 canonical 字段判断
- correlation-matrix 可以用统一语义做 Join
- 新数据源接入时只需补字段映射，不需要改代码

---

## 7. Correlation Matrix：跨源证据关联合同

Correlation Matrix 是平台的关联大脑，定义：

- 哪些数据源可以关联
- 用哪些字段关联
- 在多大时间窗内关联
- 哪些调查场景使用这些关联链路
- fetch 时如何根据上下文补拉关联证据

例如：

```text
WAF 告警 → WEB 访问日志 → 主机命令执行 → 主机外联 → SSH 横向
```

这让 AI 不再凭感觉“猜关联”，而是在明确的 Join 合同内执行分析。

关键价值：

- 跨源分析可复现
- 攻击链还原可审计
- 新数据源接入后可快速加入关联链路
- 安全专家经验可以沉淀为机器可执行规则

---

## 8. 上线门禁：让运营配置可独立、可控、可上线

平台提供 validate 上线门禁，避免“配置能写但不能用”。

门禁检查包括：

- JSON Schema 是否通过
- active 资产是否有 owner、retention、query template
- active 资产的 coverage.hosts 是否只包含日志来源 IP
- evidence 必需字段是否可通过 schema.fields 或 field_aliases 解析
- query template 是否匹配 connector_type 和 asset_type
- bundle 是否引用了非 active 资产
- correlation-matrix Join 字段是否可达
- anchor-patterns 是否引用真实 Join 链

支持三种模式：

```bash
validate.py
validate.py --json
validate.py --json --strict --only-active
```

其中严格门禁可用于发布前检查：warning 也会作为 blocking issue。

---

## 9. 场景一：数据源完整性分析

在开始溯源前，平台先判断当前数据是否足够。

它会回答：

- 是否有 WAF / WEB / 主机 / SSH / DNS / 防火墙等必要数据？
- 关键字段是否存在？
- 时间保留周期是否覆盖调查窗口？
- 覆盖来源 IP 和字段归一是否可用？
- 当前证据是否足够确认攻击链？

价值：

> 在分析前先知道“缺什么数据”，避免安全分析变成盲查。

---

## 10. 场景二：风险识别

平台可以对主机行为数据进行 AI 风险识别。

典型数据：

- 对外监听进程命令执行
- 主机主动外联
- 文件操作行为
- 交互式 TTY 命令
- listener_pid / listener_port / process 信息

典型风险：

- WebShell 执行命令
- 反弹 shell
- 下载恶意工具
- 对外 C2 连接
- 外部入口进程异常执行高危命令

安全运营同学可以选择资产和 Skill，让 AI 按已沉淀规则进行高危命令识别和证据归因。

---

## 11. 场景三：攻击溯源分析

当已知外部攻击 IP 或告警时间时，平台可以自动进行跨源溯源。

示例链路：

```text
外部攻击 IP
  → WAF 告警
  → WEB 访问日志
  → 主机命令执行
  → 主机主动外联
  → SSH 横向登录
  → 影响主机范围
```

平台输出：

- 第一个可能被攻破的入口
- 攻击时间线
- 命令执行证据
- 横向移动路径
- 受影响主机列表
- 缺失数据说明
- 后续处置建议

---

## 12. 场景四：告警确认

面对 WAF / WEB / IDS 等告警，平台执行两层确认。

### 第一层：告警本身是否成立

- payload 是否明显恶意
- 告警规则是否命中真实攻击语义
- 是否可能是误报或扫描噪声

### 第二层：攻击是否成功

- 是否有对应 WEB 访问上下文
- 是否出现主机命令执行
- 是否出现外联、文件写入、横向登录
- 是否形成可验证证据链

输出结论：

```text
误报 / 尝试攻击 / 真实攻击 / 攻击成功 / 需要补数据确认
```

---

## 13. 已实现的工程化能力

目前平台已经具备从数据接入到 AI 分析的基础闭环。

| 模块 | 状态 |
|---|---|
| dataasset 目录模型 | 已实现 |
| Asset / Connector / Host / Bundle 管理 | 已实现 |
| SOPS Vault 凭证边界 | 已实现 |
| SLS / ES / SSH 文件 / 本地文件 / MySQL / MariaDB / PostgreSQL / HTTP API fetch 支持 | 已实现 |
| AWS / Azure / GCP / 腾讯云 / 华为云日志、Splunk、ClickHouse、Hive 扩展型 Connector | 已纳入模型与执行入口 |
| evidence normalizer + field_aliases | 已实现 |
| correlation-matrix v1.1 | 已实现 |
| data-source-completeness Skill | 已实现 |
| alert-confirmation Skill | 已实现 |
| traceability-analysis Skill | 已实现 |
| risk-identification Skill | 已实现 |
| validate 上线门禁 | 已实现 |
| 最小本地 UI / 表单向导 | 已实现 |

---

## 14. 平台架构概览

```text
运营配置层
  hosts / assets / connectors / bundles / query-templates / correlation-matrix
        ↓
上线门禁层
  validate.py --json --strict --only-active
        ↓
数据访问层
  template_select / vault / fetch / normalizer / field_inventory
        ↓
关联分析层
  correlation_engine / field_resolver / join_edges / fetch_plan
        ↓
AI Skill 层
  完整性分析 / 风险识别 / 溯源分析 / 告警确认
        ↓
交付层
  结论 / 证据链 / 时间线 / 缺失数据 / 处置建议
```

---

## 15. 对客户的核心价值

### 更快确认告警

从人工逐条研判，变成 AI 自动拉取上下文、交叉验证、输出结论。

### 更完整还原攻击链

把 WAF、WEB、主机、SSH、网络外联等多源证据串成可解释时间线。

### 更低运营门槛

通过数据资产模型、表单向导和上线门禁，让运营同学可以独立接入和维护数据源。

### 更容易沉淀专家经验

把专家分析流程固化为 Skill 和 correlation-matrix，而不是停留在个人经验里。

### 更强可扩展性

新增数据源、新字段、新 Join、新场景，都有明确扩展点。

---

## 16. 适用客户与落地场景

适用于已经具备一定安全数据基础，但希望提升分析效率和运营自动化能力的团队。

典型客户：

- 企业安全运营中心 SOC
- 云上安全运营团队
- 攻防演练保障团队
- 重保与应急响应团队
- 有 WAF / IDS / EDR / SIEM 但缺少自动关联能力的组织

典型落地场景：

- WAF 告警二次确认
- WebShell 攻击确认
- 外部 IP 溯源
- 主机高危命令识别
- 反弹 shell / C2 外联识别
- SSH 横向移动分析
- 安全数据源完整性评估

---

## 17. 产品范围与演进方向

| 范围 | 当前定位 |
|---|---|
| Community | DataAsset、Skills、CLI、本地 DataAsset Studio、采集 Agent 与离线样例 |
| 托管 SaaS | 企业工作台 → 智能体配置提供接入入口；服务端、多租户和商业控制面不随开源包交付 |
| 后续演进 | 更丰富的协作、审批和运营体验属于方向说明，不是本归档的功能或发布日期承诺 |

本地 DataAsset Studio 已有配置能力，不能再将所有 UI 统称为“下一阶段”。具体已交付内容以本次归档、各模块 README 和 CHANGELOG 为准。

## 18. 总结

SecWeaver 的核心不是“让 AI 随便分析日志”，而是构建一个可控、可审计、可扩展的 AI 安全运营平台。

它通过：

- 数据资产定义
- 字段归一
- 上线门禁
- 跨源关联矩阵
- 可复用安全 Skill
- AI 编排执行

让安全团队把分散的数据、工具和专家经验组织成可持续运行的安全分析能力。

> 从单点告警到完整证据链，从个人经验到平台能力，从人工研判到 AI 协同安全运营。
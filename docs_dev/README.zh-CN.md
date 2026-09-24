# SecWeaver 开发者文档

**语言：** [English](README.md) | 简体中文（本文）

本目录面向开发贡献者、维护者、架构师和集成开发者。安全运营、SOC 分析师和平台管理员的日常使用文档放在 [`docs_user/`](../docs_user/README.zh-CN.md)。

## 从这里开始

| 文档 | 说明 |
|---|---|
| [01-new-contributor-quickstart.zh-CN.md](01-new-contributor-quickstart.zh-CN.md) | 开发贡献者第一天上手路径 |
| [02-developer-guide.zh-CN.md](02-developer-guide.zh-CN.md) | 贡献者改动地图、Skill manifest 工作流与测试矩阵 |
| [03-community-add-asset-connector.zh-CN.md](03-community-add-asset-connector.zh-CN.md) | 如何贡献一个资产和 connector |
| [04-connector-plugins.zh-CN.md](04-connector-plugins.zh-CN.md) | Connector 插件 manifest、协议和校验 |
| [05-external-connector-executors.zh-CN.md](05-external-connector-executors.zh-CN.md) | 外部执行器示例与契约 |
| [25-ui-contribution-guide.zh-CN.md](25-ui-contribution-guide.zh-CN.md) | UI 贡献、页面扩展与整套 UI 重写契约 |

## Community 发布维护

按[发布验收清单](community-release-checklist.zh-CN.md)准备干净 HEAD、验证公开归档并记录未完成的真实平台验收。用户数据配置与安全边界另见[真实数据使用说明](../docs_user/community-release-and-data-safety.zh-CN.md)。

## Agent 开发与发布

按运维任务查阅 [Agent 专题索引](../src/tools/secweaver-agent/docs/README.zh-CN.md)。

| 文档 | 说明 |
|---|---|
| [`secweaver-agent` 工程手册](../src/tools/secweaver-agent/README.zh-CN.md) | 构建、配置、模块开发、签名升级、公钥轮换、紧急停止和回滚行为 |
| [26-secweaver-agent-device-identity-and-enrollment-design.zh-CN.md](26-secweaver-agent-device-identity-and-enrollment-design.zh-CN.md) | 不可变设备身份、注册协议、设备额度和撤销模型 |
| [30-agent-behavior-learning-design.zh-CN.md](30-agent-behavior-learning-design.zh-CN.md) | 24 小时行为学习、首期实现边界、日志减量、证据保留与上线验收设计 |
| [真实服务升级集成测试](../src/tools/secweaver-agent/integration/service-upgrade/README.md) | Linux systemd 与 Windows SCM 的 N-1 到 N 失败和自动回滚测试 |

## 架构与规划

| 中文 | English |
|---|---|
| [06-secweaver-architecture-and-features.zh-CN.md](06-secweaver-architecture-and-features.zh-CN.md) | [06-secweaver-architecture-and-features.md](06-secweaver-architecture-and-features.md) |
| [08-secweaver-architecture.zh-CN.svg](08-secweaver-architecture.zh-CN.svg) | 中文架构图 |
| [08-secweaver-architecture.svg](08-secweaver-architecture.svg) | English architecture diagram |

## DataAsset 设计

| 中文 | English |
|---|---|
| [09-data-asset-design.zh-CN.md](09-data-asset-design.zh-CN.md) | [09-data-asset-design.md](09-data-asset-design.md) |
| [12-agent-collection-and-evidence-spec.zh-CN.md](12-agent-collection-and-evidence-spec.zh-CN.md) | [12-agent-collection-and-evidence-spec.md](12-agent-collection-and-evidence-spec.md) |
| [23-sls-proxy-multi-tenant-design.zh-CN.md](23-sls-proxy-multi-tenant-design.zh-CN.md) | [23-sls-proxy-multi-tenant-design.md](23-sls-proxy-multi-tenant-design.md) |
| [26-secweaver-agent-device-identity-and-enrollment-design.zh-CN.md](26-secweaver-agent-device-identity-and-enrollment-design.zh-CN.md) | [26-secweaver-agent-device-identity-and-enrollment-design.md](26-secweaver-agent-device-identity-and-enrollment-design.md) |

## Skill 与引擎设计

| 中文 | English |
|---|---|
| [13-data-source-completeness-skill-design.zh-CN.md](13-data-source-completeness-skill-design.zh-CN.md) | [13-data-source-completeness-skill-design.md](13-data-source-completeness-skill-design.md) |
| [14-alert-confirmation-skill-design.zh-CN.md](14-alert-confirmation-skill-design.zh-CN.md) | [14-alert-confirmation-skill-design.md](14-alert-confirmation-skill-design.md) |
| [15-traceability-analysis-skill-design.zh-CN.md](15-traceability-analysis-skill-design.zh-CN.md) | [15-traceability-analysis-skill-design.md](15-traceability-analysis-skill-design.md) |
| [17-risk-identification-skill-design.zh-CN.md](17-risk-identification-skill-design.zh-CN.md) | [17-risk-identification-skill-design.md](17-risk-identification-skill-design.md) |
| [18-risk-identification-engine-design.zh-CN.md](18-risk-identification-engine-design.zh-CN.md) | [18-risk-identification-engine-design.md](18-risk-identification-engine-design.md) |
| [19-behavior-policy-engine-design.zh-CN.md](19-behavior-policy-engine-design.zh-CN.md) | [19-behavior-policy-engine-design.md](19-behavior-policy-engine-design.md) |
| [20-log-format-discovery-design.zh-CN.md](20-log-format-discovery-design.zh-CN.md) | [20-log-format-discovery-design.md](20-log-format-discovery-design.md) |
| [21-trace-profile-design.zh-CN.md](21-trace-profile-design.zh-CN.md) | [21-trace-profile-design.md](21-trace-profile-design.md) |
| [29-scenario-pattern-runtime-and-evolution.zh-CN.md](29-scenario-pattern-runtime-and-evolution.zh-CN.md) | [29-scenario-pattern-runtime-and-evolution.md](29-scenario-pattern-runtime-and-evolution.md) |

## 当前关联规范

- [关联矩阵概念](../docs_user/04-correlation-matrix.zh-CN.md)
- [跨源字段关联与运行时约束](../docs_user/21-cross-source-field-correlation.zh-CN.md)
- [关联矩阵 Schema](../dataasset/schema/correlation-matrix.schema.json)

## 历史评估

以下文档集中放在 [`history/`](history/README.zh-CN.md)，保留设计演进和决策依据，同时避免把旧评分和待办误解为当前实现状态。评分、问题和版本状态以各篇评估日期为限，不作为当前发布承诺；实现与配置以当前 Schema、用户指南和代码为准。

| 中文 | English |
|---|---|
| [10-data-asset-design-evaluation.zh-CN.md](history/10-data-asset-design-evaluation.zh-CN.md) | [10-data-asset-design-evaluation.md](history/10-data-asset-design-evaluation.md) |
| [11-data-object-model-evaluation.zh-CN.md](history/11-data-object-model-evaluation.zh-CN.md) | [11-data-object-model-evaluation.md](history/11-data-object-model-evaluation.md) |
| [16-traceability-analysis-architecture-evaluation.zh-CN.md](history/16-traceability-analysis-architecture-evaluation.zh-CN.md) | [16-traceability-analysis-architecture-evaluation.md](history/16-traceability-analysis-architecture-evaluation.md) |
| [22-correlation-matrix-design-evaluation.zh-CN.md](history/22-correlation-matrix-design-evaluation.zh-CN.md) | [22-correlation-matrix-design-evaluation.md](history/22-correlation-matrix-design-evaluation.md) |
| [28-secweaver-agent-audit-design.zh-CN.md](history/28-secweaver-agent-audit-design.zh-CN.md) | [28-secweaver-agent-audit-design.md](history/28-secweaver-agent-audit-design.md) |

## 可选托管服务的公开集成边界

Community 的本地分析和自建数据源接入不依赖私有服务端文档。接入托管服务时，开发者可参考以下公开契约：

- [SLS Proxy 客户端契约与安全边界](23-sls-proxy-multi-tenant-design.zh-CN.md)：查询协议、凭证引用和失败行为。
- [Agent 设备身份与注册协议](26-secweaver-agent-device-identity-and-enrollment-design.zh-CN.md)：客户端身份、注册和撤销约定。

这些文档说明客户端集成所需行为，不包含托管服务端实现或生产部署手册。

## 目录规则

- `docs_dev/`：当前开发、架构、设计、贡献、插件和集成文档。
- `docs_dev/history/`：为决策追溯保留的历史评估，不作为当前实现待办。
- `docs_user/`：安全运营、SOC 分析师、平台管理员、数据源接入和日常使用文档。
- `docs_ai/`：智能体按任务加载的可选上下文；运行时契约仍以 `dataasset/` 为准，工作流指令仍以 `src/skills/` 为准。
- 不单独设置 `docs_public/`。以上三个目录共同构成公开文档；私有产品、服务端、交付材料和内部评审原件不进入 Community 归档。

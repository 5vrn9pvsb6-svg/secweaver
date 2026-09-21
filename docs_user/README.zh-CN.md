# SecWeaver 用户文档索引

**语言：** [English](README.md) | 简体中文（本文）

本页提供面向运营人员的文档索引与快速导读。产品介绍、Quick Start、Agent 安装方式和
DataAsset 接入选型统一见[根目录 README](../README.zh-CN.md)；开发与贡献说明见
[docs_dev](../docs_dev/README.zh-CN.md)。

## 快速导读

### Community 独立使用

以下路径不要求开通 SecWeaver SaaS，也不依赖私有服务端文档。使用自然语言交互时需要自行配置智能体；查询真实数据时需要可访问的数据源及相应权限。

| 你的目标 | 建议阅读路径 |
|---|---|
| 第一次离线体验 | [10 分钟快速上手](00-security-operator-quickstart.zh-CN.md) → [离线 AI Showcase](../examples/ai-showcase/README.zh-CN.md) |
| 接入自有 ES、SLS、数据库、文件或其他数据源 | 先看[配置数据源](03-configure-data-sources.zh-CN.md)；字段未知看[格式发现](20-log-format-discovery.zh-CN.md)，失败时看[运营排错](09-operations-troubleshooting.zh-CN.md) |
| 采集主机日志并写入自建 ES | [Agent 工程手册](../src/tools/secweaver-agent/README.zh-CN.md) → [公开初始化与 Filebeat 接入指南](../src/tools/secweaver-agent/elasticsearch/README.zh-CN.md) |
| 开始调查事件 | [完整性预检](15-data-source-completeness.zh-CN.md) → 按需选择[告警确认](17-alert-confirmation.zh-CN.md)、[溯源分析](18-traceability-analysis.zh-CN.md)或[风险识别](19-risk-identification.zh-CN.md) |
| 排错或调整规则 | [运营排错](09-operations-troubleshooting.zh-CN.md)、[FAQ](10-faq.zh-CN.md) → [运营配置指南](25-traceability-analysis-ops-config-guide.zh-CN.md) |

### 可选 SaaS 接入

以下路径适用于已开通 SecWeaver Data Cloud 并取得企业授权的用户。企业工作台提供安装与查询凭证入口，托管服务端由平台运营方维护。

| 你的目标 | 建议阅读路径 |
|---|---|
| 安装托管采集客户端并使用已配置的分析环境 | [Data Cloud 客户快速上手](29-secweaver-data-system-quickstart.zh-CN.md) |
| 用本地智能体查询托管 SLS 数据 | [SLS Proxy 用户接入指南](30-sls-proxy-onboarding.zh-CN.md) |

按当前任务选择文档即可；文件编号是标识，不代表必须依次读完。

## 入门与基础

接入真实数据时，阅读[真实数据使用说明](community-release-and-data-safety.zh-CN.md)；维护者准备发布时，阅读[Community 发布验收清单](../docs_dev/community-release-checklist.zh-CN.md)。

| 简体中文 | English |
|---|---|
| [安全运营 10 分钟快速上手](00-security-operator-quickstart.zh-CN.md) | [Security Operator 10-Minute Quickstart](00-security-operator-quickstart.md) |
| [快速理解 SecWeaver](01-getting-started.zh-CN.md) | [Getting Started with SecWeaver](01-getting-started.md) |
| [核心概念](02-core-concepts.zh-CN.md) | [Core Concepts](02-core-concepts.md) |
| [AI原生安全分析与溯源平台介绍](14-platform-introduction.zh-CN.md) | [AI-Native Security Analysis and Traceability Platform](14-platform-introduction.md) |
| [AI原生的安全运营观&实践](00-ai-native-security-operations-philosophy-and-practice.zh-CN.md) | [AI-Native Security Operations: Philosophy & Practice](00-ai-native-security-operations-philosophy-and-practice.md) |
| [智能体配置指南](38-ai-agent-host-setup.zh-CN.md) | [AI Agent Host Setup](38-ai-agent-host-setup.md) |

## DataAsset 接入

| 简体中文 | English |
|---|---|
| [如何配置数据源](03-configure-data-sources.zh-CN.md) | [How to Configure Data Sources](03-configure-data-sources.md) |
| [数据源接入 UI 图文教程](11-onboarding-ui-walkthrough.zh-CN.md) | [Data Source Onboarding UI Walkthrough](11-onboarding-ui-walkthrough.md) |
| [数据源接入短 FAQ](16-data-source-onboarding-faq.zh-CN.md) | [Short Data Source Onboarding FAQ](16-data-source-onboarding-faq.md) |
| [日志格式发现](20-log-format-discovery.zh-CN.md) | [Log Format Discovery](20-log-format-discovery.md) |
| [SLS Proxy 用户接入指南](30-sls-proxy-onboarding.zh-CN.md) | [SLS Proxy User Onboarding](30-sls-proxy-onboarding.md) |
| [SecWeaver 数据底座四种部署模式](36-data-foundation-deployment-modes.zh-CN.md) | [SecWeaver Data Foundation Deployment Modes](36-data-foundation-deployment-modes.md) |

## 调查与日常运营

| 简体中文 | English |
|---|---|
| [项目技能与使用方式：让 AI 做安全运营任务](06-skills-and-usage.zh-CN.md) | [Project Skills and Usage: Let AI Run Security Operations Tasks](06-skills-and-usage.md) |
| [如何使用](07-how-to-use.zh-CN.md) | [How to Use](07-how-to-use.md) |
| [调查场景说明](08-investigation-scenarios.zh-CN.md) | [Investigation Scenarios](08-investigation-scenarios.md) |
| [数据源完整性分析](15-data-source-completeness.zh-CN.md) | [Data Source Completeness Analysis](15-data-source-completeness.md) |
| [告警确认](17-alert-confirmation.zh-CN.md) | [Alert Confirmation](17-alert-confirmation.md) |
| [溯源分析](18-traceability-analysis.zh-CN.md) | [Traceability Analysis](18-traceability-analysis.md) |
| [风险识别](19-risk-identification.zh-CN.md) | [Risk Identification](19-risk-identification.md) |
| [对外监听进程命令风险模式参考](23-external-listener-command-risk.zh-CN.md) | [External Listener Command Risk Pattern Reference](23-external-listener-command-risk.md) |
| [日常运营检查与排错](09-operations-troubleshooting.zh-CN.md) | [Operations Checks and Troubleshooting](09-operations-troubleshooting.md) |
| [常见问题 FAQ](10-faq.zh-CN.md) | [FAQ](10-faq.md) |
| [SecWeaver CLI](13-SecWeaver-CLI.zh-CN.md) | [SecWeaver CLI](13-SecWeaver-CLI.md) |

## 关联与运营配置

| 简体中文 | English |
|---|---|
| [Correlation Matrix 详解：告诉系统证据怎么关联](04-correlation-matrix.zh-CN.md) | [Correlation Matrix Explained: How Evidence Is Linked](04-correlation-matrix.md) |
| [Scenario Pattern 详解：告诉 AI 先查什么](05-scenario-patterns.zh-CN.md) | [Scenario Pattern Explained: Telling AI What to Query First](05-scenario-patterns.md) |
| [跨源字段关联说明](21-cross-source-field-correlation.zh-CN.md) | [Cross-Source Field Correlation Guide](21-cross-source-field-correlation.md) |
| [Scenario Patterns（调查场景编排）说明](22-scenario-patterns.zh-CN.md) | [Scenario Patterns (Investigation Scenario Orchestration)](22-scenario-patterns.md) |
| [溯源分析运营配置指南](25-traceability-analysis-ops-config-guide.zh-CN.md) | [Traceability Operations Configuration Guide](25-traceability-analysis-ops-config-guide.md) |

## Agent 与日志采集

| 简体中文 | English |
|---|---|
| [SecWeaver Data Cloud 客户快速上手](29-secweaver-data-system-quickstart.zh-CN.md) | [SecWeaver Data Cloud Customer Quickstart](29-secweaver-data-system-quickstart.md) |
| [SecWeaver 内网 DNS 查询日志建设指南](27-internal-dns-logging.zh-CN.md) | [SecWeaver Internal DNS Query Logging Guide](27-internal-dns-logging.md) |
| [host_persistence 数据采集介绍](28-host-persistence-collection.zh-CN.md) | [host_persistence Data Collection](28-host-persistence-collection.md) |
| [host_process 主机进程快照采集](32-host-process-snapshot.zh-CN.md) | [host_process Host Process Snapshots](32-host-process-snapshot.md) |
| [主机状态快照采集与接入](33-host-state-snapshot.zh-CN.md) | [Host state snapshot collection and onboarding](33-host-state-snapshot.md) |

## 相关资源

- [Agent 工程手册](../src/tools/secweaver-agent/README.zh-CN.md)
- [DataAsset 参考](../dataasset/README.zh-CN.md)
- [示例报告](../examples/reports/README.zh-CN.md)
- [Attack Lab](../attack_test/README.md)
- 图文教程配图：[默认接入页](images/onboarding-default.png)、[CloudWatch](images/onboarding-cloudwatch.png)

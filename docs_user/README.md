# SecWeaver User Documentation Index

**Languages:** English (this page) | [简体中文](README.zh-CN.md)

Find an operator guide here. Product overview, Quick Start, Agent installation choices,
and DataAsset onboarding choices are maintained in the [project README](../README.md).
Developer and contributor guides live in [docs_dev](../docs_dev/README.md).

## Quick Reading Paths

### Standalone Community Use

These paths do not require SecWeaver SaaS activation or private server documentation. Configure your own AI agent for natural-language interaction; real-data queries require an accessible data source and appropriate permissions.

| Your goal | Read in this order |
|---|---|
| First offline experience | [10-minute quickstart](00-security-operator-quickstart.md), then [Offline AI Showcase](../examples/ai-showcase/README.md) |
| Connect your own ES, SLS, database, files, or another source | [Configure data sources](03-configure-data-sources.md); for unknown fields use [format discovery](20-log-format-discovery.md), and for failures use [operations troubleshooting](09-operations-troubleshooting.md) |
| Collect host logs and send them to your ES | [Agent engineering manual](../src/tools/secweaver-agent/README.md), then [public initialization and Filebeat guide](../src/tools/secweaver-agent/elasticsearch/README.md) |
| Investigate an incident | [Completeness](15-data-source-completeness.md), then [alert confirmation](17-alert-confirmation.md), [traceability](18-traceability-analysis.md), or [risk identification](19-risk-identification.md) |
| Troubleshoot or adjust rules | [Operations](09-operations-troubleshooting.md), [FAQ](10-faq.md), then [configuration guide](25-traceability-analysis-ops-config-guide.md) |

### Optional SaaS Integration

These paths are for users with an active SecWeaver Data Cloud service and enterprise authorization. The enterprise workspace provides installation and query credential entry points; the platform operator maintains the managed server components.

| Your goal | Recommended guide |
|---|---|
| Install managed collectors and use a configured analysis environment | [Data Cloud customer quickstart](29-secweaver-data-system-quickstart.md) |
| Query managed SLS data from your local AI agent | [SLS Proxy user onboarding](30-sls-proxy-onboarding.md) |

Read the guides relevant to your task; numbered filenames are identifiers, not a required reading sequence.

## Getting Started

For live data, read [data safety guidance](community-release-and-data-safety.md). Maintainers preparing a release should use the [Community release checklist](../docs_dev/community-release-checklist.md).

| English | 简体中文 |
|---|---|
| [Security Operator 10-Minute Quickstart](00-security-operator-quickstart.md) | [安全运营 10 分钟快速上手](00-security-operator-quickstart.zh-CN.md) |
| [Getting Started with SecWeaver](01-getting-started.md) | [快速理解 SecWeaver](01-getting-started.zh-CN.md) |
| [Core Concepts](02-core-concepts.md) | [核心概念](02-core-concepts.zh-CN.md) |
| [AI-Native Security Analysis and Traceability Platform](14-platform-introduction.md) | [AI原生安全分析与溯源平台介绍](14-platform-introduction.zh-CN.md) |
| [AI-Native Security Operations: Philosophy & Practice](00-ai-native-security-operations-philosophy-and-practice.md) | [AI原生的安全运营观&实践](00-ai-native-security-operations-philosophy-and-practice.zh-CN.md) |
| [AI Agent Host Setup](38-ai-agent-host-setup.md) | [智能体配置指南](38-ai-agent-host-setup.zh-CN.md) |

## DataAsset Onboarding

| English | 简体中文 |
|---|---|
| [How to Configure Data Sources](03-configure-data-sources.md) | [如何配置数据源](03-configure-data-sources.zh-CN.md) |
| [Data Source Onboarding UI Walkthrough](11-onboarding-ui-walkthrough.md) | [数据源接入 UI 图文教程](11-onboarding-ui-walkthrough.zh-CN.md) |
| [Short Data Source Onboarding FAQ](16-data-source-onboarding-faq.md) | [数据源接入短 FAQ](16-data-source-onboarding-faq.zh-CN.md) |
| [Log Format Discovery](20-log-format-discovery.md) | [日志格式发现](20-log-format-discovery.zh-CN.md) |
| [SLS Proxy User Onboarding](30-sls-proxy-onboarding.md) | [SLS Proxy 用户接入指南](30-sls-proxy-onboarding.zh-CN.md) |
| [SecWeaver Data Foundation Deployment Modes](36-data-foundation-deployment-modes.md) | [SecWeaver 数据底座四种部署模式](36-data-foundation-deployment-modes.zh-CN.md) |

## Investigation And Operations

| English | 简体中文 |
|---|---|
| [Project Skills and Usage: Let AI Run Security Operations Tasks](06-skills-and-usage.md) | [项目技能与使用方式：让 AI 做安全运营任务](06-skills-and-usage.zh-CN.md) |
| [How to Use](07-how-to-use.md) | [如何使用](07-how-to-use.zh-CN.md) |
| [Investigation Scenarios](08-investigation-scenarios.md) | [调查场景说明](08-investigation-scenarios.zh-CN.md) |
| [Data Source Completeness Analysis](15-data-source-completeness.md) | [数据源完整性分析](15-data-source-completeness.zh-CN.md) |
| [Alert Confirmation](17-alert-confirmation.md) | [告警确认](17-alert-confirmation.zh-CN.md) |
| [Traceability Analysis](18-traceability-analysis.md) | [溯源分析](18-traceability-analysis.zh-CN.md) |
| [Risk Identification](19-risk-identification.md) | [风险识别](19-risk-identification.zh-CN.md) |
| [External Listener Command Risk Pattern Reference](23-external-listener-command-risk.md) | [对外监听进程命令风险模式参考](23-external-listener-command-risk.zh-CN.md) |
| [Operations Checks and Troubleshooting](09-operations-troubleshooting.md) | [日常运营检查与排错](09-operations-troubleshooting.zh-CN.md) |
| [FAQ](10-faq.md) | [常见问题 FAQ](10-faq.zh-CN.md) |
| [SecWeaver CLI](13-SecWeaver-CLI.md) | [SecWeaver CLI](13-SecWeaver-CLI.zh-CN.md) |

## Correlation And Configuration

| English | 简体中文 |
|---|---|
| [Correlation Matrix Explained: How Evidence Is Linked](04-correlation-matrix.md) | [Correlation Matrix 详解：告诉系统证据怎么关联](04-correlation-matrix.zh-CN.md) |
| [Scenario Pattern Explained: Telling AI What to Query First](05-scenario-patterns.md) | [Scenario Pattern 详解：告诉 AI 先查什么](05-scenario-patterns.zh-CN.md) |
| [Cross-Source Field Correlation Guide](21-cross-source-field-correlation.md) | [跨源字段关联说明](21-cross-source-field-correlation.zh-CN.md) |
| [Scenario Patterns (Investigation Scenario Orchestration)](22-scenario-patterns.md) | [Scenario Patterns（调查场景编排）说明](22-scenario-patterns.zh-CN.md) |
| [Traceability Operations Configuration Guide](25-traceability-analysis-ops-config-guide.md) | [溯源分析运营配置指南](25-traceability-analysis-ops-config-guide.zh-CN.md) |

## Agent And Log Collection

| English | 简体中文 |
|---|---|
| [SecWeaver Data Cloud Customer Quickstart](29-secweaver-data-system-quickstart.md) | [SecWeaver Data Cloud 客户快速上手](29-secweaver-data-system-quickstart.zh-CN.md) |
| [SecWeaver Internal DNS Query Logging Guide](27-internal-dns-logging.md) | [SecWeaver 内网 DNS 查询日志建设指南](27-internal-dns-logging.zh-CN.md) |
| [host_persistence Data Collection](28-host-persistence-collection.md) | [host_persistence 数据采集介绍](28-host-persistence-collection.zh-CN.md) |
| [host_process Host Process Snapshots](32-host-process-snapshot.md) | [host_process 主机进程快照采集](32-host-process-snapshot.zh-CN.md) |
| [Host state snapshot collection and onboarding](33-host-state-snapshot.md) | [主机状态快照采集与接入](33-host-state-snapshot.zh-CN.md) |

## Related Resources

- [Agent engineering manual](../src/tools/secweaver-agent/README.md)
- [DataAsset reference](../dataasset/README.md)
- [Sample reports](../examples/reports/README.md)
- [Attack Lab](../attack_test/README.md)
- Walkthrough images: [default onboarding](images/onboarding-default.png), [CloudWatch](images/onboarding-cloudwatch.png)
